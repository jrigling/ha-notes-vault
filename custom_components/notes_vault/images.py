"""Pictures embedded in notes, served to the Home Assistant frontend.

Administrators add pictures with an upload, from the editor's photo button or by
pasting or dropping one in. Uploads go to one attachments folder, like Obsidian's.

A browser can't put Home Assistant's token on an `<img>`, so each picture gets a
signed URL, the way camera snapshots do. The URLs are handed out only alongside a
note the viewer may read, and carry a key that only Notes Vault can make, so
signing an arbitrary path through Home Assistant's own `auth/sign_path` gets
nobody into the rest of the vault.
"""

from __future__ import annotations

import hashlib
import hmac
import mimetypes
from datetime import timedelta
from urllib.parse import quote, unquote

from aiohttp import hdrs, web
from homeassistant.components.http import KEY_HASS_USER, HomeAssistantView
from homeassistant.components.http.auth import async_sign_path
from homeassistant.core import HomeAssistant, callback

from .const import IMAGE_URL, UPLOAD_URL
from .manager import IMAGE_SUFFIXES, NotesVault, loaded_manager
from .vault import NotFoundError, VaultError, safe_name

#: How long a picture URL works. The note is fetched again when it's opened.
URL_LIFETIME = timedelta(hours=24)
#: Upper bound for one picture, so a stray video renamed .jpg can't exhaust memory.
MAX_IMAGE = 50 * 1024 * 1024
KEY_PARAM = "k"
#: Where uploads go, from the top of the vault.
ATTACHMENTS_FOLDER = "Attachments"
#: Upper bound for one upload. The editor shrinks photos to a few hundred KB first.
MAX_UPLOAD = 25 * 1024 * 1024

#: What an upload has to start with to be the picture its name says.
_MAGIC = (
    (b"\xff\xd8\xff", ".jpg"),
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
)

_HEADERS = {
    # Embedded by notes only, never run: an SVG opened on its own gets no scripts.
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "private, max-age=86400",
}


def _key(manager: NotesVault, path: str) -> str:
    return hmac.new(manager.image_key, path.encode(), hashlib.sha256).hexdigest()[:32]


@callback
def async_image_urls(
    hass: HomeAssistant, manager: NotesVault, images: dict[str, str]
) -> dict[str, str]:
    """Turn each embedded picture's vault path into a URL the current viewer can load."""
    return {
        target: async_sign_path(
            hass,
            f"{IMAGE_URL}/{quote(path)}?{KEY_PARAM}={_key(manager, path)}",
            URL_LIFETIME,
        )
        for target, path in images.items()
    }


class NotesVaultImageView(HomeAssistantView):
    """Serve one picture from the vault, given a URL from `async_image_urls`."""

    url = IMAGE_URL + "/{path:.+}"
    name = "api:notes_vault:image"
    requires_auth = True

    def __init__(self, hass: HomeAssistant) -> None:
        """Look the vault up per request, like the WebDAV view, to survive reloads."""
        self.hass = hass

    async def get(self, request: web.Request, path: str) -> web.Response:
        """Send the picture if the URL's key matches its path."""
        manager = loaded_manager(self.hass)
        if manager is None:
            return web.Response(status=404)
        try:
            path = manager.vault.normalize(path)
        except VaultError:
            return web.Response(status=404)
        given = request.query.get(KEY_PARAM, "")
        if not hmac.compare_digest(given, _key(manager, path)):
            return web.Response(status=403)
        suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if f".{suffix}" not in IMAGE_SUFFIXES:
            return web.Response(status=404)
        try:
            info = await self.hass.async_add_executor_job(manager.vault.stat, path)
            if info.is_dir:
                return web.Response(status=404)
            if info.size > MAX_IMAGE:
                return web.Response(status=413)
            body = await self.hass.async_add_executor_job(
                manager.vault.read_bytes, path
            )
        except (NotFoundError, VaultError):
            return web.Response(status=404)
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if suffix == "avif":
            ctype = "image/avif"
        return web.Response(body=body, headers={**_HEADERS, hdrs.CONTENT_TYPE: ctype})


def _picture_suffix(head: bytes) -> str | None:
    """Return the file extension a picture's first bytes say it is, if any."""
    for magic, suffix in _MAGIC:
        if head.startswith(magic):
            return suffix
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return ".webp"
    return None


def _free_path(manager: NotesVault, stem: str, suffix: str) -> str:
    """Pick a name in the attachments folder that isn't taken. Runs in the executor."""
    candidate, n = f"{stem}{suffix}", 1
    while manager.vault.exists(f"{ATTACHMENTS_FOLDER}/{candidate}"):
        n += 1
        candidate = f"{stem} {n}{suffix}"
    return f"{ATTACHMENTS_FOLDER}/{candidate}"


class NotesVaultUploadView(HomeAssistantView):
    """Save one uploaded picture in the attachments folder."""

    url = UPLOAD_URL
    name = "api:notes_vault:upload"
    requires_auth = True

    def __init__(self, hass: HomeAssistant) -> None:
        """Look the vault up per request, like the other views."""
        self.hass = hass

    async def post(self, request: web.Request) -> web.Response:
        """Take a multipart `file`, check it's a picture, and store it.

        Returns the stored file's `name`, which is what an `![[...]]` embed uses,
        its vault `path`, and a `url` to show it with right away.
        """
        manager = loaded_manager(self.hass)
        if manager is None:
            return web.Response(status=404)
        if not request[KEY_HASS_USER].is_admin:
            return web.Response(
                status=403, text="Adding pictures needs an administrator"
            )
        try:
            reader = await request.multipart()
        except (AssertionError, ValueError):
            return web.Response(status=400, text="Expected a multipart upload")
        field = await reader.next()
        while field is not None and getattr(field, "name", None) != "file":
            field = await reader.next()
        if field is None:
            return web.Response(status=400, text="No file in the upload")

        data = bytearray()
        while chunk := await field.read_chunk(64 * 1024):
            data.extend(chunk)
            if len(data) > MAX_UPLOAD:
                return web.Response(status=413, text="That picture is too large")
        suffix = _picture_suffix(bytes(data[:16]))
        if suffix is None:
            return web.Response(
                status=415, text="That isn't a JPEG, PNG, GIF or WebP picture"
            )
        # The name comes from the client: keep only what's safe as a file name.
        # Some clients percent-encode it.
        raw = unquote(field.filename or "Picture").replace("\\", "/").rsplit("/", 1)[-1]
        stem = safe_name(raw.rsplit(".", 1)[0] if "." in raw else raw)

        async with manager.lock:
            path = await self.hass.async_add_executor_job(
                _free_path, manager, stem, suffix
            )
            await self.hass.async_add_executor_job(
                manager.vault.write_bytes, path, data
            )
        name = path.rsplit("/", 1)[-1]
        url = async_image_urls(self.hass, manager, {name: path})[name]
        return self.json({"name": name, "path": path, "url": url}, status_code=201)
