"""Pictures embedded in notes, served to the Home Assistant frontend.

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
from urllib.parse import quote

from aiohttp import hdrs, web
from homeassistant.components.http import HomeAssistantView
from homeassistant.components.http.auth import async_sign_path
from homeassistant.core import HomeAssistant, callback

from .const import IMAGE_URL
from .manager import IMAGE_SUFFIXES, NotesVault, loaded_manager
from .vault import NotFoundError, VaultError

#: How long a picture URL works. The note is fetched again when it's opened.
URL_LIFETIME = timedelta(hours=24)
#: Upper bound for one picture, so a stray video renamed .jpg can't exhaust memory.
MAX_IMAGE = 50 * 1024 * 1024
KEY_PARAM = "k"

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
