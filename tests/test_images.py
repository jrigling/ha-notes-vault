"""Pictures embedded in notes: resolved like Obsidian does, served by signed URL."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
from homeassistant.core import HomeAssistant

from custom_components.notes_vault.manager import NotesVault

PNG = b"\x89PNG\r\n\x1a\nfake"
LAMP = "Home Assistant/Entities/light.kitchen_ceiling.md"


def _put(vault_dir: Path, path: str, data: bytes = PNG) -> None:
    full = vault_dir / path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(data)


async def test_images_resolve_like_obsidian(
    manager: NotesVault, vault_dir: Path
) -> None:
    """By vault path, from the note's folder, or by name, nearest copy first."""
    _put(vault_dir, "Attachments/valve box.jpg")
    _put(vault_dir, "Garden/Attachments/My photo.png")
    _put(vault_dir, "Garden/sprinkler.webp")
    _put(vault_dir, "Garden/dup.png")
    _put(vault_dir, "Elsewhere/dup.png")
    _put(vault_dir, "Garden/notes.txt", b"not a picture")
    text = (
        "![[valve box.jpg|300]]\n"
        "![[sprinkler.webp]]\n"
        "![[dup.png]]\n"
        "![[Attachments/valve box.jpg]]\n"
        "![zone map](Attachments/My%20photo.png)\n"
        "![](https://example.com/web.png)\n"
        "![[missing.png]]\n"
        "![[Nowhere/valve box.jpg]]\n"
        "![[notes.txt]]\n"
        "![[../secrets.png]]\n"
    )
    images = await manager.async_resolve_images(text, "Garden/Irrigation.md")
    assert images == {
        "valve box.jpg": "Attachments/valve box.jpg",
        "sprinkler.webp": "Garden/sprinkler.webp",
        "dup.png": "Garden/dup.png",
        "Attachments/valve box.jpg": "Attachments/valve box.jpg",
        "Attachments/My%20photo.png": "Garden/Attachments/My photo.png",
    }


async def test_note_brings_signed_image_urls(
    hass: HomeAssistant,
    home: dict,
    manager: NotesVault,
    hass_ws_client,
    hass_client_no_auth,
    hass_read_only_access_token: str,
    vault_dir: Path,
) -> None:
    """A user who can read a note can load its pictures, and nothing else."""
    await manager.async_sync()
    _put(vault_dir, "Attachments/bulb.png")
    _put(vault_dir, "Private/receipt.png", b"\x89PNGsecret")
    ws = await hass_ws_client(hass)
    await ws.send_json_auto_id(
        {"type": "notes_vault/set", "path": LAMP, "note": "The bulb:\n\n![[bulb.png]]"}
    )
    saved = (await ws.receive_json())["result"]
    assert set(saved["images"]) == {"bulb.png"}

    # A non-administrator reads the light's note and gets the picture's URL.
    user_ws = await hass_ws_client(hass, hass_read_only_access_token)
    await user_ws.send_json_auto_id(
        {"type": "notes_vault/get", "entity_id": "light.kitchen_ceiling"}
    )
    note = (await user_ws.receive_json())["result"]
    url = note["images"]["bulb.png"]
    assert "authSig=" in url

    client = await hass_client_no_auth()
    resp = await client.get(url)
    assert resp.status == 200
    assert await resp.read() == PNG
    assert resp.headers["Content-Type"] == "image/png"
    assert "sandbox" in resp.headers["Content-Security-Policy"]

    # Signing works per path: the URL can't be bent to another picture...
    split = urlsplit(url)
    other = url.replace(split.path, split.path.replace("bulb.png", "receipt.png"))
    assert (await client.get(other)).status in (401, 403)

    # ...nor can a path signed through Home Assistant's own command, without the key.
    await user_ws.send_json_auto_id(
        {"type": "auth/sign_path", "path": "/api/notes_vault/image/Private/receipt.png"}
    )
    signed = (await user_ws.receive_json())["result"]["path"]
    assert (await client.get(signed)).status == 403

    # And without a signature at all, nothing.
    assert (
        await client.get(split.path + "?" + split.query.split("&authSig")[0])
    ).status == 401


async def test_only_pictures_are_served(
    hass: HomeAssistant,
    manager: NotesVault,
    hass_ws_client,
    hass_client_no_auth,
    vault_dir: Path,
) -> None:
    """A note embedding a non-picture gets no URL for it."""
    _put(vault_dir, "doc.pdf", b"%PDF")
    ws = await hass_ws_client(hass)
    await ws.send_json_auto_id(
        {"type": "notes_vault/set", "path": "Manuals.md", "note": "![[doc.pdf]]"}
    )
    assert (await ws.receive_json())["result"]["images"] == {}


JPEG = b"\xff\xd8\xff\xe0fake jpeg"


def _form(data: bytes, filename: str) -> aiohttp.FormData:
    form = aiohttp.FormData()
    form.add_field("file", data, filename=filename, content_type="image/jpeg")
    return form


async def test_upload_stores_picture_in_attachments(
    hass: HomeAssistant,
    manager: NotesVault,
    hass_client,
    hass_client_no_auth,
    vault_dir: Path,
) -> None:
    """An administrator's upload lands in Attachments, named safely and uniquely."""
    client = await hass_client()
    resp = await client.post(
        "/api/notes_vault/upload",
        data=_form(JPEG, "Irrigation 2026-11-11 22-31-05.jpg"),
    )
    assert resp.status == 201
    first = await resp.json()
    assert first["path"] == "Attachments/Irrigation 2026-11-11 22-31-05.jpg"
    assert (vault_dir / first["path"]).read_bytes() == JPEG

    # The same name again gets a number, never overwrites.
    resp = await client.post(
        "/api/notes_vault/upload",
        data=_form(JPEG, "Irrigation 2026-11-11 22-31-05.jpg"),
    )
    assert (await resp.json())["name"] == "Irrigation 2026-11-11 22-31-05 2.jpg"

    # A name can't climb out of the folder or break an embed; the bytes set the type.
    resp = await client.post(
        "/api/notes_vault/upload", data=_form(PNG, "../../[[evil]]|x.jpg")
    )
    stored = await resp.json()
    assert stored["path"].startswith("Attachments/")
    assert stored["name"].endswith(".png")
    assert not any(c in stored["name"] for c in "[]|/")

    # The returned URL shows the picture right away.
    shown = await (await hass_client_no_auth()).get(first["url"])
    assert shown.status == 200


async def test_upload_refuses_what_isnt_a_picture(
    hass: HomeAssistant,
    manager: NotesVault,
    hass_client,
    hass_read_only_access_token: str,
    vault_dir: Path,
) -> None:
    """Only pictures, and only from administrators."""
    client = await hass_client()
    resp = await client.post(
        "/api/notes_vault/upload", data=_form(b"<svg onload=alert(1)>", "x.jpg")
    )
    assert resp.status == 415

    user = await hass_client(hass_read_only_access_token)
    resp = await user.post("/api/notes_vault/upload", data=_form(JPEG, "x.jpg"))
    assert resp.status == 403
    assert not (vault_dir / "Attachments").exists()
