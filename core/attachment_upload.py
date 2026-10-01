"""HTTP upload into the managed attachment directory (same bearer as /mcp).

Remote MCP clients (Claude Code / Codex on a Mac) cannot pass local paths to the
VPS. They POST multipart here, receive attachment_id, then pass that id into
draft/update Gmail tools — avoiding huge base64 in tool arguments.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Optional

from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Match Gmail's practical attachment ceiling.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def _expected_bearer() -> str:
    return os.environ.get("GOOGLE_MCP_BEARER_TOKEN", "") or ""


def require_mcp_bearer(request: Request) -> Optional[JSONResponse]:
    """Same bearer as /mcp (GOOGLE_MCP_BEARER_TOKEN). Fail-closed when unset."""
    expected = _expected_bearer()
    auth = (
        request.headers.get("authorization")
        or request.headers.get("Authorization")
        or ""
    )
    if not expected:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not auth.lower().startswith("bearer "):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    token = auth[7:].strip()
    if not token or not secrets.compare_digest(token, expected):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return None


async def upload_attachment(request: Request) -> JSONResponse:
    """POST /attachments — multipart field ``file`` (optional ``filename`` form field)."""
    denied = require_mcp_bearer(request)
    if denied is not None:
        return denied

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_UPLOAD_BYTES + 4096:
                return JSONResponse(
                    {"error": f"File too large (max {MAX_UPLOAD_BYTES} bytes)"},
                    status_code=413,
                )
        except ValueError:
            pass

    form = await request.form()
    upload = form.get("file")
    if upload is None:
        return JSONResponse(
            {"error": "Missing multipart field 'file'"}, status_code=400
        )

    filename = getattr(upload, "filename", None) or form.get("filename") or "attachment"
    if isinstance(filename, str):
        filename = filename.strip() or "attachment"
    else:
        filename = "attachment"

    mime_type = getattr(upload, "content_type", None) or "application/octet-stream"
    if hasattr(upload, "read"):
        data = await upload.read()
    else:
        return JSONResponse({"error": "Invalid file upload"}, status_code=400)

    if not isinstance(data, (bytes, bytearray)):
        return JSONResponse({"error": "Invalid file upload"}, status_code=400)
    data = bytes(data)

    if len(data) > MAX_UPLOAD_BYTES:
        return JSONResponse(
            {"error": f"File too large (max {MAX_UPLOAD_BYTES} bytes)"},
            status_code=413,
        )
    if len(data) == 0:
        return JSONResponse({"error": "Empty file"}, status_code=400)

    from core.attachment_storage import get_attachment_storage, get_attachment_url

    storage = get_attachment_storage()
    saved = storage.save_attachment_bytes(
        file_bytes=data, filename=str(filename), mime_type=str(mime_type)
    )
    meta = storage.get_attachment_metadata(saved.file_id) or {}
    logger.info(
        "HTTP attachment upload file_id=%s filename=%s size=%s",
        saved.file_id,
        filename,
        len(data),
    )
    return JSONResponse(
        {
            "attachment_id": saved.file_id,
            "path": saved.path,
            "filename": meta.get("original_filename")
            or meta.get("filename")
            or filename,
            "mime_type": meta.get("mime_type") or mime_type,
            "size": len(data),
            "url": get_attachment_url(saved.file_id),
            "expires_in_seconds": storage.expiration_seconds,
        },
        status_code=201,
    )


def register_attachment_upload_route(server) -> None:
    """Mount POST /attachments on the FastMCP/Starlette app."""
    server.custom_route("/attachments", methods=["POST"])(upload_attachment)
