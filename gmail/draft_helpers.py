"""Helpers for Gmail draft list/update/delete and attachment source resolution."""

from __future__ import annotations

import base64
import io
import logging
import mimetypes
from email import policy
from email.parser import BytesParser
from typing import Any, Dict, List, Optional, Tuple

from googleapiclient.http import MediaIoBaseDownload

logger = logging.getLogger(__name__)

_GOOGLE_NATIVE_EXPORT = {
    "application/vnd.google-apps.document": (
        "application/pdf",
        ".pdf",
    ),
    "application/vnd.google-apps.spreadsheet": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".xlsx",
    ),
    "application/vnd.google-apps.presentation": (
        "application/pdf",
        ".pdf",
    ),
}


def signature_already_present(
    body: str, body_format: str, signature_html: str, html_to_text
) -> bool:
    """True when signature content is already embedded in body (avoid duplicates)."""
    if not signature_html or not signature_html.strip():
        return True
    if body_format == "html":
        return signature_html.strip() in body
    sig_text = html_to_text(signature_html).strip()
    return bool(sig_text) and sig_text in body


def parse_raw_mime_message(raw_b64: str) -> Dict[str, Any]:
    """Parse Gmail raw (urlsafe base64) MIME into headers, body, and attachments."""
    raw_bytes = base64.urlsafe_b64decode(raw_b64)
    msg = BytesParser(policy=policy.SMTP).parsebytes(raw_bytes)

    def _hdr(name: str) -> Optional[str]:
        val = msg.get(name)
        return str(val) if val is not None else None

    text_body = ""
    html_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if ctype == "text/plain" and "attachment" not in disp.lower():
                try:
                    text_body = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    text_body = payload.decode("utf-8", errors="replace")
            elif ctype == "text/html" and "attachment" not in disp.lower():
                try:
                    html_body = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    html_body = payload.decode("utf-8", errors="replace")
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if ctype == "text/html":
            html_body = content
        else:
            text_body = content

    attachments: List[Dict[str, Any]] = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        disp = str(part.get("Content-Disposition") or "").lower()
        # Keep both attachment and inline file parts that carry a filename.
        if "attachment" not in disp and "inline" not in disp and not filename:
            continue
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            continue
        if not data:
            continue
        mime_type = part.get_content_type() or "application/octet-stream"
        attachments.append(
            {
                "filename": filename,
                "mime_type": mime_type,
                "_resolved_bytes": data,
            }
        )

    body_format = "html" if html_body else "plain"
    body = html_body if html_body else text_body
    return {
        "subject": _hdr("Subject") or "",
        "to": _hdr("To"),
        "cc": _hdr("Cc"),
        "bcc": _hdr("Bcc"),
        "from": _hdr("From"),
        "in_reply_to": _hdr("In-Reply-To"),
        "references": _hdr("References"),
        "body": body,
        "body_format": body_format,
        "attachments": attachments,
    }


def attachment_filenames_from_payload(payload: dict) -> List[str]:
    """Collect attachment filenames from a Gmail API message payload."""
    names: List[str] = []

    def walk(part: dict) -> None:
        filename = part.get("filename")
        if filename and part.get("body", {}).get("attachmentId"):
            names.append(filename)
        for sub in part.get("parts") or []:
            walk(sub)

    walk(payload or {})
    return names


async def download_drive_file_bytes(
    drive_service, file_id: str
) -> Tuple[bytes, str, str]:
    """Download/export a Drive file; Google Docs → PDF like get_drive_file_download_url."""
    import asyncio

    meta = await asyncio.to_thread(
        drive_service.files().get(fileId=file_id, fields="id,name,mimeType").execute
    )
    mime_type = meta.get("mimeType") or "application/octet-stream"
    file_name = meta.get("name") or "attachment"
    export_mime = None
    output_name = file_name
    output_mime = mime_type

    if mime_type in _GOOGLE_NATIVE_EXPORT:
        export_mime, ext = _GOOGLE_NATIVE_EXPORT[mime_type]
        output_mime = export_mime
        from pathlib import Path

        if not output_name.lower().endswith(ext):
            output_name = f"{Path(output_name).stem}{ext}"

    request_obj = (
        drive_service.files().export_media(fileId=file_id, mimeType=export_mime)
        if export_mime
        else drive_service.files().get_media(fileId=file_id)
    )
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request_obj)
    loop = asyncio.get_event_loop()
    done = False
    while not done:
        _status, done = await loop.run_in_executor(None, downloader.next_chunk)
    data = fh.getvalue()
    if not output_mime or output_mime == "application/octet-stream":
        guessed, _ = mimetypes.guess_type(output_name)
        output_mime = guessed or output_mime
    return data, output_name, output_mime
