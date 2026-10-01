"""GG-1442: list/update/delete drafts, attachment_id/drive_file_id, upload auth."""

from __future__ import annotations

import base64
import os
import sys
from email.message import EmailMessage
from email.policy import SMTP
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.attachment_storage import get_attachment_storage
from core.attachment_upload import MAX_UPLOAD_BYTES, upload_attachment
from gmail.draft_helpers import (
    parse_raw_mime_message,
    signature_already_present,
)
from gmail.gmail_tools import (
    delete_gmail_draft,
    list_gmail_drafts,
    update_gmail_draft,
    _prepare_gmail_message,
    _resolve_url_attachments,
)
from core.utils import validate_file_path


def _unwrap(tool):
    fn = tool.fn if hasattr(tool, "fn") else tool
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    return fn


def _raw_draft_bytes(
    *,
    subject="Hello",
    body="Body text",
    to="a@example.com",
    in_reply_to="<msg1@x>",
    references="<msg1@x>",
    attachment_name=None,
    attachment_bytes=b"payload",
):
    msg = EmailMessage(policy=SMTP)
    msg["Subject"] = subject
    msg["To"] = to
    msg["From"] = "Me <me@example.com>"
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    msg.set_content(body)
    if attachment_name:
        msg.add_attachment(
            attachment_bytes,
            maintype="application",
            subtype="octet-stream",
            filename=attachment_name,
        )
    return base64.urlsafe_b64encode(msg.as_bytes(policy=SMTP)).decode()


@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    import core.attachment_storage as storage_module

    monkeypatch.setattr(storage_module, "STORAGE_DIR", tmp_path)
    storage_module._attachment_storage = None
    yield get_attachment_storage()
    storage_module._attachment_storage = None


def test_signature_already_present_html():
    sig = "<div>-- GG</div>"
    assert signature_already_present(f"Hi{sig}", "html", sig, lambda s: s) is True
    assert signature_already_present("Hi only", "html", sig, lambda s: "GG") is False


def test_parse_raw_preserves_thread_headers_and_attachment():
    raw = _raw_draft_bytes(attachment_name="raport_złoty.pdf")
    parsed = parse_raw_mime_message(raw)
    assert parsed["subject"] == "Hello"
    assert parsed["to"] == "a@example.com"
    assert parsed["in_reply_to"] == "<msg1@x>"
    assert parsed["references"] == "<msg1@x>"
    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["filename"] == "raport_złoty.pdf"
    assert parsed["attachments"][0]["_resolved_bytes"] == b"payload"


@pytest.mark.asyncio
async def test_update_body_keeps_attachments_and_thread_headers():
    raw = _raw_draft_bytes(attachment_name="keep.txt", attachment_bytes=b"keep-me")
    service = MagicMock()
    service.users().drafts().get().execute.return_value = {
        "id": "d1",
        "message": {"id": "m1", "threadId": "t1", "raw": raw},
    }
    service.users().drafts().update().execute.return_value = {"id": "d1"}

    result = await _unwrap(update_gmail_draft)(
        service,
        "me@example.com",
        draft_id="d1",
        body="Updated only",
        include_signature=False,
    )
    assert "Draft updated" in result
    assert "d1" in result

    call_kwargs = service.users.return_value.drafts.return_value.update.call_args.kwargs
    body = call_kwargs["body"]
    assert body["message"]["threadId"] == "t1"
    updated_raw = body["message"]["raw"]
    parsed = parse_raw_mime_message(updated_raw)
    assert "Updated only" in (parsed["body"] or "")
    assert parsed["in_reply_to"] == "<msg1@x>"
    assert parsed["references"] == "<msg1@x>"
    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["filename"] == "keep.txt"


@pytest.mark.asyncio
async def test_update_remove_and_add_attachment(isolated_storage):
    raw = _raw_draft_bytes(attachment_name="old.txt", attachment_bytes=b"old")
    service = MagicMock()
    service.users().drafts().get().execute.return_value = {
        "id": "d1",
        "message": {"id": "m1", "threadId": "t1", "raw": raw},
    }
    service.users().drafts().update().execute.return_value = {"id": "d1"}

    saved = isolated_storage.save_attachment_bytes(
        b"new-bytes", filename="nowy_plik.pdf", mime_type="application/pdf"
    )

    await _unwrap(update_gmail_draft)(
        service,
        "me@example.com",
        draft_id="d1",
        remove_attachments=["old.txt"],
        attachments=[{"attachment_id": saved.file_id}],
        keep_existing_attachments=True,
    )
    call_kwargs = service.users.return_value.drafts.return_value.update.call_args.kwargs
    parsed = parse_raw_mime_message(call_kwargs["body"]["message"]["raw"])
    names = [a["filename"] for a in parsed["attachments"]]
    assert "old.txt" not in names
    assert any("nowy_plik" in n for n in names)


@pytest.mark.asyncio
async def test_update_no_double_signature():
    sig = "<div class='sig'>-- Signature</div>"
    body_with_sig = f"Hello<br>{sig}"
    msg = EmailMessage(policy=SMTP)
    msg["Subject"] = "S"
    msg["To"] = "a@example.com"
    msg.set_content("plain")
    msg.add_alternative(body_with_sig, subtype="html")
    raw = base64.urlsafe_b64encode(msg.as_bytes(policy=SMTP)).decode()

    service = MagicMock()
    service.users().drafts().get().execute.return_value = {
        "id": "d1",
        "message": {"id": "m1", "threadId": "t1", "raw": raw},
    }
    service.users().drafts().update().execute.return_value = {"id": "d1"}

    with patch(
        "gmail.gmail_tools._get_send_as_signature_html_for_tool",
        new=AsyncMock(return_value=sig),
    ):
        await _unwrap(update_gmail_draft)(
            service,
            "me@example.com",
            draft_id="d1",
            body=body_with_sig,
            body_format="html",
            include_signature=True,
        )
    call_kwargs = service.users.return_value.drafts.return_value.update.call_args.kwargs
    parsed = parse_raw_mime_message(call_kwargs["body"]["message"]["raw"])
    assert parsed["body"].count(sig) == 1


@pytest.mark.asyncio
async def test_list_gmail_drafts_summary():
    service = MagicMock()
    service.users().drafts().list().execute.return_value = {
        "drafts": [{"id": "d1", "message": {"id": "m1", "threadId": "t1"}}]
    }
    service.users().drafts().get().execute.return_value = {
        "id": "d1",
        "message": {
            "id": "m1",
            "threadId": "t1",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Subj"},
                    {"name": "To", "value": "to@x"},
                    {"name": "Date", "value": "Thu, 1 Oct 2026"},
                ],
                "parts": [
                    {
                        "filename": "a.pdf",
                        "mimeType": "application/pdf",
                        "body": {"attachmentId": "att1", "size": 10},
                    }
                ],
            },
        },
    }
    result = await _unwrap(list_gmail_drafts)(
        service, "me@example.com", query=None, page_size=10
    )
    assert "draft_id=d1" in result
    assert "message_id=m1" in result
    assert "thread_id=t1" in result
    assert "Subj" in result
    assert "a.pdf" in result


@pytest.mark.asyncio
async def test_delete_gmail_draft_permanent():
    service = MagicMock()
    service.users().drafts().delete().execute.return_value = None
    result = await _unwrap(delete_gmail_draft)(service, "me@example.com", draft_id="d9")
    assert "permanently deleted" in result.lower()
    assert "d9" in result
    service.users().drafts().delete.assert_called()


@pytest.mark.asyncio
async def test_attachment_id_resolves_into_mime(isolated_storage):
    saved = isolated_storage.save_attachment_bytes(
        "zażółć gęślą jaźń".encode("utf-8"),
        filename="notatka_żółć.txt",
        mime_type="text/plain",
    )
    resolved = await _resolve_url_attachments(
        [{"attachment_id": saved.file_id}],
        user_google_email="me@example.com",
    )
    assert resolved[0]["_resolved_bytes"].decode("utf-8").startswith("zażółć")
    assert "żółć" in resolved[0]["filename"]

    raw, _, count, errs = _prepare_gmail_message(
        subject="S",
        body="B",
        to="a@x",
        attachments=resolved,
    )
    assert count == 1
    assert not errs
    parsed = parse_raw_mime_message(raw)
    assert any("żółć" in a["filename"] for a in parsed["attachments"])


@pytest.mark.asyncio
async def test_drive_file_id_resolves(monkeypatch):
    async def fake_download(_svc, file_id):
        assert file_id == "drive123"
        return b"%PDF-1.4", "Dokument.pdf", "application/pdf"

    monkeypatch.setattr(
        "gmail.draft_helpers.download_drive_file_bytes", fake_download
    )

    async def fake_auth(*_a, **_k):
        return MagicMock(), "me@example.com"

    monkeypatch.setattr(
        "auth.google_auth.get_authenticated_google_service", fake_auth
    )

    resolved = await _resolve_url_attachments(
        [{"drive_file_id": "drive123"}],
        user_google_email="me@example.com",
        tool_name="test",
    )
    assert resolved[0]["filename"] == "Dokument.pdf"
    assert resolved[0]["_resolved_bytes"].startswith(b"%PDF")


def test_path_outside_managed_mentions_attachment_id(tmp_path, monkeypatch):
    import core.attachment_storage as storage_module

    monkeypatch.setattr(storage_module, "STORAGE_DIR", tmp_path / "managed")
    (tmp_path / "managed").mkdir()
    outside = tmp_path / "elsewhere" / "x.pdf"
    outside.parent.mkdir()
    outside.write_bytes(b"x")
    with pytest.raises(ValueError) as exc:
        validate_file_path(str(outside))
    msg = str(exc.value)
    assert "attachment_id" in msg
    assert "drive_file_id" in msg
    assert str(tmp_path / "managed") in msg


def test_upload_requires_bearer(isolated_storage, monkeypatch):
    monkeypatch.setenv("GOOGLE_MCP_BEARER_TOKEN", "secret-token")
    app = Starlette(routes=[Route("/attachments", upload_attachment, methods=["POST"])])
    client = TestClient(app)
    files = {"file": ("doc.pdf", b"%PDF-demo", "application/pdf")}
    r = client.post("/attachments", files=files)
    assert r.status_code == 401

    r_ok = client.post(
        "/attachments",
        files=files,
        headers={"Authorization": "Bearer secret-token"},
    )
    assert r_ok.status_code == 201
    data = r_ok.json()
    assert data["attachment_id"]
    assert data["filename"]
    assert "path" in data


def test_upload_too_large_413(isolated_storage, monkeypatch):
    monkeypatch.setenv("GOOGLE_MCP_BEARER_TOKEN", "secret-token")
    app = Starlette(routes=[Route("/attachments", upload_attachment, methods=["POST"])])
    client = TestClient(app)
    big = b"x" * (MAX_UPLOAD_BYTES + 1)
    r = client.post(
        "/attachments",
        files={"file": ("big.bin", big, "application/octet-stream")},
        headers={"Authorization": "Bearer secret-token"},
    )
    assert r.status_code == 413
