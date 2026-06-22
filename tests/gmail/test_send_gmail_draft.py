import os
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from gmail.gmail_tools import send_gmail_draft


def _unwrap(tool):
    """Unwrap FunctionTool + decorators to the original async function."""
    fn = tool.fn if hasattr(tool, "fn") else tool
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    return fn


@pytest.mark.asyncio
async def test_send_gmail_draft_sends_by_id_and_returns_message_id():
    mock_service = Mock()
    mock_service.users().drafts().send().execute.return_value = {"id": "sent_msg_123"}

    result = await _unwrap(send_gmail_draft)(
        service=mock_service,
        user_google_email="user@example.com",
        draft_id="r-draft-456",
    )

    assert "Draft sent! Message ID: sent_msg_123" in result

    send_kwargs = (
        mock_service.users.return_value.drafts.return_value.send.call_args.kwargs
    )
    assert send_kwargs["userId"] == "me"
    assert send_kwargs["body"] == {"id": "r-draft-456"}


@pytest.mark.asyncio
async def test_send_gmail_draft_handles_missing_message_id():
    """If the API response lacks an id, return should still be well-formed."""
    mock_service = Mock()
    mock_service.users().drafts().send().execute.return_value = {}

    result = await _unwrap(send_gmail_draft)(
        service=mock_service,
        user_google_email="user@example.com",
        draft_id="r-draft-789",
    )

    assert "Draft sent! Message ID: None" in result
