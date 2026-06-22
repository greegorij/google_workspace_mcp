"""Regression test for OAuth incremental authorization (sesja 490).

When an account that already authorized some scopes (e.g. Gmail) re-consents to add
a new scope (e.g. Calendar), Google must return an access token covering the UNION of
all previously-granted scopes — otherwise the narrowly-scoped token cannot call the
userinfo API in handle_auth_callback (no openid/userinfo.email), the callback raises
"Failed to get user email for identification" and returns HTTP 500. The visible symptom
is a misleading "Invalid or expired OAuth state parameter" on the browser retry.

The fix is passing include_granted_scopes="true" to flow.authorization_url().
"""

import pytest

import auth.google_auth as google_auth


@pytest.mark.asyncio
async def test_start_auth_flow_requests_include_granted_scopes(monkeypatch):
    captured = {}

    class FakeFlow:
        code_verifier = "verifier"

        def authorization_url(self, **kwargs):
            captured.update(kwargs)
            return "https://accounts.google.com/o/oauth2/auth?fake=1", "state"

    def fake_create_oauth_flow(scopes, redirect_uri, state, **kwargs):  # noqa: ARG001
        return FakeFlow()

    async def fake_determine_prompt(**kwargs):  # noqa: ARG001
        return "consent"

    class FakeStore:
        def __init__(self):
            self.stored = {}

        def store_oauth_state(self, state, **kwargs):
            self.stored["state"] = state
            self.stored.update(kwargs)

    monkeypatch.setattr(google_auth, "get_current_scopes", lambda: ["openid"])
    monkeypatch.setattr(google_auth, "create_oauth_flow", fake_create_oauth_flow)
    monkeypatch.setattr(google_auth, "get_fastmcp_session_id", lambda: "sess-1")
    monkeypatch.setattr(google_auth, "_determine_oauth_prompt", fake_determine_prompt)
    monkeypatch.setattr(google_auth, "get_oauth21_session_store", lambda: FakeStore())

    message = await google_auth.start_auth_flow(
        user_google_email="grzegorz.gie@gmail.com",
        service_name="Google Calendar",
        redirect_uri="https://google.example.com/oauth2callback",
    )

    # The core regression assertion: incremental scopes must be requested.
    assert captured.get("include_granted_scopes") == "true"
    # And the existing offline/consent behaviour must be preserved.
    assert captured.get("access_type") == "offline"
    assert captured.get("prompt") == "consent"
    assert "accounts.google.com" in message
