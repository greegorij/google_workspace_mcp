"""Testy bramy tożsamości Google dla google-mcp (s1286).

Wzorowane na testach bramy vikunja-mcp (workos/tests/test_vikunja_mcp.py). Brama to
samodzielne trasy Starlette — dla testów zachowania budujemy aplikację wprost z
`gate.routes` (lub z wrapperów adaptera dla rate-limitu), bez pełnej aplikacji FastMCP.

Pokrycie:
- fail-closed bez konfiguracji (503),
- redirect → Google gdy brama skonfigurowana (302 na accounts.google.com),
- /oauth/google/callback w OPEN_PATHS,
- rate-limit per-IP (429),
- trasy odkrywania (/.well-known/*) zwrócone 200,
- register_gate_routes montuje trasy na serwerze (idempotentnie).
"""

import base64
import hashlib
import secrets

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from auth import mcp_oauth_gate as gate
from auth.mcp_oauth import McpOAuthGate

ALLOWED_REDIRECT = "https://claude.ai/api/mcp/auth_callback"


def _pkce():
    v = secrets.token_urlsafe(64)
    c = (
        base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return v, c


def _authorize_params(challenge):
    return {
        "response_type": "code",
        "client_id": "c",
        "redirect_uri": ALLOWED_REDIRECT,
        "state": "s",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


def _gated_gate() -> McpOAuthGate:
    """Brama w pełni skonfigurowana (4 elementy) → identity_gate_enabled = True."""
    return McpOAuthGate(
        service_name="google-mcp",
        master_token="secret",
        public_base="https://google.grzegorzgolas.com",
        redirect_allowlist={ALLOWED_REDIRECT},
        google_client_id="g",
        google_client_secret="s",
        google_redirect_uri="https://google.grzegorzgolas.com/oauth/google/callback",
        allowed_emails={"gg@example.com"},
    )


# ── testy zachowania bramy (aplikacja z gate.routes wprost) ───────────────────


def test_fail_closed_without_config():
    """Brama nieskonfigurowana → /oauth/authorize fail-closed 503 (nie auto-approve)."""
    bare = McpOAuthGate(
        service_name="google-mcp",
        master_token="secret",
        public_base="https://google.grzegorzgolas.com",
        redirect_allowlist={ALLOWED_REDIRECT},
    )
    assert bare.identity_gate_enabled is False
    app = Starlette(routes=bare.routes)
    c = TestClient(app, base_url="https://testserver")
    _, ch = _pkce()
    r = c.get("/oauth/authorize", params=_authorize_params(ch), follow_redirects=False)
    assert r.status_code == 503


def test_authorize_redirects_to_google_when_gated():
    """Brama skonfigurowana → /oauth/authorize przekierowuje do logowania Google (302)."""
    app = Starlette(routes=_gated_gate().routes)
    c = TestClient(app, base_url="https://testserver")
    _, ch = _pkce()
    r = c.get("/oauth/authorize", params=_authorize_params(ch), follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith(
        "https://accounts.google.com/o/oauth2/v2/auth"
    )


def test_google_callback_in_open_paths():
    """Callback Google zwolniony z bearer-auth (musi być w OPEN_PATHS)."""
    assert "/oauth/google/callback" in gate.OPEN_PATHS
    # OPEN_PATHS wyprowadzone z bramy — single source.
    assert "/oauth/google/callback" in _gated_gate().open_paths


def test_discovery_routes_return_200():
    """Trasy odkrywania (/.well-known/*) publiczne i 200 — claude.ai je odpytuje."""
    app = Starlette(routes=_gated_gate().routes)
    c = TestClient(app, base_url="https://testserver")
    assert c.get("/.well-known/oauth-authorization-server").status_code == 200
    assert c.get("/.well-known/oauth-protected-resource").status_code == 200
    assert c.get("/.well-known/oauth-protected-resource/mcp").status_code == 200


# ── rate-limit per-IP (przez wrappery adaptera) ───────────────────────────────


def test_oauth_rate_limit(monkeypatch):
    """Wrappery adaptera (authorize/token/...) limitują per-IP; discovery NIE limitowane."""
    monkeypatch.setattr(gate, "RATE_LIMIT_OAUTH_PER_MIN", 3)
    monkeypatch.setattr(gate, "_GATE", _gated_gate())
    gate._oauth_hits.clear()
    # Aplikacja z wrapperów adaptera (te mają rate-limit), nie z gołych gate.routes.
    app = Starlette(
        routes=[
            Route("/oauth/authorize", gate._authorize, methods=["GET", "POST"]),
            Route(
                "/.well-known/oauth-authorization-server",
                gate._metadata,
                methods=["GET"],
            ),
        ]
    )
    c = TestClient(app, base_url="https://testserver")
    _, ch = _pkce()
    codes = [
        c.get(
            "/oauth/authorize",
            params=_authorize_params(ch),
            follow_redirects=False,
        ).status_code
        for _ in range(5)
    ]
    assert 429 in codes
    # discovery NIE limitowane
    assert c.get("/.well-known/oauth-authorization-server").status_code == 200


# ── register_gate_routes — montowanie na serwerze (stub custom_route) ─────────


class _StubServer:
    """Imituje SecureFastMCP.custom_route(path, methods=...)(handler) — zbiera rejestracje."""

    def __init__(self):
        self.registered = []

    def custom_route(self, path, methods):
        def deco(handler):
            self.registered.append((path, tuple(methods), handler))
            return handler

        return deco


def test_register_gate_routes_mounts_all_and_is_idempotent(monkeypatch):
    monkeypatch.setattr(gate, "_registered", False)
    srv = _StubServer()
    gate.register_gate_routes(srv)
    paths = {p for p, _m, _h in srv.registered}
    assert paths == {
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/oauth/authorize",
        "/oauth/google/callback",
        "/oauth/token",
        "/oauth/register",
    }
    # methody jawne (bez auto-HEAD seta Starlette)
    by_path = {p: m for p, m, _h in srv.registered}
    assert by_path["/oauth/authorize"] == ("GET", "POST")
    assert by_path["/oauth/token"] == ("POST",)
    assert by_path["/.well-known/oauth-authorization-server"] == ("GET",)
    # idempotencja — drugie wywołanie nic nie dokłada
    n = len(srv.registered)
    gate.register_gate_routes(srv)
    assert len(srv.registered) == n


def test_register_gate_routes_wraps_oauth_with_ratelimit(monkeypatch):
    """authorize/token/register/google-callback owinięte rate-limitem; discovery plain."""
    monkeypatch.setattr(gate, "_registered", False)
    srv = _StubServer()
    gate.register_gate_routes(srv)
    handlers = {p: h for p, _m, h in srv.registered}
    # rate-limitowane wrappery
    assert handlers["/oauth/authorize"] is gate._authorize
    assert handlers["/oauth/token"] is gate._token
    assert handlers["/oauth/register"] is gate._register
    assert handlers["/oauth/google/callback"] is gate._google_callback
    # discovery plain (bez rate-limitu)
    assert handlers["/.well-known/oauth-authorization-server"] is gate._metadata
    assert handlers["/.well-known/oauth-protected-resource"] is gate._protected_resource


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
