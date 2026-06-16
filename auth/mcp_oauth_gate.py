"""Adapter bramy tożsamości Google dla google-mcp — cienka warstwa nad wendorowaną bramą.

Cała logika OAuth (authorization_code + PKCE) i brama tożsamości Google żyją w
`auth.mcp_oauth.McpOAuthGate` (wendorowana kopia workos_shared — JEDEN mechanizm dla
wszystkich serwerów MCP, kanon GOLDEN-PATTERNS Wzorzec 9). Ten moduł tylko:

1. Buduje instancję bramy z env `GOOGLE_MCP_GATE_*` (klient Google, allowlista e-maili,
   base-url) + `GOOGLE_MCP_BEARER_TOKEN` jako master-token (token wydawany po logowaniu
   Google = dokładnie ten, którego Caddy już pilnuje na bramie).
2. Dokłada fork-owy rate-limit per-IP na publicznych wejściach OAuth (audyt s1099 S77/S81)
   — komponent celowo go nie ma (różne usługi mają różne progi).
3. Eksponuje `register_gate_routes(server)` (montuje trasy na FastMCP przez custom_route)
   i `OPEN_PATHS` (wyjątek bearer-auth, egzekwowany na warstwie Caddy).

🔴 KOLIZJA NAZW ENV (s1286): serwer używa GOOGLE_OAUTH_CLIENT_ID/SECRET dla WŁASNEGO OAuth
do Google Workspace API (Gmail/Calendar). Klient bramy to INNY (współdzielony MCP) klient,
więc env bramy mają osobne nazwy GOOGLE_MCP_GATE_* — żeby się nie nadpisać.

FAIL-CLOSED bez konfiguracji bramy: `/oauth/authorize` zwraca 503, dopóki nie ustawisz
klienta Google + allowlisty e-maili. Brama jest niezależna od natywnego OAuth21 FastMCP —
montuje się zawsze (gdy transport = streamable-http), to tylko trasy Starlette.
"""

from __future__ import annotations

import os
import time

from starlette.requests import Request
from starlette.responses import JSONResponse

from .mcp_oauth import McpOAuthGate

# Allowlista adresów powrotnych OAuth (exact match). Bez tego ktokolwiek mógłby poprowadzić
# /oauth/authorize i dostarczyć kod na host atakującego (KRYT, audyt s693). Konfigurowalne
# env (przecinki); domyślnie callback konektora MCP claude.ai.
REDIRECT_ALLOWLIST = frozenset(
    u.strip()
    for u in os.environ.get(
        "GOOGLE_MCP_GATE_REDIRECT_ALLOWLIST",
        "https://claude.ai/api/mcp/auth_callback",
    ).split(",")
    if u.strip()
)

# Rate-limit publicznych wejść OAuth per-IP (audyt s1099 S77/S81). Konfigurowalne env.
RATE_LIMIT_OAUTH_PER_MIN = int(os.environ.get("GOOGLE_MCP_GATE_RATELIMIT", "20"))


def _build_gate() -> McpOAuthGate:
    """Brama z bieżącego env. Wydzielone, by testy mogły zbudować wariant z bramą włączoną."""
    return McpOAuthGate(
        service_name="google-mcp",
        # Master-token = ten sam Bearer, którego Caddy już pilnuje na bramie. Po logowaniu
        # Google wydajemy DOKŁADNIE ten token (egzekucja bearer zostaje w Caddy, nie w app).
        master_token=os.environ.get("GOOGLE_MCP_BEARER_TOKEN", ""),
        public_base=os.environ.get("GOOGLE_MCP_GATE_BASE_URL", ""),
        resource_path="/mcp",
        redirect_allowlist=REDIRECT_ALLOWLIST,
        google_client_id=os.environ.get("GOOGLE_MCP_GATE_CLIENT_ID", ""),
        google_client_secret=os.environ.get("GOOGLE_MCP_GATE_SECRET", ""),
        google_redirect_uri=os.environ.get("GOOGLE_MCP_GATE_REDIRECT_URI", ""),
        allowed_emails=[
            e.strip().lower()
            for e in os.environ.get("GOOGLE_MCP_GATE_ALLOWED_EMAILS", "").split(",")
            if e.strip()
        ],
        dev_insecure=os.environ.get("GOOGLE_MCP_GATE_DEV_INSECURE", "") == "1",
    )


# Instancja modułowa — trasy referują ją DYNAMICZNIE (przez nazwę globalną), więc test może
# podmienić `mcp_oauth_gate._GATE` na wariant z włączoną bramą bez przebudowy tras.
_GATE = _build_gate()

# Ścieżki zwolnione z bearer-auth (pre-auth flow OAuth + odkrywania). Wyprowadzone z bramy
# — single source, obejmuje /oauth/google/callback (nowy w s1286).
OPEN_PATHS = _GATE.open_paths

# Guard idempotencji rejestracji tras (wzorzec _ensure_legacy_callback_route w core/server).
_registered = False

# ── rate-limit per-IP publicznych wejść OAuth (audyt s1099 S77/S81) ────────────
_OAUTH_WINDOW_S = 60
_oauth_hits: dict[str, list[float]] = {}


def _client_ip(request: Request) -> str:
    """Realny adres za Caddy z X-Forwarded-For (port bindowany na loopback)."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _oauth_rate_limited(request: Request) -> bool:
    """True gdy IP przekroczył limit żądań OAuth w oknie 60 s (S77/S81)."""
    ip = _client_ip(request)
    cutoff = time.time() - _OAUTH_WINDOW_S
    for key in list(_oauth_hits):
        fresh = [t for t in _oauth_hits[key] if t > cutoff]
        if fresh:
            _oauth_hits[key] = fresh
        else:
            del _oauth_hits[key]
    hits = _oauth_hits.setdefault(ip, [])
    hits.append(time.time())
    return len(hits) > RATE_LIMIT_OAUTH_PER_MIN


# Wrappery referują `_GATE` dynamicznie (nie wiążą bound-method przy konstrukcji trasy).
# Discovery (metadata/protected) NIE limitowane — claude.ai odpytuje je często przy odkrywaniu.
async def _metadata(request: Request):
    return await _GATE.metadata(request)


async def _protected_resource(request: Request):
    return await _GATE.protected_resource(request)


async def _authorize(request: Request):
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    return await _GATE.authorize(request)


async def _google_callback(request: Request):
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    return await _GATE.google_callback(request)


async def _token(request: Request):
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    return await _GATE.token(request)


async def _register(request: Request):
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    return await _GATE.register(request)


# Mapowanie ścieżka bramy → (methody, wrapper adaptera). Methody jawne (nie z `route.methods`,
# bo Starlette auto-dokłada tam HEAD do seta — chcemy dokładnie to, co definiuje brama).
# Discovery (metadata/protected_resource) montowane plain; authorize/token/register/google-callback
# owinięte rate-limitem.
_HANDLERS = {
    "/.well-known/oauth-authorization-server": (["GET"], _metadata),
    "/.well-known/oauth-protected-resource": (["GET"], _protected_resource),
    "/.well-known/oauth-protected-resource/mcp": (["GET"], _protected_resource),
    "/oauth/authorize": (["GET", "POST"], _authorize),
    "/oauth/google/callback": (["GET"], _google_callback),
    "/oauth/token": (["POST"], _token),
    "/oauth/register": (["POST"], _register),
}


def register_gate_routes(server) -> None:
    """Montuje trasy bramy na serwerze FastMCP przez `server.custom_route` (idempotentnie).

    Wzorzec jak `_ensure_legacy_callback_route` w core/server.py — guard `_registered`
    chroni przed podwójną rejestracją. Ścieżki bierzemy z `_GATE.routes` (single source),
    methody z `_HANDLERS` (jawne), a handler podmieniamy na wrapper adaptera (rate-limit +
    dynamiczna referencja do `_GATE`, żeby testy mogły go podmienić)."""
    global _registered
    if _registered:
        return
    for route in _GATE.routes:
        methods, handler = _HANDLERS[route.path]
        server.custom_route(route.path, methods=methods)(handler)
    _registered = True
