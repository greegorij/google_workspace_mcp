# Fork GG — różnice względem upstream

**Cel:** jedna kartka o tym, czym ten fork (`greegorij/google_workspace_mcp`) różni się od
upstream [`taylorwilsdon/google_workspace_mcp`](https://github.com/taylorwilsdon/google_workspace_mcp).  
**Dla kogo:** operator VPS / agent wdrażający / kto synchronizuje z upstream.  
**Stan na:** 2026-10-01 · gałąź `main` forka (po scaleniu GG-1442).

Upstream README poniżej nadal opisuje ogólne API Workspace MCP. **Operacyjne różnice forka
są tylko tutaj** — nie w osobnych gałęziach feature (po scaleniu żyją na `main`).

## Co dodaje fork

| Obszar | Opis |
|---|---|
| Brama tożsamości OAuth | `auth/mcp_oauth_gate.py` — przed dostępem do `/mcp` wymaga logowania Google + allowlisty e-maili; master-token to ten sam bearer co Caddy |
| `send_gmail_draft` | wysyłka istniejącego szkicu po ID |
| `list_gmail_drafts` / `update_gmail_draft` / `delete_gmail_draft` | lista / edycja / trwałe usunięcie szkiców |
| `POST /attachments` | upload multipart → `attachment_id` (bez base64 w tool call); limit **25 MB**, ważność domyślnie **1 h** |
| `drive_file_id` | załącznik ze wskazanego pliku Drive (Docs/Sheets/Slides jak eksport w narzędziach Drive) |
| `SO_REUSEADDR` | sonda/bind portu w `main.py` / `auth/port_resolver.py` — mniej fałszywych „port zajęty” po szybkim restarcie (TIME_WAIT) |

## Zmienne środowiskowe (nazwy — bez wartości)

| Nazwa | Rola |
|---|---|
| `GOOGLE_MCP_BEARER_TOKEN` | Bearer dla `/mcp` i `POST /attachments` (fail-closed gdy pusty) |
| `GOOGLE_MCP_GATE_BASE_URL` | Publiczny base URL bramy |
| `GOOGLE_MCP_GATE_CLIENT_ID` | OAuth client id bramy |
| `GOOGLE_MCP_GATE_SECRET` | OAuth client secret bramy |
| `GOOGLE_MCP_GATE_REDIRECT_URI` | Redirect URI bramy |
| `GOOGLE_MCP_GATE_ALLOWED_EMAILS` | Allowlista e-maili (csv) |
| `GOOGLE_MCP_GATE_REDIRECT_ALLOWLIST` | Allowlista redirectów |
| `GOOGLE_MCP_GATE_RATELIMIT` | Limit żądań OAuth / min (domyślnie 20) |
| `GOOGLE_MCP_GATE_DEV_INSECURE` | `1` = tryb deweloperski (nie używać na VPS) |
| `WORKSPACE_ATTACHMENT_DIR` | Katalog managed attachments (upload + download) |
| `ALLOWED_FILE_DIRS` | Opcjonalna rozszerzona allowlista ścieżek lokalnych (ostrożnie) |

Pełna lista env upstream (OAuth Workspace, credentials dir, …) zostaje w `README.md`.

## Wdrożenie na VPS

- Katalog: `~/google-mcp` (klon forka, nie osobnego drzewa patchy).
- Aktualizacja:

```bash
cd ~/google-mcp
git fetch origin
git pull --ff-only origin main
```

- Restart usługi: **`stop` → `start`**, nie `restart`.
  Szybki `restart` na porcie **8771** bywa wyścigiem z TIME_WAIT / starą sondą
  (`SO_REUSEADDR` łagodzi, ale kolejność stop→start jest kanoniczna).

```bash
sudo systemctl stop google-mcp.service
sudo systemctl start google-mcp.service
sudo systemctl status google-mcp.service --no-pager
```

Publiczny front: Caddy → `127.0.0.1:8771` (domena `google.grzegorzgolas.com`).

## Synchronizacja z upstream

1. `git remote add upstream https://github.com/taylorwilsdon/google_workspace_mcp.git` (raz).
2. `git fetch upstream`.
3. Scalaj `upstream/main` do lokalnej gałęzi roboczej → PR do `greegorij/...` `main`.
4. Po konflikcie w strefach forka (`auth/mcp_oauth_gate.py`, `core/attachment_upload.py`,
   draft tools w `gmail/`) **zachowuj zachowanie forka**; resztę bierz z upstream.
5. Nie utrzymuj długo żyjących gałęzi `feat/*` na origin — po odbiorze scalaj do `main`
   i usuwaj (unikaj martwych odwołań w docs).

## Czego tu nie ma

- Wartości sekretów / treści `.env`.
- Instrukcji `sudo` poza `systemctl stop|start|status`.
- Opisu scalania PR — to orkiestrator / człowiek.
