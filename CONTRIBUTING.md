# Contributing

Thank you for improving Google Workspace MCP.

## Working agreement

1. Create a focused branch from the current `main` branch.
2. Keep credentials out of the repository. Copy `.env.oauth21.example` to `.env` only in your local workspace.
3. Add or update tests for behavior changes and update the README when commands, configuration, or operational behavior changes.
4. Run the checks below before opening a pull request.
5. Open a pull request and wait for all required checks and review conversations to be resolved. Do not push directly to `main`.

## Local checks

Run checks in an environment that does not expose local Google or OAuth credentials:

```bash
env -u GOOGLE_OAUTH_CLIENT_ID \
    -u GOOGLE_OAUTH_CLIENT_SECRET \
    -u GOOGLE_APPLICATION_CREDENTIALS \
    -u FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY \
    uv sync --frozen --extra test --group dev

env -u GOOGLE_OAUTH_CLIENT_ID \
    -u GOOGLE_OAUTH_CLIENT_SECRET \
    -u GOOGLE_APPLICATION_CREDENTIALS \
    -u FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY \
    uv run pytest -m "not integration"

uv run ruff check .
uv run ruff format --check .
docker compose config --quiet
docker build --platform linux/amd64 -t workspace-mcp:local-check .
```

The secret gate is intentionally fail-closed. Pull requests accept no baseline entries. The full-history scan on `main` accepts only the exact, reviewed historical findings encoded in `.github/scripts/secret_gate.py`; a new result, a missing expected result, malformed scanner output, or scanner error stops the job. The baseline records old synthetic examples, placeholders, one revoked GitHub credential, and one already-expired registry token. It is not permission to add similar material.

## Continuous integration contract

Pull requests run four read-only jobs on GitHub-hosted `ubuntu-24.04`: `Test`, `Ruff`, `Docker Validate`, and `Secret Scan`. A push to `main` runs only the full-history `Secret Scan`. The workflow has no publishing, package upload, registry login, write permission, cache, artifact, matrix, or self-hosted runner.

The technical ceiling is two workflow runs and five jobs for one pull-request-and-merge path. Job timeouts sum to 45 minutes: 15 + 5 + 15 + 5 minutes for the pull request and 5 minutes for the `main` scan. These are limits, not a billing guarantee; unrelated automation and account-wide usage remain separate.

A newer update to the same pull request cancels its older in-progress CI run. The `main` history scan has a stable group but is never cancelled by this rule, so a merge cannot silently replace an unfinished history check.
