# Repository instructions

- Read `CONTRIBUTING.md` before changing the repository.
- Work on a feature branch or an isolated worktree. Never push directly to `main`.
- Never commit credentials, local `.env` files, OAuth tokens, generated caches, build output, or editor state.
- Keep code, tests, README guidance, and examples consistent in the same change.
- Before requesting review, run the local checks documented in `CONTRIBUTING.md` with Google and OAuth variables cleared.
- Do not weaken, skip, or expand the historical secret baseline. A new finding or scanner error must stop the change.
- Do not add publishing, package-upload, registry-login, write-token, self-hosted runner, cache, artifact, or matrix jobs without an explicit repository-policy decision.
- GitHub settings, releases, deployments, tags, and workflow runs are maintained by the repository owner; agents prepare local changes only unless given a separate, explicit publication authorization.
