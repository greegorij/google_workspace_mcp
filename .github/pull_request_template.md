## Summary

Describe the problem and the smallest change that solves it.

## Verification

- [ ] `uv run pytest -m "not integration"`
- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] Docker Compose and the amd64 image were validated when relevant
- [ ] Documentation and examples reflect the final behavior
- [ ] No credentials, local environment files, caches, or build artifacts are included
- [ ] For a fork pull request, **Allow edits from maintainers** is enabled

## Operational impact

- GitHub Actions runs/jobs and timeout impact:
- Cache, artifact, registry, package, release, or deployment impact:
- Follow-up work or known limitations:
