"""Security and cost contract for the consolidated GitHub Actions workflow."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Tuple

import yaml

REPO_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW_PATH: str = os.path.join(REPO_ROOT, ".github", "workflows", "ci.yml")
SHA_PIN = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def load_workflow(path: str) -> Tuple[Dict[str, Any], str]:
    with open(path, encoding="utf-8") as stream:
        raw = stream.read()
    parsed: Dict[str, Any] = yaml.safe_load(raw)
    return parsed, raw


def _has_write_permission(permissions: Any) -> bool:
    if isinstance(permissions, str):
        return permissions == "write-all"
    if isinstance(permissions, dict):
        return any(value == "write" for value in permissions.values())
    return False


def test_no_fork_repository_checkout() -> None:
    workflow, _ = load_workflow(WORKFLOW_PATH)
    for job_name, job in workflow.get("jobs", {}).items():
        for step in job.get("steps", []):
            uses = str(step.get("uses", ""))
            if "actions/checkout" not in uses:
                continue
            parameters = step.get("with", {})
            assert "pull_request.head.repo" not in str(
                parameters.get("repository", "")
            ), job_name


def test_workflow_is_read_only_and_checkout_drops_credentials() -> None:
    workflow, _ = load_workflow(WORKFLOW_PATH)
    assert not _has_write_permission(workflow.get("permissions", {}))
    for job_name, job in workflow.get("jobs", {}).items():
        assert not _has_write_permission(job.get("permissions", {})), job_name
        for step in job.get("steps", []):
            if "actions/checkout" in str(step.get("uses", "")):
                assert step.get("with", {}).get("persist-credentials") is False, (
                    job_name
                )


def test_fork_pull_requests_require_maintainer_edits_without_api_access() -> None:
    workflow, raw = load_workflow(WORKFLOW_PATH)
    steps = workflow["jobs"]["test"]["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name") == "Require maintainer edits for fork pull requests"
    )
    assert "head.repo.fork == true" in str(gate.get("if", ""))
    assert gate.get("env", {}).get("MAINTAINER_CAN_MODIFY")
    assert 'test "$MAINTAINER_CAN_MODIFY" = "true"' in str(gate.get("run", ""))
    assert "actions/github-script" not in raw
    assert "createComment" not in raw


def test_pull_request_and_main_jobs_match_the_cost_contract() -> None:
    workflow, _ = load_workflow(WORKFLOW_PATH)
    workflow_on: Any = workflow.get("on", workflow.get(True, {}))
    assert set(workflow_on) == {"pull_request", "push"}
    assert workflow_on["pull_request"]["branches"] == ["main"]
    assert workflow_on["push"]["branches"] == ["main"]

    jobs = workflow.get("jobs", {})
    assert set(jobs) == {"test", "ruff", "docker-validate", "secret-scan"}
    for name in ("test", "ruff", "docker-validate"):
        assert "github.event_name == 'pull_request'" in str(jobs[name].get("if", ""))
    assert "if" not in jobs["secret-scan"]

    pr_ceiling = sum(int(jobs[name]["timeout-minutes"]) for name in jobs)
    main_ceiling = int(jobs["secret-scan"]["timeout-minutes"])
    assert pr_ceiling == 40
    assert main_ceiling == 5
    assert pr_ceiling + main_ceiling == 45


def test_concurrency_cancels_only_superseded_pull_request_runs() -> None:
    workflow, _ = load_workflow(WORKFLOW_PATH)
    concurrency = workflow.get("concurrency", {})
    group = str(concurrency.get("group", ""))
    cancellation = str(concurrency.get("cancel-in-progress", ""))
    assert "github.event.pull_request.number" in group
    assert "github.ref" in group
    assert "github.event_name == 'pull_request'" in cancellation


def test_actions_are_sha_pinned_and_runners_are_standard_linux() -> None:
    workflow, raw = load_workflow(WORKFLOW_PATH)
    assert "self-hosted" not in raw
    assert "matrix:" not in raw
    for job in workflow.get("jobs", {}).values():
        assert job.get("runs-on") == "ubuntu-24.04"
        for step in job.get("steps", []):
            uses = step.get("uses")
            if uses:
                assert SHA_PIN.fullmatch(str(uses)), uses


def test_main_path_has_only_secret_scan_and_no_publish_or_cache() -> None:
    workflow, raw = load_workflow(WORKFLOW_PATH)
    for name in ("test", "ruff", "docker-validate"):
        assert "pull_request" in str(workflow["jobs"][name].get("if", ""))
    forbidden = (
        "self-hosted",
        "upload-artifact",
        "cache-to:",
        "cache-from:",
        "docker/login-action",
        "gh-action-pypi-publish",
        "mcp-publisher publish",
    )
    assert all(token not in raw for token in forbidden)


def test_docker_validation_is_amd64_and_health_check_is_offline() -> None:
    workflow, _ = load_workflow(WORKFLOW_PATH)
    steps = workflow["jobs"]["docker-validate"]["steps"]
    commands = "\n".join(str(step.get("run", "")) for step in steps)
    assert "docker build --platform linux/amd64" in commands
    assert "docker run --detach --platform linux/amd64 --network none" in commands
    assert "/app/.venv/bin/python main.py --transport streamable-http" in commands
