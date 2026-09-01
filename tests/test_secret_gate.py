from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parents[1]
MODULE_PATH = REPO_ROOT / ".github" / "scripts" / "secret_gate.py"
SPEC = importlib.util.spec_from_file_location("secret_gate", MODULE_PATH)
assert SPEC and SPEC.loader
secret_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = secret_gate
SPEC.loader.exec_module(secret_gate)


def test_reviewed_history_baseline_is_exact_and_complete() -> None:
    assert sum(secret_gate.HISTORY_BASELINE.values()) == 20
    secret_gate.enforce("history", secret_gate.HISTORY_BASELINE.copy(), 183)


def test_history_rejects_extra_or_missing_findings() -> None:
    exact = secret_gate.HISTORY_BASELINE.copy()
    sample = next(iter(exact))
    extra = exact.copy()
    extra[
        secret_gate.FindingKey(
            "Unexpected", sample.commit, sample.path, sample.line, sample.raw_sha256
        )
    ] += 1
    with pytest.raises(secret_gate.GateError, match="unexpected=1"):
        secret_gate.enforce("history", extra, 183)

    missing = exact.copy()
    missing[sample] -= 1
    if not missing[sample]:
        del missing[sample]
    with pytest.raises(secret_gate.GateError, match="missing=1"):
        secret_gate.enforce("history", missing, 183)


def test_diff_rejects_every_finding_and_accepts_empty_scan() -> None:
    secret_gate.enforce("diff", Counter(), 0)
    sample = next(iter(secret_gate.HISTORY_BASELINE))
    with pytest.raises(secret_gate.GateError, match="contains 1"):
        secret_gate.enforce("diff", Counter({sample: 1}), 183)


def test_scanner_error_or_exit_mismatch_is_fail_closed() -> None:
    with pytest.raises(secret_gate.GateError, match="scanner failed"):
        secret_gate.enforce("diff", Counter(), 2)
    with pytest.raises(secret_gate.GateError, match="disagree"):
        secret_gate.enforce("diff", Counter(), 183)


def test_jsonl_parser_hashes_raw_without_printing_it(tmp_path: Path) -> None:
    value = "synthetic-value-for-parser-test"
    record = {
        "DetectorName": "Synthetic",
        "Raw": value,
        "SourceMetadata": {
            "Data": {
                "Git": {
                    "commit": "a" * 40,
                    "file": "tests/fixture.txt",
                    "line": 7,
                }
            }
        },
    }
    path = tmp_path / "findings.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    findings = secret_gate.load_findings(path)
    key = next(iter(findings))
    assert key.detector == "Synthetic"
    assert value not in repr(key)


def test_jsonl_parser_rejects_malformed_or_unsafe_metadata(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text("{not-json}\n", encoding="utf-8")
    with pytest.raises(secret_gate.GateError, match="malformed"):
        secret_gate.load_findings(malformed)

    unsafe = tmp_path / "unsafe.jsonl"
    unsafe.write_text(
        json.dumps(
            {
                "DetectorName": "Synthetic",
                "Raw": "value",
                "SourceMetadata": {
                    "Data": {
                        "Git": {"commit": "b" * 40, "file": "../secret", "line": 1}
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(secret_gate.GateError, match="unsafe path"):
        secret_gate.load_findings(unsafe)

    undecodable = tmp_path / "undecodable.jsonl"
    undecodable.write_bytes(b"\xff\n")
    with pytest.raises(secret_gate.GateError, match="cannot read scanner output"):
        secret_gate.load_findings(undecodable)
