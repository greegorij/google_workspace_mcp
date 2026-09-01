#!/usr/bin/env python3
"""Fail-closed policy for TruffleHog JSONL output.

Pull-request diffs accept no findings. The full-history mode accepts exactly the
reviewed post-revocation multiset below and nothing else. Secret values are never
printed; comparison uses their SHA-256 digests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
RAW_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@dataclass(frozen=True, order=True)
class FindingKey:
    detector: str
    commit: str
    path: str
    line: int
    raw_sha256: str


def _baseline(
    detector: str, commit: str, path: str, line: int, raw_sha256: str
) -> FindingKey:
    return FindingKey(detector, commit, path, line, raw_sha256)


HISTORY_BASELINE = Counter(
    {
        _baseline(
            "FTP",
            "31263e5b5f48643f114774a8b874bf6af6a6d508",
            "tests/gdrive/test_ssrf_protections.py",
            172,
            "e140560686c27695b8f035b6733c81469a8636445bf882919bf4ba6210b69a8a",
        ): 1,
        _baseline(
            "GoogleOauth2",
            "e43766d63395fa09208b5d4f558775fe01ca49cb",
            "google_workspace_mcp.dxt",
            278,
            "178f5d62ec4dec02acd52b61a04acb5670947f1ac732344278eef93f82fcb344",
        ): 1,
        _baseline(
            "Github",
            "7cc281e26a42f4f2d2a2dafed7b8a7838ef2fb8d",
            "google_workspace_mcp.dxt",
            1,
            "0107ed832a98a4d23ccd58bde2df5ef529fcb9e03fb884cc0734351ef315dfb8",
        ): 1,
        _baseline(
            "JWT",
            "7cc281e26a42f4f2d2a2dafed7b8a7838ef2fb8d",
            "google_workspace_mcp.dxt",
            1,
            "98c06062ce91d27c13c34b43cc07f8ca79a2a13edd108b27e7037c84a39d63c2",
        ): 1,
        **{
            _baseline(
                "GCPApplicationDefaultCredentials", commit, path, 1, RAW_EMPTY_SHA256
            ): 1
            for commit, path in (
                (
                    "086c0adef31d742d0ca1e09f3716583f10a314ce",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "1c7354cb5e426947ccbe149b99a1984ddf43f65e",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "20965716c5d86f736fa6c69e3cc79f3da216df5b",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "2434d3bc54702fc505ac643078979c7a2437b805",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "2521694eaa7b5f08eff9aae0ea99a783130c5a9a",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "31e6987010578f48d852d27d2a696ceee45d06ad",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "3eb81e16b09eb46c3e36aaba0d2e97132968d9dd",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "78a458b226b3a0b77cbadbc69711f97a928e0a96",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "91742faca0dcf8f6f47bd7ed8bb9c8cb1120c823",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "9c63e0267c2a47f8c5b72f1d0e134f22f24e26cb",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "a446b721049823b2f9f9d0c5e13d43e9fff4f1f2",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "a60a556359e70763303a88ad80eee1f24f10686c",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "a9625dd71a42a55aae6bf59406c1414a32a0e99f",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "ad198ef2a9bf8d9f1b43fad1588b5a005f8483b2",
                    "google_workspace_mcp.dxt",
                ),
                (
                    "d4b7cab7ab5306129073688ff4359ebdf16147b1",
                    "google_workspace_mcp.dxt",
                ),
                ("fc89a20c643c9ec8b02309dd057922cfbfda71d0", "manifest.json"),
            )
        },
    }
)


class GateError(ValueError):
    pass


def finding_key(record: dict[str, Any]) -> FindingKey:
    detector = record.get("DetectorName")
    raw = record.get("Raw")
    git = record.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
    commit = git.get("commit")
    path = git.get("file")
    line = git.get("line")
    if not isinstance(detector, str) or not detector:
        raise GateError("scanner record has no detector")
    if not isinstance(raw, str):
        raise GateError("scanner record has non-text Raw data")
    if not isinstance(commit, str) or not GIT_SHA.fullmatch(commit):
        raise GateError("scanner record has invalid commit")
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or ".." in Path(path).parts
    ):
        raise GateError("scanner record has unsafe path")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise GateError("scanner record has invalid line")
    return FindingKey(
        detector, commit, path, line, hashlib.sha256(raw.encode("utf-8")).hexdigest()
    )


def load_findings(path: Path) -> Counter[FindingKey]:
    findings: Counter[FindingKey] = Counter()
    try:
        with path.open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise GateError(f"malformed scanner JSON at line {number}") from exc
                if not isinstance(record, dict):
                    raise GateError(f"non-object scanner record at line {number}")
                findings[finding_key(record)] += 1
    except (OSError, UnicodeError) as exc:
        raise GateError("cannot read scanner output") from exc
    return findings


def enforce(mode: str, findings: Counter[FindingKey], scanner_exit: int) -> None:
    if scanner_exit not in {0, 183}:
        raise GateError(f"scanner failed with exit {scanner_exit}")
    expected_exit = 183 if findings else 0
    if scanner_exit != expected_exit:
        raise GateError("scanner exit code and findings disagree")
    if mode == "diff":
        if findings:
            raise GateError(
                f"pull-request diff contains {sum(findings.values())} secret finding(s)"
            )
        return
    if mode != "history":
        raise GateError("unsupported gate mode")
    unexpected = findings - HISTORY_BASELINE
    missing = HISTORY_BASELINE - findings
    if unexpected or missing:
        raise GateError(
            "full-history result differs from the reviewed baseline: "
            f"unexpected={sum(unexpected.values())}, missing={sum(missing.values())}"
        )


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("diff", "history"), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--scanner-exit", type=int, required=True)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        findings = load_findings(args.input)
        enforce(args.mode, findings, args.scanner_exit)
    except GateError as exc:
        print(f"secret gate: FAIL: {exc}")
        return 1
    print(f"secret gate: PASS: mode={args.mode}, findings={sum(findings.values())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
