#!/usr/bin/env python3
"""Validate the redacted handoff from the live storage qualification lane.

The live lane deliberately writes a public evidence transcript rather than a
request dump. This small gate makes that boundary explicit: it requires every
instrument and the final reduced token record, and rejects keys, prefixes,
upload ids, bodies, endpoints, and authorization-shaped fields if a future
lane change accidentally puts one back into the handoff.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


FORBIDDEN_KEYS = frozenset(
    {
        "access_key",
        "authorization",
        "body",
        "body_head",
        "bucket",
        "current_keys",
        "endpoint",
        "fullest_key",
        "key",
        "key_tail",
        "prefix",
        "query",
        "secret_key",
        "upload_id",
    }
)
REQUIRED_OPS = frozenset(
    {
        "calibration-list",
        "conditional-create-fresh",
        "conditional-create-repeat",
        "checksum-put",
        "versioning-put-1",
        "versioning-put-2",
        "versioning-list",
        "sse-put",
        "sse-plain-put",
        "bucket-encryption-get",
        "mp-create",
        "mp-upload-part",
        "mp-complete",
        "mp-abort-create",
        "mp-abort-part",
        "mp-abort",
        "mp-abort-repeat",
        "mp-open-list",
        "readback-list",
        "readback-versions",
        "teardown-list-open",
        "teardown-verify",
    }
)
TOKEN_KEYS = frozenset(
    {
        "conditional_create",
        "stored_checksum",
        "versioning",
        "server_side_encryption",
        "multipart_commit_abort",
    }
)
TOKEN_VALUES = {
    "conditional_create": frozenset({"supported", "unavailable"}),
    "stored_checksum": frozenset({"sha256", "md5", "provider_specific", "unavailable"}),
    "versioning": frozenset({"enabled", "disabled", "unknown"}),
    "server_side_encryption": frozenset({"verified", "unavailable"}),
    "multipart_commit_abort": frozenset({"verified", "not_a_profile"}),
}


def forbidden_paths(value: object, path: str = "record") -> list[str]:
    """Return paths containing a field that must never cross the handoff."""
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in FORBIDDEN_KEYS:
                findings.append(child_path)
            findings.extend(forbidden_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(forbidden_paths(child, f"{path}[{index}]"))
    return findings


def validate_lines(lines: list[str]) -> list[str]:
    violations: list[str] = []
    records: list[dict] = []
    for number, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            violations.append(f"line {number}: invalid JSON ({exc.msg})")
            continue
        if not isinstance(record, dict):
            violations.append(f"line {number}: record must be an object")
            continue
        records.append(record)
        for path in forbidden_paths(record, f"line {number}"):
            violations.append(f"{path}: infrastructure or secret field is forbidden")

    complete = [record for record in records if record.get("op") == "lane-complete"]
    operations = {record.get("op") for record in records}
    missing_ops = sorted(REQUIRED_OPS - operations)
    if missing_ops:
        violations.append(f"handoff is missing live instrument operations: {', '.join(missing_ops)}")
    if len(complete) != 1:
        violations.append(f"handoff must contain exactly one lane-complete record (found {len(complete)})")
    if len(complete) == 1:
        tokens = complete[0].get("tokens")
        if not isinstance(tokens, dict) or set(tokens) != TOKEN_KEYS:
            violations.append("lane-complete.tokens must contain exactly the five capability axes")
        else:
            for axis, allowed in TOKEN_VALUES.items():
                if tokens.get(axis) not in allowed:
                    violations.append(f"lane-complete.tokens.{axis} has an unknown or missing value")
        observations = complete[0].get("observations")
        if not isinstance(observations, dict):
            violations.append("lane-complete.observations must be the redacted observation summary")
    return violations


def check(path: Path) -> int:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"error: {path}: cannot be read: {exc}", file=sys.stderr)
        return 2
    violations = validate_lines(lines)
    for violation in violations:
        print(f"error: {violation}", file=sys.stderr)
    if violations:
        return 2
    print(f"OK: redacted live storage evidence is complete ({path})")
    return 0


def self_test() -> int:
    safe = [
        json.dumps({"op": operation, "status": 200})
        for operation in sorted(REQUIRED_OPS)
    ]
    safe.append(
        json.dumps(
            {
                "op": "lane-complete",
                "observations": {"read_back": {"version_count": 1}},
                "tokens": {
                    "conditional_create": "unavailable",
                    "stored_checksum": "provider_specific",
                    "versioning": "enabled",
                    "server_side_encryption": "verified",
                    "multipart_commit_abort": "verified",
                },
            }
        )
    )
    if validate_lines(safe):
        print("FAIL: safe redacted transcript rejected", file=sys.stderr)
        return 2

    unsafe = list(safe)
    unsafe[0] = json.dumps({"op": "calibration-list", "key": "secret-prefix/object"})
    if not validate_lines(unsafe):
        print("FAIL: transcript containing a key was accepted", file=sys.stderr)
        return 2
    print("self-test: redaction boundary enforced")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 3 and argv[1] == "--transcript":
        return check(Path(argv[2]))
    print("usage: check-live-storage-evidence.py --transcript FILE | --self-test", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
