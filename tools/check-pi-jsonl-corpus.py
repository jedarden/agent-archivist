#!/usr/bin/env python3
"""Verify the committed, sanitized Pi JSONL corpus without modifying it."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "contributed" / "pi-jsonl"
MANIFEST = ROOT / "manifest.json"

# These are deliberately conservative corpus-review indicators, not a claim
# that a regex can replace human review. The committed corpus is expected to
# contain none of them.
SENSITIVE = re.compile(
    r"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"(?:^|\W)(?:api[_-]?key|access[_-]?token|auth(?:orization)?|password|secret)"
    r"(?:\W|$)|(?:^|\W)Bearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"(?:^|\W)(?:sk|ghp|github_pat|xox[baprs])-[-A-Za-z0-9_]{8,})",
    re.IGNORECASE,
)


def fail(message: str) -> None:
    raise SystemExit(f"pi-jsonl corpus check failed: {message}")


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("read_only") is not True:
        fail("manifest does not mark the corpus read-only")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        fail("manifest has no artifacts")

    seen_fingerprints: set[str] = set()
    for record in artifacts:
        relative = record.get("path")
        if not isinstance(relative, str) or Path(relative).is_absolute():
            fail("artifact path is not a relative path")
        path = (ROOT / relative).resolve()
        if path.parent != ROOT.resolve() or not path.is_file():
            fail(f"artifact is missing or escapes corpus root: {relative}")

        raw = path.read_bytes()
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != record.get("sha256"):
            fail(f"checksum mismatch: {relative}")
        if len(raw) != record.get("bytes"):
            fail(f"byte count mismatch: {relative}")

        lines = raw.splitlines()
        if len(lines) != record.get("jsonl_records"):
            fail(f"record count mismatch: {relative}")
        try:
            objects = [json.loads(line) for line in lines]
        except json.JSONDecodeError as error:
            fail(f"invalid JSONL in {relative}: line {error.lineno}")
        if any(not isinstance(obj, dict) for obj in objects):
            fail(f"non-object JSONL record: {relative}")

        header = objects[0]
        expected_version = record.get("header_version")
        actual_version = header.get("version", 1)
        if header.get("type") != "session" or actual_version != expected_version:
            fail(f"header version mismatch: {relative}")
        if expected_version == 1 and "version" in header:
            fail(f"v1 artifact must omit its legacy version member: {relative}")
        if expected_version == 2 and header.get("version") != 2:
            fail(f"v2 artifact must carry an explicit version member: {relative}")
        if not all(header.get(key) for key in ("id", "timestamp", "cwd")):
            fail(f"header is missing required identity fields: {relative}")

        message = objects[1].get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            fail(f"flush sentinel is not an assistant message: {relative}")
        if message.get("content") != []:
            fail(f"flush sentinel contains transcript content: {relative}")
        if expected_version == 2 and not objects[1].get("id"):
            fail(f"v2 entry is missing its id: {relative}")
        if expected_version == 2 and "parentId" not in objects[1]:
            fail(f"v2 entry is missing its parentId: {relative}")

        text = raw.decode("utf-8")
        if SENSITIVE.search(text):
            fail(f"credential-looking content found: {relative}")
        seen_fingerprints.add(record.get("fingerprint", ""))

    if seen_fingerprints != {"pi-jsonl-v1", "pi-jsonl-v2"}:
        fail(f"expected both header fingerprints, found {sorted(seen_fingerprints)}")
    print(f"pi-jsonl corpus verified: {len(artifacts)} artifacts, checksums and review shape pass")


if __name__ == "__main__":
    main()
