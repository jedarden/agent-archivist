#!/usr/bin/env python3
"""Requirement-verification mapping gate for Agent Archivist.

Implements the Phase 0 traceability format (plan Sections 10 and 16): every
normative requirement in docs/notes/requirements.md carries stable
verification IDs — ``T-<REQ>`` for an automated test and ``OV-<REQ>`` for an
operational verification — recorded in ``tools/verification-register.json``
beside this script. A verification run emits a versioned
``verification-manifest.json`` keyed by Git commit, toolchain, lock, and
fixture digests; this tool then rejects absent, stale, cross-commit, or
incomplete evidence for any requirement marked implemented.

Subcommands:

  check  Validate the register against the requirements document (always)
         and, given ``--manifest``, the evidence the manifest records for
         the evaluated commit. Without ``--manifest`` this is the per-change
         gate: a requirement marked implemented must have its mapped checks
         present in the evaluated commit.
  emit   Write a manifest for the current commit from a run's outcomes file
         (TSV ``name<TAB>pass|fail`` lines or the equivalent JSON object).
  sync   Add register skeleton entries for requirements not yet mapped.
  self-test
         Prove the rejection paths against sandbox roots: the committed
         register must validate, then mutated registers and manifests must
         be rejected under the right failure category, and a manifest the
         emit subcommand writes must check clean for the same commit.

Usage::

    tools/verification-manifest.py check [--manifest FILE]
    tools/verification-manifest.py emit --outcomes FILE [--output FILE]
    tools/verification-manifest.py sync
    tools/verification-manifest.py self-test

The script is standard-library only so a clean checkout can run it before any
dependency is fetched. Every string it reads or writes is bounded and
content-free — identifiers, closed enums, hex digests, and repo-relative
locators only (docs/notes/verification.md, "Content-free constraints").
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REGISTER_PATH = Path("tools/verification-register.json")
REQUIREMENTS_PATH = Path("docs/notes/requirements.md")
TOOLCHAIN_PATH = Path("rust-toolchain.toml")
LOCK_PATH = Path("Cargo.lock")
FIXTURES_PATH = Path("fixtures")

REGISTER_VERSION = 1
MANIFEST_VERSION = 1

# Failure categories. Every error line carries one so a rejected manifest
# states which acceptance clause it violates.
REGISTER = "REGISTER"          # the mapping file itself is inconsistent
MALFORMED = "MALFORMED"        # manifest shape or schema violation
CROSS_COMMIT = "CROSS-COMMIT"  # evidence keyed to a different commit
STALE = "STALE"                # digest no longer matches the evaluated tree
ABSENT = "ABSENT"              # required evidence entry does not exist
INCOMPLETE = "INCOMPLETE"      # entry exists but is not passing/complete

STATUSES = ("planned", "implemented")
VERIFICATION_KINDS = ("test", "operational")
LANES = ("fast", "slow", "audit", "release")
EVIDENCE_SECTIONS = (
    "outcomes",
    "benchmarks",
    "capability_reports",
    "sbom",
    "artifacts",
    "pilot_evidence",
)
PILOT_EVIDENCE_KINDS = (
    "pilot-soak",
    "restore-drill",
    "review-record",
    "coverage-report",
    "cutover-checklist",
)
ARTIFACT_KINDS = ("oci", "archive", "checksum")
SBOM_FORMATS = ("cyclonedx", "spdx")

# Verification owners, one per requirement group (plan Section 16). A new
# requirement group is a reviewed change that extends this map in the same
# commit as the requirements document.
GROUP_OWNERS = {
    "ARCH": "stateless-replacement",
    "ID": "auth-conformance",
    "SID": "golden-ids",
    "CAP": "adapter-suites",
    "SCH": "scheduler-simulation",
    "VAL": "protocol-corpus",
    "STO": "compatibility-matrix",
    "RCPT": "fault-injection",
    "SEC": "security-scans",
    "OPS": "operations-exercises",
    "PUB": "release-audit",
}
OWNERS = frozenset(GROUP_OWNERS.values())

REQ_ID_RE = re.compile(r"^[A-Z]+-\d{3}$")
VER_ID_RE = re.compile(r"^(?P<kind>T|OV)-(?P<req>[A-Z]+-\d{3})$")
REQ_DOC_LINE_RE = re.compile(r"^- \*\*(?P<id>[A-Z]+-\d{3})\*\*", re.M)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
# Bounded, content-free strings: identifiers, enums, digests, repo-relative
# locators, and suite names. No "@", "=", "?", "&", quoting, or commas, so an
# email, a URL query, a key=value pair, or free prose cannot be recorded.
SAFE_STRING_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()/:+-]{0,127}$")
CHANNEL_RE = re.compile(r'^channel\s*=\s*"(?P<channel>[^"]+)"', re.M)

MANIFEST_TOP_KEYS = frozenset(
    {
        "manifest_version",
        "commit",
        "generated_at",
        "toolchain",
        "lock_digest",
        "fixture_digest",
        *EVIDENCE_SECTIONS,
    }
)
MANIFEST_REQUIRED_KEYS = (
    "manifest_version",
    "commit",
    "generated_at",
    "toolchain",
    "lock_digest",
    "fixture_digest",
    "outcomes",
)


def report(errors: list[tuple[str, str]]) -> int:
    """Print every accumulated failure and return the process exit code."""
    for category, message in errors:
        print(f"error: [{category}] {message}", file=sys.stderr)
    return 2 if errors else 0


# ---------------------------------------------------------------------------
# Content-free constraints
# ---------------------------------------------------------------------------


def string_errors(value: str, where: str) -> list[str]:
    """Return human-readable violations of the bounded-string rule."""
    problems: list[str] = []
    if not SAFE_STRING_RE.match(value):
        problems.append(f"{where}: string is not a bounded identifier/enum/digest/locator")
    if value != value.strip():
        problems.append(f"{where}: string has leading or trailing whitespace")
    if value.startswith("/") or ".." in value:
        problems.append(f"{where}: string looks like an escaping path")
    if len(value) > 128:
        problems.append(f"{where}: string exceeds 128 characters")
    return problems


def content_free_errors(value: object, where: str = "$") -> list[str]:
    """Walk a parsed JSON value and reject anything unbounded or unsafe."""
    problems: list[str] = []
    if isinstance(value, str):
        problems.extend(string_errors(value, where))
    elif isinstance(value, bool):
        pass
    elif isinstance(value, int):
        if not 0 <= value < 2**63:
            problems.append(f"{where}: integer out of bounds")
    elif isinstance(value, float):
        problems.append(f"{where}: floating-point values are not recorded")
    elif value is None:
        problems.append(f"{where}: null is not recorded; omit the entry instead")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            problems.extend(content_free_errors(item, f"{where}[{index}]"))
    elif isinstance(value, dict):
        for key, item in value.items():
            problems.extend(string_errors(str(key), f"{where} key {key!r}"))
            problems.extend(content_free_errors(item, f"{where}.{key}"))
    else:
        problems.append(f"{where}: unsupported type {type(value).__name__}")
    return problems


# ---------------------------------------------------------------------------
# Digests and environment facts
# ---------------------------------------------------------------------------


def file_digest(path: Path) -> str | None:
    """Return ``sha256:<hex>`` for a file, or ``None`` when it is absent."""
    if not path.is_file():
        return None
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{digest}"


def fixture_digest(root: Path) -> str:
    """Digest the synthetic-fixture tree, or ``"absent"`` before it exists.

    The tree hash covers every file under ``fixtures/`` in sorted
    repo-relative order: ``<path>\\0<sha256(bytes)>\\n`` per file, hashed
    once. Fixture reproduction (Phase 0 exit gate) makes this stable for a
    recorded seed.
    """
    fixtures = root / FIXTURES_PATH
    if not fixtures.is_dir():
        return "absent"
    combined = hashlib.sha256()
    files = sorted(p for p in fixtures.rglob("*") if p.is_file())
    if not files:
        return "absent"
    for path in files:
        relative = path.relative_to(root).as_posix()
        file_hex = hashlib.sha256(path.read_bytes()).hexdigest()
        combined.update(f"{relative}\0{file_hex}\n".encode("utf-8"))
    return f"sha256:{combined.hexdigest()}"


def toolchain_channel(root: Path) -> str:
    """Return the pinned channel string, or ``"unknown"`` when unparseable."""
    path = root / TOOLCHAIN_PATH
    if not path.is_file():
        return "unknown"
    match = CHANNEL_RE.search(path.read_text(encoding="utf-8"))
    return match.group("channel") if match else "unknown"


def git_commit(root: Path) -> str:
    """Return the full commit hash evaluated in this tree."""
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git rev-parse HEAD failed: {result.stderr.strip()}")
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Register (the requirement-to-verification mapping)
# ---------------------------------------------------------------------------


def requirement_ids_from_doc(root: Path) -> list[str]:
    """Extract every normative requirement ID from the requirements document."""
    path = root / REQUIREMENTS_PATH
    text = path.read_text(encoding="utf-8")
    return sorted(set(REQ_DOC_LINE_RE.findall(text)))


def safe_locator(root: Path, locator: str) -> Path | None:
    """Resolve a repo-relative locator, or ``None`` when it escapes the root."""
    if locator.startswith("/") or ".." in locator:
        return None
    candidate = (root / locator).resolve()
    root_resolved = root.resolve()
    if root_resolved != candidate and root_resolved not in candidate.parents:
        return None
    return candidate


def load_register(root: Path) -> tuple[dict | None, list[tuple[str, str]]]:
    """Load and fully validate the verification register.

    Returns the parsed register (``None`` when it cannot be used) and the
    accumulated ``(category, message)`` failures.
    """
    errors: list[tuple[str, str]] = []
    path = root / REGISTER_PATH
    try:
        register = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [(REGISTER, f"{REGISTER_PATH}: cannot be read: {exc}")]

    where = str(REGISTER_PATH)
    if not isinstance(register, dict):
        return None, [(REGISTER, f"{where}: top level must be an object")]
    errors.extend(
        (MALFORMED, message) for message in content_free_errors(register, where)
    )

    expected_keys = {"register_version", "requirements", "verifications"}
    if set(register) != expected_keys:
        errors.append(
            (
                REGISTER,
                f"{where}: keys must be exactly {sorted(expected_keys)}, got "
                f"{sorted(set(register))}",
            )
        )
        return None, errors
    if register["register_version"] != REGISTER_VERSION:
        errors.append(
            (
                REGISTER,
                f"{where}: register_version must be {REGISTER_VERSION}, got "
                f"{register['register_version']!r}",
            )
        )
        return None, errors

    requirements = register["requirements"]
    verifications = register["verifications"]
    if not isinstance(requirements, dict) or not isinstance(verifications, dict):
        errors.append((REGISTER, f"{where}: requirements and verifications must be objects"))
        return None, errors

    try:
        doc_ids = requirement_ids_from_doc(root)
    except OSError as exc:
        return None, [(REGISTER, f"{REQUIREMENTS_PATH}: cannot be read: {exc}")]
    register_ids = sorted(requirements)
    for rid in register_ids:
        if not REQ_ID_RE.match(rid):
            errors.append((REGISTER, f"{where}: malformed requirement ID {rid!r}"))
    missing = sorted(set(doc_ids) - set(register_ids))
    extra = sorted(set(register_ids) - set(doc_ids))
    if missing:
        errors.append(
            (
                REGISTER,
                f"requirements document defines {', '.join(missing)} with no register "
                f"entry; run `tools/verification-manifest.py sync` and complete the "
                f"mapping in the same commit",
            )
        )
    if extra:
        errors.append(
            (
                REGISTER,
                f"register entries {', '.join(extra)} match no requirement in "
                f"{REQUIREMENTS_PATH}",
            )
        )

    for rid, entry in sorted(requirements.items()):
        rwhere = f"{where} requirement {rid}"
        if not isinstance(entry, dict) or set(entry) != {"status", "verifications"}:
            errors.append(
                (REGISTER, f"{rwhere}: keys must be exactly ['status', 'verifications']")
            )
            continue
        if entry["status"] not in STATUSES:
            errors.append(
                (REGISTER, f"{rwhere}: status must be one of {STATUSES}, got {entry['status']!r}")
            )
        vids = entry["verifications"]
        if not isinstance(vids, list) or not vids:
            errors.append(
                (
                    REGISTER,
                    f"{rwhere}: verifications must be a non-empty list of verification IDs",
                )
            )
            continue
        for vid in vids:
            match = VER_ID_RE.match(vid) if isinstance(vid, str) else None
            if not match or match.group("req") != rid:
                errors.append(
                    (REGISTER, f"{rwhere}: verification {vid!r} is not an ID derived from {rid}")
                )

    for vid, entry in sorted(verifications.items()):
        vwhere = f"{where} verification {vid}"
        match = VER_ID_RE.match(vid) if isinstance(vid, str) else None
        if not match:
            errors.append(
                (REGISTER, f"{vwhere}: ID must be T-<REQ> or OV-<REQ>, got {vid!r}")
            )
            continue
        rid = match.group("req")
        implied_kind = "test" if match.group("kind") == "T" else "operational"
        if rid not in requirements:
            errors.append(
                (REGISTER, f"{vwhere}: maps to requirement {rid}, which has no register entry")
            )
            continue
        requirement_entry = requirements[rid]
        listed = (
            requirement_entry.get("verifications")
            if isinstance(requirement_entry, dict)
            else None
        )
        if not isinstance(listed, list) or vid not in listed:
            errors.append(
                (REGISTER, f"{vwhere}: requirement {rid} does not list this verification")
            )
            continue

        if not isinstance(entry, dict):
            errors.append((REGISTER, f"{vwhere}: entry must be an object"))
            continue
        allowed = {"kind", "lane", "owner", "locator", "evidence", "operational_kind"}
        if not set(entry) <= allowed:
            errors.append(
                (REGISTER, f"{vwhere}: unknown keys {sorted(set(entry) - allowed)}")
            )
            continue
        required = {"kind", "lane", "owner", "evidence"}
        if not required <= set(entry):
            errors.append(
                (REGISTER, f"{vwhere}: missing keys {sorted(required - set(entry))}")
            )
            continue
        if entry["kind"] != implied_kind:
            errors.append(
                (
                    REGISTER,
                    f"{vwhere}: kind {entry['kind']!r} contradicts the ID prefix "
                    f"({'test' if implied_kind == 'test' else 'operational'})",
                )
            )
        if entry["kind"] not in VERIFICATION_KINDS:
            errors.append((REGISTER, f"{vwhere}: kind must be one of {VERIFICATION_KINDS}"))
        if entry["lane"] not in LANES:
            errors.append((REGISTER, f"{vwhere}: lane must be one of {LANES}"))
        if entry["owner"] not in OWNERS:
            errors.append(
                (REGISTER, f"{vwhere}: owner must be one of {sorted(OWNERS)}, got {entry['owner']!r}")
            )
        evidence = entry["evidence"]
        if (
            not isinstance(evidence, list)
            or not evidence
            or sorted(set(evidence)) != sorted(evidence)
            or not set(evidence) <= set(EVIDENCE_SECTIONS)
        ):
            errors.append(
                (
                    REGISTER,
                    f"{vwhere}: evidence must be a non-empty duplicate-free subset of "
                    f"{list(EVIDENCE_SECTIONS)}",
                )
            )
        elif entry["kind"] == "test" and "outcomes" not in evidence:
            errors.append((REGISTER, f"{vwhere}: a test verification requires outcomes evidence"))
        # The locator key is omitted (not null) while a verification is
        # unplanned or has no located check yet.
        locator = entry.get("locator")
        if locator is not None:
            if not isinstance(locator, str):
                errors.append((REGISTER, f"{vwhere}: locator must be a string"))
            else:
                locator_errors = string_errors(locator, f"{vwhere} locator")
                errors.extend((REGISTER, message) for message in locator_errors)
                if not locator_errors:
                    resolved = safe_locator(root, locator)
                    if resolved is None:
                        errors.append(
                            (REGISTER, f"{vwhere}: locator {locator!r} escapes the repository root")
                        )
                    elif not resolved.is_file():
                        errors.append(
                            (
                                REGISTER,
                                f"{vwhere}: locator {locator!r} does not exist in the "
                                f"evaluated commit",
                            )
                        )
        operational_kind = entry.get("operational_kind")
        if operational_kind is not None and operational_kind not in PILOT_EVIDENCE_KINDS:
            errors.append(
                (
                    REGISTER,
                    f"{vwhere}: operational_kind must be one of {PILOT_EVIDENCE_KINDS}",
                )
            )

    return register, errors


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def manifest_shape_errors(manifest: object) -> list[tuple[str, str]]:
    """Validate manifest structure independent of the evaluated commit."""
    errors: list[tuple[str, str]] = []
    if not isinstance(manifest, dict):
        return [(MALFORMED, "manifest: top level must be an object")]
    errors.extend((MALFORMED, m) for m in content_free_errors(manifest, "manifest"))

    unknown = sorted(set(manifest) - MANIFEST_TOP_KEYS)
    if unknown:
        errors.append((MALFORMED, f"manifest: unknown top-level keys {unknown}"))
    for key in MANIFEST_REQUIRED_KEYS:
        if key not in manifest:
            errors.append((INCOMPLETE, f"manifest: required entry {key!r} is missing"))
    if "manifest_version" in manifest and manifest["manifest_version"] != MANIFEST_VERSION:
        errors.append(
            (
                MALFORMED,
                f"manifest: manifest_version must be {MANIFEST_VERSION}, got "
                f"{manifest['manifest_version']!r}",
            )
        )
    commit = manifest.get("commit")
    if commit is not None and not (isinstance(commit, str) and COMMIT_RE.match(commit)):
        errors.append((MALFORMED, "manifest: commit must be a 40-character lowercase hex SHA"))
    stamp = manifest.get("generated_at")
    if stamp is not None and not (isinstance(stamp, str) and TIMESTAMP_RE.match(stamp)):
        errors.append((MALFORMED, "manifest: generated_at must be an RFC 3339 UTC timestamp"))
    toolchain = manifest.get("toolchain")
    if toolchain is not None:
        if not isinstance(toolchain, dict) or set(toolchain) != {"channel", "digest"}:
            errors.append(
                (MALFORMED, "manifest: toolchain must be exactly {channel, digest}")
            )
        elif not DIGEST_RE.match(str(toolchain["digest"])):
            errors.append((MALFORMED, "manifest: toolchain digest must be sha256:<64 hex>"))
    for key in ("lock_digest",):
        value = manifest.get(key)
        if value is not None and not (isinstance(value, str) and DIGEST_RE.match(value)):
            errors.append((MALFORMED, f"manifest: {key} must be sha256:<64 hex>"))
    fixture = manifest.get("fixture_digest")
    if fixture is not None and fixture != "absent" and not (
        isinstance(fixture, str) and DIGEST_RE.match(fixture)
    ):
        errors.append((MALFORMED, "manifest: fixture_digest must be sha256:<64 hex> or 'absent'"))
    for section in EVIDENCE_SECTIONS:
        value = manifest.get(section)
        if value is not None and not isinstance(value, dict):
            errors.append((MALFORMED, f"manifest: {section} must be an object keyed by ID"))
    return errors


def manifest_environment_errors(
    manifest: dict, root: Path, commit: str
) -> list[tuple[str, str]]:
    """Reject evidence keyed to another commit or a since-changed tree."""
    errors: list[tuple[str, str]] = []
    recorded_commit = manifest.get("commit")
    if isinstance(recorded_commit, str) and COMMIT_RE.match(recorded_commit):
        if recorded_commit != commit:
            errors.append(
                (
                    CROSS_COMMIT,
                    f"manifest is keyed to commit {recorded_commit[:12]} but the "
                    f"evaluated commit is {commit[:12]}",
                )
            )
    toolchain = manifest.get("toolchain")
    actual_toolchain = file_digest(root / TOOLCHAIN_PATH)
    if isinstance(toolchain, dict) and DIGEST_RE.match(str(toolchain.get("digest", ""))):
        if toolchain["digest"] != actual_toolchain:
            errors.append(
                (
                    STALE,
                    f"manifest toolchain digest {toolchain['digest']} does not match the "
                    f"evaluated {TOOLCHAIN_PATH} ({actual_toolchain})",
                )
            )
    lock = manifest.get("lock_digest")
    actual_lock = file_digest(root / LOCK_PATH)
    if isinstance(lock, str) and DIGEST_RE.match(lock):
        if lock != actual_lock:
            errors.append(
                (
                    STALE,
                    f"manifest lock digest does not match the evaluated {LOCK_PATH} "
                    f"({actual_lock})",
                )
            )
    fixture = manifest.get("fixture_digest")
    actual_fixture = fixture_digest(root)
    if isinstance(fixture, str) and (fixture == "absent" or DIGEST_RE.match(fixture)):
        if fixture != actual_fixture:
            errors.append(
                (
                    STALE,
                    f"manifest fixture digest does not match the evaluated "
                    f"{FIXTURES_PATH}/ tree ({actual_fixture})",
                )
            )
    return errors


def entry_shape_errors(
    section: str, entry: object, where: str
) -> list[tuple[str, str]]:
    """Validate one evidence entry against its section's required fields."""
    errors: list[tuple[str, str]] = []
    if not isinstance(entry, dict):
        return [(INCOMPLETE, f"{where}: entry must be an object")]
    if section == "outcomes":
        if "result" not in entry:
            errors.append((INCOMPLETE, f"{where}: 'result' is missing"))
        elif entry["result"] not in ("pass", "fail"):
            errors.append((INCOMPLETE, f"{where}: result must be 'pass' or 'fail'"))
        digest = entry.get("locator_digest")
        if digest is not None and not (
            isinstance(digest, str) and DIGEST_RE.match(digest)
        ):
            errors.append((INCOMPLETE, f"{where}: locator_digest must be sha256:<64 hex>"))
        unknown = set(entry) - {"result", "locator_digest"}
        if unknown:
            errors.append((MALFORMED, f"{where}: unknown keys {sorted(unknown)}"))
    elif section == "benchmarks":
        if set(entry) != {"profile", "results_digest", "passed"}:
            errors.append(
                (INCOMPLETE, f"{where}: must be exactly {{profile, results_digest, passed}}")
            )
        elif not DIGEST_RE.match(str(entry["results_digest"])) or not isinstance(
            entry["passed"], bool
        ):
            errors.append((INCOMPLETE, f"{where}: malformed benchmark result"))
    elif section == "capability_reports":
        profiles = entry.get("profiles")
        if set(entry) != {"profiles", "report_digest"}:
            errors.append(
                (INCOMPLETE, f"{where}: must be exactly {{profiles, report_digest}}")
            )
        elif not isinstance(profiles, list) or not profiles or not DIGEST_RE.match(
            str(entry.get("report_digest", ""))
        ):
            errors.append((INCOMPLETE, f"{where}: malformed capability report"))
    elif section == "pilot_evidence":
        allowed = {"kind", "digest", "result"}
        if set(entry) != allowed:
            errors.append((INCOMPLETE, f"{where}: must be exactly {sorted(allowed)}"))
        else:
            if entry["kind"] not in PILOT_EVIDENCE_KINDS:
                errors.append(
                    (INCOMPLETE, f"{where}: kind must be one of {PILOT_EVIDENCE_KINDS}")
                )
            if not DIGEST_RE.match(str(entry["digest"])):
                errors.append((INCOMPLETE, f"{where}: digest must be sha256:<64 hex>"))
            if entry["result"] not in ("pass", "fail"):
                errors.append((INCOMPLETE, f"{where}: result must be 'pass' or 'fail'"))
    elif section == "artifacts":
        if set(entry) != {"kind", "digest"}:
            errors.append((INCOMPLETE, f"{where}: must be exactly {{kind, digest}}"))
        elif entry["kind"] not in ARTIFACT_KINDS or not DIGEST_RE.match(
            str(entry["digest"])
        ):
            errors.append((INCOMPLETE, f"{where}: malformed artifact entry"))
    return errors


def evidence_errors(
    register: dict, manifest: dict, root: Path
) -> list[tuple[str, str]]:
    """Enforce the acceptance rule for every requirement marked implemented."""
    errors: list[tuple[str, str]] = []
    requirements = register["requirements"]
    verifications = register["verifications"]

    sbom = manifest.get("sbom")
    artifacts = manifest.get("artifacts")

    for rid in sorted(requirements):
        entry = requirements[rid]
        if not isinstance(entry, dict) or entry.get("status") != "implemented":
            continue
        listed = entry.get("verifications")
        if not isinstance(listed, list):
            continue
        for vid in listed:
            verification = (
                verifications.get(vid) if isinstance(verifications, dict) else None
            )
            if not isinstance(verification, dict):
                continue  # already reported by register validation
            where = f"requirement {rid} via {vid}"
            locator = verification.get("locator")
            kind = verification.get("kind")
            evidence = verification.get("evidence")
            if kind not in VERIFICATION_KINDS or not isinstance(evidence, list):
                continue
            if kind == "test":
                if locator is None:
                    errors.append(
                        (
                            ABSENT,
                            f"{where}: requirement is marked implemented but the mapped "
                            f"check has no locator in the evaluated commit",
                        )
                    )
                elif (root / locator).is_file():
                    outcomes = manifest.get("outcomes", {})
                    outcome = outcomes.get(vid)
                    if outcome is None:
                        errors.append(
                            (
                                ABSENT,
                                f"{where}: no outcome recorded for the mapped check",
                            )
                        )
                        continue
                    errors.extend(entry_shape_errors("outcomes", outcome, f"{where}"))
                    if isinstance(outcome, dict):
                        if outcome.get("result") != "pass":
                            errors.append(
                                (
                                    INCOMPLETE,
                                    f"{where}: recorded outcome is "
                                    f"{outcome.get('result')!r}, not 'pass'",
                                )
                            )
                        locator_digest = outcome.get("locator_digest")
                        actual = file_digest(root / locator)
                        if locator_digest is None:
                            errors.append(
                                (
                                    INCOMPLETE,
                                    f"{where}: outcome lacks locator_digest for "
                                    f"{locator}",
                                )
                            )
                        elif locator_digest != actual:
                            errors.append(
                                (
                                    STALE,
                                    f"{where}: locator_digest matches an earlier version "
                                    f"of {locator} (now {actual})",
                                )
                            )
            elif "outcomes" in evidence:
                # An operational verification that lists outcomes evidence is
                # held to the same recorded-outcome rule as a test.
                outcome = manifest.get("outcomes", {}).get(vid)
                if outcome is None:
                    errors.append(
                        (ABSENT, f"{where}: no outcome recorded for the mapped check")
                    )
                else:
                    errors.extend(entry_shape_errors("outcomes", outcome, where))
                    if isinstance(outcome, dict) and outcome.get("result") != "pass":
                        errors.append(
                            (
                                INCOMPLETE,
                                f"{where}: recorded outcome is "
                                f"{outcome.get('result')!r}, not 'pass'",
                            )
                        )
            for section in evidence:
                if section == "outcomes":
                    continue  # handled for both kinds above
                if section == "sbom":
                    if not isinstance(sbom, dict) or not sbom:
                        errors.append(
                            (ABSENT, f"{where}: requires sbom evidence; none is recorded")
                        )
                    else:
                        if set(sbom) != {"format", "digest"}:
                            errors.append(
                                (INCOMPLETE, "sbom: must be exactly {format, digest}")
                            )
                        elif sbom["format"] not in SBOM_FORMATS or not DIGEST_RE.match(
                            str(sbom["digest"])
                        ):
                            errors.append((INCOMPLETE, "sbom: malformed entry"))
                    continue
                if section == "artifacts":
                    if not isinstance(artifacts, dict) or not artifacts:
                        errors.append(
                            (ABSENT, f"{where}: requires artifact evidence; none is recorded")
                        )
                    else:
                        for name, artifact in artifacts.items():
                            errors.extend(
                                entry_shape_errors(
                                    "artifacts", artifact, f"artifacts.{name}"
                                )
                            )
                    continue
                section_value = manifest.get(section) or {}
                evidence_entry = section_value.get(vid)
                if evidence_entry is None:
                    errors.append(
                        (
                            ABSENT,
                            f"{where}: requires a {section} entry; the manifest has none",
                        )
                    )
                    continue
                evidence_where = f"{section}.{vid}"
                errors.extend(
                    entry_shape_errors(section, evidence_entry, evidence_where)
                )
                if isinstance(evidence_entry, dict):
                    if section == "benchmarks" and evidence_entry.get("passed") is not True:
                        errors.append(
                            (INCOMPLETE, f"{evidence_where}: benchmark did not meet its floor")
                        )
                    if section == "pilot_evidence":
                        if evidence_entry.get("result") != "pass":
                            errors.append(
                                (
                                    INCOMPLETE,
                                    f"{evidence_where}: operational evidence did not pass",
                                )
                            )
                        pinned = verification.get("operational_kind")
                        if pinned is not None and evidence_entry.get("kind") != pinned:
                            errors.append(
                                (
                                    INCOMPLETE,
                                    f"{evidence_where}: kind must be {pinned!r} for {vid}",
                                )
                            )
    return errors


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def implemented_requirements(register: dict) -> list[str]:
    return sorted(
        rid
        for rid, entry in register["requirements"].items()
        if isinstance(entry, dict) and entry.get("status") == "implemented"
    )


def per_change_errors(register: dict, root: Path) -> list[tuple[str, str]]:
    """Per-change rule (plan Section 16): a requirement marked implemented
    must have its mapped checks present in the evaluated commit, manifest
    or not."""
    errors: list[tuple[str, str]] = []
    requirements = register.get("requirements")
    verifications = register.get("verifications")
    if not isinstance(requirements, dict) or not isinstance(verifications, dict):
        return errors  # already reported by register validation
    for rid in implemented_requirements(register):
        entry = requirements[rid]
        listed = entry.get("verifications") if isinstance(entry, dict) else None
        if not isinstance(listed, list):
            continue
        for vid in listed:
            verification = verifications.get(vid)
            if not isinstance(verification, dict):
                continue  # already reported by register validation
            if verification.get("kind") == "test":
                locator = verification.get("locator")
                if locator is None or not (root / locator).is_file():
                    errors.append(
                        (
                            ABSENT,
                            f"requirement {rid} via {vid}: marked implemented but the "
                            f"mapped check is absent from the evaluated commit",
                        )
                    )
    return errors


def cmd_check(
    root: Path, manifest_path: Path | None, commit_override: str | None = None
) -> int:
    register, errors = load_register(root)
    if register is None:
        return report(errors)

    manifest: dict | None = None
    if manifest_path is not None:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return report([(MALFORMED, f"{manifest_path}: cannot be read: {exc}")])
        assert manifest is not None
        errors.extend(manifest_shape_errors(manifest))

    errors.extend(per_change_errors(register, root))

    implemented = implemented_requirements(register)
    if manifest is not None:
        try:
            commit = commit_override or git_commit(root)
        except RuntimeError as exc:
            return report([(MALFORMED, f"cannot establish the evaluated commit: {exc}")])
        errors.extend(manifest_environment_errors(manifest, root, commit))
        errors.extend(evidence_errors(register, manifest, root))
        source = str(manifest_path)
    else:
        source = "(register-only mode: no manifest supplied)"
        if implemented:
            print(
                "note: requirements marked implemented exist; supply --manifest for "
                "full evidence checking",
                file=sys.stderr,
            )

    # A register that reached here may still carry per-entry errors, so the
    # summary must not assume every verification entry is a well-formed dict.
    test_count = sum(
        1
        for v in register["verifications"].values()
        if isinstance(v, dict) and v.get("kind") == "test"
    )
    operational_count = len(register["verifications"]) - test_count
    print(
        f"agent-archivist verification register: "
        f"{len(register['requirements'])} requirements, "
        f"{len(register['verifications'])} verifications "
        f"({test_count} test, {operational_count} operational)"
    )
    summary = f"implemented: {len(implemented)}"
    if implemented:
        summary += " (" + ", ".join(implemented) + ")"
    print(summary)
    print(f"manifest: {source}")
    if report(errors):
        return 2
    print("OK")
    return 0


def read_outcomes(path: Path) -> dict[str, str]:
    """Read a run's outcomes as ``{name: 'pass' | 'fail'}``.

    Accepts TSV lines (``name<TAB>pass``) as written by the definition-of-done
    script, or the equivalent JSON object mapping a name to a result string
    or an object with a ``result`` field.
    """
    raw = path.read_text(encoding="utf-8")
    outcomes: dict[str, str] = {}
    if raw.lstrip().startswith("{"):
        parsed = json.loads(raw)
        for name, value in parsed.items():
            result = value.get("result") if isinstance(value, dict) else value
            outcomes[str(name)] = str(result)
        return outcomes
    for line in raw.splitlines():
        if not line.strip():
            continue
        name, _, result = line.partition("\t")
        outcomes[name.strip()] = result.strip()
    return outcomes


def cmd_emit(
    root: Path, outcomes_path: Path, output_path: Path, commit: str | None
) -> int:
    errors: list[tuple[str, str]] = []
    try:
        outcomes = read_outcomes(outcomes_path)
    except (OSError, json.JSONDecodeError) as exc:
        return report([(MALFORMED, f"{outcomes_path}: cannot be read: {exc}")])
    for name, result in outcomes.items():
        if result not in ("pass", "fail"):
            errors.append((MALFORMED, f"outcome {name!r}: result must be 'pass' or 'fail'"))
    if errors:
        return report(errors)

    register, register_errors = load_register(root)
    if register is None or register_errors:
        # Same policy as sync: never proceed over an inconsistent register —
        # a manifest emitted from a broken mapping is not evidence.
        print("refusing to emit over an inconsistent register:", file=sys.stderr)
        return report(register_errors)

    if commit is None:
        try:
            commit = git_commit(root)
        except RuntimeError as exc:
            return report([(MALFORMED, f"cannot establish the evaluated commit: {exc}")])

    toolchain = file_digest(root / TOOLCHAIN_PATH)
    lock = file_digest(root / LOCK_PATH)
    if toolchain is None or lock is None:
        missing = [
            str(path)
            for path, digest in ((TOOLCHAIN_PATH, toolchain), (LOCK_PATH, lock))
            if digest is None
        ]
        return report(
            [(MALFORMED, f"cannot digest pinned build inputs {', '.join(missing)}")]
        )

    outcome_entries: dict[str, dict] = {}
    for name, result in outcomes.items():
        outcome_entries[name] = {"result": result}
    # Attach locator digests for verification-keyed outcomes so check can
    # prove the evidence describes the evaluated version of each test.
    for vid, verification in register["verifications"].items():
        # load_register has already reported malformed entries; skip them
        # here rather than assume every entry is a dict.
        if not isinstance(verification, dict):
            continue
        locator = verification.get("locator")
        if vid in outcome_entries and verification.get("kind") == "test" and locator:
            digest = file_digest(root / locator)
            if digest is not None:
                outcome_entries[vid]["locator_digest"] = digest

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "commit": commit,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "toolchain": {
            "channel": toolchain_channel(root),
            "digest": toolchain,
        },
        "lock_digest": lock,
        "fixture_digest": fixture_digest(root),
        "outcomes": outcome_entries,
        "benchmarks": {},
        "capability_reports": {},
        "sbom": {},
        "artifacts": {},
        "pilot_evidence": {},
    }
    shape = manifest_shape_errors(manifest)
    if shape:
        return report(shape)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {output_path} keyed to commit {commit[:12]}")
    return 0


def cmd_sync(root: Path) -> int:
    try:
        doc_ids = requirement_ids_from_doc(root)
    except OSError as exc:
        print(f"error: [REGISTER] {REQUIREMENTS_PATH}: cannot be read: {exc}", file=sys.stderr)
        return 2
    path = root / REGISTER_PATH
    register: dict = {
        "register_version": REGISTER_VERSION,
        "requirements": {},
        "verifications": {},
    }
    if path.is_file():
        existing, errors = load_register(root)
        if existing is None:
            print(f"refusing to sync over an inconsistent register:", file=sys.stderr)
            return report(errors)
        register = existing

    added: list[str] = []
    for rid in doc_ids:
        if rid in register["requirements"]:
            continue
        group = rid.split("-", 1)[0]
        owner = GROUP_OWNERS.get(group)
        if owner is None:
            print(
                f"error: [REGISTER] requirement group {group!r} has no verification "
                f"owner; extend GROUP_OWNERS in this script in the same commit",
                file=sys.stderr,
            )
            return 2
        vid = f"T-{rid}"
        register["requirements"][rid] = {
            "status": "planned",
            "verifications": [vid],
        }
        register["verifications"][vid] = {
            "kind": "test",
            "lane": "slow",
            "owner": owner,
            "evidence": ["outcomes"],
        }
        added.append(rid)

    if added:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(register, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"added register entries for {len(added)} requirements: {', '.join(added)}")
    else:
        print("register already covers every requirement; nothing to add")
    return 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

# A fixed synthetic commit pair: digests and identity without a repository.
SANDBOX_COMMIT = "1" * 40
OTHER_COMMIT = "2" * 40

SANDBOX_REQUIREMENTS = (
    "# Sandbox requirements\n"
    "\n"
    "- **TST-001** — The widget MUST be verified end to end.\n"
    "- **TST-002** — The wadge MUST remain planned until it is implemented.\n"
)

SANDBOX_REGISTER: dict = {
    "register_version": 1,
    "requirements": {
        "TST-001": {"status": "implemented", "verifications": ["T-TST-001", "OV-TST-001"]},
        "TST-002": {"status": "planned", "verifications": ["T-TST-002"]},
    },
    "verifications": {
        "T-TST-001": {
            "kind": "test",
            "lane": "slow",
            "owner": "golden-ids",
            "locator": "tests/widget.rs",
            "evidence": ["outcomes"],
        },
        "OV-TST-001": {
            "kind": "operational",
            "lane": "release",
            "owner": "operations-exercises",
            "evidence": ["pilot_evidence"],
            "operational_kind": "restore-drill",
        },
        "T-TST-002": {
            "kind": "test",
            "lane": "slow",
            "owner": "golden-ids",
            "evidence": ["outcomes"],
        },
    },
}


def clone(value: dict) -> dict:
    """Deep-copy a sandbox structure for mutation."""
    return json.loads(json.dumps(value))


def write_sandbox(base: Path, register: dict | None = None) -> Path:
    """Materialize a minimal evaluation root under *base* and return it."""
    root = base / "root"
    (root / "docs/notes").mkdir(parents=True)
    (root / "tools").mkdir(parents=True)
    (root / "tests").mkdir(parents=True)
    (root / REQUIREMENTS_PATH).write_text(SANDBOX_REQUIREMENTS, encoding="utf-8")
    payload = SANDBOX_REGISTER if register is None else register
    (root / REGISTER_PATH).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "tests/widget.rs").write_text("fn widget() {}\n", encoding="utf-8")
    (root / TOOLCHAIN_PATH).write_text('[toolchain]\nchannel = "1.97.1"\n', encoding="utf-8")
    (root / LOCK_PATH).write_text("# sandbox lock\n", encoding="utf-8")
    return root


def sandbox_manifest(root: Path, commit: str = SANDBOX_COMMIT) -> dict:
    """Build a manifest that satisfies every rule for the sandbox root."""
    return {
        "manifest_version": MANIFEST_VERSION,
        "commit": commit,
        "generated_at": "2026-09-11T00:00:00Z",
        "toolchain": {
            "channel": toolchain_channel(root),
            "digest": file_digest(root / TOOLCHAIN_PATH),
        },
        "lock_digest": file_digest(root / LOCK_PATH),
        "fixture_digest": fixture_digest(root),
        "outcomes": {
            "T-TST-001": {
                "result": "pass",
                "locator_digest": file_digest(root / "tests/widget.rs"),
            }
        },
        "benchmarks": {},
        "capability_reports": {},
        "sbom": {},
        "artifacts": {},
        "pilot_evidence": {
            "OV-TST-001": {
                "kind": "restore-drill",
                "digest": "sha256:" + "0" * 64,
                "result": "pass",
            }
        },
    }


def full_errors(root: Path, manifest: dict | None, commit: str) -> list[tuple[str, str]]:
    """Every check stage in cmd_check's order, without the CLI surround."""
    register, errors = load_register(root)
    if register is None:
        return errors
    if manifest is not None:
        errors.extend(manifest_shape_errors(manifest))
    errors.extend(per_change_errors(register, root))
    if manifest is not None:
        errors.extend(manifest_environment_errors(manifest, root, commit))
        errors.extend(evidence_errors(register, manifest, root))
    return errors


def self_test() -> int:
    base_register, base_errors = load_register(ROOT)
    if base_register is None or base_errors or per_change_errors(base_register, ROOT):
        for category, message in base_errors:
            print(f"error: [{category}] {message}", file=sys.stderr)
        print(
            "self-test base: the committed register itself is invalid",
            file=sys.stderr,
        )
        return 2

    passed = 0
    failed = 0

    def case(
        label: str,
        errors: list[tuple[str, str]],
        must_reject: bool,
        category: str | None = None,
    ) -> None:
        nonlocal passed, failed
        rejected = bool(errors)
        categories = {c for c, _ in errors}
        ok = rejected == must_reject and (category is None or category in categories)
        if ok:
            passed += 1
            print(f"  ok  {'rejects' if rejected else 'accepts'}: {label}")
        else:
            failed += 1
            state = "should reject" if must_reject else "should accept"
            wanted = f" (wanted [{category}])" if category else ""
            print(f"  FAIL {state}: {label}{wanted}")
            for cat, message in errors:
                print(f"       violation: [{cat}] {message}")

    def run_quiet(argv: list[str]) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            return main(argv)

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        # Register-only mode: the per-change gate without a manifest.
        root = write_sandbox(base / "a")
        case(
            "consistent register with no manifest",
            full_errors(root, None, SANDBOX_COMMIT),
            False,
        )

        register = clone(SANDBOX_REGISTER)
        del register["requirements"]["TST-002"]
        root = write_sandbox(base / "b", register)
        case(
            "requirement missing from the register",
            full_errors(root, None, SANDBOX_COMMIT),
            True,
            REGISTER,
        )

        register = clone(SANDBOX_REGISTER)
        register["requirements"]["TST-002"]["status"] = "implemented"
        root = write_sandbox(base / "c", register)
        case(
            "implemented without a located check",
            full_errors(root, None, SANDBOX_COMMIT),
            True,
            ABSENT,
        )

        root = write_sandbox(base / "d")
        manifest = sandbox_manifest(root)
        (root / "tests/widget.rs").unlink()
        case(
            "located check absent from the evaluated commit",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            ABSENT,
        )

        # Manifest shape and content-free constraints.
        root = write_sandbox(base / "e")
        manifest = sandbox_manifest(root)
        manifest["manifest_version"] = 2
        case(
            "wrong manifest_version",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            MALFORMED,
        )

        root = write_sandbox(base / "f")
        manifest = sandbox_manifest(root)
        manifest["extra"] = "x"
        case(
            "unknown top-level manifest key",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            MALFORMED,
        )

        root = write_sandbox(base / "g")
        manifest = sandbox_manifest(root)
        manifest["outcomes"]["T-TST-001"]["seconds"] = 1.5
        case(
            "floating-point value in the manifest",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            MALFORMED,
        )

        root = write_sandbox(base / "h")
        manifest = sandbox_manifest(root)
        manifest["outcomes"]["T-TST-001"]["contact"] = "a@b"
        case(
            "email-shaped string in the manifest",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            MALFORMED,
        )

        # Environment binding: commit, toolchain, lock, fixtures, test bytes.
        root = write_sandbox(base / "i")
        case(
            "manifest keyed to another commit",
            full_errors(root, sandbox_manifest(root, OTHER_COMMIT), SANDBOX_COMMIT),
            True,
            CROSS_COMMIT,
        )

        root = write_sandbox(base / "j")
        manifest = sandbox_manifest(root)
        manifest["toolchain"]["digest"] = "sha256:" + "3" * 64
        case(
            "toolchain digest drift",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            STALE,
        )

        root = write_sandbox(base / "k")
        manifest = sandbox_manifest(root)
        manifest["lock_digest"] = "sha256:" + "3" * 64
        case(
            "lock digest drift",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            STALE,
        )

        root = write_sandbox(base / "l")
        manifest = sandbox_manifest(root)
        (root / "fixtures/synthetic").mkdir(parents=True)
        (root / "fixtures/synthetic/session.jsonl").write_text("{}\n", encoding="utf-8")
        case(
            "fixture digest drift",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            STALE,
        )

        root = write_sandbox(base / "m")
        manifest = sandbox_manifest(root)
        (root / "tests/widget.rs").write_text("fn widget() { changed }\n", encoding="utf-8")
        case(
            "outcome recorded for an earlier version of the mapped check",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            STALE,
        )

        # Evidence presence and completeness.
        root = write_sandbox(base / "n")
        manifest = sandbox_manifest(root)
        del manifest["outcomes"]["T-TST-001"]
        case(
            "no outcome recorded for the mapped check",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            ABSENT,
        )

        root = write_sandbox(base / "o")
        manifest = sandbox_manifest(root)
        manifest["outcomes"]["T-TST-001"]["result"] = "fail"
        case(
            "failing test outcome",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            INCOMPLETE,
        )

        root = write_sandbox(base / "p")
        manifest = sandbox_manifest(root)
        del manifest["pilot_evidence"]["OV-TST-001"]
        case(
            "no operational evidence entry",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            ABSENT,
        )

        root = write_sandbox(base / "q")
        manifest = sandbox_manifest(root)
        manifest["pilot_evidence"]["OV-TST-001"]["result"] = "fail"
        case(
            "failing operational evidence",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            INCOMPLETE,
        )

        root = write_sandbox(base / "r")
        manifest = sandbox_manifest(root)
        manifest["pilot_evidence"]["OV-TST-001"]["kind"] = "coverage-report"
        case(
            "operational evidence kind differs from the pinned kind",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            INCOMPLETE,
        )

        register = clone(SANDBOX_REGISTER)
        register["verifications"]["OV-TST-001"]["evidence"] = ["outcomes", "pilot_evidence"]
        root = write_sandbox(base / "s", register)
        # sandbox_manifest records no outcome for OV-TST-001, which this
        # register now requires.
        manifest = sandbox_manifest(root)
        case(
            "operational verification listing outcomes without a recorded outcome",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            ABSENT,
        )

        register = clone(SANDBOX_REGISTER)
        register["verifications"]["T-TST-001"]["evidence"] = ["outcomes", "sbom"]
        root = write_sandbox(base / "t", register)
        manifest = sandbox_manifest(root)
        case(
            "required sbom evidence absent",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            ABSENT,
        )
        manifest["sbom"] = {"format": "pdf", "digest": "sha256:" + "4" * 64}
        case(
            "malformed sbom entry",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            INCOMPLETE,
        )

        register = clone(SANDBOX_REGISTER)
        register["requirements"]["TST-001"]["verifications"] = ["T-TST-001"]
        register["verifications"]["T-TST-001"]["evidence"] = [
            "outcomes",
            "benchmarks",
            "artifacts",
        ]
        del register["verifications"]["OV-TST-001"]
        root = write_sandbox(base / "u", register)
        manifest = sandbox_manifest(root)
        case(
            "required benchmark and artifact evidence absent",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            ABSENT,
        )
        manifest["benchmarks"]["T-TST-001"] = {
            "profile": "std",
            "results_digest": "sha256:" + "4" * 64,
            "passed": False,
        }
        manifest["artifacts"]["server-image"] = {
            "kind": "pdf",
            "digest": "sha256:" + "4" * 64,
        }
        case(
            "benchmark under its floor and malformed artifact",
            full_errors(root, manifest, SANDBOX_COMMIT),
            True,
            INCOMPLETE,
        )

        # A malformed register must be reported under REGISTER, never crash
        # the summarizer or the emit path with a traceback.
        register = clone(SANDBOX_REGISTER)
        register["verifications"]["T-TST-001"] = "not-an-object"
        root = write_sandbox(base / "y", register)
        case(
            "malformed verification entry",
            full_errors(root, None, SANDBOX_COMMIT),
            True,
            REGISTER,
        )
        check_reports = run_quiet(["check", "--root", str(root)])
        emit_outcomes = base / "malformed.tsv"
        emit_outcomes.write_text("T-TST-001\tpass\n", encoding="utf-8")
        emit_reports = run_quiet(
            [
                "emit",
                "--outcomes",
                str(emit_outcomes),
                "--output",
                str(base / "malformed-manifest.json"),
                "--root",
                str(root),
                "--commit",
                SANDBOX_COMMIT,
            ]
        )
        if check_reports == 2 and emit_reports == 2:
            passed += 1
            print("  ok  rejects: malformed register reported, not crashed")
        else:
            failed += 1
            print(
                f"  FAIL should reject: malformed register reported, not crashed "
                f"(check exit {check_reports}, emit exit {emit_reports})"
            )

        # CLI wiring: emit and check must agree end to end. The register here
        # requires only outcomes evidence — emit fills the outcomes section;
        # the remaining sections arrive from later pipeline stages.
        register = clone(SANDBOX_REGISTER)
        register["requirements"]["TST-001"]["verifications"] = ["T-TST-001"]
        register["verifications"]["T-TST-001"]["evidence"] = ["outcomes"]
        del register["verifications"]["OV-TST-001"]
        outcomes = base / "outcomes.tsv"
        outcomes.write_text("fmt\tpass\nT-TST-001\tpass\n", encoding="utf-8")
        emitted = base / "verification-manifest.json"
        root = write_sandbox(base / "v", register)
        emitted_ok = (
            run_quiet(
                [
                    "emit",
                    "--outcomes",
                    str(outcomes),
                    "--output",
                    str(emitted),
                    "--root",
                    str(root),
                    "--commit",
                    SANDBOX_COMMIT,
                ]
            )
            == 0
            and run_quiet(
                ["check", "--manifest", str(emitted), "--root", str(root), "--commit", SANDBOX_COMMIT]
            )
            == 0
        )
        if emitted_ok:
            passed += 1
            print("  ok  accepts: emit then check round trip")
        else:
            failed += 1
            print("  FAIL should accept: emit then check round trip")
        cross_commit = (
            run_quiet(
                ["check", "--manifest", str(emitted), "--root", str(root), "--commit", OTHER_COMMIT]
            )
            == 2
        )
        if cross_commit:
            passed += 1
            print("  ok  rejects: emitted manifest checked against another commit")
        else:
            failed += 1
            print("  FAIL should reject: emitted manifest checked against another commit")

        # sync: skeleton entries for unmapped requirements, owner required.
        sync_root = base / "w"
        (sync_root / "docs/notes").mkdir(parents=True)
        (sync_root / REQUIREMENTS_PATH).write_text(
            "- **SID-001** — Sandbox session identity.\n"
            "- **SID-002** — Another sandbox identity.\n",
            encoding="utf-8",
        )
        sync_ok = (
            run_quiet(["sync", "--root", str(sync_root)]) == 0
            and (sync_root / REGISTER_PATH).is_file()
            and run_quiet(["check", "--root", str(sync_root)]) == 0
            and run_quiet(["sync", "--root", str(sync_root)]) == 0
        )
        if sync_ok:
            passed += 1
            print("  ok  accepts: sync maps unmapped requirements and is idempotent")
        else:
            failed += 1
            print("  FAIL should accept: sync maps unmapped requirements and is idempotent")

        unknown_root = base / "x"
        (unknown_root / "docs/notes").mkdir(parents=True)
        (unknown_root / REQUIREMENTS_PATH).write_text(
            "- **XYZ-001** — Requirement group with no verification owner.\n",
            encoding="utf-8",
        )
        if run_quiet(["sync", "--root", str(unknown_root)]) == 2:
            passed += 1
            print("  ok  rejects: sync for a group with no verification owner")
        else:
            failed += 1
            print("  FAIL should reject: sync for a group with no verification owner")

    print(f"self-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Requirement-verification register and manifest gate."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate the register and any evidence manifest")
    check.add_argument(
        "--manifest", type=Path, default=None, help="verification-manifest.json to verify"
    )
    check.add_argument(
        "--root", type=Path, default=ROOT, help="repository root to evaluate"
    )
    check.add_argument(
        "--commit", default=None, help=argparse.SUPPRESS
    )

    emit = sub.add_parser("emit", help="write a manifest for this commit")
    emit.add_argument(
        "--outcomes", type=Path, required=True, help="run outcomes (TSV or JSON)"
    )
    emit.add_argument(
        "--output", type=Path, default=Path("verification-manifest.json"),
        help="manifest destination (default: ./verification-manifest.json)",
    )
    emit.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    emit.add_argument("--commit", default=None, help=argparse.SUPPRESS)

    sync = sub.add_parser("sync", help="register requirements not yet mapped")
    sync.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)

    sub.add_parser(
        "self-test", help="prove the rejection paths against sandbox roots"
    )

    args = parser.parse_args(argv)
    if args.command == "check":
        return cmd_check(args.root.resolve(), args.manifest, args.commit)
    if args.command == "emit":
        return cmd_emit(
            args.root.resolve(), args.outcomes, args.output, args.commit
        )
    if args.command == "self-test":
        return self_test()
    return cmd_sync(args.root.resolve())


if __name__ == "__main__":
    sys.exit(main())
