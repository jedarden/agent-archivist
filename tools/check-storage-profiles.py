#!/usr/bin/env python3
"""Storage-profile registry gate for Agent Archivist.

The qualification path for community storage profiles and the recording
format live in ``docs/notes/storage-profiles.md``; the machine-readable
record is ``tools/storage-profiles.toml``; this gate (fast lane of
``scripts/definition-of-done.sh``) rejects any state of the three that
disagrees with the other two. It reads committed files only, so it runs on
a clean checkout with no network access, no external credentials, and no
S3 backend of any kind — which is the point: qualification evidence enters
this repository only as a recorded community run, never as something the
gate could be imagined to have produced itself.

Policy, one rule per check below:

1. the registry declares exactly the pinned schema, and every profile's
   class comes from the closed set {reference, target, community} with
   MinIO pinned as the one reference profile (plan Section 7.7);
2. reference and target profiles carry no qualification records — their
   qualification lives in the compatibility suite's own lanes — while
   every community profile carries at least one, so no community profile
   is ever silently claimable (an absent record is not a soft "probably
   works"; it is a gate failure);
3. a record's outcome is ``qualified`` or ``unqualified`` and its shape is
   the outcome's: ``unqualified`` states a non-empty reason and offers no
   capability fields, ``qualified`` states the suite revision, the
   operator, and the full five-axis capability matrix with closed tokens
   and ``multipart_commit_abort`` verified — the one primitive a backend
   cannot lack and still be a profile at all;
4. records are append-only per profile: dates never decrease, so a
   profile's standing is always its latest record and history cannot be
   reordered after the fact;
5. no free-text field carries infrastructure identifiers — endpoints,
   credentials, tailnet names — mirroring PUB-002/SEC-010 at the shape
   level;
6. the note's standing table and the README agree with the registry:
   every profile appears in the table, every community row states the
   computed standing and record date, the README names each community
   profile and its unqualified standing when any profile stands
   unqualified, and the retired unevidenced claim ("expected to be
   usable") appears nowhere it can creep back from.

``--self-test`` runs the same validators against the committed registry
with embedded mutations (plus README and note edits in memory) and
requires every rejection path to fire and every well-formed variant to
pass. On success the plain run prints the computed standing per profile
and exits 0; any failure prints a report on stderr and exits 2.

Usage::

    tools/check-storage-profiles.py [--self-test]

The script is standard-library only.
"""

from __future__ import annotations

import copy
import datetime as dt
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = Path("tools/storage-profiles.toml")
NOTE_PATH = Path("docs/notes/storage-profiles.md")
README_PATH = Path("README.md")

REGISTRY_SCHEMA = "archivist.storage-profiles/v1"

# docs/notes/storage-profiles.md Section 1. The reference class is MinIO's
# alone (plan Section 7.7); the gate pins that along with the token set.
PROFILE_CLASSES = ("reference", "target", "community")
REFERENCE_PROFILE = "minio"

# docs/notes/storage-profiles.md Section 3: the closed field sets per record.
RECORD_OUTCOMES = ("qualified", "unqualified")
RECORD_KEYS_COMMON = frozenset({"profile", "date", "outcome", "submitted_by", "note"})
RECORD_KEYS_UNQUALIFIED = RECORD_KEYS_COMMON | {"reason"}
RECORD_KEYS_QUALIFIED = RECORD_KEYS_COMMON | {"suite_revision", "operator", "capability"}

# The capability model of plan Section 7.7 / crates' `capability` module.
# `multipart_commit_abort` has one qualified value: a backend without
# begin/write/commit/abort is not a supported profile, so there is nothing
# else a qualified record could honestly state on that axis.
CAPABILITY_AXES = {
    "conditional_create": ("supported", "unavailable"),
    "multipart_commit_abort": ("verified",),
    "stored_checksum": ("sha256", "md5", "provider_specific", "unavailable"),
    "versioning": ("enabled", "disabled", "unknown"),
    "server_side_encryption": ("verified", "unavailable"),
}

# README display names for the community-class profiles the documents name.
COMMUNITY_DISPLAY_NAMES = {"aws-s3": "AWS S3", "garage": "Garage"}

# The unevidenced claim this registry exists to retire (bead-motivated; the
# phrase is forbidden in the README and the note precisely because it reads
# as a capability statement while carrying no record behind it).
RETIRED_CLAIM = "expected to be usable"

# PUB-002/SEC-010 at the shape level: none of these belong in any free-text
# field of a public qualification record.
IDENTIFIER_PATTERNS = (
    (re.compile(r"https?://|://"), "a URL or scheme prefix"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "an IPv4 address"),
    (re.compile(r"[\w.-]+\.ts\.net", re.I), "a tailnet hostname"),
    (re.compile(r"\S+@\S+"), "an address-shaped string (user@host)"),
)

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# The standing table in docs/notes/storage-profiles.md Section 5. Community
# rows are machine-checked; reference and target rows are prose the gate only
# requires to exist, because their qualification is the suite's business.
# Requiring the class cell to be a real class keeps unrelated tables in the
# note (the field table in Section 3 also starts with a slugged first cell)
# from reading as standing rows.
STANDING_ROW_RE = re.compile(
    r"^\|\s*`(?P<key>[a-z0-9-]+)`\s*\|\s*(?:reference|target|community)\s*\|"
    r"\s*(?P<standing>[^|]+)\|\s*(?P<evidence>[^|]*)\|",
    re.M,
)


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


# --- loading ---------------------------------------------------------------


def load_registry(path: Path) -> dict | None:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"{path}: cannot be read as TOML: {exc}")
        return None


def load_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"{path}: cannot be read: {exc}")
        return None


# --- registry validation -----------------------------------------------------


def parse_date(text: str) -> dt.date | None:
    if not DATE_RE.match(text or ""):
        return None
    try:
        return dt.date.fromisoformat(text)
    except ValueError:
        return None


def identifier_violations(where: str, text: str) -> list[str]:
    return [
        f"{where} contains {what}: PUB-002/SEC-010 forbid infrastructure "
        "identifiers in qualification records"
        for pattern, what in IDENTIFIER_PATTERNS
        if pattern.search(text or "")
    ]


def validate_registry(registry: dict) -> list[str]:
    violations: list[str] = []

    if registry.get("schema") != REGISTRY_SCHEMA:
        violations.append(
            f"registry schema must be exactly {REGISTRY_SCHEMA!r}, "
            f"found {registry.get('schema')!r}"
        )

    profiles = registry.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        return violations + ["registry has no [profiles] table"]

    reference_keys = []
    community_keys = []
    target_count = 0
    for key, profile in profiles.items():
        where = f"profiles.{key}"
        if not re.match(r"^[a-z0-9-]+$", key):
            violations.append(f"{where}: profile keys are lowercase slugs")
        if not isinstance(profile, dict):
            violations.append(f"{where}: must be a table")
            continue
        unknown = set(profile) - {"class", "description"}
        if unknown:
            violations.append(
                f"{where}: unknown fields {sorted(unknown)}; a profile is "
                "class and description only"
            )
        profile_class = profile.get("class")
        if profile_class not in PROFILE_CLASSES:
            violations.append(
                f"{where}.class must be one of {list(PROFILE_CLASSES)}, "
                f"found {profile_class!r}"
            )
        elif profile_class == "reference":
            reference_keys.append(key)
        elif profile_class == "community":
            community_keys.append(key)
        else:
            target_count += 1
        description = profile.get("description")
        if not isinstance(description, str) or not description.strip():
            violations.append(f"{where}.description must be a non-empty string")
        else:
            violations.extend(identifier_violations(where, description))

    if reference_keys != [REFERENCE_PROFILE]:
        violations.append(
            f"the reference profile is pinned to {REFERENCE_PROFILE!r} "
            f"(plan Section 7.7); reference-class profiles found: "
            f"{reference_keys or 'none'}"
        )
    if target_count == 0:
        violations.append("the registry names no target-class profile")

    records = registry.get("records", [])
    if not isinstance(records, list):
        return violations + ["registry 'records' must be an array of tables"]

    per_profile_dates: dict[str, list[dt.date]] = {}
    for index, record in enumerate(records):
        where = f"records[{index}]"
        if not isinstance(record, dict):
            violations.append(f"{where}: must be a table")
            continue

        profile_key = record.get("profile")
        if profile_key not in profiles:
            violations.append(
                f"{where}.profile {profile_key!r} is not in [profiles]"
            )
            profile_key = None

        outcome = record.get("outcome")
        if outcome not in RECORD_OUTCOMES:
            violations.append(
                f"{where}.outcome must be one of {list(RECORD_OUTCOMES)}, "
                f"found {outcome!r}"
            )
            outcome = None

        submitted_by = record.get("submitted_by")
        if not isinstance(submitted_by, str) or not submitted_by.strip():
            violations.append(
                f"{where}.submitted_by must be a non-empty string (a public "
                "contributor handle or 'maintainer')"
            )
        else:
            violations.extend(identifier_violations(f"{where}.submitted_by", submitted_by))

        date = parse_date(record.get("date", ""))
        if date is None:
            violations.append(
                f"{where}.date must be an ISO 8601 calendar date (YYYY-MM-DD)"
            )
        elif profile_key is not None:
            per_profile_dates.setdefault(profile_key, []).append(date)

        allowed = (
            RECORD_KEYS_QUALIFIED if outcome == "qualified"
            else RECORD_KEYS_UNQUALIFIED if outcome == "unqualified"
            else RECORD_KEYS_COMMON
        )
        unknown = set(record) - allowed
        if unknown:
            violations.append(
                f"{where}: fields {sorted(unknown)} do not belong to a "
                f"{outcome or 'well-formed'} record"
            )

        for field in ("reason", "note"):
            if field in record:
                value = record[field]
                if not isinstance(value, str) or not value.strip():
                    violations.append(f"{where}.{field} must be a non-empty string")
                else:
                    violations.extend(identifier_violations(f"{where}.{field}", value))

        if outcome == "unqualified":
            if "reason" not in record:
                violations.append(
                    f"{where}: an unqualified record must state why no "
                    "capability claim exists"
                )
        elif outcome == "qualified":
            for field in ("suite_revision", "operator"):
                value = record.get(field)
                if not isinstance(value, str) or not value.strip():
                    violations.append(
                        f"{where}.{field} is required on a qualified record "
                        "and must be a non-empty string"
                    )
                else:
                    violations.extend(identifier_violations(f"{where}.{field}", value))
            capability = record.get("capability")
            if not isinstance(capability, dict):
                violations.append(
                    f"{where}.capability is required on a qualified record: "
                    "the observed five-axis matrix"
                )
            else:
                unknown_axes = set(capability) - set(CAPABILITY_AXES)
                if unknown_axes:
                    violations.append(
                        f"{where}.capability: unknown axes {sorted(unknown_axes)}"
                    )
                for axis, tokens in CAPABILITY_AXES.items():
                    value = capability.get(axis)
                    if value not in tokens:
                        violations.append(
                            f"{where}.capability.{axis} must be one of "
                            f"{list(tokens)}, found {value!r}"
                        )

    for key, profile in profiles.items():
        profile_records = [
            record for record in records
            if isinstance(record, dict) and record.get("profile") == key
        ]
        if profile.get("class") == "community" and not profile_records:
            violations.append(
                f"profiles.{key}: a community profile with no record is the "
                "silent claim this registry exists to prevent — record an "
                "explicit qualified or unqualified standing"
            )
        if profile.get("class") in ("reference", "target") and profile_records:
            violations.append(
                f"profiles.{key}: {profile['class']}-class profiles are "
                "qualified by the suite's own lanes, not by records here"
            )

    for key, dates in per_profile_dates.items():
        if dates != sorted(dates):
            violations.append(
                f"records for profile {key!r} are not in append-only date "
                "order; a profile's standing is its latest record"
            )

    return violations


def standing(registry: dict, profile_key: str) -> tuple[str, str] | None:
    """The (outcome, date) of a profile's latest record, or ``None``."""
    dated: list[tuple[dt.date, str]] = []
    for record in registry.get("records", []):
        if not isinstance(record, dict) or record.get("profile") != profile_key:
            continue
        date = parse_date(record.get("date", ""))
        if date is not None:
            dated.append((date, record.get("outcome", "")))
    if not dated:
        return None
    dated.sort()
    return dated[-1][1], dated[-1][0].isoformat()


# --- document coherence -----------------------------------------------------


def validate_coherence(registry: dict, readme: str, note: str) -> list[str]:
    violations: list[str] = []
    profiles = registry.get("profiles", {})

    for label, text in (("README.md", readme), (str(NOTE_PATH), note)):
        if RETIRED_CLAIM in text:
            violations.append(
                f"{label}: the claim {RETIRED_CLAIM!r} is retired; a profile "
                "is usable exactly when a recorded run says so"
            )

    table_rows = {
        match.group("key"): match.groupdict()
        for match in STANDING_ROW_RE.finditer(note)
    }
    for key, profile in profiles.items():
        row = table_rows.get(key)
        if row is None:
            violations.append(
                f"{NOTE_PATH}: the standing table has no row for {key!r}"
            )
            continue
        if profile.get("class") == "community":
            current = standing(registry, key)
            if current is None:
                continue  # already a registry violation
            outcome, date = current
            if row["standing"].strip() != outcome:
                violations.append(
                    f"{NOTE_PATH}: standing for {key!r} says "
                    f"{row['standing'].strip()!r}; the registry's latest "
                    f"record says {outcome!r}"
                )
            if row["evidence"].strip() != f"record {date}":
                violations.append(
                    f"{NOTE_PATH}: evidence for {key!r} must cite the latest "
                    f"record as 'record {date}', found {row['evidence'].strip()!r}"
                )

    if str(NOTE_PATH).rsplit("/", 1)[-1] not in readme and "docs/notes/storage-profiles.md" not in readme:
        violations.append(
            "README.md must link docs/notes/storage-profiles.md, where the "
            "qualification path and records live"
        )
    unqualified = [
        key for key, profile in profiles.items()
        if profile.get("class") == "community"
        and (standing(registry, key) or ("", ""))[0] == "unqualified"
    ]
    if unqualified:
        if "unqualified" not in readme:
            violations.append(
                "README.md must state the unqualified standing of community "
                f"profiles ({', '.join(sorted(unqualified))}) instead of an "
                "unevidenced expectation"
            )
        for key in unqualified:
            display = COMMUNITY_DISPLAY_NAMES.get(key)
            if display and display not in readme:
                violations.append(
                    f"README.md must name the community profile {display!r} "
                    f"({key}) when stating its standing"
                )

    return violations


def validate_all(registry: dict, readme: str, note: str) -> list[str]:
    return validate_registry(registry) + validate_coherence(registry, readme, note)


# --- self-test ----------------------------------------------------------------


def apply_mutation(base: dict, mutation) -> dict:
    registry = copy.deepcopy(base)
    mutation(registry)
    return registry


def add_qualified_garage_record(registry: dict) -> None:
    registry["records"].append(
        {
            "profile": "garage",
            "date": "2026-10-01",
            "outcome": "qualified",
            "submitted_by": "community-contributor",
            "suite_revision": "v0.2.0-suite",
            "operator": "community-contributor",
            "capability": {
                "conditional_create": "supported",
                "multipart_commit_abort": "verified",
                "stored_checksum": "md5",
                "versioning": "enabled",
                "server_side_encryption": "unavailable",
            },
        }
    )


def set_unknown_class(registry: dict) -> None:
    registry["profiles"]["aws-s3"]["class"] = "experimental"


def unpin_reference_profile(registry: dict) -> None:
    registry["profiles"]["minio"]["class"] = "target"


SELF_TEST_REGISTRY_CASES = [
    ("the committed registry", False, lambda r: None),
    ("a wrong schema token", True,
     lambda r: r.update(schema="archivist.storage-profiles/v2")),
    ("an unknown profile class", True, set_unknown_class),
    ("the reference profile unpinned from MinIO", True, unpin_reference_profile),
    ("a community profile with no record", True,
     lambda r: r["profiles"].__setitem__(
         "ceph", {"class": "community", "description": "Ceph RGW"})),
    ("a record on the reference profile", True,
     lambda r: r["records"].append(
         {"profile": "minio", "date": "2026-09-15", "outcome": "unqualified",
          "submitted_by": "maintainer", "reason": "must not be recorded here"})),
    ("an unknown outcome token", True,
     lambda r: r["records"][0].update({"outcome": "expected-usable"})),
    ("an unqualified record without a reason", True,
     lambda r: r["records"][0].pop("reason")),
    ("an unqualified record carrying capabilities", True,
     lambda r: r["records"][0].update(
         {"capability": {"conditional_create": "supported"}})),
    ("a qualified record without a suite revision", True,
     lambda r: add_qualified_garage_record(r)
     or r["records"][-1].pop("suite_revision")),
    ("a qualified record without the capability matrix", True,
     lambda r: add_qualified_garage_record(r)
     or r["records"][-1].pop("capability")),
    ("a qualified record with an open capability token", True,
     lambda r: add_qualified_garage_record(r)
     or r["records"][-1]["capability"].update({"versioning": "sometimes"})),
    ("a qualified record with multipart unverified", True,
     lambda r: add_qualified_garage_record(r)
     or r["records"][-1]["capability"].update(
         {"multipart_commit_abort": "unavailable"})),
    ("a qualified record carrying a reason", True,
     lambda r: add_qualified_garage_record(r)
     or r["records"][-1].update({"reason": "qualified anyway"})),
    ("an incomplete capability matrix", True,
     lambda r: add_qualified_garage_record(r)
     or r["records"][-1]["capability"].pop("stored_checksum")),
    ("records reordered after the fact", True,
     lambda r: r["records"].append(
         {"profile": "garage", "date": "2026-01-01", "outcome": "unqualified",
          "submitted_by": "maintainer", "reason": "backdated"})),
    ("an endpoint smuggled into a reason", True,
     lambda r: r["records"][0].update(
         {"reason": "tested once against https://example.invalid/run"})),
    ("a non-calendar date", True,
     lambda r: r["records"][0].update({"date": "2026-02-30"})),
]

# A qualified record changes a profile's standing, so it can only be shown
# to pass alongside the note edit that records the new standing (SP-008):
# these cases mutate the registry and the note together. A qualified record
# whose note row still states the old standing is itself a rejection path.
SELF_TEST_COMBINED_CASES = [
    ("a well-formed qualified community record", False,
     add_qualified_garage_record,
     lambda note: note.replace(
         "| `garage` | community | unqualified | record 2026-09-15 |",
         "| `garage` | community | qualified | record 2026-10-01 |", 1)),
    ("a qualified record the note's table still calls unqualified", True,
     add_qualified_garage_record,
     lambda note: note),
]

SELF_TEST_TEXT_CASES = [
    ("the committed README and note", False, lambda readme, note: (readme, note)),
    ("the retired claim restored to the README", True,
     lambda readme, note: (readme.replace("community profiles", "expected to be usable community profiles", 1), note)),
    ("the note standing flipped against the registry", True,
     lambda readme, note: (
         readme,
         note.replace("| `aws-s3` | community | unqualified |",
                      "| `aws-s3` | community | qualified |", 1))),
    ("the note evidence citing a stale record date", True,
     lambda readme, note: (
         readme,
         note.replace("record 2026-09-15 |", "record 2026-08-01 |", 1))),
    ("the README dropping the note link", True,
     lambda readme, note: (
         readme.replace("storage-profiles.md", "verification.md"),
         note)),
    ("the README hiding the unqualified standing", True,
     lambda readme, note: (readme.replace("unqualified", "untested"), note)),
]


def run_self_test(base_registry: dict, base_readme: str, base_note: str) -> int:
    passed = 0
    failed = 0

    for label, must_reject, mutation in SELF_TEST_REGISTRY_CASES:
        registry = apply_mutation(base_registry, mutation)
        violations = validate_all(registry, base_readme, base_note)
        rejected = bool(violations)
        if rejected == must_reject:
            passed += 1
            print(f"  ok  {'rejects' if rejected else 'accepts'}: {label}")
        else:
            failed += 1
            print(f"  FAIL {'should reject' if must_reject else 'should accept'}: "
                  f"{label}")
            for violation in violations:
                print(f"       violation: {violation}")

    for label, must_reject, mutation in SELF_TEST_TEXT_CASES:
        readme, note = mutation(base_readme, base_note)
        violations = validate_all(base_registry, readme, note)
        rejected = bool(violations)
        if rejected == must_reject:
            passed += 1
            print(f"  ok  {'rejects' if rejected else 'accepts'}: {label}")
        else:
            failed += 1
            print(f"  FAIL {'should reject' if must_reject else 'should accept'}: "
                  f"{label}")
            for violation in violations:
                print(f"       violation: {violation}")

    for label, must_reject, reg_mutation, note_mutation in SELF_TEST_COMBINED_CASES:
        registry = apply_mutation(base_registry, reg_mutation)
        note = note_mutation(base_note)
        violations = validate_all(registry, base_readme, note)
        rejected = bool(violations)
        if rejected == must_reject:
            passed += 1
            print(f"  ok  {'rejects' if rejected else 'accepts'}: {label}")
        else:
            failed += 1
            print(f"  FAIL {'should reject' if must_reject else 'should accept'}: "
                  f"{label}")
            for violation in violations:
                print(f"       violation: {violation}")

    print(f"self-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        registry = load_registry(ROOT / REGISTRY_PATH)
        readme = load_text(ROOT / README_PATH)
        note = load_text(ROOT / NOTE_PATH)
        if registry is None or readme is None or note is None:
            return 2
        if validate_all(registry, readme, note):
            fail("self-test base: the committed registry itself is invalid")
            return 2
        return run_self_test(registry, readme, note)
    if argv[1:]:
        fail(f"unknown arguments: {' '.join(argv[1:])}")
        return 2

    registry = load_registry(ROOT / REGISTRY_PATH)
    readme = load_text(ROOT / README_PATH)
    note = load_text(ROOT / NOTE_PATH)
    if registry is None or readme is None or note is None:
        return 2

    violations = validate_all(registry, readme, note)
    for violation in violations:
        fail(violation)
    if violations:
        return 2

    profiles = registry["profiles"]
    print(f"agent-archivist storage-profile registry: {REGISTRY_SCHEMA}")
    for key in sorted(profiles):
        profile = profiles[key]
        line = f"  {key} ({profile['class']}): "
        if profile["class"] == "community":
            outcome, date = standing(registry, key) or ("no record", "")
            line += f"{outcome} ({date})"
        else:
            line += "qualified by the suite's own lanes"
        print(line)
    community = sum(1 for p in profiles.values() if p["class"] == "community")
    print(f"profiles: {len(profiles)} ({community} community), "
          f"records: {len(registry.get('records', []))}")
    print(f"OK: registry satisfies docs/notes/storage-profiles.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
