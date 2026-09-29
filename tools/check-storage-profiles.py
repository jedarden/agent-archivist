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
2. reference profiles carry no qualification records, while target records
   are reserved for redacted release-live evidence and every community
   profile carries at least one record, so no profile is silently claimable;
   the B2 release gate separately requires a qualified live record for the
   requested release (an absent record is a gate failure);
3. a record's outcome is ``qualified`` or ``unqualified`` and its shape is
   the outcome's: ``unqualified`` states a non-empty reason, a SemVer
   release, and offers no capability fields, ``qualified`` states the suite
   revision, the operator, and the full five-axis capability matrix with
   closed tokens and ``multipart_commit_abort`` verified — the one primitive
   a backend cannot lack and still be a profile at all;
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
7. while a community profile's latest record is ``unqualified``, the
   release and support policy states that record's versioned negative
   disposition — the record's release, the unqualified standing, the
   deferral or exclusion, and the no-support / no-deployment /
   no-capability denials — and no sentence of the README, RELEASE.md,
   SUPPORT.md, or the registry note names the profile without carrying
   that disposition: a deployment-profile or support claim for an
   unqualified profile is a gate failure (SP-009), derived from the
   records rather than pinned to any one release.

``--self-test`` runs the same validators against the committed registry
with embedded mutations (plus README, note, release, and support edits in memory) and
requires every rejection path to fire and every well-formed variant to
pass. On success the plain run prints the computed standing per profile
and exits 0; any failure prints a report on stderr and exits 2.

Usage::

    tools/check-storage-profiles.py [--self-test | --release SEMVER]

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
RELEASE_PATH = Path("RELEASE.md")
SUPPORT_PATH = Path("SUPPORT.md")
DOD_PATH = Path("scripts/definition-of-done.sh")

REGISTRY_SCHEMA = "archivist.storage-profiles/v1"

# docs/notes/storage-profiles.md Section 1. The reference class is MinIO's
# alone (plan Section 7.7); the gate pins that along with the token set.
PROFILE_CLASSES = ("reference", "target", "community")
REFERENCE_PROFILE = "minio"

# docs/notes/storage-profiles.md Section 3: the closed field sets per record.
RECORD_OUTCOMES = ("qualified", "unqualified")
RECORD_KEYS_COMMON = frozenset({"profile", "date", "outcome", "submitted_by", "note"})
RECORD_KEYS_UNQUALIFIED = RECORD_KEYS_COMMON | {"reason", "release"}
RECORD_KEYS_QUALIFIED = RECORD_KEYS_COMMON | {"suite_revision", "operator", "capability"}
TARGET_RECORD_KEYS_COMMON = RECORD_KEYS_COMMON | {"evidence", "release"}
TARGET_RECORD_KEYS_UNQUALIFIED = TARGET_RECORD_KEYS_COMMON | {"reason"}
TARGET_RECORD_KEYS_QUALIFIED = TARGET_RECORD_KEYS_COMMON | {
    "suite_revision", "operator", "capability"
}

# A target's synthetic lane is a prerequisite, not release evidence. Target
# records are therefore a separate, explicitly live shape. B2 is the target
# whose release-support claim this gate currently protects; ARMOR has its own
# deployment gate and may use the same record shape when that gate is wired.
LIVE_EVIDENCE = "live"
LIVE_RELEASE_PROFILES = ("backblaze-b2",)

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
RELEASE_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)

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


STORAGE_GATE_LINE = re.compile(
    r"^\s*run_check\s+\"storage profiles\"\s+"
    r"python3\s+tools/check-storage-profiles\.py\s+--self-test\s*$",
    re.M,
)
FAST_LANE_BLOCK = (
    'if [ "$LANE" = "fast" ] || [ "$LANE" = "all" ]; then',
    'if [ "$LANE" = "slow" ] || [ "$LANE" = "all" ]; then',
)


def validate_definition_of_done(text: str) -> list[str]:
    """Keep the registry gate in the fast lane used by ``--all``.

    The checker cannot enforce its own invocation if the invocation disappears
    from the definition-of-done script.  Checking the integration here gives
    the self-test a regression case for that exact failure, while the normal
    registry check also catches a manually run tree whose release gate has
    drifted.
    """
    violations: list[str] = []
    matches = list(STORAGE_GATE_LINE.finditer(text))
    if len(matches) != 1:
        violations.append(
            "scripts/definition-of-done.sh must invoke the storage-profile "
            "self-test exactly once"
        )
        return violations

    fast_start = text.find(FAST_LANE_BLOCK[0])
    slow_start = text.find(FAST_LANE_BLOCK[1])
    match_start = matches[0].start()
    if fast_start < 0 or slow_start < 0 or not fast_start < match_start < slow_start:
        violations.append(
            "the storage-profile self-test must run in the definition-of-done "
            "fast/all lane"
        )
    return violations


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

        profile_class = (
            profiles.get(profile_key, {}).get("class")
            if profile_key is not None else None
        )
        target_record = profile_class == "target"
        allowed = (
            TARGET_RECORD_KEYS_QUALIFIED if target_record and outcome == "qualified"
            else TARGET_RECORD_KEYS_UNQUALIFIED if target_record and outcome == "unqualified"
            else RECORD_KEYS_QUALIFIED if outcome == "qualified"
            else RECORD_KEYS_UNQUALIFIED if outcome == "unqualified"
            else TARGET_RECORD_KEYS_COMMON if target_record else RECORD_KEYS_COMMON
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

        if target_record:
            evidence = record.get("evidence")
            if evidence != LIVE_EVIDENCE:
                violations.append(
                    f"{where}.evidence must be {LIVE_EVIDENCE!r} on a target record"
                )
            release = record.get("release")
            if not isinstance(release, str) or not RELEASE_RE.match(release):
                violations.append(
                    f"{where}.release is required on a target live record and "
                    "must be a SemVer release"
                )

        if outcome == "unqualified":
            if "reason" not in record:
                violations.append(
                    f"{where}: an unqualified record must state why no "
                    "capability claim exists"
                )
            release = record.get("release")
            if not isinstance(release, str) or not RELEASE_RE.match(release):
                violations.append(
                    f"{where}.release is required on an unqualified record "
                    "and must be a SemVer release"
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
        if profile.get("class") == "reference" and profile_records:
            violations.append(
                "profiles.minio: the reference profile is qualified by the "
                "suite's own lane, not by records here"
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


def latest_record(registry: dict, profile_key: str) -> tuple[dt.date, dict] | None:
    """The (date, record) of a profile's latest record, or ``None``."""
    dated: list[tuple[dt.date, dict]] = []
    for record in registry.get("records", []):
        if not isinstance(record, dict) or record.get("profile") != profile_key:
            continue
        date = parse_date(record.get("date", ""))
        if date is not None:
            dated.append((date, record))
    if not dated:
        return None
    return max(dated, key=lambda item: item[0])


def latest_live_record_for_release(
    registry: dict, profile_key: str, release: str
) -> dict | None:
    """Return the newest live record for one target release.

    Equal-day records are resolved in append order, so a later failed rerun
    cannot be hidden by an earlier pass on the same day.
    """
    candidates = [
        (index, record)
        for index, record in enumerate(registry.get("records", []))
        if isinstance(record, dict)
        and record.get("profile") == profile_key
        and record.get("evidence") == LIVE_EVIDENCE
        and record.get("release") == release
        and parse_date(record.get("date", "")) is not None
    ]
    if not candidates:
        return None
    _, record = max(
        candidates,
        key=lambda item: (parse_date(item[1]["date"]), item[0]),
    )
    return record


def validate_release_live(registry: dict, release: str) -> list[str]:
    """Require release-live evidence before a protected target is claimable."""
    violations: list[str] = []
    if not isinstance(release, str) or not RELEASE_RE.match(release):
        return [f"release gate requires a SemVer release, found {release!r}"]

    for profile_key in LIVE_RELEASE_PROFILES:
        profile = registry.get("profiles", {}).get(profile_key)
        if not isinstance(profile, dict) or profile.get("class") != "target":
            violations.append(
                f"release gate profile {profile_key!r} is not a target profile"
            )
            continue
        record = latest_live_record_for_release(registry, profile_key, release)
        if record is None:
            violations.append(
                f"release {release}: {profile_key} has no live qualification "
                "record; synthetic evidence cannot support the release claim"
            )
        elif record.get("outcome") != "qualified":
            violations.append(
                f"release {release}: {profile_key} live qualification is "
                f"{record.get('outcome')!r}; B2 support claims are blocked"
            )
    return violations


def unqualified_community_profiles(registry: dict) -> dict[str, dict]:
    """Community profiles whose latest record is ``unqualified``, keyed by
    profile, each carrying the governing record (the versioned deferral a
    later release must supersede before any claim can exist)."""
    governing: dict[str, dict] = {}
    for key, profile in registry.get("profiles", {}).items():
        if profile.get("class") != "community":
            continue
        latest = latest_record(registry, key)
        if latest is not None and latest[1].get("outcome") == "unqualified":
            governing[key] = latest[1]
    return governing


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
            expected_evidence = f"record {date}"
            if outcome == "unqualified":
                latest_community_record = max(
                    (
                        record for record in registry.get("records", [])
                        if isinstance(record, dict)
                        and record.get("profile") == key
                        and parse_date(record.get("date", "")) is not None
                    ),
                    key=lambda record: parse_date(record["date"]),
                )
                record_release = latest_community_record.get("release")
                if isinstance(record_release, str) and RELEASE_RE.match(record_release):
                    expected_evidence += f" (release {record_release})"
            if row["evidence"].strip() != expected_evidence:
                violations.append(
                    f"{NOTE_PATH}: evidence for {key!r} must cite the latest "
                    f"record as {expected_evidence!r}, found "
                    f"{row['evidence'].strip()!r}"
                )
        elif key in LIVE_RELEASE_PROFILES:
            latest = latest_record(registry, key)
            if latest is not None:
                date, record = latest
                expected_evidence = f"record {date.isoformat()}"
                if expected_evidence not in row["evidence"]:
                    violations.append(
                        f"{NOTE_PATH}: live evidence for {key!r} must cite "
                        f"{expected_evidence!r}"
                    )
                if row["standing"].strip() != "release-gated":
                    violations.append(
                        f"{NOTE_PATH}: target {key!r} must be marked "
                        "release-gated rather than unconditionally qualified"
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


# SP-009's claims prohibition at sentence level: a sentence of a policy
# document that names an unqualified community profile must carry one of
# these markers, so an affirmative mention cannot stand in for the negative
# disposition. Sentences split on a period or semicolon followed by
# whitespace — a version number's internal periods never split, and each
# sentence is whitespace-normalized so a name wrapped across source lines
# still matches.
CLAIM_SENTENCE_SPLIT = re.compile(r"(?<=[.;])\s+")

DISPOSITION_MARKERS = (
    "unqualified",
    "unsupported",
    "not supported",
    "no deployment",
    "no capability",
    "no support",
    "deferred",
    "excluded",
    "neither is supported",
)


def claim_sentences(text: str) -> list[str]:
    """Whitespace-normalized sentences of a policy document."""
    return [
        " ".join(sentence.split())
        for sentence in CLAIM_SENTENCE_SPLIT.split(text or "")
        if sentence.strip()
    ]


def validate_release_support(
    registry: dict, release: str, support: str, readme: str, note: str
) -> list[str]:
    """SP-009 at gate strength, derived from the records rather than pinned:
    while a community profile's latest record is ``unqualified``, the release
    and support policy must state that record's versioned negative
    disposition, and no sentence of the policy documents may name the
    profile without carrying the disposition — a deployment-profile or
    support claim for an unqualified profile is a gate failure, not
    documentation."""
    violations: list[str] = []
    unqualified = unqualified_community_profiles(registry)

    for label, text in ((str(RELEASE_PATH), release), (str(SUPPORT_PATH), support)):
        normalized = " ".join(text.split())
        for key, record in sorted(unqualified.items()):
            display = COMMUNITY_DISPLAY_NAMES.get(key, key)
            governing_release = record.get("release", "")
            required = (
                display,
                "unqualified",
                "not supported",
                "no deployment",
                "no capability claim",
                governing_release,
            )
            for term in required:
                if term and term not in normalized:
                    violations.append(
                        f"{label} must explicitly name {display} ({key}) as "
                        f"unqualified with no deployment or capability claim "
                        f"for release {governing_release} (missing {term!r})"
                    )
            if not any(term in normalized for term in ("deferred", "excluded")):
                violations.append(
                    f"{label} must state the versioned deferral or exclusion "
                    f"of {display} ({key}) for release {governing_release}"
                )

    policy_docs = {
        "README.md": readme,
        str(RELEASE_PATH): release,
        str(SUPPORT_PATH): support,
        str(NOTE_PATH): note,
    }
    for key, record in sorted(unqualified.items()):
        display = COMMUNITY_DISPLAY_NAMES.get(key, key)
        names = (display, key)
        for label, text in policy_docs.items():
            for sentence in claim_sentences(text):
                if not any(name in sentence for name in names):
                    continue
                lowered = sentence.lower()
                if not any(marker in lowered for marker in DISPOSITION_MARKERS):
                    violations.append(
                        f"{label}: a sentence names {display} ({key}) without "
                        f"its unqualified disposition — no deployment-profile "
                        f"or support claim may exist while the latest record "
                        f"(release {record.get('release', 'n/a')}) says "
                        "unqualified (SP-009)"
                    )
    return violations


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
    ("an unqualified record without a release", True,
     lambda r: r["records"][0].pop("release")),
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


# Every free-text field is subject to PUB-002/SEC-010's identifier ban. Keep
# one mutation per field so a future shape change cannot quietly stop scanning
# one of the record variants. The target record at the end of the committed
# registry supplies the qualified-only fields.
SELF_TEST_SENSITIVE_FIELD_CASES = [
    ("an infrastructure URL in a profile description", True,
     lambda r: r["profiles"]["aws-s3"].update(
         description="community profile at https://example.invalid")),
    ("an address-shaped submitter", True,
     lambda r: r["records"][0].update(
         submitted_by="operator@example.invalid")),
    ("an IPv4 address in a reason", True,
     lambda r: r["records"][0].update(reason="run reached 192.0.2.10")),
    ("a tailnet hostname in a record note", True,
     lambda r: r["records"][0].update(note="operator.example.ts.net")),
    ("an address-shaped qualified operator", True,
     lambda r: r["records"][-1].update(operator="operator@example.invalid")),
    ("an infrastructure URL in a suite revision", True,
     lambda r: r["records"][-1].update(
         suite_revision="https://example.invalid/revision")),
]


def remove_storage_gate(text: str) -> str:
    return STORAGE_GATE_LINE.sub("# storage-profile gate removed", text, count=1)


def remove_all_storage_gate(text: str) -> str:
    return text.replace(
        'if [ "$LANE" = "fast" ] || [ "$LANE" = "all" ]; then',
        'if [ "$LANE" = "fast" ]; then',
        1,
    )


SELF_TEST_INTEGRATION_CASES = [
    ("the storage gate in the fast/all lane", False, lambda text: text),
    ("the definition-of-done storage gate removed", True, remove_storage_gate),
    ("the storage gate no longer included by --all", True,
     remove_all_storage_gate),
]

# A qualified record changes a profile's standing, so it can only be shown
# to pass alongside the note edit that records the new standing (SP-008):
# these cases mutate the registry and the note together. A qualified record
# whose note row still states the old standing is itself a rejection path.
SELF_TEST_COMBINED_CASES = [
    ("a well-formed qualified community record", False,
     add_qualified_garage_record,
     lambda note: note.replace(
         "| `garage` | community | unqualified | record 2026-09-27 (release 1.0.0) |",
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
         note.replace("record 2026-09-27 (release 1.0.0) |",
                      "record 2026-08-01 |", 1))),
    ("the README dropping the note link", True,
     lambda readme, note: (
         readme.replace("storage-profiles.md", "verification.md"),
         note)),
    ("the README hiding the unqualified standing", True,
     lambda readme, note: (readme.replace("unqualified", "untested"), note)),
]

# Policy-document cases mutate whichever of the four policy documents the
# claims prohibition reads (release, support, README, note); the committed
# registry and the unmutated siblings stay in scope, because the validator
# derives the unqualified set from the records.
SELF_TEST_POLICY_CASES = [
    ("the committed policy documents", False, lambda docs: None),
    ("release policy omits the negative disposition", True,
     lambda docs: docs.update(
         release=re.sub(r"not\s+supported", "supported", docs["release"]))),
    ("support policy omits the no-support claim", True,
     lambda docs: docs.update(
         support=docs["support"].replace("unqualified", "qualified", 1))),
    ("the release policy dropping the governing release", True,
     lambda docs: docs.update(
         release=docs["release"].replace("1.0.0", "9.9.9"))),
    ("a release note claiming AWS S3 support", True,
     lambda docs: docs.update(release=docs["release"] + "\n"
         "AWS S3 is a supported storage profile for production deployments.")),
    ("a deployment-profile claim for Garage in the support policy", True,
     lambda docs: docs.update(support=docs["support"] + "\n"
         "Garage deployment profile: point the endpoint at the instance "
         "and deploy.")),
    ("a README sentence naming Garage without its disposition", True,
     lambda docs: docs.update(readme=docs["readme"] + "\n"
         "Garage works today.")),
    ("a note sentence claiming AWS S3 was tested", True,
     lambda docs: docs.update(note=docs["note"] + "\n"
         "AWS S3 passed the full suite.")),
]

LIVE_RELEASE = "0.1.0"


def b2_live_records(registry: dict) -> list[dict]:
    return [
        record for record in registry["records"]
        if isinstance(record, dict)
        and record.get("profile") == "backblaze-b2"
        and record.get("evidence") == LIVE_EVIDENCE
    ]


def remove_b2_live_record(registry: dict) -> None:
    registry["records"] = [
        record for record in registry["records"]
        if not (
            isinstance(record, dict)
            and record.get("profile") == "backblaze-b2"
            and record.get("evidence") == LIVE_EVIDENCE
        )
    ]


def fail_b2_live_record(registry: dict) -> None:
    records = b2_live_records(registry)
    if records:
        records[-1].update(
            outcome="unqualified",
            reason="live run failed before all instruments completed",
        )
        for field in ("suite_revision", "operator", "capability"):
            records[-1].pop(field, None)


SELF_TEST_LIVE_RELEASE_CASES = [
    ("the committed B2 live release record", False, lambda r: None),
    ("B2 live evidence missing for the release", True, remove_b2_live_record),
    ("B2 live run failed for the release", True, fail_b2_live_record),
    ("B2 live evidence belongs to another release", True,
     lambda r: b2_live_records(r)[-1].update(release="9.9.9")),
]


def run_self_test(base_registry: dict, base_readme: str, base_note: str,
                  base_release: str, base_support: str, base_dod: str) -> int:
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

    for label, must_reject, mutation in SELF_TEST_SENSITIVE_FIELD_CASES:
        registry = apply_mutation(base_registry, mutation)
        violations = validate_registry(registry)
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

    for label, must_reject, mutation in SELF_TEST_INTEGRATION_CASES:
        violations = validate_definition_of_done(mutation(base_dod))
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

    for label, must_reject, mutation in SELF_TEST_POLICY_CASES:
        docs = {
            "release": base_release,
            "support": base_support,
            "readme": base_readme,
            "note": base_note,
        }
        mutation(docs)
        violations = validate_release_support(
            base_registry, docs["release"], docs["support"],
            docs["readme"], docs["note"])
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

    for label, must_reject, mutation in SELF_TEST_LIVE_RELEASE_CASES:
        registry = apply_mutation(base_registry, mutation)
        violations = validate_release_live(registry, LIVE_RELEASE)
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
    if argv[1:] == ["--self-test"]:
        registry = load_registry(ROOT / REGISTRY_PATH)
        readme = load_text(ROOT / README_PATH)
        note = load_text(ROOT / NOTE_PATH)
        release = load_text(ROOT / RELEASE_PATH)
        support = load_text(ROOT / SUPPORT_PATH)
        dod = load_text(ROOT / DOD_PATH)
        if (registry is None or readme is None or note is None
                or release is None or support is None or dod is None):
            return 2
        if (validate_all(registry, readme, note)
                or validate_release_support(registry, release, support,
                                            readme, note)
                or validate_definition_of_done(dod)):
            fail("self-test base: the committed storage-profile gate is invalid")
            return 2
        return run_self_test(registry, readme, note, release, support, dod)
    requested_release = None
    if len(argv) == 3 and argv[1] == "--release":
        requested_release = argv[2]
    elif argv[1:]:
        fail(f"unknown arguments: {' '.join(argv[1:])}")
        return 2

    registry = load_registry(ROOT / REGISTRY_PATH)
    readme = load_text(ROOT / README_PATH)
    note = load_text(ROOT / NOTE_PATH)
    release = load_text(ROOT / RELEASE_PATH)
    support = load_text(ROOT / SUPPORT_PATH)
    dod = load_text(ROOT / DOD_PATH)
    if (registry is None or readme is None or note is None
            or release is None or support is None or dod is None):
        return 2

    violations = (validate_all(registry, readme, note)
                  + validate_release_support(registry, release, support,
                                             readme, note)
                  + validate_definition_of_done(dod))
    if requested_release is not None:
        violations += validate_release_live(registry, requested_release)
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
        elif key in LIVE_RELEASE_PROFILES:
            if requested_release is None:
                line += "release-live evidence required (use --release SEMVER)"
            else:
                line += f"live-qualified ({requested_release})"
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
