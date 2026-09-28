#!/usr/bin/env python3
"""Noncurrent-version lifecycle gate for Agent Archivist.

Versioning enabled plus deterministic overwrite (STO-006) means every
replayed duplicate and equivalent overwrite lands a noncurrent physical
version behind the current one, and requirements STO-009 makes expiring
those copies a deployment action — subject to retention policy, and, per
``docs/notes/s3-noncurrent-lifecycle.md``, scoped so the current version
of a source-of-truth object is never a lifecycle target. The guidance
lives in that note (the retention matrix); the machine-readable record is
``tools/s3-lifecycle-rules.toml``; this gate rejects any state of the
committed tree in which the records disagree with each other or the
invariant fails:

1. registry shape — the pinned schema and guidance id, six closed
   prefix families with unique ids, partitioning ``subprefixes``, a
   closed overwrite vocabulary, six prefix-family current-version policies,
   three profiles with their versioning
   shape, and one rule per (profile, family) cell plus the reserved
   bucket-wide multipart row; rule actions are the closed five-token set,
   ``days`` is present exactly for the actions that take one, and every
   ``not-applicable`` cell carries its profile-shape reason;
2. the protection invariant (L-001) — a rule aimed at a family whose
   current versions are protected may only ``expire-noncurrent``,
   ``retain-noncurrent``, or declare itself ``not-applicable``;
   ``expire-objects`` (current versions included) is legal only for an
   explicitly expirable family, which today means the probe namespace
   alone;
3. the current-pointer pin (L-002) — for every profile whose versioning
   is enabled, the ``control-current-pointer`` cell is exactly
   ``retain-noncurrent`` and no other family carries that action;
4. the control split — the registry's two control families partition the
   control-records registry (``tools/control-records.toml``) by write
   class exactly: the current-pointer families' ``subprefixes`` are the
   object-key segments of the ``current-pointer`` records and the
   immutable family's are the ``immutable`` records', so a new or
   reclassified control record fails here until the matrix says how its
   versions age;
5. the note's retention-matrix table agrees with the registry row for
   row: same cells, same actions, same days;
6. the guidance id the noncurrent-version audit renders
   (``NONCURRENT_VERSION_GUIDANCE`` in
   ``crates/archivist-storage/src/lifecycle_audit.rs``) equals the
   registry's ``guidance_id`` — the citation quoted out of context still
   names the duty it measures;
7. the reference provisioning script configures exactly the minio raw
   cell: its pinned noncurrent-expiration days equal the registry's
   ``(minio, raw)`` rule's.

``--self-test`` runs the same validators against the committed files with
embedded mutations and requires every rejection path to fire and the
unmutated tree to pass. On success the plain run prints the covered
matrix and exits 0; any failure prints a report on stderr and exits 2.

Usage::

    tools/check-s3-lifecycle.py [--self-test]

The script is standard-library only and offline: it validates committed
records against committed records — the lifecycle rules themselves are
operator-managed and invisible to every archivist identity, so what this
gate proves is that the *documented* configuration cannot drift from the
invariant, not that a live bucket carries it (the audit store and the
reference profile's live ``verify`` are the live-side halves,
s3-noncurrent-lifecycle.md Section 5).
"""

from __future__ import annotations

import copy
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = Path("tools/s3-lifecycle-rules.toml")
NOTE_PATH = Path("docs/notes/s3-noncurrent-lifecycle.md")
CONTROL_RECORDS_PATH = Path("tools/control-records.toml")
MINIO_SCRIPT_PATH = Path("tools/minio-reference-provision.sh")
AUDIT_SOURCE_PATH = Path("crates/archivist-storage/src/lifecycle_audit.rs")

REGISTRY_SCHEMA = "archivist.s3-lifecycle/v1"
GUIDANCE_CONSTANT_RE = re.compile(
    r"NONCURRENT_VERSION_GUIDANCE\s*:\s*&str\s*=\s*\"(?P<guidance>[^\"]+)\""
)
MINIO_DAYS_RE = re.compile(r"^RAW_NONCURRENT_EXPIRE_DAYS=(?P<days>\d+)$", re.M)
CONTROL_KEY_RE = re.compile(r"^tenants/<[^>]+>/v1/control/(?P<segment>[^/]+)/")

# The closed rule vocabulary; the actions that carry a `days` value.
ACTION_DAYS = {"expire-noncurrent", "expire-objects", "abort-incomplete-multipart"}
ACTION_NO_DAYS = {"retain-noncurrent", "not-applicable"}
ACTIONS = ACTION_DAYS | ACTION_NO_DAYS
OVERWRITES = frozenset({"convergent", "epoch-replacement"})
PROFILE_CLASSES = frozenset({"reference", "target"})
VERSIONING_SHAPES = frozenset({"enabled", "raw-bucket-only"})
CURRENT_VERSION_POLICIES = frozenset({"protected", "expirable"})

# The reserved scopes outside the profile/family registries: the
# bucket-wide multipart row.
RESERVED_PROFILE = "all"
RESERVED_FAMILY = "multipart"

DAYS_FLOOR = 1
DAYS_CEILING = 365


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def read_toml(path: Path) -> dict | None:
    try:
        with (ROOT / path).open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read {path}: {exc}")
        return None


def read_text(path: Path) -> str | None:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")
        return None


def note_section(note: str, heading: str) -> str:
    """Return the body of the ``## <heading>`` section."""
    match = re.search(
        rf"^## {re.escape(heading)}\s*$(.*?)(?=^## |\Z)",
        note,
        re.M | re.S,
    )
    return match.group(1) if match else ""


def table_rows(section: str) -> list[list[str]]:
    """Parse a markdown table into rows of raw cells."""
    rows: list[list[str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        if re.fullmatch(r"\|(?:\s*:?-+:?\s*\|)+", stripped):
            continue  # header separator
        rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
    return rows


def rule_days(rule: dict) -> int | None:
    return rule.get("days")


def check_registry_shape(registry: dict) -> bool:
    """Rule 1: pinned schema, closed vocabularies, one rule per cell."""
    if registry.get("schema") != REGISTRY_SCHEMA:
        fail(f"registry schema is {registry.get('schema')!r}, "
             f"expected {REGISTRY_SCHEMA!r}")
        return False
    if not isinstance(registry.get("guidance_id"), str) or \
            not registry["guidance_id"]:
        fail("registry guidance_id must be a non-empty string")
        return False

    families = registry.get("family")
    if not isinstance(families, list) or not families:
        fail("registry declares no [[family]] rows")
        return False
    family_ids: set[str] = set()
    seen_subprefixes: dict[str, str] = {}
    ok = True
    for family in families:
        fid = family.get("id", "")
        label = f"family {fid!r}"
        if not fid or fid in family_ids:
            fail(f"{label}: family id is empty or duplicated")
            ok = False
            continue
        family_ids.add(fid)
        if family.get("overwrite") not in OVERWRITES:
            fail(f"{label}: overwrite {family.get('overwrite')!r} is not one "
                 f"of {sorted(OVERWRITES)}")
            ok = False
        if not isinstance(family.get("source_of_truth"), bool):
            fail(f"{label}: source_of_truth must be a boolean")
            ok = False
        if family.get("current_versions") not in CURRENT_VERSION_POLICIES:
            fail(f"{label}: current_versions "
                 f"{family.get('current_versions')!r} is not one of "
                 f"{sorted(CURRENT_VERSION_POLICIES)}")
            ok = False
        subprefixes = family.get("subprefixes")
        if not isinstance(subprefixes, list) or not subprefixes or \
                not all(isinstance(s, str) and s for s in subprefixes):
            fail(f"{label}: subprefixes must be a non-empty list of strings")
            ok = False
            continue
        for subprefix in subprefixes:
            if subprefix in seen_subprefixes:
                fail(f"{label}: subprefix {subprefix!r} is already covered "
                     f"by family {seen_subprefixes[subprefix]!r}; the "
                     "families must partition the tenant tree")
                ok = False
            seen_subprefixes[subprefix] = fid

    profiles = registry.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        fail("registry declares no [profiles.*] tables")
        return False
    for name, profile in profiles.items():
        if profile.get("class") not in PROFILE_CLASSES:
            fail(f"profile {name!r}: class {profile.get('class')!r} is not "
                 f"one of {sorted(PROFILE_CLASSES)}")
            ok = False
        if profile.get("versioning") not in VERSIONING_SHAPES:
            fail(f"profile {name!r}: versioning {profile.get('versioning')!r} "
                 f"is not one of {sorted(VERSIONING_SHAPES)}")
            ok = False
        note_ref = profile.get("note", "")
        if not note_ref or not (ROOT / note_ref).exists():
            fail(f"profile {name!r}: note {note_ref!r} does not exist")
            ok = False

    rules = registry.get("rule")
    if not isinstance(rules, list):
        fail("registry declares no [[rule]] rows")
        return False
    expected_cells = len(profiles) * len(families) + 1  # + the multipart row
    if len(rules) != expected_cells:
        fail(f"registry declares {len(rules)} rules, expected exactly "
             f"{expected_cells} (one per profile × family, plus the "
             "bucket-wide multipart row); every cell must be explicit — "
             "an absent row says the matrix was not filled in")
        ok = False
    seen_cells: set[tuple[str, str]] = set()
    for rule in rules:
        profile = rule.get("profile", "")
        family = rule.get("family", "")
        cell = (profile, family)
        label = f"rule {cell}"
        if cell in seen_cells:
            fail(f"{label}: duplicate (profile, family) cell")
            ok = False
        seen_cells.add(cell)
        action = rule.get("action", "")
        if action not in ACTIONS:
            fail(f"{label}: action {action!r} is not one of {sorted(ACTIONS)}")
            ok = False
            continue
        days = rule_days(rule)
        if action in ACTION_DAYS:
            if not isinstance(days, int) or not DAYS_FLOOR <= days <= DAYS_CEILING:
                fail(f"{label}: action {action!r} needs an integer days in "
                     f"[{DAYS_FLOOR}, {DAYS_CEILING}], got {days!r}")
                ok = False
        elif days is not None:
            fail(f"{label}: action {action!r} takes no days, got {days!r}")
            ok = False
        if action == "not-applicable" and not rule.get("reason"):
            fail(f"{label}: not-applicable requires the profile-shape reason")
            ok = False
        if action != "not-applicable" and rule.get("reason"):
            fail(f"{label}: only a not-applicable cell carries a reason")
            ok = False
        if profile != RESERVED_PROFILE and profile not in profiles:
            fail(f"{label}: unknown profile {profile!r}")
            ok = False
        if profile == RESERVED_PROFILE and family != RESERVED_FAMILY:
            fail(f"{label}: the reserved {RESERVED_PROFILE!r} profile scope "
                 f"carries only the {RESERVED_FAMILY!r} family")
            ok = False
        if family != RESERVED_FAMILY and family not in family_ids:
            fail(f"{label}: unknown family {family!r}")
            ok = False

    # Every real profile must state a cell for every family.
    for name in profiles:
        for fid in family_ids:
            if (name, fid) not in seen_cells:
                fail(f"registry has no ({name!r}, {fid!r}) rule; every "
                     "profile × family cell must be explicit")
                ok = False
    return ok


def rules_by_cell(registry: dict) -> dict[tuple[str, str], dict]:
    return {(rule.get("profile", ""), rule.get("family", "")): rule
            for rule in registry.get("rule", [])}


def check_protection_invariant(registry: dict) -> bool:
    """Rule 2 (L-001): tenant current versions are untouchable."""
    current_versions = {family["id"]: family.get("current_versions")
                        for family in registry.get("family", [])}
    source_of_truth = {family["id"]: family.get("source_of_truth", False)
                       for family in registry.get("family", [])}
    ok = True
    for rule in registry.get("rule", []):
        family = rule.get("family", "")
        action = rule.get("action", "")
        cell = (rule.get("profile", ""), family)
        if family == RESERVED_FAMILY:
            continue
        if current_versions.get(family, "protected") != "expirable" \
                and action == "expire-objects":
            fail(f"rule {cell}: expire-objects would expire CURRENT versions "
                 f"of protected tenant family ({family!r}); current versions "
                 "under raw, control, catalog, and derived are never a "
                 "lifecycle target (L-001)")
            ok = False
        if not source_of_truth.get(family, True) and \
                action not in ("expire-objects", "expire-noncurrent",
                               "not-applicable"):
            fail(f"rule {cell}: action {action!r} does not age anything; a "
                 "family that is not source-of-truth is either expired or "
                 "declared not-applicable")
            ok = False
    return ok


def check_current_pointer_pin(registry: dict) -> bool:
    """Rule 3 (L-002): the current-pointer cell retains, and only it."""
    versioning = registry.get("profiles", {})
    ok = True
    for rule in registry.get("rule", []):
        profile, family = rule.get("profile", ""), rule.get("family", "")
        if profile == RESERVED_PROFILE:
            continue
        if versioning.get(profile, {}).get("versioning") != "enabled":
            continue
        if family == "control-current-pointer":
            if rule.get("action") != "retain-noncurrent":
                fail(f"rule {(profile, family)}: action "
                     f"{rule.get('action')!r} on a versioned profile; the "
                     "current-pointer families' noncurrent copies are the "
                     "previous signed trust epoch's only copy at that key "
                     "and are retained indefinitely (L-002)")
                ok = False
        elif rule.get("action") == "retain-noncurrent":
            fail(f"rule {(profile, family)}: retain-noncurrent is the "
                 "current-pointer families' action alone (L-002)")
            ok = False
    return ok


def check_control_split(registry: dict) -> bool:
    """Rule 4: the registry's control families match the control-records
    registry's write classes exactly."""
    records = read_toml(CONTROL_RECORDS_PATH)
    if records is None:
        return False
    by_class: dict[str, set[str]] = {"current-pointer": set(), "immutable": set()}
    for record in records.get("records", {}).values():
        write_class = record.get("write_class")
        if write_class not in by_class:
            fail(f"control-records registry carries write_class "
                 f"{write_class!r}, which this gate does not know; extend "
                 "the gate and the lifecycle matrix in the same commit")
            return False
        match = CONTROL_KEY_RE.match(record.get("object_key", ""))
        if not match:
            fail(f"control record with object_key {record.get('object_key')!r} "
                 "does not follow the tenants/<tenant>/v1/control/<segment>/ "
                 "shape")
            return False
        by_class[write_class].add(f"control/{match.group('segment')}")

    registry_classes = {
        "current-pointer": "control-current-pointer",
        "immutable": "control-immutable",
    }
    families = {family["id"]: family for family in registry.get("family", [])}
    ok = True
    for write_class, family_id in registry_classes.items():
        family = families.get(family_id)
        declared = set(family.get("subprefixes", [])) if family else set()
        derived = by_class[write_class]
        if declared != derived:
            fail(f"family {family_id!r} declares {sorted(declared)}, but the "
                 f"control-records registry's {write_class!r} records derive "
                 f"{sorted(derived)}; the lifecycle matrix must say how "
                 "every control record family's versions age, in the same "
                 "commit as the record change")
            ok = False
    return ok


def check_note_matrix(registry: dict, note: str) -> bool:
    """Rule 5: the note's retention-matrix table agrees with the registry."""
    section = note_section(note, "3. The retention matrix")
    if not section:
        fail("note has no '## 3. The retention matrix' section")
        return False
    rows = table_rows(section)
    if not rows:
        fail("note's retention-matrix section contains no table")
        return False
    header, data_rows = rows[0], rows[1:]
    if header != ["Profile", "Family", "Rule", "Days", "Basis"]:
        fail(f"note's matrix header is {header}, expected "
             "Profile/Family/Rule/Days/Basis")
        return False

    registry_cells = rules_by_cell(registry)
    seen: set[tuple[str, str]] = set()
    ok = True
    for row in data_rows:
        if len(row) != 5:
            fail(f"matrix row {row!r} does not have five cells")
            ok = False
            continue
        profile, family, action, days_text, _basis = row
        cell = (profile, family)
        if cell in seen:
            fail(f"matrix row {cell} appears twice")
            ok = False
        seen.add(cell)
        rule = registry_cells.get(cell)
        if rule is None:
            fail(f"matrix row {cell} is not in the registry")
            ok = False
            continue
        if action != rule.get("action"):
            fail(f"matrix row {cell}: rule {action!r} != registry "
                 f"{rule.get('action')!r}")
            ok = False
        days = int(days_text) if days_text not in ("—", "") else None
        if days != rule_days(rule):
            fail(f"matrix row {cell}: days {days_text!r} != registry "
                 f"{rule_days(rule)!r}")
            ok = False
    missing = sorted(set(registry_cells) - seen)
    if missing:
        fail(f"matrix table is missing registry cells: {missing}")
        ok = False
    return ok


def check_guidance_constant(registry: dict, audit_source: str) -> bool:
    """Rule 6: the audit's rendered guidance id equals the registry's."""
    match = GUIDANCE_CONSTANT_RE.search(audit_source)
    if not match:
        fail("could not find NONCURRENT_VERSION_GUIDANCE in "
             f"{AUDIT_SOURCE_PATH}")
        return False
    if match.group("guidance") != registry.get("guidance_id"):
        fail(f"the audit renders guidance {match.group('guidance')!r} but the "
             f"registry pins {registry.get('guidance_id')!r}; the citation "
             "and the registry are one contract — move them in the same "
             "commit")
        return False
    return True


def check_minio_script(registry: dict, script: str) -> bool:
    """Rule 7: the reference script configures the (minio, raw) cell."""
    rule = rules_by_cell(registry).get(("minio", "raw"))
    if rule is None:
        fail("registry has no (minio, raw) rule for the script to configure")
        return False
    match = MINIO_DAYS_RE.search(script)
    if not match:
        fail(f"{MINIO_SCRIPT_PATH} does not pin RAW_NONCURRENT_EXPIRE_DAYS; "
             "the reference profile's noncurrent-expiration rule must be "
             "machine-applied, not prose")
        return False
    if int(match.group("days")) != rule.get("days"):
        fail(f"{MINIO_SCRIPT_PATH} pins "
             f"RAW_NONCURRENT_EXPIRE_DAYS={match.group('days')} but the "
             f"registry's (minio, raw) cell says {rule.get('days')}")
        return False
    if "noncurrent-expire-days" not in script:
        fail(f"{MINIO_SCRIPT_PATH} never passes --noncurrent-expire-days; "
             "the rule must select noncurrent versions only (L-001)")
        return False
    return True


CHECKS = (
    ("registry shape", "shape", lambda reg, note, rec, script, src: check_registry_shape(reg)),
    ("protection invariant", "protection", lambda reg, note, rec, script, src: check_protection_invariant(reg)),
    ("current-pointer pin", "pin", lambda reg, note, rec, script, src: check_current_pointer_pin(reg)),
    ("control split", "split", lambda reg, note, rec, script, src: check_control_split(reg)),
    ("note matrix table", "note", lambda reg, note, rec, script, src: check_note_matrix(reg, note)),
    ("guidance constant", "guidance", lambda reg, note, rec, script, src: check_guidance_constant(reg, src)),
    ("minio script", "script", lambda reg, note, rec, script, src: check_minio_script(reg, script)),
)


def run_all(registry: dict, note: str, control_records_unused: str,
            script: str, audit_source: str) -> bool:
    # The control-records TOML is read inside its own check (the mutation
    # sweep never edits it); parse it once here to fail fast on a broken
    # file.
    if read_toml(CONTROL_RECORDS_PATH) is None:
        return False
    ok = True
    for name, _key, check in CHECKS:
        if not check(registry, note, None, script, audit_source):
            ok = False
    return ok


def self_test(registry: dict, note: str, script: str, audit_source: str) -> bool:
    """Prove every rejection path fires and the committed tree passes."""
    if not run_all(registry, note, "", script, audit_source):
        fail("self-test: the committed tree already fails the gate; fix it "
             "before the mutation sweep can mean anything")
        return False

    # Text mutations, keyed by mutation index — keep in sync with
    # MUTATIONS below.
    note_days_drift = note.replace(
        "| minio | raw | expire-noncurrent | 30 |",
        "| minio | raw | expire-noncurrent | 31 |", 1)
    note_row_drop = note.replace(
        "| armor | derived | expire-noncurrent | 7 | STO-011, STO-012 |\n",
        "", 1)
    text_mutations = {11: note_days_drift, 12: note_row_drop}

    # Rule indices: 0-5 minio, 6-11 backblaze-b2, 12-17 armor in family
    # order raw / control-current-pointer / control-immutable / catalog /
    # derived / probe, then 18 the bucket-wide multipart row.
    mutations = (
        # (label, targeted check key, mutator)
        ("protection invariant (expire-objects on raw)",
         "protection",
         lambda reg, note_t, script_t: reg["rule"][12].update(
             {"action": "expire-objects"})),
        ("protection invariant (expire-objects on control current-pointer)",
         "protection",
         lambda reg, note_t, script_t: reg["rule"][13].update(
             {"action": "expire-objects"})),
        ("protection invariant (expire-objects on control immutable)",
         "protection",
         lambda reg, note_t, script_t: reg["rule"][14].update(
             {"action": "expire-objects"})),
        ("protection invariant (expire-objects on catalog)",
         "protection",
         lambda reg, note_t, script_t: reg["rule"][15].update(
             {"action": "expire-objects"})),
        ("protection invariant (expire-objects on derived)",
         "protection",
         lambda reg, note_t, script_t: reg["rule"][16].update(
             {"action": "expire-objects"})),
        ("protection invariant (retain on a rebuildable family)",
         "protection",
         lambda reg, note_t, script_t: reg["rule"][10].update(
             {"action": "retain-noncurrent", "days": None})),
        ("current-pointer pin (expire the pointer history)",
         "pin",
         lambda reg, note_t, script_t: reg["rule"][13].update(
             {"action": "expire-noncurrent", "days": 30})),
        ("current-pointer pin (retain a redundant family)",
         "pin",
         lambda reg, note_t, script_t: reg["rule"][9].update(
             {"action": "retain-noncurrent", "days": None})),
        ("control split (steal an immutable segment)",
         "split",
         lambda reg, note_t, script_t: reg["family"][1]["subprefixes"].append(
             "control/revocations")),
        ("registry shape (duplicate cell)",
         "shape",
         lambda reg, note_t, script_t: reg["rule"].append(
             dict(reg["rule"][0]))),
        ("registry shape (not-applicable without a reason)",
         "shape",
         lambda reg, note_t, script_t: reg["rule"][1].pop("reason")),
        ("note matrix table (days drift)",
         "note",
         lambda reg, note_t, script_t: None),
        ("note matrix table (dropped row)",
         "note",
         lambda reg, note_t, script_t: None),
        ("guidance constant (registry drift)",
         "guidance",
         lambda reg, note_t, script_t: reg.update({"guidance_id": "sto-009"})),
        ("minio script (registry days drift)",
         "script",
         lambda reg, note_t, script_t: next(
             r for r in reg["rule"]
             if (r["profile"], r["family"]) == ("minio", "raw")
         ).update({"days": 45})),
    )

    ok = True
    for index, (label, expected_key, mutate) in enumerate(mutations):
        reg_copy = copy.deepcopy(registry)
        mutate(reg_copy, text_mutations.get(index, note), script)
        for name, key, check in CHECKS:
            if key != expected_key:
                continue
            if check(reg_copy, text_mutations.get(index, note), None,
                     script, audit_source):
                fail(f"self-test: mutation {label!r} did not fire the "
                     f"{name!r} rejection")
                ok = False
    if not ok:
        return False

    print(f"lifecycle gate self-test: {len(mutations)} mutations, every "
          "rejection path fired; committed tree passes")
    return True


def main() -> int:
    registry = read_toml(REGISTRY_PATH)
    note = read_text(NOTE_PATH)
    script = read_text(MINIO_SCRIPT_PATH)
    audit_source = read_text(AUDIT_SOURCE_PATH)
    if registry is None or note is None or script is None or audit_source is None:
        return 2

    if "--self-test" in sys.argv[1:]:
        if not self_test(registry, note, script, audit_source):
            return 2
        return 0

    if not run_all(registry, note, "", script, audit_source):
        return 2

    rules = registry["rule"]
    expiring = sum(1 for r in rules
                   if r["action"] in ("expire-noncurrent", "expire-objects"))
    print(f"s3 lifecycle gate: {len(rules)} rule cells, {expiring} expiring, "
          "current tenant versions unreachable by every rule; "
          "registry, note, control records, audit constant, and reference "
          "script agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
