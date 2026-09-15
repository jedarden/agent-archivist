#!/usr/bin/env python3
"""ARMOR storage-identity gate for Agent Archivist.

The ARMOR-side storage decision for this tenant — the prefix tree and the
six scoped identities that gate it — lives in
``docs/notes/armor-storage-provisioning.md``; the machine-readable record
is ``tools/armor-identities.toml``; this gate rejects any state of the two
that disagrees with the other. It reads committed files only, so it runs
on a clean checkout with no network access and no credentials — which is
the point: the registry records *references* (names, ACL strings, OpenBao
paths), never values, and a provisioning change that alters the identity
set must update the note and the registry in the same commit or the gate
fails. What it cannot see is OpenBao itself; verifying the provisioned
state against the documented one is the rotation procedure's job (property
checks against the live instance), and the gate's job is to make the
documented set unable to drift silently — internally, or from the
registry.

Policy, one rule per check below:

1. the registry declares exactly the pinned schema and exactly the six
   identities, each with a unique role, auth-file name, and OpenBao path;
   auth-file names are ``ARCHIVIST_<ROLE>`` and per-role paths follow
   ``secret/rs-manager/iad-ci/armor/archivist-<role-slug>``;
2. every ACL entry is a well-formed ARMOR ADR-012 string,
   ``<bucket>:<prefix>:<verbs>`` with a non-empty ``+``-joined verb set
   from {get, put, delete, list, abort} — no duplicates, no empty verb —
   under this tenant's bucket and prefix tree;
3. no identity holds ``delete`` (the note pins this permanently: ``abort``
   never implies ``delete`` and nothing in the set may destroy a committed
   object), and ``abort`` — the one teardown verb — is granted only to the
   raw writer, over its own prefix;
4. holder classes are the plan's control-plane boundary: exactly the
   ingest-replica pair {control reader, raw writer}, exactly the offline
   pair {control admin, backup/restore}, exactly the Phase 10 pipeline
   pair {catalog writer, derived writer}; a Phase 10 writer is exactly
   ``put+list`` — it never reads object bodies back through the write
   identity; and the rotation cadence follows residence (90 days for
   resident classes, 180 for offline);
5. the note's identities table agrees with the registry row for row:
   same six roles, same auth-file names, same ACL strings (the note's
   brace-expansion shorthand for the backup/restore grants is expanded
   before comparison), same holders, same OpenBao paths;
6. the note's current-state counts all say six — the pinned sentences are
   present and the stale four-identity phrasings appear nowhere they can
   creep back from (historical counts, such as the original four-entry
   provisioning record, are labeled as history and are not matched by the
   forbidden patterns); the merged auth-file document's entry count is
   pinned the same way (twelve 4-line entries since the Phase 10 writers
   were appended, not the stale ten);
7. the note's prefix table marks ``catalog/`` and ``derived/`` as more
   than bare "reserved, Phase 10" — their writers are provisioned, and a
   revert of the Status column is a gate failure, not a silent downgrade.

``--self-test`` runs the same validators against the committed registry
and note with embedded mutations and requires every rejection path to
fire and the unmutated pair to pass. On success the plain run prints the
verified identity set and exits 0; any failure prints a report on stderr
and exits 2.

Usage::

    tools/check-armor-identities.py [--self-test]

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
REGISTRY_PATH = Path("tools/armor-identities.toml")
NOTE_PATH = Path("docs/notes/armor-storage-provisioning.md")

REGISTRY_SCHEMA = "archivist.armor-identities/v1"
IDENTITY_COUNT = 6

# docs/notes/armor-storage-provisioning.md preamble: the ADR-012 verb set.
ACL_VERBS = frozenset({"get", "put", "delete", "list", "abort"})
ACL_RE = re.compile(
    r"^iad-ci:agent-archivist/(?P<sub>[a-z0-9-]+)/\*:(?P<verbs>[a-z+]+)$"
)
AUTH_FILE_NAME_RE = re.compile(r"^ARCHIVIST_[A-Z0-9_]+$")
OPENBAO_PATH_RE = re.compile(
    r"^secret/rs-manager/iad-ci/armor/archivist-(?P<slug>[a-z0-9-]+)$"
)

# docs/notes/armor-storage-provisioning.md "Identities": the classes are
# the plan §"Control-plane boundary" plus Phase 10, and their membership
# is exact — a new identity is a plan change and edits this gate in the
# same commit.
CLASS_INGEST = "ingest-replica"
CLASS_OFFLINE = "offline"
CLASS_PHASE10 = "phase10-pipeline"
CLASS_MEMBERSHIP = {
    CLASS_INGEST: frozenset({"control reader", "raw writer"}),
    CLASS_OFFLINE: frozenset({"control admin", "backup/restore"}),
    CLASS_PHASE10: frozenset({"catalog writer", "derived writer"}),
}
CLASS_ROTATION_DAYS = {CLASS_INGEST: 90, CLASS_OFFLINE: 180, CLASS_PHASE10: 90}
RESIDENT_CLASSES = frozenset({CLASS_INGEST, CLASS_PHASE10})

# The note's current-state count sentences, pinned by rule 6.
REQUIRED_PHRASES = (
    "Six credentials, disjoint action-by-prefix policy.",
    "The same six pairs are entries in the ARMOR_AUTH_FILE",
    "The six identities are long-lived machine credentials",
    "rotate any of the six roles",
    "overrides the calendar for all six",
    "twelve 4-line entries",
)
FORBIDDEN_PHRASES = (
    "Four credentials, disjoint",
    "the same four pairs",
    "The four identities are long-lived",
    "any of the four roles",
    "the calendar for all four",
    "the four archivist credentials",
    "hold all four",
    "ten 4-line entries",
)

# docs/notes/armor-storage-provisioning.md "Prefix layout": the reserved
# prefixes whose writers are provisioned must say so.
WRITER_PROVISIONED_MARKER = "writer provisioned"
BARE_RESERVED_STATUS = "reserved, phase 10"


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def normalize(text: str) -> str:
    """Collapse whitespace so sentence pins survive a reflow."""
    return " ".join(text.split())


def role_slug(role: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", role.lower()).strip("-")


def read_registry() -> dict | None:
    path = ROOT / REGISTRY_PATH
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read {REGISTRY_PATH}: {exc}")
        return None


def read_note() -> str | None:
    path = ROOT / NOTE_PATH
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read {NOTE_PATH}: {exc}")
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
    """Parse a markdown table into rows of backtick-stripped cells."""
    rows: list[list[str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        if re.fullmatch(r"\|(?:\s*:?-+:?\s*\|)+", stripped):
            continue  # header separator
        cells = [cell.strip().strip("`").strip() for cell in stripped.strip("|").split("|")]
        rows.append(cells)
    return rows


def expand_acl_cell(cell: str) -> list[str]:
    """Expand the note's ACL shorthand into explicit ADR-012 entries.

    Handles ``iad-ci:agent-archivist/{raw,control,...}/*:get+list`` (with an
    optional trailing parenthetical) into one entry per brace alternative.
    """
    cell = re.sub(r"\s*\([^)]*\)\s*$", "", cell.replace("`", "")).strip()
    brace = re.fullmatch(r"(.*)\{([^}]+)\}(.*)", cell)
    if not brace:
        return [cell]
    head, alternatives, tail = brace.groups()
    return [head + alt.strip() + tail for alt in alternatives.split(",")]


def check_registry_shape(registry: dict) -> bool:
    """Rule 1: pinned schema, exactly six identities, unique keys, grammars."""
    if registry.get("schema") != REGISTRY_SCHEMA:
        fail(f"registry schema is {registry.get('schema')!r}, "
             f"expected {REGISTRY_SCHEMA!r}")
        return False
    identities = registry.get("identity")
    if not isinstance(identities, list) or len(identities) != IDENTITY_COUNT:
        fail(f"registry declares {len(identities) if isinstance(identities, list) else 'no'} "
             f"identities, expected exactly {IDENTITY_COUNT}; a new identity "
             "is a plan change and updates CLASS_MEMBERSHIP in this gate in "
             "the same commit")
        return False

    seen_roles: set[str] = set()
    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    ok = True
    for identity in identities:
        role = identity.get("role", "")
        label = f"identity {role!r}"
        if role in seen_roles:
            fail(f"{label}: duplicate role")
            ok = False
        seen_roles.add(role)

        name = identity.get("auth_file_name", "")
        if name in seen_names:
            fail(f"{label}: duplicate auth-file name {name!r}")
            ok = False
        seen_names.add(name)
        if not AUTH_FILE_NAME_RE.fullmatch(name):
            fail(f"{label}: auth-file name {name!r} is not ARCHIVIST_<ROLE>")
            ok = False

        path = identity.get("openbao_path", "")
        if path in seen_paths:
            fail(f"{label}: duplicate OpenBao path {path!r}")
            ok = False
        seen_paths.add(path)
        path_match = OPENBAO_PATH_RE.fullmatch(path)
        if not path_match:
            fail(f"{label}: OpenBao path {path!r} is not "
                 "secret/rs-manager/iad-ci/armor/archivist-<role-slug>")
            ok = False
        elif path_match.group("slug") != role_slug(role):
            fail(f"{label}: OpenBao path slug {path_match.group('slug')!r} "
                 f"does not match role {role!r}")
            ok = False

        provisioned = identity.get("provisioned", "")
        try:
            dt.date.fromisoformat(provisioned)
        except ValueError:
            fail(f"{label}: provisioned {provisioned!r} is not an ISO date")
            ok = False

        if identity.get("rotation_interval_days") not in (90, 180):
            fail(f"{label}: rotation_interval_days "
                 f"{identity.get('rotation_interval_days')!r} is not 90 or 180")
            ok = False
    return ok


def parsed_acl(identity: dict) -> list[tuple[str, frozenset[str]]] | None:
    """Return (prefix, verbs) per ACL entry, or None on any malformed entry."""
    parsed: list[tuple[str, frozenset[str]]] = []
    for entry in identity.get("acl", []):
        match = ACL_RE.fullmatch(entry)
        if not match:
            fail(f"identity {identity.get('role')!r}: ACL {entry!r} is not "
                 "iad-ci:agent-archivist/<prefix>/*:<verbs>")
            return None
        verbs = frozenset(match.group("verbs").split("+"))
        if not verbs or not verbs <= ACL_VERBS:
            unknown = sorted(verbs - ACL_VERBS)
            fail(f"identity {identity.get('role')!r}: ACL {entry!r} uses "
                 f"verbs outside ADR-012's set: {unknown or 'none'}")
            return None
        if len(verbs) != len(match.group("verbs").split("+")):
            fail(f"identity {identity.get('role')!r}: ACL {entry!r} repeats "
                 "a verb")
            return None
        parsed.append((match.group("sub"), verbs))
    if not parsed:
        fail(f"identity {identity.get('role')!r}: no ACL entries")
        return None
    prefixes = [prefix for prefix, _ in parsed]
    if len(prefixes) != len(set(prefixes)):
        fail(f"identity {identity.get('role')!r}: a prefix appears in two "
             "ACL entries")
        return None
    return parsed


def check_acl_grammar(registry: dict) -> bool:
    """Rule 2: every ACL entry is well-formed ADR-012."""
    return all(
        parsed_acl(identity) is not None for identity in registry["identity"]
    )


def check_no_destroy(registry: dict) -> bool:
    """Rule 3: delete nowhere; abort only on the raw writer."""
    ok = True
    for identity in registry["identity"]:
        parsed = parsed_acl(identity)
        if parsed is None:
            ok = False
            continue
        role = identity["role"]
        for prefix, verbs in parsed:
            if "delete" in verbs:
                fail(f"identity {role!r}: holds delete over {prefix!r}; no "
                     "credential in this set may destroy a committed object "
                     "(abort never implies delete, and delete is not "
                     "granted at all)")
                ok = False
            if "abort" in verbs and role != "raw writer":
                fail(f"identity {role!r}: holds abort over {prefix!r}; the "
                     "one teardown verb is granted to the raw writer alone")
                ok = False
    return ok


def check_holder_classes(registry: dict) -> bool:
    """Rule 4: closed classes, exact membership, phase-10 shape, cadence."""
    identities = registry["identity"]
    ok = True
    by_class: dict[str, set[str]] = {}
    for identity in identities:
        role = identity.get("role", "")
        klass = identity.get("class")
        if klass not in CLASS_MEMBERSHIP:
            fail(f"identity {role!r}: class {klass!r} is not one of "
                 f"{sorted(CLASS_MEMBERSHIP)}")
            ok = False
            continue
        by_class.setdefault(klass, set()).add(role)

        if klass == CLASS_PHASE10:
            for entry in identity.get("acl", []):
                match = ACL_RE.fullmatch(entry)
                verbs = set(match.group("verbs").split("+")) if match else set()
                if verbs != {"put", "list"}:
                    fail(f"identity {role!r}: a phase10-pipeline writer is "
                         f"exactly put+list, not {entry!r} — it never reads "
                         "object bodies back through the write identity")
                    ok = False

        expected_days = CLASS_ROTATION_DAYS.get(klass)
        if expected_days is not None and \
                identity.get("rotation_interval_days") != expected_days:
            fail(f"identity {role!r}: class {klass!r} rotates on "
                 f"{expected_days} days, registry says "
                 f"{identity.get('rotation_interval_days')!r}")
            ok = False

    for klass, expected_roles in CLASS_MEMBERSHIP.items():
        actual = by_class.get(klass, set())
        if actual != set(expected_roles):
            fail(f"class {klass!r} holds {sorted(actual)}, expected exactly "
                 f"{sorted(expected_roles)}")
            ok = False
    return ok


def check_note_table(registry: dict, note: str) -> bool:
    """Rule 5: the note's identities table agrees with the registry."""
    section = note_section(note, "Identities")
    if not section:
        fail("note has no '## Identities' section")
        return False
    rows = table_rows(section)
    if not rows:
        fail("note's Identities section contains no table")
        return False
    header, data_rows = rows[0], rows[1:]
    if header[:5] != ["Role", "Auth-file name", "ACL", "Held by",
                      "OpenBao path (per-role copy)"]:
        fail(f"note's identities table header is {header[:5]}, expected the "
             "Role/Auth-file name/ACL/Held by/OpenBao path columns")
        return False

    by_role = {identity["role"]: identity for identity in registry["identity"]}
    seen_roles: set[str] = set()
    ok = True
    for row in data_rows:
        if len(row) < 5:
            fail(f"identities table row {row!r} does not have five cells")
            ok = False
            continue
        role, name, acl_cell, holder, path = row[:5]
        identity = by_role.get(role)
        if identity is None:
            fail(f"identities table row {role!r} is not in the registry")
            ok = False
            continue
        seen_roles.add(role)
        if name != identity["auth_file_name"]:
            fail(f"{role}: table auth-file name {name!r} != registry "
                 f"{identity['auth_file_name']!r}")
            ok = False
        expected_acl = sorted(identity["acl"])
        actual_acl = sorted(expand_acl_cell(acl_cell))
        if actual_acl != expected_acl:
            fail(f"{role}: table ACL {actual_acl} != registry {expected_acl}")
            ok = False
        if holder != identity["holder"]:
            fail(f"{role}: table holder {holder!r} != registry "
                 f"{identity['holder']!r}")
            ok = False
        if path != identity["openbao_path"]:
            fail(f"{role}: table OpenBao path {path!r} != registry "
                 f"{identity['openbao_path']!r}")
            ok = False

    missing = sorted(set(by_role) - seen_roles)
    if missing:
        fail(f"identities table is missing registry roles: {missing}")
        ok = False
    return ok


def check_note_counts(note: str) -> bool:
    """Rule 6: the note's current-state counts all say six."""
    normalized = normalize(note)
    ok = True
    for phrase in REQUIRED_PHRASES:
        if normalize(phrase) not in normalized:
            fail(f"note is missing the pinned current-state phrase: "
                 f"{phrase!r}")
            ok = False
    lowered = normalized.lower()
    for phrase in FORBIDDEN_PHRASES:
        if phrase.lower() in lowered:
            fail(f"note carries the stale four-identity count {phrase!r}; "
                 "the set is six — fix the count or label the sentence as "
                 "explicit history")
            ok = False
    return ok


def check_note_prefix_table(note: str) -> bool:
    """Rule 7: catalog/ and derived/ are marked writer-provisioned."""
    section = note_section(note, "Prefix layout")
    if not section:
        fail("note has no '## Prefix layout' section")
        return False
    rows = table_rows(section)
    if len(rows) < 2:
        fail("note's Prefix layout section contains no table")
        return False
    ok = True
    for row in rows[1:]:
        if len(row) < 3:
            continue
        prefix, _purpose, status = row[0], row[1], row[2]
        if prefix not in ("agent-archivist/catalog/",
                          "agent-archivist/derived/"):
            continue
        if status.strip().lower() == BARE_RESERVED_STATUS:
            fail(f"prefix table marks {prefix!r} as bare {status!r}; its "
                 "writer is provisioned — state the provisioning or explain "
                 "the retraction in the same commit")
            ok = False
        elif WRITER_PROVISIONED_MARKER not in status.lower():
            fail(f"prefix table status for {prefix!r} ({status!r}) lacks a "
                 f"{WRITER_PROVISIONED_MARKER!r} marker")
            ok = False
    return ok


CHECKS = (
    ("registry shape", lambda reg, note: check_registry_shape(reg)),
    ("ACL grammar", lambda reg, note: check_acl_grammar(reg)),
    ("no destroy capability", lambda reg, note: check_no_destroy(reg)),
    ("holder classes", lambda reg, note: check_holder_classes(reg)),
    ("note identities table", check_note_table),
    ("note count pins", lambda reg, note: check_note_counts(note)),
    ("note prefix table", lambda reg, note: check_note_prefix_table(note)),
)


def run_checks(registry: dict, note: str) -> bool:
    ok = True
    for name, check in CHECKS:
        if not check(registry, note):
            ok = False
    return ok


MUTATIONS = (
    ("registry shape (seventh identity)",
     "add a seventh identity",
     lambda reg, note: reg["identity"].append({
         "role": "audit reader", "auth_file_name": "ARCHIVIST_AUDIT_READER",
         "acl": ["iad-ci:agent-archivist/control/*:get"],
         "openbao_path": "secret/rs-manager/iad-ci/armor/archivist-audit-reader",
         "holder": "nobody", "class": "offline",
         "provisioned": "2026-09-15", "rotation_interval_days": 180,
     }), 0),
    ("registry shape (path naming)",
     "break the per-role path convention",
     lambda reg, note: reg["identity"][2].update({
         "openbao_path": "secret/rs-manager/iad-ci/armor/control-admin"}),
     0),
    ("ACL grammar (unknown verb)",
     "grant an out-of-set verb",
     lambda reg, note: reg["identity"][4].update({
         "acl": ["iad-ci:agent-archivist/catalog/*:put+list+read"]}), 1),
    ("no destroy capability (delete)",
     "grant delete to a writer",
     lambda reg, note: reg["identity"][4].update({
         "acl": ["iad-ci:agent-archivist/catalog/*:put+list+delete"]}), 2),
    ("no destroy capability (abort scope)",
     "grant abort to the derived writer",
     lambda reg, note: reg["identity"][5].update({
         "acl": ["iad-ci:agent-archivist/derived/*:put+list+abort"]}), 2),
    ("holder classes (wrong class)",
     "reclass the control admin as ingest-replica",
     lambda reg, note: reg["identity"][2].update({"class": CLASS_INGEST}), 3),
    ("holder classes (phase10 shape)",
     "give a phase10 writer get",
     lambda reg, note: reg["identity"][4].update({
         "acl": ["iad-ci:agent-archivist/catalog/*:get+put+list"]}), 3),
    ("note identities table (registry drift)",
     "change a registry ACL without touching the note",
     lambda reg, note: reg["identity"][0].update({
         "acl": ["iad-ci:agent-archivist/control/*:get"]}), 4),
    ("note identities table (dropped row)",
     "drop the derived-writer row from the note",
     lambda reg, note: None, 4),
    ("note count pins",
     "reintroduce the four-identity count",
     lambda reg, note: None, 5),
    ("note count pins (merged-document entry count)",
     "revert the merged document to the stale ten-entry count",
     lambda reg, note: None, 5),
    ("note prefix table",
     "revert the catalog prefix status",
     lambda reg, note: None, 6),
)


def self_test(registry: dict, note: str) -> bool:
    """Prove every rejection path fires and the committed pair passes."""
    if not run_checks(registry, note):
        fail("self-test: the committed registry and note already fail the "
             "gate; fix them before the mutation sweep can mean anything")
        return False

    ok = True

    # Text mutations rewrite the note before the validators run.
    note_row_drop = re.sub(
        r"^\| derived writer \|[^\n]*\n", "", note, count=1, flags=re.M)
    note_four_count = note.replace(
        "Six credentials, disjoint action-by-prefix policy.",
        "Four credentials, disjoint action-by-prefix policy.", 1)
    note_prefix_revert = note.replace(
        "reserved, Phase 10 — writer provisioned 2026-09-15",
        "reserved, Phase 10", 1)
    note_entry_count = note.replace(
        "twelve 4-line entries", "ten 4-line entries", 1)
    # Keys are MUTATIONS indices — keep them in sync with the tuple above.
    text_mutations = {
        8: note_row_drop, 9: note_four_count, 10: note_entry_count,
        11: note_prefix_revert,
    }

    for index, (label, action, mutate, expected_check) in enumerate(MUTATIONS):
        reg_copy = copy.deepcopy(registry)
        note_copy = text_mutations.get(index, note)
        mutate(reg_copy, note_copy)
        # Run only the validator the mutation targets, so an unrelated
        # co-failure (expected when registry and note disagree) cannot mask
        # the path under test.
        name, check = CHECKS[expected_check]
        if check(reg_copy, note_copy):
            fail(f"self-test: mutation {label!r} ({action}) did not fire "
                 f"the {name!r} rejection")
            ok = False
    if not ok:
        return False

    print(f"identity gate self-test: {len(MUTATIONS)} mutations, every "
          "rejection path fired; committed pair passes")
    return True


def main() -> int:
    registry = read_registry()
    note = read_note()
    if registry is None or note is None:
        return 2

    if "--self-test" in sys.argv[1:]:
        if not self_test(registry, note):
            return 2
        return 0

    if not run_checks(registry, note):
        return 2

    identities = registry["identity"]
    print(f"armor identity gate: {len(identities)} identities, "
          f"{sum(len(i['acl']) for i in identities)} ACL entries, no delete "
          "anywhere; note and registry agree")
    for identity in identities:
        print(f"  {identity['role']:16s} {identity['auth_file_name']:28s} "
              f"{identity['class']:16s} {identity['rotation_interval_days']}d")
    return 0


if __name__ == "__main__":
    sys.exit(main())
