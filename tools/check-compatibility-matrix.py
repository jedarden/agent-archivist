#!/usr/bin/env python3
"""Adapter compatibility-matrix gate for Agent Archivist.

The published source-adapter compatibility matrix lives in
``docs/notes/compatibility-matrix.md`` (plan Phase 6 exit gate: "the
committed compatibility matrix names every supported source fingerprint and
the inventory reports every observed fingerprint as supported or
unsupported"). This gate rejects any state of that note, the adapter
sources, and the fleet inventory that disagrees with the others. It reads
committed files only, so it runs on a clean checkout with no network access
and no credentials — the point is that a support claim is data pinned to the
evidence that earned it (threat ``AC-11``), and the published set cannot
drift silently from the allowlists the adapters actually embed.

Policy, one rule per check below:

1. **adapter matrix rows** — every released adapter's fingerprint allowlist
   and projection version, parsed from its own ``pub const`` declarations,
   matches the note's published-matrix table exactly: same fingerprints per
   adapter, same projection token, no unknown adapters, no missing rows;
2. **artifact kinds and states** — every row's artifact kind is one of the
   protocol's closed pair (``file-slice``, ``database-projection``) and
   every row's state is ``supported`` or ``unsupported``;
3. **observed reconciliation** — the note's reconciliation table carries
   exactly the fingerprints the fleet inventory observed (parsed from the
   inventory's "Observed fingerprints" section), each with a verdict from
   {supported, unsupported, unobserved}; a supported verdict must admit at
   least one published fingerprint and only published fingerprints, and any
   other verdict must claim no admission;
4. **pinned versions** — every adapter that pins a closed version
   vocabulary (OpenCode's ``ALLOWED_VERSIONS``) has each pinned version
   named in its matrix rows, so a widened or reversioned allowlist without
   a note edit fails;
5. **coverage vocabulary** — the note's six coverage states carry exactly
   the tokens and aggregate ranks parsed from
   ``archivist-adapter-sdk::status::CoverageState`` (requirement CAP-010:
   absent, unsupported, failed, partial, current, fully backfilled stay
   distinguishable and correctly ordered);
6. **phrase pins** — the note keeps its normative sentences: unknown
   fingerprints fail closed (plan ``EC-08``), allowlist/evidence/note
   change in the same commit, and the ``AC-11`` claim gate is named;
7. **marathon evidence** — the opencode row's marathon-scale paragraph
   (requirement ``CAP-004`` at scale) stays owned: its figures parse from
   the note and are pinned to the constants of
   ``crates/archivist-adapter-opencode/tests/marathon_scale.rs`` (sessions,
   allowlisted rows, growth append, scale multiple over the fleet count,
   and the bound relationships the recorded observations must respect),
   and the ``#[ignore]``d suite is invoked by the definition of done's
   slow lane — so the matrix's marathon evidence is re-measured by a gate
   and its published numbers cannot drift from what the suite asserts.

``--self-test`` runs the same validators against the committed sources and
note with embedded mutations and requires every rejection path to fire and
the unmutated tree to pass. On success the plain run prints the verified
matrix summary and exits 0; any failure prints a report on stderr and
exits 2.

Usage::

    tools/check-compatibility-matrix.py [--self-test]

The script is standard-library only.
"""

from __future__ import annotations

import copy
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTE_PATH = Path("docs/notes/compatibility-matrix.md")
INVENTORY_PATH = Path("docs/notes/fleet-source-inventory.md")
STATUS_SOURCE_PATH = Path("crates/archivist-adapter-sdk/src/status.rs")
# Rule 7's other two records: the marathon suite whose constants the note's
# figures are pinned to, and the definition of done whose slow lane
# re-measures it (the suite is `#[ignore]`d from ordinary lanes).
MARATHON_TEST_PATH = Path(
    "crates/archivist-adapter-opencode/tests/marathon_scale.rs")
DOD_PATH = Path("scripts/definition-of-done.sh")

# One entry per released adapter: where its constants live and which consts
# hold the identity, projection, fingerprint allowlist, and (when the
# dialect is version-gated) the pinned version vocabulary. A new adapter, a
# renamed const, or a moved file edits this table in the same commit as the
# note — that is the drift the gate exists to catch.
ADAPTERS = (
    {
        "id": "claude-jsonl",
        "source": Path("crates/archivist-adapter-claude/src/lib.rs"),
        "id_const": "ADAPTER_ID",
        "projection_const": "PROJECTION_VERSION",
        "fingerprint_consts": (
            ("JSONL_FINGERPRINTS", "array"),
            ("SIDECAR_FINGERPRINT", "string"),
        ),
        "allowed_versions_const": None,
    },
    {
        "id": "codex-jsonl",
        "source": Path("crates/archivist-adapter-codex/src/lib.rs"),
        "id_const": "ADAPTER_ID",
        "projection_const": "PROJECTION_VERSION",
        "fingerprint_consts": (
            ("ROLLOUT_FINGERPRINT", "string"),
            ("HISTORY_FINGERPRINT", "string"),
        ),
        "allowed_versions_const": None,
    },
    {
        "id": "opencode",
        "source": Path("crates/archivist-adapter-opencode/src/schema.rs"),
        # The OpenCode adapter id is inline in adapter_descriptor().
        "id_const": None,
        "projection_const": "PROJECTION_VERSION",
        "fingerprint_consts": (("SUPPORTED_FINGERPRINT", "string"),),
        "allowed_versions_const": "ALLOWED_VERSIONS",
    },
    {
        "id": "pi",
        "source": Path("crates/archivist-adapter-pi/src/lib.rs"),
        "id_const": "ADAPTER_ID",
        "projection_const": "PROJECTION_VERSION",
        "fingerprint_consts": (
            ("JSONL_FINGERPRINTS", "array"),
            ("IMMUTABLE_FINGERPRINT", "string"),
        ),
        "allowed_versions_const": None,
    },
)

# The protocol's closed artifact-kind pair (archivist-protocol vocabulary)
# and the note's state/verdict vocabularies.
ARTIFACT_KINDS = frozenset({"file-slice", "database-projection"})
MATRIX_STATES = frozenset({"supported", "unsupported"})
VERDICTS = frozenset({"supported", "unsupported", "unobserved"})

MATRIX_HEADER = [
    "Adapter", "Projection", "Source fingerprint", "Artifact kind",
    "State", "Known gap and evidence",
]
RECONCILIATION_HEADER = [
    "Observed fingerprint", "Verdict", "Admitted by", "Evidence",
]
COVERAGE_HEADER = ["State", "Token", "Rank", "Meaning"]

# Rule 6: sentences whose retraction is itself a compatibility change.
# Matched whitespace-normalized so a reflow cannot break a pin.
REQUIRED_PHRASES = (
    "fails closed as `unsupported` after the bounded header probe",
    "only in the same commit as the adapter's allowlist constant",
    "rejected (threat `AC-11`)",
    "re-measured by the definition of done's slow lane",
)

STRING_CONST_RE = r'pub const {name}: &str = "([^"]+)";'
# Fixed arrays (`[&str; N] = [..]`) and slice references (`&[&str] = &[..]`).
ARRAY_CONST_RE = (
    r"pub const {name}: (?:\[&str; \d+\]|&\[&str\]) = &?\[([^\]]*)\]"
)
INLINE_ADAPTER_ID_RE = re.compile(r'AdapterId::parse\("([^"]+)"\)')
COVERAGE_BLOCK_RE = re.compile(r"CoverageState \{(.*?)\n    \}", re.S)
VARIANT_TOKEN_RE = re.compile(r'(\w+) => "([a-z-]+)",')
RANK_BLOCK_RE = re.compile(
    r"pub fn rank\(self\) -> u8 \{\s*match self \{(.*?)\n        \}", re.S)
VARIANT_RANK_RE = re.compile(r"Self::(\w+) => (\d+),")


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


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
    """Parse a markdown table into rows of raw cells (backticks kept)."""
    rows: list[list[str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        if re.fullmatch(r"\|(?:\s*:?-+:?\s*\|)+", stripped):
            continue  # header separator
        rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
    return rows


def cell_tokens(cell: str) -> list[str]:
    """The backtick-quoted tokens of one cell."""
    return re.findall(r"`([^`]+)`", cell)


def bare(cell: str) -> str:
    return cell.replace("`", "").strip()


def parse_string_const(text: str, name: str) -> str | None:
    match = re.search(STRING_CONST_RE.format(name=name), text)
    return match.group(1) if match else None


def parse_array_const(text: str, name: str) -> list[str] | None:
    match = re.search(ARRAY_CONST_RE.format(name=name), text)
    if not match:
        return None
    return re.findall(r'"([^"]+)"', match.group(1))


def parse_adapter(spec: dict, text: str) -> dict | None:
    """Parse one adapter's published constants from its source text."""
    adapter_id = None
    if spec["id_const"] is not None:
        adapter_id = parse_string_const(text, spec["id_const"])
        if adapter_id is None:
            fail(f"{spec['source']}: no `pub const {spec['id_const']}`")
            return None
    else:
        match = INLINE_ADAPTER_ID_RE.search(text)
        adapter_id = match.group(1) if match else None
        if adapter_id is None:
            fail(f"{spec['source']}: no inline AdapterId::parse")
            return None
    if adapter_id != spec["id"]:
        fail(f"{spec['source']}: adapter id {adapter_id!r} != configured "
             f"{spec['id']!r}")
        return None

    projection = parse_string_const(text, spec["projection_const"])
    if projection is None:
        fail(f"{spec['source']}: no `pub const {spec['projection_const']}`")
        return None

    fingerprints: set[str] = set()
    for name, kind in spec["fingerprint_consts"]:
        if kind == "array":
            tokens = parse_array_const(text, name)
        else:
            token = parse_string_const(text, name)
            tokens = None if token is None else [token]
        if not tokens:
            fail(f"{spec['source']}: fingerprint const {name!r} missing or "
                 "empty")
            return None
        fingerprints.update(tokens)

    versions: list[str] = []
    if spec["allowed_versions_const"] is not None:
        versions = parse_array_const(text, spec["allowed_versions_const"])
        if not versions:
            fail(f"{spec['source']}: version vocabulary const "
                 f"{spec['allowed_versions_const']!r} missing or empty")
            return None

    return {
        "id": adapter_id,
        "projection": projection,
        "fingerprints": fingerprints,
        "allowed_versions": versions,
    }


def parse_adapters(sources: dict[str, str]) -> dict[str, dict] | None:
    adapters: dict[str, dict] = {}
    ok = True
    for spec in ADAPTERS:
        text = sources.get(str(spec["source"]))
        if text is None:
            fail(f"adapter source not loaded: {spec['source']}")
            ok = False
            continue
        parsed = parse_adapter(spec, text)
        if parsed is None:
            ok = False
            continue
        adapters[parsed["id"]] = parsed
    return adapters if ok else None


def parse_coverage(status_text: str) -> dict[str, int] | None:
    """Token -> aggregate rank from status.rs CoverageState."""
    block = COVERAGE_BLOCK_RE.search(status_text)
    if not block:
        fail(f"{STATUS_SOURCE_PATH}: no CoverageState enum block")
        return None
    variant_tokens = dict(VARIANT_TOKEN_RE.findall(block.group(1)))
    rank_block = RANK_BLOCK_RE.search(status_text)
    if not rank_block:
        fail(f"{STATUS_SOURCE_PATH}: no CoverageState::rank match block")
        return None
    variant_ranks = {
        variant: int(rank)
        for variant, rank in VARIANT_RANK_RE.findall(rank_block.group(1))
    }
    if set(variant_tokens) != set(variant_ranks):
        fail(f"{STATUS_SOURCE_PATH}: CoverageState variants and ranks "
             f"disagree ({sorted(variant_tokens)} vs "
             f"{sorted(variant_ranks)})")
        return None
    return {token: variant_ranks[v] for v, token in variant_tokens.items()}


def inventory_observed_names(inventory: str) -> set[str] | None:
    """The bold fingerprint names of the inventory's observed section."""
    section = note_section(inventory, "Observed fingerprints")
    if not section:
        fail(f"{INVENTORY_PATH}: no '## Observed fingerprints' section")
        return None
    names = set(re.findall(r"^\*\*([a-z0-9-]+)", section, re.M))
    if not names:
        fail(f"{INVENTORY_PATH}: observed-fingerprints section names no "
             "bold fingerprint tokens")
        return None
    return names


def parse_matrix_rows(note: str) -> list[dict] | None:
    section = note_section(note, "The published matrix")
    rows = table_rows(section)
    if len(rows) < 2:
        fail("note's published-matrix section contains no table")
        return None
    if rows[0][:6] != MATRIX_HEADER:
        fail(f"published-matrix table header is {rows[0][:6]}, expected the "
             f"{'/'.join(MATRIX_HEADER)} columns")
        return None
    parsed: list[dict] = []
    ok = True
    for row in rows[1:]:
        if len(row) < 6:
            fail(f"published-matrix row {row!r} does not have six cells")
            ok = False
            continue
        adapter, projection, fingerprint, kind, state, gap = row[:6]
        record = {
            "adapter": cell_tokens(adapter),
            "projection": cell_tokens(projection),
            "fingerprint": cell_tokens(fingerprint),
            "kind": cell_tokens(kind),
            "state": bare(state),
            "gap": gap,
        }
        for key in ("adapter", "projection", "fingerprint", "kind"):
            if len(record[key]) != 1:
                fail(f"published-matrix row {fingerprint!r}: cell {key!r} "
                     f"must carry exactly one token, has {record[key]}")
                ok = False
        parsed.append(record)
    return parsed if ok else None


def check_adapter_matrix(sources: dict[str, str], note: str) -> bool:
    """Rule 1: the note's matrix equals the adapters' embedded allowlists."""
    adapters = parse_adapters(sources)
    rows = parse_matrix_rows(note)
    if adapters is None or rows is None:
        return False

    ok = True
    seen: dict[str, set[str]] = {}
    for row in rows:
        adapter_id = row["adapter"][0]
        spec = adapters.get(adapter_id)
        if spec is None:
            fail(f"published-matrix row names unknown adapter "
                 f"{adapter_id!r}")
            ok = False
            continue
        if row["projection"][0] != spec["projection"]:
            fail(f"{adapter_id}: matrix projection {row['projection'][0]!r}"
                 f" != source {spec['projection']!r}")
            ok = False
        seen.setdefault(adapter_id, set()).add(row["fingerprint"][0])

    for adapter_id, spec in adapters.items():
        matrix_set = seen.get(adapter_id, set())
        if matrix_set != spec["fingerprints"]:
            fail(f"{adapter_id}: published fingerprints {sorted(matrix_set)}"
                 f" != allowlist {sorted(spec['fingerprints'])}")
            ok = False
    return ok


def check_kinds_states(sources: dict[str, str], note: str) -> bool:
    """Rule 2: closed artifact-kind and state vocabularies."""
    rows = parse_matrix_rows(note)
    if rows is None:
        return False
    ok = True
    for row in rows:
        kind = row["kind"][0]
        if kind not in ARTIFACT_KINDS:
            fail(f"fingerprint {row['fingerprint'][0]!r}: artifact kind "
                 f"{kind!r} is not one of {sorted(ARTIFACT_KINDS)}")
            ok = False
        if row["state"] not in MATRIX_STATES:
            fail(f"fingerprint {row['fingerprint'][0]!r}: state "
                 f"{row['state']!r} is not one of {sorted(MATRIX_STATES)}")
            ok = False
    return ok


def check_reconciliation(sources: dict[str, str], note: str) -> bool:
    """Rule 3: every observed fingerprint reconciles, honestly."""
    inventory = sources.get(str(INVENTORY_PATH))
    observed = None if inventory is None else inventory_observed_names(inventory)
    rows = parse_matrix_rows(note)
    if observed is None or rows is None:
        return False
    published = {row["fingerprint"][0] for row in rows}

    section = note_section(note, "Observed-fingerprint reconciliation")
    table = table_rows(section)
    if len(table) < 2:
        fail("note's reconciliation section contains no table")
        return False
    if table[0][:4] != RECONCILIATION_HEADER:
        fail(f"reconciliation table header is {table[0][:4]}, expected the "
             f"{'/'.join(RECONCILIATION_HEADER)} columns")
        return False

    ok = True
    reconciled: set[str] = set()
    for row in table[1:]:
        if len(row) < 4:
            fail(f"reconciliation row {row!r} does not have four cells")
            ok = False
            continue
        observed_name, verdict, admitted, _evidence = row[:4]
        name = bare(observed_name)
        if name in reconciled:
            fail(f"reconciliation names {name!r} twice")
            ok = False
        reconciled.add(name)
        verdict = bare(verdict)
        if verdict not in VERDICTS:
            fail(f"reconciliation verdict for {name!r} is {verdict!r}, "
                 f"not one of {sorted(VERDICTS)}")
            ok = False
        admitted_tokens = cell_tokens(admitted)
        if verdict == "supported":
            if not admitted_tokens:
                fail(f"reconciliation row {name!r} is supported but admits "
                     "no published fingerprint")
                ok = False
            unknown = sorted(set(admitted_tokens) - published)
            if unknown:
                fail(f"reconciliation row {name!r} admits {unknown}, which "
                     "the published matrix does not contain")
                ok = False
        elif admitted_tokens or bare(admitted) != "—":
            fail(f"reconciliation row {name!r} is {verdict!r} but claims "
                 f"admission ({admitted!r}); only supported rows admit")
            ok = False

    if reconciled != observed:
        fail(f"reconciliation covers {sorted(reconciled)}; the fleet "
             f"inventory observed {sorted(observed)}")
        ok = False
    return ok


def check_version_pins(sources: dict[str, str], note: str) -> bool:
    """Rule 4: pinned version vocabularies are named in their rows."""
    adapters = parse_adapters(sources)
    rows = parse_matrix_rows(note)
    if adapters is None or rows is None:
        return False
    ok = True
    for spec in ADAPTERS:
        if not spec["allowed_versions_const"]:
            continue
        adapter = adapters[spec["id"]]
        gap_cells = [
            row["gap"] for row in rows if row["adapter"][0] == spec["id"]
        ]
        if not gap_cells:
            fail(f"{spec['id']}: published matrix has no rows to pin "
                 "versions in")
            ok = False
            continue
        joined = " ".join(gap_cells)
        for version in adapter["allowed_versions"]:
            if version not in joined:
                fail(f"{spec['id']}: pinned version {version!r} is not "
                     "named in its published-matrix rows")
                ok = False
    return ok


def check_coverage(sources: dict[str, str], note: str) -> bool:
    """Rule 5: the note's coverage states match status.rs token for token."""
    status_text = sources.get(str(STATUS_SOURCE_PATH))
    if status_text is None:
        fail(f"status source not loaded: {STATUS_SOURCE_PATH}")
        return False
    coverage = parse_coverage(status_text)
    if coverage is None:
        return False

    section = note_section(note, "Coverage status vocabulary")
    table = table_rows(section)
    if len(table) < 2:
        fail("note's coverage-vocabulary section contains no table")
        return False
    if table[0][:4] != COVERAGE_HEADER:
        fail(f"coverage table header is {table[0][:4]}, expected the "
             f"{'/'.join(COVERAGE_HEADER)} columns")
        return False

    ok = True
    note_tokens: dict[str, int] = {}
    for row in table[1:]:
        if len(row) < 4:
            fail(f"coverage row {row!r} does not have four cells")
            ok = False
            continue
        _state, token, rank, _meaning = row[:4]
        token = bare(token)
        if token in note_tokens:
            fail(f"coverage table names token {token!r} twice")
            ok = False
        if not rank.strip().isdigit():
            fail(f"coverage row for {token!r}: rank {rank!r} is not an "
                 "integer")
            ok = False
            continue
        note_tokens[token] = int(rank)

    if note_tokens != coverage:
        fail(f"coverage vocabulary {note_tokens} != status.rs "
             f"{coverage}")
        ok = False
    return ok


def normalize(text: str) -> str:
    """Collapse whitespace so sentence pins survive a reflow."""
    return " ".join(text.split())


def check_phrases(sources: dict[str, str], note: str) -> bool:
    """Rule 6: the normative sentences stay."""
    normalized = normalize(note)
    ok = True
    for phrase in REQUIRED_PHRASES:
        if normalize(phrase) not in normalized:
            fail(f"note is missing the pinned phrase: {phrase!r}")
            ok = False
    return ok


# ---------------------------------------------------------------------------
# Rule 7: the opencode row's marathon-scale evidence. The suite behind it is
# `#[ignore]`d from ordinary lanes (it is meaningful only at its own scale),
# so "owned" means two pinned records: the note's published figures equal
# what the suite's constants actually produce, and the definition of done's
# slow lane invokes the suite — the assertions stay a regression gate, not
# a benchmark someone remembers to run.
# ---------------------------------------------------------------------------

# The exact slow-lane invocation the definition of done must carry.
MARATHON_DOD_INVOCATION = (
    "cargo test -p archivist-adapter-opencode"
    " --test marathon_scale -- --ignored"
)

# The note's marathon paragraph (inside the opencode row's gap cell) and the
# inventory's fleet-count finding, parsed rather than duplicated: a figure
# that drifts from the suite's constants is a matrix claim the project no
# longer measures.
MARATHON_SCALE_RE = re.compile(
    r"a synthetic ([\d,]+)-session / ([\d,]+)-row / (\d+) MiB store"
    r" \((\d+)× the fleet session count\)")
MARATHON_APPEND_RE = re.compile(r"a ([\d,]+)-row append re-captured in full")
MARATHON_BOUNDS_RE = re.compile(
    r"observed ≥([\d.]+) MiB/s, peak ≈([\d.]+)× store")
MARATHON_TEST_TOKEN_RE = re.compile(
    r"Marathon scale \(\d{4}-\d{2}-\d{2}, `([^`]+)`\)")
FLEET_OPENCODE_SESSIONS_RE = re.compile(
    r"\*\*OpenCode is single-host and small\*\* \((\d+) sessions\)")

# The suite's plain (non-`pub`) scale and bound constants; underscores are
# the Rust digit separator, not part of the value.
NUMBER_CONST_RE = r"(?:pub )?const {name}: \w+ = ([\d_]+(?:\.[\d_]+)?);"

# The constants the note's figures are derived from (scale) and held under
# (bounds).
MARATHON_INT_CONSTS = (
    "SESSIONS",
    "MESSAGES_PER_SESSION",
    "PARTS_PER_MESSAGE",
    "INPUTS_PER_SESSION",
    "TODOS_PER_SESSION",
    "GROWTH_SESSIONS",
    "MAX_PEAK_RSS_STORE_MULTIPLE",
    "MAX_PEAK_RSS_ABSOLUTE_MIB",
)
MARATHON_FLOAT_CONSTS = ("MIN_CAPTURE_MIB_PER_S",)


def parse_number_const(text: str, name: str) -> float | None:
    match = re.search(NUMBER_CONST_RE.format(name=name), text)
    if match is None:
        return None
    return float(match.group(1).replace("_", ""))


def marathon_suite_constants(test_text: str) -> dict[str, float] | None:
    """The suite's scale and bound constants, keyed by const name."""
    constants: dict[str, float] = {}
    for name in MARATHON_INT_CONSTS + MARATHON_FLOAT_CONSTS:
        value = parse_number_const(test_text, name)
        if value is None:
            fail(f"{MARATHON_TEST_PATH}: no `const {name}`")
            return None
        constants[name] = value
    return constants


def check_marathon_evidence(sources: dict[str, str], note: str) -> bool:
    """Rule 7: the marathon figures stay pinned to their suite and lane."""
    test_text = sources.get(str(MARATHON_TEST_PATH))
    dod_text = sources.get(str(DOD_PATH))
    inventory = sources.get(str(INVENTORY_PATH))
    if test_text is None or dod_text is None or inventory is None:
        fail("marathon evidence: suite, definition of done, or inventory "
             "not loaded")
        return False
    constants = marathon_suite_constants(test_text)
    if constants is None:
        return False

    rows = parse_matrix_rows(note)
    if rows is None:
        return False
    gap_cells = [
        row["gap"] for row in rows if row["adapter"][0] == "opencode"
    ]
    if len(gap_cells) != 1:
        fail(f"expected exactly one opencode matrix row, found "
             f"{len(gap_cells)}")
        return False
    gap = gap_cells[0]

    fleet = FLEET_OPENCODE_SESSIONS_RE.search(inventory)
    if fleet is None:
        fail(f"{INVENTORY_PATH}: no OpenCode fleet session count")
        return False
    fleet_sessions = int(fleet.group(1))

    ok = True

    test_token = MARATHON_TEST_TOKEN_RE.search(gap)
    expected_token = f"tests/{MARATHON_TEST_PATH.name}"
    if test_token is None:
        fail("opencode row: no marathon paragraph naming its date and suite")
        ok = False
    elif test_token.group(1) != expected_token:
        fail(f"opencode row names suite {test_token.group(1)!r}, expected "
             f"{expected_token!r}")
        ok = False

    scale = MARATHON_SCALE_RE.search(gap)
    append = MARATHON_APPEND_RE.search(gap)
    bounds = MARATHON_BOUNDS_RE.search(gap)
    for label, match in (
        ("synthetic-store figures", scale),
        ("append figure", append),
        ("observed bound figures", bounds),
    ):
        if match is None:
            fail(f"opencode row: marathon paragraph is missing its "
                 f"{label}")
            ok = False
    if not ok:
        return False

    per_session = (1
                   + constants["MESSAGES_PER_SESSION"]
                   + constants["MESSAGES_PER_SESSION"]
                   * constants["PARTS_PER_MESSAGE"]
                   + constants["INPUTS_PER_SESSION"]
                   + constants["TODOS_PER_SESSION"])
    suite_rows = constants["SESSIONS"] * per_session
    suite_append = constants["GROWTH_SESSIONS"] * per_session
    suite_multiple = constants["SESSIONS"] / fleet_sessions

    note_sessions, note_rows, note_store_mib, note_multiple = (
        int(scale.group(1).replace(",", "")),
        int(scale.group(2).replace(",", "")),
        int(scale.group(3)),
        int(scale.group(4)),
    )
    if note_sessions != constants["SESSIONS"]:
        fail(f"opencode row: marathon store is {note_sessions} sessions, "
             f"the suite seeds {constants['SESSIONS']:.0f}")
        ok = False
    if note_rows != suite_rows:
        fail(f"opencode row: marathon store is {note_rows} allowlisted "
             f"rows, the suite's constants produce {suite_rows:.0f}")
        ok = False
    if note_multiple != round(suite_multiple):
        fail(f"opencode row: marathon store is {note_multiple}× the fleet "
             f"session count, {constants['SESSIONS']:.0f} over "
             f"{fleet_sessions} is {round(suite_multiple)}×")
        ok = False

    note_append = int(append.group(1).replace(",", ""))
    if note_append != suite_append:
        fail(f"opencode row: marathon append is {note_append} rows, the "
             f"suite appends {suite_append:.0f}")
        ok = False

    note_mib_per_s = float(bounds.group(1))
    note_peak_multiple = float(bounds.group(2))
    floor = constants["MIN_CAPTURE_MIB_PER_S"]
    if note_mib_per_s <= floor:
        fail(f"opencode row: observed marathon throughput "
             f"{note_mib_per_s} MiB/s does not exceed the suite's "
             f"{floor} MiB/s floor, so the published evidence would sit "
             "under its own bound")
        ok = False
    peak_bound = constants["MAX_PEAK_RSS_STORE_MULTIPLE"]
    if note_peak_multiple >= peak_bound:
        fail(f"opencode row: observed marathon peak ≈{note_peak_multiple}× "
             f"store is not under the suite's {peak_bound:.0f}× ceiling, "
             "so the published evidence would sit on its own bound")
        ok = False
    absolute_mib = constants["MAX_PEAK_RSS_ABSOLUTE_MIB"]
    if note_store_mib * peak_bound > absolute_mib:
        fail(f"opencode row: the suite's {peak_bound:.0f}× multiple over "
             f"the published {note_store_mib} MiB store exceeds its "
             f"{absolute_mib:.0f} MiB absolute ceiling, so the relative "
             "bound alone governs nothing at this scale")
        ok = False

    # The definition of done must invoke the suite, and in its slow lane:
    # the assertion set is minutes of work at its own scale, and the
    # fast-lane block must stay fast.
    invocation = " ".join(MARATHON_DOD_INVOCATION.split())
    normalized_dod = " ".join(dod_text.split())
    invocation_at = normalized_dod.find(invocation)
    slow_at = normalized_dod.find('[ "$LANE" = "slow" ]')
    audit_at = normalized_dod.find('[ "$LANE" = "audit" ]')
    if invocation_at < 0:
        fail(f"{DOD_PATH}: the marathon suite is not invoked (expected "
             f"`{MARATHON_DOD_INVOCATION}`), so its assertions gate "
             "nothing")
        ok = False
    elif slow_at < 0 or invocation_at < slow_at or (
            0 <= audit_at < invocation_at):
        fail(f"{DOD_PATH}: the marathon suite invocation sits outside the "
             "slow lane's block")
        ok = False
    return ok


CHECKS = (
    ("adapter matrix rows", check_adapter_matrix),
    ("artifact kinds and states", check_kinds_states),
    ("observed reconciliation", check_reconciliation),
    ("pinned versions", check_version_pins),
    ("coverage vocabulary", check_coverage),
    ("phrase pins", check_phrases),
    ("marathon evidence", check_marathon_evidence),
)


def load_sources() -> dict[str, str] | None:
    sources: dict[str, str] = {}
    ok = True
    for path in [INVENTORY_PATH, STATUS_SOURCE_PATH, MARATHON_TEST_PATH,
                 DOD_PATH] + [spec["source"] for spec in ADAPTERS]:
        text = read_text(path)
        if text is None:
            ok = False
            continue
        sources[str(path)] = text
    return sources if ok else None


def run_checks(sources: dict[str, str], note: str) -> bool:
    ok = True
    for name, check in CHECKS:
        if not check(sources, note):
            ok = False
    return ok


# (label, action, targeted check index). Every mutation rewrites text —
# source or note — in mutate() below and must fire exactly the check it
# targets.
MUTATIONS = (
    ("matrix drift (source allowlist)",
     "drop a fingerprint from the Claude allowlist const", 0),
    ("matrix drift (dropped row)",
     "drop the claude-sidecar row from the note", 0),
    ("matrix drift (projection)",
     "change the Codex projection cell in the note", 0),
    ("artifact kind",
     "rewrite one row's artifact kind to an out-of-set token", 1),
    ("state vocabulary",
     "rewrite one row's state to an out-of-set token", 1),
    ("reconciliation (dropped row)",
     "drop the prototype-legacy reconciliation row", 2),
    ("reconciliation (verdict)",
     "flip one verdict to an out-of-set token", 2),
    ("reconciliation (unsupported admission)",
     "make the unsupported row claim admission", 2),
    ("reconciliation (unknown admission)",
     "make a supported row admit an unpublished fingerprint", 2),
    ("pinned versions",
     "strip the pinned OpenCode version from its row", 3),
    ("coverage vocabulary (dropped state)",
     "drop the failed coverage row", 4),
    ("coverage vocabulary (rank)",
     "change one coverage rank", 4),
    ("phrase pins",
     "retract the fail-closed sentence", 5),
    ("phrase pins (marathon ownership)",
     "retract the marathon re-measurement sentence", 5),
    ("marathon evidence (note session figure)",
     "change the note's marathon session count", 6),
    ("marathon evidence (note row figure)",
     "change the note's marathon allowlisted-row count", 6),
    ("marathon evidence (note append figure)",
     "change the note's marathon append-row count", 6),
    ("marathon evidence (note scale multiple)",
     "change the note's fleet-multiple figure", 6),
    ("marathon evidence (observed under floor)",
     "drop the note's observed throughput under the suite's floor", 6),
    ("marathon evidence (peak over bound)",
     "raise the note's observed peak over the suite's ceiling", 6),
    ("marathon evidence (suite constant)",
     "change the suite's SESSIONS constant under the note", 6),
    ("marathon evidence (slow-lane wiring)",
     "strip the slow lane's invocation of the marathon suite", 6),
)


def mutate(index: int, sources: dict[str, str], note: str
           ) -> tuple[dict[str, str], str]:
    """Apply mutation ``index``; returns the mutated (sources, note)."""
    claude_path = str(ADAPTERS[0]["source"])
    sources = copy.deepcopy(sources)
    if index == 0:
        sources[claude_path] = sources[claude_path].replace(
            '["claude-jsonl-v1", "claude-jsonl-v2"]',
            '["claude-jsonl-v2"]', 1)
    elif index == 1:
        note = re.sub(r"^\| `claude-jsonl` \| `1` \| `claude-sidecar-v1`"
                      r" \|[^\n]*\n", "", note, count=1, flags=re.M)
    elif index == 2:
        note = note.replace("| `1` | `codex-rollout-jsonl` |",
                            "| `2` | `codex-rollout-jsonl` |", 1)
    elif index == 3:
        note = note.replace("| `claude-jsonl-v1` | `file-slice` |",
                            "| `claude-jsonl-v1` | `object` |", 1)
    elif index == 4:
        note = note.replace("| `claude-jsonl-v1` | `file-slice` | supported |",
                            "| `claude-jsonl-v1` | `file-slice` | beta |", 1)
    elif index == 5:
        note = re.sub(r"^\| `prototype-legacy` \|[^\n]*\n", "", note,
                      count=1, flags=re.M)
    elif index == 6:
        note = note.replace("| `pi-session-jsonl` | unobserved |",
                            "| `pi-session-jsonl` | pending |", 1)
    elif index == 7:
        note = note.replace("| `prototype-legacy` | unsupported | — |",
                            "| `prototype-legacy` | unsupported |"
                            " `claude-jsonl-v1` |", 1)
    elif index == 8:
        note = note.replace(
            "| `claude-jsonl` | supported | `claude-jsonl-v1`, "
            "`claude-jsonl-v2` |",
            "| `claude-jsonl` | supported | `claude-jsonl-v1`, "
            "`claude-jsonl-v9` |", 1)
    elif index == 9:
        note = note.replace("Only allowlisted application version: "
                            "`1.18.29`.",
                            "Only allowlisted application version: pinned.", 1)
    elif index == 10:
        note = re.sub(r"^\| Failed \| `failed` \| 5 \|[^\n]*\n", "", note,
                      count=1, flags=re.M)
    elif index == 11:
        note = note.replace("| Unsupported | `unsupported` | 4 |",
                            "| Unsupported | `unsupported` | 9 |", 1)
    elif index == 12:
        note = note.replace("fails closed as `unsupported` after the bounded",
                            "is parsed anyway as `unsupported` after the "
                            "bounded", 1)
    elif index == 13:
        note = note.replace(
            "re-measured by the definition of done's slow lane",
            "recounted by the definition of done's slow lane", 1)
    elif index == 14:
        note = note.replace("2,048-session", "4,096-session", 1)
    elif index == 15:
        note = note.replace("227,328-row", "227,329-row", 1)
    elif index == 16:
        note = note.replace("1,776-row append", "1,777-row append", 1)
    elif index == 17:
        note = note.replace("(114× the fleet session count)",
                            "(112× the fleet session count)", 1)
    elif index == 18:
        note = note.replace("observed ≥8.7 MiB/s", "observed ≥4.1 MiB/s", 1)
    elif index == 19:
        note = note.replace("peak ≈6.4× store", "peak ≈16× store", 1)
    elif index == 20:
        marathon_path = str(MARATHON_TEST_PATH)
        sources[marathon_path] = sources[marathon_path].replace(
            "const SESSIONS: usize = 2_048;",
            "const SESSIONS: usize = 4_096;", 1)
    elif index == 21:
        dod_path = str(DOD_PATH)
        sources[dod_path] = sources[dod_path].replace(
            "--test marathon_scale -- --ignored",
            "--test marathon_scale", 1)
    return sources, note


def self_test(sources: dict[str, str], note: str) -> bool:
    """Prove every rejection path fires and the committed tree passes."""
    if not run_checks(sources, note):
        fail("self-test: the committed sources and note already fail the "
             "gate; fix them before the mutation sweep can mean anything")
        return False

    ok = True
    for index, (label, action, expected_check) in enumerate(MUTATIONS):
        mutated_sources, mutated_note = mutate(index, sources, note)
        name, check = CHECKS[expected_check]
        if check(mutated_sources, mutated_note):
            fail(f"self-test: mutation {label!r} ({action}) did not fire "
                 f"the {name!r} rejection")
            ok = False
    if not ok:
        return False

    print(f"compatibility-matrix self-test: {len(MUTATIONS)} mutations, "
          "every rejection path fired; committed tree passes")
    return True


def main() -> int:
    note = read_text(NOTE_PATH)
    sources = load_sources()
    if note is None or sources is None:
        return 2

    if "--self-test" in sys.argv[1:]:
        if not self_test(sources, note):
            return 2
        return 0

    if not run_checks(sources, note):
        return 2

    adapters = parse_adapters(sources)
    if adapters is None:
        # run_checks just proved these parses pass; this is unreachable
        # defence, not a second opinion.
        return 2
    fingerprint_count = sum(
        len(spec["fingerprints"]) for spec in adapters.values())
    print(f"compatibility matrix gate: {len(adapters)} adapters, "
          f"{fingerprint_count} supported fingerprints, every observed "
          "fingerprint reconciled; note, adapter sources, and inventory "
          "agree; marathon evidence pinned to the suite's constants and "
          "re-measured by the slow lane")
    for spec in ADAPTERS:
        adapter = adapters[spec["id"]]
        versions = (f", versions {adapter['allowed_versions']}"
                    if adapter["allowed_versions"] else "")
        print(f"  {spec['id']:14s} projection {adapter['projection']:8s} "
              f"{len(adapter['fingerprints'])} fingerprints{versions}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
