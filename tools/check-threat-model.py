#!/usr/bin/env python3
"""Threat-model acceptance gate for Agent Archivist.

Validates ``docs/security/threat-model.md`` and the four domain documents
under ``docs/security/threats/`` against the acceptance check that document
states for itself — the machine-checked form of the Phase 1 exit gate
sentence "The threat model has a mitigation or explicitly accepted risk for
every finding" (plan Section 8):

1. register shape — consolidated and domain register rows carry the six
   fixed columns, IDs follow the ``<GROUP>-<NN>`` grammar over the four
   closed groups, IDs are unique, and the STRIDE cell is a non-empty
   combination of the six STRIDE letters;
2. coverage — the consolidated register holds every finding from all four
   domain documents row for row, none missing and none added, and that set
   equals the expansion of the ID ranges declared in the "Domain documents"
   table;
3. disposition — every consolidated and domain row states a mitigation or an
   acceptance (the disposition names one, and the row carries an enforcing
   test class and/or an accepted risk: a bare em-dash cell is empty);
4. accepted-risk register — every row expands a consolidated row (its base
   ID, with any ``(a)``/``(b)`` arm suffix stripped), its Owner column names
   at least one owner from the closed vocabulary (SEC working group, tenant
   operator, adapter owners, `` `archivist-*` `` crate owners), every
   backticked ``archivist-*`` token anywhere in the five documents names a
   real workspace crate, and the owner-bearing consolidated rows and the
   accepted-risk register rows map one to one in both directions;
5. deliverable-list coverage — the nine plan-named threat families are each
   present exactly once and map to at least one existing finding, with
   ``…`` ranges expanded within one group;
6. wiring — the "Acceptance check" section names this tool, so the document
   and the gate cannot drift apart silently.

On success it prints a content-free summary and exits 0. Any failure prints
a report on stderr and exits 2.

``--self-test`` first validates the committed tree, then validates a minimal
synthetic threat model, then requires mutated copies of it to be rejected
under the rule each mutation breaks — proving the rejection paths (a finding
dropped from the consolidated register, a disposition that neither mitigates
nor accepts, an accepted risk without an owner) rather than only the accept
path.

Usage::

    tools/check-threat-model.py [--self-test]

Standard-library only, so a clean checkout runs it before any dependency is
fetched. Its output names IDs, groups, sections, paths, and counts only.
"""

from __future__ import annotations

import argparse
import copy
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODEL_REL = "docs/security/threat-model.md"
THREATS_REL = "docs/security/threats"
CRATES_REL = "crates"

# The four finding groups and their documents, fixed by the domain-documents
# table. A new group is a reviewed change that extends this map, the table,
# and the four documents in the same commit.
GROUPS = ("IA", "PI", "RD", "RMD")

ID_RE = re.compile(r"^(?:IA|PI|RD|RMD)-\d{2}$")
ID_TOKEN_RE = re.compile(r"\b(?:IA|PI|RD|RMD)-\d{2}\b")
# "IA-01 … IA-11" — both endpoints must share one group.
RANGE_RE = re.compile(
    r"^(?P<lo_group>IA|PI|RD|RMD)-(?P<lo>\d{2}) … (?P<hi_group>IA|PI|RD|RMD)-(?P<hi>\d{2})$"
)
RANGE_TOKEN_RE = re.compile(
    r"\b(?P<lo_group>IA|PI|RD|RMD)-(?P<lo>\d{2}) … (?P<hi_group>IA|PI|RD|RMD)-(?P<hi>\d{2})\b"
)
# An accepted-risk register ID may carry one arm suffix: IA-07(b).
BASE_ID_RE = re.compile(r"^(?P<base>(?:IA|PI|RD|RMD)-\d{2})(?:\([a-z]\))?$")
STRIDE_RE = re.compile(r"^[STRIDE](?:/[STRIDE])*$")
CRATE_OWNER_RE = re.compile(r"`(archivist-[a-z0-9-]+)`")
OWNER_PHRASES = ("SEC working group", "tenant operator", "adapter owners")

# The plan's Phase 1 deliverable families plus the two umbrella families the
# threat model adds (plan Section 8, deliverable list). The closed set is the
# contract: renaming or dropping a family is a reviewed change.
FAMILIES = (
    "Spoofing",
    "Replay",
    "Cross-tenant writes",
    "Digest confusion",
    "Decompression bombs",
    "Poisoned manifests",
    "Metadata leakage",
    "Relay/delegation abuse",
    "Receipt trust failure",
)

DOMAIN_COLUMNS = 3
REGISTER_COLUMNS = 6
RISK_COLUMNS = 4
EMPTY_CELLS = ("", "—")
TOOL_NAME = "tools/check-threat-model.py"
DOMAIN_SECTION = "Coverage and disposition register"
# Where the model lives; domain-document hrefs resolve beside it.
MODEL_DIR = "docs/security"


def domain_rel(href: str) -> str:
    """Repo-relative label for a domain document."""
    return f"{MODEL_DIR}/{href}"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Markdown parsing (pure: text in, data out)
# ---------------------------------------------------------------------------


def section_body(text: str, title: str) -> str | None:
    """The body of a ``## title`` section, up to the next heading or EOF."""
    match = re.search(rf"^## {re.escape(title)}\s*$", text, re.M)
    if match is None:
        return None
    rest = text[match.end() :]
    nxt = re.search(r"^## ", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def table_rows(body: str, columns: int, where: str) -> tuple[list[list[str]], list[str]]:
    """Rows of the first markdown table in *body*, header and separator excluded."""
    lines = body.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip().startswith("|")), None)
    if start is None:
        return [], [f"{where}: no table found"]
    table_lines: list[str] = []
    for line in lines[start:]:
        if not line.strip().startswith("|"):
            break
        table_lines.append(line.strip())
    if len(table_lines) < 2:
        return [], [f"{where}: table has no rows"]
    rows: list[list[str]] = []
    for index, line in enumerate(table_lines[2:], start=3):
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != columns:
            return [], [f"{where}: row {index} has {len(cells)} cells, expected {columns}"]
        rows.append(cells)
    return rows, []


def parse_coverage(body: str) -> dict[str, list[str]]:
    """Family name -> finding IDs, ranges expanded, from bullet lines."""
    families: dict[str, list[str]] = {}
    current: str | None = None
    buffer: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            if current is not None:
                families[current] = coverage_ids(" ".join(buffer))
            parts = stripped[2:].split("—", 1)
            current = parts[0].strip()
            buffer = [parts[1] if len(parts) > 1 else ""]
        elif current is not None and stripped:
            buffer.append(stripped)
    if current is not None:
        families[current] = coverage_ids(" ".join(buffer))
    return families


def coverage_ids(text: str) -> list[str]:
    """Every finding ID a coverage bullet names, ranges expanded."""
    ids = set(ID_TOKEN_RE.findall(text))
    for match in RANGE_TOKEN_RE.finditer(text):
        if match.group("lo_group") != match.group("hi_group"):
            continue
        group = match.group("lo_group")
        lo, hi = int(match.group("lo")), int(match.group("hi"))
        ids.update(f"{group}-{n:02d}" for n in range(lo, hi + 1))
    return sorted(ids)


def expand_range(cell: str) -> list[str] | None:
    """Expand a declared ``IA-01 … IA-11`` range cell, or ``None``."""
    match = RANGE_RE.match(cell.strip())
    if match is None or match.group("lo_group") != match.group("hi_group"):
        return None
    group = match.group("lo_group")
    lo, hi = int(match.group("lo")), int(match.group("hi"))
    if lo < 1 or hi < lo:
        return None
    return [f"{group}-{n:02d}" for n in range(lo, hi + 1)]


# ---------------------------------------------------------------------------
# State snapshot: every validator below is a pure function of this state
# ---------------------------------------------------------------------------


def parse_state(root: Path) -> tuple[dict | None, list[str]]:
    """Read the five documents and the crate list into a plain state dict."""
    errors: list[str] = []
    model_path = root / MODEL_REL
    try:
        model_text = model_path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [f"{MODEL_REL}: cannot be read: {exc}"]

    domain_body = section_body(model_text, "Domain documents")
    consolidated_body = section_body(model_text, "Consolidated register")
    risk_body = section_body(model_text, "Accepted-risk register")
    coverage_body = section_body(model_text, "Deliverable-list coverage")
    acceptance_body = section_body(model_text, "Acceptance check")
    missing = [
        title
        for title, body in (
            ("Domain documents", domain_body),
            ("Consolidated register", consolidated_body),
            ("Accepted-risk register", risk_body),
            ("Deliverable-list coverage", coverage_body),
            ("Acceptance check", acceptance_body),
        )
        if body is None
    ]
    if missing:
        return None, [f"{MODEL_REL}: section(s) missing: {', '.join(missing)}"]
    assert domain_body and consolidated_body and risk_body and coverage_body and acceptance_body

    # 1. the domain-documents table: document path, declared ID range, group
    domain_rows, row_errors = table_rows(domain_body, DOMAIN_COLUMNS, "Domain documents")
    errors.extend(row_errors)
    domains: dict[str, dict[str, str]] = {}
    for cells in domain_rows:
        link = re.search(r"\(([^)]+\.md)\)", cells[0])
        declared = expand_range(cells[1])
        if link is None or declared is None:
            errors.append(
                f"Domain documents: row {cells[0][:40]!r} needs a document link and a "
                f"'<GROUP>-NN … <GROUP>-NN' range"
            )
            continue
        group = declared[0].split("-", 1)[0]
        if group in domains:
            errors.append(f"Domain documents: group {group} is declared twice")
            continue
        domains[group] = {"path": link.group(1), "declared": declared}

    # 2. the consolidated register
    consolidated, consolidated_errors = table_rows(
        consolidated_body, REGISTER_COLUMNS, "Consolidated register"
    )
    errors.extend(consolidated_errors)
    consolidated_rows = [
        {
            "id": cells[0],
            "stride": cells[2],
            "disposition": cells[3],
            "mitigation": cells[4],
            "accepted": cells[5],
        }
        for cells in consolidated
    ]

    # 3. the accepted-risk register
    risk_rows, risk_errors = table_rows(risk_body, RISK_COLUMNS, "Accepted-risk register")
    errors.extend(risk_errors)
    accepted_risk_rows = [{"id": cells[0], "owner": cells[3]} for cells in risk_rows]

    # 4. each domain document's closing register (hrefs are relative to the
    #    model document's own directory)
    domain_registers: dict[str, list[dict[str, str]]] = {}
    domain_texts: dict[str, str] = {}
    for group, info in sorted(domains.items()):
        path = root / MODEL_DIR / info["path"]
        rel = domain_rel(info["path"])
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{rel}: cannot be read: {exc}")
            continue
        domain_texts[group] = text
        body = section_body(text, DOMAIN_SECTION)
        if body is None:
            errors.append(f"{rel}: '{DOMAIN_SECTION}' section is missing")
            continue
        rows, row_errs = table_rows(body, REGISTER_COLUMNS, rel)
        errors.extend(row_errs)
        domain_registers[group] = [
            {
                "id": cells[0],
                "stride": cells[2],
                "disposition": cells[3],
                "mitigation": cells[4],
                "accepted": cells[5],
            }
            for cells in rows
        ]

    if errors:
        return None, errors

    crates_dir = root / CRATES_REL
    if not crates_dir.is_dir():
        return None, [f"{CRATES_REL}/: workspace crate directory is missing"]
    crates = sorted(p.name for p in crates_dir.iterdir() if p.is_dir())

    return (
        {
            "consolidated": consolidated_rows,
            "accepted_risk": accepted_risk_rows,
            "domains": domains,
            "domain_registers": domain_registers,
            "domain_texts": domain_texts,
            "coverage": parse_coverage(coverage_body),
            "acceptance_text": acceptance_body,
            "model_text": model_text,
            "crates": crates,
        },
        [],
    )


# ---------------------------------------------------------------------------
# Validators (pure functions of the state)
# ---------------------------------------------------------------------------


def names_owner(cell: str) -> bool:
    """Does a cell name an owner from the closed vocabulary?"""
    if any(phrase in cell for phrase in OWNER_PHRASES):
        return True
    return bool(CRATE_OWNER_RE.search(cell))


def row_shape_errors(rows: list[dict[str, str]], where: str) -> list[str]:
    """Register-row grammar: ID shape, uniqueness, STRIDE vocabulary."""
    errors: list[str] = []
    seen: set[str] = set()
    for row in rows:
        rid = row["id"]
        if not ID_RE.match(rid):
            errors.append(f"{where}: malformed finding ID {rid[:24]!r}")
            continue
        if rid in seen:
            errors.append(f"{where}: finding {rid} appears twice")
        seen.add(rid)
        if not STRIDE_RE.match(row["stride"]):
            errors.append(f"{where}: {rid} STRIDE {row['stride'][:12]!r} is not a STRIDE combination")
    return errors


def disposition_errors(rows: list[dict[str, str]], where: str) -> list[str]:
    """The Phase 1 exit-gate rule, per row: mitigation or accepted risk.

    A row must state one in its disposition, and must carry an enforcing
    test class and/or an accepted risk — a bare em-dash cell is empty.
    """
    errors: list[str] = []
    for row in rows:
        rid = row["id"]
        if not ID_RE.match(rid):
            continue  # already reported by the shape validator
        lowered = row["disposition"].lower()
        if "mitigat" not in lowered and "accept" not in lowered:
            errors.append(f"{where}: {rid} disposition states neither a mitigation nor an acceptance")
        mitigation = row["mitigation"] not in EMPTY_CELLS
        acceptance = row["accepted"] not in EMPTY_CELLS
        if not mitigation and not acceptance:
            errors.append(f"{where}: {rid} carries neither an enforcing test class nor an accepted risk")
    return errors


def coverage_set_errors(state: dict) -> list[str]:
    """Row-for-row coverage: consolidated == every domain register == ranges."""
    errors: list[str] = []
    consolidated_ids = {row["id"] for row in state["consolidated"] if ID_RE.match(row["id"])}
    declared_ids: set[str] = set()
    for group, info in state["domains"].items():
        declared = set(info["declared"])
        declared_ids |= declared
        register = {
            row["id"] for row in state["domain_registers"].get(group, []) if ID_RE.match(row["id"])
        }
        if register != declared:
            errors.append(
                f"{domain_rel(info['path'])}: register {sorted(register)} does not match the "
                f"declared {group} range {sorted(declared)}"
            )
    if consolidated_ids != declared_ids:
        missing = sorted(declared_ids - consolidated_ids)
        added = sorted(consolidated_ids - declared_ids)
        if missing:
            errors.append(f"Consolidated register: findings missing vs the domain documents: {missing}")
        if added:
            errors.append(f"Consolidated register: findings absent from every domain document: {added}")
    return errors


def risk_register_errors(state: dict) -> list[str]:
    """Accepted-risk register rows expand owner-bearing consolidated rows."""
    errors: list[str] = []
    consolidated = {row["id"]: row for row in state["consolidated"] if ID_RE.match(row["id"])}
    bases: set[str] = set()
    for row in state["accepted_risk"]:
        rid = row["id"]
        match = BASE_ID_RE.match(rid)
        if match is None:
            errors.append(f"Accepted-risk register: malformed ID {rid[:24]!r}")
            continue
        base = match.group("base")
        bases.add(base)
        if base not in consolidated:
            errors.append(f"Accepted-risk register: {rid} expands no consolidated finding")
            continue
        if not names_owner(row["owner"]):
            errors.append(
                f"Accepted-risk register: {rid} Owner column names no owner from the closed vocabulary"
            )
    owner_bearing = {
        row["id"] for row in state["consolidated"] if names_owner(row["accepted"])
    }
    for rid in sorted(owner_bearing - bases):
        errors.append(
            f"Accepted-risk register: owner-bearing finding {rid} has no accepted-risk row"
        )
    for rid in sorted(bases - owner_bearing):
        errors.append(
            f"Accepted-risk register: {rid} carries no owner in the consolidated register"
        )
    return errors


def crate_reference_errors(state: dict) -> list[str]:
    """Every backticked `archivist-*` token names a real workspace crate."""
    errors: list[str] = []
    crates = set(state["crates"])
    texts = [state["model_text"], *state["domain_texts"].values()]
    for text in texts:
        for crate in CRATE_OWNER_RE.findall(text):
            if crate not in crates:
                errors.append(f"owner vocabulary: `{crate}` names no crate in {CRATES_REL}/")
    return sorted(set(errors))


def family_errors(state: dict) -> list[str]:
    """The nine plan-named families each map to existing findings."""
    errors: list[str] = []
    coverage = state["coverage"]
    unknown = sorted(set(coverage) - set(FAMILIES))
    missing = sorted(set(FAMILIES) - set(coverage))
    if unknown:
        errors.append(f"Deliverable-list coverage: unknown families: {unknown}")
    if missing:
        errors.append(f"Deliverable-list coverage: families missing: {missing}")
    consolidated_ids = {row["id"] for row in state["consolidated"] if ID_RE.match(row["id"])}
    for family in FAMILIES:
        ids = coverage.get(family)
        if ids is None:
            continue  # already reported as missing
        if not ids:
            errors.append(f"Deliverable-list coverage: {family} maps to no finding")
            continue
        unknown_ids = sorted(set(ids) - consolidated_ids)
        if unknown_ids:
            errors.append(
                f"Deliverable-list coverage: {family} names findings absent from the "
                f"register: {unknown_ids}"
            )
    return errors


def wiring_errors(state: dict) -> list[str]:
    """The acceptance check names this tool, so doc and gate stay one fact."""
    if TOOL_NAME not in state["acceptance_text"]:
        return [f"Acceptance check: does not name the enforcing gate {TOOL_NAME}"]
    return []


ALL_VALIDATORS = (
    ("register shape", lambda s: row_shape_errors(s["consolidated"], "Consolidated register")),
    ("disposition", lambda s: disposition_errors(s["consolidated"], "Consolidated register")),
    ("coverage", coverage_set_errors),
    ("risk register", risk_register_errors),
    ("crate references", crate_reference_errors),
    ("families", family_errors),
    ("wiring", wiring_errors),
)


def validate_state(state: dict) -> list[tuple[str, str]]:
    """Run every domain-register validator too, then the model validators."""
    failures: list[tuple[str, str]] = []
    for group in sorted(state["domain_registers"]):
        rows = state["domain_registers"][group]
        where = domain_rel(state["domains"][group]["path"])
        for label, errors in (
            ("register shape", row_shape_errors(rows, where)),
            ("disposition", disposition_errors(rows, where)),
        ):
            failures.extend((label, message) for message in errors)
    for label, validator in ALL_VALIDATORS:
        failures.extend((label, message) for message in validator(state))
    return failures


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def check(root: Path) -> int:
    state, errors = parse_state(root)
    if errors:
        for message in errors:
            fail(message)
        return 2
    assert state is not None
    failures = validate_state(state)
    for _, message in failures:
        fail(message)
    if failures:
        return 2
    counts = {group: sum(1 for row in state["consolidated"] if row["id"].startswith(group))
              for group in GROUPS}
    print(
        "threat model: "
        + ", ".join(f"{group} {counts[group]}" for group in GROUPS)
        + f"; {len(state['accepted_risk'])} accepted risks; "
        + f"{len(state['coverage'])} families"
    )
    print("OK")
    return 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

SANDBOX_MODEL = """# Sandbox threat model

## Domain documents

| Document | Findings | Domain |
|---|---|---|
| [Identity](threats/identity-access.md) | IA-01 … IA-02 | identity |
| [Payload](threats/payload-integrity.md) | PI-01 … PI-01 | payload |
| [Relay](threats/relay-delegation.md) | RD-01 … RD-02 | relay |
| [Receipts](threats/receipts-and-disclosure.md) | RMD-01 … RMD-01 | receipts |

## Consolidated register

| ID | Finding | STRIDE | Disposition | Tested mitigation — enforcing test class | Accepted risk — owner |
|---|---|---|---|---|---|
| IA-01 | Spoofed uploader | S | Mitigated | altered vectors | — |
| IA-02 | Window replay residual | R | Mitigated; residual accepted | convergence vectors | SEC working group |
| PI-01 | Digest confusion | T | Mitigated | digest mismatch conformance | — |
| RD-01 | Out-of-scope relay | S/E | Mitigated | delegation negatives | — |
| RD-02 | Relay fabrication | S/R | Accepted | — (bounded by RD-01 proofs) | tenant operator |
| RMD-01 | Forged receipt | S/T | Mitigated | receipt-signature vectors | — |

## Accepted-risk register

| ID | Accepted risk | Containment (plan-fixed) | Owner |
|---|---|---|---|
| IA-02 | Replay cost inside the window | idempotent convergence | SEC working group |
| RD-02 | Fabrication residual | attribution and containment | tenant operator |

## Deliverable-list coverage

- Spoofing — IA-01, RD-01, RD-02
- Replay — IA-02
- Cross-tenant writes — RD-01
- Digest confusion — PI-01
- Decompression bombs — PI-01
- Poisoned manifests — PI-01
- Metadata leakage — RMD-01
- Relay/delegation abuse — RD-01 … RD-02
- Receipt trust failure — RMD-01

## Acceptance check

Machine-checked by `tools/check-threat-model.py` in the definition-of-done
fast lane.
"""

SANDBOX_DOMAINS = {
    "identity-access.md": """# Sandbox identity threats

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| IA-01 | Spoofed uploader | S | Mitigated | altered vectors | — |
| IA-02 | Window replay residual | R | Mitigated; residual accepted | convergence vectors | SEC working group |
""",
    "payload-integrity.md": """# Sandbox payload threats

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| PI-01 | Digest confusion | T | Mitigated | digest mismatch conformance | — |
""",
    "relay-delegation.md": """# Sandbox relay threats

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| RD-01 | Out-of-scope relay | S/E | Mitigated | delegation negatives | — |
| RD-02 | Relay fabrication | S/R | Accepted | — (bounded by RD-01 proofs) | tenant operator |
""",
    "receipts-and-disclosure.md": """# Sandbox receipt threats

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| RMD-01 | Forged receipt | S/T | Mitigated | receipt-signature vectors | — |
""",
}


def write_sandbox(base: Path) -> Path:
    """Materialize the minimal threat-model tree under *base*."""
    root = base / "root"
    (root / "docs/security/threats").mkdir(parents=True)
    (root / CRATES_REL / "archivist-auth").mkdir(parents=True)
    (root / CRATES_REL / "archivist-server").mkdir(parents=True)
    (root / MODEL_REL).write_text(SANDBOX_MODEL, encoding="utf-8")
    for name, text in SANDBOX_DOMAINS.items():
        (root / THREATS_REL / name).write_text(text, encoding="utf-8")
    return root


def self_test() -> int:
    # The committed tree must validate before any sandbox claim matters.
    committed, committed_errors = parse_state(ROOT)
    if committed is None:
        for message in committed_errors:
            fail(message)
        print("self-test base: the committed threat model is invalid", file=sys.stderr)
        return 2
    base_failures = validate_state(committed)
    if base_failures:
        for _, message in base_failures:
            fail(message)
        print("self-test base: the committed threat model is invalid", file=sys.stderr)
        return 2

    passed = 0
    failed = 0

    def case(label: str, errors: list[tuple[str, str]], must_reject: bool, want: str | None = None) -> None:
        nonlocal passed, failed
        rejected = bool(errors)
        labels = {name for name, _ in errors}
        ok = rejected == must_reject and (want is None or want in labels)
        if ok:
            passed += 1
            print(f"  ok  {'rejects' if rejected else 'accepts'}: {label}")
        else:
            failed += 1
            state = "should reject" if must_reject else "should accept"
            print(f"  FAIL {state}: {label} (rule labels: {sorted(labels)})")
            for _, message in errors:
                print(f"       violation: {message}")

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        root = write_sandbox(base)
        state, errors = parse_state(root)
        if errors:
            for message in errors:
                fail(message)
            failed += 1
            print("  FAIL should accept: sandbox parse")
        else:
            assert state is not None
            case("clean sandbox model", validate_state(state), False)

        def mutated() -> dict:
            fresh, fresh_errors = parse_state(root)
            assert fresh is not None and not fresh_errors, "sandbox stopped parsing"
            return copy.deepcopy(fresh)

        # Coverage: row-for-row agreement across the three sources.
        state = mutated()
        state["consolidated"] = [r for r in state["consolidated"] if r["id"] != "IA-02"]
        case("finding dropped from the consolidated register", validate_state(state), True, "coverage")

        state = mutated()
        state["consolidated"].append(
            {"id": "IA-03", "stride": "S", "disposition": "Mitigated",
             "mitigation": "vectors", "accepted": "—"}
        )
        case("finding added to the consolidated register alone", validate_state(state), True, "coverage")

        state = mutated()
        state["domains"]["IA"]["declared"] = ["IA-01", "IA-02", "IA-03"]
        case("declared domain range disagrees with the registers", validate_state(state), True, "coverage")

        state = mutated()
        state["domain_registers"]["RD"] = state["domain_registers"]["RD"][:1]
        case("domain register loses a row", validate_state(state), True, "coverage")

        # Disposition: the Phase 1 exit-gate sentence, per row.
        state = mutated()
        state["consolidated"][0]["disposition"] = "Deferred to Phase 11"
        case("disposition neither mitigates nor accepts", validate_state(state), True, "disposition")

        state = mutated()
        state["consolidated"][2]["mitigation"] = "—"
        state["consolidated"][2]["accepted"] = "—"
        case("row carries neither test class nor accepted risk", validate_state(state), True, "disposition")

        state = mutated()
        state["consolidated"][0]["stride"] = "X/Y"
        case("STRIDE cell outside the closed letters", validate_state(state), True, "register shape")

        state = mutated()
        state["consolidated"].append(copy.deepcopy(state["consolidated"][0]))
        case("duplicate finding row", validate_state(state), True, "register shape")

        # Accepted-risk register: expansion, owners, one-to-one mapping.
        state = mutated()
        state["accepted_risk"][0]["id"] = "IA-09"
        case("accepted-risk row expands no consolidated finding", validate_state(state), True, "risk register")

        state = mutated()
        state["accepted_risk"][0]["owner"] = "the committee"
        case("accepted-risk owner outside the vocabulary", validate_state(state), True, "risk register")

        state = mutated()
        state["accepted_risk"] = [r for r in state["accepted_risk"] if r["id"] != "IA-02"]
        case("owner-bearing finding without an accepted-risk row", validate_state(state), True, "risk register")

        state = mutated()
        state["accepted_risk"].append({"id": "PI-01", "owner": "tenant operator"})
        case("accepted-risk row for a finding with no residual", validate_state(state), True, "risk register")

        # Crate references: owner tokens name real crates.
        state = mutated()
        state["model_text"] = state["model_text"].replace(
            "SEC working group", "`archivist-nonesuch` owner"
        )
        state["consolidated"][1]["accepted"] = "`archivist-nonesuch` owner"
        case("owner token names no workspace crate", validate_state(state), True, "crate references")

        # Families: closed set, existing findings, non-empty mapping.
        state = mutated()
        state["coverage"]["Spoofing"] = ["IA-09"]
        case("family maps to a finding absent from the register", validate_state(state), True, "families")

        state = mutated()
        state["coverage"]["Replay"] = []
        case("family maps to no finding", validate_state(state), True, "families")

        state = mutated()
        del state["coverage"]["Spoofing"]
        case("plan-named family missing", validate_state(state), True, "families")

        state = mutated()
        state["coverage"]["Usurpation"] = state["coverage"].pop("Spoofing")
        case("family outside the closed set", validate_state(state), True, "families")

        # Wiring: the acceptance check names the enforcing tool.
        state = mutated()
        state["acceptance_text"] = "checked by hand"
        case("acceptance check names no enforcing gate", validate_state(state), True, "wiring")

        # File-level rejection: a broken tree must not parse as success.
        broken = base / "broken"
        root2 = write_sandbox(broken)
        text = (root2 / MODEL_REL).read_text(encoding="utf-8")
        (root2 / MODEL_REL).write_text(
            text.replace("## Accepted-risk register", "## Risk list"), encoding="utf-8"
        )
        _, parse_errors = parse_state(root2)
        ok = bool(parse_errors)
        if ok:
            passed += 1
            print("  ok  rejects: required section removed from the model")
        else:
            failed += 1
            print("  FAIL should reject: required section removed from the model")

    print(f"self-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Threat-model acceptance gate.")
    parser.add_argument(
        "--self-test", action="store_true", help="prove the rejection paths on a sandbox model"
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    return check(ROOT)


if __name__ == "__main__":
    sys.exit(main())
