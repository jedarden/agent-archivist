#!/usr/bin/env python3
"""README status-coherence gate for Agent Archivist.

The README's implementation-status statements are claims about the
machine-checked records, and they drifted once already: the README still
described the ingestion data plane, the harness adapters, and the
``archivist`` CLI as "still ahead of their phases" after all twelve
crates had landed behavior. This gate (fast lane of
``scripts/definition-of-done.sh``) reads committed files only and
rejects any state of the three that disagrees with the other two:

1. the requirement counts the README displays match
   ``tools/verification-register.json`` — every "N of T requirements"
   phrase equals the register's implemented and total counts, and at
   least one such phrase exists;
2. the crate counts the README displays match the Landed-state column
   of ``docs/notes/crate-ownership.md`` — every "N of T workspace
   crates" phrase equals the map's landed and total row counts, and at
   least one such phrase exists;
3. every ownership row states its landed state in the established
   vocabulary ("Landed — …" or "… not started — documentation-only"),
   so the counts in rule 2 are derived from cells that mean what they
   say;
4. the README links both authorities it derives its status from — the
   crate ownership map and the verification register;
5. the retired stage claims ("design-stage", "still ahead of their
   phases") appear nowhere in the README: the first describes a
   design-only repository this workspace stopped being, and the second
   is the exact drift this gate exists to catch.

``--self-test`` replays the rejection paths against the committed files
with in-memory mutations and requires every one to fire and every
well-formed variant to pass. The plain run prints the derived counts and
exits 0; any failure prints a report on stderr and exits 2.

Usage::

    tools/check-readme-status.py [--self-test]

The script is standard-library only and offline: it validates documents
against documents, never against a live system, which is what keeps a
status claim and its evidence in one commit.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README_PATH = Path("README.md")
REGISTER_PATH = Path("tools/verification-register.json")
OWNERSHIP_PATH = Path("docs/notes/crate-ownership.md")

# The two count phrases the README carries. Each occurrence must agree
# with the record it summarizes, and at least one occurrence of each
# must exist — a README that stops stating a count has stopped making
# the claim the record can check.
REQUIREMENT_COUNT_RE = re.compile(r"(\d+) of (\d+) requirements")
CRATE_COUNT_RE = re.compile(r"(\d+) of (\d+) workspace crates")

# Rows of the Ownership table: "| `archivist-…` | layer | purpose |
# phase | dependencies | Landed state |". The landed cell is the last
# pipe-delimited cell of the row.
OWNERSHIP_ROW_RE = re.compile(
    r"^\|\s*`(?P<crate>archivist-[a-z0-9-]+)`.*$", re.M
)

# The note's own vocabulary: a crate's cell either records landed
# behavior or the not-started marker from the workspace baseline rule.
NOT_STARTED_MARKER = "documentation-only"

# The stage claims this gate retires. Both read as honest summaries
# while carrying no record behind them, which is how the README drifted
# in the first place.
RETIRED_CLAIMS = ("design-stage", "still ahead of their phases")

VALID_STATUSES = frozenset({"planned", "implemented"})


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def load_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"{path}: cannot be read: {exc}")
        return None


def load_register(path: Path) -> dict | None:
    try:
        register = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"{path}: cannot be read: {exc}")
        return None
    except json.JSONDecodeError as exc:
        fail(f"{path}: cannot be parsed as JSON: {exc}")
        return None
    if not isinstance(register, dict) or not isinstance(
        register.get("requirements"), dict
    ):
        fail(f"{path}: has no 'requirements' object")
        return None
    return register


def register_counts(register: dict) -> tuple[int, int] | None:
    """The (implemented, total) requirement counts, or ``None``."""
    implemented = 0
    total = 0
    for requirement, entry in register["requirements"].items():
        status = entry.get("status") if isinstance(entry, dict) else None
        if status not in VALID_STATUSES:
            fail(
                f"{REGISTER_PATH}: requirement {requirement!r} carries status "
                f"{status!r}; the closed set is {sorted(VALID_STATUSES)}"
            )
            return None
        total += 1
        if status == "implemented":
            implemented += 1
    return implemented, total


def landed_cells(ownership: str) -> dict[str, str] | None:
    """The per-crate Landed-state cells, or ``None`` on a shape fault."""
    cells: dict[str, str] = {}
    for match in OWNERSHIP_ROW_RE.finditer(ownership):
        crate = match.group("crate")
        row = match.group(0).rstrip()
        if not row.endswith("|"):
            fail(
                f"{OWNERSHIP_PATH}: the row for {crate!r} does not end its "
                "last cell with '|'"
            )
            return None
        cell = row[: row.rfind("|")].split("|")[-1].strip()
        cells[crate] = cell
    if not cells:
        fail(f"{OWNERSHIP_PATH}: no ownership rows found")
        return None
    return cells


def validate_ownership(cells: dict[str, str]) -> list[str]:
    violations: list[str] = []
    for crate, cell in sorted(cells.items()):
        if not cell.startswith("Landed") and NOT_STARTED_MARKER not in cell:
            violations.append(
                f"{OWNERSHIP_PATH}: the Landed state cell for {crate!r} uses "
                "neither the landed vocabulary ('Landed — …') nor the "
                "not-started marker ('… not started — documentation-only'); "
                "a cell outside the vocabulary cannot be counted"
            )
    return violations


def validate_coherence(
    readme: str,
    register: dict,
    cells: dict[str, str],
) -> list[str]:
    violations: list[str] = []

    counts = register_counts(register)
    if counts is not None:
        implemented, total = counts
        phrases = REQUIREMENT_COUNT_RE.findall(readme)
        if not phrases:
            violations.append(
                "README.md must state the register's counts as "
                f"'{implemented} of {total} requirements' — the "
                f"machine-checked statement in {REGISTER_PATH} is what the "
                "README's status claims derive from"
            )
        for stated_n, stated_t in phrases:
            if (int(stated_n), int(stated_t)) != (implemented, total):
                violations.append(
                    "README.md states "
                    f"{stated_n} of {stated_t} requirements; "
                    f"{REGISTER_PATH} counts {implemented} implemented of "
                    f"{total}"
                )

    landed = sum(1 for cell in cells.values() if cell.startswith("Landed"))
    total = len(cells)
    phrases = CRATE_COUNT_RE.findall(readme)
    if not phrases:
        violations.append(
            "README.md must state the workspace's landed-crate counts as "
            f"'{landed} of {total} workspace crates' — the Landed-state "
            f"column of {OWNERSHIP_PATH} is what the README's status claims "
            "derive from"
        )
    for stated_n, stated_t in phrases:
        if (int(stated_n), int(stated_t)) != (landed, total):
            violations.append(
                f"README.md states {stated_n} of {stated_t} workspace "
                f"crates; {OWNERSHIP_PATH} carries {landed} landed rows of "
                f"{total}"
            )

    if "docs/notes/crate-ownership.md" not in readme:
        violations.append(
            "README.md must link docs/notes/crate-ownership.md, the "
            "per-crate record of landed behavior and open work"
        )
    if "tools/verification-register.json" not in readme:
        violations.append(
            "README.md must link tools/verification-register.json, the "
            "machine-checked statement of implemented requirements"
        )

    for claim in RETIRED_CLAIMS:
        if claim in readme:
            violations.append(
                f"README.md: the claim {claim!r} is retired; the status "
                "sections derive from the register and the ownership map, "
                "which is what keeps them checkable"
            )

    return violations


def validate_all(register: dict, readme: str, ownership: str) -> list[str]:
    cells = landed_cells(ownership)
    if cells is None:
        return ["the ownership map could not be parsed"]
    counts_ok = register_counts(register) is not None
    violations = validate_ownership(cells) if counts_ok else []
    return violations + validate_coherence(readme, register, cells)


# --- self-test ----------------------------------------------------------------


def flip_first_planned(register: dict) -> None:
    for entry in register["requirements"].values():
        if entry.get("status") == "planned":
            entry["status"] = "implemented"
            return


# (label, must_reject, README mutation, ownership mutation, register
# mutation). Every rejection path must fire and every well-formed
# variant must pass against the committed base.
SELF_TEST_CASES = [
    (
        "the committed README, register, and ownership map",
        False,
        lambda readme: readme,
        lambda ownership: ownership,
        None,
    ),
    (
        "the retired design-stage claim restored to the README",
        True,
        lambda readme: readme.replace(
            "Agent Archivist is an open system",
            "Agent Archivist is a design-stage, open system",
            1,
        ),
        lambda ownership: ownership,
        None,
    ),
    (
        "the retired ahead-of-phase claim restored to the README",
        True,
        lambda readme: readme.replace(
            "health-check compositions. The",
            "health-check compositions, all still ahead of their phases. The",
            1,
        ),
        lambda ownership: ownership,
        None,
    ),
    (
        "the README's crate count disagreeing with the ownership map",
        True,
        lambda readme: readme.replace(
            "12 of 12 workspace crates", "11 of 12 workspace crates", 1
        ),
        lambda ownership: ownership,
        None,
    ),
    (
        "the README's requirement count disagreeing with the register",
        True,
        lambda readme: readme.replace(
            "10 of 116 requirements", "11 of 116 requirements", 1
        ),
        lambda ownership: ownership,
        None,
    ),
    (
        "the register moving ahead of the README's counts",
        True,
        lambda readme: readme,
        lambda ownership: ownership,
        flip_first_planned,
    ),
    (
        "the README dropping the ownership-map link",
        True,
        lambda readme: readme.replace(
            "docs/notes/crate-ownership.md", "docs/notes/requirements.md"
        ),
        lambda ownership: ownership,
        None,
    ),
    (
        "the README dropping the register link",
        True,
        lambda readme: readme.replace(
            "tools/verification-register.json", "docs/notes/verification.md"
        ),
        lambda ownership: ownership,
        None,
    ),
    (
        "a landed crate's cell reverted to the not-started marker",
        True,
        lambda readme: readme,
        lambda ownership: ownership.replace(
            "| Landed — Phase 6C:",
            "| Phase 6C not started — documentation-only; previously:",
            1,
        ),
        None,
    ),
    (
        "a landed-state cell outside the established vocabulary",
        True,
        lambda readme: readme,
        lambda ownership: ownership.replace(
            "| Landed — Phase 6C:", "| Under construction, partly:", 1
        ),
        None,
    ),
    (
        "the README counts following a crate reverted to not-started",
        False,
        lambda readme: readme.replace(
            "12 of 12 workspace crates", "11 of 12 workspace crates", 1
        ),
        lambda ownership: ownership.replace(
            "| Landed — Phase 6C:",
            "| Phase 6C not started — documentation-only; previously:",
            1,
        ),
        None,
    ),
]


def run_self_test(
    base_register: dict, base_readme: str, base_ownership: str
) -> int:
    passed = 0
    failed = 0

    for label, must_reject, readme_fn, ownership_fn, register_fn in SELF_TEST_CASES:
        readme = readme_fn(base_readme)
        ownership = ownership_fn(base_ownership)
        register = base_register if register_fn is None else copy.deepcopy(
            base_register
        )
        if register_fn is not None:
            register_fn(register)
        violations = validate_all(register, readme, ownership)
        rejected = bool(violations)
        if rejected == must_reject:
            passed += 1
            print(f"  ok  {'rejects' if rejected else 'accepts'}: {label}")
        else:
            failed += 1
            print(
                f"  FAIL {'should reject' if must_reject else 'should accept'}: "
                f"{label}"
            )
            for violation in violations:
                print(f"       violation: {violation}")

    print(f"self-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


def main(argv: list[str]) -> int:
    register = load_register(ROOT / REGISTER_PATH)
    readme = load_text(ROOT / README_PATH)
    ownership = load_text(ROOT / OWNERSHIP_PATH)
    if register is None or readme is None or ownership is None:
        return 2

    if "--self-test" in argv[1:]:
        if validate_all(register, readme, ownership):
            fail("self-test base: the committed documents themselves disagree")
            return 2
        return run_self_test(register, readme, ownership)
    if argv[1:]:
        fail(f"unknown arguments: {' '.join(argv[1:])}")
        return 2

    violations = validate_all(register, readme, ownership)
    for violation in violations:
        fail(violation)
    if violations:
        return 2

    cells = landed_cells(ownership) or {}
    counts = register_counts(register) or (0, 0)
    landed = sum(1 for cell in cells.values() if cell.startswith("Landed"))
    print("agent-archivist README status coherence")
    print(
        f"  requirements: {counts[0]} implemented of {counts[1]} "
        f"({REGISTER_PATH})"
    )
    print(f"  crates: {landed} landed of {len(cells)} ({OWNERSHIP_PATH})")
    print("OK: README status statements match the machine-checked records")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
