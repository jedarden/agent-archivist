#!/usr/bin/env python3
"""No-SDK-type public-surface gate for ``archivist-protocol``.

The crate boundary promises that no public item can expose a replaceable
third-party SDK shape (plan Section 4; docs/notes/crate-ownership.md rule 6).
``tools/check-crate-graph.py`` enforces the manifest half — the sealed crate
declares no dependency outside the workspace. This tool enforces the source
half, which nothing else scans:

1. every ``pub use`` re-export names an allowed path root (``crate``/``self``/
   ``super``/``std``/``core``/``alloc``, or a project ``archivist_*`` crate);
2. every public signature — inherent methods and macro-generated items
   included — names only allowed type paths: fully qualified paths through the
   allowed roots above, or locally imported names that resolve to them. A
   signature referencing ``serde_json::Value`` — or a bare ``Value`` imported
   from it — fails;
3. the public API inventory test
   (``crates/archivist-protocol/tests/public_api_inventory.rs``) is complete
   and current: every public type, top-level function, and constant the
   source declares appears in the inventory, every inventory entry names an
   item that still exists, and the pinned-count literals match.

Discovery is source-scanning, including through the crate's own
``macro_rules!`` generators: a macro whose body emits ``pub struct $name`` or
``pub enum $name`` has its invocations' type arguments inventoried like
hand-written items. The scan is fail-closed — a path root that resolves to
nothing allowed is a violation, not a skip.

``--self-test`` first runs the real scan (the committed crate is the base
case), then proves the rejection paths against embedded fixture crates.

The script is standard-library only so a clean checkout can run it before any
dependency is fetched.

Usage::

    tools/check-protocol-boundary.py [--self-test]
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTOCOL_SRC = ROOT / "crates" / "archivist-protocol" / "src"
PROTOCOL_INVENTORY = (
    ROOT / "crates" / "archivist-protocol" / "tests" / "public_api_inventory.rs"
)

# Path roots a public signature or re-export may name: the crate itself, its
# descendants, the language core, and the allocation layer. Anything else —
# any third-party SDK crate — is a boundary violation.
ALLOWED_ROOTS = frozenset({"crate", "self", "super", "std", "core", "alloc"})
PROJECT_ROOT_PREFIX = "archivist_"

# Public declarations whose span is scanned for type paths. Indented matches
# are included, so inherent `impl` methods and macro-generated items are
# scanned exactly like top-level items.
PUB_DECLARATION_RE = re.compile(
    r"^[ \t]*pub\s+(?P<kind>const|static|fn|struct|enum|trait|type|use)\b", re.M
)

# Top-level (column-0) items are the documented inventory. Indented items are
# methods on inventoried types, not inventory entries.
HAND_WRITTEN_TYPE_RE = re.compile(r"^pub\s+(?:struct|enum|type|trait)\s+([A-Za-z0-9_]+)", re.M)
TOP_LEVEL_FN_RE = re.compile(r"^pub\s+fn\s+([a-z0-9_]+)", re.M)
TOP_LEVEL_CONST_RE = re.compile(r"^pub\s+const\s+([A-Z0-9_]+)", re.M)

MACRO_RULES_RE = re.compile(r"^macro_rules!\s+([a-z0-9_]+)\s*\{", re.M)
MACRO_INVOKE_RE = re.compile(r"\b([a-z0-9_]+)!\s*\(")
MACRO_TYPE_ARG_RE = re.compile(r"^\s+([A-Z][A-Za-z0-9_]*)\s*(?:,|;|\{|\)|$)", re.M)

USE_RE = re.compile(
    r"^\s*use\s+([A-Za-z0-9_:]+?)\s*::\s*(?:\{([^}]*)\}|([A-Za-z0-9_]+))\s*;", re.M
)

# The first segment of a type path only: a segment preceded by `::` is a
# continuation (`crate::vocabulary::X` has the root `crate`, not `vocabulary`),
# and a segment preceded by a word character is part of a longer identifier.
PATH_ROOT_RE = re.compile(r"(?<![\w:])([A-Za-z_][A-Za-z0-9_]*)\s*::")
IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")

INVENTORY_FUNCTIONS = ("type_inventory", "function_inventory", "constant_inventory")
# Inventory keys are crate-relative ``module::Item`` paths, so a leading
# allowed path root (``crate::thing::Good``, the resolved-name half of a
# type tuple) is not an entry — the lookahead keeps tuple-mate literals
# from registering as phantom entries.
INVENTORY_ENTRY_RE = re.compile(
    r'"(?!crate::|self::|super::|std::|core::|alloc::|archivist_)'
    r'([a-z_][a-z0-9_]*(?:::[A-Za-z0-9_]+)+)"'
)
TYPE_COUNT_LITERAL_RE = re.compile(r"PUBLIC_TYPES:\s*usize\s*=\s*(\d+)")
FN_COUNT_LITERAL_RE = re.compile(r"FREE_FUNCTIONS:\s*usize\s*=\s*(\d+)")


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def strip_comments(text: str) -> str:
    """Blank out ``//`` and ``/* */`` comments, preserving line structure."""
    text = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), text, flags=re.S)
    return re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)


def use_aliases(text: str) -> dict[str, str]:
    """Map every locally imported name to the first segment of its path."""
    aliases: dict[str, str] = {}
    for path, braces, single in USE_RE.findall(text):
        root = path.split("::")[0]
        # ``findall`` yields '' (not None) for the group of the un-taken
        # alternative, so a braced-import test must be truthiness, not
        # ``is not None`` — otherwise single imports never register.
        if braces:
            for item in braces.split(","):
                item = item.strip()
                if not item:
                    continue
                name = item.split(" as ")[-1].strip()
                if name == "self":
                    name = path.split("::")[-1]
                aliases[name] = root
        else:
            aliases[single] = root
    return aliases


def root_allowed(root: str) -> bool:
    return root in ALLOWED_ROOTS or root.startswith(PROJECT_ROOT_PREFIX)


def declaration_span(text: str, start: int) -> str:
    """Return one declaration up to its body ``{`` or terminator ``;``.

    Bracket depth is tracked so an interior ``;`` (an array const's element
    separator) never ends the span early.
    """
    depth = 0
    end = start
    while end < len(text):
        char = text[end]
        if depth == 0 and char in "{;":
            break
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        end += 1
    return text[start:end]


def resolve_root(root: str, aliases: dict[str, str]) -> str:
    """Follow alias chains (bounded) to the underlying path root."""
    for _ in range(8):
        if root not in aliases:
            return root
        root = aliases[root]
    return root


def check_public_spans(
    relative: str, text: str, aliases: dict[str, str], errors: list[str]
) -> None:
    """Reject foreign type paths and foreign imports in public signatures."""
    for match in PUB_DECLARATION_RE.finditer(text):
        span = declaration_span(text, match.start())
        where = f"{relative}:{text[: match.start()].count(chr(10)) + 1}"
        for root in PATH_ROOT_RE.findall(span):
            if root_allowed(root):
                continue
            resolved = resolve_root(root, aliases)
            if root_allowed(resolved):
                continue
            errors.append(
                f"{where}: public {match.group('kind')} names non-project type "
                f"path `{root}::` — the no-SDK-type boundary allows only "
                f"{sorted(ALLOWED_ROOTS)} and `{PROJECT_ROOT_PREFIX}*` roots"
            )
        for ident in set(IDENT_RE.findall(span)):
            if ident in aliases and not root_allowed(resolve_root(ident, aliases)):
                errors.append(
                    f"{where}: public {match.group('kind')} references foreign "
                    f"type `{ident}` imported from `{aliases[ident]}::`"
                )


def balanced_body(text: str, open_paren: int) -> str:
    """Return the text between a ``(`` and its balancing ``)``."""
    depth = 1
    end = open_paren + 1
    while end < len(text) and depth:
        if text[end] == "(":
            depth += 1
        elif text[end] == ")":
            depth -= 1
        end += 1
    return text[open_paren + 1 : end - 1]


def macro_type_generators(text: str) -> set[str]:
    """Names of ``macro_rules!`` in this file that emit public types."""
    generators: set[str] = set()
    for match in MACRO_RULES_RE.finditer(text):
        body = balanced_body(text, text.find("{", match.start()))
        if "$name" in body and re.search(r"pub\s+(?:struct|enum)\s+\$name", body):
            generators.add(match.group(1))
    return generators


def source_modules(src: Path) -> list[tuple[str, Path]]:
    """``(module, path)`` for the library's own modules (``bin/`` excluded)."""
    modules: list[tuple[str, Path]] = []
    for path in sorted(src.rglob("*.rs")):
        relative = path.relative_to(src)
        if relative.parts[0] == "bin":
            continue
        module = "" if relative.name == "lib.rs" else relative.stem
        modules.append((module, path))
    return modules


def discover_public_items(src: Path) -> tuple[set[str], set[str], set[str]]:
    """The public types, top-level functions, and constants, per module."""
    types: set[str] = set()
    functions: set[str] = set()
    constants: set[str] = set()
    for module, path in source_modules(src):
        text = strip_comments(path.read_text(encoding="utf-8"))
        prefix = f"{module}::" if module else ""
        generators = macro_type_generators(text)
        for match in HAND_WRITTEN_TYPE_RE.finditer(text):
            types.add(f"{prefix}{match.group(1)}")
        for match in MACRO_INVOKE_RE.finditer(text):
            if match.group(1) not in generators:
                continue
            body = balanced_body(text, match.end() - 1)
            named = MACRO_TYPE_ARG_RE.search(body)
            if named:
                types.add(f"{prefix}{named.group(1)}")
        for match in TOP_LEVEL_FN_RE.finditer(text):
            functions.add(f"{prefix}{match.group(1)}")
        for match in TOP_LEVEL_CONST_RE.finditer(text):
            constants.add(f"{prefix}{match.group(1)}")
    return types, functions, constants


def inventory_entries(test_path: Path) -> tuple[set[str], set[str], set[str], int, int]:
    """Parse the inventory test into its three entry sets and count literals."""
    text = test_path.read_text(encoding="utf-8")
    chunks = re.split(r"^(?:#\[test\]\n)?fn ", text, flags=re.M)
    types: set[str] = set()
    functions: set[str] = set()
    constants: set[str] = set()
    for chunk in chunks:
        for name in INVENTORY_FUNCTIONS:
            if chunk.startswith(f"{name}("):
                entries = set(INVENTORY_ENTRY_RE.findall(chunk))
                if name == "type_inventory":
                    types = entries
                elif name == "function_inventory":
                    functions = entries
                else:
                    constants = entries
    type_match = TYPE_COUNT_LITERAL_RE.search(text)
    fn_match = FN_COUNT_LITERAL_RE.search(text)
    type_count = int(type_match.group(1)) if type_match else -1
    fn_count = int(fn_match.group(1)) if fn_match else -1
    return types, functions, constants, type_count, fn_count


def scan_surface(src: Path, inventory: Path) -> list[str]:
    """Run every boundary rule; return the violation list (empty = pass)."""
    errors: list[str] = []
    if not inventory.is_file():
        return [
            f"inventory test not found: {inventory} — the public surface must "
            "be documented to be enforced"
        ]
    for _module, path in source_modules(src):
        text = strip_comments(path.read_text(encoding="utf-8"))
        check_public_spans(str(path.relative_to(src)), text, use_aliases(text), errors)

    discovered_types, discovered_fns, discovered_consts = discover_public_items(src)
    inventory_types, inventory_fns, inventory_consts, type_count, fn_count = (
        inventory_entries(inventory)
    )

    for missing in sorted(discovered_types - inventory_types):
        errors.append(
            f"public type `{missing}` is missing from the inventory test ({inventory})"
        )
    for stale in sorted(inventory_types - discovered_types):
        errors.append(f"inventory entry `{stale}` names no public type in the crate")
    for missing in sorted(discovered_fns - inventory_fns):
        errors.append(
            f"public function `{missing}` is missing from the inventory test"
        )
    for stale in sorted(inventory_fns - discovered_fns):
        errors.append(f"inventory entry `{stale}` names no public function in the crate")
    for missing in sorted(discovered_consts - inventory_consts):
        errors.append(
            f"public constant `{missing}` is missing from the inventory test"
        )
    for stale in sorted(inventory_consts - discovered_consts):
        errors.append(f"inventory entry `{stale}` names no public constant in the crate")

    if type_count != len(discovered_types):
        errors.append(
            f"PUBLIC_TYPES literal is {type_count} but the crate declares "
            f"{len(discovered_types)} public types"
        )
    if fn_count != len(discovered_fns):
        errors.append(
            f"FREE_FUNCTIONS literal is {fn_count} but the crate declares "
            f"{len(discovered_fns)} top-level public functions"
        )
    return errors


# --- self-test ---------------------------------------------------------------

CLEAN_LIB = """\
pub mod thing;
"""
CLEAN_THING = """\
use std::fmt;

/// A project-owned wire value.
pub struct Good;

/// Builds nothing; exists to be public.
pub fn make(text: &str) -> Good {
    let _ = text;
    Good
}

/// Renders a good.
pub fn render(good: &Good) -> impl fmt::Display + '_ {
    let _ = good;
    "good"
}

/// The only limit.
pub const LIMIT: usize = 16;
"""
CLEAN_INVENTORY = """\
const PUBLIC_TYPES: usize = 1;
const FREE_FUNCTIONS: usize = 2;

fn type_inventory() -> Vec<(&'static str, &'static str)> {
    vec![("thing::Good", "crate::thing::Good")]
}

fn function_inventory() -> Vec<&'static str> {
    vec!["thing::make", "thing::render"]
}

fn constant_inventory() -> Vec<&'static str> {
    vec!["thing::LIMIT"]
}
"""


def write_fixture(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def run_self_test() -> int:
    """The committed crate must be clean, then every rejection must fire."""
    committed = scan_surface(PROTOCOL_SRC, PROTOCOL_INVENTORY)
    for violation in committed:
        fail(f"self-test base: committed crate violates the boundary: {violation}")
    if committed:
        return 2

    cases: list[tuple[str, dict[str, str], str]] = [
        ("clean surface passes", {"src/lib.rs": CLEAN_LIB, "src/thing.rs": CLEAN_THING,
                                  "tests/inventory.rs": CLEAN_INVENTORY}, None),
        ("foreign signature path fails", {
            "src/lib.rs": CLEAN_LIB,
            "src/thing.rs": CLEAN_THING + "\npub fn bad(value: foreign_sdk::Value) -> usize { 1 }\n",
            "tests/inventory.rs": CLEAN_INVENTORY}, "non-project type path `foreign_sdk::`"),
        ("foreign re-export fails", {
            "src/lib.rs": CLEAN_LIB,
            "src/thing.rs": CLEAN_THING + "\npub use foreign_sdk::Value;\n",
            "tests/inventory.rs": CLEAN_INVENTORY}, "non-project type path `foreign_sdk::`"),
        ("aliased foreign type fails", {
            "src/lib.rs": CLEAN_LIB,
            "src/thing.rs": "use foreign_sdk::Value;\n\n" + CLEAN_THING
                            + "\npub fn bare(value: Value) -> usize { 2 }\n",
            "tests/inventory.rs": CLEAN_INVENTORY}, "references foreign type `Value`"),
        ("uninventoried public type fails", {
            "src/lib.rs": CLEAN_LIB,
            "src/thing.rs": CLEAN_THING + "\npub struct Undocumented;\n",
            "tests/inventory.rs": CLEAN_INVENTORY}, "`thing::Undocumented` is missing"),
        ("stale inventory entry fails", {
            "src/lib.rs": CLEAN_LIB,
            "src/thing.rs": CLEAN_THING,
            "tests/inventory.rs": CLEAN_INVENTORY.replace(
                '"thing::LIMIT"', '"thing::LIMIT", "thing::GONE"')},
         "names no public constant"),
        ("wrong count literal fails", {
            "src/lib.rs": CLEAN_LIB,
            "src/thing.rs": CLEAN_THING,
            "tests/inventory.rs": CLEAN_INVENTORY.replace(
                "const PUBLIC_TYPES: usize = 1;", "const PUBLIC_TYPES: usize = 7;")},
         "PUBLIC_TYPES literal is 7"),
        ("macro-generated type must be inventoried", {
            "src/lib.rs": CLEAN_LIB,
            "src/thing.rs": CLEAN_THING + """
macro_rules! good_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(String);
    };
}

good_newtype!(
    /// A generated wire value.
    Generated
);
""",
            "tests/inventory.rs": CLEAN_INVENTORY}, "`thing::Generated` is missing"),
    ]

    passed = 0
    failed = 0
    with tempfile.TemporaryDirectory() as scratch:
        base = Path(scratch)
        for index, (description, files, expected) in enumerate(cases):
            tree = base / f"case-{index}"
            write_fixture(tree, files)
            violations = scan_surface(tree / "src", tree / "tests" / "inventory.rs")
            if expected is None:
                if violations:
                    fail(f"self-test ({description}): unexpected violations:")
                    for violation in violations:
                        fail(f"  {violation}")
                    failed += 1
                else:
                    passed += 1
            elif any(expected in violation for violation in violations):
                passed += 1
            else:
                fail(f"self-test ({description}): expected a violation matching "
                     f"{expected!r}, got:")
                for violation in violations:
                    fail(f"  {violation}")
                failed += 1

    print(f"self-test: {passed} passed, {failed} failed")
    return 2 if failed else 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        return run_self_test()
    if argv[1:]:
        fail(f"unknown arguments: {' '.join(argv[1:])}")
        return 2

    errors = scan_surface(PROTOCOL_SRC, PROTOCOL_INVENTORY)
    for violation in errors:
        fail(violation)
    if errors:
        return 2

    types, functions, constants = discover_public_items(PROTOCOL_SRC)
    print("agent-archivist protocol boundary (archivist-protocol)")
    print(f"public surface: {len(types)} types, {len(functions)} top-level "
          f"functions, {len(constants)} constants — all project-owned")
    print("OK: no-SDK-type boundary holds (plan Section 4, "
          "docs/notes/crate-ownership.md rule 6)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
