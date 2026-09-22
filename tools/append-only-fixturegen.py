#!/usr/bin/env python3
"""Generate the synthetic append-only adapter corpus.

The corpus is deliberately small and boring: each source is UTF-8 JSON Lines
made from fixed, synthetic records.  The files are useful to adapters because
the byte boundaries are the fixture, while no adapter or test-harness format
is encoded in them.

Usage::

    tools/append-only-fixturegen.py --verify
    tools/append-only-fixturegen.py --generate /path/to/output
    tools/append-only-fixturegen.py --generate fixtures/synthetic/append-only \
        --force

``--verify`` compares the canonical corpus with bytes produced in memory. It
also rejects unrecognized files and checks that the missing-root scene really
has no source root. The generator uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CANONICAL_OUTPUT = ROOT / "fixtures" / "synthetic" / "append-only"
SCHEMA = "archivist.synthetic-append-only/v1"
SEED = "archivist-phase6d-append-only-2026-09-22"


def json_line(record: dict[str, object]) -> bytes:
    """Render one record in the corpus' canonical JSONL representation."""

    rendered = json.dumps(
        record,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return (rendered + "\n").encode("ascii")


def source(records: list[dict[str, object]]) -> bytes:
    """Render a complete source made of newline-terminated records."""

    return b"".join(json_line(record) for record in records)


def records(
    session_id: str,
    event_ids: tuple[str, ...],
    timestamps: tuple[str, ...],
    texts: tuple[tuple[str, str], ...],
) -> list[dict[str, object]]:
    """Build one fixed synthetic session from its pinned values."""

    if len(event_ids) != len(timestamps) or len(texts) != len(event_ids) - 2:
        raise ValueError("a session needs start, messages, and end values")
    result: list[dict[str, object]] = [
        {
            "id": session_id,
            "schema": 1,
            "ts": timestamps[0],
            "type": "session_start",
        }
    ]
    for index, (role, text) in enumerate(texts, start=1):
        result.append(
            {
                "id": event_ids[index],
                "role": role,
                "text": text,
                "ts": timestamps[index],
                "type": role,
            }
        )
    result.append(
        {
            "id": event_ids[-1],
            "reason": "complete",
            "ts": timestamps[-1],
            "type": "session_end",
        }
    )
    return result


def complete_records() -> bytes:
    """The golden whole-store scene."""

    return source(
        records(
            "00000000-0000-4000-8000-000000000001",
            (
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
                "00000000-0000-4000-8000-000000000003",
                "00000000-0000-4000-8000-000000000004",
            ),
            (
                "2026-06-01T10:00:00Z",
                "2026-06-01T10:00:01Z",
                "2026-06-01T10:00:02Z",
                "2026-06-01T10:00:03Z",
            ),
            (
                ("user", "quiet cedar meets amber marsh"),
                ("assistant", "the lantern follows the river"),
            ),
        )
    )


def partial_tail() -> bytes:
    """A complete prefix followed by a deliberately torn JSON line."""

    complete = records(
        "00000000-0000-4000-8000-000000000101",
        (
            "00000000-0000-4000-8000-000000000101",
            "00000000-0000-4000-8000-000000000102",
            "00000000-0000-4000-8000-000000000103",
            "00000000-0000-4000-8000-000000000104",
        ),
        (
            "2026-06-02T11:00:00Z",
            "2026-06-02T11:00:01Z",
            "2026-06-02T11:00:02Z",
            "2026-06-02T11:00:03Z",
        ),
        (
            ("user", "pale meadow keeps a patient watch"),
            ("assistant", "the cove returns a clear signal"),
        ),
    )
    prefix = source(complete[:3])
    torn = json_line(complete[3])
    # Leave neither the closing JSON object nor a newline in the tail.  The
    # exact cut is pinned by this generator, not chosen by a reader at run
    # time.
    return prefix + torn[:-9]


def growth() -> tuple[bytes, bytes]:
    """Return an unchanged prefix and its append-only successor."""

    all_records = records(
        "00000000-0000-4000-8000-000000000201",
        (
            "00000000-0000-4000-8000-000000000201",
            "00000000-0000-4000-8000-000000000202",
            "00000000-0000-4000-8000-000000000203",
            "00000000-0000-4000-8000-000000000204",
            "00000000-0000-4000-8000-000000000205",
            "00000000-0000-4000-8000-000000000206",
        ),
        (
            "2026-06-03T12:00:00Z",
            "2026-06-03T12:00:01Z",
            "2026-06-03T12:00:02Z",
            "2026-06-03T12:00:03Z",
            "2026-06-03T12:00:04Z",
            "2026-06-03T12:00:05Z",
        ),
        (
            ("user", "a willow bends beside the water"),
            ("assistant", "the beacon mirrors the southern sky"),
            ("user", "a second quiet record arrives"),
            ("assistant", "the record settles under the first"),
        ),
    )
    before = source(all_records[:4])
    after = source(all_records)
    if not after.startswith(before) or after == before:
        raise AssertionError("growth scene must append to an unchanged prefix")
    return before, after


def replacement() -> tuple[bytes, bytes]:
    """Return two complete roots whose source bytes have different identities."""

    old = source(
        records(
            "00000000-0000-4000-8000-000000000301",
            (
                "00000000-0000-4000-8000-000000000301",
                "00000000-0000-4000-8000-000000000302",
                "00000000-0000-4000-8000-000000000303",
                "00000000-0000-4000-8000-000000000304",
            ),
            (
                "2026-06-04T13:00:00Z",
                "2026-06-04T13:00:01Z",
                "2026-06-04T13:00:02Z",
                "2026-06-04T13:00:03Z",
            ),
            (
                ("user", "the old grove holds a steady shape"),
                ("assistant", "the old signal remains complete"),
            ),
        )
    )
    new = source(
        records(
            "00000000-0000-4000-8000-000000000401",
            (
                "00000000-0000-4000-8000-000000000401",
                "00000000-0000-4000-8000-000000000402",
                "00000000-0000-4000-8000-000000000403",
                "00000000-0000-4000-8000-000000000404",
            ),
            (
                "2026-06-04T14:00:00Z",
                "2026-06-04T14:00:01Z",
                "2026-06-04T14:00:02Z",
                "2026-06-04T14:00:03Z",
            ),
            (
                ("user", "the new grove opens a different path"),
                ("assistant", "the new signal starts a fresh record"),
            ),
        )
    )
    if old == new:
        raise AssertionError("replacement roots must differ byte-for-byte")
    return old, new


def permissions() -> bytes:
    """A normal complete scene whose mode is changed by the consuming suite."""

    return source(
        records(
            "00000000-0000-4000-8000-000000000501",
            (
                "00000000-0000-4000-8000-000000000501",
                "00000000-0000-4000-8000-000000000502",
                "00000000-0000-4000-8000-000000000503",
                "00000000-0000-4000-8000-000000000504",
            ),
            (
                "2026-06-05T15:00:00Z",
                "2026-06-05T15:00:01Z",
                "2026-06-05T15:00:02Z",
                "2026-06-05T15:00:03Z",
            ),
            (
                ("user", "permissions leave the source unchanged"),
                ("assistant", "the reader reports a bounded failure"),
            ),
        )
    )


README = """# Synthetic append-only corpus

This directory contains six small, adapter-agnostic scenes for the Phase 6D
append-only source contract. Every source file is UTF-8 JSON Lines with LF
line endings. The records, identifiers, timestamps, and text are fixed
synthetic values; no file contains a private transcript, path, URL, or
credential. The JSONL bytes are the contract, so consumers must preserve the
complete-record boundary and must not invent a parser-specific wrapper.

The scene roots are laid out as follows:

```
complete-records/root/source.jsonl   complete newline-terminated store
partial-tail/root/source.jsonl      complete prefix plus a torn final line
growth/before/source.jsonl           first snapshot
growth/after/source.jsonl            byte-identical before prefix plus appends
replacement/old/source.jsonl         old complete root
replacement/new/source.jsonl         different complete root
permissions/root/source.jsonl        normal complete store; remove read access after copying
missing-root/                         no `root/` directory by design
```

The `missing-root` scene is represented by its scene directory and the absence
of `missing-root/root`. A suite should configure that absent path and report a
coverage gap. A suite should copy `permissions/root` before changing its mode;
checked-in Git modes are not part of this fixture contract.

`manifest.json` records the six scene names, their materialization rules, and
the SHA-256 digest and byte count of every generated file. Run
`python3 tools/append-only-fixturegen.py --verify` from the repository root to
check the committed bytes. To regenerate a target, use `--generate PATH`; use
`--force` only when replacing an existing target.
"""


MISSING_ROOT_README = """# Missing-root scene

This scene intentionally has no `root/` directory. Configure the adapter with
`missing-root/root` and verify that an absent source is a coverage gap rather
than an error storm.
"""


def payloads() -> dict[str, bytes]:
    """Return every non-manifest file in deterministic path order."""

    before, after = growth()
    old, new = replacement()
    result = {
        "README.md": README.encode("utf-8"),
        "complete-records/root/source.jsonl": complete_records(),
        "growth/after/source.jsonl": after,
        "growth/before/source.jsonl": before,
        "missing-root/README.md": MISSING_ROOT_README.encode("utf-8"),
        "partial-tail/root/source.jsonl": partial_tail(),
        "permissions/root/source.jsonl": permissions(),
        "replacement/new/source.jsonl": new,
        "replacement/old/source.jsonl": old,
    }
    return dict(sorted(result.items()))


SCENARIOS = [
    {
        "name": "complete-records",
        "kind": "complete",
        "root": "complete-records/root",
        "files": ["complete-records/root/source.jsonl"],
    },
    {
        "name": "partial-tail",
        "kind": "torn-final-line",
        "root": "partial-tail/root",
        "files": ["partial-tail/root/source.jsonl"],
    },
    {
        "name": "growth",
        "kind": "append-pair",
        "roots": {"before": "growth/before", "after": "growth/after"},
        "files": ["growth/before/source.jsonl", "growth/after/source.jsonl"],
    },
    {
        "name": "replacement",
        "kind": "root-swap",
        "roots": {"old": "replacement/old", "new": "replacement/new"},
        "files": ["replacement/old/source.jsonl", "replacement/new/source.jsonl"],
    },
    {
        "name": "permissions",
        "kind": "normal-readable-source",
        "root": "permissions/root",
        "files": ["permissions/root/source.jsonl"],
    },
    {
        "name": "missing-root",
        "kind": "absent-root",
        "root": "missing-root/root",
        "files": [],
    },
]


def digest_entries(files: dict[str, bytes]) -> list[dict[str, object]]:
    """Create sorted, byte-counted file entries for the manifest."""

    return [
        {
            "bytes": len(data),
            "path": path,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for path, data in files.items()
    ]


def manifest_for(files: dict[str, bytes]) -> bytes:
    """Render the manifest, which intentionally does not self-hash."""

    entries = digest_entries(files)
    corpus_digest = hashlib.sha256(
        b"".join(
            f"{entry['path']}\0{entry['sha256']}\n".encode("ascii")
            for entry in entries
        )
    ).hexdigest()
    manifest = {
        "corpus_digest": corpus_digest,
        "files": entries,
        "scenarios": SCENARIOS,
        "schema": SCHEMA,
        "seed": SEED,
    }
    return (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def expected_files() -> dict[str, bytes]:
    """Build the complete deterministic output, including its manifest."""

    files = payloads()
    files["manifest.json"] = manifest_for(files)
    return dict(sorted(files.items()))


def source_paths(root: Path) -> list[str]:
    """List regular files below a corpus root using POSIX relative paths."""

    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    )


def validate_payloads(files: dict[str, bytes]) -> None:
    """Check the intentionally narrow content envelope of source files."""

    for path, data in files.items():
        if not path.endswith(".jsonl"):
            continue
        if b"/" in data or b"@" in data or b"\x00" in data:
            raise ValueError(f"unsafe byte in synthetic source {path}")
        lines = data.splitlines(keepends=True)
        if not lines or not lines[-1].endswith(b"\n"):
            if path != "partial-tail/root/source.jsonl":
                raise ValueError(f"source is not newline-terminated: {path}")
        complete_lines = lines[:-1] if path == "partial-tail/root/source.jsonl" else lines
        for line in complete_lines:
            if not line.endswith(b"\n"):
                raise ValueError(f"complete record is not newline-terminated: {path}")
            json.loads(line)
        if path == "partial-tail/root/source.jsonl":
            tail = lines[-1]
            if tail.endswith(b"\n") or not tail:
                raise ValueError("partial-tail scene has no torn final line")
            try:
                json.loads(tail)
            except json.JSONDecodeError:
                pass
            else:
                raise ValueError("partial-tail final line unexpectedly parses")
    before = files["growth/before/source.jsonl"]
    after = files["growth/after/source.jsonl"]
    if not after.startswith(before) or after == before:
        raise ValueError("growth files do not form a strict append pair")
    if files["replacement/old/source.jsonl"] == files["replacement/new/source.jsonl"]:
        raise ValueError("replacement roots are byte-identical")


def verify(root: Path) -> int:
    """Verify the corpus without modifying it."""

    expected = expected_files()
    validate_payloads(expected)
    if not root.is_dir():
        print(f"missing corpus directory: {root}", file=sys.stderr)
        return 2
    actual = source_paths(root)
    wanted = sorted(expected)
    if actual != wanted:
        print("append-only corpus file set drift", file=sys.stderr)
        print(f"expected: {wanted}", file=sys.stderr)
        print(f"actual:   {actual}", file=sys.stderr)
        return 2
    missing_root = root / "missing-root" / "root"
    if missing_root.exists():
        print("missing-root scene unexpectedly contains root/", file=sys.stderr)
        return 2
    for relative, wanted_bytes in expected.items():
        actual_bytes = (root / relative).read_bytes()
        if actual_bytes != wanted_bytes:
            print(f"byte drift: {relative}", file=sys.stderr)
            return 2
    total = sum(len(data) for data in expected.values())
    digest = hashlib.sha256(
        b"".join(path.encode("utf-8") + b"\0" + data for path, data in expected.items())
    ).hexdigest()
    print(f"verified {len(expected)} files, {total} bytes, digest {digest}")
    return 0


def generate(output: Path, force: bool) -> int:
    """Write a deterministic corpus to ``output``."""

    if output.exists():
        canonical = output.resolve() == CANONICAL_OUTPUT.resolve()
        if not canonical and not force and any(output.iterdir()):
            print(f"refusing to overwrite existing directory: {output}", file=sys.stderr)
            print("pass --force to replace it", file=sys.stderr)
            return 2
        if not output.is_dir():
            print(f"refusing to replace non-directory: {output}", file=sys.stderr)
            return 2
        shutil.rmtree(output)
    files = expected_files()
    validate_payloads(files)
    for relative, data in files.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return verify(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify", action="store_true", help="verify the canonical corpus")
    mode.add_argument("--generate", metavar="OUTPUT", type=Path, help="generate a corpus")
    parser.add_argument("--force", action="store_true", help="replace an existing output")
    args = parser.parse_args()
    if args.verify:
        if args.force:
            parser.error("--force is only valid with --generate")
        return verify(CANONICAL_OUTPUT)
    return generate(args.generate, args.force)


if __name__ == "__main__":
    raise SystemExit(main())
