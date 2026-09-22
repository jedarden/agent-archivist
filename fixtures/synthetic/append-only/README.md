# Synthetic append-only corpus

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
