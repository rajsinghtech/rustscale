description: Find line numbers of a pattern in a file without re-reading the whole file into context (the #1 token-sink fix from phases 5-7). Prints file:line:match for each hit so you can then Read a narrow offset/limit window around the exact line to edit.
agent: build
---

Find line numbers of `$ARGUMENTS` in the codebase WITHOUT re-reading whole files.

Run `tools/where.sh <pattern> <file>` (which is `grep -n`/`rg -n` under the hood) to get `file:line:matched-text` lines. Then, if you need to edit, use the Read tool with a narrow `offset`/`limit` window around the specific line number — do NOT re-read the whole file.

Arguments: $ARGUMENTS

This replaces the phase 5-7 anti-pattern of re-reading large own files dozens of times (tsnet/src/lib.rs was re-read 53x in phase 7, 124K chars) just to locate one function. Files over ~300 lines should never be fully re-read once you've learned their shape.
