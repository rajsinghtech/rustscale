---
description: Find line numbers of a pattern without re-reading a whole file. Prints file:line:match for narrow follow-up reads.
agent: build
---

Find line numbers of `$ARGUMENTS` in the codebase WITHOUT re-reading whole files.

Run `tools/where.sh <pattern> <file>` (which is `grep -n`/`rg -n` under the hood) to get `file:line:matched-text` lines. Then, if you need to edit, use the Read tool with a narrow `offset`/`limit` window around the specific line number — do NOT re-read the whole file.

Arguments: $ARGUMENTS

Prefer narrow follow-up reads for large files once you know their structure.
