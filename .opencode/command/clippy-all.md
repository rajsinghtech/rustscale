---
description: Run clippy in a single pass, showing ALL warnings deduplicated and sorted (capped at 50 lines). Prevents the anti-pattern of running clippy 6+ times fixing one warning at a time.
agent: build
---

Run `tools/clippy-all.sh $ARGUMENTS` to see ALL clippy warnings in one pass. The script deduplicates warning lines, sorts them, and caps output at 50 unique warnings. Fix all warnings before re-running — do not fix one warning at a time.

If the report shows no warnings, you're clean. If errors exist alongside warnings, fix errors first.

Arguments: $ARGUMENTS
