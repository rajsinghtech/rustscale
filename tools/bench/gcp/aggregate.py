#!/usr/bin/env python3
"""tools/bench/gcp/aggregate.py — glob per-run JSONs into a single summary.json.

Usage:
    python3 tools/bench/gcp/aggregate.py <results_dir> > <results_dir>/summary.json

Globs <results_dir>/<topology>/<path>/<config>.json, reads each, and emits a
JSON array of all run objects (sorted by topology, path, config). The output
is consumed by render-html.py.
"""

import json
import sys
from pathlib import Path

CONFIG_ORDER = {"rs-userspace": 0, "rs-tun": 1, "ts-userspace": 2, "ts-tun": 3}
PATH_ORDER = {"direct": 0, "derp": 1}
TOPO_ORDER = {"same-zone": 0, "cross-region": 1}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: aggregate.py <results_dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    runs = []
    failed = 0
    for cfg_json in sorted(root.glob("*/*/*.json")):
        # Skip a stray summary.json at the root (depth 0).
        try:
            obj = json.loads(cfg_json.read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"warn: skipping {cfg_json}: {e}", file=sys.stderr)
            continue
        # Only include objects that look like a bench run.
        if isinstance(obj, dict) and "config" in obj and "throughput" in obj:
            # Ensure error and log_tail fields exist so downstream
            # render-html.py can distinguish real zeros from stubs.
            obj.setdefault("error", "")
            obj.setdefault("log_tail", "")
            if obj["error"]:
                failed += 1
                print(
                    f"warn: {obj.get('topology','?')}/{obj.get('path','?')}/"
                    f"{obj.get('config','?')}: FAILED ({obj['error']})",
                    file=sys.stderr,
                )
            runs.append(obj)

    # Check for missing cells: every (topology, path, config) combo should
    # have a run. Report gaps so they are not silently absent from the
    # dashboard.
    seen = {(r.get("topology"), r.get("path"), r.get("config")) for r in runs}
    for topo in ("same-zone", "cross-region"):
        for path in ("direct", "derp"):
            for cfg in ("rs-userspace", "rs-tun", "ts-userspace", "ts-tun"):
                if (topo, path, cfg) not in seen:
                    print(
                        f"warn: MISSING {topo}/{path}/{cfg} — no JSON found",
                        file=sys.stderr,
                    )

    runs.sort(
        key=lambda r: (
            TOPO_ORDER.get(r.get("topology", ""), 99),
            PATH_ORDER.get(r.get("path", ""), 99),
            CONFIG_ORDER.get(r.get("config", ""), 99),
        )
    )

    json.dump(runs, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
