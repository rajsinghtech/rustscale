#!/usr/bin/env bash
# tools/bench/gcp/collect.sh — gather every GCP bench run into one place.
#
# Walks all bench-results/gcp-* run directories, (re)builds each run's
# summary.json + dashboard.html from its per-run JSONs, then writes a single
# bench-results/gcp-index.html linking every run newest-first with a one-line
# health summary (runs / failed / missing) per dashboard.
#
# Idempotent and offline: no gcloud, no API, no network — pure aggregate +
# render over whatever JSONs already exist on disk. Safe to re-run any time.
#
# Usage:
#   tools/bench/gcp/collect.sh [RESULTS_ROOT]
#     RESULTS_ROOT defaults to bench-results/
#
# Output:
#   <root>/gcp-<stamp>/summary.json   (regenerated)
#   <root>/gcp-<stamp>/dashboard.html (regenerated)
#   <root>/gcp-index.html             (index of all runs)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

ROOT="${1:-bench-results}"
AGG="tools/bench/gcp/aggregate.py"
RENDER="tools/bench/gcp/render-html.py"
INDEX="$ROOT/gcp-index.html"

if [[ ! -d "$ROOT" ]]; then
  echo "[collect] no results dir at $ROOT — nothing to collect" >&2
  exit 0
fi

shopt -s nullglob
runs=("$ROOT"/gcp-*/)
shopt -u nullglob
if [[ ${#runs[@]} -eq 0 ]]; then
  echo "[collect] no gcp-* run dirs under $ROOT" >&2
  exit 0
fi

# Newest first by directory name (gcp-YYYYMMDD-HHMMSS sorts lexically = chrono).
mapfile -t runs < <(printf '%s\n' "${runs[@]}" | sort -r)

# Index rows accumulate here (a temp file avoids subshell scoping issues).
rows="$(mktemp)"
trap 'rm -f "$rows"' EXIT

total_runs=0 total_failed=0 total_missing=0
for dir in "${runs[@]}"; do
  dir="${dir%/}"
  stamp="$(basename "$dir")"
  json_count=$(find "$dir" -name '*.json' ! -name 'summary.json' 2>/dev/null | wc -l | tr -d ' ')

  # (Re)build summary + dashboard. aggregate warns to stderr about FAILED and
  # MISSING cells; capture that to count them for the index.
  agg_err="$(mktemp)"
  if python3 "$AGG" "$dir" > "$dir/summary.json" 2>"$agg_err"; then
    python3 "$RENDER" "$dir/summary.json" > "$dir/dashboard.html"
    ok=1
  else
    ok=0
  fi
  failed=$(grep -c 'FAILED' "$agg_err" 2>/dev/null || true)
  missing=$(grep -c 'MISSING' "$agg_err" 2>/dev/null || true)
  failed=${failed:-0}; missing=${missing:-0}
  rm -f "$agg_err"

  total_runs=$((total_runs + 1))
  total_failed=$((total_failed + failed))
  total_missing=$((total_missing + missing))

  if [[ "$ok" = 1 ]]; then
    status="<span class=\"ok\">rendered</span>"
    [[ "$failed" -gt 0 ]] && status="$status · <span class=\"bad\">$failed failed</span>"
    [[ "$missing" -gt 0 ]] && status="$status · <span class=\"warn\">$missing missing</span>"
    link="<a href=\"$stamp/dashboard.html\">dashboard</a>"
  else
    status="<span class=\"bad\">render failed</span>"
    link="—"
  fi

  printf '<tr><td>%s</td><td>%s JSON</td><td>%s</td><td>%s</td></tr>\n' \
    "$stamp" "$json_count" "$status" "$link" >> "$rows"
  echo "[collect] $stamp: $json_count JSON, failed=$failed missing=$missing" >&2
done

# Emit the index.
{
  cat <<'HTML'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rustscale GCP benchmark runs</title>
<style>
  :root { --bg:#0f1115; --fg:#e4e7eb; --fg-dim:#9aa4b2; --elev:#171a21;
          --border:#2a313c; --accent:#3b82f6; --good:#22c55e; --bad:#ef4444; --warn:#f59e0b; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  header { padding:20px 28px; background:var(--elev); border-bottom:1px solid var(--border); }
  h1 { margin:0 0 6px; font-size:22px; }
  .meta { color:var(--fg-dim); font-size:13px; }
  main { padding:24px 28px 64px; max-width:1100px; margin:0 auto; }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:10px 14px; border-bottom:1px solid var(--border); }
  th { color:var(--fg-dim); font-size:12px; text-transform:uppercase; letter-spacing:.5px; }
  a { color:var(--accent); text-decoration:none; }
  a:hover { text-decoration:underline; }
  .ok { color:var(--good); } .bad { color:var(--bad); } .warn { color:var(--warn); }
</style>
</head>
<body>
<header>
  <h1>rustscale GCP benchmark runs</h1>
  <div class="meta" id="meta"></div>
</header>
<main>
<table>
<thead><tr><th>Run</th><th>Data</th><th>Status</th><th>Dashboard</th></tr></thead>
<tbody>
HTML
  cat "$rows"
  cat <<HTML
</tbody>
</table>
</main>
<script>
document.getElementById('meta').textContent =
  '$total_runs run(s) collected — $total_failed failed cell(s), $total_missing missing cell(s) across all runs.';
</script>
</body>
</html>
HTML
} > "$INDEX"

echo "[collect] wrote $INDEX ($total_runs runs)" >&2
echo "$INDEX"
