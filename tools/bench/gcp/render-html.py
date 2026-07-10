#!/usr/bin/env python3
"""tools/bench/gcp/render-html.py — render a standalone HTML dashboard from
summary.json.

Usage:
    python3 tools/bench/gcp/render-html.py <summary.json> > <dashboard.html>
    python3 tools/bench/gcp/render-html.py          # reads stdin

Emits a single self-contained HTML document (no external network deps) with:
  - 4 throughput grouped bar charts (one per topology/path combo)
  - 1 latency grouped bar chart (p50/p95/p99 per config)
  - 1 footprint table with conditional formatting
  - per-config detail cards (collapsible)
  - dark-mode default with light-mode toggle
  - topology/path/mode filters

Charting is a hand-rolled canvas bar-chart implementation (no Chart.js) so the
file stays small and opens via file:// with zero dependencies.
"""

import html
import json
import os
import sys
from datetime import datetime, timezone

CONFIGS = ["rs-userspace", "rs-tun", "ts-userspace", "ts-tun"]
CONFIG_COLORS = {
    "rs-userspace": "#3b82f6",  # blue
    "rs-tun": "#22c55e",        # green
    "ts-userspace": "#f97316",  # orange
    "ts-tun": "#ef4444",        # red
}
CONFIG_LABELS = {
    "rs-userspace": "rustscale (userspace)",
    "rs-tun": "rustscale (TUN)",
    "ts-userspace": "tailscaled (userspace)",
    "ts-tun": "tailscaled (TUN)",
}
TOPOLOGIES = ["same-zone", "cross-region"]
PATHS = ["direct", "derp"]
PARALLELS = [1, 10, 25, 50, 100]


def load_summary() -> list:
    if len(sys.argv) > 1 and sys.argv[1] not in ("-", ""):
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            return json.load(f)
    return json.load(sys.stdin)


def index_runs(runs: list) -> dict:
    """Index runs by (topology, path, config) -> run obj."""
    idx = {}
    for r in runs:
        key = (r.get("topology", "?"), r.get("path", "?"), r.get("config", "?"))
        idx[key] = r
    return idx


def fmt_bytes(n: float) -> str:
    if n >= 1_073_741_824:
        return f"{n / 1_073_741_824:.2f} GiB"
    if n >= 1_048_576:
        return f"{n / 1_048_576:.2f} MiB"
    if n >= 1024:
        return f"{n / 1024:.2f} KiB"
    return f"{n} B"


def fmt_kb(n: float) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.2f} GiB"
    if n >= 1024:
        return f"{n / 1024:.2f} MiB"
    return f"{n} KiB"


def fmt_us(n: float) -> str:
    if n >= 1000:
        return f"{n / 1000:.2f} ms"
    return f"{n} µs"


def fmt_mbps(n: float) -> str:
    if n >= 1000:
        return f"{n / 1000:.2f} Gbps"
    return f"{n:.1f} Mbps"


# ---------------------------------------------------------------------------
# Bar-chart data preparation.
# ---------------------------------------------------------------------------
def throughput_chart_data(runs_idx: dict, topo: str, path: str) -> dict:
    """Return {parallels: [...], series: {config: [mbps per parallel]},
    failed: {config: bool}, errors: {config: str}}."""
    series = {}
    failed = {}
    errors = {}
    for cfg in CONFIGS:
        run = runs_idx.get((topo, path, cfg))
        vals = []
        if run:
            err = run.get("error", "")
            if err:
                failed[cfg] = True
                errors[cfg] = err
            tp = {t["parallel"]: t.get("mbps", 0) for t in run.get("throughput", [])}
            for p in PARALLELS:
                vals.append(float(tp.get(p, 0)))
        else:
            failed[cfg] = True
            errors[cfg] = "missing (no JSON)"
            vals = [0.0] * len(PARALLELS)
        series[cfg] = vals
    return {
        "parallels": PARALLELS,
        "series": series,
        "failed": failed,
        "errors": errors,
    }


def latency_chart_data(runs_idx: dict) -> dict:
    """Return {topos_paths: [...], series: {config: {p50,p95,p99 per combo}}}."""
    combos = []
    for topo in TOPOLOGIES:
        for path in PATHS:
            combos.append(f"{topo} / {path}")
    series = {}
    for cfg in CONFIGS:
        rows = []
        for topo in TOPOLOGIES:
            for path in PATHS:
                run = runs_idx.get((topo, path, cfg))
                lat = run.get("latency", {}) if run else {}
                rows.append({
                    "p50": float(lat.get("p50_us", 0)),
                    "p95": float(lat.get("p95_us", 0)),
                    "p99": float(lat.get("p99_us", 0)),
                })
        series[cfg] = rows
    return {"combos": combos, "series": series}


def footprint_rows(runs_idx: dict) -> list:
    """Return one row per (topo, path, config) with footprint metrics."""
    rows = []
    for topo in TOPOLOGIES:
        for path in PATHS:
            for cfg in CONFIGS:
                run = runs_idx.get((topo, path, cfg))
                if not run:
                    continue
                foot = run.get("footprint", {})
                rows.append({
                    "topo": topo,
                    "path": path,
                    "config": cfg,
                    "error": run.get("error", ""),
                    "binary_bytes": int(foot.get("binary_size_bytes", 0)),
                    "rss_peak_kb": int(foot.get("rss_peak_kb", 0)),
                    "rss_avg_kb": int(foot.get("rss_avg_kb", 0)),
                    "cpu_peak_pct": float(foot.get("cpu_peak_pct", 0)),
                    "cpu_avg_pct": float(foot.get("cpu_avg_pct", 0)),
                    "samples": int(foot.get("samples", 0)),
                })
    return rows


# ---------------------------------------------------------------------------
# HTML emission.
# ---------------------------------------------------------------------------
HTML_HEAD = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rustscale GCP bench dashboard</title>
<style>
:root {
  --bg: #0f1115;
  --bg-elev: #171a21;
  --bg-elev2: #1f2430;
  --fg: #e4e7eb;
  --fg-dim: #9aa4b2;
  --border: #2a313c;
  --accent: #3b82f6;
  --good: #22c55e;
  --bad: #ef4444;
  --warn: #f59e0b;
  --rs-us: #3b82f6;
  --rs-tun: #22c55e;
  --ts-us: #f97316;
  --ts-tun: #ef4444;
  --grid: #232a35;
}
[data-theme="light"] {
  --bg: #ffffff;
  --bg-elev: #f5f7fa;
  --bg-elev2: #eef2f7;
  --fg: #1a1f29;
  --fg-dim: #5a6478;
  --border: #d6dde6;
  --accent: #2563eb;
  --grid: #e2e8f0;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
header.app {
  padding: 20px 28px;
  background: var(--bg-elev);
  border-bottom: 1px solid var(--border);
}
header.app h1 { margin: 0 0 6px; font-size: 22px; }
header.app .meta { color: var(--fg-dim); font-size: 13px; }
main { padding: 24px 28px 64px; max-width: 1600px; margin: 0 auto; }
section.block { margin-bottom: 36px; }
section.block > h2 {
  font-size: 17px; margin: 0 0 14px; padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}
.filters {
  display: flex; flex-wrap: wrap; gap: 18px; align-items: center;
  margin-bottom: 18px; padding: 14px 18px;
  background: var(--bg-elev); border: 1px solid var(--border); border-radius: 8px;
}
.filters .group { display: flex; gap: 10px; align-items: center; }
.filters label { color: var(--fg-dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
.filters button {
  background: var(--bg-elev2); color: var(--fg); border: 1px solid var(--border);
  padding: 5px 12px; border-radius: 5px; cursor: pointer; font-size: 13px;
}
.filters button.active { background: var(--accent); border-color: var(--accent); color: #fff; }
.filters button:hover { border-color: var(--accent); }
.theme-toggle { margin-left: auto; }
.chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }
.chart-card {
  background: var(--bg-elev); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px;
}
.chart-card h3 { margin: 0 0 10px; font-size: 14px; color: var(--fg-dim); }
.chart-card canvas { width: 100%; height: 280px; display: block; }
.legend { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 10px; }
.legend .item { display: flex; align-items: center; gap: 6px; font-size: 12px; }
.legend .swatch { width: 12px; height: 12px; border-radius: 2px; }
table.footprint {
  width: 100%; border-collapse: collapse;
  background: var(--bg-elev); border: 1px solid var(--border); border-radius: 8px;
  overflow: hidden;
}
table.footprint th, table.footprint td {
  padding: 9px 12px; text-align: right; border-bottom: 1px solid var(--border);
  font-variant-numeric: tabular-nums;
}
table.footprint th { background: var(--bg-elev2); font-size: 12px; color: var(--fg-dim); text-transform: uppercase; }
table.footprint td.label { text-align: left; }
table.footprint td.best { color: var(--good); font-weight: 600; }
table.footprint td.worst { color: var(--bad); font-weight: 600; }
table.footprint tr:hover td { background: var(--bg-elev2); }
details.detail-card {
  background: var(--bg-elev); border: 1px solid var(--border); border-radius: 8px;
  margin-bottom: 8px; padding: 10px 14px;
}
details.detail-card summary { cursor: pointer; font-weight: 600; }
details.detail-card pre {
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 12px; overflow-x: auto; font-size: 12px; margin-top: 10px;
}
.empty { color: var(--fg-dim); padding: 20px; text-align: center; }
.hidden { display: none !important; }
/* Failed-run styling. */
.failed-banner {
  background: rgba(239,68,68,0.12); border: 1px solid var(--bad);
  border-radius: 8px; padding: 14px 18px; margin-bottom: 22px;
}
.failed-banner h2 { color: var(--bad); border-bottom: none; margin: 0 0 8px; }
.failed-banner .count { font-size: 13px; color: var(--fg-dim); margin-bottom: 10px; }
table.failed-runs {
  width: 100%; border-collapse: collapse; font-size: 13px;
}
table.failed-runs th, table.failed-runs td {
  padding: 7px 10px; text-align: left; border-bottom: 1px solid var(--border);
}
table.failed-runs th { color: var(--fg-dim); font-size: 11px; text-transform: uppercase; }
table.failed-runs td.error { color: var(--bad); font-family: monospace; font-size: 12px; }
table.failed-runs details { margin-top: 4px; }
table.failed-runs details summary { cursor: pointer; font-size: 12px; color: var(--fg-dim); }
table.failed-runds pre, table.failed-runs pre {
  background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
  padding: 8px; font-size: 11px; overflow-x: auto; margin-top: 6px;
  white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto;
}
.chart-card.has-failures { border-color: var(--bad); }
.chart-card .fail-badge {
  display: inline-block; background: var(--bad); color: #fff;
  font-size: 10px; padding: 2px 7px; border-radius: 3px; margin-left: 8px;
  font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
}
.detail-card.has-error summary { color: var(--bad); }
.detail-card .error-box {
  background: rgba(239,68,68,0.10); border: 1px solid var(--bad);
  border-radius: 6px; padding: 10px 14px; margin-top: 8px;
}
.detail-card .error-box .label { color: var(--bad); font-weight: 600; font-size: 12px; }
.detail-card .error-box .reason { font-family: monospace; font-size: 13px; }
.detail-card details.log-tail { margin-top: 8px; }
.detail-card details.log-tail summary { cursor: pointer; font-size: 12px; color: var(--fg-dim); }
.detail-card details.log-tail pre {
  background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
  padding: 10px; font-size: 11px; overflow-x: auto; margin-top: 6px;
  white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto;
}
table.footprint td.status-failed {
  color: var(--bad); font-weight: 600; font-size: 11px; text-transform: uppercase;
}
table.footprint td.status-ok {
  color: var(--good); font-size: 11px;
}
</style>
</head>
<body>
"""

HTML_FOOT = """</body>
</html>
"""


def render_chart_js_block(canvas_id: str, data: dict, kind: str) -> str:
    """Emit a <script> block drawing one chart on canvas_id.
    kind is 'throughput' or 'latency'."""
    json_data = json.dumps(data)
    return f"""<script>
(function() {{
  var data = {json_data};
  var canvas = document.getElementById({json.dumps(canvas_id)});
  if (!canvas) return;
  drawGroupedBars(canvas, data, {json.dumps(kind)});
}})();
</script>"""


def emit_throughput_charts(runs_idx: dict) -> str:
    parts = ['<div class="chart-grid" id="throughput-grid">']
    for topo in TOPOLOGIES:
        for path in PATHS:
            cid = f"tp-{topo}-{path}"
            data = throughput_chart_data(runs_idx, topo, path)
            data["title"] = f"{topo} / {path}"
            n_failed = len(data["failed"])
            fail_badge = ""
            card_class = "chart-card throughput-card"
            if n_failed:
                fail_badge = f'<span class="fail-badge">{n_failed} failed</span>'
                card_class += " has-failures"
            parts.append(f"""<div class="{card_class}" data-topo="{topo}" data-path="{path}">
  <h3>{html.escape(data["title"])} — throughput (Mbps){fail_badge}</h3>
  <canvas id="{cid}"></canvas>
</div>""")
    parts.append("</div>")
    # Legend.
    parts.append('<div class="legend">')
    for cfg in CONFIGS:
        parts.append(
            f'<div class="item"><span class="swatch" style="background:{CONFIG_COLORS[cfg]}"></span>'
            f'{html.escape(CONFIG_LABELS[cfg])}</div>'
        )
    parts.append("</div>")
    # Scripts (after DOM — but we emit them inline; the draw fn is defined
    # later in the global script).
    scripts = []
    for topo in TOPOLOGIES:
        for path in PATHS:
            cid = f"tp-{topo}-{path}"
            data = throughput_chart_data(runs_idx, topo, path)
            scripts.append(render_chart_js_block(cid, data, "throughput"))
    return "".join(parts) + "".join(scripts)


def emit_latency_chart(runs_idx: dict) -> str:
    data = latency_chart_data(runs_idx)
    parts = [
        '<div class="chart-card">',
        '  <h3>Latency p50 / p95 / p99 (µs) — grouped by topology / path</h3>',
        '  <canvas id="latency-chart"></canvas>',
        '</div>',
        '<div class="legend">',
    ]
    for lbl, color in [("p50", "#3b82f6"), ("p95", "#f59e0b"), ("p99", "#ef4444")]:
        parts.append(
            f'<div class="item"><span class="swatch" style="background:{color}"></span>{lbl}</div>'
        )
    parts.append("</div>")
    parts.append(render_chart_js_block("latency-chart", data, "latency"))
    return "".join(parts)


def emit_footprint_table(runs_idx: dict) -> str:
    rows = footprint_rows(runs_idx)
    if not rows:
        return '<div class="empty">No footprint data.</div>'
    # Compute best (min) per metric within each (topo, path) group.
    groups = {}
    for r in rows:
        groups.setdefault((r["topo"], r["path"]), []).append(r)
    best = {}
    for key, grp in groups.items():
        best[key] = {
            "binary_bytes": min((g["binary_bytes"] for g in grp if g["binary_bytes"]), default=0),
            "rss_peak_kb": min((g["rss_peak_kb"] for g in grp if g["rss_peak_kb"]), default=0),
            "rss_avg_kb": min((g["rss_avg_kb"] for g in grp if g["rss_avg_kb"]), default=0),
            "cpu_peak_pct": min((g["cpu_peak_pct"] for g in grp if g["cpu_peak_pct"]), default=0),
            "cpu_avg_pct": min((g["cpu_avg_pct"] for g in grp if g["cpu_avg_pct"]), default=0),
        }
    out = [
        '<table class="footprint" id="footprint-table">',
        '<thead><tr><th class="label">topology / path</th><th class="label">config</th>'
        '<th>status</th>',
        '<th>binary size</th><th>RSS peak</th><th>RSS avg</th>',
        '<th>CPU peak %</th><th>CPU avg %</th><th>samples</th></tr></thead>',
        '<tbody>',
    ]
    for r in rows:
        key = (r["topo"], r["path"])
        b = best[key]
        def cls(metric, val):
            return "best" if val == b[metric] and val > 0 else ""
        if r["error"]:
            status_cls = "status-failed"
            status_text = f"FAILED: {html.escape(r['error'])}"
        else:
            status_cls = "status-ok"
            status_text = "OK"
        out.append(
            f'<tr class="footprint-row" data-topo="{r["topo"]}" data-path="{r["path"]}" '
            f'data-config="{r["config"]}" data-mode="{"tun" if r["config"].endswith("tun") else "userspace"}">'
            f'<td class="label">{r["topo"]} / {r["path"]}</td>'
            f'<td class="label" style="color:{CONFIG_COLORS[r["config"]]}">{html.escape(CONFIG_LABELS[r["config"]])}</td>'
            f'<td class="{status_cls}">{status_text}</td>'
            f'<td class="{cls("binary_bytes", r["binary_bytes"])}">{fmt_bytes(r["binary_bytes"])}</td>'
            f'<td class="{cls("rss_peak_kb", r["rss_peak_kb"])}">{fmt_kb(r["rss_peak_kb"])}</td>'
            f'<td class="{cls("rss_avg_kb", r["rss_avg_kb"])}">{fmt_kb(r["rss_avg_kb"])}</td>'
            f'<td class="{cls("cpu_peak_pct", r["cpu_peak_pct"])}">{r["cpu_peak_pct"]:.1f}</td>'
            f'<td class="{cls("cpu_avg_pct", r["cpu_avg_pct"])}">{r["cpu_avg_pct"]:.1f}</td>'
            f'<td>{r["samples"]}</td></tr>'
        )
    out.append("</tbody></table>")
    return "".join(out)


def emit_detail_cards(runs: list) -> str:
    if not runs:
        return '<div class="empty">No runs.</div>'
    parts = ["<div>"]
    for r in runs:
        key = f'{r.get("topology","?")} / {r.get("path","?")} / {r.get("config","?")}'
        cfg = r.get("config", "?")
        topo = r.get("topology", "?")
        path = r.get("path", "?")
        mode = "tun" if cfg.endswith("tun") else "userspace"
        err = r.get("error", "")
        card_class = "detail-card detail-row"
        if err:
            card_class += " has-error"
        parts.append(
            f'<details class="{card_class}" data-topo="{topo}" data-path="{path}" '
            f'data-config="{cfg}" data-mode="{mode}">'
            f"<summary>{html.escape(key)}</summary>"
        )
        if err:
            parts.append(
                f'<div class="error-box">'
                f'<div class="label">FAILED</div>'
                f'<div class="reason">{html.escape(err)}</div>'
                f"</div>"
            )
        parts.append(f"<pre>{html.escape(json.dumps(r, indent=2))}</pre>")
        log_tail = r.get("log_tail", "")
        if log_tail:
            parts.append(
                '<details class="log-tail"><summary>log tail '
                f"({log_tail.count(chr(10))+1} lines)</summary>"
                f"<pre>{html.escape(log_tail)}</pre></details>"
            )
        parts.append("</details>")
    parts.append("</div>")
    return "".join(parts)


def emit_failed_runs(runs: list) -> str:
    """Emit a red banner listing all runs with a non-empty error field."""
    failed = [r for r in runs if r.get("error")]
    if not failed:
        return ""
    parts = [
        '<section class="block" id="failed-runs">',
        '<div class="failed-banner">',
        f"<h2>⚠ {len(failed)} failed run{'s' if len(failed) != 1 else ''}</h2>",
        f'<div class="count">{len(failed)} of {len(runs)} cells returned an error — '
        "zeros below are stubs, not measurements.</div>",
        '<table class="failed-runs">',
        "<thead><tr><th>topology / path</th><th>config</th><th>error</th>"
        "<th>log tail</th></tr></thead><tbody>",
    ]
    for r in failed:
        key = f'{r.get("topology","?")} / {r.get("path","?")}'
        cfg = r.get("config", "?")
        err = r.get("error", "?")
        log_tail = r.get("log_tail", "")
        if log_tail:
            log_cell = (
                f'<details><summary>show last {log_tail.count(chr(10))+1} lines</summary>'
                f"<pre>{html.escape(log_tail)}</pre></details>"
            )
        else:
            log_cell = '<span class="empty" style="padding:0">(none)</span>'
        parts.append(
            f"<tr>"
            f'<td>{html.escape(key)}</td>'
            f'<td style="color:{CONFIG_COLORS.get(cfg, "#fff")}">{html.escape(CONFIG_LABELS.get(cfg, cfg))}</td>'
            f'<td class="error">{html.escape(err)}</td>'
            f"<td>{log_cell}</td>"
            f"</tr>"
        )
    parts.append("</tbody></table></div></section>")
    return "".join(parts)


def emit_header(runs: list) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    n = len(runs)
    n_failed = sum(1 for r in runs if r.get("error"))
    n_missing = 16 - n  # 2 topos × 2 paths × 4 configs
    tool_versions = {}
    for r in runs:
        tool_versions[r.get("tool", "?")] = r.get("version", "?")
    ver_str = " · ".join(f"{k} {v}" for k, v in sorted(tool_versions.items())) or "no runs"
    fail_str = ""
    if n_failed:
        fail_str = f' · <span style="color:var(--bad)">{n_failed} FAILED</span>'
    miss_str = f" · {n_missing} missing" if n_missing > 0 else ""
    return (
        f'<header class="app">'
        f"<h1>rustscale GCP bench dashboard</h1>"
        f'<div class="meta">{n} runs{fail_str}{miss_str} · generated {stamp} · {html.escape(ver_str)}</div>'
        f"</header>"
    )


def emit_filters() -> str:
    return """<div class="filters" id="filters">
  <div class="group">
    <label>topology</label>
    <button data-filter="topo" data-value="all" class="active">all</button>
    <button data-filter="topo" data-value="same-zone">same-zone</button>
    <button data-filter="topo" data-value="cross-region">cross-region</button>
  </div>
  <div class="group">
    <label>path</label>
    <button data-filter="path" data-value="all" class="active">all</button>
    <button data-filter="path" data-value="direct">direct</button>
    <button data-filter="path" data-value="derp">derp</button>
  </div>
  <div class="group">
    <label>mode</label>
    <button data-filter="mode" data-value="all" class="active">all</button>
    <button data-filter="mode" data-value="userspace">userspace</button>
    <button data-filter="mode" data-value="tun">TUN</button>
  </div>
  <div class="group theme-toggle">
    <button id="theme-toggle">☾ dark</button>
  </div>
</div>"""


# Hand-rolled canvas grouped bar chart renderer.
CHART_JS = r"""
<script>
// drawGroupedBars(canvas, data, kind)
//   kind: "throughput" | "latency"
//   throughput data: { title, parallels: [1,10,25,50,100], series: {config: [mbps,...]} }
//   latency    data: { combos: ["topo/path", ...], series: {config: [{p50,p95,p99}, ...]} }
const CONFIG_COLORS = {
  "rs-userspace": "#3b82f6",
  "rs-tun": "#22c55e",
  "ts-userspace": "#f97316",
  "ts-tun": "#ef4444"
};
const LAT_COLORS = { p50: "#3b82f6", p95: "#f59e0b", p99: "#ef4444" };
const CONFIGS = ["rs-userspace","rs-tun","ts-userspace","ts-tun"];

function drawGroupedBars(canvas, data, kind) {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth, cssH = canvas.clientHeight;
  canvas.width = cssW * dpr; canvas.height = cssH * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  const cs = getComputedStyle(document.documentElement);
  const fg = cs.getPropertyValue("--fg").trim() || "#e4e7eb";
  const fgDim = cs.getPropertyValue("--fg-dim").trim() || "#9aa4b2";
  const grid = cs.getPropertyValue("--grid").trim() || "#232a35";

  const padL = 56, padR = 14, padT = 14, padB = 38;
  const plotW = cssW - padL - padR, plotH = cssH - padT - padB;

  // Build groups + series.
  let groups, series, colorFor;
  if (kind === "throughput") {
    groups = data.parallels.map(String);
    series = CONFIGS.map(c => ({
      key: c,
      vals: data.series[c] || [],
      color: CONFIG_COLORS[c],
      failed: (data.failed && data.failed[c]) || false
    }));
    colorFor = (i) => series[i].color;
  } else {
    groups = data.combos;
    series = [
      { key: "p50", vals: [], color: LAT_COLORS.p50, field: "p50" },
      { key: "p95", vals: [], color: LAT_COLORS.p95, field: "p95" },
      { key: "p99", vals: [], color: LAT_COLORS.p99, field: "p99" }
    ];
    // Fill each series from each config? No — latency chart groups by config,
    // not by combo. Re-interpret: one cluster per combo, 3 bars (p50/p95/p99)
    // summed across configs? Simpler: cluster per config, 3 bars per cluster,
    // averaged across combos. We'll cluster per config with p50/p95/p99 from
    // the first combo, OR cluster per combo with 3 bars. Use per-combo cluster.
    // series already set to 3 pct series. For each combo, take the mean across
    // configs of each percentile.
    series = series.map(s => {
      s.vals = groups.map((_, gi) => {
        const vals = CONFIGS.map(c => {
          const arr = (data.series[c] || []);
          const row = arr[gi] || {};
          return row[s.field] || 0;
        });
        // mean across configs
        return vals.reduce((a,b)=>a+b,0) / (vals.length||1);
      });
      return s;
    });
    colorFor = (i) => series[i].color;
  }

  const nGroups = groups.length, nSeries = series.length;
  const groupW = plotW / nGroups;
  const barW = (groupW * 0.78) / nSeries;
  const gap = (groupW * 0.22) / (nSeries + 1);

  // Y scale.
  let maxVal = 0;
  series.forEach(s => s.vals.forEach(v => { if (v > maxVal) maxVal = v; }));
  if (maxVal === 0) maxVal = 1;
  const yMax = niceMax(maxVal);
  const yScale = plotH / yMax;

  // Grid + Y ticks.
  ctx.strokeStyle = grid; ctx.fillStyle = fgDim;
  ctx.font = "11px sans-serif"; ctx.textAlign = "right"; ctx.textBaseline = "middle";
  const yTicks = niceTicks(yMax, 5);
  yTicks.forEach(t => {
    const y = padT + plotH - t * yScale;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + plotW, y); ctx.stroke();
    ctx.fillText(fmtNum(t), padL - 8, y);
  });

  // Bars.
  series.forEach((s, si) => {
    if (s.failed) {
      // Draw a red marker at the baseline instead of bars, so failed
      // configs are visually distinct from real zero-throughput runs.
      ctx.fillStyle = "rgba(239,68,68,0.20)";
      s.vals.forEach((v, gi) => {
        const x = padL + gi * groupW + gap + si * barW;
        ctx.fillRect(x, padT + plotH - 3, barW * 0.92, 3);
      });
      ctx.save();
      ctx.fillStyle = "rgba(239,68,68,0.8)";
      ctx.font = "9px sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "bottom";
      s.vals.forEach((v, gi) => {
        const x = padL + gi * groupW + gap + si * barW + barW * 0.46;
        ctx.fillText("\u2715", x, padT + plotH - 5);
      });
      ctx.restore();
      return;
    }
    ctx.fillStyle = s.color;
    s.vals.forEach((v, gi) => {
      const x = padL + gi * groupW + gap + si * barW;
      const h = v * yScale;
      const y = padT + plotH - h;
      ctx.fillRect(x, y, barW * 0.92, h);
    });
  });

  // X labels.
  ctx.fillStyle = fgDim; ctx.textAlign = "center"; ctx.textBaseline = "top";
  ctx.font = "11px sans-serif";
  groups.forEach((g, gi) => {
    const x = padL + gi * groupW + groupW / 2;
    ctx.fillText(String(g), x, padT + plotH + 8);
  });

  // Y axis label.
  ctx.save();
  ctx.translate(14, padT + plotH / 2); ctx.rotate(-Math.PI / 2);
  ctx.textAlign = "center"; ctx.textBaseline = "middle";
  ctx.fillStyle = fgDim;
  ctx.fillText(kind === "throughput" ? "Mbps" : "µs", 0, 0);
  ctx.restore();
}

function niceMax(v) {
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / exp;
  let m;
  if (n <= 1) m = 1; else if (n <= 2) m = 2; else if (n <= 5) m = 5; else m = 10;
  return m * exp;
}
function niceTicks(maxV, count) {
  const step = maxV / count;
  const exp = Math.pow(10, Math.floor(Math.log10(step)));
  const n = step / exp;
  let m;
  if (n <= 1) m = 1; else if (n <= 2) m = 2; else if (n <= 5) m = 5; else m = 10;
  const niceStep = m * exp;
  const ticks = [];
  for (let t = 0; t <= maxV + 1e-9; t += niceStep) ticks.push(t);
  return ticks;
}
function fmtNum(v) {
  if (v >= 1000) return (v / 1000).toFixed(v >= 10000 ? 0 : 1) + "k";
  if (v >= 100) return v.toFixed(0);
  if (v >= 10) return v.toFixed(0);
  return v.toFixed(1);
}

// Re-draw on resize + theme change.
function redrawAll() {
  document.querySelectorAll("canvas").forEach(c => {
    const kind = c.id.startsWith("latency") ? "latency" : "throughput";
    // Re-fetch data from the global registry populated at render time.
    const data = window.__chartData && window.__chartData[c.id];
    if (data) drawGroupedBars(c, data, kind);
  });
}
window.addEventListener("resize", () => { clearTimeout(window.__rzT); window.__rzT = setTimeout(redrawAll, 120); });

// Filters + theme toggle.
function applyFilters() {
  const f = window.__filters || { topo: "all", path: "all", mode: "all" };
  document.querySelectorAll(".throughput-card").forEach(card => {
    const okT = f.topo === "all" || card.dataset.topo === f.topo;
    const okP = f.path === "all" || card.dataset.path === f.path;
    card.classList.toggle("hidden", !(okT && okP));
  });
  document.querySelectorAll(".footprint-row, .detail-row").forEach(row => {
    const okT = f.topo === "all" || row.dataset.topo === f.topo;
    const okP = f.path === "all" || row.dataset.path === f.path;
    const okM = f.mode === "all" || row.dataset.mode === f.mode;
    row.classList.toggle("hidden", !(okT && okP && okM));
  });
}
function initFilters() {
  window.__filters = { topo: "all", path: "all", mode: "all" };
  document.querySelectorAll("#filters button[data-filter]").forEach(btn => {
    btn.addEventListener("click", () => {
      const f = btn.dataset.filter, v = btn.dataset.value;
      window.__filters[f] = v;
      document.querySelectorAll(`#filters button[data-filter="${f}"]`).forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      applyFilters();
    });
  });
  document.getElementById("theme-toggle").addEventListener("click", () => {
    const html = document.documentElement;
    const cur = html.getAttribute("data-theme") || "dark";
    const next = cur === "dark" ? "light" : "dark";
    html.setAttribute("data-theme", next);
    document.getElementById("theme-toggle").textContent = next === "dark" ? "☾ dark" : "☀ light";
    redrawAll();
  });
}
document.addEventListener("DOMContentLoaded", () => { initFilters(); applyFilters(); redrawAll(); });
</script>
"""


def emit_chart_data_registry(runs_idx: dict) -> str:
    """Emit a <script> registering chart data on window.__chartData for redraw."""
    entries = {}
    for topo in TOPOLOGIES:
        for path in PATHS:
            cid = f"tp-{topo}-{path}"
            entries[cid] = throughput_chart_data(runs_idx, topo, path)
    entries["latency-chart"] = latency_chart_data(runs_idx)
    return f'<script>window.__chartData = {json.dumps(entries)};</script>'


def main() -> int:
    runs = load_summary()
    if not isinstance(runs, list):
        runs = []
    runs_idx = index_runs(runs)

    out = []
    out.append(HTML_HEAD)
    out.append(emit_header(runs))
    out.append("<main>")
    out.append(emit_filters())

    # Failed-runs banner (only if any runs have errors).
    out.append(emit_failed_runs(runs))

    # Throughput.
    out.append('<section class="block" id="throughput">')
    out.append("<h2>Throughput — iperf3 TCP sweep (30s, download)</h2>")
    out.append(emit_throughput_charts(runs_idx))
    out.append("</section>")

    # Latency.
    out.append('<section class="block" id="latency">')
    out.append("<h2>Latency — ping-pong p50 / p95 / p99</h2>")
    out.append(emit_latency_chart(runs_idx))
    out.append("</section>")

    # Footprint.
    out.append('<section class="block" id="footprint">')
    out.append("<h2>Footprint — binary size, RSS, CPU (green = best in group)</h2>")
    out.append(emit_footprint_table(runs_idx))
    out.append("</section>")

    # Detail cards.
    out.append('<section class="block" id="details">')
    out.append("<h2>Per-run detail (raw JSON)</h2>")
    out.append(emit_detail_cards(runs))
    out.append("</section>")

    out.append("</main>")
    # Chart data registry must come before CHART_JS so redraw can find it.
    out.append(emit_chart_data_registry(runs_idx))
    out.append(CHART_JS)
    out.append(HTML_FOOT)

    sys.stdout.write("".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
