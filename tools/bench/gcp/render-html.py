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
from pathlib import Path

CONFIGS = ["rs-userspace", "ts-embedded", "ts-userspace", "rs-tun", "ts-tun"]
CONFIG_COLORS = {
    "rs-userspace": "#3b82f6",  # blue
    "ts-embedded": "#a855f7",   # purple
    "ts-userspace": "#f97316",  # orange
    "rs-tun": "#22c55e",        # green
    "ts-tun": "#ef4444",        # red
}
CONFIG_LABELS = {
    "rs-userspace": "RustScale embedded tsnet",
    "ts-embedded": "Go embedded tsnet",
    "ts-userspace": "tailscaled daemon proxy",
    "rs-tun": "RustScale TUN",
    "ts-tun": "tailscaled TUN",
}
TOPOLOGIES = ["same-zone", "cross-region"]
PATHS = ["direct", "derp"]
DEFAULT_MATRIX = {"topologies": TOPOLOGIES, "paths": PATHS, "configs": CONFIGS}


def valid_matrix(data: dict) -> dict | None:
    try:
        if data.get("schema_version") not in (1, 2, 3, 4):
            return None
        matrix = {key: data[key] for key in DEFAULT_MATRIX}
        for key, values in matrix.items():
            if (not isinstance(values, list) or not values or
                    len(values) != len(set(values)) or
                    any(value not in DEFAULT_MATRIX[key] for value in values)):
                return None
        if not isinstance(data.get("dry_run", False), bool):
            return None
        matrix["dry_run"] = data.get("dry_run", False)
        direction = data.get("direction", "down")
        if direction not in {"down", "up", "bidir"}:
            return None
        matrix["direction"] = direction
        for key in ("parallelism", "duration_s", "sample_cadence_s", "peer_count_requested"):
            if key in data: matrix[key] = data[key]
        if data.get("schema_version") in (2, 3) and isinstance(data.get("run"), dict):
            matrix["run"] = data["run"]
        for key in ("selection", "load"):
            if key in data: matrix[key] = data[key]
        return matrix
    except (AttributeError, KeyError, TypeError):
        return None


def load_summary() -> tuple[list, dict]:
    if len(sys.argv) > 1 and sys.argv[1] not in ("-", ""):
        summary = os.path.abspath(sys.argv[1])
        with open(summary, "r", encoding="utf-8") as f:
            payload = json.load(f)
    else:
        payload = json.load(sys.stdin)
        summary = None
    if isinstance(payload, dict) and payload.get("summary_schema_version") == 1:
        matrix = valid_matrix(payload.get("manifest"))
        cells = payload.get("cells")
        if matrix is None or payload["manifest"].get("schema_version") not in (3, 4) or not isinstance(cells, list):
            raise SystemExit("invalid self-contained current benchmark summary")
        matrix["completeness"] = payload.get("completeness", {})
        return cells, matrix
    if not isinstance(payload, list):
        raise SystemExit("summary must be a current envelope or historical result list")
    if summary is not None:
        manifest = os.path.join(os.path.dirname(summary), "matrix.json")
        try:
            with open(manifest, encoding="utf-8") as f:
                data = json.load(f)
            matrix = valid_matrix(data)
            if matrix is not None:
                return payload, matrix
        except (OSError, json.JSONDecodeError):
            pass
    return payload, DEFAULT_MATRIX


def index_runs(runs: list) -> dict:
    """Index runs by (topology, path, config) -> run obj."""
    idx = {}
    for r in runs:
        key = (r.get("topology", "?"), r.get("path", "?"), r.get("config", "?"))
        idx[key] = r
    return idx


def configured_parallels(runs: list) -> list:
    """Return the throughput shape declared by the result data."""
    return sorted({
        int(row["parallel"])
        for run in runs
        for row in (run.get("throughput") or [])
        if "parallel" in row
    })


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


def config_mode(config: str) -> str:
    return {"rs-userspace": "embedded", "ts-embedded": "embedded",
            "ts-userspace": "daemon-proxy", "rs-tun": "tun", "ts-tun": "tun"}.get(config, "historical")


# ---------------------------------------------------------------------------
# Bar-chart data preparation.
# ---------------------------------------------------------------------------
def throughput_chart_data(runs_idx: dict, parallels: list[int], topo: str, path: str, configs: list[str]) -> dict:
    """Return {parallels: [...], series: {config: [mbps per parallel]},
    failed: {config: bool}, errors: {config: str}}."""
    series = {}
    failed = {}
    errors = {}
    for cfg in configs:
        run = runs_idx.get((topo, path, cfg))
        vals = []
        if run:
            err = run.get("error", "")
            if run.get("status") == "failed" or err:
                failed[cfg] = True
                errors[cfg] = err
            tp = {t["parallel"]: t.get("mbps") for t in (run.get("throughput") or [])}
            for p in parallels:
                value = tp.get(p)
                vals.append(float(value) if isinstance(value, (int, float)) else None)
        else:
            failed[cfg] = True
            errors[cfg] = "missing (no JSON)"
            vals = [None] * len(parallels)
        series[cfg] = vals
    return {
        "parallels": parallels,
        "configs": configs,
        "series": series,
        "failed": failed,
        "errors": errors,
    }


def latency_chart_data(runs_idx: dict, matrix: dict) -> dict:
    """One cluster per config/cell; protocols are labeled, never averaged."""
    groups, rows = [], []
    for topo in matrix["topologies"]:
        for path in matrix["paths"]:
            for cfg in matrix["configs"]:
                run = runs_idx.get((topo, path, cfg))
                lat = (run.get("latency") or {}) if run and run.get("status") == "ok" else {}
                protocol = lat.get("protocol") or (run.get("workload") or {}).get("latency_protocol") if run else None
                groups.append(f"{topo}/{path}/{cfg} [{protocol or 'legacy/unscoped'}]")
                rows.append({name: float(lat[name + "_us"]) if isinstance(lat.get(name + "_us"), (int, float)) else None
                             for name in ("p50", "p95", "p99")})
    return {"groups": groups, "rows": rows}


def footprint_rows(runs_idx: dict, matrix: dict) -> list:
    """Return one row per (topo, path, config) with footprint metrics."""
    rows = []
    for topo in matrix["topologies"]:
        for path in matrix["paths"]:
            for cfg in matrix["configs"]:
                run = runs_idx.get((topo, path, cfg))
                if not run:
                    continue
                resources = run.get("resources") if isinstance(run.get("resources"), dict) else None
                endpoints = [(name, resources.get(name) or {}) for name in ("server", "client")] if resources else [("legacy/unscoped", run.get("footprint") or {})]
                for endpoint, foot in endpoints:
                    scope = foot.get("scope") if isinstance(foot.get("scope"), dict) else None
                    subjects = ",".join(foot.get("subjects") or [])
                    identities = foot.get("binary_identities") if isinstance(foot.get("binary_identities"), list) else []
                    identity_label = ",".join(f'{Path(item.get("path", "?")).name}@{str(item.get("sha256", ""))[:12]}' for item in identities if isinstance(item, dict))
                    scope_label = (f'{scope.get("kind")}; subjects={subjects or "unspecified"}; binaries={identity_label or "historical/unspecified"}; descendants={scope.get("includes_descendants")}; kernel={scope.get("includes_kernel")}'
                                   if scope else "legacy/unscoped")
                    primary = run.get("binary") if endpoint == "server" and isinstance(run.get("binary"), dict) else {}
                    rows.append({
                        "topo": topo, "path": path, "config": cfg, "endpoint": endpoint,
                        "scope": scope_label,
                        "error": run.get("error", "") or ("failed" if run.get("status") == "failed" else ""),
                        "binary_bytes": int(primary["size_bytes"]) if isinstance(primary.get("size_bytes"), (int, float)) else (int(foot["binary_size_bytes"]) if isinstance(foot.get("binary_size_bytes"), (int, float)) else None),
                        "rss_peak_kb": int(foot["rss_peak_kb"]) if isinstance(foot.get("rss_peak_kb"), (int, float)) else None,
                        "rss_avg_kb": int(foot["rss_avg_kb"]) if isinstance(foot.get("rss_avg_kb"), (int, float)) else None,
                        "cpu_peak_pct": float(foot["cpu_peak_pct"]) if isinstance(foot.get("cpu_peak_pct"), (int, float)) else None,
                        "cpu_avg_pct": float(foot["cpu_avg_pct"]) if isinstance(foot.get("cpu_avg_pct"), (int, float)) else None,
                        "samples": int(foot["samples"]) if isinstance(foot.get("samples"), (int, float)) else None,
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


def throughput_groups(configs: list[str], runs_idx: dict, topo: str, path: str) -> list[tuple[str, list[str]]]:
    grouped = {}
    for cfg in configs:
        run = runs_idx.get((topo, path, cfg)) or {}
        workload = run.get("workload") if isinstance(run.get("workload"), dict) else {}
        if run.get("schema_version") == 6 and workload.get("implementation") in {"rustscale-bench", "go-tsnet-rsb1"} and workload.get("protocol") == "RSB1":
            label = f"Matched five-cell RSB1 workload ({workload.get('direction', 'down')})"
        elif run.get("schema_version") == 5 and workload.get("implementation") == "rustscale-bench" and workload.get("protocol") == "RSB1":
            label = "Historical matched four-cell RSB1 workload"
        elif workload.get("implementation") == "rustscale-bench" and workload.get("protocol") == "RSB1":
            label = "Historical RustScale RSB1 parity (not merged)"
        elif cfg.startswith("ts-"):
            label = "Tailscale iperf3 comparator (not parity-ranked)"
        else:
            label = "Historical/unscoped workload (not parity-ranked)"
        grouped.setdefault(label, []).append(cfg)
    return list(grouped.items())


def emit_throughput_charts(runs_idx: dict, parallels: list[int], matrix: dict) -> str:
    parts = ['<div class="chart-grid" id="throughput-grid">']
    scripts = []
    for topo in matrix["topologies"]:
        for path in matrix["paths"]:
            for group_index, (group_label, configs) in enumerate(throughput_groups(matrix["configs"], runs_idx, topo, path)):
                cid = f"tp-{topo}-{path}-{group_index}"
                data = throughput_chart_data(runs_idx, parallels, topo, path, configs)
                n_failed = len(data["failed"])
                fail_badge = f'<span class="fail-badge">{n_failed} failed</span>' if n_failed else ""
                card_class = "chart-card throughput-card" + (" has-failures" if n_failed else "")
                parts.append(f"""<div class="{card_class}" data-topo="{topo}" data-path="{path}">
  <h3>{html.escape(topo)} / {html.escape(path)} — {html.escape(group_label)} (Mbps){fail_badge}</h3>
  <canvas id="{cid}"></canvas>
</div>""")
                scripts.append(render_chart_js_block(cid, data, "throughput"))
    parts.append("</div><div class=\"legend\">")
    for cfg in matrix["configs"]:
        parts.append(f'<div class="item"><span class="swatch" style="background:{CONFIG_COLORS[cfg]}"></span>{html.escape(CONFIG_LABELS[cfg])}</div>')
    parts.append("</div>")
    return "".join(parts) + "".join(scripts)


def emit_repeat_dispersion(runs_idx: dict, matrix: dict) -> str:
    rows = []
    for topo in matrix["topologies"]:
        for path in matrix["paths"]:
            for config in matrix["configs"]:
                run = runs_idx.get((topo, path, config)) or {}
                if run.get("status") != "ok" or run.get("error"):
                    continue
                for point in run.get("throughput") or []:
                    samples = point.get("samples_mbps")
                    if isinstance(samples, list) and samples:
                        rows.append((topo, path, config, point))
    if not rows:
        return '<div class="empty">No repeat-dispersion data.</div>'
    out = [
        '<table class="footprint" id="repeat-dispersion-table">',
        '<thead><tr><th class="label">topology / path</th><th class="label">cell</th>',
        '<th>streams</th><th>repeats</th><th>samples Mbps</th><th>median</th>',
        '<th>min</th><th>max</th><th>population σ</th><th>CV %</th></tr></thead><tbody>',
    ]
    for topo, path, config, point in rows:
        samples = point["samples_mbps"]
        sample_text = ", ".join(f"{float(value):.1f}" for value in samples)
        def value(name):
            item = point.get(name)
            return "—" if not isinstance(item, (int, float)) else f"{float(item):.2f}"
        out.append(
            f'<tr class="dispersion-row" data-topo="{html.escape(topo)}" data-path="{html.escape(path)}" '
            f'data-config="{html.escape(config)}" data-mode="{config_mode(config)}">'
            f'<td class="label">{html.escape(topo)} / {html.escape(path)}</td>'
            f'<td class="label" style="color:{CONFIG_COLORS[config]}">{html.escape(CONFIG_LABELS[config])}</td>'
            f'<td>{point.get("parallel", "—")}</td><td>{len(samples)}</td>'
            f'<td>{html.escape(sample_text)}</td><td>{value("mbps")}</td>'
            f'<td>{value("min_mbps")}</td><td>{value("max_mbps")}</td>'
            f'<td>{value("population_stddev_mbps")}</td>'
            f'<td>{value("coefficient_of_variation_pct")}</td></tr>'
        )
    out.append('</tbody></table>')
    return "".join(out)


def emit_latency_chart(runs_idx: dict, matrix: dict) -> str:
    data = latency_chart_data(runs_idx, matrix)
    parts = [
        '<div class="chart-card">',
        '  <h3>Latency p50 / p95 / p99 (µs) — per config; protocol-scoped, never averaged</h3>',
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


def emit_footprint_table(runs_idx: dict, matrix: dict) -> str:
    rows = footprint_rows(runs_idx, matrix)
    if not rows:
        return '<div class="empty">No footprint data.</div>'
    # Scope-dependent footprint values are descriptive only; never rank them.
    out = [
        '<table class="footprint" id="footprint-table">',
        '<thead><tr><th class="label">topology / path</th><th class="label">config</th>'
        '<th>endpoint</th><th>process scope</th><th>status</th>',
        '<th>binary size</th><th>RSS peak</th><th>RSS avg</th>',
        '<th>CPU peak %</th><th>CPU avg %</th><th>samples</th></tr></thead>',
        '<tbody>',
    ]
    for r in rows:
        def cls(metric, val):
            return ""
        if r["error"]:
            status_cls = "status-failed"
            status_text = f"FAILED: {html.escape(r['error'])}"
        else:
            status_cls = "status-ok"
            status_text = "OK"
        out.append(
            f'<tr class="footprint-row" data-topo="{r["topo"]}" data-path="{r["path"]}" '
            f'data-config="{r["config"]}" data-mode="{config_mode(r["config"])}">'
            f'<td class="label">{r["topo"]} / {r["path"]}</td>'
            f'<td class="label" style="color:{CONFIG_COLORS[r["config"]]}">{html.escape(CONFIG_LABELS[r["config"]])}</td>'
            f'<td>{html.escape(r["endpoint"])}</td><td>{html.escape(r["scope"])}</td>'
            f'<td class="{status_cls}">{status_text}</td>'
            f'<td>{"—" if r["binary_bytes"] is None else fmt_bytes(r["binary_bytes"])}</td>'
            f'<td>{"—" if r["rss_peak_kb"] is None else fmt_kb(r["rss_peak_kb"])}</td>'
            f'<td>{"—" if r["rss_avg_kb"] is None else fmt_kb(r["rss_avg_kb"])}</td>'
            f'<td>{"—" if r["cpu_peak_pct"] is None else format(r["cpu_peak_pct"], ".1f")}</td>'
            f'<td>{"—" if r["cpu_avg_pct"] is None else format(r["cpu_avg_pct"], ".1f")}</td>'
            f'<td>{"—" if r["samples"] is None else r["samples"]}</td></tr>'
        )
    out.append("</tbody></table>")
    return "".join(out)


def emit_scale_context(matrix: dict) -> str:
    streams = matrix.get("parallelism", [])
    return (
        '<div class="filters">'
        f'<div class="group"><label>streams</label><strong>{html.escape(", ".join(map(str, streams)) or "historical/unspecified")}</strong></div>'
        f'<div class="group"><label>duration</label><strong>{html.escape(str(matrix.get("duration_s", "historical/unspecified")))} s</strong></div>'
        f'<div class="group"><label>requested peer load</label><strong>{html.escape(str(matrix.get("peer_count_requested", "historical/unspecified")))} (not applied or observed)</strong></div>'
        f'<div class="group"><label>resource cadence</label><strong>{html.escape(str(matrix.get("sample_cadence_s", "historical/unspecified")))} s</strong></div>'
        '</div>'
    )


def emit_resource_trends(runs: list) -> str:
    # Bound every cell independently so a long first cell cannot hide all
    # later configurations. Keep endpoints when downsampling.
    per_cell_limit = 200
    cells = []
    for run in runs:
        if run.get("status") != "ok" or run.get("error"):
            continue
        resources = run.get("resources") if isinstance(run.get("resources"), dict) else None
        endpoints = [(name, resources.get(name) or {}) for name in ("server", "client")] if resources else [("legacy/unscoped", run.get("footprint") or {})]
        for endpoint, footprint in endpoints:
            retained = footprint.get("series") or []
            if not retained:
                continue
            if len(retained) <= per_cell_limit:
                displayed = retained
            else:
                indexes = [round(i * (len(retained) - 1) / (per_cell_limit - 1)) for i in range(per_cell_limit)]
                displayed = [retained[i] for i in indexes]
            cells.append((run, endpoint, footprint, displayed))
    if not cells:
        return '<div class="empty">No resource series in this (possibly historical) result set.</div>'
    out = ['<p class="empty">Samples cover the complete ordered workload, including throughput points, gaps, and latency; they are not attributed to an individual stream count or peer effect.</p>',
           '<table class="footprint"><thead><tr><th class="label">cell</th><th>configured peer load</th><th>sample coverage</th><th>elapsed</th><th>CPU %</th><th>RSS</th></tr></thead><tbody>']
    for run, endpoint, footprint, displayed in cells:
        topo, path, config = (run.get("topology", "?"), run.get("path", "?"), run.get("config", "?"))
        mode = config_mode(str(config))
        retained_count = len(footprint.get("series") or [])
        total_count = footprint.get("samples", retained_count)
        truncated = footprint.get("series_truncated") is True
        coverage = f'{len(displayed)} displayed / {retained_count} retained / {total_count} total'
        if truncated:
            coverage += " (source truncated)"
        scope = footprint.get("scope") or {}
        subjects = ",".join(footprint.get("subjects") or [])
        identities = footprint.get("binary_identities") if isinstance(footprint.get("binary_identities"), list) else []
        identity_label = ",".join(f'{Path(item.get("path", "?")).name}@{str(item.get("sha256", ""))[:12]}' for item in identities if isinstance(item, dict))
        scope_label = (f'{scope.get("kind")}; subjects={subjects or "unspecified"}; binaries={identity_label or "historical/unspecified"}; descendants={scope.get("includes_descendants")}; kernel={scope.get("includes_kernel")}'
                       if scope else "legacy/unscoped")
        cell = f'{topo} / {path} / {config} / {endpoint} / {scope_label}'
        for sample in displayed:
            cpu, rss = sample.get("cpu_pct"), sample.get("rss_kb")
            out.append(
                f'<tr class="resource-row" data-topo="{html.escape(str(topo))}" data-path="{html.escape(str(path))}" '
                f'data-config="{html.escape(str(config))}" data-mode="{mode}">'
                f'<td class="label">{html.escape(cell)}</td><td>{html.escape(str(run.get("peer_count_requested", "—")))}</td>'
                f'<td>{html.escape(coverage)}</td><td>{html.escape(str(sample.get("offset_ms", sample.get("elapsed_s", "—"))))} {"ms" if "offset_ms" in sample else "s"}</td>'
                f'<td>{"—" if cpu is None else f"{cpu:.1f}"}</td><td>{"—" if rss is None else fmt_kb(rss)}</td></tr>')
    out.append('</tbody></table>')
    return ''.join(out)


def emit_detail_cards(runs: list) -> str:
    if not runs:
        return '<div class="empty">No runs.</div>'
    parts = ["<div>"]
    for r in runs:
        key = f'{r.get("topology","?")} / {r.get("path","?")} / {r.get("config","?")}'
        cfg = r.get("config", "?")
        topo = r.get("topology", "?")
        path = r.get("path", "?")
        mode = config_mode(cfg)
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
        if r.get("legacy"):
            parts.append(
                '<div class="error-box" style="border-color:var(--warn)">'
                '<div class="label" style="color:var(--warn)">LEGACY NORMALIZED</div>'
                f'<div class="reason">{html.escape(r.get("legacy_note", "historical partial data"))}</div>'
                '</div>'
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
    failed = [r for r in runs if r.get("status") == "failed" or r.get("error")]
    if not failed:
        return ""
    parts = [
        '<section class="block" id="failed-runs">',
        '<div class="failed-banner">',
        f"<h2>⚠ {len(failed)} failed run{'s' if len(failed) != 1 else ''}</h2>",
        f'<div class="count">{len(failed)} of {len(runs)} cells returned an error — '
        "failed cells have no numeric measurements.</div>",
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


def emit_dry_run_notice(matrix: dict) -> str:
    """Make intentionally failed dry-run stubs unmistakable in the dashboard."""
    if not matrix.get("dry_run"):
        return ""
    return (
        '<section class="block"><div class="failed-banner" '
        'style="border-color:var(--warn)">'
        '<h2 style="color:var(--warn)">DRY-RUN — PARTIAL</h2>'
        '<div class="count">No benchmark measurements were taken. Failed/null '
        'cells are intentional dry-run stubs and must not be interpreted as results.</div>'
        '</div></section>'
    )


def observed_product_versions(runs: list) -> list[tuple[str, str, str]]:
    """Return every current-run product identity in deterministic order.

    Observed product lists are config-scoped, so a dashboard must inspect all
    cells rather than borrowing the first cell's filtered list. Keep path and
    version in the key: conflicting executable identities remain visible.
    """
    products = set()
    for run in runs:
        observed = run.get("observed")
        if not isinstance(observed, dict):
            continue
        product = observed.get("product")
        if not isinstance(product, dict):
            continue
        for endpoint in ("server", "client"):
            entries = product.get(endpoint)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path, version = entry.get("path"), entry.get("version")
                if isinstance(path, str) and isinstance(version, str):
                    products.add((Path(path).name, path, version))
    return sorted(products)


def emit_header(runs: list, matrix: dict) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    n = len(runs)
    n_failed = sum(1 for r in runs if r.get("status") == "failed" or r.get("error"))
    n_legacy = sum(1 for r in runs if r.get("legacy"))
    expected = len(matrix["topologies"]) * len(matrix["paths"]) * len(matrix["configs"])
    n_missing = max(0, expected - n)
    tool_versions = {}
    for r in runs:
        tool_versions[r.get("tool", "?")] = r.get("version", "?")
    ver_str = " · ".join(f"{k} {v}" for k, v in sorted(tool_versions.items())) or "no runs"
    fail_str = ""
    if n_failed:
        fail_str = f' · <span style="color:var(--bad)">{n_failed} FAILED</span>'
    miss_str = f" · {n_missing} missing"
    legacy_str = f' · <span style="color:var(--warn)">{n_legacy} LEGACY NORMALIZED</span>' if n_legacy else ''
    dry_run = matrix.get("dry_run", False)
    dry_run_str = ' · <span style="color:var(--warn);font-weight:600">DRY-RUN</span>' if dry_run else ''
    if dry_run:
        partial = ' · <span style="color:var(--warn);font-weight:600">PARTIAL</span>'
    elif n_failed or n_missing or n_legacy:
        partial = ' · <span style="color:var(--warn);font-weight:600">PARTIAL — NOT COMPLETE</span>'
    else:
        partial = ''
    provenance = ""
    run = matrix.get("run")
    if isinstance(run, dict):
        source = run.get("source", {})
        cloud = run.get("cloud", {})
        observed = next((r.get("observed") for r in runs if isinstance(r.get("observed"), dict)), {})
        versions = [f"{name} [{path}] {version}" for name, path, version in observed_product_versions(runs)]
        resolved = observed.get("resolved_image", "pending") if isinstance(observed, dict) else "pending"
        dirty = "dirty launch" if source.get("launch_worktree_dirty") else "clean launch"
        provenance = (f'<div class="meta">run {html.escape(str(run.get("id", "?")))} · '
                      f'{html.escape(str(run.get("started_at_utc", "?")))} · '
                      f'commit {html.escape(str(source.get("commit", ""))[:12])} ({dirty}) · '
                      f'image requested {html.escape(str(cloud.get("requested_image_family", "?")))} / resolved {html.escape(str(resolved))} · '
                      f'machine {html.escape(str(cloud.get("requested_machine_type", "?")))} · '
                      f'{html.escape(" | ".join(dict.fromkeys(versions)) or "tool versions pending")}</div>')
    return (
        f'<header class="app">'
        f"<h1>rustscale GCP bench dashboard</h1>"
        f'<div class="meta">{n} runs{fail_str}{miss_str}{legacy_str}{dry_run_str}{partial} · generated {stamp} · {html.escape(ver_str)}</div>{provenance}'
        f"</header>"
    )


def emit_filters(matrix: dict) -> str:
    buttons = lambda field, values: ''.join(
        f'<button data-filter="{field}" data-value="{v}">{html.escape(v)}</button>' for v in values)
    return f'''<div class="filters" id="filters">
  <div class="group">
    <label>topology</label>
    <button data-filter="topo" data-value="all" class="active">all</button>
    {buttons("topo", matrix["topologies"])}
  </div>
  <div class="group">
    <label>path</label>
    <button data-filter="path" data-value="all" class="active">all</button>
    {buttons("path", matrix["paths"])}
  </div>
  <div class="group">
    <label>mode</label>
    <button data-filter="mode" data-value="all" class="active">all</button>
    <button data-filter="mode" data-value="embedded">embedded</button>
    <button data-filter="mode" data-value="daemon-proxy">daemon proxy</button>
    <button data-filter="mode" data-value="tun">TUN</button>
  </div>
  <div class="group theme-toggle">
    <button id="theme-toggle">☾ dark</button>
  </div>
</div>'''


# Hand-rolled canvas grouped bar chart renderer.
CHART_JS = r"""
<script>
// drawGroupedBars(canvas, data, kind)
//   kind: "throughput" | "latency"
//   throughput data: { title, parallels: [1,10,25,50,100], series: {config: [mbps,...]} }
//   latency    data: { combos: ["topo/path", ...], series: {config: [{p50,p95,p99}, ...]} }
const CONFIG_COLORS = {
  "rs-userspace": "#3b82f6",
  "ts-embedded": "#a855f7",
  "ts-userspace": "#f97316",
  "rs-tun": "#22c55e",
  "ts-tun": "#ef4444"
};
const LAT_COLORS = { p50: "#3b82f6", p95: "#f59e0b", p99: "#ef4444" };
const CONFIGS = ["rs-userspace","ts-embedded","ts-userspace","rs-tun","ts-tun"];

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
    series = (data.configs || CONFIGS).map(c => ({
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
    groups = data.groups;
    series = series.map(s => {
      s.vals = data.rows.map(row => row[s.field]);
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
  series.forEach(s => s.vals.forEach(v => { if (v != null && v > maxVal) maxVal = v; }));
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
      if (v == null) return;
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
  document.querySelectorAll(".dispersion-row, .footprint-row, .resource-row, .detail-row").forEach(row => {
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


def emit_chart_data_registry(runs_idx: dict, parallels: list[int], matrix: dict) -> str:
    """Emit a <script> registering chart data on window.__chartData for redraw."""
    entries = {}
    for topo in matrix["topologies"]:
        for path in matrix["paths"]:
            for group_index, (_, configs) in enumerate(throughput_groups(matrix["configs"], runs_idx, topo, path)):
                cid = f"tp-{topo}-{path}-{group_index}"
                entries[cid] = throughput_chart_data(runs_idx, parallels, topo, path, configs)
    entries["latency-chart"] = latency_chart_data(runs_idx, matrix)
    return f'<script>window.__chartData = {json.dumps(entries)};</script>'


def main() -> int:
    runs, matrix = load_summary()
    if not isinstance(runs, list):
        runs = []
    runs_idx = index_runs(runs)
    parallels = matrix.get("parallelism") or configured_parallels(runs)

    out = []
    out.append(HTML_HEAD)
    out.append(emit_header(runs, matrix))
    out.append("<main>")
    out.append(emit_filters(matrix))

    out.append(emit_dry_run_notice(matrix))
    out.append(emit_scale_context(matrix))

    # Failed-runs banner (only if any runs have errors).
    out.append(emit_failed_runs(runs))

    # Throughput.
    out.append('<section class="block" id="throughput">')
    out.append("<h2>Throughput — per-configuration TCP workload (download)</h2>")
    out.append(emit_throughput_charts(runs_idx, parallels, matrix))
    out.append("<h2>Repeat dispersion</h2>")
    out.append('<p class="empty">Every successful current cell retains each repeat and reports min/max, population standard deviation, and coefficient of variation; medians alone are not treated as stability evidence.</p>')
    out.append(emit_repeat_dispersion(runs_idx, matrix))
    out.append("</section>")

    # Latency.
    out.append('<section class="block" id="latency">')
    out.append("<h2>Latency — ping-pong p50 / p95 / p99</h2>")
    out.append(emit_latency_chart(runs_idx, matrix))
    out.append("</section>")

    # Footprint.
    out.append('<section class="block" id="footprint">')
    out.append("<h2>Footprint — descriptive only; scope-mismatched values are never ranked</h2>")
    out.append(emit_footprint_table(runs_idx, matrix))
    out.append("</section>")

    out.append('<section class="block" id="resource-trends">')
    out.append("<h2>CPU and RSS samples over the complete workload (successful cells only)</h2>")
    out.append(emit_resource_trends(runs))
    out.append("</section>")

    # Detail cards.
    out.append('<section class="block" id="details">')
    out.append("<h2>Per-run detail (raw JSON)</h2>")
    out.append(emit_detail_cards(runs))
    out.append("</section>")

    out.append("</main>")
    # Chart data registry must come before CHART_JS so redraw can find it.
    out.append(emit_chart_data_registry(runs_idx, parallels, matrix))
    out.append(CHART_JS)
    out.append(HTML_FOOT)

    sys.stdout.write("".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
