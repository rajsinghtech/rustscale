#!/usr/bin/env python3
"""Hermetic regression fixtures for strict GCP benchmark collection."""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GCP = ROOT / "tools/bench/gcp"
PARALLELS = [1, 10, 100]


def run(*args, ok=True, env=None):
    result = subprocess.run(args, text=True, capture_output=True, env=env)
    if ok:
        assert result.returncode == 0, result.stderr
    return result


def matrix(root, *, repeat=2, parallelism=PARALLELS, include_parallelism=True, dry_run=False):
    data = {"schema_version": 1, "topologies": ["same-zone"], "paths": ["direct"],
            "configs": ["rs-tun"], "repeat": repeat, "dry_run": dry_run}
    if include_parallelism:
        data["parallelism"] = parallelism
    (root / "matrix.json").write_text(json.dumps(data))


def valid(*, repeat=2, config="rs-tun", path="direct", parallels=PARALLELS):
    rows = []
    for parallel in parallels:
        rows.append({"parallel": parallel, "mbps": 100.0 + parallel,
                     "duration_s": 10, "samples_mbps": [99.0 + parallel, 101.0 + parallel],
                     "statistic": "median"})
    return {"schema_version": 2, "status": "ok", "tool": "rustscale", "mode": "tun",
            "topology": "same-zone", "path": path, "config": config, "repeat": repeat,
            "parallelism_requested": list(parallels), "error": "", "log_tail": "",
            "throughput": rows, "latency": {"requested": 50, "transmitted": 50, "received": 50,
                                                "loss": 0, "p50_us": 10, "p95_us": 20, "p99_us": 30, "count": 50},
            "footprint": {"binary_size_bytes": 1, "rss_peak_kb": 2, "rss_avg_kb": 1,
                          "cpu_peak_pct": 0, "cpu_avg_pct": 0, "samples": 1},
            "path_class_reported": path}


def legacy_success():
    obj = valid()
    obj.pop("schema_version"); obj.pop("status"); obj.pop("repeat"); obj.pop("parallelism_requested")
    for row in obj["throughput"]:
        row.pop("samples_mbps"); row.pop("statistic")
    return obj


def legacy_failure():
    obj = legacy_success()
    obj["error"] = "old daemon failure"
    for row in obj["throughput"]:
        row["mbps"] = 0
    obj["latency"] = {"p50_us": 0, "p95_us": 0, "p99_us": 0, "count": 0}
    obj["footprint"] = {"binary_size_bytes": 0, "rss_peak_kb": 0, "rss_avg_kb": 0,
                        "cpu_peak_pct": 0, "cpu_avg_pct": 0, "samples": 0}
    return obj


def write_cell(root, obj, filename="rs-tun.json", *, topo="same-zone", path="direct"):
    destination = root / topo / path / filename
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(obj, allow_nan=True))
    return destination


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp) / "run"; root.mkdir()
    matrix(root); cell = write_cell(root, valid())
    result = run("python3", GCP / "aggregate.py", root)
    manifest = json.loads((root / "matrix.json").read_text())
    assert manifest["parallelism"] == [1, 10, 100]
    assert all(type(value) is int for value in manifest["parallelism"])
    assert len(json.loads(result.stdout)) == 1

    # Matrix repeat and ordered parallelism are exact contracts.
    mismatch = valid(repeat=3); write_cell(root, mismatch)
    assert "expected matrix repeat" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    mismatch = valid(); mismatch["parallelism_requested"] = [100, 10, 1]; write_cell(root, mismatch)
    assert "expected matrix parallelism" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    matrix(root, repeat=0)
    assert "repeat must be a positive integer" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    matrix(root)

    statistic = valid(); statistic["throughput"][0]["statistic"] = "mean"; write_cell(root, statistic)
    assert "statistic must be median" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    wrong_median = valid(); wrong_median["throughput"][0]["mbps"] += 1; write_cell(root, wrong_median)
    assert "mbps must equal median" in run("python3", GCP / "aggregate.py", root, ok=False).stderr

    infinite = valid(); infinite["throughput"][0]["samples_mbps"][0] = float("inf"); write_cell(root, infinite)
    assert "finite positive" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    bool_count = valid(); bool_count["latency"]["count"] = True; write_cell(root, bool_count)
    assert "latency count" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    wrong_mode = valid(); wrong_mode["mode"] = "userspace"; write_cell(root, wrong_mode)
    assert "expected 'tun' for rs-tun" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    partial_latency = valid()
    for field in ("requested", "transmitted", "received", "count"):
        partial_latency["latency"][field] = 1
    write_cell(root, partial_latency)
    assert "all 50 requested replies" in run("python3", GCP / "aggregate.py", root, ok=False).stderr

    write_cell(root, valid()); write_cell(root, valid(), "duplicate.json")
    assert "DUPLICATE" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    (root / "same-zone/direct/duplicate.json").unlink()
    cell.unlink()
    assert "MISSING" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    write_cell(root, valid())

    # A fully foreign three-level result cannot hide beside selected cells.
    write_cell(root, {**valid(), "topology": "foreign-topology", "path": "foreign-path", "config": "foreign-config"},
               "foreign-config.json", topo="foreign-topology", path="foreign-path")
    assert "IDENTITY" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    shutil.rmtree(root / "foreign-topology")

    failed = valid(); failed.update({"status": "failed", "error": "daemon never became ready",
                                     "throughput": None, "latency": None, "footprint": None})
    write_cell(root, failed)
    strict = run("python3", GCP / "aggregate.py", root, ok=False)
    assert "FAILED" in strict.stderr
    partial = run("python3", GCP / "aggregate.py", "--allow-partial", root)
    assert json.loads(partial.stdout)[0]["status"] == "failed"
    malformed_failed = dict(failed); malformed_failed["schema_version"] = 1
    write_cell(root, malformed_failed)
    partial = run("python3", GCP / "aggregate.py", "--allow-partial", root)
    summary = root / "summary.json"; summary.write_text(partial.stdout)
    assert "failed cells have no numeric measurements" in run("python3", GCP / "render-html.py", summary).stdout
    cell.write_text("null")
    null_partial = run("python3", GCP / "aggregate.py", "--allow-partial", root)
    summary.write_text(null_partial.stdout)
    assert "No runs." in run("python3", GCP / "render-html.py", summary).stdout

    # Strict aggregation is schema-v2 only.  Partial collection normalizes a
    # real pre-v2 positive success, but turns historical error/zero stubs into
    # an explicit failed/null cell that the renderer will not chart as zero.
    write_cell(root, legacy_success())
    assert "schema_version" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    legacy = run("python3", GCP / "aggregate.py", "--allow-partial", root)
    legacy_rows = json.loads(legacy.stdout)
    assert legacy_rows[0]["legacy"] is True and legacy_rows[0]["status"] == "ok"
    summary.write_text(legacy.stdout)
    legacy_html = run("python3", GCP / "render-html.py", summary).stdout
    assert "LEGACY NORMALIZED" in legacy_html and "PARTIAL — NOT COMPLETE" in legacy_html
    # Old manifests did not serialize parallelism.  That fixed historical
    # default is accepted only while collecting partial/legacy data.
    matrix(root, include_parallelism=False)
    assert "parallelism is required" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    assert json.loads(run("python3", GCP / "aggregate.py", "--allow-partial", root).stdout)[0]["legacy"] is True
    matrix(root)
    write_cell(root, legacy_failure())
    legacy_failed = run("python3", GCP / "aggregate.py", "--allow-partial", root)
    normalized = json.loads(legacy_failed.stdout)[0]
    assert normalized["status"] == "failed" and normalized["throughput"] is None
    summary.write_text(legacy_failed.stdout)
    assert "failed cells have no numeric measurements" in run("python3", GCP / "render-html.py", summary).stdout

    # collect.sh preserves prior artifacts if rendering fails, records the
    # failure in its atomically replaced index, and does not trip set -e.
    collect_root = Path(tmp) / "collect"; run_dir = collect_root / "gcp-20260101-000000"
    run_dir.mkdir(parents=True); matrix(run_dir); write_cell(run_dir, legacy_success())
    collected = run("bash", GCP / "collect.sh", collect_root)
    index = (collect_root / "gcp-index.html").read_text()
    # A safely normalized historical success is still partial provenance, not
    # a green current-schema result in either the row or aggregate metadata.
    assert "PARTIAL" in index and "LEGACY NORMALIZED" in index
    assert "legacy-normalized cell(s)" in index
    assert 'class="ok">rendered' not in index
    (run_dir / "summary.json").write_text("old summary")
    (run_dir / "dashboard.html").write_text("old dashboard")
    bad_renderer = Path(tmp) / "bad-render.py"; bad_renderer.write_text("import sys; sys.exit(7)\n")
    env = {**os.environ, "RENDER": str(bad_renderer)}
    collected = run("bash", GCP / "collect.sh", collect_root, env=env)
    assert "gcp-index.html" in collected.stdout
    assert (run_dir / "summary.json").read_text() == "old summary"
    assert (run_dir / "dashboard.html").read_text() == "old dashboard"
    assert "render-failed" in (collect_root / "gcp-index.html").read_text()

print("strict benchmark fixtures: OK")
