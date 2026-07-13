#!/usr/bin/env python3
"""Dependency-free focused regression fixture for matrix manifests."""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GCP = ROOT / "tools/bench/gcp"


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True)


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp) / "gcp-focused"
    source = GCP / "samples/stub-runs/same-zone/direct"
    dest = root / "same-zone/direct"
    dest.mkdir(parents=True)
    for cfg in ("rs-tun", "ts-tun"):
        shutil.copy(source / f"{cfg}.json", dest / f"{cfg}.json")
    # Keep rs-tun in the historical row shape while enriching ts-tun.  The
    # aggregate/dashboard path must accept both during the additive rollout.
    ts_tun = dest / "ts-tun.json"
    enriched = json.loads(ts_tun.read_text())
    for row in enriched["throughput"]:
        value = row["mbps"]
        row.update({"samples_mbps": [value - 1, value, value + 1],
                    "statistic": "median"})
    ts_tun.write_text(json.dumps(enriched))
    (root / "matrix.json").write_text(json.dumps({"schema_version": 1,
        "topologies": ["same-zone"], "paths": ["direct"],
        "configs": ["rs-tun", "ts-tun"], "repeat": 3,
        "warmup": {"parallel": 1, "duration_s": 3, "reverse": True}}))
    aggregate = run("python3", GCP / "aggregate.py", root)
    assert "MISSING" not in aggregate.stderr
    results = json.loads(aggregate.stdout)
    assert len(results) == 2 and [r["config"] for r in results] == ["rs-tun", "ts-tun"]
    assert results[1]["throughput"][0]["statistic"] == "median"
    summary = root / "summary.json"; summary.write_text(aggregate.stdout)
    html = run("python3", GCP / "render-html.py", summary).stdout
    assert "2 runs" in html and "0 missing" in html
    assert 'data-value="cross-region"' not in html
    assert "tp-cross-region" not in html and "tp-same-zone-derp" not in html
    (root / "matrix.json").unlink()
    assert run("python3", GCP / "aggregate.py", root).stderr.count("MISSING") == 14
    (root / "matrix.json").write_text(json.dumps({"schema_version": 1,
        "topologies": ["same-zone", "same-zone"], "paths": ["direct"],
        "configs": ["rs-tun", "unknown"]}))
    invalid = run("python3", GCP / "aggregate.py", root)
    assert "invalid" in invalid.stderr and invalid.stderr.count("MISSING") == 14
    summary.write_text(invalid.stdout)
    assert 'data-value="cross-region"' in run("python3", GCP / "render-html.py", summary).stdout
    (root / "matrix.json").write_text(json.dumps({"schema_version": 1,
        "topologies": ["same-zone"], "paths": ["direct"],
        "configs": ["rs-tun", "ts-tun"]}))
    (dest / "ts-tun.json").unlink()
    assert run("python3", GCP / "aggregate.py", root).stderr.count("MISSING") == 1

    aborted = Path(tmp) / "collect/gcp-aborted"; aborted.mkdir(parents=True)
    failed = Path(tmp) / "collect/gcp-failed/same-zone/direct"; failed.mkdir(parents=True)
    shutil.copy(source / "rs-tun.json", failed / "rs-tun.json")
    index = run("bash", GCP / "collect.sh", Path(tmp) / "collect")
    content = Path(index.stdout.strip()).read_text()
    assert "gcp-aborted" not in content and "gcp-failed" in content

print("manifest fixtures: OK")
