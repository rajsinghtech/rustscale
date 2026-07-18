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


def run_identity():
    return {"id": "gcp-20260714-010203-fixture", "started_at_utc": "2026-07-14T01:02:03Z",
            "source": {"commit": "a" * 40, "delivery": "git-archive-head",
                       "includes_uncommitted_changes": False, "launch_worktree_dirty": False},
            "cloud": {"provider": "gcp", "project": "fixture-project", "requested_image_project": "ubuntu-os-cloud",
                      "requested_image_family": "ubuntu-2204-lts", "requested_machine_type": "n1-standard-4",
                      "network": "default", "disk_type": "pd-standard", "disk_gb": 200},
            "build": {"command": "cargo build --release", "rustflags": "", "cargo_profile_release_lto": "", "cargo_profile_release_codegen_units": "",
                      "go_command": "go build", "go_toolchain": "go1.26.4",
                      "go_toolchain_archive": "go1.26.4.linux-amd64.tar.gz",
                      "go_toolchain_archive_sha256": "1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f",
                      "go_module": "tailscale.com", "go_module_version": "v1.100.0",
                      "go_module_sum": "h1:nm/M/dEaW9RaRsGUjW2HsSDpsZ60Jwd9k4gNW9tTFiE="},
            "runtime": {"rs_tun_inbound_pipeline": False, "rs_tun_outbound_send_pipeline": False, "linux_udp_batch": True, "linux_udp_gro": True, "linux_udp_gso": True}}


def observed(include_bench=True):
    server = {"zone": "us-central1-a", "machine_type": "n1-standard-4", "cpu_platform": "Intel Skylake",
                "cpu_model": "Intel(R) Xeon", "logical_cpus": 4, "kernel_release": "6.8.0", "os_pretty_name": "Ubuntu 22.04"}
    client = {**server, "zone": "us-central1-b"}
    products = [{"path": "/opt/rustscale/target/release/rustscale", "version": "rustscale 1.2.0", "version_source": "executable --version", "sha256": "b" * 64},
                {"path": "/opt/rustscale/target/release/rustscaled", "version": "rustscaled 1.2.0", "version_source": "executable --version", "sha256": "c" * 64}]
    if include_bench:
        products.append({"path": "/opt/rustscale/target/release/rustscale-bench", "version": "rustscale-bench 1.2.0", "version_source": "executable --version", "sha256": "f" * 64})
    return {"resolved_image": "https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/ubuntu-2204-immutable",
            "server": server, "client": client,
            "toolchain": {"server_cargo": "cargo 1.80", "server_rustc_verbose": "rustc 1.80\ncommit-hash: 'abc'",
                          "client_cargo": "cargo 1.80", "client_rustc_verbose": "rustc 1.80\ncommit-hash: 'abc'",
                          "server_go": "go version go1.26.4 linux/amd64", "client_go": "go version go1.26.4 linux/amd64"},
            "measurement_tools": {"server": [{"path": "/usr/bin/ncat", "version": "Ncat 7.80", "sha256": "1" * 64}],
                                  "client": [{"path": "/usr/bin/ncat", "version": "Ncat 7.80", "sha256": "1" * 64}]},
            "product": {"server": [dict(item) for item in products], "client": [dict(item) for item in products]}}


def matrix(root, *, repeat=2, parallelism=PARALLELS, include_parallelism=True, dry_run=False, configs=None, identity=None):
    data = {"schema_version": 2, "topologies": ["same-zone"], "paths": ["direct"],
            "configs": configs or ["rs-tun"], "repeat": repeat, "dry_run": dry_run,
            "warmup": {"parallel": 1, "duration_s": 3, "reverse": True}, "run": identity or run_identity()}
    if include_parallelism:
        data["parallelism"] = parallelism
    (root / "matrix.json").write_text(json.dumps(data))


def valid(*, repeat=2, config="rs-tun", path="direct", parallels=PARALLELS, identity=None):
    rows = []
    for parallel in parallels:
        rows.append({"parallel": parallel, "mbps": 100.0 + parallel,
                     "duration_s": 10, "samples_mbps": [99.0 + parallel, 101.0 + parallel],
                     "statistic": "median"})
    return {"schema_version": 3, "status": "ok", "tool": "rustscale", "mode": "tun",
            "topology": "same-zone", "path": path, "config": config, "repeat": repeat,
            "parallelism_requested": list(parallels), "error": "", "log_tail": "",
            "throughput": rows, "latency": {"requested": 50, "transmitted": 50, "received": 50,
                                                "loss": 0, "p50_us": 10, "p95_us": 20, "p99_us": 30, "count": 50},
            "footprint": {"binary_size_bytes": 1, "rss_peak_kb": 2, "rss_avg_kb": 1,
                          "cpu_peak_pct": 0, "cpu_avg_pct": 0, "samples": 1,
                          "sample_cadence_s": 1,
                          "series": [{"elapsed_s": 1, "rss_kb": 2, "cpu_pct": 0}],
                          "series_truncated": False},
            "path_class_reported": path, "run": identity or run_identity(), "observed": observed(False)}


def valid_ts_tun():
    obj = valid(config="ts-tun")
    obj["tool"] = "tailscaled"
    products = [{"path": "/usr/sbin/tailscaled", "version": "1.2.0", "version_source": "executable --version", "sha256": "d" * 64},
                {"path": "/usr/bin/tailscale", "version": "1.2.0", "version_source": "executable --version", "sha256": "e" * 64},
                {"path": "/opt/rustscale/target/release/rustscale-bench", "version": "rustscale-bench 1.2.0", "version_source": "executable --version", "sha256": "f" * 64}]
    obj["observed"]["product"] = {"server": [dict(item) for item in products], "client": [dict(item) for item in products]}
    return obj


def matched_manifest(root, identity):
    configs = ["rs-userspace", "rs-tun", "ts-embedded", "ts-userspace", "ts-tun"]
    modes = {"rs-userspace": "embedded", "rs-tun": "tun", "ts-embedded": "embedded",
             "ts-userspace": "daemon-proxy", "ts-tun": "tun"}
    data = {"schema_version": 4, "topologies": ["same-zone"], "paths": ["direct"],
            "configs": configs, "parallelism": [1], "repeat": 1, "duration_s": 10,
            "sample_cadence_s": 1, "peer_count_requested": 1, "dry_run": False,
            "warmup": {"parallel": 1, "duration_s": 3, "direction": "down", "protocol": "RSB1"},
            "selection": {"preset": "normal-v1", "source": {"topologies": "default", "paths": "default", "configs": "default"},
                          "cells": [{"id": config, "implementation": "rustscale" if config.startswith("rs-") else "tailscale",
                                     "mode": modes[config]} for config in configs]},
            "load": {"preset": "custom", "parallelism_target": [1], "repeat": 1, "duration_s": 10,
                     "sample_cadence_s": 1, "peer_load": {"requested": 1, "effective": None,
                                                            "observed": None, "status": "not-applied"}},
            "run": identity}
    (root / "matrix.json").write_text(json.dumps(data, indent=2) + "\n")
    return data


def matched_result(root, config, manifest):
    import hashlib
    modes = {"rs-userspace": "embedded", "rs-tun": "tun", "ts-embedded": "embedded",
             "ts-userspace": "daemon-proxy", "ts-tun": "tun"}
    mode = modes[config]
    implementation = "rustscale" if config.startswith("rs-") else "tailscale"
    tool = {"rs-userspace": "rustscale", "rs-tun": "rustscale", "ts-embedded": "go-tsnet-rsb1",
            "ts-userspace": "tailscaled", "ts-tun": "tailscaled"}[config]
    transport = "userspace-tsnet" if config in {"rs-userspace", "ts-embedded"} else "kernel-tcp"
    subject_map = {
        "rs-userspace": (["rustscale-bench"], ["rustscale-bench"]),
        "rs-tun": (["rustscaled", "rustscale-bench"], ["rustscaled", "rustscale-bench"]),
        "ts-embedded": (["go-tsnet-rsb1"], ["go-tsnet-rsb1"]),
        "ts-userspace": (["tailscaled", "rustscale-bench"], ["tailscaled", "ncat", "rustscale-bench"]),
        "ts-tun": (["tailscaled", "rustscale-bench"], ["tailscaled", "rustscale-bench"]),
    }
    transport_path = {"rs-userspace": "embedded-rust-tsnet", "rs-tun": "kernel-tcp-via-rustscaled-tun",
                      "ts-embedded": "embedded-go-tsnet",
                      "ts-userspace": "kernel-tcp-via-loopback-ncat-socks5-tailscaled-serve",
                      "ts-tun": "kernel-tcp-via-tailscaled-tun"}[config]
    primary_subject = {"rs-userspace": "rustscale-bench", "rs-tun": "rustscaled", "ts-embedded": "go-tsnet-rsb1",
                       "ts-userspace": "tailscaled", "ts-tun": "tailscaled"}[config]
    if config.startswith("ts-"):
        obs = valid_ts_tun()["observed"]
        if config == "ts-embedded":
            products = [{"path": "/opt/rustscale/bin/go-tsnet-rsb1",
                         "version": "go-tsnet-rsb1 tailscale.com/v1.100.0",
                         "version_source": "executable --version", "sha256": "9" * 64}]
            obs["product"] = {"server": products, "client": products}
        elif config == "ts-userspace":
            allowed = {"tailscaled", "tailscale", "rustscale-bench"}
            obs["product"] = {endpoint: [item for item in obs["product"][endpoint]
                                          if Path(item["path"]).name in allowed] for endpoint in ("server", "client")}
    else:
        obs = observed()
        allowed = {"rustscale-bench"} if config == "rs-userspace" else {"rustscale", "rustscaled", "rustscale-bench"}
        obs["product"] = {endpoint: [item for item in obs["product"][endpoint]
                                      if Path(item["path"]).name in allowed] for endpoint in ("server", "client")}
    scope = {"kind": "dynamic_process_set", "includes_descendants": False, "includes_kernel": False}
    def identity(endpoint, subject):
        candidates = list(obs["product"][endpoint]) + list(obs.get("measurement_tools", {}).get(endpoint, []))
        return next(item for item in candidates if Path(item["path"]).name == subject)
    def resource(endpoint, subjects):
        return {"endpoint": endpoint, "subjects": subjects, "scope": scope,
                "binary_identities": [identity(endpoint, subject) for subject in subjects],
                "rss_peak_kb": 2, "rss_avg_kb": 1, "cpu_peak_pct": 1, "cpu_avg_pct": 0.5,
                "samples": 2, "missing_samples": 0, "sample_cadence_s": 1, "clock": "monotonic",
                "series": [{"offset_ms": 0, "rss_kb": 1, "cpu_pct": 0,
                            "included_processes": [f"{index + 1}:{subject}" for index, subject in enumerate(subjects)], "status": "observed"},
                           {"offset_ms": 1000, "rss_kb": 2, "cpu_pct": 1,
                            "included_processes": [f"{index + 1}:{subject}" for index, subject in enumerate(subjects)], "status": "observed"}],
                "series_truncated": False}
    server = resource("server", subject_map[config][0])
    client = resource("client", subject_map[config][1])
    warmup_path = "direct" if config in {"rs-userspace", "ts-embedded"} else "externally-gated"
    raw_latency = list(range(1, 51))
    result = {"schema_version": 6, "status": "ok", "tool": tool, "implementation": implementation,
              "mode": mode, "topology": "same-zone", "path": "direct", "config": config,
              "repeat": 1, "parallelism_requested": [1], "duration_s_requested": 10,
              "sample_cadence_s": 1, "peer_count_requested": 1, "error": "", "log_tail": "",
              "path_class_reported": "direct", "transport": transport,
              "warmup_evidence": {"transport": transport, "protocol": "RSB1", "direction": "down",
                                  "duration_secs": 3, "parallel": 1, "established": 1,
                                  "handshaken": 1, "completed": 1, "total_mbps": 10.0,
                                  "path_class": warmup_path},
              "throughput": [{"parallel": 1, "mbps": 100.0, "duration_s": 10,
                              "samples_mbps": [100.0], "statistic": "median",
                              "min_mbps": 100.0, "max_mbps": 100.0,
                              "population_stddev_mbps": 0.0,
                              "coefficient_of_variation_pct": 0.0}],
              "throughput_trials": [{"parallel": 1, "repeat_index": 1, "transport": transport,
                                     "protocol": "RSB1", "direction": "down", "duration_s": 10,
                                     "established": 1, "handshaken": 1, "completed": 1,
                                     "total_mbps": 100.0, "path_class": warmup_path}],
              "latency": {"protocol": "RSB1-tcp-pingpong", "requested": 50, "successful": 50,
                          "timed_out": 0, "malformed": 0, "count": 50, "min_ns": 1,
                          "max_ns": 50, "mean_ns": 25.5, "p50_ns": 26, "p95_ns": 48, "p99_ns": 50,
                          "min_us": .001, "max_us": .05, "mean_us": .0255,
                          "p50_us": .026, "p95_us": .048, "p99_us": .05, "samples_ns": raw_latency},
              "workload": {"implementation": "go-tsnet-rsb1" if config == "ts-embedded" else "rustscale-bench",
                           "protocol": "RSB1", "direction": "down", "payload_bytes": 1280,
                           "warmup": {"parallel": 1, "duration_s": 3, "max_attempts": 1},
                           "client_lifecycle": "new_benchmark_process_per_trial",
                           "transport_identity_lifecycle": "one_persisted_identity_per_endpoint_cell",
                           "measured_trial_attempts": 1, "latency_protocol": "RSB1-tcp-pingpong",
                           "latency_payload_bytes": 8, "latency_count": 50, "transport_path": transport_path,
                           "userspace_portmapping": {"rs-userspace": "disabled", "ts-embedded": "upstream-default"}.get(config, "not-applicable")},
              "resources": {"phase_set": ["measured_client_process_lifecycle", "inter_trial_gap", "latency"],
                            "sample_cadence_ms": 1000, "server": server, "client": client},
              "footprint": dict(server, binary_size_bytes=1, subject=primary_subject),
              "binary": dict(identity("server", primary_subject), subject=primary_subject, size_bytes=1),
              "path_gate": {"requested": "direct", "pre": "direct", "post": "direct", "matched": True},
              "cleanup": {"status": "clean", "samplers_stopped": True, "workload_stopped": True,
                          "transport_stopped": True, "postconditions_verified": True},
              "identity": {"key": f"same-zone/direct/{config}", "cell_id": config,
                           "implementation": implementation, "mode": mode, "topology": "same-zone", "path": "direct"},
              "load": {"preset": "custom", "parallelism_requested": [1], "repeat": 1, "duration_s": 10,
                       "peer_load": manifest["load"]["peer_load"]},
              "manifest_sha256": hashlib.sha256((root / "matrix.json").read_bytes()).hexdigest(),
              "run": manifest["run"], "observed": obs}
    return result


def legacy_success():
    obj = valid()
    obj.pop("schema_version"); obj.pop("status"); obj.pop("repeat"); obj.pop("parallelism_requested"); obj.pop("run"); obj.pop("observed")
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
    root = Path(tmp) / run_identity()["id"]; root.mkdir()
    matrix(root); cell = write_cell(root, valid())
    result = run("python3", GCP / "aggregate.py", root)
    manifest = json.loads((root / "matrix.json").read_text())
    assert manifest["parallelism"] == [1, 10, 100]
    assert all(type(value) is int for value in manifest["parallelism"])
    assert len(json.loads(result.stdout)) == 1

    # A current schema-v4 run is one self-contained five-cell matched envelope.
    matched_identity = run_identity(); matched_identity["id"] = "gcp-20260714-010203-matched"
    matched_root = Path(tmp) / matched_identity["id"]; matched_root.mkdir()
    matched = matched_manifest(matched_root, matched_identity)
    for config in matched["configs"]:
        write_cell(matched_root, matched_result(matched_root, config, matched), f"{config}.json")
    matched_summary = run("python3", GCP / "aggregate.py", matched_root)
    envelope = json.loads(matched_summary.stdout)
    assert envelope["summary_schema_version"] == 1
    assert envelope["completeness"] == {"expected": 5, "ok": 5, "failed": 0, "missing": 0,
                                          "complete": True, "normal_complete": True}
    assert [cell["config"] for cell in envelope["cells"]] == ["rs-userspace", "ts-embedded", "ts-userspace", "rs-tun", "ts-tun"]
    moved_summary = Path(tmp) / "moved-summary.json"; moved_summary.write_text(matched_summary.stdout)
    moved_html = run("python3", GCP / "render-html.py", moved_summary).stdout
    assert "Matched five-cell RSB1 workload" in moved_html and "requested peer load" in moved_html
    assert "RustScale embedded tsnet" in moved_html and "Go embedded tsnet" in moved_html
    assert "tailscaled daemon proxy" in moved_html
    assert "Repeat dispersion" in moved_html and "coefficient of variation" in moved_html
    ts_user_path = matched_root / "same-zone/direct/ts-userspace.json"
    original_ts_user = json.loads(ts_user_path.read_text())
    for expected_error, mutate in (
        ("throughput_trials", lambda value: value.__setitem__("throughput_trials", [])),
        ("clean teardown", lambda value: value["cleanup"].__setitem__("status", "failed")),
        ("pre/post path gate", lambda value: value["path_gate"].__setitem__("post", "derp")),
        ("manifest_sha256", lambda value: value.__setitem__("manifest_sha256", "0" * 64)),
        ("repeat dispersion", lambda value: value["throughput"][0].__setitem__("max_mbps", 99.0)),
        ("process-set scope", lambda value: [sample.__setitem__("included_processes", []) for sample in value["resources"]["client"]["series"]]),
    ):
        changed = json.loads(json.dumps(original_ts_user)); mutate(changed); ts_user_path.write_text(json.dumps(changed))
        assert expected_error in run("python3", GCP / "aggregate.py", matched_root, ok=False).stderr
    ts_user_path.write_text(json.dumps(original_ts_user))
    for expected_error, mutate in (
        ("incomplete RSB1 lifecycle", lambda value: value["throughput_trials"][0].__setitem__("completed", 0)),
        ("positive RTT", lambda value: value["latency"]["samples_ns"].__setitem__(0, 0)),
        ("CPU/RSS", lambda value: value["resources"]["client"].__setitem__("cpu_avg_pct", None)),
        ("binary identity", lambda value: value["resources"]["server"].__setitem__("binary_identities", [])),
        ("primary binary identity", lambda value: value["binary"].__setitem__("sha256", "8" * 64)),
    ):
        changed = json.loads(json.dumps(original_ts_user)); mutate(changed); ts_user_path.write_text(json.dumps(changed))
        assert expected_error in run("python3", GCP / "aggregate.py", matched_root, ok=False).stderr
    ts_user_path.write_text(json.dumps(original_ts_user))

    # A full current runtime object must still describe a realizable receive
    # mode. Scalar batch mode cannot claim that GRO was active.
    impossible = Path(tmp) / "impossible-runtime" / run_identity()["id"]; impossible.mkdir(parents=True)
    impossible_identity = run_identity()
    impossible_identity["runtime"] = {"rs_tun_inbound_pipeline": False, "rs_tun_outbound_send_pipeline": False, "linux_udp_batch": False, "linux_udp_gro": True, "linux_udp_gso": True}
    matrix(impossible, identity=impossible_identity)
    assert "linux_udp_gro requires linux_udp_batch" in run("python3", GCP / "provenance.py", "validate", "--manifest", impossible / "matrix.json", ok=False).stderr
    impossible_gso = Path(tmp) / "impossible-gso-runtime" / run_identity()["id"]; impossible_gso.mkdir(parents=True)
    impossible_gso_identity = run_identity()
    impossible_gso_identity["runtime"].update({"linux_udp_batch": False, "linux_udp_gro": False, "linux_udp_gso": True})
    matrix(impossible_gso, identity=impossible_gso_identity)
    assert "linux_udp_gso requires linux_udp_batch" in run("python3", GCP / "provenance.py", "validate", "--manifest", impossible_gso / "matrix.json", ok=False).stderr

    # Historical schema-v2 manifests can omit runtime metadata entirely. They
    # remain readable and aggregate without assigning unrecorded modes, but
    # cannot be used to launch a new paid cell.
    historical = Path(tmp) / "historical" / run_identity()["id"]; historical.mkdir(parents=True)
    historical_identity = run_identity(); historical_identity.pop("runtime")
    matrix(historical, identity=historical_identity)
    historical_cell = write_cell(historical, valid(identity=historical_identity))
    run("python3", GCP / "provenance.py", "validate", "--manifest", historical / "matrix.json")
    run("python3", GCP / "provenance.py", "validate", "--manifest", historical / "matrix.json", "--result", historical_cell)
    historical_summary = run("python3", GCP / "aggregate.py", historical)
    assert len(json.loads(historical_summary.stdout)) == 1

    # The immediately preceding runtime shape recorded only the inbound
    # pipeline flag. It is likewise historical provenance, not an assertion
    # about Linux batch or GRO state.
    legacy_runtime = Path(tmp) / "legacy-runtime" / run_identity()["id"]; legacy_runtime.mkdir(parents=True)
    legacy_runtime_identity = run_identity()
    legacy_runtime_identity["runtime"] = {"rs_tun_inbound_pipeline": True}
    matrix(legacy_runtime, identity=legacy_runtime_identity)
    legacy_runtime_cell = write_cell(legacy_runtime, valid(identity=legacy_runtime_identity))
    run("python3", GCP / "provenance.py", "validate", "--manifest", legacy_runtime / "matrix.json")
    run("python3", GCP / "provenance.py", "validate", "--manifest", legacy_runtime / "matrix.json", "--result", legacy_runtime_cell)
    legacy_runtime_summary = run("python3", GCP / "aggregate.py", legacy_runtime)
    assert len(json.loads(legacy_runtime_summary.stdout)) == 1

    # The prior complete receive-mode shape remains readable after the
    # outbound sender and TX-GSO modes were added, but cannot launch a paid
    # cell.
    pre_outbound = Path(tmp) / "pre-outbound" / run_identity()["id"]; pre_outbound.mkdir(parents=True)
    pre_outbound_identity = run_identity()
    pre_outbound_identity["runtime"].pop("rs_tun_outbound_send_pipeline")
    pre_outbound_identity["runtime"].pop("linux_udp_gso")
    matrix(pre_outbound, identity=pre_outbound_identity)
    pre_outbound_cell = write_cell(pre_outbound, valid(identity=pre_outbound_identity))
    run("python3", GCP / "provenance.py", "validate", "--manifest", pre_outbound / "matrix.json", "--result", pre_outbound_cell)
    assert len(json.loads(run("python3", GCP / "aggregate.py", pre_outbound).stdout)) == 1

    # TX-GSO was added independently of the established receive modes. The
    # immediately prior complete runtime object is still historical/readable.
    pre_gso = Path(tmp) / "pre-gso" / run_identity()["id"]; pre_gso.mkdir(parents=True)
    pre_gso_identity = run_identity()
    pre_gso_identity["runtime"].pop("linux_udp_gso")
    matrix(pre_gso, identity=pre_gso_identity)
    pre_gso_cell = write_cell(pre_gso, valid(identity=pre_gso_identity))
    run("python3", GCP / "provenance.py", "validate", "--manifest", pre_gso / "matrix.json", "--result", pre_gso_cell)
    assert len(json.loads(run("python3", GCP / "aggregate.py", pre_gso).stdout)) == 1

    gso_off = Path(tmp) / "gso-off" / run_identity()["id"]; gso_off.mkdir(parents=True)
    gso_off_identity = run_identity(); gso_off_identity["runtime"]["linux_udp_gso"] = False
    matrix(gso_off, identity=gso_off_identity)
    run("python3", GCP / "provenance.py", "validate", "--manifest", gso_off / "matrix.json")

    # Semantic current-manifest validation rejects impossible timestamps,
    # duplicate sweeps, and any warmup contract drift.
    for mutate in (
        lambda m: m["run"].__setitem__("started_at_utc", "2026-99-99T99:99:99Z"),
        lambda m: m.__setitem__("parallelism", [1, 1]),
        lambda m: m.__setitem__("warmup", {"parallel": 1, "duration_s": 4, "reverse": True}),
    ):
        manifest = json.loads((root / "matrix.json").read_text()); mutate(manifest)
        (root / "matrix.json").write_text(json.dumps(manifest))
        assert run("python3", GCP / "aggregate.py", root, ok=False).returncode == 1
        matrix(root)

    # Matrix repeat and ordered parallelism are exact contracts.
    mismatch = valid(repeat=3); write_cell(root, mismatch)
    assert "expected matrix repeat" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    mismatch = valid(); mismatch["parallelism_requested"] = [100, 10, 1]; write_cell(root, mismatch)
    assert "expected matrix parallelism" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    matrix(root, repeat=0)
    assert "invalid repeat" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
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
    # Schema-v3 history is aggregate-only. Raw-series fields, when present,
    # are not reinterpreted as a modern monotonic process-set contract.
    historical_series = valid(); historical_series["footprint"].pop("series"); historical_series["footprint"].pop("series_truncated"); historical_series["footprint"].pop("sample_cadence_s"); write_cell(root, historical_series)
    run("python3", GCP / "aggregate.py", root)

    write_cell(root, valid()); write_cell(root, valid(), "duplicate.json")
    assert "DUPLICATE" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    (root / "same-zone/direct/duplicate.json").unlink()
    cell.unlink()
    assert "MISSING" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    write_cell(root, valid())

    # Product filtering is config-scoped: TS-only does not need a Rust source
    # tree/product, while rs-only excludes unrelated Tailscale executables.
    base = Path(tmp) / "base-observed.json"; selected = Path(tmp) / "selected-observed.json"
    base.write_text(json.dumps(valid_ts_tun()["observed"]))
    run("python3", GCP / "provenance.py", "select-observed", selected, "--input", base, "--config", "ts-tun", "--topology", "same-zone", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--machine", "n1-standard-4")
    assert {Path(x["path"]).name for x in json.loads(selected.read_text())["product"]["server"]} == {"tailscaled", "tailscale", "rustscale-bench"}
    base.write_text(json.dumps(observed()))
    run("python3", GCP / "provenance.py", "select-observed", selected, "--input", base, "--config", "rs-tun", "--topology", "same-zone", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--machine", "n1-standard-4")
    assert {Path(x["path"]).name for x in json.loads(selected.read_text())["product"]["server"]} == {"rustscale", "rustscaled", "rustscale-bench"}
    assert {x["version_source"] for x in observed()["product"]["server"]} == {"executable --version"}
    go_observed = observed()
    go_entry = {"path": "/opt/rustscale/bin/go-tsnet-rsb1", "version": "go-tsnet-rsb1 tailscale.com/v1.100.0",
                "version_source": "executable --version", "sha256": "9" * 64}
    for endpoint in ("server", "client"):
        go_observed["product"][endpoint].append(go_entry)
    base.write_text(json.dumps(go_observed))
    run("python3", GCP / "provenance.py", "select-observed", selected, "--input", base, "--config", "ts-embedded", "--topology", "same-zone", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--machine", "n1-standard-4")
    assert {Path(x["path"]).name for x in json.loads(selected.read_text())["product"]["server"]} == {"go-tsnet-rsb1"}
    base.write_text(json.dumps(observed()))
    run("python3", GCP / "provenance.py", "select-observed", selected, "--input", base, "--config", "rs-tun", "--topology", "same-zone", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--machine", "n1-standard-4")

    # Machine type is an exact, per-run provenance constraint. Keep the
    # normal fixture on the deterministic n1 default, then prove a supported
    # override is accepted only when both observed endpoints match it.
    n2_root = Path(tmp) / "machine-n2" / run_identity()["id"]; n2_root.mkdir(parents=True)
    n2_identity = run_identity()
    n2_identity["cloud"]["requested_machine_type"] = "n2-standard-4"
    matrix(n2_root, identity=n2_identity)
    n2_observed = observed()
    n2_observed["server"]["machine_type"] = "n2-standard-4"
    n2_observed["client"]["machine_type"] = "n2-standard-4"
    n2_base = Path(tmp) / "n2-observed.json"; n2_selected = Path(tmp) / "n2-selected.json"
    n2_base.write_text(json.dumps(n2_observed))
    run("python3", GCP / "provenance.py", "select-observed", n2_selected, "--input", n2_base, "--config", "rs-tun", "--topology", "same-zone", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--machine", "n2-standard-4")
    run("python3", GCP / "provenance.py", "preflight", "--manifest", n2_root / "matrix.json", "--observed", n2_selected,
        "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "0", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "1")
    wrong_machine = run("python3", GCP / "provenance.py", "select-observed", n2_selected, "--input", n2_base, "--config", "rs-tun", "--topology", "same-zone", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--machine", "n1-standard-4", ok=False)
    assert "observed machine type does not match request" in wrong_machine.stderr

    # Preflight is a paid-work gate, so all runtime modes and selected-cell dimensions are
    # checked before run-config can start a daemon or profile a VM.
    run("python3", GCP / "provenance.py", "preflight", "--manifest", root / "matrix.json", "--observed", selected,
        "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "0", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "1")
    unbound = run("python3", GCP / "provenance.py", "preflight", "--manifest", root / "matrix.json", "--observed", selected,
                  "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", ok=False)
    assert unbound.returncode == 2 and "--rs-tun-inbound-pipeline" in unbound.stderr
    missing_runtime = run("python3", GCP / "provenance.py", "preflight", "--manifest", historical / "matrix.json", "--observed", selected,
                  "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "0", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "1", ok=False)
    assert "complete runtime modes are required" in missing_runtime.stderr
    legacy_runtime_preflight = run("python3", GCP / "provenance.py", "preflight", "--manifest", legacy_runtime / "matrix.json", "--observed", selected,
                  "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "1", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "1", ok=False)
    assert "complete runtime modes are required" in legacy_runtime_preflight.stderr
    pre_outbound_preflight = run("python3", GCP / "provenance.py", "preflight", "--manifest", pre_outbound / "matrix.json", "--observed", selected,
                  "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "0", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "1", ok=False)
    assert "complete runtime modes are required" in pre_outbound_preflight.stderr
    pre_gso_preflight = run("python3", GCP / "provenance.py", "preflight", "--manifest", pre_gso / "matrix.json", "--observed", selected,
                  "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "0", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "1", ok=False)
    assert "complete runtime modes are required" in pre_gso_preflight.stderr
    excluded = run("python3", GCP / "provenance.py", "preflight", "--manifest", root / "matrix.json", "--observed", selected,
                   "--config", "rs-tun", "--topology", "same-zone", "--path", "derp", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "0", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "1", ok=False)
    assert "not selected" in excluded.stderr
    mismatch = run("python3", GCP / "provenance.py", "preflight", "--manifest", root / "matrix.json", "--observed", selected,
                   "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "1", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "1", ok=False)
    assert "runtime modes" in mismatch.stderr
    mismatch = run("python3", GCP / "provenance.py", "preflight", "--manifest", root / "matrix.json", "--observed", selected,
                   "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "0", "--rs-tun-outbound-send-pipeline", "1", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "1", ok=False)
    assert "runtime modes" in mismatch.stderr
    mismatch = run("python3", GCP / "provenance.py", "preflight", "--manifest", root / "matrix.json", "--observed", selected,
                   "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "0", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "0", "--linux-udp-gro", "1", "--linux-udp-gso", "1", ok=False)
    assert "runtime modes" in mismatch.stderr
    mismatch = run("python3", GCP / "provenance.py", "preflight", "--manifest", root / "matrix.json", "--observed", selected,
                   "--config", "rs-tun", "--topology", "same-zone", "--path", "direct", "--server-zone", "us-central1-a", "--client-zone", "us-central1-b", "--rs-tun-inbound-pipeline", "0", "--rs-tun-outbound-send-pipeline", "0", "--linux-udp-batch", "1", "--linux-udp-gro", "1", "--linux-udp-gso", "0", ok=False)
    assert "runtime modes" in mismatch.stderr

    # Two current cells share endpoint environment/toolchain identity but have
    # config-specific product lists. Valid-but-different provenance must be
    # rejected, including when the mutated peer is failed.
    mixed = Path(tmp) / "mixed" / run_identity()["id"]; mixed.mkdir(parents=True)
    matrix(mixed, configs=["rs-tun", "ts-tun"])
    write_cell(mixed, valid())
    write_cell(mixed, valid_ts_tun(), "ts-tun.json")
    mixed_summary = run("python3", GCP / "aggregate.py", mixed).stdout
    assert len(json.loads(mixed_summary)) == 2
    summary_path = mixed / "summary.json"; summary_path.write_text(mixed_summary)
    mixed_html = run("python3", GCP / "render-html.py", summary_path).stdout
    for expected in ("rustscale [/opt/rustscale/target/release/rustscale] rustscale 1.2.0",
                     "rustscaled [/opt/rustscale/target/release/rustscaled] rustscaled 1.2.0",
                     "tailscaled [/usr/sbin/tailscaled] 1.2.0", "tailscale [/usr/bin/tailscale] 1.2.0"):
        assert expected in mixed_html
    assert "CPU and RSS samples over the complete workload" in mixed_html
    assert "Historical/unscoped workload (not parity-ranked)" in mixed_html and "Tailscale iperf3 comparator (not parity-ranked)" in mixed_html
    assert "RustScale RSB1 parity" not in mixed_html
    assert "protocol-scoped, never averaged" in mixed_html
    assert "descriptive only; scope-mismatched values are never ranked" in mixed_html
    assert 'class="best"' not in mixed_html
    assert "1 displayed / 1 retained / 1 total" in mixed_html
    assert 'class="resource-row"' in mixed_html
    assert "not attributed to an individual stream count or peer effect" in mixed_html
    assert "2 KiB" in mixed_html
    summary_path.unlink()
    for mutate in (
        lambda o: o["observed"].__setitem__("resolved_image", "another-image"),
        lambda o: o["observed"]["toolchain"].__setitem__("server_cargo", "cargo different"),
    ):
        changed = valid_ts_tun(); mutate(changed); write_cell(mixed, changed, "ts-tun.json")
        assert "mixed observed identity" in run("python3", GCP / "aggregate.py", mixed, ok=False).stderr
        changed.update({"status":"failed", "error":"fixture failure", "throughput":None, "latency":None, "footprint":None})
        write_cell(mixed, changed, "ts-tun.json")
        assert "mixed observed identity" in run("python3", GCP / "aggregate.py", mixed, ok=False).stderr
    moved = Path(tmp) / "moved-current"; shutil.copytree(mixed, moved)
    assert "basename" in run("python3", GCP / "aggregate.py", moved, ok=False).stderr

    # Current provenance is immutable: strict aggregation rejects each
    # identity/environment/toolchain/product mutation for successes and
    # failures alike.
    mutations = [
        ("run.source.commit", lambda o: o["run"]["source"].__setitem__("commit", "d" * 40)),
        ("run.id", lambda o: o["run"].__setitem__("id", "gcp-20260714-010204-fixture")),
        ("run.started_at_utc", lambda o: o["run"].__setitem__("started_at_utc", "2026-07-14T01:02:04Z")),
        ("cloud.machine", lambda o: o["run"]["cloud"].__setitem__("requested_machine_type", "n2-standard-4")),
        ("runtime.pipeline", lambda o: o["run"]["runtime"].__setitem__("rs_tun_inbound_pipeline", True)),
        ("runtime.outbound_pipeline", lambda o: o["run"]["runtime"].__setitem__("rs_tun_outbound_send_pipeline", True)),
        ("runtime.udp_gso", lambda o: o["run"]["runtime"].__setitem__("linux_udp_gso", False)),
        ("endpoint zone", lambda o: o["observed"]["client"].__setitem__("zone", "us-central1-a")),
        ("endpoint machine", lambda o: o["observed"]["server"].__setitem__("machine_type", "n2-standard-4")),
        ("environment", lambda o: o["observed"]["server"].__setitem__("kernel_release", "")),
        ("toolchain", lambda o: o["observed"]["toolchain"].__setitem__("server_cargo", "")),
        ("product version", lambda o: o["observed"]["product"]["server"][0].__setitem__("version", "")),
        ("product hash", lambda o: o["observed"]["product"]["server"][0].__setitem__("sha256", "not-a-hash")),
    ]
    for name, mutate in mutations:
        changed = valid(); mutate(changed); write_cell(root, changed)
        assert run("python3", GCP / "aggregate.py", root, ok=False).returncode == 1, name
        failed_changed = valid(); failed_changed.update({"status": "failed", "error": "fixture failure", "throughput": None, "latency": None, "footprint": None}); mutate(failed_changed); write_cell(root, failed_changed)
        assert run("python3", GCP / "aggregate.py", root, ok=False).returncode == 1, name
    write_cell(root, valid())

    # Same config across paths must bind one executable identity and one image;
    # valid alternate hashes/versions are not interchangeable provenance.
    identities = Path(tmp) / "identities" / run_identity()["id"]; identities.mkdir(parents=True)
    matrix(identities)
    manifest = json.loads((identities / "matrix.json").read_text()); manifest["paths"] = ["direct", "derp"]
    (identities / "matrix.json").write_text(json.dumps(manifest))
    write_cell(identities, valid(path="direct")); alternate = valid(path="derp")
    alternate["observed"]["product"]["server"][0]["sha256"] = "f" * 64
    write_cell(identities, alternate, "rs-tun.json", path="derp")
    assert "mixed executable identity" in run("python3", GCP / "aggregate.py", identities, ok=False).stderr
    alternate.update({"status":"failed", "error":"fixture failure", "throughput":None, "latency":None, "footprint":None})
    write_cell(identities, alternate, "rs-tun.json", path="derp")
    assert "mixed executable identity" in run("python3", GCP / "aggregate.py", identities, ok=False).stderr
    alternate = valid(path="derp"); alternate["observed"]["resolved_image"] = "different-image"
    write_cell(identities, alternate, "rs-tun.json", path="derp")
    assert "mixed resolved image" in run("python3", GCP / "aggregate.py", identities, ok=False).stderr

    production_sentinel = json.loads((root / "matrix.json").read_text()); production_sentinel["run"]["build"]["rustflags"] = "unavailable"
    (root / "matrix.json").write_text(json.dumps(production_sentinel))
    assert "reserved sentinel" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    matrix(root)

    for mutate in (
        lambda o: o["observed"]["server"].__setitem__("kernel_release", "dry-run"),
        lambda o: o["observed"]["toolchain"].__setitem__("server_cargo", "unavailable"),
        lambda o: o["observed"]["product"]["server"][0].__setitem__("version_source", "dry-run"),
        lambda o: o["observed"].__setitem__("resolved_image", "unavailable"),
    ):
        sentinel = valid(); mutate(sentinel); write_cell(root, sentinel)
        assert "reserved observed sentinel" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
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
    kept = json.loads(partial.stdout)[0]
    assert kept["status"] == "failed" and kept["schema_version"] == 3 and kept["run"] == run_identity() and "observed" in kept and not kept.get("legacy")
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
    assert "invalid parallelism" in run("python3", GCP / "aggregate.py", root, ok=False).stderr
    assert run("python3", GCP / "aggregate.py", "--allow-partial", root, ok=False).returncode == 1
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
    run_dir.mkdir(parents=True)
    (run_dir / "matrix.json").write_text(json.dumps({"schema_version": 1, "topologies": ["same-zone"], "paths": ["direct"], "configs": ["rs-tun"], "repeat": 2, "dry_run": False}))
    write_cell(run_dir, legacy_success())
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
