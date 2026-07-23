#!/usr/bin/env python3
"""Validate and aggregate GCP benchmark cells.

By default this is a fail-closed gate: every cell selected by matrix.json must
occur exactly once and satisfy the manifest's matching result schema. Historical
collection may use --allow-partial; its output retains failed cells explicitly
so render-html.py never mistakes a failure for a measured zero.
"""

import hashlib
import json
import math
import sys
from pathlib import Path
import provenance

CONFIG_ORDER = {"rs-userspace": 0, "ts-embedded": 1, "ts-userspace": 2, "rs-tun": 3, "ts-tun": 4}
LEGACY_CONFIGS = ["rs-userspace", "rs-tun", "ts-userspace", "ts-tun"]
PATH_ORDER = {"direct": 0, "derp": 1}
TOPO_ORDER = {"same-zone": 0, "cross-region": 1}
DEFAULT_PARALLELISM = [1, 10, 100, 500, 1000]
DEFAULT_MATRIX = {"topologies": list(TOPO_ORDER), "paths": list(PATH_ORDER), "configs": LEGACY_CONFIGS,
                  "parallelism": DEFAULT_PARALLELISM}
RESULT_SCHEMA_VERSION = 6
PRIOR_MATCHED_RESULT_SCHEMA_VERSION = 5
SCOPED_RESULT_SCHEMA_VERSION = 4
HISTORICAL_RESULT_SCHEMA_VERSION = 3
CONFIG_MODE = {"rs-userspace": "embedded", "rs-tun": "tun", "ts-embedded": "embedded",
               "ts-userspace": "daemon-proxy", "ts-tun": "tun"}
LEGACY_CONFIG_MODE = {"rs-userspace": "userspace", "rs-tun": "tun",
                      "ts-userspace": "userspace", "ts-tun": "tun"}
# Results are written by Python JSON and retain full binary64 precision.  This
# tolerance allows only JSON/float round-off, not a materially different value.
MEDIAN_REL_TOL = 1e-12
MEDIAN_ABS_TOL = 1e-9


def positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def selected_matrix(root: Path, allow_partial: bool) -> dict:
    manifest = root / "matrix.json"
    if not manifest.exists():
        if not allow_partial:
            raise ValueError("matrix.json is required for strict aggregation")
        return {**DEFAULT_MATRIX, "repeat": None, "legacy_manifest": True}
    data = json.loads(manifest.read_text())
    if data.get("schema_version") in (2, 3, 4):
        provenance.validate_manifest(data)
        if root.name != data["run"]["id"]:
            raise ValueError("current run directory basename must equal matrix run.id")
        matrix = {key: data[key] for key in ("topologies", "paths", "configs", "parallelism", "repeat", "dry_run", "run")}
        matrix["manifest_schema"] = data["schema_version"]
        matrix["manifest_document"] = data
        matrix["manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        for key in ("duration_s", "sample_cadence_s", "peer_count_requested", "direction", "selection", "load"):
            if key in data: matrix[key] = data[key]
        return matrix
    if data.get("schema_version") != 1 or not allow_partial:
        raise ValueError("matrix schema_version must be 2, 3, or 4 for aggregation")
    matrix = {key: data[key] for key in ("topologies", "paths", "configs")}
    for key, values in matrix.items():
        if (not isinstance(values, list) or not values or len(values) != len(set(values))
                or any(value not in DEFAULT_MATRIX[key] for value in values)):
            raise ValueError(f"invalid {key}")
    if not positive_int(data.get("repeat")):
        raise ValueError("repeat must be a positive integer")
    matrix["repeat"] = data["repeat"]
    # Before matrix manifests carried this field every producer used this
    # fixed list.  Retain that historical collection compatibility only for
    # --allow-partial; a current strict run must declare its exact shape.
    if "parallelism" not in data:
        if not allow_partial:
            raise ValueError("parallelism is required for strict aggregation")
        matrix["parallelism"] = list(DEFAULT_PARALLELISM)
        matrix["legacy_manifest"] = True
    else:
        parallelism = data["parallelism"]
        if (not isinstance(parallelism, list) or not parallelism or
                len(parallelism) != len(set(parallelism)) or
                not all(positive_int(value) for value in parallelism)):
            raise ValueError("invalid parallelism")
        matrix["parallelism"] = parallelism
        matrix["legacy_manifest"] = False
    return matrix


def finite_positive(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def median(values: list[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def validate_ok(obj: dict, key: tuple[str, str, str], matrix: dict) -> list[str]:
    topo, path, config = key
    errors = []
    schema_version = obj.get("schema_version")
    supported_schemas = (HISTORICAL_RESULT_SCHEMA_VERSION, SCOPED_RESULT_SCHEMA_VERSION,
                         PRIOR_MATCHED_RESULT_SCHEMA_VERSION, RESULT_SCHEMA_VERSION)
    if schema_version not in supported_schemas:
        errors.append(f"schema_version must be one of {supported_schemas}")
    current = schema_version == RESULT_SCHEMA_VERSION
    prior_matched = schema_version == PRIOR_MATCHED_RESULT_SCHEMA_VERSION
    scoped = schema_version in (SCOPED_RESULT_SCHEMA_VERSION, PRIOR_MATCHED_RESULT_SCHEMA_VERSION, RESULT_SCHEMA_VERSION)
    if matrix.get("manifest_schema") == 4 and not current:
        errors.append("schema-v4 matched manifests require schema-v6 results")
    if matrix.get("manifest_schema") == 3 and not prior_matched:
        errors.append("schema-v3 matched manifests require schema-v5 results")
    if "run" in matrix:
        if obj.get("run") != matrix["run"]:
            errors.append("result run must exactly equal matrix run")
        try:
            zones = provenance.observed_topology_zones(obj.get("observed"), topo)
            provenance.validate_observed(obj.get("observed"), config, matrix["dry_run"], topo, *zones, matrix["run"]["cloud"]["requested_machine_type"], current=scoped)
        except (ValueError, TypeError) as exc:
            errors.append(str(exc))
    if obj.get("status") != "ok":
        errors.append("status must be ok")
    if obj.get("error") != "":
        errors.append("error must be empty")
    for field, expected in zip(("topology", "path", "config"), key):
        if obj.get(field) != expected:
            errors.append(f"{field}={obj.get(field)!r}, expected {expected!r}")
    expected_mode = CONFIG_MODE[config] if current else LEGACY_CONFIG_MODE.get(config, CONFIG_MODE[config])
    if obj.get("mode") != expected_mode:
        errors.append(f"mode={obj.get('mode')!r}, expected {expected_mode!r} for {config}")
    if obj.get("path_class_reported") != path:
        errors.append(f"path_class_reported={obj.get('path_class_reported')!r}, expected {path!r}")
    repeat = obj.get("repeat")
    if not isinstance(repeat, int) or isinstance(repeat, bool) or repeat <= 0:
        errors.append("repeat must be a positive integer")
        repeat = 0
    elif current and matrix.get("load", {}).get("preset") != "custom" and repeat < 3:
        errors.append("current publishable evidence requires at least three successful repeats")
    elif matrix["repeat"] is not None and repeat != matrix["repeat"]:
        errors.append(f"repeat={repeat!r}, expected matrix repeat {matrix['repeat']!r}")
    requested = obj.get("parallelism_requested")
    if (not isinstance(requested, list) or not requested or any(not isinstance(p, int) or isinstance(p, bool) or p <= 0 for p in requested)
            or len(requested) != len(set(requested))):
        errors.append("parallelism_requested must be a nonempty unique list of positive integers")
        requested = []
    elif requested != matrix["parallelism"]:
        errors.append(f"parallelism_requested={requested!r}, expected matrix parallelism {matrix['parallelism']!r}")
    if "duration_s" in matrix and obj.get("duration_s_requested") != matrix["duration_s"]:
        errors.append("duration_s_requested must exactly match matrix duration_s")
    if "sample_cadence_s" in matrix and obj.get("sample_cadence_s") != matrix["sample_cadence_s"]:
        errors.append("sample_cadence_s must exactly match matrix sample_cadence_s")
    if "peer_count_requested" in matrix and obj.get("peer_count_requested") != matrix["peer_count_requested"]:
        errors.append("peer_count_requested must exactly match matrix peer_count_requested")
    rows = obj.get("throughput")
    if not isinstance(rows, list):
        errors.append("throughput must be a list")
        rows = []
    parallels = []
    for row in rows:
        if not isinstance(row, dict):
            errors.append("throughput row is not an object")
            continue
        parallel = row.get("parallel")
        parallels.append(parallel)
        if not isinstance(parallel, int) or isinstance(parallel, bool) or parallel <= 0:
            errors.append("throughput parallel must be a positive integer")
        if not finite_positive(row.get("mbps")):
            errors.append(f"parallel {parallel}: mbps must be finite and positive")
        if not finite_positive(row.get("duration_s")):
            errors.append(f"parallel {parallel}: duration_s must be positive")
        elif "duration_s" in matrix and row.get("duration_s") != matrix["duration_s"]:
            errors.append(f"parallel {parallel}: duration_s must equal matrix duration_s")
        if row.get("statistic") != "median":
            errors.append(f"parallel {parallel}: statistic must be median")
        samples = row.get("samples_mbps")
        if not isinstance(samples, list) or len(samples) != repeat or not all(finite_positive(sample) for sample in samples):
            errors.append(f"parallel {parallel}: samples_mbps must contain {repeat} finite positive samples")
        else:
            expected_median = median(samples)
            if not math.isclose(row.get("mbps"), expected_median, rel_tol=MEDIAN_REL_TOL, abs_tol=MEDIAN_ABS_TOL):
                errors.append(f"parallel {parallel}: mbps must equal median(samples_mbps) within rel={MEDIAN_REL_TOL:g}, abs={MEDIAN_ABS_TOL:g}")
            if current:
                mean = sum(samples) / len(samples)
                stddev = math.sqrt(sum((sample - mean) ** 2 for sample in samples) / len(samples))
                expected_dispersion = {
                    "min_mbps": min(samples), "max_mbps": max(samples),
                    "population_stddev_mbps": stddev,
                    "coefficient_of_variation_pct": stddev / mean * 100,
                }
                for name, expected_value in expected_dispersion.items():
                    value = row.get(name)
                    if (not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value)
                            or value < 0 or not math.isclose(value, expected_value, rel_tol=MEDIAN_REL_TOL, abs_tol=MEDIAN_ABS_TOL)):
                        errors.append(f"parallel {parallel}: {name} must match repeat dispersion")
    if len(parallels) != len(set(parallels)) or set(parallels) != set(requested) or len(rows) != len(requested):
        errors.append("throughput must contain each requested parallelism exactly once")
    latency = obj.get("latency")
    if not isinstance(latency, dict) or not positive_int(latency.get("count")):
        errors.append("latency count must be positive")
    else:
        percentiles = [latency.get(name) for name in ("p50_us", "p95_us", "p99_us")]
        if not all(finite_positive(value) for value in percentiles) or percentiles != sorted(percentiles):
            errors.append("latency percentiles must be finite, positive, and ordered")
        if scoped:
            expected = 200
            if (latency.get("protocol") != "RSB1-tcp-pingpong" or latency.get("requested") != expected
                    or latency.get("successful") != expected or latency.get("timed_out") != 0
                    or latency.get("malformed") != 0 or latency.get("count") != expected):
                errors.append("scoped latency must contain all 200 RSB1 ping-pong replies")
            raw = latency.get("samples_ns")
            if not isinstance(raw, list) or len(raw) != expected or not all(positive_int(value) for value in raw):
                errors.append("scoped latency samples_ns must contain every positive RTT")
            elif current:
                ordered = sorted(raw)
                percentile = lambda p: ordered[math.floor((len(ordered) - 1) * p + 0.5)]
                expected_ns = {"min_ns": ordered[0], "max_ns": ordered[-1],
                               "p50_ns": percentile(.50), "p95_ns": percentile(.95),
                               "p99_ns": percentile(.99)}
                for name, expected_value in expected_ns.items():
                    if latency.get(name) != expected_value:
                        errors.append(f"latency {name} does not match samples_ns")
                mean_ns = sum(raw) / len(raw)
                if not finite_positive(latency.get("mean_ns")) or not math.isclose(latency["mean_ns"], mean_ns, rel_tol=MEDIAN_REL_TOL, abs_tol=MEDIAN_ABS_TOL):
                    errors.append("latency mean_ns does not match samples_ns")
                for ns_name, us_name in (("min_ns", "min_us"), ("max_ns", "max_us"), ("mean_ns", "mean_us"),
                                         ("p50_ns", "p50_us"), ("p95_ns", "p95_us"), ("p99_ns", "p99_us")):
                    if not finite_positive(latency.get(us_name)) or not finite_positive(latency.get(ns_name)) or not math.isclose(latency[us_name], latency[ns_name] / 1000, rel_tol=MEDIAN_REL_TOL, abs_tol=MEDIAN_ABS_TOL):
                        errors.append(f"latency {us_name} does not match {ns_name}")
        elif expected_mode == "tun":
            expected = 200
            complete_fields = ("requested", "transmitted", "received", "count")
            if any(latency.get(name) != expected for name in complete_fields):
                errors.append("TUN latency must contain all 200 requested replies")
            loss = latency.get("loss")
            if not isinstance(loss, (int, float)) or isinstance(loss, bool) or not math.isfinite(loss) or loss != 0:
                errors.append("TUN latency loss must be zero")
    footprint = obj.get("footprint")
    if not isinstance(footprint, dict):
        errors.append("footprint must be an object")
    else:
        for name in ("binary_size_bytes", "rss_peak_kb", "rss_avg_kb", "samples"):
            if not finite_positive(footprint.get(name)):
                errors.append(f"footprint {name} must be finite and positive")
        for name in ("cpu_peak_pct", "cpu_avg_pct"):
            value = footprint.get(name)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
                errors.append(f"footprint {name} must be finite and nonnegative")
        # Raw monotonic process-set series are a scoped-result contract. Historical
        # schema-v3 cells remain valid aggregate-only records; do not fabricate
        # timing, process scope, or samples when rendering old runs.
        if scoped:
            series = footprint.get("series")
            truncated = footprint.get("series_truncated")
            samples = footprint.get("samples")
            expected_retained = min(samples, 3600) if positive_int(samples) else None
            if not isinstance(series, list) or not series or len(series) > 3600:
                errors.append("footprint series must contain 1..=3600 samples")
            elif expected_retained is not None and len(series) != expected_retained:
                errors.append("footprint series length must equal min(samples, 3600)")
            else:
                elapsed = [sample.get("offset_ms") for sample in series if isinstance(sample, dict)]
                if (len(elapsed) != len(series) or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in elapsed)
                        or elapsed != sorted(elapsed) or len(elapsed) != len(set(elapsed))):
                    errors.append("footprint series offset_ms must be unique and monotonic")
                if footprint.get("clock") != "monotonic": errors.append("scoped footprint clock must be monotonic")
                for sample in series:
                    for name in ("rss_kb", "cpu_pct"):
                        value = sample.get(name) if isinstance(sample, dict) else None
                        if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0):
                            errors.append(f"footprint series {name} must be finite, nonnegative, or null")
                            break
                if footprint.get("sample_cadence_s") != matrix.get("sample_cadence_s", 1):
                    errors.append("footprint sample cadence must match matrix")
            if type(truncated) is not bool:
                errors.append("footprint series_truncated must be boolean")
            elif expected_retained is not None and truncated != (samples > 3600):
                errors.append("footprint series_truncated must equal samples > 3600")
    if current:
        embedded = config in {"rs-userspace", "ts-embedded"}
        expected_transport = "userspace-tsnet" if embedded else "kernel-tcp"
        expected_implementation = "rustscale" if config.startswith("rs-") else "tailscale"
        expected_identity = {"key": f"{topo}/{path}/{config}", "cell_id": config,
                             "implementation": expected_implementation, "mode": CONFIG_MODE[config],
                             "topology": topo, "path": path}
        if obj.get("identity") != expected_identity:
            errors.append("canonical result identity does not match its selected cell")
        if obj.get("manifest_sha256") != matrix.get("manifest_sha256"):
            errors.append("result manifest_sha256 does not match matrix.json")
        load = obj.get("load")
        expected_peer = matrix.get("load", {}).get("peer_load", {"requested": matrix.get("peer_count_requested", 1),
                         "effective": None, "observed": None, "status": "not-applied"})
        if (not isinstance(load, dict) or load.get("preset") != matrix.get("load", {}).get("preset", "custom")
                or load.get("parallelism_requested") != matrix["parallelism"] or load.get("repeat") != matrix["repeat"]
                or load.get("duration_s") != matrix.get("duration_s", 10) or load.get("peer_load") != expected_peer):
            errors.append("result load contract does not match matrix.json")
        expected_tool = {"rs-userspace": "rustscale", "rs-tun": "rustscale", "ts-embedded": "go-tsnet-rsb1",
                         "ts-userspace": "tailscaled", "ts-tun": "tailscaled"}[config]
        expected_subjects = {
            "rs-userspace": {"server": ["rustscale-bench"], "client": ["rustscale-bench"]},
            "rs-tun": {"server": ["rustscaled", "rustscale-bench"], "client": ["rustscaled", "rustscale-bench"]},
            "ts-embedded": {"server": ["go-tsnet-rsb1"], "client": ["go-tsnet-rsb1"]},
            "ts-userspace": {"server": ["tailscaled", "rustscale-bench"], "client": ["tailscaled", "ncat", "rustscale-bench"]},
            "ts-tun": {"server": ["tailscaled", "rustscale-bench"], "client": ["tailscaled", "rustscale-bench"]},
        }[config]
        expected_transport_path = {
            "rs-userspace": "embedded-rust-tsnet",
            "rs-tun": "kernel-tcp-via-rustscaled-tun",
            "ts-embedded": "embedded-go-tsnet",
            "ts-userspace": "kernel-tcp-via-loopback-ncat-socks5-tailscaled-serve",
            "ts-tun": "kernel-tcp-via-tailscaled-tun",
        }[config]
        expected_workload = "go-tsnet-rsb1" if config == "ts-embedded" else "rustscale-bench"
        expected_direction = matrix.get("direction", "down")
        expected_portmapping = {"rs-userspace": "disabled", "ts-embedded": "upstream-default"}.get(config, "not-applicable")
        primary_subject = {"rs-userspace": "rustscale-bench", "rs-tun": "rustscaled", "ts-embedded": "go-tsnet-rsb1",
                           "ts-userspace": "tailscaled", "ts-tun": "tailscaled"}[config]
        if obj.get("transport") != expected_transport:
            errors.append(f"transport must be {expected_transport}")
        if obj.get("implementation") != expected_implementation or obj.get("tool") != expected_tool:
            errors.append("implementation/tool identity does not match config")
        workload = obj.get("workload")
        if (not isinstance(workload, dict) or workload.get("implementation") != expected_workload
                or workload.get("protocol") != "RSB1" or workload.get("direction") != expected_direction
                or workload.get("payload_bytes") != 1280
                or workload.get("warmup") != {"parallel": 1, "duration_s": 3, "max_attempts": 1}
                or workload.get("client_lifecycle") != "new_benchmark_process_per_trial"
                or workload.get("transport_identity_lifecycle") != "one_persisted_identity_per_endpoint_cell"
                or workload.get("measured_trial_attempts") != 1
                or workload.get("latency_protocol") != "RSB1-tcp-pingpong"
                or workload.get("latency_payload_bytes") != 8 or workload.get("latency_count") != 200
                or workload.get("transport_path") != expected_transport_path
                or workload.get("userspace_portmapping") != expected_portmapping):
            errors.append("invalid five-cell matched RSB1 workload identity")
        warmup_evidence = obj.get("warmup_evidence")
        expected_warmup_path = path if embedded else "externally-gated"
        if (not isinstance(warmup_evidence, dict) or warmup_evidence.get("transport") != expected_transport
                or warmup_evidence.get("protocol") != "RSB1" or warmup_evidence.get("direction") != expected_direction
                or warmup_evidence.get("duration_secs") != 3 or warmup_evidence.get("parallel") != 1
                or any(warmup_evidence.get(name) != 1 for name in ("established", "handshaken", "completed"))
                or not finite_positive(warmup_evidence.get("total_mbps"))
                or warmup_evidence.get("path_class") != expected_warmup_path):
            errors.append("warmup evidence must be one complete positive RSB1 P1/3s trial")
        trials = obj.get("throughput_trials")
        expected_trials = [(parallel, index) for parallel in requested for index in range(1, repeat + 1)]
        if not isinstance(trials, list) or len(trials) != len(expected_trials):
            errors.append("throughput_trials must retain every requested repeat")
        else:
            row_samples = {row.get("parallel"): row.get("samples_mbps") for row in rows if isinstance(row, dict)}
            for trial, expected_trial in zip(trials, expected_trials):
                parallel, repeat_index = expected_trial
                expected_trial_path = path if embedded else "externally-gated"
                if (not isinstance(trial, dict) or (trial.get("parallel"), trial.get("repeat_index")) != expected_trial
                        or trial.get("transport") != expected_transport or trial.get("protocol") != "RSB1"
                        or trial.get("direction") != expected_direction or trial.get("duration_s") != matrix.get("duration_s", 10)
                        or any(trial.get(name) != parallel for name in ("established", "handshaken", "completed"))
                        or not finite_positive(trial.get("total_mbps")) or trial.get("path_class") != expected_trial_path):
                    errors.append(f"P{parallel} repeat {repeat_index} has incomplete RSB1 lifecycle evidence")
                    continue
                samples_for_parallel = row_samples.get(parallel)
                if (not isinstance(samples_for_parallel, list) or repeat_index > len(samples_for_parallel)
                        or not math.isclose(trial["total_mbps"], samples_for_parallel[repeat_index - 1], rel_tol=MEDIAN_REL_TOL, abs_tol=MEDIAN_ABS_TOL)):
                    errors.append(f"P{parallel} repeat {repeat_index} does not match samples_mbps")
        path_gate = obj.get("path_gate")
        if path_gate != {"requested": path, "pre": path, "post": path, "matched": True}:
            errors.append("pre/post path gate must match the selected path")
        cleanup = obj.get("cleanup")
        if cleanup != {"status":"clean", "samplers_stopped":True, "workload_stopped":True,
                       "transport_stopped":True, "postconditions_verified":True}:
            errors.append("successful current cell requires verified clean teardown")

        observed = obj.get("observed") if isinstance(obj.get("observed"), dict) else {}
        products = observed.get("product") if isinstance(observed.get("product"), dict) else {}
        measurement_tools = observed.get("measurement_tools") if isinstance(observed.get("measurement_tools"), dict) else {}
        def binary_identity(endpoint, subject):
            candidates = []
            for collection in (products.get(endpoint), measurement_tools.get(endpoint)):
                if isinstance(collection, list): candidates.extend(collection)
            matches = [entry for entry in candidates if isinstance(entry, dict) and Path(entry.get("path", "")).name == subject]
            return matches[0] if len(matches) == 1 else None

        primary = binary_identity("server", primary_subject)
        binary = obj.get("binary")
        if (primary is None or not isinstance(binary, dict) or binary.get("subject") != primary_subject
                or not positive_int(binary.get("size_bytes"))
                or any(binary.get(name) != primary.get(name) for name in primary)):
            errors.append("primary binary identity must match observed server provenance")
        if (not isinstance(footprint, dict) or footprint.get("subject") != primary_subject
                or footprint.get("binary_size_bytes") != (binary.get("size_bytes") if isinstance(binary, dict) else None)
                or footprint.get("scope") != {"kind":"dynamic_process_set","includes_descendants":False,"includes_kernel":False}):
            errors.append("footprint must bind the primary binary and process scope")

        resources = obj.get("resources")
        if (not isinstance(resources, dict) or resources.get("sample_cadence_ms") != 1000
                or resources.get("phase_set") != ["measured_client_process_lifecycle", "inter_trial_gap", "latency"]):
            errors.append("schema-v6 resources must declare the complete common measurement window")
        else:
            for endpoint in ("server", "client"):
                measured = resources.get(endpoint)
                scope = measured.get("scope") if isinstance(measured, dict) else None
                subjects = expected_subjects[endpoint]
                expected_binaries = [binary_identity(endpoint, subject) for subject in subjects]
                series = measured.get("series") if isinstance(measured, dict) else None
                aggregate_valid = (isinstance(measured, dict)
                    and finite_positive(measured.get("rss_peak_kb")) and finite_positive(measured.get("rss_avg_kb"))
                    and isinstance(measured.get("cpu_peak_pct"), (int, float)) and not isinstance(measured.get("cpu_peak_pct"), bool)
                    and math.isfinite(measured["cpu_peak_pct"]) and measured["cpu_peak_pct"] >= 0
                    and isinstance(measured.get("cpu_avg_pct"), (int, float)) and not isinstance(measured.get("cpu_avg_pct"), bool)
                    and math.isfinite(measured["cpu_avg_pct"]) and measured["cpu_avg_pct"] >= 0)
                observed_subjects = {
                    item.rsplit(":", 1)[-1]
                    for sample in series if isinstance(series, list) and isinstance(sample, dict)
                    for item in sample.get("included_processes", []) if isinstance(item, str) and ":" in item
                }
                series_valid = (isinstance(series, list) and bool(series)
                    and any(isinstance(sample, dict) and sample.get("rss_kb") is not None for sample in series)
                    and any(isinstance(sample, dict) and sample.get("cpu_pct") is not None for sample in series)
                    and any(isinstance(sample, dict) and sample.get("included_processes") for sample in series)
                    and set(subjects) <= observed_subjects)
                if (not isinstance(measured, dict) or measured.get("endpoint") != endpoint
                        or measured.get("subjects") != subjects
                        or scope != {"kind":"dynamic_process_set","includes_descendants":False,"includes_kernel":False}
                        or not positive_int(measured.get("samples"))
                        or measured.get("samples", 0) <= measured.get("missing_samples", measured.get("samples", 0))
                        or not aggregate_valid or not series_valid
                        or any(identity is None for identity in expected_binaries)
                        or measured.get("binary_identities") != expected_binaries):
                    errors.append(f"invalid {endpoint} resource process-set scope, CPU/RSS, or binary identity")
    return errors


def validate_failed(obj: dict, key: tuple[str, str, str], matrix: dict) -> list[str]:
    errors = []
    supported_schemas = (HISTORICAL_RESULT_SCHEMA_VERSION, SCOPED_RESULT_SCHEMA_VERSION,
                         PRIOR_MATCHED_RESULT_SCHEMA_VERSION, RESULT_SCHEMA_VERSION)
    if obj.get("schema_version") not in supported_schemas:
        errors.append(f"schema_version must be one of {supported_schemas}")
    if "run" in matrix:
        if obj.get("run") != matrix["run"]:
            errors.append("result run must exactly equal matrix run")
        try:
            zones = provenance.observed_topology_zones(obj.get("observed"), key[0])
            provenance.validate_observed(obj.get("observed"), key[2], matrix["dry_run"], key[0], *zones, matrix["run"]["cloud"]["requested_machine_type"], current=obj.get("schema_version") in (SCOPED_RESULT_SCHEMA_VERSION, PRIOR_MATCHED_RESULT_SCHEMA_VERSION, RESULT_SCHEMA_VERSION))
        except (ValueError, TypeError) as exc:
            errors.append(str(exc))
    for field, expected in zip(("topology", "path", "config"), key):
        if obj.get(field) != expected:
            errors.append(f"{field}={obj.get(field)!r}, expected {expected!r}")
    if matrix["repeat"] is not None and obj.get("repeat") != matrix["repeat"]:
        errors.append(f"repeat={obj.get('repeat')!r}, expected matrix repeat {matrix['repeat']!r}")
    if obj.get("parallelism_requested") != matrix["parallelism"]:
        errors.append("parallelism_requested must exactly match matrix parallelism")
    for result_key, matrix_key in (("duration_s_requested", "duration_s"), ("sample_cadence_s", "sample_cadence_s"), ("peer_count_requested", "peer_count_requested")):
        if matrix_key in matrix and obj.get(result_key) != matrix[matrix_key]:
            errors.append(f"{result_key} must exactly match matrix {matrix_key}")
    if not isinstance(obj.get("error"), str) or not obj["error"]:
        errors.append("failed cell must have an actionable error")
    if any(obj.get(field) is not None for field in ("throughput", "latency", "footprint")):
        errors.append("failed cell measurements must be null")
    return errors


def failed_cell(obj: dict, key: tuple[str, str, str], reason: str) -> dict:
    """Make malformed historical input safe for the partial-only renderer."""
    topo, path, config = key
    return {
        "schema_version": RESULT_SCHEMA_VERSION, "status": "failed", "legacy": True,
        "topology": topo, "path": path, "config": config,
        "error": reason, "log_tail": obj.get("log_tail", "") if isinstance(obj, dict) else "",
        "throughput": None, "latency": None, "footprint": None,
        "path_class_reported": obj.get("path_class_reported", "unknown") if isinstance(obj, dict) else "unknown",
    }


def normalize_legacy_success(obj: dict, key: tuple[str, str, str], matrix: dict) -> tuple[dict | None, str | None]:
    """Normalize only safe pre-v2 successes for historical partial dashboards."""
    if obj.get("status") == "failed" or obj.get("error") or obj.get("schema_version") == RESULT_SCHEMA_VERSION:
        return None, "legacy result is failed or is not a pre-v2 success"
    rows = obj.get("throughput")
    latency = obj.get("latency")
    footprint = obj.get("footprint")
    if not isinstance(rows, list) or not isinstance(latency, dict) or not isinstance(footprint, dict):
        return None, "legacy result lacks successful numeric measurements"
    requested = [row.get("parallel") for row in rows if isinstance(row, dict)]
    if (len(requested) != len(rows) or not requested or len(requested) != len(set(requested)) or
            not all(positive_int(value) for value in requested) or
            (not matrix.get("legacy_manifest") and requested != matrix["parallelism"])):
        return None, "legacy throughput parallelism does not match matrix"
    normalized_rows = []
    for row in rows:
        if (not positive_int(row.get("parallel")) or not finite_positive(row.get("mbps")) or
                not finite_positive(row.get("duration_s"))):
            return None, "legacy throughput contains non-positive or non-finite data"
        # Old successful rows were single measurements.  Preserve their value,
        # while representing it as one explicit median sample for the renderer.
        normalized_rows.append({"parallel": row["parallel"], "mbps": row["mbps"],
                                "duration_s": row["duration_s"], "samples_mbps": [row["mbps"]],
                                "statistic": "median"})
    if (not positive_int(latency.get("count")) or
            not all(finite_positive(latency.get(name)) for name in ("p50_us", "p95_us", "p99_us")) or
            [latency[name] for name in ("p50_us", "p95_us", "p99_us")] != sorted(latency[name] for name in ("p50_us", "p95_us", "p99_us"))):
        return None, "legacy latency is invalid"
    if not all(finite_positive(footprint.get(name)) for name in ("binary_size_bytes", "rss_peak_kb", "rss_avg_kb", "samples")):
        return None, "legacy footprint is invalid"
    if not all(isinstance(footprint.get(name), (int, float)) and not isinstance(footprint.get(name), bool) and math.isfinite(footprint[name]) and footprint[name] >= 0 for name in ("cpu_peak_pct", "cpu_avg_pct")):
        return None, "legacy CPU footprint is invalid"
    topo, path, config = key
    return ({"schema_version": RESULT_SCHEMA_VERSION, "status": "ok", "legacy": True,
             "legacy_note": "normalized pre-v2 single-sample success (partial collection only)",
             "tool": obj.get("tool", "unknown"), "mode": obj.get("mode", "unknown"),
             "topology": topo, "path": path, "config": config, "repeat": 1,
             "parallelism_requested": requested, "error": "", "log_tail": obj.get("log_tail", ""),
             "throughput": normalized_rows, "latency": latency, "footprint": footprint,
             "path_class_reported": obj.get("path_class_reported", path)}, None)


def main() -> int:
    args = sys.argv[1:]
    allow_partial = False
    if args and args[0] == "--allow-partial":
        allow_partial = True; args.pop(0)
    if len(args) != 1:
        print("usage: aggregate.py [--allow-partial] <results_dir>", file=sys.stderr); return 2
    root = Path(args[0])
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr); return 1
    try:
        matrix = selected_matrix(root, allow_partial)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"error: invalid {root / 'matrix.json'}: {exc}", file=sys.stderr); return 1
    selected = [(t, p, c) for t in matrix["topologies"] for p in matrix["paths"] for c in matrix["configs"]]
    found: dict[tuple[str, str, str], list[tuple[Path, object]]] = {key: [] for key in selected}
    problems = []
    for filename in root.glob("*/*/*.json"):
        # Provenance sidecars are intentionally not result cells. They remain
        # under the run directory for auditability and are attached into each
        # result before aggregation.
        if filename.relative_to(root).parts[0] == "metadata":
            continue
        try:
            obj = json.loads(filename.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            problems.append((None, f"MALFORMED {filename}: {exc}")); continue
        if not isinstance(obj, dict):
            problems.append((None, f"MALFORMED {filename}: result is not an object")); continue
        key = (obj.get("topology"), obj.get("path"), obj.get("config"))
        if key in found:
            found[key].append((filename, obj))
        else:
            # Every three-level result-shaped JSON participates in the gate.
            # A fully foreign topology/path/config is just as suspicious as a
            # one-field mismatch and must never be silently ignored.
            problems.append((None, f"IDENTITY {filename}: does not match a selected cell ({key})"))
    output = []
    topology_provenance = {}; config_products = {}; run_image = None
    def check_topology_provenance(key, obj):
        if "run" not in matrix or not isinstance(obj.get("observed"), dict):
            return
        # Per-config product lists intentionally differ. Endpoint image,
        # runtime environment, and toolchain must remain topology-consistent.
        nonlocal run_image
        observed = obj["observed"]
        if run_image is None: run_image = observed.get("resolved_image")
        elif run_image != observed.get("resolved_image"):
            problems.append((key, f"PROVENANCE {'/'.join(key)}: mixed resolved image within run"))
        fingerprint = json.dumps({field: observed.get(field) for field in ("resolved_image", "server", "client", "toolchain", "measurement_tools")}, sort_keys=True, separators=(",", ":"))
        prior = topology_provenance.setdefault(key[0], fingerprint)
        if prior != fingerprint:
            problems.append((key, f"PROVENANCE {'/'.join(key)}: mixed observed identity within topology"))
        product = json.dumps(observed.get("product"), sort_keys=True, separators=(",", ":"))
        prior_product = config_products.setdefault(key[2], product)
        if prior_product != product:
            problems.append((key, f"PROVENANCE {'/'.join(key)}: mixed executable identity for {key[2]}"))
    for key in selected:
        entries = found[key]
        expected = root / key[0] / key[1] / f"{key[2]}.json"
        if not entries:
            problems.append((key, f"MISSING {'/'.join(key)} — no JSON found")); continue
        if len(entries) != 1:
            problems.append((key, f"DUPLICATE {'/'.join(key)} — found {len(entries)} JSON files")); continue
        filename, obj = entries[0]
        if filename != expected:
            problems.append((key, f"IDENTITY {filename}: expected {expected}"))
        if obj.get("status") == "failed":
            reason = obj.get("error")
            if not isinstance(reason, str) or not reason:
                reason = "failed cell has no actionable error"
            failed_errors = validate_failed(obj, key, matrix)
            if failed_errors:
                reason = "; ".join(failed_errors)
                problems.append((key, f"MALFORMED {'/'.join(key)}: {reason}"))
            else:
                problems.append((key, f"FAILED {'/'.join(key)}: {reason}"))
                check_topology_provenance(key, obj)
            if allow_partial and not failed_errors and "run" in matrix:
                output.append(obj)
            else:
                output.append(failed_cell(obj, key, reason))
            continue
        if obj.get("schema_version") not in (HISTORICAL_RESULT_SCHEMA_VERSION, SCOPED_RESULT_SCHEMA_VERSION, PRIOR_MATCHED_RESULT_SCHEMA_VERSION, RESULT_SCHEMA_VERSION) and allow_partial:
            normalized, legacy_error = normalize_legacy_success(obj, key, matrix)
            if normalized is not None:
                output.append(normalized)
                problems.append((key, f"LEGACY {'/'.join(key)}: normalized pre-v2 success for partial collection"))
                continue
            reason = legacy_error or "invalid legacy result"
            problems.append((key, f"MALFORMED {'/'.join(key)}: {reason}"))
            output.append(failed_cell(obj, key, reason))
            continue
        errors = validate_ok(obj, key, matrix)
        if errors:
            reason = "; ".join(errors)
            problems.append((key, f"MALFORMED {'/'.join(key)}: {reason}"))
            output.append(failed_cell(obj, key, reason)); continue
        check_topology_provenance(key, obj)
        output.append(obj)
    for _, problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    output.sort(key=lambda r: (TOPO_ORDER.get(r["topology"], 99), PATH_ORDER.get(r["path"], 99), CONFIG_ORDER.get(r["config"], 99)))
    published = output if allow_partial or not problems else []
    if matrix.get("manifest_schema") in (3, 4):
        ok_count = sum(1 for cell in output if cell.get("status") == "ok" and not cell.get("error"))
        missing_count = sum(1 for key in selected if not found[key])
        summary = {"summary_schema_version": 1, "manifest": matrix["manifest_document"],
                   "completeness": {"expected": len(selected), "ok": ok_count,
                                    "failed": max(0, len(selected) - ok_count - missing_count),
                                    "missing": missing_count, "complete": not problems,
                                    "normal_complete": matrix.get("selection", {}).get("preset") == "normal-v1" and not problems},
                   "cells": published}
        json.dump(summary, sys.stdout, indent=2)
    else:
        json.dump(published, sys.stdout, indent=2)
    sys.stdout.write("\n")
    if problems and not allow_partial:
        return 1
    if problems:
        print("warn: PARTIAL output requested; it is not production benchmark data", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
