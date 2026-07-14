#!/usr/bin/env python3
"""Validate and aggregate GCP benchmark cells.

By default this is a fail-closed gate: every cell selected by matrix.json must
occur exactly once and be a valid successful schema-v2 result.  Historical
collection may use --allow-partial; its output retains failed cells explicitly
so render-html.py never mistakes a failure for a measured zero.
"""

import json
import math
import sys
from pathlib import Path

CONFIG_ORDER = {"rs-userspace": 0, "rs-tun": 1, "ts-userspace": 2, "ts-tun": 3}
PATH_ORDER = {"direct": 0, "derp": 1}
TOPO_ORDER = {"same-zone": 0, "cross-region": 1}
DEFAULT_PARALLELISM = [1, 10, 100]
DEFAULT_MATRIX = {"topologies": list(TOPO_ORDER), "paths": list(PATH_ORDER), "configs": list(CONFIG_ORDER),
                  "parallelism": DEFAULT_PARALLELISM}
RESULT_SCHEMA_VERSION = 2
CONFIG_MODE = {"rs-userspace": "userspace", "rs-tun": "tun",
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
    if data.get("schema_version") != 1:
        raise ValueError("unsupported matrix schema_version")
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
    if obj.get("schema_version") != RESULT_SCHEMA_VERSION:
        errors.append(f"schema_version must be {RESULT_SCHEMA_VERSION}")
    if obj.get("status") != "ok":
        errors.append("status must be ok")
    if obj.get("error") != "":
        errors.append("error must be empty")
    for field, expected in zip(("topology", "path", "config"), key):
        if obj.get(field) != expected:
            errors.append(f"{field}={obj.get(field)!r}, expected {expected!r}")
    expected_mode = CONFIG_MODE[config]
    if obj.get("mode") != expected_mode:
        errors.append(f"mode={obj.get('mode')!r}, expected {expected_mode!r} for {config}")
    if obj.get("path_class_reported") != path:
        errors.append(f"path_class_reported={obj.get('path_class_reported')!r}, expected {path!r}")
    repeat = obj.get("repeat")
    if not isinstance(repeat, int) or isinstance(repeat, bool) or repeat <= 0:
        errors.append("repeat must be a positive integer")
        repeat = 0
    elif matrix["repeat"] is not None and repeat != matrix["repeat"]:
        errors.append(f"repeat={repeat!r}, expected matrix repeat {matrix['repeat']!r}")
    requested = obj.get("parallelism_requested")
    if (not isinstance(requested, list) or not requested or any(not isinstance(p, int) or isinstance(p, bool) or p <= 0 for p in requested)
            or len(requested) != len(set(requested))):
        errors.append("parallelism_requested must be a nonempty unique list of positive integers")
        requested = []
    elif requested != matrix["parallelism"]:
        errors.append(f"parallelism_requested={requested!r}, expected matrix parallelism {matrix['parallelism']!r}")
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
        if row.get("statistic") != "median":
            errors.append(f"parallel {parallel}: statistic must be median")
        samples = row.get("samples_mbps")
        if not isinstance(samples, list) or len(samples) != repeat or not all(finite_positive(sample) for sample in samples):
            errors.append(f"parallel {parallel}: samples_mbps must contain {repeat} finite positive samples")
        elif not math.isclose(row.get("mbps"), median(samples), rel_tol=MEDIAN_REL_TOL, abs_tol=MEDIAN_ABS_TOL):
            errors.append(f"parallel {parallel}: mbps must equal median(samples_mbps) within rel={MEDIAN_REL_TOL:g}, abs={MEDIAN_ABS_TOL:g}")
    if len(parallels) != len(set(parallels)) or set(parallels) != set(requested) or len(rows) != len(requested):
        errors.append("throughput must contain each requested parallelism exactly once")
    latency = obj.get("latency")
    if not isinstance(latency, dict) or not positive_int(latency.get("count")):
        errors.append("latency count must be positive")
    else:
        percentiles = [latency.get(name) for name in ("p50_us", "p95_us", "p99_us")]
        if not all(finite_positive(value) for value in percentiles) or percentiles != sorted(percentiles):
            errors.append("latency percentiles must be finite, positive, and ordered")
        if expected_mode == "tun":
            expected = 50
            complete_fields = ("requested", "transmitted", "received", "count")
            if any(latency.get(name) != expected for name in complete_fields):
                errors.append("TUN latency must contain all 50 requested replies")
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
    return errors


def validate_failed(obj: dict, key: tuple[str, str, str], matrix: dict) -> list[str]:
    errors = []
    if obj.get("schema_version") != RESULT_SCHEMA_VERSION:
        errors.append(f"schema_version must be {RESULT_SCHEMA_VERSION}")
    for field, expected in zip(("topology", "path", "config"), key):
        if obj.get(field) != expected:
            errors.append(f"{field}={obj.get(field)!r}, expected {expected!r}")
    if matrix["repeat"] is not None and obj.get("repeat") != matrix["repeat"]:
        errors.append(f"repeat={obj.get('repeat')!r}, expected matrix repeat {matrix['repeat']!r}")
    if obj.get("parallelism_requested") != matrix["parallelism"]:
        errors.append("parallelism_requested must exactly match matrix parallelism")
    if not isinstance(obj.get("error"), str) or not obj["error"]:
        errors.append("failed cell must have an actionable error")
    if any(obj.get(field) is not None for field in ("throughput", "latency", "footprint")):
        errors.append("failed cell measurements must be null")
    return errors


def failed_cell(obj: dict, key: tuple[str, str, str], reason: str) -> dict:
    """Make malformed historical input safe for the partial-only renderer."""
    topo, path, config = key
    return {
        "schema_version": RESULT_SCHEMA_VERSION, "status": "failed",
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
            output.append(failed_cell(obj, key, reason)); continue
        if obj.get("schema_version") != RESULT_SCHEMA_VERSION and allow_partial:
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
        output.append(obj)
    for _, problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    output.sort(key=lambda r: (TOPO_ORDER.get(r["topology"], 99), PATH_ORDER.get(r["path"], 99), CONFIG_ORDER.get(r["config"], 99)))
    json.dump(output if allow_partial or not problems else [], sys.stdout, indent=2)
    sys.stdout.write("\n")
    if problems and not allow_partial:
        return 1
    if problems:
        print("warn: PARTIAL output requested; it is not production benchmark data", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
