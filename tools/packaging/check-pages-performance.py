#!/usr/bin/env python3
"""Verify that Pages performance labels and values match tracked evidence."""

from __future__ import annotations

import hashlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "docs/performance/benchmarks-2026-07-15.json"
PAGE = ROOT / "site/index.html"
PERFORMANCE = ROOT / "PERFORMANCE.md"
USERSPACE = ROOT / "docs/benchmarks.md"
CANONICAL_RUN_ID = "gcp-20260721-080637-4aca6f6c1e"
CANONICAL_SOURCE_COMMIT = "395bf8db6648e67f61bc571e1a755b27cd714e12"
CANONICAL_DIR = ROOT / "docs/performance" / CANONICAL_RUN_ID


def workspace_version() -> str:
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    section = re.search(
        r'^\[workspace\.package\]\s*$(.*?)(?=^\[|\Z)',
        manifest,
        re.MULTILINE | re.DOTALL,
    )
    if section is None:
        raise SystemExit("workspace package section is unavailable")
    match = re.search(r'^version\s*=\s*"([^"]+)"', section.group(1), re.MULTILINE)
    if match is None:
        raise SystemExit("workspace package version is unavailable")
    return match.group(1)


WORKSPACE_VERSION = workspace_version()

HOST_RUN_IDS = {
    "rustscale": "gcp-20260715-085022-076e87bd41",
    "tailscaled": "gcp-20260715-090601-02788a10b4",
}

PANEL_CONTRACTS = {
    "performance": {
        "data-environment": "gcp-host-vm",
        "data-mode": "five-config-rsb1",
        "data-evidence-status": "measured",
        "data-comparison": "matched-evidence-without-winner",
        "data-run": CANONICAL_RUN_ID,
        "data-source-commit": CANONICAL_SOURCE_COMMIT,
        "data-provenance": "docs/performance",
    },
    "container-tun": {
        "data-environment": "container",
        "data-mode": "kernel-tun",
        "data-evidence-status": "not-measured",
        "data-comparison": "none",
        "data-provenance": "none",
    },
    "userspace": {
        "data-environment": "local-host",
        "data-mode": "userspace-netstack",
        "data-evidence-status": "historical",
        "data-comparison": "unmatched",
        "data-provenance": "unrecorded",
        "data-duration-match": "false",
        "data-footprint": "not-recorded",
    },
}

CONTAINER_COMMAND = (
    "docker run --rm --privileged --device /dev/net/tun -e TS_USERSPACE=0 "
    f"-e TS_AUTHKEY=tskey-... ghcr.io/rajsinghtech/rustscale:v{WORKSPACE_VERSION}"
)
USERSPACE_COMMAND = (
    "tools/bench/gcp/run-matrix.sh --repeat 3 --topology same-zone "
    "--path direct --config rs-userspace,ts-userspace"
)


class PerformanceParser(HTMLParser):
    VOID_TAGS = {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }

    def __init__(self) -> None:
        super().__init__()
        self.depth = 0
        self.performance_depth: int | None = None
        self.performance_sections = 0
        self.panels: dict[str, dict[str, object]] = {}
        self.current_panel: dict[str, object] | None = None
        self.current_panel_depth: int | None = None
        self.current_bar: dict[str, object] | None = None
        self.current_bar_depth: int | None = None
        self.current_fact: dict[str, object] | None = None
        self.current_fact_depth: int | None = None
        self.current_command: dict[str, str] | None = None
        self.current_command_depth: int | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if tag not in self.VOID_TAGS:
            self.depth += 1
        classes = values.get("class", "").split()

        if tag == "section" and "performance" in classes:
            if self.performance_depth is not None:
                raise SystemExit("nested Pages performance sections are not allowed")
            self.performance_depth = self.depth
            self.performance_sections += 1
            return
        if self.performance_depth is None:
            return

        if tag == "article" and "performance-panel" in classes:
            if self.current_panel is not None:
                raise SystemExit("nested Pages performance panels are not allowed")
            benchmark = values.get("data-benchmark", "")
            if not benchmark or benchmark in self.panels:
                raise SystemExit(f"invalid or duplicate Pages performance panel {benchmark!r}")
            self.current_panel = {
                "attrs": values,
                "bars": [],
                "charts": [],
                "facts": [],
                "commands": {},
                "links": set(),
                "text": "",
            }
            self.current_panel_depth = self.depth
            return
        if self.current_panel is None:
            return

        if tag == "a":
            links = self.current_panel["links"]
            assert isinstance(links, set)
            links.add(values.get("href", ""))
        if tag == "div" and "chart" in classes:
            charts = self.current_panel["charts"]
            assert isinstance(charts, list)
            charts.append(values)
        if tag == "div" and "bar" in classes:
            if self.current_bar is not None:
                raise SystemExit("nested Pages performance bars are not allowed")
            self.current_bar = {"attrs": values, "text": ""}
            self.current_bar_depth = self.depth
        if tag == "div" and "fact" in classes:
            if self.current_fact is not None:
                raise SystemExit("nested Pages userspace facts are not allowed")
            self.current_fact = {"attrs": values, "text": ""}
            self.current_fact_depth = self.depth
        if tag == "code" and "data-reproduction" in values:
            if self.current_command is not None:
                raise SystemExit("nested Pages reproduction commands are not allowed")
            self.current_command = {
                "benchmark": values["data-reproduction"],
                "text": "",
            }
            self.current_command_depth = self.depth

    def handle_data(self, data: str) -> None:
        if self.current_panel is not None:
            self.current_panel["text"] = str(self.current_panel["text"]) + data
        if self.current_bar is not None:
            self.current_bar["text"] = str(self.current_bar["text"]) + data
        if self.current_fact is not None:
            self.current_fact["text"] = str(self.current_fact["text"]) + data
        if self.current_command is not None:
            self.current_command["text"] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "div" and self.current_bar_depth == self.depth:
            assert self.current_panel is not None and self.current_bar is not None
            self.current_bar["text"] = normalize(str(self.current_bar["text"]))
            bars = self.current_panel["bars"]
            assert isinstance(bars, list)
            bars.append(self.current_bar)
            self.current_bar = None
            self.current_bar_depth = None
        if tag == "div" and self.current_fact_depth == self.depth:
            assert self.current_panel is not None and self.current_fact is not None
            self.current_fact["text"] = normalize(str(self.current_fact["text"]))
            facts = self.current_panel["facts"]
            assert isinstance(facts, list)
            facts.append(self.current_fact)
            self.current_fact = None
            self.current_fact_depth = None
        if tag == "code" and self.current_command_depth == self.depth:
            assert self.current_panel is not None and self.current_command is not None
            commands = self.current_panel["commands"]
            assert isinstance(commands, dict)
            benchmark = self.current_command["benchmark"]
            if benchmark in commands:
                raise SystemExit(f"duplicate Pages reproduction command {benchmark}")
            commands[benchmark] = normalize(self.current_command["text"])
            self.current_command = None
            self.current_command_depth = None
        if tag == "article" and self.current_panel_depth == self.depth:
            assert self.current_panel is not None
            attrs = self.current_panel["attrs"]
            assert isinstance(attrs, dict)
            benchmark = attrs["data-benchmark"]
            self.current_panel["text"] = normalize(str(self.current_panel["text"]))
            self.panels[benchmark] = self.current_panel
            self.current_panel = None
            self.current_panel_depth = None
        if tag == "section" and self.performance_depth == self.depth:
            if self.current_panel is not None:
                raise SystemExit("unterminated Pages performance panel")
            self.performance_depth = None
        self.depth -= 1
        if self.depth < 0:
            raise SystemExit("invalid HTML nesting in Pages source")


def normalize(value: str) -> str:
    return " ".join(value.split())


def one_run(runs: list[dict], run_id: str) -> dict:
    matches = [run for run in runs if run.get("run_id") == run_id]
    if len(matches) != 1:
        raise SystemExit(f"expected one performance run {run_id}, found {len(matches)}")
    return matches[0]


def throughput(run: dict, parallel: int) -> float:
    matches = [point for point in run["throughput"] if point.get("parallel") == parallel]
    if len(matches) != 1:
        raise SystemExit(
            f"expected one P{parallel} result in {run['run_id']}, found {len(matches)}"
        )
    return float(matches[0]["mbps"])


def width(value: float, maximum: float) -> str:
    return f"{value / maximum * 100:.1f}".rstrip("0").rstrip(".")


def panel(parser: PerformanceParser, benchmark: str) -> dict[str, object]:
    result = parser.panels.get(benchmark)
    if result is None:
        raise SystemExit(f"Pages is missing the {benchmark} performance panel")
    return result


def require_text(panel_data: dict[str, object], *phrases: str) -> None:
    text = str(panel_data["text"])
    for phrase in phrases:
        if phrase not in text:
            raise SystemExit(f"Pages panel is missing required disclosure: {phrase}")


def validate_panel_contracts(parser: PerformanceParser) -> None:
    if parser.performance_sections != 1:
        raise SystemExit(
            f"expected one Pages performance section, found {parser.performance_sections}"
        )
    if parser.panels.keys() != PANEL_CONTRACTS.keys():
        raise SystemExit(
            "Pages performance panels differ: "
            f"missing={PANEL_CONTRACTS.keys() - parser.panels.keys()}, "
            f"extra={parser.panels.keys() - PANEL_CONTRACTS.keys()}"
        )
    for benchmark, contract in PANEL_CONTRACTS.items():
        attrs = parser.panels[benchmark]["attrs"]
        assert isinstance(attrs, dict)
        for key, expected in contract.items():
            if attrs.get(key) != expected:
                raise SystemExit(
                    f"Pages {benchmark} label {key} drifted: "
                    f"expected {expected!r}, got {attrs.get(key)!r}"
                )


def validate_matched_runs(selected: dict[str, dict]) -> None:
    rustscale = selected["rustscale"]
    tailscaled = selected["tailscaled"]
    if rustscale.get("product") != "rustscale" or tailscaled.get("product") != "tailscaled":
        raise SystemExit("Pages host TUN run IDs no longer identify the labeled products")
    if rustscale.get("product_version") != "rustscaled 0.1.1":
        raise SystemExit("Pages host TUN RustScale version label drifted")
    if tailscaled.get("product_version") != "1.98.9":
        raise SystemExit("Pages host TUN tailscaled version label drifted")
    matched_fields = (
        "machine_type",
        "cpu_platform",
        "server_zone",
        "client_zone",
        "resolved_image",
        "kernel_release",
        "repeat",
        "path",
        "path_class_reported",
        "topology_harness_label",
    )
    for field in matched_fields:
        if rustscale.get(field) != tailscaled.get(field):
            raise SystemExit(f"host TUN evidence is not matched on {field}")
    if rustscale["path_class_reported"] != "direct":
        raise SystemExit("Pages matched host TUN graph requires confirmed direct paths")
    if any(run["latency"]["loss"] != 0 for run in selected.values()):
        raise SystemExit("Pages host TUN summary cannot claim zero ping loss")
    for run in selected.values():
        if not run.get("source_clean") or not run.get("source_artifact_sha256"):
            raise SystemExit("Pages host TUN evidence requires clean, hashed source artifacts")
        points = {point["parallel"]: point for point in run["throughput"]}
        if set(points) != {1, 10, 100}:
            raise SystemExit("Pages host TUN graph requires P1, P10, and P100 evidence")
        for point in points.values():
            if (
                point.get("duration_s") != 10
                or point.get("statistic") != "median"
                or len(point.get("samples_mbps", [])) != run["repeat"]
            ):
                raise SystemExit("Pages host TUN throughput sampling labels are not true")
    runtime = rustscale["runtime"]
    if not runtime.get("rs_tun_outbound_send_pipeline"):
        raise SystemExit("Pages host TUN RustScale profile is not the recorded opt-in run")
    if not runtime.get("linux_udp_batch") or not runtime.get("linux_udp_gro"):
        raise SystemExit("Pages host TUN RustScale receive-mode label is not recorded")
    if "linux_udp_gso" in runtime:
        raise SystemExit("historical host TUN evidence unexpectedly changed GSO provenance")


def expected_host_bars(selected: dict[str, dict]) -> dict[tuple[str, str, str], tuple[float, str, str]]:
    expected: dict[tuple[str, str, str], tuple[float, str, str]] = {}
    for parallel in (1, 10, 100):
        values = {product: throughput(run, parallel) for product, run in selected.items()}
        maximum = max(values.values())
        for product, value in values.items():
            expected[("throughput", str(parallel), product)] = (
                value,
                f"{round(value)} Mbps",
                width(value, maximum),
            )

    latency_metrics = {
        "latency_p50_us": "p50_us",
        "latency_p95_us": "p95_us",
        "latency_p99_us": "p99_us",
    }
    for metric, evidence_key in latency_metrics.items():
        values = {
            product: float(run["latency"][evidence_key])
            for product, run in selected.items()
        }
        maximum = max(values.values())
        for product, value in values.items():
            expected[(metric, "", product)] = (
                value,
                f"{value:.0f} us",
                width(value, maximum),
            )

    footprint_formats = {
        "cpu_avg_pct": lambda value: f"{value:.1f}%",
        "cpu_peak_pct": lambda value: f"{value:.1f}%",
        "rss_avg_kb": lambda value: f"{value / 1024:.1f} MiB",
        "rss_peak_kb": lambda value: f"{value / 1024:.1f} MiB",
    }
    for metric, display in footprint_formats.items():
        values = {
            product: float(run["footprint"][metric])
            for product, run in selected.items()
        }
        maximum = max(values.values())
        for product, value in values.items():
            expected[(metric, "", product)] = (
                value,
                display(value),
                width(value, maximum),
            )
    return expected


def validate_host_bars(host: dict[str, object], selected: dict[str, dict]) -> None:
    expected = expected_host_bars(selected)
    actual: dict[tuple[str, str, str], tuple[float, str, str]] = {}
    bars = host["bars"]
    assert isinstance(bars, list)
    for bar in bars:
        attrs = bar["attrs"]
        product = attrs.get("data-product", "")
        metric = attrs.get("data-metric", "")
        parallel = attrs.get("data-parallel", "")
        key = (metric, parallel, product)
        if product not in HOST_RUN_IDS or key in actual:
            raise SystemExit(f"invalid or duplicate Pages host TUN bar {key}")
        try:
            value = float(attrs["data-value"])
        except (KeyError, ValueError) as error:
            raise SystemExit(f"invalid value for Pages host TUN bar {key}") from error
        match = re.fullmatch(r"width:([0-9]+(?:\.[0-9]+)?)%", attrs.get("style", ""))
        if match is None:
            raise SystemExit(f"invalid width for Pages host TUN bar {key}")
        expected_class = "bar-rs" if product == "rustscale" else "bar-ts"
        if expected_class not in attrs.get("class", "").split():
            raise SystemExit(f"wrong product class for Pages host TUN bar {key}")
        actual[key] = (value, str(bar["text"]), match.group(1))

    if actual.keys() != expected.keys():
        raise SystemExit(
            f"Pages host TUN bars differ: missing={expected.keys() - actual.keys()}, "
            f"extra={actual.keys() - expected.keys()}"
        )
    for key, expected_bar in expected.items():
        actual_bar = actual[key]
        if abs(actual_bar[0] - expected_bar[0]) > 1e-9:
            raise SystemExit(f"wrong source value for Pages host TUN bar {key}")
        if actual_bar[1:] != expected_bar[1:]:
            raise SystemExit(
                f"wrong label/width for Pages host TUN bar {key}: "
                f"expected {expected_bar[1:]}, got {actual_bar[1:]}"
            )


def validate_host_charts(host: dict[str, object], selected: dict[str, dict]) -> None:
    rustscale = selected["rustscale"]
    tailscaled = selected["tailscaled"]
    expected = [
        (
            "Matched host TUN direct throughput in megabits per second. "
            f"At one stream RustScale {round(throughput(rustscale, 1))} and "
            f"tailscaled {round(throughput(tailscaled, 1))}. At ten streams "
            f"RustScale {round(throughput(rustscale, 10))} and tailscaled "
            f"{round(throughput(tailscaled, 10))}. At one hundred streams "
            f"RustScale {round(throughput(rustscale, 100))} and tailscaled "
            f"{round(throughput(tailscaled, 100))}."
        ),
        (
            "Matched host TUN ping latency. "
            f"RustScale p50 {rustscale['latency']['p50_us']}, p95 "
            f"{rustscale['latency']['p95_us']}, and p99 "
            f"{rustscale['latency']['p99_us']} microseconds. tailscaled p50 "
            f"{tailscaled['latency']['p50_us']}, p95 "
            f"{tailscaled['latency']['p95_us']}, and p99 "
            f"{tailscaled['latency']['p99_us']} microseconds. Lower is better."
        ),
        (
            "Matched host TUN server CPU. RustScale average "
            f"{rustscale['footprint']['cpu_avg_pct']} and peak "
            f"{rustscale['footprint']['cpu_peak_pct']:.0f} percent. tailscaled "
            f"average {tailscaled['footprint']['cpu_avg_pct']} and peak "
            f"{tailscaled['footprint']['cpu_peak_pct']:.0f} percent. Lower is better."
        ),
        (
            "Matched host TUN server resident memory. RustScale average "
            f"{rustscale['footprint']['rss_avg_kb'] / 1024:.1f} and peak "
            f"{rustscale['footprint']['rss_peak_kb'] / 1024:.0f} mebibytes. "
            f"tailscaled average {tailscaled['footprint']['rss_avg_kb'] / 1024:.1f} "
            f"and peak {tailscaled['footprint']['rss_peak_kb'] / 1024:.2f} "
            "mebibytes. Lower is better."
        ),
    ]
    charts = host["charts"]
    assert isinstance(charts, list)
    actual = [chart.get("aria-label", "") for chart in charts[:len(expected)]]
    if actual != expected:
        raise SystemExit(f"Pages host TUN accessible chart labels drifted: {actual!r}")


def markdown_row(document: str, label: str, second_column: str) -> list[str]:
    matches: list[list[str]] = []
    for line in document.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 6 and cells[0] == label and cells[1] == second_column:
            matches.append(cells)
    if len(matches) != 1:
        raise SystemExit(f"expected one tracked userspace row {label!r}, found {len(matches)}")
    return matches[0]


def tracked_userspace(document: str) -> dict[str, dict[str, str]]:
    definitions = {
        "rustscale": "rustscale (after 10d)",
        "tailscaled": "tailscaled daemon proxy",
    }
    result: dict[str, dict[str, str]] = {}
    for product, label in definitions.items():
        throughput_row = markdown_row(document, label, "down")
        latency_row = markdown_row(document, label, "direct")
        if throughput_row[1:4] != ["down", "1", "direct"]:
            raise SystemExit(f"tracked userspace throughput scope drifted for {product}")
        if latency_row[1] != "direct":
            raise SystemExit(f"tracked userspace latency path drifted for {product}")
        result[product] = {
            "data-product": product,
            "data-userspace-record": "historical",
            "data-throughput-mbps": throughput_row[4],
            "data-throughput-duration-s": throughput_row[5].removesuffix("s"),
            "data-latency-p50-us": latency_row[2].replace(",", ""),
            "data-latency-p95-us": latency_row[3].replace(",", ""),
            "data-latency-p99-us": latency_row[4].replace(",", ""),
            "data-latency-count": latency_row[5],
        }
    return result


def validate_userspace_facts(userspace: dict[str, object], document: str) -> None:
    expected = tracked_userspace(document)
    evidence_labels = {
        "rustscale": "RustScale · phase-10d",
        "tailscaled": "tailscaled daemon proxy · 1.98.8-t05a918293",
    }
    facts = userspace["facts"]
    assert isinstance(facts, list)
    actual: dict[str, dict[str, str]] = {}
    for fact in facts:
        attrs = fact["attrs"]
        product = attrs.get("data-product", "")
        if product not in expected or product in actual:
            raise SystemExit(f"invalid or duplicate Pages userspace fact {product!r}")
        actual[product] = attrs
        for key, value in expected[product].items():
            if attrs.get(key) != value:
                raise SystemExit(
                    f"Pages userspace {product} field {key} drifted: "
                    f"expected {value!r}, got {attrs.get(key)!r}"
                )
        fact_text = str(fact["text"])
        if evidence_labels[product] not in fact_text:
            raise SystemExit(f"Pages userspace evidence label drifted for {product}")
        if evidence_labels[product].replace(" · ", "  | ") not in document:
            # The tracked Markdown table uses padded pipe-delimited cells.
            label_value = evidence_labels[product].split(" · ", 1)[1]
            if label_value not in document:
                raise SystemExit(f"tracked userspace evidence label is missing for {product}")
        for value in (
            f"{expected[product]['data-throughput-mbps']} Mbps",
            f"{expected[product]['data-throughput-duration-s']}s",
            f"p50 {expected[product]['data-latency-p50-us']} us",
            f"p95 {expected[product]['data-latency-p95-us']} us",
            f"p99 {expected[product]['data-latency-p99-us']} us",
            f"{expected[product]['data-latency-count']} rounds",
        ):
            if value not in fact_text:
                raise SystemExit(f"Pages userspace display text drifted: missing {value}")
    if actual.keys() != expected.keys():
        raise SystemExit("Pages userspace facts do not match tracked products")


def validate_evidence_docs(selected: dict[str, dict], performance: str) -> None:
    for product, run_id in HOST_RUN_IDS.items():
        if run_id not in performance:
            raise SystemExit(f"PERFORMANCE.md does not cite {product} run {run_id}")
    for parallel in (1, 10, 100):
        for run in selected.values():
            if f"{throughput(run, parallel):.1f} Mbps" not in performance:
                raise SystemExit("PERFORMANCE.md throughput differs from graph evidence")
    for run in selected.values():
        latency = run["latency"]
        for percentile in ("p50_us", "p95_us", "p99_us"):
            if f"{latency[percentile]} us" not in performance:
                raise SystemExit("PERFORMANCE.md latency differs from graph evidence")
    for value in (
        "97.30%",
        "152.43%",
        "152.00%",
        "248.00%",
        "17.91 MiB",
        "51.54 MiB",
        "18.00 MiB",
        "57.75 MiB",
    ):
        if value not in performance:
            raise SystemExit(f"PERFORMANCE.md is missing graph source value {value}")


def validate_canonical_evidence(parser: PerformanceParser, performance: str) -> None:
    configs = ("rs-userspace", "ts-embedded", "rs-tun", "ts-userspace", "ts-tun")
    parallelism = (1, 10, 100, 500, 1000)
    manifest = json.loads((CANONICAL_DIR / "matrix.json").read_text(encoding="utf-8"))
    source = manifest.get("run", {}).get("source", {})
    if (
        manifest.get("schema_version") != 4
        or manifest.get("run", {}).get("id") != CANONICAL_RUN_ID
        or source.get("commit") != CANONICAL_SOURCE_COMMIT
        or source.get("launch_worktree_dirty") is not False
        or source.get("includes_uncommitted_changes") is not False
        or manifest.get("configs") != list(configs)
        or manifest.get("repeat") != 3
        or manifest.get("duration_s") != 10
        or manifest.get("parallelism") != list(parallelism)
        or manifest.get("peer_count_requested") != 1
        or manifest.get("paths") != ["direct"]
        or manifest.get("topologies") != ["same-zone"]
    ):
        raise SystemExit("tracked canonical RSB1 manifest drifted")

    checksum_lines = (CANONICAL_DIR / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    if len(checksum_lines) != 20:
        raise SystemExit("canonical SHA256SUMS does not cover the complete result tree")
    for line in checksum_lines:
        digest, relative = line.split(maxsplit=1)
        path = CANONICAL_DIR / relative.removeprefix("./")
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SystemExit(f"canonical artifact checksum drifted: {relative}")

    canonical = panel(parser, "performance")
    facts = canonical["facts"]
    assert isinstance(facts, list)
    actual_facts = {
        fact["attrs"].get("data-config", ""): fact
        for fact in facts
        if "canonical-config" in fact["attrs"].get("class", "").split()
    }
    if actual_facts.keys() != set(configs):
        raise SystemExit("Pages canonical facts do not contain the exact five configurations")

    for config in configs:
        result_path = CANONICAL_DIR / "same-zone" / "direct" / f"{config}.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        gate = result.get("path_gate", {})
        cleanup = result.get("cleanup", {})
        if (
            result.get("schema_version") != 6
            or result.get("status") != "ok"
            or result.get("path_class_reported") != "direct"
            or gate != {"requested": "direct", "pre": "direct", "post": "direct", "matched": True}
            or not cleanup
            or not all(cleanup.values())
            or result.get("workload", {}).get("measured_trial_attempts") != 1
        ):
            raise SystemExit(f"tracked {config} result is not successful direct evidence")
        trials = result.get("throughput_trials", [])
        if len(trials) != 15:
            raise SystemExit(f"tracked {config} does not contain 15 exact trials")
        for streams in parallelism:
            rows = [trial for trial in trials if trial.get("parallel") == streams]
            if len(rows) != 3 or any(
                row.get("established") != streams
                or row.get("handshaken") != streams
                or row.get("completed") != streams
                for row in rows
            ):
                raise SystemExit(f"tracked {config} P{streams} lifecycle is incomplete")

        fact = actual_facts[config]
        attrs = fact["attrs"]
        text = str(fact["text"])
        points = {row.get("parallel"): row for row in result.get("throughput", [])}
        for streams in parallelism:
            row = points.get(streams, {})
            samples = row.get("samples_mbps", [])
            if len(samples) != 3 or not all(value > 0 for value in samples):
                raise SystemExit(f"tracked {config} P{streams} samples are incomplete")
            if abs(float(attrs[f"data-p{streams}-mbps"]) - float(row["mbps"])) > 1e-9:
                raise SystemExit(f"Pages {config} P{streams} value drifted")
            displayed = f"P{streams} {row['mbps']:.1f} ({row['coefficient_of_variation_pct']:.1f}%)"
            if displayed not in text:
                raise SystemExit(f"Pages is missing {config} display value {displayed}")

        latency = result.get("latency", {})
        if (
            latency.get("requested") != 200
            or latency.get("successful") != 200
            or latency.get("timed_out") != 0
            or latency.get("malformed") != 0
            or len(latency.get("samples_ns", [])) != 200
        ):
            raise SystemExit(f"tracked {config} latency distribution is incomplete")
        for attr, key in (("data-p50-us", "p50_us"), ("data-p95-us", "p95_us"), ("data-p99-us", "p99_us")):
            if abs(float(attrs[attr]) - float(latency[key])) > 1e-9:
                raise SystemExit(f"Pages {config} {key} drifted")
            if f"{latency[key]:.3f} us" not in text:
                raise SystemExit(f"Pages is missing {config} {key}")
        if attrs.get("data-latency-count") != "200" or "200/200" not in text:
            raise SystemExit(f"Pages {config} latency count drifted")

        for endpoint in ("client", "server"):
            resources = result.get("resources", {}).get(endpoint, {})
            series = resources.get("series", [])
            if not series or not any(sample.get("cpu_pct") is not None and sample.get("rss_kb") is not None for sample in series):
                raise SystemExit(f"tracked {config} {endpoint} resource series is empty")
            for suffix, key in (
                ("cpu-avg", "cpu_avg_pct"),
                ("cpu-peak", "cpu_peak_pct"),
                ("rss-avg-kb", "rss_avg_kb"),
                ("rss-peak-kb", "rss_peak_kb"),
            ):
                if abs(float(attrs[f"data-{endpoint}-{suffix}"]) - float(resources[key])) > 1e-9:
                    raise SystemExit(f"Pages {config} {endpoint} {key} drifted")

    summary = json.loads((CANONICAL_DIR / "summary.json").read_text(encoding="utf-8"))
    completeness = summary.get("completeness", {})
    if (
        not completeness.get("complete")
        or completeness.get("expected") != 5
        or completeness.get("ok") != 5
        or completeness.get("failed") != 0
        or completeness.get("missing") != 0
    ):
        raise SystemExit("canonical summary is not complete")
    require_text(
        canonical,
        "Complete matched evidence",
        "no winner is declared",
        "53–60% CV",
        "exclude kernel CPU",
        "double-count shared pages",
        "complete raw evidence",
        "full generated dashboard",
    )
    for value in (CANONICAL_RUN_ID, CANONICAL_SOURCE_COMMIT):
        if value not in performance:
            raise SystemExit(f"PERFORMANCE.md is missing canonical evidence {value}")


def main() -> None:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    page_source = PAGE.read_text(encoding="utf-8")
    performance = PERFORMANCE.read_text(encoding="utf-8")
    userspace_document = USERSPACE.read_text(encoding="utf-8")
    runs = data.get("runs", [])
    selected = {
        product: one_run(runs, run_id) for product, run_id in HOST_RUN_IDS.items()
    }

    parser = PerformanceParser()
    parser.feed(page_source)
    parser.close()
    if any(
        value is not None
        for value in (
            parser.performance_depth,
            parser.current_panel,
            parser.current_bar,
            parser.current_fact,
            parser.current_command,
        )
    ):
        raise SystemExit("unterminated Pages performance markup")

    validate_panel_contracts(parser)
    validate_matched_runs(selected)
    validate_canonical_evidence(parser, performance)

    container = panel(parser, "container-tun")
    if container["bars"] or container["facts"]:
        raise SystemExit("Pages container TUN panel cannot contain untracked results")
    if re.search(r"\b\d+(?:\.\d+)?\s*(?:Mbps|MiB|us|%)\b", str(container["text"])):
        raise SystemExit("Pages container TUN panel cannot contain benchmark numbers")
    require_text(
        container,
        "Not yet measured",
        "No reproducible container-TUN result or provenance ID is tracked.",
        "host-VM TUN numbers above must not be read as container results",
        "this panel intentionally contains no benchmark values",
        "Provenance IDs: none",
    )
    container_commands = container["commands"]
    assert isinstance(container_commands, dict)
    if container_commands != {"container-tun": CONTAINER_COMMAND}:
        raise SystemExit("Pages container TUN reproduction command drifted")

    userspace = panel(parser, "userspace")
    if userspace["bars"]:
        raise SystemExit("Pages unmatched userspace evidence cannot use comparative bars")
    validate_userspace_facts(userspace, userspace_document)
    require_text(
        userspace,
        "Historical · unmatched",
        "single-run localhost samples",
        "they are not a matched comparison",
        "No deltas or comparative bars are shown.",
        "CPU and RSS: not recorded.",
        "RustScale used embedded tsnet",
        "--tun=userspace-networking",
        "daemon plus SOCKS5/Serve proxy boundaries",
        "not embedded Go tsnet evidence",
        "do not establish current defaults or an opt-in performance profile",
        "Provenance IDs: not recorded by the historical harness",
    )
    if "gcp-" in str(userspace["text"]):
        raise SystemExit("Pages userspace panel cannot invent historical run IDs")
    userspace_commands = userspace["commands"]
    assert isinstance(userspace_commands, dict)
    if userspace_commands != {"userspace": USERSPACE_COMMAND}:
        raise SystemExit("Pages userspace reproduction command drifted")
    userspace_links = userspace["links"]
    assert isinstance(userspace_links, set)
    expected_userspace_link = (
        "https://github.com/rajsinghtech/rustscale/blob/master/docs/benchmarks.md#results"
    )
    if expected_userspace_link not in userspace_links:
        raise SystemExit("Pages userspace evidence does not link to its tracked record")

    validate_evidence_docs(selected, performance)
    print("Pages performance summary: environments, labels, and evidence match")


if __name__ == "__main__":
    main()
