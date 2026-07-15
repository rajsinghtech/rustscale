#!/usr/bin/env python3
"""Verify that the Pages graph matches the tracked performance evidence."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "docs/performance/benchmarks-2026-07-15.json"
PAGE = ROOT / "site/index.html"
PERFORMANCE = ROOT / "PERFORMANCE.md"


class PerformanceParser(HTMLParser):
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self) -> None:
        super().__init__()
        self.depth = 0
        self.performance_depth: int | None = None
        self.section_attrs: dict[str, str] = {}
        self.links: set[str] = set()
        self.bars: list[dict[str, object]] = []
        self.current_bar: dict[str, object] | None = None
        self.current_bar_depth: int | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if tag not in self.VOID_TAGS:
            self.depth += 1
        classes = values.get("class", "").split()
        if tag == "section" and "performance" in classes:
            if self.performance_depth is not None:
                raise SystemExit("nested Pages performance sections are not allowed")
            self.performance_depth = self.depth
            self.section_attrs = values
        if self.performance_depth is None:
            return
        if tag == "a":
            self.links.add(values.get("href", ""))
        if tag == "div" and "bar" in classes:
            if self.current_bar is not None:
                raise SystemExit("nested Pages performance bars are not allowed")
            self.current_bar = {"attrs": values, "text": ""}
            self.current_bar_depth = self.depth

    def handle_data(self, data: str) -> None:
        if self.current_bar is not None:
            self.current_bar["text"] = str(self.current_bar["text"]) + data

    def handle_endtag(self, tag: str) -> None:
        if tag == "div" and self.current_bar_depth == self.depth:
            assert self.current_bar is not None
            self.current_bar["text"] = str(self.current_bar["text"]).strip()
            self.bars.append(self.current_bar)
            self.current_bar = None
            self.current_bar_depth = None
        if tag == "section" and self.performance_depth == self.depth:
            self.performance_depth = None
        self.depth -= 1
        if self.depth < 0:
            raise SystemExit("invalid HTML nesting in Pages source")


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


def main() -> None:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    page = PAGE.read_text(encoding="utf-8")
    performance = PERFORMANCE.read_text(encoding="utf-8")
    runs = data.get("runs", [])

    run_ids = {
        "rustscale": "gcp-20260715-085022-076e87bd41",
        "tailscaled": "gcp-20260715-090601-02788a10b4",
    }
    selected = {product: one_run(runs, run_id) for product, run_id in run_ids.items()}

    parser = PerformanceParser()
    parser.feed(page)
    parser.close()
    if parser.performance_depth is not None or parser.current_bar is not None:
        raise SystemExit("unterminated Pages performance markup")
    if parser.section_attrs.get("data-rustscale-run") != run_ids["rustscale"]:
        raise SystemExit("Pages RustScale run ID does not match benchmark evidence")
    if parser.section_attrs.get("data-tailscaled-run") != run_ids["tailscaled"]:
        raise SystemExit("Pages tailscaled run ID does not match benchmark evidence")

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

    footprint_formats = {
        "cpu_avg_pct": lambda value: f"{value:.1f}%",
        "rss_avg_kb": lambda value: f"{value / 1024:.1f} MiB",
        "binary_size_bytes": lambda value: f"{value / 1048576:.1f} MiB",
    }
    for metric, display in footprint_formats.items():
        values = {
            product: float(run["footprint"][metric]) for product, run in selected.items()
        }
        maximum = max(values.values())
        for product, value in values.items():
            expected[(metric, "", product)] = (value, display(value), width(value, maximum))

    actual: dict[tuple[str, str, str], tuple[float, str, str]] = {}
    for bar in parser.bars:
        attrs = bar["attrs"]
        assert isinstance(attrs, dict)
        product = attrs.get("data-product", "")
        metric = attrs.get("data-metric", "")
        parallel = attrs.get("data-parallel", "")
        key = (metric, parallel, product)
        if key in actual:
            raise SystemExit(f"duplicate Pages performance bar {key}")
        try:
            value = float(attrs["data-value"])
        except (KeyError, ValueError) as error:
            raise SystemExit(f"invalid value for Pages performance bar {key}") from error
        match = re.fullmatch(r"width:([0-9]+(?:\.[0-9]+)?)%", attrs.get("style", ""))
        if match is None:
            raise SystemExit(f"invalid width for Pages performance bar {key}")
        classes = attrs.get("class", "").split()
        expected_class = "bar-rs" if product == "rustscale" else "bar-ts"
        if expected_class not in classes:
            raise SystemExit(f"wrong product class for Pages performance bar {key}")
        actual[key] = (value, str(bar["text"]), match.group(1))

    if actual.keys() != expected.keys():
        raise SystemExit(
            f"Pages performance bars differ: missing={expected.keys() - actual.keys()}, "
            f"extra={actual.keys() - expected.keys()}"
        )
    for key, expected_bar in expected.items():
        actual_bar = actual[key]
        if abs(actual_bar[0] - expected_bar[0]) > 1e-9:
            raise SystemExit(f"wrong source value for Pages performance bar {key}")
        if actual_bar[1:] != expected_bar[1:]:
            raise SystemExit(
                f"wrong label/width for Pages performance bar {key}: "
                f"expected {expected_bar[1:]}, got {actual_bar[1:]}"
            )

    expected_link = (
        "https://github.com/rajsinghtech/rustscale/blob/master/PERFORMANCE.md"
    )
    if expected_link not in parser.links:
        raise SystemExit("Pages performance graph does not link to PERFORMANCE.md")
    if "zero ping packet loss" not in page:
        raise SystemExit("Pages performance caveat is missing ping-loss scope")
    if any(run["latency"]["loss"] != 0 for run in selected.values()):
        raise SystemExit("Pages summary cannot claim zero ping loss for these runs")
    if any(run["path_class_reported"] != "direct" for run in selected.values()):
        raise SystemExit("Pages summary requires confirmed direct paths")

    for product, run_id in run_ids.items():
        if run_id not in performance:
            raise SystemExit(f"PERFORMANCE.md does not cite {product} run {run_id}")
    for parallel in (1, 10, 100):
        for run in selected.values():
            if f"{throughput(run, parallel):.1f} Mbps" not in performance:
                raise SystemExit("PERFORMANCE.md throughput differs from graph evidence")
    for value in ("97.30%", "152.43%", "17.91 MiB", "51.54 MiB", "15.82 MiB", "39.22 MiB"):
        if value not in performance:
            raise SystemExit(f"PERFORMANCE.md is missing graph source value {value}")

    print("Pages performance summary: graph and benchmark evidence match")


if __name__ == "__main__":
    main()
