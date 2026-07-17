#!/usr/bin/env python3
"""Generate deterministic, versioned rustscale compatibility contracts.

Normal generation is offline: it reads checked-in upstream snapshots plus local
source/build artifacts. Refreshing the pinned upstream snapshots is an explicit
separate operation that requires the Go module and an upstream CLI artifact.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import html
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
COMPAT = ROOT / "compat"
UPSTREAM_DIR = COMPAT / "upstream"
MANIFEST_DIR = COMPAT / "manifests"
PROVENANCE_PATH = UPSTREAM_DIR / "provenance.json"
OVERRIDES_PATH = COMPAT / "tsnet-overrides.json"
SCHEMA_REF = "../schema/manifest-v1.schema.json"
SCHEMA_VERSION = 1
CONTRACT_VERSION = 1
GENERATOR_VERSION = 1
CLASSIFICATIONS = {"exact", "semantic", "shimmed", "unsupported"}


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def sha256_ids(ids: Iterable[str]) -> str:
    normalized = "\n".join(sorted(set(ids))) + "\n"
    return hashlib.sha256(normalized.encode()).hexdigest()


def id_guard(ids: Iterable[str]) -> dict[str, Any]:
    values = sorted(set(ids))
    return {"count": len(values), "sha256": sha256_ids(values), "ids": values}


def shape_guard(items: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Guard item signatures/aliases/schemas as well as their stable IDs."""
    fingerprints = []
    for item in items:
        payload = {key: value for key, value in item.items() if key != "source"}
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        fingerprints.append(f"{item['id']}@{hashlib.sha256(encoded).hexdigest()}")
    return id_guard(fingerprints)


def upstream_provenance() -> dict[str, Any]:
    raw = read_json(PROVENANCE_PATH)
    return {
        "module": raw["module"],
        "version": raw["version"],
        "sum": raw["sum"],
        "go_mod_sum": raw["go_mod_sum"],
        "repository": raw["repository"],
        "revision": raw["revision"],
    }


def base_document(kind: str) -> dict[str, Any]:
    return {
        "$schema": SCHEMA_REF,
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "generator_version": GENERATOR_VERSION,
        "kind": kind,
        "upstream": upstream_provenance(),
    }


def validate_document(document: dict[str, Any]) -> None:
    required = {
        "$schema",
        "schema_version",
        "contract_version",
        "generator_version",
        "kind",
        "upstream",
        "denominator",
        "guards",
        "inventory",
        "comparisons",
    }
    missing = required - document.keys()
    if missing:
        raise ValueError(f"{document.get('kind', '<unknown>')}: missing keys {sorted(missing)}")
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"{document['kind']}: unsupported schema version")
    denominator = document["denominator"]
    if denominator["ids"] != sorted(set(denominator["ids"])):
        raise ValueError(f"{document['kind']}: denominator IDs are not normalized")
    if denominator["count"] != len(denominator["ids"]):
        raise ValueError(f"{document['kind']}: denominator count mismatch")
    if denominator["sha256"] != sha256_ids(denominator["ids"]):
        raise ValueError(f"{document['kind']}: denominator digest mismatch")
    covered: set[str] = set()
    comparison_ids: set[str] = set()
    for comparison in document["comparisons"]:
        if comparison.get("id") in comparison_ids:
            raise ValueError(f"{document['kind']}: duplicate comparison ID")
        comparison_ids.add(comparison.get("id"))
        classification = comparison.get("classification")
        if classification not in CLASSIFICATIONS:
            raise ValueError(
                f"{document['kind']}: invalid classification {classification!r}"
            )
        denominator_id = comparison.get("denominator_id")
        if denominator_id is not None:
            covered.add(denominator_id)
    omitted = set(denominator["ids"]) - covered
    if omitted:
        raise ValueError(
            f"{document['kind']}: unclassified denominator entries: {sorted(omitted)[:8]}"
        )
    for name, guard in document["guards"].items():
        if guard["ids"] != sorted(set(guard["ids"])):
            raise ValueError(f"{document['kind']}: {name} guard IDs are not normalized")
        if guard["count"] != len(guard["ids"]):
            raise ValueError(f"{document['kind']}: {name} guard count mismatch")
        if guard["sha256"] != sha256_ids(guard["ids"]):
            raise ValueError(f"{document['kind']}: {name} guard digest mismatch")


def removed_guard_ids(old: dict[str, Any], new: dict[str, Any]) -> dict[str, list[str]]:
    removed: dict[str, list[str]] = {}
    old_guards = {"denominator": old.get("denominator", {})} | old.get("guards", {})
    new_guards = {"denominator": new.get("denominator", {})} | new.get("guards", {})
    for name, previous in old_guards.items():
        if name not in new_guards:
            removed[name] = list(previous.get("ids", []))
            continue
        missing = sorted(set(previous.get("ids", [])) - set(new_guards[name].get("ids", [])))
        if missing:
            removed[name] = missing
    return removed


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def emit_json(
    path: Path,
    document: dict[str, Any],
    *,
    check: bool,
    allow_removals: bool,
) -> bool:
    validate_document(document)
    rendered = canonical_json(document)
    existing = path.read_text(encoding="utf-8") if path.exists() else None
    if check:
        if existing != rendered:
            print(f"compat drift: {display_path(path)}", file=sys.stderr)
            return False
        return True
    if existing is not None and not allow_removals:
        removed = removed_guard_ids(json.loads(existing), document)
        if removed:
            details = "; ".join(
                f"{name}: {', '.join(ids[:8])}{' ...' if len(ids) > 8 else ''}"
                for name, ids in removed.items()
            )
            raise ValueError(
                f"refusing denominator/API shrink in {display_path(path)} ({details}); "
                "review the removal and rerun with --allow-removals"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    return True


def emit_text(path: Path, value: str, *, check: bool) -> bool:
    existing = path.read_text(encoding="utf-8") if path.exists() else None
    if check:
        if existing != value:
            print(f"compat drift: {display_path(path)}", file=sys.stderr)
            return False
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    return True


# ---------------------------------------------------------------------------
# CLI extraction and comparison
# ---------------------------------------------------------------------------


def flatten_upstream_cli(raw: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    commands: list[dict[str, Any]] = []
    flags: list[dict[str, Any]] = []

    def walk(command: dict[str, Any], parents: list[str]) -> None:
        name = command["Name"]
        path = parents + ([] if not parents and name == "tailscale" else [name])
        if path:
            command_path = "/".join(path)
            commands.append(
                {
                    "id": f"command:{command_path}",
                    "path": command_path,
                    "aliases": [],
                }
            )
        flag_owner = "/".join(path) if path else "/"
        for entry in command.get("Flags", []):
            flag_name = entry["Name"]
            flags.append(
                {
                    "id": f"flag:{flag_owner}:{flag_name}",
                    "command": flag_owner,
                    "name": "--" + flag_name,
                    # Go's flag package accepts both one- and two-dash forms.
                    "aliases": ["-" + flag_name],
                }
            )
        for child in command.get("Subcommands", []):
            walk(child, path)

    walk(raw, [])
    commands.sort(key=lambda item: item["id"])
    flags.sort(key=lambda item: item["id"])
    return commands, flags


def flatten_local_cli(raw: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    commands: list[dict[str, Any]] = []
    flags: list[dict[str, Any]] = []

    def walk(command: dict[str, Any], parents: list[str]) -> None:
        path = parents + [command["name"]]
        command_path = "/".join(path)
        commands.append(
            {
                "id": f"command:{command_path}",
                "path": command_path,
                "aliases": sorted(command.get("aliases", [])),
            }
        )
        for entry in command.get("flags", []):
            flags.append(
                {
                    "id": f"flag:{command_path}:{entry['name']}",
                    "command": command_path,
                    "name": entry["name"],
                    "aliases": sorted(entry.get("aliases", [])),
                    "value": entry["value"],
                }
            )
        for child in command.get("subcommands", []):
            walk(child, path)

    for entry in raw.get("flags", []):
        flags.append(
            {
                "id": f"flag:/:{entry['name']}",
                "command": "/",
                "name": entry["name"],
                "aliases": sorted(entry.get("aliases", [])),
                "value": entry["value"],
            }
        )
    for command in raw["commands"]:
        walk(command, [])
    commands.sort(key=lambda item: item["id"])
    flags.sort(key=lambda item: item["id"])
    return commands, flags


CLI_CASES = [
    ("no_args", []),
    ("help_long", ["--help"]),
    ("help_short", ["-h"]),
    ("help_word", ["help"]),
    ("unknown_command", ["definitely-not-a-command"]),
    ("version", ["--version"]),
    (
        "status_help",
        ["--socket", "/__rustscale_compat_missing__/daemon.sock", "status", "--help"],
    ),
    ("nc_help", ["nc", "--help"]),
]


def output_markers(data: bytes) -> list[str]:
    text = data.decode("utf-8", errors="replace").lower()
    markers: list[str] = []
    checks = [
        ("usage", "usage"),
        ("subcommands", "subcommands"),
        ("flags", "flags"),
        ("unknown_subcommand", "unknown subcommand"),
        ("version", "version"),
        ("daemon_unavailable", "failed to connect"),
        ("nc_description", "connected to stdin/stdout"),
        ("wait_description", "wait for tailscale"),
    ]
    for marker, needle in checks:
        if needle in text:
            markers.append(marker)
    return markers


def probe_cli(binary: Path) -> list[dict[str, Any]]:
    behavior: list[dict[str, Any]] = []
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("RUSTSCALE_", "TS_", "TSNET_"))
    }
    environment.update({"LANG": "C", "LC_ALL": "C", "NO_COLOR": "1"})
    for name, argv in CLI_CASES:
        completed = subprocess.run(
            [str(binary), *argv],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
            env=environment,
        )
        behavior.append(
            {
                "id": f"behavior:{name}",
                "case": name,
                "argv": argv,
                "exit_code": completed.returncode,
                "stdout": {
                    "nonempty": bool(completed.stdout),
                    "markers": output_markers(completed.stdout),
                },
                "stderr": {
                    "nonempty": bool(completed.stderr),
                    "markers": output_markers(completed.stderr),
                },
            }
        )
    return sorted(behavior, key=lambda item: item["id"])


def cli_manifest(cli_binary: Path) -> dict[str, Any]:
    raw = json.loads(
        subprocess.check_output(
            [str(cli_binary), "__compat-contract"], cwd=ROOT, text=True, timeout=15
        )
    )
    local_commands, local_flags = flatten_local_cli(raw)
    local_behavior = probe_cli(cli_binary)
    upstream = read_json(UPSTREAM_DIR / "cli.json")
    upstream_commands = upstream["inventory"]["commands"]
    upstream_flags = upstream["inventory"]["flags"]
    upstream_behavior = upstream["inventory"]["behavior"]

    comparisons: list[dict[str, Any]] = []
    local_command_by_path = {entry["path"]: entry for entry in local_commands}
    matched_local: set[str] = set()
    for entry in upstream_commands:
        local = local_command_by_path.get(entry["path"])
        classification = "exact" if local else "unsupported"
        if local:
            matched_local.add(local["id"])
        comparisons.append(
            {
                "id": "compare:" + entry["id"],
                "denominator_id": entry["id"],
                "classification": classification,
                "upstream_ids": [entry["id"]],
                "local_ids": [local["id"]] if local else [],
                "note": "normalized command path matches" if local else "no local command",
            }
        )

    local_flags_by_owner: dict[str, list[dict[str, Any]]] = {}
    for entry in local_flags:
        local_flags_by_owner.setdefault(entry["command"], []).append(entry)
    for entry in upstream_flags:
        local = None
        via_alias = False
        upstream_spellings = {entry["name"], *entry.get("aliases", [])}
        for candidate in local_flags_by_owner.get(entry["command"], []):
            local_spellings = {candidate["name"], *candidate.get("aliases", [])}
            if entry["name"] in local_spellings:
                local = candidate
                via_alias = entry["name"] != candidate["name"]
                break
        if local:
            matched_local.add(local["id"])
            local_spellings = {local["name"], *local.get("aliases", [])}
            all_spellings = upstream_spellings <= local_spellings
            if via_alias and all_spellings:
                classification = "shimmed"
                note = "all upstream spellings are available through a local alias group"
            elif not via_alias and all_spellings:
                classification = "exact"
                note = "canonical flag and accepted alias spellings match"
            else:
                classification = "semantic"
                missing_aliases = sorted(upstream_spellings - local_spellings)
                note = "canonical flag is present; missing accepted spelling(s): " + ", ".join(
                    missing_aliases
                )
        else:
            classification = "unsupported"
            note = "no local flag on this command"
        comparisons.append(
            {
                "id": "compare:" + entry["id"],
                "denominator_id": entry["id"],
                "classification": classification,
                "upstream_ids": [entry["id"]],
                "local_ids": [local["id"]] if local else [],
                "note": note,
            }
        )

    local_behavior_by_case = {entry["case"]: entry for entry in local_behavior}
    for entry in upstream_behavior:
        local = local_behavior_by_case[entry["case"]]
        comparable_upstream = {
            key: value for key, value in entry.items() if key not in {"id", "argv"}
        }
        comparable_local = {
            key: value for key, value in local.items() if key not in {"id", "argv"}
        }
        if comparable_upstream == comparable_local:
            classification = "exact"
            note = "exit code, output channel, and normalized help markers match"
        elif entry["exit_code"] == local["exit_code"]:
            classification = "semantic"
            note = "exit code matches; normalized output behavior differs"
        elif entry["exit_code"] != 0 and local["exit_code"] == 0:
            classification = "shimmed"
            note = "rustscale supplies a successful compatibility alias"
        else:
            classification = "unsupported"
            note = "representative exit behavior is incompatible"
        comparisons.append(
            {
                "id": "compare:" + entry["id"],
                "denominator_id": entry["id"],
                "classification": classification,
                "upstream_ids": [entry["id"]],
                "local_ids": [local["id"]],
                "note": note,
            }
        )
        matched_local.add(local["id"])

    for entry in [*local_commands, *local_flags]:
        if entry["id"] in matched_local:
            continue
        comparisons.append(
            {
                "id": "local-only:" + entry["id"],
                "denominator_id": None,
                "classification": "shimmed",
                "upstream_ids": [],
                "local_ids": [entry["id"]],
                "note": "rustscale-only command, flag, or alias surface",
            }
        )

    denominator_ids = [
        entry["id"]
        for entry in [*upstream_commands, *upstream_flags, *upstream_behavior]
    ]
    local_ids = [
        entry["id"] for entry in [*local_commands, *local_flags, *local_behavior]
    ]
    document = base_document("cli")
    document.update(
        {
            "scope": "public command tree plus representative daemon-free help/exit probes",
            "denominator": {"source": "pinned-upstream-cli", **id_guard(denominator_ids)},
            "guards": {
                "upstream": id_guard(denominator_ids),
                "upstream_shape": shape_guard(
                    [*upstream_commands, *upstream_flags, *upstream_behavior]
                ),
                "local": id_guard(local_ids),
                "local_shape": shape_guard(
                    [*local_commands, *local_flags, *local_behavior]
                ),
            },
            "inventory": {
                "upstream": {
                    "commands": upstream_commands,
                    "flags": upstream_flags,
                    "behavior": upstream_behavior,
                },
                "local": {
                    "commands": local_commands,
                    "flags": local_flags,
                    "behavior": local_behavior,
                },
            },
            "comparisons": sorted(comparisons, key=lambda item: item["id"]),
        }
    )
    return document


# ---------------------------------------------------------------------------
# Rustdoc public API extraction
# ---------------------------------------------------------------------------


def strip_html(fragment: str) -> str:
    value = re.sub(r"<[^>]+>", "", fragment)
    return " ".join(html.unescape(value).replace("\u200b", "").split())


def rustdoc_items(doc_dir: Path) -> list[dict[str, Any]]:
    all_html = (doc_dir / "all.html").read_text(encoding="utf-8")
    links = re.findall(r'<li><a href="([^"]+)">(.*?)</a></li>', all_html, re.DOTALL)
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    kind_map = {
        "fn": "function",
        "constant": "constant",
        "type": "type",
        "struct": "struct",
        "enum": "enum",
        "trait": "trait",
        "macro": "macro",
    }
    for href, label_html in links:
        filename = Path(href).name
        prefix = filename.split(".", 1)[0]
        if prefix not in kind_map:
            continue
        name = strip_html(label_html)
        page = (doc_dir / href).read_text(encoding="utf-8")
        declaration = re.search(
            r'<pre class="rust item-decl"><code>(.*?)</code></pre>', page, re.DOTALL
        )
        signature = strip_html(declaration.group(1)) if declaration else ""
        item_id = f"{kind_map[prefix]}:{name}"
        if item_id not in seen:
            items.append(
                {
                    "id": item_id,
                    "kind": kind_map[prefix],
                    "name": name,
                    "signature": signature,
                    "source": "rustdoc:" + href,
                }
            )
            seen.add(item_id)

        sections = re.finditer(
            r'<section id="(method|tymethod|associatedconstant|associatedtype)\.([^"-]+)(?:-[^"]+)?"[^>]*>.*?<h4 class="code-header">(.*?)</h4>',
            page,
            re.DOTALL,
        )
        for section in sections:
            member_kind, member_name, header = section.groups()
            member_signature = strip_html(header)
            if prefix != "trait" and not member_signature.startswith("pub "):
                continue
            normalized_kind = {
                "method": "method",
                "tymethod": "method",
                "associatedconstant": "associated-constant",
                "associatedtype": "associated-type",
            }[member_kind]
            member_id = f"{normalized_kind}:{name}.{member_name}"
            if member_id in seen:
                continue
            items.append(
                {
                    "id": member_id,
                    "kind": normalized_kind,
                    "name": member_name,
                    "owner": name,
                    "signature": member_signature,
                    "source": "rustdoc:" + href,
                }
            )
            seen.add(member_id)

    index_html = (doc_dir / "index.html").read_text(encoding="utf-8")
    for module in re.findall(r'<a class="mod" href="[^"]+"[^>]*>(.*?)</a>', index_html):
        name = strip_html(module)
        item_id = "module:" + name
        if item_id not in seen:
            items.append(
                {
                    "id": item_id,
                    "kind": "module",
                    "name": name,
                    "signature": f"pub mod {name}",
                    "source": "rustdoc:index.html",
                }
            )
            seen.add(item_id)
    for name, declaration in re.findall(
        r'<dt id="reexport\.([^"]+)"><code>(.*?)</code></dt>', index_html, re.DOTALL
    ):
        item_id = "reexport:" + name
        if item_id not in seen:
            items.append(
                {
                    "id": item_id,
                    "kind": "reexport",
                    "name": name,
                    "signature": strip_html(declaration),
                    "source": "rustdoc:index.html",
                }
            )
            seen.add(item_id)
    items.sort(key=lambda item: item["id"])
    if not items:
        raise ValueError(f"no rustdoc items found under {doc_dir}")
    return items


def camel_to_snake(name: str) -> str:
    first = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    second = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first)
    return second.replace("__", "_").lower()


def load_tsnet_overrides() -> dict[str, dict[str, Any]]:
    if not OVERRIDES_PATH.exists():
        return {}
    raw = read_json(OVERRIDES_PATH)
    if raw["schema_version"] != SCHEMA_VERSION:
        raise ValueError("tsnet override schema version mismatch")
    if raw["upstream_version"] != upstream_provenance()["version"]:
        raise ValueError("tsnet overrides target a different upstream version")
    return raw["mappings"]


def resolve_tsnet_mapping(
    upstream_item: dict[str, Any],
    local_items: list[dict[str, Any]],
    overrides: dict[str, dict[str, Any]],
) -> tuple[list[str], str, str]:
    override = overrides.get(upstream_item["id"])
    if override is not None:
        return (
            override.get("local_ids", []),
            override["classification"],
            override.get("note", "reviewed conceptual mapping"),
        )

    local_by_id = {item["id"]: item for item in local_items}
    local_by_name: dict[str, list[str]] = {}
    for item in local_items:
        local_by_name.setdefault(item["name"], []).append(item["id"])
    kind = upstream_item["kind"]
    name = upstream_item["name"]
    owner = upstream_item.get("owner")
    candidates: list[str] = []
    if kind == "method":
        candidates.append(f"method:{owner}.{camel_to_snake(name)}")
    elif kind == "field" and owner == "Server":
        candidates.append(f"method:ServerBuilder.{camel_to_snake(name)}")
    elif kind == "function":
        candidates.append(f"function:{camel_to_snake(name)}")
    else:
        candidates.extend(local_by_name.get(name, []))
    matches = [candidate for candidate in candidates if candidate in local_by_id]
    if matches:
        return matches, "semantic", "idiomatic Rust spelling/type adaptation"
    return [], "unsupported", "no reviewed rustscale tsnet equivalent"


def tsnet_documents(local_items: list[dict[str, Any]]) -> tuple[dict[str, Any], str, set[str]]:
    upstream = read_json(UPSTREAM_DIR / "tsnet.json")
    upstream_items = upstream["inventory"]["items"]
    overrides = load_tsnet_overrides()
    comparisons: list[dict[str, Any]] = []
    mapped_local: set[str] = set()
    local_ids = {entry["id"] for entry in local_items}
    for entry in upstream_items:
        targets, classification, note = resolve_tsnet_mapping(
            entry, local_items, overrides
        )
        unknown = set(targets) - local_ids
        if unknown:
            raise ValueError(
                f"tsnet override for {entry['id']} names missing Rust API items: {sorted(unknown)}"
            )
        mapped_local.update(targets)
        comparisons.append(
            {
                "id": "compare:" + entry["id"],
                "denominator_id": entry["id"],
                "classification": classification,
                "upstream_ids": [entry["id"]],
                "local_ids": targets,
                "note": note,
            }
        )
    document = base_document("tsnet-conceptual-mapping")
    upstream_ids = [entry["id"] for entry in upstream_items]
    document.update(
        {
            "scope": "exported tailscale.com/tsnet identifiers mapped to rustscale-tsnet --all-features",
            "denominator": {"source": "pinned-upstream-tsnet", **id_guard(upstream_ids)},
            "guards": {
                "upstream": id_guard(upstream_ids),
                "upstream_shape": shape_guard(upstream_items),
                "local_targets": id_guard(mapped_local),
                "local_shape": shape_guard(local_items),
            },
            "inventory": {"upstream": upstream_items, "local": local_items},
            "comparisons": comparisons,
        }
    )

    lines = [
        "# Conceptual `tsnet` mapping",
        "",
        f"Generated from `tailscale.com@{document['upstream']['version']}` and the",
        "`rustscale-tsnet` all-features rustdoc artifact. This table maps concepts;",
        "`semantic` does not assert byte-for-byte signatures or runtime parity.",
        "",
        "| Upstream identifier | Rust identifier(s) | Classification | Note |",
        "| --- | --- | --- | --- |",
    ]
    for comparison in comparisons:
        upstream_id = comparison["upstream_ids"][0].replace("|", "\\|")
        rust_ids = ", ".join(comparison["local_ids"]) or "—"
        note = comparison["note"].replace("|", "\\|")
        lines.append(
            f"| `{upstream_id}` | {('`' + rust_ids.replace(', ', '`, `') + '`') if rust_ids != '—' else '—'} | "
            f"{comparison['classification']} | {note} |"
        )
    lines.append("")
    return document, "\n".join(lines), mapped_local


def rust_api_manifest(
    items: list[dict[str, Any]], mapped_local: set[str]
) -> dict[str, Any]:
    comparisons = []
    for entry in items:
        mapped = entry["id"] in mapped_local
        comparisons.append(
            {
                "id": "stability:" + entry["id"],
                "denominator_id": entry["id"],
                "classification": "semantic" if mapped else "shimmed",
                "upstream_ids": [],
                "local_ids": [entry["id"]],
                "note": (
                    "participates in the conceptual tsnet map"
                    if mapped
                    else "rustscale-specific public extension; retained by the local API denominator"
                ),
            }
        )
    ids = [entry["id"] for entry in items]
    document = base_document("rust-public-api")
    document.update(
        {
            "scope": "rustscale-tsnet public rustdoc surface with all Cargo features enabled",
            "denominator": {"source": "local-public-api", **id_guard(ids)},
            "guards": {"local": id_guard(ids), "local_shape": shape_guard(items)},
            "inventory": {"local": items},
            "comparisons": comparisons,
        }
    )
    return document


# ---------------------------------------------------------------------------
# C ABI and Python exports
# ---------------------------------------------------------------------------


def extract_c_abi(header_path: Path, source_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    header = header_path.read_text(encoding="utf-8")
    functions: list[dict[str, Any]] = []
    for match in re.finditer(r"(?ms)^int\s+(ts_[a-z0-9_]+)\s*\((.*?)\);", header):
        name, args = match.groups()
        signature = f"int {name}({' '.join(args.split())});"
        functions.append(
            {
                "id": "function:" + name,
                "kind": "function",
                "name": name,
                "signature": signature,
                "source": "include/rustscale.h",
            }
        )
    constants = []
    for name, value in re.findall(r"(?m)^#define\s+(RS_[A-Z0-9_]+)\s+([^\s]+)$", header):
        constants.append(
            {
                "id": "constant:" + name,
                "kind": "constant",
                "name": name,
                "value": value,
                "source": "include/rustscale.h",
            }
        )
    items = sorted([*functions, *constants], key=lambda item: item["id"])
    source = source_path.read_text(encoding="utf-8")
    source_symbols = sorted(
        set(
            re.findall(
                r'#\[no_mangle\]\s*pub\s+extern\s+"C"\s+fn\s+(ts_[a-z0-9_]+)',
                source,
            )
        )
    )
    header_symbols = sorted(item["name"] for item in functions)
    if source_symbols != header_symbols:
        raise ValueError(
            "C header/export mismatch: "
            f"source-only={sorted(set(source_symbols) - set(header_symbols))}, "
            f"header-only={sorted(set(header_symbols) - set(source_symbols))}"
        )
    return items, {
        "header_symbols": header_symbols,
        "rust_no_mangle_symbols": source_symbols,
        "match": True,
    }


C_TARGETS = {
    "ts_new": "rustscale_tsnet::Server::builder",
    "ts_set_authkey": "rustscale_tsnet::ServerBuilder::auth_key",
    "ts_set_hostname": "rustscale_tsnet::ServerBuilder::hostname",
    "ts_set_control_url": "rustscale_tsnet::ServerBuilder::control_url",
    "ts_set_state_dir": "rustscale_tsnet::ServerBuilder::state_dir",
    "ts_set_ephemeral": "rustscale_tsnet::ServerBuilder::ephemeral",
    "ts_set_localapi": "rustscale_tsnet::ServerBuilder::localapi_path",
    "ts_up": "rustscale_tsnet::Server::up",
    "ts_close": "rustscale_tsnet::Server::close",
    "ts_status_json": "rustscale_tsnet::Server::status",
    "ts_localapi_path": "rustscale_tsnet::Server::localapi_path",
    "ts_whois": "rustscale_tsnet::Server::whois",
    "ts_set_exit_node": "rustscale_tsnet::Server::set_exit_node",
    "ts_clear_exit_node": "rustscale_tsnet::Server::clear_exit_node",
    "ts_serve_tcp": "rustscale_tsnet::Server::set_serve_config",
    "ts_listen_socks5": "rustscale_tsnet::Server::listen_socks5",
    "ts_listen": "rustscale_tsnet::Server::listen",
    "ts_dial": "rustscale_tsnet::Server::dial",
}


def c_abi_manifest(items: list[dict[str, Any]], consistency: dict[str, Any]) -> dict[str, Any]:
    comparisons = []
    for entry in items:
        target = C_TARGETS.get(entry["name"], "rustscale C ABI support surface")
        comparisons.append(
            {
                "id": "abi:" + entry["id"],
                "denominator_id": entry["id"],
                "classification": "shimmed",
                "upstream_ids": [],
                "local_ids": [entry["id"]],
                "target": target,
                "note": "stable C shim over the Rust embedding/runtime API",
            }
        )
    ids = [entry["id"] for entry in items]
    document = base_document("c-abi")
    document.update(
        {
            "abi_version": 1,
            "scope": "generated C header declarations checked against Rust no_mangle exports",
            "denominator": {"source": "local-c-abi", **id_guard(ids)},
            "guards": {"local": id_guard(ids), "local_shape": shape_guard(items)},
            "inventory": {"local": items, "consistency": consistency},
            "comparisons": comparisons,
        }
    )
    return document


def annotation_source(source: str, node: ast.AST | None) -> str | None:
    if node is None:
        return None
    segment = ast.get_source_segment(source, node)
    return " ".join(segment.split()) if segment else None


def python_signature(source: str, function: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    positional = [*function.args.posonlyargs, *function.args.args]
    defaults_start = len(positional) - len(function.args.defaults)
    parameters = []
    for index, argument in enumerate(positional):
        parameters.append(
            {
                "name": argument.arg,
                "kind": "positional_only" if index < len(function.args.posonlyargs) else "positional_or_keyword",
                "annotation": annotation_source(source, argument.annotation),
                "has_default": index >= defaults_start,
            }
        )
    if function.args.vararg:
        parameters.append(
            {
                "name": function.args.vararg.arg,
                "kind": "var_positional",
                "annotation": annotation_source(source, function.args.vararg.annotation),
                "has_default": False,
            }
        )
    for argument, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
        parameters.append(
            {
                "name": argument.arg,
                "kind": "keyword_only",
                "annotation": annotation_source(source, argument.annotation),
                "has_default": default is not None,
            }
        )
    if function.args.kwarg:
        parameters.append(
            {
                "name": function.args.kwarg.arg,
                "kind": "var_keyword",
                "annotation": annotation_source(source, function.args.kwarg.annotation),
                "has_default": False,
            }
        )
    return {
        "async": isinstance(function, ast.AsyncFunctionDef),
        "parameters": parameters,
        "returns": annotation_source(source, function.returns),
    }


def extract_python_api(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    exports: list[str] | None = None
    definitions: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            definitions[node.name] = node
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                definitions[target.id] = node
                if target.id == "__all__" and isinstance(value, (ast.List, ast.Tuple)):
                    exports = [
                        element.value
                        for element in value.elts
                        if isinstance(element, ast.Constant)
                        and isinstance(element.value, str)
                    ]
    if exports is None:
        raise ValueError("bindings/python/rustscale.py must define explicit __all__")
    missing = sorted(set(exports) - definitions.keys())
    if missing:
        raise ValueError(f"Python __all__ contains undefined names: {missing}")

    items: list[dict[str, Any]] = []
    # Validate every ctypes declaration/reference in the module, including
    # constructor setup performed outside a public method body.
    backing_symbols: set[str] = set(re.findall(r"_lib\.(ts_[a-z0-9_]+)", source))
    public_protocol_methods = {"__enter__", "__exit__", "__init__"}
    for name in sorted(exports):
        node = definitions[name]
        if isinstance(node, ast.ClassDef):
            items.append(
                {
                    "id": "class:" + name,
                    "kind": "class",
                    "name": name,
                    "source": "bindings/python/rustscale.py",
                }
            )
            for member in node.body:
                if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if member.name.startswith("_") and member.name not in public_protocol_methods:
                    continue
                member_source = ast.get_source_segment(source, member) or ""
                symbols = sorted(set(re.findall(r"_lib\.(ts_[a-z0-9_]+)", member_source)))
                backing_symbols.update(symbols)
                items.append(
                    {
                        "id": f"method:{name}.{member.name}",
                        "kind": "method",
                        "name": member.name,
                        "owner": name,
                        "property": any(
                            isinstance(decorator, ast.Name) and decorator.id == "property"
                            for decorator in member.decorator_list
                        ),
                        "signature": python_signature(source, member),
                        "backing_symbols": symbols,
                        "source": "bindings/python/rustscale.py",
                    }
                )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_source = ast.get_source_segment(source, node) or ""
            symbols = sorted(set(re.findall(r"_lib\.(ts_[a-z0-9_]+)", function_source)))
            backing_symbols.update(symbols)
            items.append(
                {
                    "id": "function:" + name,
                    "kind": "function",
                    "name": name,
                    "signature": python_signature(source, node),
                    "backing_symbols": symbols,
                    "source": "bindings/python/rustscale.py",
                }
            )
        else:
            value_node = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
            value = ast.literal_eval(value_node) if value_node is not None else None
            items.append(
                {
                    "id": "constant:" + name,
                    "kind": "constant",
                    "name": name,
                    "value": value,
                    "source": "bindings/python/rustscale.py",
                }
            )
    items.sort(key=lambda item: item["id"])
    return items, sorted(backing_symbols)


def python_manifest(
    items: list[dict[str, Any]], backing_symbols: list[str], c_items: list[dict[str, Any]]
) -> dict[str, Any]:
    c_symbols = {entry["name"] for entry in c_items if entry["kind"] == "function"}
    missing = sorted(set(backing_symbols) - c_symbols)
    if missing:
        raise ValueError(f"Python binding references undeclared C symbols: {missing}")
    comparisons = []
    for entry in items:
        symbols = entry.get("backing_symbols", [])
        comparisons.append(
            {
                "id": "python:" + entry["id"],
                "denominator_id": entry["id"],
                "classification": "shimmed",
                "upstream_ids": [],
                "local_ids": [entry["id"]],
                "target": symbols or ["Python API support surface"],
                "note": "explicit Python export backed by the checked C ABI",
            }
        )
    ids = [entry["id"] for entry in items]
    document = base_document("python-exports")
    document.update(
        {
            "api_version": 1,
            "scope": "explicit __all__ exports, public class methods, and C backing symbols",
            "denominator": {"source": "local-python-api", **id_guard(ids)},
            "guards": {
                "local": id_guard(ids),
                "local_shape": shape_guard(items),
                "c_backing": id_guard(backing_symbols),
            },
            "inventory": {
                "local": items,
                "backing_symbols": backing_symbols,
                "c_symbols_resolved": True,
            },
            "comparisons": comparisons,
        }
    )
    return document


# ---------------------------------------------------------------------------
# LocalAPI extraction and comparison
# ---------------------------------------------------------------------------


def extract_localapi_contract(path: Path) -> list[dict[str, Any]]:
    source = path.read_text(encoding="utf-8")
    pattern = re.compile(
        r'localapi_contract!\(\s*"([A-Z]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)',
        re.MULTILINE,
    )
    routes = []
    for method, endpoint, request_schema, response_schema in pattern.findall(source):
        full_path = "/" if endpoint == "/" else "/localapi/v0/" + endpoint
        routes.append(
            {
                "id": f"route:{method}:{full_path}",
                "method": method,
                "path": full_path,
                "request_schema": request_schema,
                "response_schema": response_schema,
                "source": "crates/tsnet/src/localapi_contract.rs",
            }
        )
    routes.sort(key=lambda item: item["id"])
    ids = [entry["id"] for entry in routes]
    if not routes or len(ids) != len(set(ids)):
        raise ValueError("LocalAPI route contract is empty or contains duplicates")
    return routes


def route_path_matches(upstream_path: str, local_path: str) -> bool:
    upstream = upstream_path.removeprefix("/localapi/v0/")
    local = local_path.removeprefix("/localapi/v0/")
    if upstream == local:
        return True
    if upstream.endswith("<suffix>"):
        return local.startswith(upstream[: -len("<suffix>")])
    local_prefix = re.split(r"<|\[", local, maxsplit=1)[0]
    return bool(local_prefix) and upstream.startswith(local_prefix) and local.startswith(
        upstream.split("<", 1)[0]
    )


def localapi_manifest(local_routes: list[dict[str, Any]]) -> dict[str, Any]:
    upstream = read_json(UPSTREAM_DIR / "localapi.json")
    upstream_routes = upstream["inventory"]["routes"]
    comparisons: list[dict[str, Any]] = []
    matched_local: set[str] = set()
    for route_entry in upstream_routes:
        candidates = [
            local
            for local in local_routes
            if local["path"] != "/"
            and route_path_matches(route_entry["path"], local["path"])
            and (
                "ANY" in route_entry["methods"]
                or local["method"] in route_entry["methods"]
            )
        ]
        matched_local.update(candidate["id"] for candidate in candidates)
        if not candidates:
            classification = "unsupported"
            note = "no local route with a compatible method"
        else:
            local_methods = sorted({candidate["method"] for candidate in candidates})
            upstream_methods = route_entry["methods"]
            upstream_schemas = {
                schema
                for schema in route_entry["schema_ids"]
                if not schema.startswith("handler.")
            }
            local_schemas = {
                candidate["request_schema"] for candidate in candidates
            } | {candidate["response_schema"] for candidate in candidates}
            if (
                upstream_methods == local_methods
                and upstream_schemas
                and upstream_schemas & local_schemas
            ):
                classification = "exact"
                note = "path, method set, and an extracted schema identifier match"
            else:
                classification = "semantic"
                note = "route intent matches with a method/schema adaptation"
        comparisons.append(
            {
                "id": "compare:" + route_entry["id"],
                "denominator_id": route_entry["id"],
                "classification": classification,
                "upstream_ids": [route_entry["id"]],
                "local_ids": [candidate["id"] for candidate in candidates],
                "note": note,
            }
        )
    for entry in local_routes:
        if entry["id"] in matched_local:
            continue
        comparisons.append(
            {
                "id": "local-only:" + entry["id"],
                "denominator_id": None,
                "classification": "shimmed",
                "upstream_ids": [],
                "local_ids": [entry["id"]],
                "note": "rustscale-specific route or method extension",
            }
        )
    upstream_ids = [entry["id"] for entry in upstream_routes]
    local_ids = [entry["id"] for entry in local_routes]
    document = base_document("localapi")
    document.update(
        {
            "scope": "registered upstream routes versus Rust admission routes, methods, and stable schema identifiers",
            "denominator": {"source": "pinned-upstream-localapi", **id_guard(upstream_ids)},
            "guards": {
                "upstream": id_guard(upstream_ids),
                "upstream_shape": shape_guard(upstream_routes),
                "local": id_guard(local_ids),
                "local_shape": shape_guard(local_routes),
            },
            "inventory": {"upstream": upstream_routes, "local": local_routes},
            "comparisons": sorted(comparisons, key=lambda item: item["id"]),
        }
    )
    return document


# ---------------------------------------------------------------------------
# Upstream refresh
# ---------------------------------------------------------------------------


def upstream_snapshot(kind: str, inventory: dict[str, Any], ids: list[str], extraction: dict[str, Any]) -> dict[str, Any]:
    document = base_document("upstream-" + kind)
    document.update(
        {
            "extraction": extraction,
            "denominator": {"source": "pinned-upstream", **id_guard(ids)},
            "guards": {
                "upstream": id_guard(ids),
                "upstream_shape": shape_guard(
                    item
                    for entries in inventory.values()
                    for item in entries
                ),
            },
            "inventory": inventory,
            "comparisons": [
                {
                    "id": "snapshot:" + identifier,
                    "denominator_id": identifier,
                    "classification": "exact",
                    "upstream_ids": [identifier],
                    "local_ids": [],
                    "note": "normalized extraction from the pinned upstream source/artifact",
                }
                for identifier in ids
            ],
        }
    )
    return document


def refresh_upstream(args: argparse.Namespace) -> int:
    module_dir = Path(args.module_dir).resolve()
    cli_json_path = Path(args.cli_json).resolve()
    cli_binary = Path(args.cli_bin).resolve()
    provenance = read_json(PROVENANCE_PATH)
    go_mod = (module_dir / "go.mod").read_text(encoding="utf-8")
    if not go_mod.startswith(f"module {provenance['module']}\n"):
        raise ValueError(f"{module_dir} is not the pinned {provenance['module']} module")

    extracted = json.loads(
        subprocess.check_output(
            ["go", "run", str(ROOT / "tools/compat/go_extract.go"), str(module_dir)],
            cwd=ROOT,
            text=True,
            timeout=120,
        )
    )
    raw_cli = read_json(cli_json_path)
    commands, flags = flatten_upstream_cli(raw_cli)
    behavior = probe_cli(cli_binary)
    cli_ids = [entry["id"] for entry in [*commands, *flags, *behavior]]
    extraction_common = {
        "module": f"{provenance['module']}@{provenance['version']}",
        "source_revision": provenance["revision"],
        "extractor": "tools/compat/generate.py",
    }
    cli_document = upstream_snapshot(
        "cli",
        {"commands": commands, "flags": flags, "behavior": behavior},
        cli_ids,
        {
            **extraction_common,
            "source": "cmd/tailscale --json-docs plus executable probes",
            "platform": f"{platform.system().lower()}/{platform.machine().lower()}",
        },
    )
    tsnet_items = extracted["tsnet"]["items"]
    tsnet_document = upstream_snapshot(
        "tsnet",
        {"items": tsnet_items},
        [entry["id"] for entry in tsnet_items],
        {**extraction_common, "source": "Go AST over tsnet/*.go (non-test source union)"},
    )
    routes = extracted["localapi"]["routes"]
    localapi_document = upstream_snapshot(
        "localapi",
        {"routes": routes},
        [entry["id"] for entry in routes],
        {
            **extraction_common,
            "source": "Go AST over ipn/localapi/*.go handler registry and method bodies",
        },
    )
    ok = True
    for path, document in [
        (UPSTREAM_DIR / "cli.json", cli_document),
        (UPSTREAM_DIR / "tsnet.json", tsnet_document),
        (UPSTREAM_DIR / "localapi.json", localapi_document),
    ]:
        ok &= emit_json(
            path,
            document,
            check=False,
            allow_removals=args.allow_removals,
        )
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Main local generation
# ---------------------------------------------------------------------------


def generate(args: argparse.Namespace) -> int:
    cli_binary = Path(args.cli_bin).resolve()
    rustdoc_dir = Path(args.rustdoc_dir).resolve()
    local_rust_items = rustdoc_items(rustdoc_dir)
    tsnet_document, tsnet_markdown, mapped_local = tsnet_documents(local_rust_items)
    rust_document = rust_api_manifest(local_rust_items, mapped_local)
    c_items, c_consistency = extract_c_abi(
        ROOT / "include/rustscale.h", ROOT / "crates/ffi/src/lib.rs"
    )
    c_document = c_abi_manifest(c_items, c_consistency)
    python_items, python_symbols = extract_python_api(
        ROOT / "bindings/python/rustscale.py"
    )
    python_document = python_manifest(python_items, python_symbols, c_items)
    localapi_routes = extract_localapi_contract(
        ROOT / "crates/tsnet/src/localapi_contract.rs"
    )

    outputs = [
        (MANIFEST_DIR / "cli.json", cli_manifest(cli_binary)),
        (MANIFEST_DIR / "rust-api.json", rust_document),
        (MANIFEST_DIR / "c-abi.json", c_document),
        (MANIFEST_DIR / "python-api.json", python_document),
        (MANIFEST_DIR / "localapi.json", localapi_manifest(localapi_routes)),
        (MANIFEST_DIR / "tsnet.json", tsnet_document),
    ]
    ok = True
    for path, document in outputs:
        ok &= emit_json(
            path,
            document,
            check=args.check,
            allow_removals=args.allow_removals,
        )
    ok &= emit_text(COMPAT / "tsnet.md", tsnet_markdown, check=args.check)
    if ok and not args.check:
        print("generated compatibility contracts")
    if ok and args.check:
        print("compatibility contracts are current")
    return 0 if ok else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="command", required=True)
    local = subcommands.add_parser("generate", help="generate/check local contracts offline")
    local.add_argument(
        "--cli-bin", default=str(ROOT / "target/debug/rustscale"), help="built rustscale CLI"
    )
    local.add_argument(
        "--rustdoc-dir",
        default=str(ROOT / "target/doc/rustscale_tsnet"),
        help="all-features rustscale-tsnet rustdoc directory",
    )
    local.add_argument("--check", action="store_true", help="fail instead of writing on drift")
    local.add_argument(
        "--allow-removals",
        action="store_true",
        help="explicitly accept reviewed denominator/API removals",
    )
    local.set_defaults(func=generate)

    refresh = subcommands.add_parser(
        "refresh-upstream", help="refresh pinned upstream snapshots (not offline)"
    )
    refresh.add_argument("--module-dir", required=True)
    refresh.add_argument("--cli-json", required=True)
    refresh.add_argument("--cli-bin", required=True)
    refresh.add_argument(
        "--allow-removals",
        action="store_true",
        help="explicitly accept reviewed upstream denominator removals",
    )
    refresh.set_defaults(func=refresh_upstream)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"compat generator: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
