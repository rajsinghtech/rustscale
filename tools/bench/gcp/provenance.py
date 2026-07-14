#!/usr/bin/env python3
"""Structured immutable provenance for the GCP benchmark harness.

This deliberately has a small command-line surface: shell code supplies paths
and scalar arguments, while this module owns JSON parsing, validation and
atomic publication.  It must never serialize credentials.
"""
import argparse
import copy
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

COMMIT = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"gcp-[0-9]{8}-[0-9]{6}-[a-z0-9_-]+\Z")
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
CONFIG_PRODUCTS = {
    "rs-tun": ("rustscaled", "rustscale"),
    "ts-tun": ("tailscaled", "tailscale"),
    "rs-userspace": ("rustscale-bench",),
    "ts-userspace": ("tailscaled", "tailscale"),
}
TOPOLOGY_ZONES = {"same-zone": ("us-central1-a", "us-central1-b"), "cross-region": ("us-central1-a", "us-west1-a")}


def read(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(name, path)
    except BaseException:
        try: os.unlink(name)
        except OSError: pass
        raise


def is_string(x): return isinstance(x, str) and bool(x.strip())
def dry(x): return x == "dry-run"
def has_reserved(value):
    if isinstance(value, str): return value in {"dry-run", "unavailable"}
    if isinstance(value, dict): return any(has_reserved(v) for v in value.values())
    if isinstance(value, list): return any(has_reserved(v) for v in value)
    return False


def validate_run(run):
    if not isinstance(run, dict): raise ValueError("run must be an object")
    if not isinstance(run.get("id"), str) or not RUN_ID.fullmatch(run["id"]): raise ValueError("invalid run.id")
    if not isinstance(run.get("started_at_utc"), str) or not TIME.fullmatch(run["started_at_utc"]): raise ValueError("invalid run.started_at_utc")
    try:
        parsed = datetime.strptime(run["started_at_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != run["started_at_utc"]: raise ValueError
    except ValueError: raise ValueError("invalid run.started_at_utc")
    source = run.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("commit"), str) or not COMMIT.fullmatch(source["commit"]): raise ValueError("invalid source.commit")
    if source.get("delivery") != "git-archive-head" or source.get("includes_uncommitted_changes") is not False or type(source.get("launch_worktree_dirty")) is not bool: raise ValueError("invalid source delivery/dirtiness")
    cloud = run.get("cloud")
    required_cloud = ("provider", "project", "requested_image_project", "requested_image_family", "requested_machine_type", "network", "disk_type")
    if not isinstance(cloud, dict) or cloud.get("provider") != "gcp" or any(not is_string(cloud.get(k)) for k in required_cloud[1:]) or type(cloud.get("disk_gb")) is not int or cloud["disk_gb"] <= 0: raise ValueError("invalid cloud metadata")
    build = run.get("build")
    if not isinstance(build, dict) or any(type(build.get(k)) is not str for k in ("command", "rustflags", "cargo_profile_release_lto", "cargo_profile_release_codegen_units")): raise ValueError("invalid build metadata")


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2: raise ValueError("matrix schema_version must be 2")
    for key, choices in (("topologies", {"same-zone", "cross-region"}), ("paths", {"direct", "derp"}), ("configs", set(CONFIG_PRODUCTS))):
        values = manifest.get(key)
        if not isinstance(values, list) or not values or len(values) != len(set(values)) or any(v not in choices for v in values): raise ValueError(f"invalid {key}")
    if type(manifest.get("repeat")) is not int or manifest["repeat"] <= 0: raise ValueError("invalid repeat")
    if not isinstance(manifest.get("parallelism"), list) or not manifest["parallelism"] or len(manifest["parallelism"]) != len(set(manifest["parallelism"])) or any(type(v) is not int or v <= 0 for v in manifest["parallelism"]): raise ValueError("invalid parallelism")
    if type(manifest.get("dry_run")) is not bool: raise ValueError("invalid dry_run")
    if not manifest["dry_run"] and has_reserved(manifest.get("run")): raise ValueError("reserved sentinel in production run metadata")
    if manifest.get("warmup") != {"parallel": 1, "duration_s": 3, "reverse": True}: raise ValueError("invalid warmup")
    validate_run(manifest.get("run"))


def validate_product(products, config, endpoint):
    if dry(products): return
    required = set(CONFIG_PRODUCTS[config])
    if not isinstance(products, list) or len(products) != len(required): raise ValueError(f"invalid {endpoint} product")
    names = set()
    for entry in products:
        if (not isinstance(entry, dict) or not is_string(entry.get("path")) or not entry["path"].startswith("/")
                or not is_string(entry.get("version")) or entry["version"] == "unavailable"
                or not is_string(entry.get("version_source")) or entry["version_source"] == "unavailable"
                or not isinstance(entry.get("sha256"), str) or not SHA.fullmatch(entry["sha256"])): raise ValueError(f"invalid {endpoint} product entry")
        names.add(Path(entry["path"]).name)
    if names != required: raise ValueError(f"{endpoint} product must exactly match {config}")


def validate_endpoint(value, config, name):
    if dry(value): return
    if not isinstance(value, dict): raise ValueError(f"invalid {name} endpoint")
    required = ("zone", "machine_type", "cpu_platform", "cpu_model", "kernel_release", "os_pretty_name")
    if any(not is_string(value.get(k)) for k in required) or type(value.get("logical_cpus")) is not int or value["logical_cpus"] <= 0: raise ValueError(f"invalid {name} environment")


def validate_observed(observed, config, dry_run, topology=None, server_zone=None, client_zone=None, requested_machine=None):
    if not isinstance(observed, dict): raise ValueError("observed must be an object")
    values = [observed.get("resolved_image"), observed.get("server"), observed.get("client"), observed.get("toolchain"), observed.get("product")]
    all_dry = all(dry(x) for x in values)
    if all_dry:
        if not dry_run or set(observed) != {"resolved_image", "server", "client", "toolchain", "product"}: raise ValueError("dry-run observed metadata in production")
        return
    if has_reserved(observed): raise ValueError("reserved observed sentinel in production metadata")
    if not is_string(observed.get("resolved_image")): raise ValueError("invalid resolved_image")
    validate_endpoint(observed.get("server"), config, "server"); validate_endpoint(observed.get("client"), config, "client")
    if topology is not None:
        expected = TOPOLOGY_ZONES.get(topology)
        if expected is None or (server_zone, client_zone) != expected: raise ValueError("invalid selected topology zones")
        if observed["server"]["zone"] != server_zone or observed["client"]["zone"] != client_zone: raise ValueError("observed endpoint zones do not match invocation")
        if requested_machine and (observed["server"]["machine_type"] != requested_machine or observed["client"]["machine_type"] != requested_machine): raise ValueError("observed machine type does not match request")
    toolchain = observed.get("toolchain")
    if not isinstance(toolchain, dict) or any(not is_string(toolchain.get(k)) for k in ("server_cargo", "server_rustc_verbose", "client_cargo", "client_rustc_verbose")): raise ValueError("invalid toolchain")
    product = observed.get("product")
    if not isinstance(product, dict): raise ValueError("invalid product")
    validate_product(product.get("server"), config, "server"); validate_product(product.get("client"), config, "client")


def command_manifest(args):
    dirty = args.dirty == "1"
    run = {"id": args.run_id, "started_at_utc": args.started_at_utc,
           "source": {"commit": args.commit, "delivery": "git-archive-head", "includes_uncommitted_changes": False, "launch_worktree_dirty": dirty},
           "cloud": {"provider": "gcp", "project": args.project, "requested_image_project": args.image_project, "requested_image_family": args.image_family, "requested_machine_type": args.machine, "network": args.network, "disk_type": args.disk_type, "disk_gb": args.disk_gb},
           "build": {"command": args.build_command, "rustflags": args.rustflags, "cargo_profile_release_lto": args.lto, "cargo_profile_release_codegen_units": args.codegen_units}}
    data = {"schema_version": 2, "topologies": args.topologies, "paths": args.paths, "configs": args.configs, "parallelism": args.parallelism, "repeat": args.repeat, "dry_run": args.dry_run, "warmup": {"parallel": 1, "duration_s": 3, "reverse": True}, "run": run}
    validate_manifest(data); atomic(args.output, data)


def command_dry_observed(args):
    atomic(args.output, {"resolved_image": "dry-run", "server": "dry-run", "client": "dry-run", "toolchain": "dry-run", "product": "dry-run"})


def command_observed_real(args):
    """Combine files captured from the created VMs and their boot disks.

    The GCE instance and disk responses are files specifically so neither
    response nor remote multiline command output travels through shell JSON.
    """
    server_instance, client_instance = read(args.server_instance), read(args.client_instance)
    server_raw, client_raw = read(args.server_endpoint), read(args.client_endpoint)
    server_disk, client_disk = read(args.server_boot_disk), read(args.client_boot_disk)
    def endpoint(instance, raw):
        if not isinstance(raw, dict): raise ValueError("remote endpoint metadata is not an object")
        return {"zone": str(instance.get("zone", "")).rsplit("/", 1)[-1],
                "machine_type": str(instance.get("machineType", "")).rsplit("/", 1)[-1],
                "cpu_platform": instance.get("cpuPlatform"), "cpu_model": raw.get("cpu_model"),
                "logical_cpus": raw.get("logical_cpus"), "kernel_release": raw.get("kernel_release"),
                "os_pretty_name": raw.get("os_pretty_name")}
    server_image, client_image = server_disk.get("sourceImage"), client_disk.get("sourceImage")
    if not is_string(server_image) or server_image != client_image: raise ValueError("server/client boot disk images differ")
    observed = {"resolved_image": server_image,
                "server": endpoint(server_instance, server_raw), "client": endpoint(client_instance, client_raw),
                "toolchain": {"server_cargo": server_raw.get("cargo"), "server_rustc_verbose": server_raw.get("rustc_verbose"), "client_cargo": client_raw.get("cargo"), "client_rustc_verbose": client_raw.get("rustc_verbose")},
                "product": {"server": server_raw.get("product"), "client": client_raw.get("product")}}
    # Validate against every selected config: a topology snapshot must be
    # adequate for any cell that receives it, but need not name binaries for
    # configs that the matrix did not build or select.
    atomic(args.output, observed)


def command_select_observed(args):
    observed = read(args.input)
    if not isinstance(observed, dict): raise ValueError("invalid base observed metadata")
    if dry(observed.get("product")):
        validate_observed(observed, args.config, args.dry_run, args.topology, args.server_zone, args.client_zone, args.machine)
    elif isinstance(observed.get("product"), dict):
        required = set(CONFIG_PRODUCTS[args.config])
        observed["product"] = {endpoint: [entry for entry in observed["product"].get(endpoint, []) if Path(entry.get("path", "")).name in required] for endpoint in ("server", "client")}
        validate_observed(observed, args.config, args.dry_run, args.topology, args.server_zone, args.client_zone, args.machine)
    else: raise ValueError("invalid base observed products")
    atomic(args.output, observed)


def command_attach(args):
    manifest, result, observed = read(args.manifest), read(args.result), read(args.observed)
    validate_manifest(manifest)
    if not isinstance(result, dict): raise ValueError("result must be an object")
    config = result.get("config")
    topology, path = result.get("topology"), result.get("path")
    if config not in manifest["configs"] or topology not in manifest["topologies"] or path not in manifest["paths"]: raise ValueError("result identity is not selected by manifest")
    zones = TOPOLOGY_ZONES.get(topology)
    if zones is None: raise ValueError("invalid result topology")
    validate_observed(observed, config, manifest["dry_run"], topology, *zones, manifest["run"]["cloud"]["requested_machine_type"])
    result["schema_version"] = 3
    result["run"] = copy.deepcopy(manifest["run"])
    result["observed"] = observed
    atomic(args.result, result)


def command_validate(args):
    manifest = read(args.manifest); validate_manifest(manifest)
    if args.result:
        result = read(args.result)
        if result.get("schema_version") != 3 or result.get("run") != manifest["run"]: raise ValueError("result run does not exactly equal matrix run")
        topology = result.get("topology"); zones = TOPOLOGY_ZONES.get(topology)
        if result.get("config") not in manifest["configs"] or topology not in manifest["topologies"] or result.get("path") not in manifest["paths"] or zones is None: raise ValueError("result identity is not selected by manifest")
        validate_observed(result.get("observed"), result.get("config"), manifest["dry_run"], topology, *zones, manifest["run"]["cloud"]["requested_machine_type"])


def command_preflight(args):
    manifest, observed = read(args.manifest), read(args.observed)
    validate_manifest(manifest)
    if (args.config not in manifest["configs"] or args.topology not in manifest["topologies"]
            or args.path not in manifest["paths"]):
        raise ValueError("preflight identity is not selected by manifest")
    validate_observed(observed, args.config, manifest["dry_run"], args.topology, args.server_zone, args.client_zone, manifest["run"]["cloud"]["requested_machine_type"])


def command_profile(args):
    manifest, observed, profile = read(args.manifest), read(args.observed), read(args.profile)
    validate_manifest(manifest)
    if not isinstance(profile, dict): raise ValueError("profile metadata must be an object")
    topology, path = profile.get("topology"), profile.get("path")
    if args.config not in manifest["configs"] or topology not in manifest["topologies"] or path not in manifest["paths"]: raise ValueError("profile identity is not selected by manifest")
    zones = TOPOLOGY_ZONES.get(topology)
    if zones is None: raise ValueError("invalid profile topology")
    validate_observed(observed, args.config, manifest["dry_run"], topology, *zones, manifest["run"]["cloud"]["requested_machine_type"])
    profile["run"] = copy.deepcopy(manifest["run"]); profile["observed"] = observed
    profile["source_commit"] = manifest["run"]["source"]["commit"]; profile["run_id"] = manifest["run"]["id"]
    if profile.get("config") != args.config: raise ValueError("profile config mismatch")
    atomic(args.profile, profile)


def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="command", required=True)
    m = sub.add_parser("manifest"); m.add_argument("output"); m.add_argument("--run-id", required=True); m.add_argument("--started-at-utc", required=True); m.add_argument("--commit", required=True); m.add_argument("--dirty", choices=("0", "1"), required=True); m.add_argument("--project", required=True); m.add_argument("--image-project", required=True); m.add_argument("--image-family", required=True); m.add_argument("--machine", required=True); m.add_argument("--network", required=True); m.add_argument("--disk-type", required=True); m.add_argument("--disk-gb", type=int, required=True); m.add_argument("--build-command", default=""); m.add_argument("--rustflags", default=""); m.add_argument("--lto", default=""); m.add_argument("--codegen-units", default=""); m.add_argument("--dry-run", action="store_true"); m.add_argument("--topologies", nargs="+", required=True); m.add_argument("--paths", nargs="+", required=True); m.add_argument("--configs", nargs="+", required=True); m.add_argument("--parallelism", type=int, nargs="+", required=True); m.add_argument("--repeat", type=int, required=True); m.set_defaults(func=command_manifest)
    d = sub.add_parser("dry-observed"); d.add_argument("output"); d.set_defaults(func=command_dry_observed)
    o = sub.add_parser("observed-real"); o.add_argument("output"); o.add_argument("--server-instance", required=True); o.add_argument("--client-instance", required=True); o.add_argument("--server-boot-disk", required=True); o.add_argument("--client-boot-disk", required=True); o.add_argument("--server-endpoint", required=True); o.add_argument("--client-endpoint", required=True); o.set_defaults(func=command_observed_real)
    s = sub.add_parser("select-observed"); s.add_argument("output"); s.add_argument("--input", required=True); s.add_argument("--config", required=True, choices=CONFIG_PRODUCTS); s.add_argument("--topology", required=True); s.add_argument("--server-zone", required=True); s.add_argument("--client-zone", required=True); s.add_argument("--machine", required=True); s.add_argument("--dry-run", action="store_true"); s.set_defaults(func=command_select_observed)
    a = sub.add_parser("attach"); a.add_argument("--manifest", required=True); a.add_argument("--observed", required=True); a.add_argument("result"); a.set_defaults(func=command_attach)
    v = sub.add_parser("validate"); v.add_argument("--manifest", required=True); v.add_argument("--result"); v.set_defaults(func=command_validate)
    f = sub.add_parser("preflight"); f.add_argument("--manifest", required=True); f.add_argument("--observed", required=True); f.add_argument("--config", required=True); f.add_argument("--topology", required=True); f.add_argument("--path", required=True); f.add_argument("--server-zone", required=True); f.add_argument("--client-zone", required=True); f.set_defaults(func=command_preflight)
    q = sub.add_parser("profile"); q.add_argument("--manifest", required=True); q.add_argument("--observed", required=True); q.add_argument("--config", required=True); q.add_argument("profile"); q.set_defaults(func=command_profile)
    args = p.parse_args()
    try: args.func(args)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as e: print(f"provenance error: {e}", file=sys.stderr); return 1
    return 0

if __name__ == "__main__": sys.exit(main())
