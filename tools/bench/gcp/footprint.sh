#!/usr/bin/env bash
# tools/bench/gcp/footprint.sh — pidstat-based RSS+CPU sampler helpers.
#
# Sourced by run-config.sh. Provides:
#   start_footprint PID OUTFILE     — launch pidstat sampler in background
#   stop_footprint  SAMPLER_PID OUTFILE — kill sampler, emit JSON parse to stdout
#
# pidstat output format (one row per second, after a header):
#   UID       PID %usr %system %guest   %wait   %CPU   CPU  Command
#   0      12345 12.3    4.5    0.0     0.0    16.8     1  rustscale-tun
# ... and a separate -r pass for RSS:
#   UID       PID  minflt/s  majflt/s  VSZ    RSS   %MEM  Command
#
# To get both in one file we use `-rud` which interleaves RSS + CPU lines.
# The parser handles both forms.

# shellcheck shell=bash

# ---------------------------------------------------------------------------
# start_footprint PID OUTFILE
# Launches `pidstat -p PID -rud 1 > OUTFILE` in the background.
# Prints the sampler PID (local or remote — caller manages remote via ssh).
# For VM usage, the caller runs these helpers *inside* an ssh_cmd invocation.
# ---------------------------------------------------------------------------
start_footprint() {
  local pid="$1" outfile="$2"
  if command -v pidstat >/dev/null 2>&1; then
    pidstat -p "$pid" -rud 1 >"$outfile" 2>&1 &
    echo $!
  else
    # Fallback: ps loop writing "rss pcpu" rows.
    (
      while kill -0 "$pid" 2>/dev/null; do
        ps -o rss=,pcpu= -p "$pid" 2>/dev/null | awk '{print $1, $2}'
        sleep 1
      done
    ) >"$outfile" 2>&1 &
    echo $!
  fi
}

# ---------------------------------------------------------------------------
# stop_footprint SAMPLER_PID OUTFILE
# Kills the sampler, parses OUTFILE, emits a JSON object on stdout with:
#   rss_peak_kb, rss_avg_kb, cpu_peak_pct, cpu_avg_pct, samples
# ---------------------------------------------------------------------------
stop_footprint() {
  local sampler_pid="$1" outfile="$2"
  kill "$sampler_pid" 2>/dev/null || true
  wait "$sampler_pid" 2>/dev/null || true
  python3 - "$outfile" <<'PYEOF'
import json, re, sys

path = sys.argv[1]
rss_vals = []
cpu_vals = []

try:
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("UID", "Linux", "#")):
                continue
            # pidstat -r row: UID PID minflt/s majflt/s VSZ RSS %MEM Command
            # pidstat -u row: UID PID %usr %system %guest %wait %CPU CPU Command
            parts = line.split()
            if len(parts) < 7:
                # ps fallback: "rss pcpu"
                if len(parts) == 2:
                    try:
                        rss_vals.append(int(parts[0]))
                        cpu_vals.append(float(parts[1]))
                    except ValueError:
                        pass
                continue
            # Heuristic: RSS rows have a large integer in column 5 (VSZ in KB)
            # and column 6 (RSS in KB); CPU rows have a float in column 6 (%CPU).
            try:
                vsz = int(parts[4])
                rss = int(parts[5])
                rss_vals.append(rss)
                continue
            except ValueError:
                pass
            try:
                cpu = float(parts[6])
                cpu_vals.append(cpu)
            except ValueError:
                pass
except FileNotFoundError:
    pass

def agg(vals, peak=True, avg=True):
    if not vals:
        return {"peak": 0, "avg": 0}
    return {
        "peak": max(vals),
        "avg": round(sum(vals) / len(vals), 2),
    }

rss = agg(rss_vals)
cpu = agg(cpu_vals)
out = {
    "rss_peak_kb": rss["peak"],
    "rss_avg_kb": rss["avg"],
    "cpu_peak_pct": cpu["peak"],
    "cpu_avg_pct": cpu["avg"],
    "samples": max(len(rss_vals), len(cpu_vals)),
}
print(json.dumps(out))
PYEOF
}

# ---------------------------------------------------------------------------
# remote_start_footprint NAME ZONE PID REMOTE_OUTFILE
# Launches pidstat on a VM in the background via ssh. Prints a local handle
# (the ssh pty PID) the caller can pass to remote_stop_footprint.
# We write the sampler PID into REMOTE_OUTFILE.handle on the VM so we can
# kill it later.
# ---------------------------------------------------------------------------
remote_start_footprint() {
  local name="$1" zone="$2" pid="$3" outfile="$4"
  ssh_cmd "$name" "$zone" \
    "nohup pidstat -p $pid -rud 1 >$outfile 2>&1 & echo \$! >$outfile.handle; cat $outfile.handle"
}

# ---------------------------------------------------------------------------
# remote_stop_footprint NAME ZONE REMOTE_OUTFILE
# Kills the remote sampler (using the handle), fetches OUTFILE, parses it,
# emits JSON on stdout.
# ---------------------------------------------------------------------------
remote_stop_footprint() {
  local name="$1" zone="$2" outfile="$3"
  local handle
  handle=$(ssh_cmd "$name" "$zone" "cat $outfile.handle 2>/dev/null || true")
  if [[ -n "$handle" ]]; then
    ssh_cmd "$name" "$zone" "kill $handle 2>/dev/null; sleep 1; pkill -f 'pidstat -p' 2>/dev/null" || true
  fi
  local local_copy
  local_copy=$(mktemp /tmp/footprint.XXXXXX)
  # gcloud scp back.
  if [[ -z "${GCP_DRY_RUN:-}" ]]; then
    gcloud compute scp "$name:$outfile" "$local_copy" --zone="$zone" \
      --ssh-flag='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' 2>/dev/null || true
  fi
  stop_footprint 0 "$local_copy"
  rm -f "$local_copy"
}
