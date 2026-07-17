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
# Launches `pidstat -p PID -ru 1 > OUTFILE` in the background.
# Prints the sampler PID (local or remote — caller manages remote via ssh).
# For VM usage, the caller runs these helpers *inside* an ssh_cmd invocation.
# ---------------------------------------------------------------------------
start_footprint() {
  local pid="$1" outfile="$2"
  if command -v pidstat >/dev/null 2>&1; then
    pidstat -p "$pid" -ru 1 >"$outfile" 2>&1 &
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
  [[ -n "$sampler_pid" && "$sampler_pid" != "0" ]] && kill "$sampler_pid" 2>/dev/null || true
  python3 - "$outfile" <<'PYEOF'
import json, re, sys

path = sys.argv[1]
rss_vals = []
cpu_vals = []

# pidstat -ru interleaves -r (memory) and -u (CPU) rows.  On sysstat >= 12.x
# each data row is prefixed with a timestamp ("HH:MM:SS" optionally followed
# by "AM"/"PM"), which shifts every column index by 1-2.  Strip it so the
# column layout matches the header.
time_re = re.compile(r'^\d{1,2}:\d{2}:\d{2}')

set_series = []
try:
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("UID", "Linux", "#")):
                continue
            if line.startswith("RSSET "):
                # RSSET monotonic_ms rss_kb cpu_pct comma-separated-pid:comm
                parts = line.split(maxsplit=4)
                try:
                    rss_observed = parts[2] != "null"
                    cpu_observed = parts[3] != "null"
                    set_series.append({"offset_ms": int(parts[1]),
                                       "rss_kb": int(parts[2]) if rss_observed else None,
                                       "cpu_pct": float(parts[3]) if cpu_observed else None,
                                       "included_processes": parts[4].split(",") if len(parts) == 5 and parts[4] else [],
                                       "status": "observed" if rss_observed and cpu_observed else ("partial" if rss_observed or cpu_observed else "missed")})
                except (ValueError, IndexError):
                    pass
                continue
            parts = line.split()
            # Strip timestamp prefix (sysstat 12.x+).
            if time_re.match(parts[0]):
                if len(parts) > 1 and parts[1] in ("AM", "PM"):
                    parts = parts[2:]
                else:
                    parts = parts[1:]
            if len(parts) < 7:
                # ps fallback: "rss pcpu"
                if len(parts) == 2:
                    try:
                        rss_vals.append(int(parts[0]))
                        cpu_vals.append(float(parts[1]))
                    except ValueError:
                        pass
                continue
            # After timestamp stripping the layout is:
            #   -r row: UID PID minflt/s majflt/s VSZ RSS %MEM Command
            #   -u row: UID PID %usr %system %guest %wait %CPU CPU Command
            # Distinguish: -r rows have an integer in col 4 (VSZ) and col 5
            # (RSS); -u rows have a float in col 4 (%guest).
            try:
                int(parts[4])  # VSZ (int) → this is a -r row
                rss = int(parts[5])
                rss_vals.append(rss)
                continue
            except ValueError:
                pass
            try:
                cpu = float(parts[6])  # %CPU
                cpu_vals.append(cpu)
            except ValueError:
                pass
except FileNotFoundError as exc:
    raise SystemExit(f"footprint source missing: {exc}")

def agg(vals):
    if not vals:
        return {"peak": 0, "avg": 0}
    return {
        "peak": max(vals),
        "avg": round(sum(vals) / len(vals), 2),
    }

if set_series:
    # Normalize real monotonic timestamps to a per-workload offset. A gap larger
    # than the requested cadence remains visible rather than being invented as
    # a zero sample.
    origin = set_series[0]["offset_ms"]
    series = [dict(sample, offset_ms=sample["offset_ms"] - origin) for sample in set_series[:3600]]
    # Summaries cover the complete source, not merely the retained dashboard
    # prefix. The original count drives the truncation disclosure.
    rss_vals = [sample["rss_kb"] for sample in set_series if sample["rss_kb"] is not None]
    cpu_vals = [sample["cpu_pct"] for sample in set_series if sample["cpu_pct"] is not None]
else:
    series = [{"offset_ms": (i + 1) * 1000,
               "rss_kb": rss_vals[i] if i < len(rss_vals) else None,
               "cpu_pct": cpu_vals[i] if i < len(cpu_vals) else None,
               "included_processes": [], "status": "observed"}
              for i in range(min(max(len(rss_vals), len(cpu_vals)), 3600))]
sample_count = len(set_series) if set_series else max(len(rss_vals), len(cpu_vals))
if sample_count == 0:
    raise SystemExit("footprint source contained no samples")
rss = agg(rss_vals)
cpu = agg(cpu_vals)
out = {
    "rss_peak_kb": rss["peak"],
    "rss_avg_kb": rss["avg"],
    "cpu_peak_pct": cpu["peak"],
    "cpu_avg_pct": cpu["avg"],
    "samples": sample_count,
    "missing_samples": sum(1 for sample in (set_series or series) if sample["status"] != "observed"),
    "sample_cadence_s": 1,
    "clock": "monotonic",
    "scope": {"kind": "dynamic_process_set", "includes_descendants": False, "includes_kernel": False},
    "series": series,
    "series_truncated": sample_count > len(series),
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
    "nohup pidstat -p $pid -ru 1 >$outfile 2>&1 & echo \$! >$outfile.handle; cat $outfile.handle"
}

# ---------------------------------------------------------------------------
# remote_stop_footprint NAME ZONE REMOTE_OUTFILE
# Kills the remote sampler (using the handle), fetches OUTFILE, parses it,
# emits JSON on stdout.
# ---------------------------------------------------------------------------
# Sample the sum of every exact-name process in a declared endpoint set. This
# catches short-lived benchmark clients while retaining each observed PID/name.
# Args: NAME ZONE OUTFILE EXACT_NAME...
remote_start_footprint_set() {
  local name="$1" zone="$2" outfile="$3"; shift 3
  local encoded
  encoded=$(python3 - <<'PYEOF'
import base64
program = r'''import os, sys, time
names=set(sys.argv[1:]); previous={}; previous_at=time.monotonic()
while True:
    now=time.monotonic(); current={}; rss=0; included=[]
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit(): continue
        try:
            stat=open(entry.path+'/stat').read().split(); comm=stat[1][1:-1]
            if comm not in names: continue
            pid=int(entry.name); ticks=int(stat[13])+int(stat[14])
            pages=int(open(entry.path+'/statm').read().split()[1])
            current[pid]=ticks; rss += pages*os.sysconf('SC_PAGE_SIZE')//1024
            included.append(f'{pid}:{comm}')
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError): pass
    shared=set(current)&set(previous); elapsed=now-previous_at
    cpu=(sum(max(0, current[p]-previous[p]) for p in shared)/os.sysconf('SC_CLK_TCK')/elapsed*100) if shared and elapsed>0 else None
    observed=bool(current)
    # RSS is valid whenever a matching process exists. CPU needs two snapshots
    # of a PID, so preserve the boundary RSS sample and mark it partial instead
    # of discarding both values.
    print('RSSET', round(now*1000), rss if observed else 'null', f'{cpu:.2f}' if cpu is not None else 'null', ','.join(sorted(included)), flush=True)
    previous=current; previous_at=now; time.sleep(1)
'''
print(base64.b64encode(program.encode()).decode())
PYEOF
)
  local quoted_names=""
  printf -v quoted_names ' %q' "$@"
  ssh_cmd "$name" "$zone" "echo $encoded | base64 -d >/tmp/rs-footprint-set.py; nohup python3 -u /tmp/rs-footprint-set.py$quoted_names >$outfile 2>&1 & echo \$! >$outfile.handle; cat $outfile.handle"
}

remote_stop_footprint() {
  local name="$1" zone="$2" outfile="$3"
  local handle
  handle=$(ssh_cmd "$name" "$zone" "cat $outfile.handle 2>/dev/null || true" 2>/dev/null)
  if [[ -n "$handle" ]]; then
    ssh_cmd "$name" "$zone" "kill $handle 2>/dev/null" 2>/dev/null || true
  fi
  # Fetch the pidstat output via ssh (cat) instead of scp.
  local local_copy
  local_copy=$(mktemp /tmp/footprint.XXXXXX)
  ssh_cmd "$name" "$zone" "cat $outfile 2>/dev/null" > "$local_copy" 2>/dev/null || true
  local status=0
  stop_footprint 0 "$local_copy" || status=$?
  rm -f "$local_copy"
  return "$status"
}
