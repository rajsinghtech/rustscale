#!/usr/bin/env bash
# Native embedded-Rust RSB1 P1/P10/P100 baseline.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT"
# shellcheck source=./lib.sh
source tools/bench/lib.sh

DURATION="${BENCH_DURATION:-10}"
REPEAT="${BENCH_REPEAT:-1}"
EXPECTED_PATH="${BENCH_EXPECT_PATH:-any}"
INTER_TRIAL_GAP="${BENCH_INTER_TRIAL_GAP:-10}"
PORT="${BENCH_PORT:-5201}"
PARALLELS=(1 10 100 500 1000)
[[ "$DURATION" =~ ^[1-9][0-9]*$ && "$DURATION" -le 120 ]] || { echo "invalid BENCH_DURATION" >&2; exit 2; }
[[ "$REPEAT" =~ ^[1-9]$ ]] || { echo "invalid BENCH_REPEAT" >&2; exit 2; }
[[ "$INTER_TRIAL_GAP" =~ ^[1-9][0-9]*$ && "$INTER_TRIAL_GAP" -le 60 ]] || { echo "invalid BENCH_INTER_TRIAL_GAP" >&2; exit 2; }
[[ "$PORT" =~ ^[1-9][0-9]*$ && "$PORT" -le 65535 ]] || { echo "invalid BENCH_PORT" >&2; exit 2; }
[[ "$EXPECTED_PATH" == any || "$EXPECTED_PATH" == direct || "$EXPECTED_PATH" == derp ]] || { echo "BENCH_EXPECT_PATH must be any, direct, or derp" >&2; exit 2; }
for name in cargo curl jq python3 sha256sum; do command -v "$name" >/dev/null || { echo "missing command: $name" >&2; exit 2; }; done

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
[[ "$TARGET_DIR" == /* ]] || TARGET_DIR="$ROOT/$TARGET_DIR"
BENCH_BIN="$TARGET_DIR/release/rustscale-bench"
SERVER_LOG="$(mktemp "${TMPDIR:-/tmp}/rs-native-server.XXXXXX")"
CLIENT_LOG="$(mktemp "${TMPDIR:-/tmp}/rs-native-client.XXXXXX")"
TRIALS="$(mktemp "${TMPDIR:-/tmp}/rs-native-trials.XXXXXX")"
SERVER_PID=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  [[ -z "$SERVER_PID" ]] || { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
  rm -rf "$SERVER_LOG" "$CLIENT_LOG" "$TRIALS"
  if ! bench_cleanup_tailnet; then [[ "$status" -ne 0 ]] || status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

validate_throughput() {
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
r=json.loads(sys.argv[1]); p=int(sys.argv[2]); path=sys.argv[3]
assert r.get("tool")=="rustscale-bench" and r.get("transport")=="userspace-tsnet", r
assert r.get("protocol")=="RSB1" and r.get("direction")=="down", r
assert r.get("parallel")==p, r
if path!="warmup":
    assert r.get("path_class") in ("direct","derp","relay"), r
    assert path=="any" or r.get("path_class")==path, r
for key in ("established","handshaken","completed"):
    assert r.get(key)==p, (key,r.get(key),p)
assert float(r.get("total_mbps",0))>0 and int(r.get("total_bytes",0))>0, r
PY
}

if [[ "${1:-}" == --self-test ]]; then
  throughput='{"tool":"rustscale-bench","transport":"userspace-tsnet","protocol":"RSB1","direction":"down","parallel":100,"path_class":"direct","established":100,"handshaken":100,"completed":100,"total_mbps":1.0,"total_bytes":1}'
  validate_throughput "$throughput" 100 direct
  if validate_throughput "$throughput" 99 direct >/dev/null 2>&1; then exit 1; fi
  echo "native baseline self-test: OK"
  exit 0
fi
[[ $# -eq 0 ]] || { echo "usage: tools/bench/run-native-baseline.sh [--self-test]" >&2; exit 2; }

run_client() {
  local parallel="$1" duration="$2" label="$3"
  "$BENCH_BIN" client --authkey "$AUTHKEY" --target "$SERVER_IP:$PORT" \
    --duration "$duration" --direction down --parallel "$parallel" \
    --hostname "rs-native-$label" --json 2>"$CLIENT_LOG"
}

echo "[native-baseline] building native release rustscale-bench" >&2
cargo build -p rustscale-bench --release
binary_sha="$(sha256sum "$BENCH_BIN" | awk '{print $1}')"
if [[ "${RUSTSCALE_REMOTE_EVIDENCE:-0}" == 1 ]]; then
  printf 'RUSTSCALE_REMOTE\tfact.baseline_binary_sha256\t%s\n' "$binary_sha"
fi
bench_provision_tailnet
# bench_provision_tailnet installs its own cleanup; extend it with process and
# temporary-state cleanup for this runner.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
AUTHKEY="$(bench_mint_authkey true)"

"$BENCH_BIN" server --authkey "$AUTHKEY" --port "$PORT" \
  --hostname rs-native-server >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 180); do
  if grep -q '^BENCH_READY 1$' "$SERVER_LOG"; then
    SERVER_IP="$(awk '$1 == "BENCH_IP" {print $2; exit}' "$SERVER_LOG")"
    [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || {
    echo "server exited before ready" >&2
    tail -n 30 "$SERVER_LOG" >&2 || true
    exit 1
  }
  sleep 1
done
[[ "${SERVER_IP:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "server readiness timed out" >&2
  tail -n 30 "$SERVER_LOG" >&2 || true
  exit 1
}

echo "[native-baseline] warmup P1" >&2
if ! warmup="$(run_client 1 3 warmup 2>/dev/null)" || ! validate_throughput "$warmup" 1 warmup; then
  echo "warmup failed" >&2
  tail -n 30 "$CLIENT_LOG" >&2 || true
  tail -n 30 "$SERVER_LOG" >&2 || true
  exit 1
fi
sleep "$INTER_TRIAL_GAP"

for parallel in "${PARALLELS[@]}"; do
  for repeat in $(seq 1 "$REPEAT"); do
    echo "[native-baseline] P$parallel repeat $repeat/$REPEAT" >&2
    if ! result="$(run_client "$parallel" "$DURATION" "p$parallel-r$repeat")"; then
      echo "P$parallel client failed" >&2
      tail -n 30 "$CLIENT_LOG" >&2 || true
      exit 1
    fi
    validate_throughput "$result" "$parallel" "$EXPECTED_PATH"
    printf '%s\n' "$result" >>"$TRIALS"
    if [[ "${RUSTSCALE_REMOTE_EVIDENCE:-0}" == 1 ]]; then
      python3 - "$result" <<'PY'
import json,sys
r=json.loads(sys.argv[1])
print(f"RUSTSCALE_REMOTE\tfact.baseline_p{r['parallel']}_mbps\t{r['total_mbps']}")
print(f"RUSTSCALE_REMOTE\tfact.baseline_p{r['parallel']}_path\t{r['path_class']}")
PY
    fi
    sleep "$INTER_TRIAL_GAP"
  done
done

summary="$(python3 - "$TRIALS" "$DURATION" "$REPEAT" "$binary_sha" <<'PY'
import json,statistics,sys
rows=[json.loads(x) for x in open(sys.argv[1]) if x.strip()]; points=[]
for p in (1,10,100):
    selected=[r for r in rows if r["parallel"]==p]
    vals=[float(r["total_mbps"]) for r in selected]
    paths=[r["path_class"] for r in selected]
    points.append({"parallel":p,"mbps":vals,"median_mbps":statistics.median(vals),"paths":paths,"setup_attempts":[1] * len(selected)})
paths=sorted(set(path for point in points for path in point["paths"]))
print(json.dumps({"schema_version":1,"tool":"rustscale-bench","mode":"embedded-rust-tsnet","identity_scope":"one-ephemeral-client-per-trial","duration_s":int(sys.argv[2]),"repeats":int(sys.argv[3]),"paths":paths,"points":points,"binary_sha256":sys.argv[4]},separators=(",",":")))
PY
)"
printf '%s\n' "$summary"
if [[ "${RUSTSCALE_REMOTE_EVIDENCE:-0}" == 1 ]]; then
  python3 - "$summary" <<'PY'
import json,sys
r=json.loads(sys.argv[1]); print("RUSTSCALE_REMOTE\tfact.baseline_paths\t"+",".join(r["paths"]))
for p in r["points"]: print(f"RUSTSCALE_REMOTE\tfact.baseline_p{p['parallel']}_mbps\t{p['median_mbps']}")
print("RUSTSCALE_REMOTE\tfact.baseline_binary_sha256\t"+r["binary_sha256"])
PY
fi
