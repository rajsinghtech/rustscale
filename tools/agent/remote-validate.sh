#!/usr/bin/env bash
# Safe, optional validation on a disposable remote source tree.
# Usage:
#   tools/agent/remote-validate.sh preflight
#   tools/agent/remote-validate.sh check [package]
#   tools/agent/remote-validate.sh interop
#   tools/agent/remote-validate.sh tun --allow-privileged
#   tools/agent/remote-validate.sh install --allow-privileged --allow-install
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel)"
DEFAULT_TARGET="ubuntu@raj-builder"
TARGET="${RUSTSCALE_REMOTE_TARGET:-$DEFAULT_TARGET}"
DISABLED="${RUSTSCALE_REMOTE_DISABLE:-0}"
MODE="${1:-preflight}"
[[ $# -eq 0 ]] || shift
PACKAGE=""
ALLOW_PRIVILEGED=0
ALLOW_INSTALL=0

usage() {
  cat >&2 <<'EOF'
usage:
  tools/agent/remote-validate.sh preflight
  tools/agent/remote-validate.sh check [package]
  tools/agent/remote-validate.sh interop
  tools/agent/remote-validate.sh tun --allow-privileged
  tools/agent/remote-validate.sh install --allow-privileged --allow-install

environment:
  RUSTSCALE_REMOTE_TARGET       SSH destination (default: ubuntu@raj-builder)
  RUSTSCALE_REMOTE_DISABLE=1    record a disabled result without connecting
  RUSTSCALE_REMOTE_TIMEOUT      positive command deadline in seconds
EOF
  exit 2
}

fail() {
  echo "[remote-validate] $*" >&2
  exit 1
}

positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

case "$DISABLED" in
  0|1) ;;
  *) fail "RUSTSCALE_REMOTE_DISABLE must be 0 or 1" ;;
esac

case "$MODE" in
  -h|--help|help) usage ;;
  preflight|interop) ;;
  check)
    if [[ $# -gt 0 && "${1:-}" != --* ]]; then
      PACKAGE="$1"
      shift
    fi
    ;;
  tun|install) ;;
  *) usage ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-privileged) ALLOW_PRIVILEGED=1 ;;
    --allow-install) ALLOW_INSTALL=1 ;;
    *) usage ;;
  esac
  shift
done

if [[ -n "$PACKAGE" && ! "$PACKAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  fail "invalid package name"
fi
if [[ "$MODE" == tun && "$ALLOW_PRIVILEGED" != 1 ]]; then
  fail "tun requires the explicit --allow-privileged flag"
fi
if [[ "$MODE" == install ]]; then
  [[ "$ALLOW_PRIVILEGED" == 1 ]] \
    || fail "install requires the explicit --allow-privileged flag"
  [[ "$ALLOW_INSTALL" == 1 ]] \
    || fail "install requires the additional --allow-install flag"
fi
if [[ "$MODE" != tun && "$MODE" != install && "$ALLOW_PRIVILEGED" == 1 ]]; then
  fail "--allow-privileged is valid only for tun or install"
fi
if [[ "$MODE" != install && "$ALLOW_INSTALL" == 1 ]]; then
  fail "--allow-install is valid only for install"
fi

case "$MODE" in
  preflight) DEFAULT_TIMEOUT=120 ;;
  check) DEFAULT_TIMEOUT=3600 ;;
  interop|tun) DEFAULT_TIMEOUT=2400 ;;
  install) DEFAULT_TIMEOUT=1200 ;;
esac
DEADLINE="${RUSTSCALE_REMOTE_TIMEOUT:-$DEFAULT_TIMEOUT}"
CONNECT_TIMEOUT="${RUSTSCALE_REMOTE_CONNECT_TIMEOUT:-10}"
MIN_MEMORY_MIB="${RUSTSCALE_REMOTE_MIN_MEMORY_MIB:-4096}"
MIN_DISK_MIB="${RUSTSCALE_REMOTE_MIN_DISK_MIB:-10240}"
for value in "$DEADLINE" "$CONNECT_TIMEOUT" "$MIN_MEMORY_MIB" "$MIN_DISK_MIB"; do
  positive_integer "$value" || fail "timeouts and resource thresholds must be positive integers"
done
(( DEADLINE <= 86400 )) || fail "remote command timeout exceeds the 86400 second safety limit"
(( CONNECT_TIMEOUT <= 60 )) || fail "SSH connect timeout exceeds the 60 second safety limit"

for command_name in git python3; do
  command -v "$command_name" >/dev/null 2>&1 \
    || fail "required local command '$command_name' is unavailable"
done

RESULT_ROOT="$ROOT/.agent-runs/remote-validation"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RESULT_FILE="$RESULT_ROOT/$RUN_ID.json"
mkdir -p "$RESULT_ROOT"
git -C "$ROOT" check-ignore --quiet "$RESULT_FILE" \
  || fail "refusing to write remote provenance outside an ignored path"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/rustscale-remote-local.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOCAL_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
INDEX_TREE="$(git -C "$ROOT" write-tree)" \
  || fail "the git index is not a reviewable tree"
UNTRACKED_COUNT="$(git -C "$ROOT" ls-files --others --exclude-standard -z | python3 -c 'import sys; print(sys.stdin.buffer.read().count(b"\0"))')"
WORKTREE_DIFF="$TMP/worktree.diff"
FULL_DIFF="$TMP/full.diff"
git -C "$ROOT" diff --no-ext-diff --binary --full-index -- . >"$WORKTREE_DIFF"
git -C "$ROOT" diff --no-ext-diff --binary --full-index HEAD -- . >"$FULL_DIFF"

hash_file() {
  python3 - "$1" <<'PYEOF'
import hashlib
import sys
value = hashlib.sha256()
with open(sys.argv[1], "rb") as handle:
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        value.update(block)
print(value.hexdigest())
PYEOF
}

DIFF_SHA256="$(hash_file "$FULL_DIFF")"

write_result() {
  local status="$1" exit_code="$2" cleanup="$3" source_tree="$4" archive_sha="$5" output="$6"
  local ended_at
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 - "$RESULT_FILE" "$RUN_ID" "$MODE" "$status" "$exit_code" "$cleanup" \
    "$TARGET" "$STARTED_AT" "$ended_at" "$DEADLINE" "$LOCAL_COMMIT" \
    "$INDEX_TREE" "$DIFF_SHA256" "$source_tree" "$archive_sha" \
    "$UNTRACKED_COUNT" "$ALLOW_PRIVILEGED" "$ALLOW_INSTALL" "$output" <<'PYEOF'
import json
import os
import sys

(
    path, run_id, mode, status, exit_code, cleanup, target, started_at,
    ended_at, deadline, commit, index_tree, diff_sha256, source_tree,
    archive_sha256, untracked_count, privileged, install, output_path,
) = sys.argv[1:]
facts = {}
missing_required = []
missing_optional = []
bootstrap = []
if output_path and os.path.exists(output_path):
    with open(output_path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            fields = raw.rstrip("\n").split("\t", 2)
            if len(fields) < 2 or fields[0] != "RUSTSCALE_REMOTE":
                continue
            kind = fields[1]
            value = fields[2] if len(fields) == 3 else ""
            if kind.startswith("fact."):
                facts[kind[5:]] = value
            elif kind == "missing.required" and value not in missing_required:
                missing_required.append(value)
            elif kind == "missing.optional" and value not in missing_optional:
                missing_optional.append(value)
            elif kind == "bootstrap" and value not in bootstrap:
                bootstrap.append(value)

data = {
    "schema_version": 1,
    "run_id": run_id,
    "mode": mode,
    "status": status,
    "exit_code": int(exit_code),
    "cleanup": cleanup,
    "target": target,
    "started_at": started_at,
    "ended_at": ended_at,
    "timeout_seconds": int(deadline),
    "source": {
        "commit": commit,
        "index_tree": index_tree,
        "diff_sha256": diff_sha256,
        "candidate_tree": source_tree or None,
        "archive_sha256": archive_sha256 or None,
        "untracked_files_excluded": int(untracked_count),
    },
    "privileged_opt_in": privileged == "1",
    "install_opt_in": install == "1",
    "remote_facts": facts,
    "missing_required": missing_required,
    "missing_optional": missing_optional,
    "bootstrap_commands": bootstrap,
}
temporary = path + ".tmp"
with open(temporary, "w", encoding="ascii") as handle:
    json.dump(data, handle, sort_keys=True, indent=2)
    handle.write("\n")
os.replace(temporary, path)
PYEOF
  printf '[remote-validate] result: .agent-runs/remote-validation/%s.json\n' "$RUN_ID" >&2
}

if [[ "$DISABLED" == 1 ]]; then
  write_result disabled 0 not_started "" "" ""
  echo "[remote-validate] remote validation is explicitly disabled" >&2
  exit 0
fi

for command_name in ssh tar tee; do
  command -v "$command_name" >/dev/null 2>&1 \
    || fail "required local command '$command_name' is unavailable"
done

# Keep the SSH destination an operand, never an option or shell fragment. More
# elaborate routing belongs in the user's normal OpenSSH configuration.
if [[ ! "$TARGET" =~ ^([A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  fail "invalid RUSTSCALE_REMOTE_TARGET; use a user@host or SSH config alias"
fi

CANDIDATE_INDEX="$TMP/candidate.index"
GIT_INDEX_FILE="$CANDIDATE_INDEX" git -C "$ROOT" read-tree "$INDEX_TREE"
if [[ -s "$WORKTREE_DIFF" ]]; then
  GIT_INDEX_FILE="$CANDIDATE_INDEX" git -C "$ROOT" apply --cached --binary \
    --whitespace=nowarn "$WORKTREE_DIFF" \
    || fail "could not apply the explicit working-tree diff to the reviewed index"
fi
CANDIDATE_TREE="$(GIT_INDEX_FILE="$CANDIDATE_INDEX" git -C "$ROOT" write-tree)"
PATH_LIST="$TMP/candidate-paths"
git -C "$ROOT" ls-tree -rz --name-only "$CANDIDATE_TREE" >"$PATH_LIST"
python3 - "$PATH_LIST" <<'PYEOF' || fail "candidate tree contains a prohibited secret or generated path"
import pathlib
import sys

blocked_components = {".git", "target", ".agent-runs", ".worktrees", ".secrets", "secrets"}
blocked_names = {
    ".env", "credentials", "credentials.json", "id_rsa", "id_ed25519",
    "known_hosts", "authorized_keys",
}
blocked_suffixes = (".pem", ".key", ".p12", ".pfx", ".kdbx")
raw = pathlib.Path(sys.argv[1]).read_bytes()
for encoded in raw.split(b"\0"):
    if not encoded:
        continue
    path = encoded.decode("utf-8", "surrogateescape")
    parts = [part.lower() for part in pathlib.PurePosixPath(path).parts]
    name = parts[-1]
    prohibited = (
        any(part in blocked_components for part in parts)
        or name in blocked_names
        or name.startswith(".env.")
        or name.endswith(blocked_suffixes)
    )
    if prohibited:
        print(f"[remote-validate] prohibited candidate path: {path}", file=sys.stderr)
        raise SystemExit(1)
PYEOF

SOURCE_TAR="$TMP/source.tar"
git -C "$ROOT" archive --format=tar --output="$SOURCE_TAR" "$CANDIDATE_TREE"
ARCHIVE_SHA256="$(hash_file "$SOURCE_TAR")"

# Detect a checkout changing while the snapshot was assembled. The archive is
# sent only when HEAD, the index tree, and the explicit unstaged diff are still
# exactly the inputs recorded above.
AFTER_DIFF="$TMP/worktree-after.diff"
git -C "$ROOT" diff --no-ext-diff --binary --full-index -- . >"$AFTER_DIFF"
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$LOCAL_COMMIT" ]] \
  || fail "HEAD changed while assembling the remote source snapshot"
[[ "$(git -C "$ROOT" write-tree)" == "$INDEX_TREE" ]] \
  || fail "the git index changed while assembling the remote source snapshot"
[[ "$(hash_file "$AFTER_DIFF")" == "$(hash_file "$WORKTREE_DIFF")" ]] \
  || fail "the working tree changed while assembling the remote source snapshot"

CONTROL="$TMP/control"
mkdir -p "$CONTROL"
cp "$SOURCE_TAR" "$CONTROL/source.tar"
cat >"$CONTROL/runner.sh" <<'REMOTE_RUNNER'
#!/usr/bin/env bash
set -u

ROOT=$1
MODE=$2
PACKAGE=$3
MIN_MEMORY_MIB=$4
MIN_DISK_MIB=$5
SOURCE="$ROOT/source"
CACHE="$ROOT/cache"

clean_value() {
  printf '%s' "$1" | tr '\t\r\n' '   ' | cut -c1-300
}
emit() {
  printf 'RUSTSCALE_REMOTE\t%s\t%s\n' "$1" "$(clean_value "${2:-}")"
}
has() {
  command -v "$1" >/dev/null 2>&1
}
add_required() {
  local value=$1 existing
  for existing in "${MISSING_REQUIRED[@]:-}"; do
    [[ "$existing" == "$value" ]] && return
  done
  MISSING_REQUIRED+=("$value")
  emit missing.required "$value"
}
add_optional() {
  local value=$1 existing
  for existing in "${MISSING_OPTIONAL[@]:-}"; do
    [[ "$existing" == "$value" ]] && return
  done
  MISSING_OPTIONAL+=("$value")
  emit missing.optional "$value"
}

MISSING_REQUIRED=()
MISSING_OPTIONAL=()
PATH="${PATH:-}:$HOME/.cargo/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
unset SSH_AUTH_SOCK GH_TOKEN GITHUB_TOKEN OPENAI_API_KEY ANTHROPIC_API_KEY \
  AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN GOOGLE_APPLICATION_CREDENTIALS \
  AZURE_CLIENT_SECRET || true

os_name=$(uname -s 2>/dev/null || printf unknown)
arch=$(uname -m 2>/dev/null || printf unknown)
kernel=$(uname -r 2>/dev/null || printf unknown)
os_id=unknown
os_version=unknown
os_pretty=unknown
if [[ -r /etc/os-release ]]; then
  os_id=$(sed -n 's/^ID=//p' /etc/os-release | sed -n '1p' | tr -d '"')
  os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | sed -n '1p' | tr -d '"')
  os_pretty=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | sed -n '1p' | tr -d '"')
elif has lsb_release; then
  os_id=$(lsb_release -is 2>/dev/null || printf unknown)
  os_version=$(lsb_release -rs 2>/dev/null || printf unknown)
  os_pretty="$os_id $os_version"
fi
cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || printf 0)
if [[ -r /proc/meminfo ]]; then
  memory_kib=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)
elif has free; then
  memory_kib=$(free -k | awk '/^Mem:/ {print $2; exit}')
else
  memory_kib=0
fi
disk_kib=$(df -Pk "$ROOT" 2>/dev/null | awk 'NR == 2 {print $4; exit}')

# Workspace acceptance includes a 1,000-stream barrier test that needs more
# than the common SSH-session soft limit of 1,024 descriptors. Raise only this
# ephemeral runner's soft limit, never the host hard limit or persistent state.
nofile_soft=$(ulimit -Sn 2>/dev/null || printf unknown)
nofile_hard=$(ulimit -Hn 2>/dev/null || printf unknown)
nofile_target=65536
if [[ "$nofile_hard" =~ ^[0-9]+$ ]] && (( nofile_hard < nofile_target )); then
  nofile_target=$nofile_hard
elif [[ "$nofile_hard" != unlimited && ! "$nofile_hard" =~ ^[0-9]+$ ]]; then
  nofile_target=0
fi
if [[ "$nofile_soft" =~ ^[0-9]+$ ]] && (( nofile_target > nofile_soft )); then
  ulimit -Sn "$nofile_target" 2>/dev/null || true
  nofile_soft=$(ulimit -Sn 2>/dev/null || printf unknown)
fi

emit fact.os "$os_name"
emit fact.os_id "${os_id:-unknown}"
emit fact.os_version "${os_version:-unknown}"
emit fact.os_pretty "${os_pretty:-unknown}"
emit fact.kernel "$kernel"
emit fact.arch "$arch"
emit fact.cpu_count "${cpus:-0}"
emit fact.memory_kib "${memory_kib:-0}"
emit fact.disk_available_kib "${disk_kib:-0}"
emit fact.open_files_soft "$nofile_soft"
emit fact.open_files_hard "$nofile_hard"

[[ "$os_name" == Linux ]] || add_required "Linux operating system"
case "$arch" in
  aarch64|arm64|x86_64|amd64) ;;
  *) add_required "supported Linux architecture (aarch64 or x86_64)" ;;
esac
[[ "${cpus:-}" =~ ^[1-9][0-9]*$ ]] || add_required "online CPU information"
if [[ ! "${memory_kib:-}" =~ ^[0-9]+$ ]] \
    || (( memory_kib < MIN_MEMORY_MIB * 1024 )); then
  add_required "at least ${MIN_MEMORY_MIB} MiB memory"
fi
if [[ ! "${disk_kib:-}" =~ ^[0-9]+$ ]] \
    || (( disk_kib < MIN_DISK_MIB * 1024 )); then
  add_required "at least ${MIN_DISK_MIB} MiB free disk"
fi
if [[ "$nofile_soft" != unlimited ]] \
    && { [[ ! "$nofile_soft" =~ ^[0-9]+$ ]] || (( nofile_soft < 4096 )); }; then
  add_required "soft open-file limit of at least 4096"
  emit bootstrap "Raise the SSH session soft open-file limit to at least 4096 (for example: ulimit -Sn 65536)"
fi

SYSTEM_BOOTSTRAP=0
for command_name in bash git tar timeout setsid sha256sum python3; do
  if ! has "$command_name"; then
    add_required "$command_name"
    SYSTEM_BOOTSTRAP=1
  fi
done
for command_name in cc pkg-config cmake curl; do
  if ! has "$command_name"; then
    add_required "$command_name"
    SYSTEM_BOOTSTRAP=1
  fi
done

if has cargo; then
  emit fact.cargo "$(cargo --version 2>/dev/null || printf unusable)"
else
  add_required cargo
fi
if has rustc; then
  emit fact.rustc "$(rustc --version 2>/dev/null || printf unusable)"
else
  add_required rustc
fi
if ! cargo clippy --version >/dev/null 2>&1; then
  add_required "rustup component clippy"
fi
if ! cargo fmt --version >/dev/null 2>&1; then
  add_required "rustup component rustfmt"
fi

if has go; then
  emit fact.go "$(go version 2>/dev/null || printf unusable)"
else
  add_optional go
fi
if has docker; then
  emit fact.docker "$(docker --version 2>/dev/null || printf unusable)"
else
  add_optional docker
fi
for command_name in tailscale tailscaled jq ip sudo systemctl; do
  has "$command_name" || add_optional "$command_name"
done

case "$MODE" in
  interop)
    for command_name in tailscale tailscaled jq curl python3; do
      has "$command_name" || add_required "$command_name"
    done
    ;;
  tun)
    for command_name in tailscale tailscaled jq curl python3 ip sudo; do
      has "$command_name" || add_required "$command_name"
    done
    [[ -c /dev/net/tun ]] || add_required /dev/net/tun
    sudo -n true >/dev/null 2>&1 || add_required "passwordless sudo"
    ;;
  install)
    has go || add_required go
    for command_name in ip sudo systemctl; do
      has "$command_name" || add_required "$command_name"
    done
    [[ -c /dev/net/tun ]] || add_required /dev/net/tun
    sudo -n true >/dev/null 2>&1 || add_required "passwordless sudo"
    ;;
esac

if (( SYSTEM_BOOTSTRAP == 1 )) || ! has cargo || ! has rustc \
    || ! cargo clippy --version >/dev/null 2>&1 \
    || ! cargo fmt --version >/dev/null 2>&1; then
  emit bootstrap "sudo apt-get update"
  emit bootstrap "sudo apt-get install --yes build-essential pkg-config libssl-dev clang cmake curl ca-certificates git python3 tar coreutils util-linux"
fi
if ! has cargo || ! has rustc || ! cargo clippy --version >/dev/null 2>&1 \
    || ! cargo fmt --version >/dev/null 2>&1; then
  emit bootstrap "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable"
  emit bootstrap '. "$HOME/.cargo/env"'
  emit bootstrap "rustup component add clippy rustfmt"
fi
if ! has go; then
  case "$arch" in aarch64|arm64) go_arch=arm64 ;; *) go_arch=amd64 ;; esac
  emit bootstrap "GO_VERSION=go1.26.4; GO_ARCH=$go_arch; GO_ARCHIVE=\"\${GO_VERSION}.linux-\${GO_ARCH}.tar.gz\""
  emit bootstrap "curl -fsSL 'https://go.dev/dl/?mode=json&include=all' -o /tmp/go-releases.json"
  emit bootstrap "GO_SHA256=\$(python3 -c 'import json,sys; n=sys.argv[1]; print(next(f[\"sha256\"] for r in json.load(open(sys.argv[2])) for f in r[\"files\"] if f[\"filename\"] == n))' \"\$GO_ARCHIVE\" /tmp/go-releases.json)"
  emit bootstrap "curl -fsSLo \"/tmp/\$GO_ARCHIVE\" \"https://go.dev/dl/\$GO_ARCHIVE\""
  emit bootstrap "printf '%s  %s\\n' \"\$GO_SHA256\" \"/tmp/\$GO_ARCHIVE\" | sha256sum -c -"
  emit bootstrap "sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf \"/tmp/\$GO_ARCHIVE\""
  emit bootstrap "export PATH=/usr/local/go/bin:\$PATH; go version"
fi
if ! has docker; then
  emit bootstrap "sudo apt-get install --yes docker.io"
fi
if ! has ip || ! has jq; then
  emit bootstrap "sudo apt-get install --yes iproute2 jq"
fi
if ! has tailscale || ! has tailscaled; then
  os_codename=unknown
  if [[ -r /etc/os-release ]]; then
    os_codename=$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release | sed -n '1p' | tr -d '"')
  fi
  if [[ "$os_id" == ubuntu && "$os_codename" =~ ^[a-z0-9]+$ ]]; then
    emit bootstrap "curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$os_codename.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null"
    emit bootstrap "curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$os_codename.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list"
    emit bootstrap "sudo apt-get update && sudo apt-get install --yes tailscale"
  else
    emit bootstrap "Install the admin-approved Tailscale package, then verify: tailscale version && tailscaled --version"
  fi
fi

if (( ${#MISSING_REQUIRED[@]} > 0 )); then
  emit status blocked
  exit 3
fi
if [[ "$MODE" == preflight ]]; then
  emit status ready
  exit 0
fi

mkdir -p "$CACHE/cargo" "$CACHE/go-build" "$CACHE/go-mod" "$CACHE/gopath" \
  "$CACHE/sccache" "$ROOT/tmp" "$ROOT/home-cache" "$ROOT/home-config" "$ROOT/home-data"
COMMON_ENV=(
  "HOME=$HOME"
  "USER=${USER:-remote}"
  "LOGNAME=${LOGNAME:-${USER:-remote}}"
  "PATH=$PATH"
  "LANG=C.UTF-8"
  "LC_ALL=C.UTF-8"
  "TMPDIR=$ROOT/tmp"
  "CARGO_HOME=$CACHE/cargo"
  "CARGO_TARGET_DIR=$ROOT/target"
  "RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}"
  "GOCACHE=$CACHE/go-build"
  "GOMODCACHE=$CACHE/go-mod"
  "GOPATH=$CACHE/gopath"
  "SCCACHE_DIR=$CACHE/sccache"
  "XDG_CACHE_HOME=$ROOT/home-cache"
  "XDG_CONFIG_HOME=$ROOT/home-config"
  "XDG_DATA_HOME=$ROOT/home-data"
)
COMMAND=()
case "$MODE" in
  check)
    COMMAND=(bash tools/check.sh)
    [[ -z "$PACKAGE" ]] || COMMAND+=("$PACKAGE")
    ;;
  interop)
    COMMAND=(bash tools/interop.sh)
    ;;
  tun)
    COMMAND=(bash tools/interop-tun.sh)
    ;;
  install)
    COMMON_ENV+=("RUSTSCALE_REQUIRE_LINUX_REPLACEMENT=1" "RUSTSCALE_LINUX_REPLACEMENT_TIMEOUT=900")
    COMMAND=(bash tools/packaging/test-linux-replacement.sh)
    ;;
esac

# Credential-free modes get an empty environment apart from build/runtime
# necessities. Explicit interop modes may consume only remote-side Tailscale
# credentials already present in sshd's environment; no local values arrive.
if [[ "$MODE" == interop || "$MODE" == tun ]]; then
  for name in TS_ORG_TOKEN TS_ORG_CLIENT_ID TS_ORG_CLIENT_SECRET; do
    if [[ -n "${!name:-}" ]]; then
      COMMON_ENV+=("$name=${!name}")
    fi
  done
fi

cd "$SOURCE" || exit 1
set +e
env -i "${COMMON_ENV[@]}" "${COMMAND[@]}"
command_status=$?
set -e
if (( command_status == 0 )); then
  emit status passed
else
  emit status failed
fi
exit "$command_status"
REMOTE_RUNNER
chmod 700 "$CONTROL/runner.sh"
BUNDLE="$TMP/bundle.tar"
tar --no-xattrs -cf "$BUNDLE" -C "$CONTROL" source.tar runner.sh

REMOTE_ENTRY=$(cat <<'REMOTE_ENTRY'
set -u
mode=$1
package=$2
deadline=$3
archive_sha=$4
min_memory_mib=$5
min_disk_mib=$6
root=
child=
cleanup_done=0
cleanup() {
  local rc=0
  if [[ -n "$child" ]]; then
    kill -TERM -- "-$child" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 -- "-$child" 2>/dev/null || break
      sleep 0.2
    done
    kill -KILL -- "-$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  if [[ -n "$root" ]]; then
    cd / 2>/dev/null || true
    rm -rf -- "$root" || rc=1
    [[ ! -e "$root" ]] || rc=1
  fi
  cleanup_done=1
  return "$rc"
}
on_signal() {
  local rc=$1
  trap - EXIT HUP INT TERM PIPE
  cleanup || true
  exit "$rc"
}
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
trap 'on_signal 141' PIPE
trap 'rc=$?; cleanup || rc=74; exit "$rc"' EXIT

for command_name in bash tar timeout setsid sha256sum mktemp rm; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'RUSTSCALE_REMOTE\tmissing.required\t%s\n' "$command_name"
    exit 69
  }
done
umask 077
root=$(mktemp -d "${TMPDIR:-/tmp}/rustscale-remote.XXXXXXXX") || exit 70
mkdir -p "$root/control" "$root/source"
tar -xf - -C "$root/control" || exit 71
actual_sha=$(sha256sum "$root/control/source.tar" | awk '{print $1}')
[[ "$actual_sha" == "$archive_sha" ]] || {
  printf 'RUSTSCALE_REMOTE\tfact.archive_integrity\tmismatch\n'
  exit 72
}
printf 'RUSTSCALE_REMOTE\tfact.archive_integrity\tverified\n'
tar -xf "$root/control/source.tar" -C "$root/source" || exit 73
for forbidden in .git target .agent-runs .worktrees .secrets secrets; do
  if find "$root/source" -name "$forbidden" -print -quit | grep -q .; then
    printf 'RUSTSCALE_REMOTE\tmissing.required\tprohibited archive path\n'
    exit 73
  fi
done
setsid timeout --signal=TERM --kill-after=30s "${deadline}s" \
  bash "$root/control/runner.sh" "$root" "$mode" "$package" \
    "$min_memory_mib" "$min_disk_mib" &
child=$!
set +e
wait "$child"
rc=$?
set -e
cleanup || rc=74
trap - EXIT HUP INT TERM PIPE
if (( cleanup_done == 1 && rc != 74 )); then
  printf 'RUSTSCALE_REMOTE\tcleanup\tok\n'
else
  printf 'RUSTSCALE_REMOTE\tcleanup\tfailed\n'
fi
exit "$rc"
REMOTE_ENTRY
)

shell_quote() {
  local value=$1
  value=${value//\'/\'\\\'\'}
  printf "'%s'" "$value"
}
REMOTE_COMMAND="bash -c $(shell_quote "$REMOTE_ENTRY") -- $(shell_quote "$MODE") $(shell_quote "$PACKAGE") $(shell_quote "$DEADLINE") $(shell_quote "$ARCHIVE_SHA256") $(shell_quote "$MIN_MEMORY_MIB") $(shell_quote "$MIN_DISK_MIB")"
SSH_OPTIONS=(
  -T
  -o BatchMode=yes
  -o "ConnectTimeout=$CONNECT_TIMEOUT"
  -o ConnectionAttempts=1
  -o StrictHostKeyChecking=yes
  -o ForwardAgent=no
  -o ForwardX11=no
  -o ForwardX11Trusted=no
  -o ClearAllForwardings=yes
  -o PermitLocalCommand=no
  -o ControlMaster=no
  -o ControlPath=none
  -o RequestTTY=no
  -o EscapeChar=none
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=3
)

OUTPUT="$TMP/remote-output"
LOCAL_DEADLINE=$(( DEADLINE + CONNECT_TIMEOUT + 45 ))
set +e
(
  unset OPENAI_API_KEY ANTHROPIC_API_KEY GH_TOKEN GITHUB_TOKEN PI_API_KEY \
    CODEX_API_KEY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN \
    GOOGLE_APPLICATION_CREDENTIALS AZURE_CLIENT_SECRET || true
  python3 "$SCRIPT_DIR/run-with-deadline.py" "$LOCAL_DEADLINE" -- \
    ssh "${SSH_OPTIONS[@]}" "$TARGET" "$REMOTE_COMMAND" <"$BUNDLE"
) 2>&1 | tee "$OUTPUT"
REMOTE_STATUS=${PIPESTATUS[0]}
set -e

CLEANUP=unconfirmed
grep -Fq $'RUSTSCALE_REMOTE\tcleanup\tok' "$OUTPUT" && CLEANUP=confirmed
REPORTED_STATUS="$(awk -F '\t' '$1 == "RUSTSCALE_REMOTE" && $2 == "status" {value=$3} END {print value}' "$OUTPUT")"
case "$REMOTE_STATUS:$REPORTED_STATUS" in
  0:ready|0:passed) STATUS="$REPORTED_STATUS" ;;
  3:blocked) STATUS=blocked ;;
  124:*) STATUS=timed_out ;;
  255:*) STATUS=disconnected ;;
  *) STATUS=failed ;;
esac
if [[ "$CLEANUP" != confirmed ]]; then
  STATUS=cleanup_unconfirmed
fi
write_result "$STATUS" "$REMOTE_STATUS" "$CLEANUP" "$CANDIDATE_TREE" \
  "$ARCHIVE_SHA256" "$OUTPUT"

if [[ "$STATUS" == ready || "$STATUS" == passed ]]; then
  exit 0
fi
if [[ "$STATUS" == blocked ]]; then
  echo "[remote-validate] remote prerequisites are incomplete; nothing was installed" >&2
  exit 3
fi
echo "[remote-validate] remote validation failed with status: $STATUS" >&2
(( REMOTE_STATUS == 0 )) && exit 1
exit "$REMOTE_STATUS"
