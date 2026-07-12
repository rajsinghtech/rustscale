# Phase: `rustscale ssh` (client) + `rustscale web`

## ssh subcommand (client-side wrapper — NOT the SSH server)

Go refs: `cmd/tailscale/cli/ssh.go`, `ssh_unix.go`, `ssh_exec.go`. Go's
`tailscale ssh user@host` is a thin wrapper that execs the system `ssh` binary
with the right arguments; the Tailscale SSH *server* (roadmap port-10) is out of
scope for this phase (partial WIP exists on branch agent/phase-10-tailscale-ssh —
do not touch it).

1. `rustscale ssh [ssh-args...] [user@]host [command...]`:
   - Resolve `host` against the netmap/MagicDNS (status peers): accept short
     hostname, FQDN, or Tailscale IP. Error clearly if the peer doesn't exist.
   - exec system `ssh` (execvp, replacing the process — unix only) with:
     `-o 'HostName <tailscale-ip-or-fqdn>'`, hostname alias handling, and pass
     through user-supplied args like Go does (see ssh.go for the exact argv
     construction, incl. `%h` handling and knownhosts notes).
   - Follow Go: if the target advertises Tailscale SSH (netmap SSH_HostKeys /
     capability), Go adds options so OpenSSH trusts the connection
     (check ssh.go for what it actually sets — port 22 on the tailscale IP).
   - Windows: print "not supported" (matches our platform posture).
2. Tests: argv-construction unit tests (host resolution → expected exec args);
   no live ssh needed.

## web subcommand (minimal management UI)

Go ref: `cmd/tailscale/cli/web.go`, `client/web/` (Go ships a React app — we do
NOT port that). rustscale scope: a small self-contained status page.

1. `rustscale web [--listen <addr:port>=localhost:8088] [--readonly]`:
   the CLI (not the daemon) serves an embedded single-file HTML page (no JS
   build step; inline vanilla JS + fetch) that talks to handlers in the CLI
   process, which proxy to LocalAPI over safesocket:
   - status overview: hostname, IPs, backend state, health, version
   - peer table: name, IP, OS, online, last path (from status JSON)
   - actions (unless --readonly): up/down toggle (EditPrefs WantRunning),
     logout. Keep it to these three.
2. Bind localhost only by default; refuse non-loopback --listen unless
   --unsafe-any-addr is passed (document the risk in help text).
3. Tests: handler unit tests against the localclient stub harness (status JSON →
   rendered page contains peers; POST /api/up toggles via a recorded stub).

## Acceptance criteria

- Standard four checks + musl-target clippy, all clean.
- ssh argv unit tests green; web handler tests green.
- docs/parity.md rows updated (ssh CLI wrapper, web UI).
