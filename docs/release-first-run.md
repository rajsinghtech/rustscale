# Linux installed first-run acceptance

`tools/packaging/test-first-run.sh` is the credential-free Linux release acceptance gate. It is part of CI's **Release and installer contract** step. The gate builds release-mode `rustscale` and `rustscaled`, makes a temporary `file://` release archive from those exact binaries, and uses `scripts/install.sh` to install it into a temporary prefix. It never uses a stub CLI or daemon.

The harness starts the root-daemon equivalent with the installed `rustscaled` binary and a temporary state directory. The daemon binds its normal `/var/run/rustscaled.sock`; all installed CLI invocations deliberately omit `--socket`. Linux `SO_PEERCRED` supplies the peer identity. The configured operator is the CI user, and `nobody` is the unrelated read-only user.

RustScale's in-process `rustscale-testcontrol` server provides a loopback-only control plane and a fake browser completion. No auth key, Tailscale account, paid service, public control plane, or outbound control dependency is used.

## Acceptance matrix

| Journey point | Hermetic gate assertion | External resource |
| --- | --- | --- |
| Installed artifact | Installer consumes a temporary archive containing the real release binaries | None (`file://`) |
| Service startup | Root daemon equivalent starts with temporary state and default LocalAPI socket | Local process only |
| Default discovery | Installed CLI reaches the daemon without `--socket` | `/var/run/rustscaled.sock` |
| Unix authorization | `nobody` can read `status` but receives `403 access denied` for `logout` | Kernel `SO_PEERCRED` |
| Operator mutation | Configured `OperatorUser` runs `up` and `logout` | Kernel `SO_PEERCRED` |
| Interactive login | `up` issues Start and LoginInteractive, stays pending after the early acknowledgement, then receives a fake-browser completion | RustScale testcontrol |
| Running and persistence | `status --json` reaches `Running`; daemon restart restores it from the temporary state directory | RustScale testcontrol |
| Logout and cleanup | Logout is observed by testcontrol, daemon exits, default socket and root-owned state are removed, and the temporary install is uninstalled | Local processes only |

The Rust test is intentionally `#[ignore]`: it requires passwordless `sudo` and exclusive ownership of `/var/run/rustscaled.sock`, so the packaging script is its supported serial entry point. Do not run it on a host with a real RustScale daemon.

## First-run hotfix integration dependencies

The gate intentionally depends on these product contracts and does not implement them itself:

- LocalAPI authorization must resolve the configured `OperatorUser` to its Unix UID and pass it to peer-credential read-write admission; all other non-root UIDs remain read-only.
- `LoginInteractive` acknowledgement must be retained when it arrives before bootstrap begins waiting for it, so the deliberately early acknowledgement in the harness cannot be lost.
- A daemon restart with persisted authorized state must restore the profile to `Running` without requiring another `up` or interactive login.

## Real Linux TUN regression gate

The installed-first-run gate above remains credential-free and does not open a
TUN device. Separately, the trusted-repository `interop-tun` job in
`.github/workflows/e2e.yml` runs on master pushes or an explicit manual
dispatch. It is the narrow privileged regression gate for real Linux TUN
startup.

Before minting a Tailscale OIDC token or provisioning an ephemeral tailnet, the
job runs `tools/interop-tun-preflight.sh`. That credential-free preflight proves
the runner has passwordless root, `/dev/net/tun`, iproute2, and permission to
create, set the MTU on, and bring up a temporary TUN interface. The supported
harness repeats the preflight before its first tailnet API call, so local runs
also fail before consuming credentials when the host cannot exercise the gate.

After those prerequisites are established, the harness runs exactly
`tests::interop_tun_rust_dials_go` serially. `up_tun` errors are fatal at that
point. On Linux the test requires the Rust-created `tun0` to have a nonzero
ifindex, `IFF_UP`, MTU 1280, the four interface-derived IPv4 policy rules with
protocol 201 (including the table-52 rule), and the `100.64.0.0/10` route in
table 52 through `tun0`. A TCP echo roundtrip to Go tailscaled then proves an OS
socket packet traverses the kernel TUN, RustScale's packet pump and WireGuard
path, and returns.

This credentialed job is deliberately not part of ordinary local or pull
request validation. It uses only short-lived OIDC and an ephemeral tailnet with
unconditional teardown; run it locally only when explicitly supplying the
documented disposable tailnet credentials.

### Installed Linux replacement journey

`tools/packaging/test-linux-replacement.sh` complements the source-level TUN
job with a credential-free, installed-service journey. It builds release-mode
CLI and daemon binaries, packages them with the checked-in systemd files, and
feeds that archive through `scripts/install.sh` at `/usr/local` with the
explicit `--tailscale-compatible` option. CI runs it in the dedicated
**Installed Linux replacement journey** job. The artifact build has a
1200-second process-group deadline; the installed journey has a 900-second
execution limit plus a 90-second diagnostic/teardown grace inside the job's
50-minute outer deadline.

The script refuses to mutate an occupied host. Before installation it requires
an active systemd manager, passwordless sudo, an unused standard RustScale
installation, an unused `tun0`, and a successful real-TUN preflight. Optional
local runs print one concrete `SKIP` reason and exit successfully when a
prerequisite is absent; CI sets `RUSTSCALE_REQUIRE_LINUX_REPLACEMENT=1`, making
that same condition a failure instead of a false pass.

The journey proves all of the following on its isolated Linux runner:

- the installer consumes the release archive, installs the exact binary bytes,
  creates only relative `tailscale`/`tailscaled` aliases, and enables the
  checked-in systemd unit;
- canaries under `/var/lib/tailscale` and `/run/tailscale` remain byte-for-byte
  unchanged while RustScale uses `/var/lib/rustscale` and
  `/var/run/rustscaled.sock`;
- the default LocalAPI first reaches `NeedsLogin`, then the service enrolls with
  the documented `tskey-testcontrol` key against the standalone pinned Go
  testcontrol server;
- `nobody` retains LocalAPI read access but cannot log out the configured
  operator's node;
- the installed service creates an up, MTU-1280 `tun0`, installs its
  interface-derived protocol-201 IPv4 policy chain and table-52 tailnet route,
  and completes an OS-socket TCP echo roundtrip through that TUN to a real
  userspace-networking Go `tailscaled` built from `tailscale.com@v1.100.0`;
- after the bootstrap key is removed, a systemd restart preserves `Running`,
  the assigned address, and the Go-peer packet path;
- logout is durable, `Restart=always` returns the service to `NeedsLogin`, and
  the old TUN routes and rules are gone; and
- public uninstall disables/removes the service, binaries, receipt, aliases,
  and LocalAPI socket without touching official-state canaries. The test then
  removes RustScale's intentionally retained identity state as fixture cleanup.

The journey runs as the invoking runner user inside a root-systemd-manager
transient cgroup. Every build, LocalAPI call, systemctl operation, wait, logout,
uninstall, and cleanup phase has its own deadline. The cgroup uses
`KillMode=control-group`: TERM lets the common EXIT trap capture the live
service journal, status, process tree, and kernel state before cleanup, while
the manager can KILL root-owned descendants after the 90-second grace. Phase
changes and operation boundaries carry UTC timestamps; CI retains a phase file
and replays the bounded log tail on failure.

Every owned child PID is also recorded. `TERM`, interruption, normal exit, and
the execution limit run the same teardown, which stops the service, escalates
stuck child processes, removes only installer-owned aliases/files, and fails if
the TUN, protocol-201 rules, table-52 route, or socket remains. This gate tests
a locally assembled candidate archive from the exact checkout; the release
workflow's Linux compatibility job remains authoritative for executing the
separately uploaded GNU archive on Debian 12.


## Protected real-control smoke gate (manual only)

This is not CI and must remain protected. Use a disposable host and a dedicated, short-lived test identity. Store the auth key only in the protected CI secret store or a local shell prompt; never put it in command history, repository files, logs, or issue text.

1. Install the candidate artifact into an isolated prefix and start its daemon with a disposable state directory and explicit socket.

2. Inject the short-lived secret only into the daemon process environment (for example via protected CI secret masking), run `rustscale up`, then verify `rustscale status --json` is `Running`.

3. Exercise only the intended real-control smoke behavior. Do not enable billing-sensitive, exit-node, or paid-resource features.

4. In an unconditional teardown step, run `rustscale logout`, stop the daemon, remove the state directory and socket, uninstall the prefix, and revoke the short-lived auth key or delete the disposable identity.

5. Redact command output and retain only pass/fail evidence. A teardown failure is a failed smoke run and requires manual cleanup before reuse.

The protected gate is a release-manager decision, not a pull-request check; the hermetic testcontrol gate remains the required CI contract.
