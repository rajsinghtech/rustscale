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

### Remaining systemd and artifact gaps

This narrow gate invokes `Server::up_tun` from a source-built Rust test binary.
It does not install a release archive, start `packaging/systemd/rustscaled.service`
as PID 1 would, exercise systemd restart/ordering in a private network
namespace, or prove that a published archive or container preserves the same
TUN behavior. The credential-free first-run gate covers installed CLI/daemon,
operator, persistence, restart, logout, and uninstall contracts, but starts the
daemon without `--tun`. A future release gate should combine the exact packaged
artifacts with a systemd-capable Linux namespace or disposable VM and repeat the
kernel assertions and packet proof without weakening either gate's credential
boundary.


## Protected real-control smoke gate (manual only)

This is not CI and must remain protected. Use a disposable host and a dedicated, short-lived test identity. Store the auth key only in the protected CI secret store or a local shell prompt; never put it in command history, repository files, logs, or issue text.

1. Install the candidate artifact into an isolated prefix and start its daemon with a disposable state directory and explicit socket.

2. Inject the short-lived secret only into the daemon process environment (for example via protected CI secret masking), run `rustscale up`, then verify `rustscale status --json` is `Running`.

3. Exercise only the intended real-control smoke behavior. Do not enable billing-sensitive, exit-node, or paid-resource features.

4. In an unconditional teardown step, run `rustscale logout`, stop the daemon, remove the state directory and socket, uninstall the prefix, and revoke the short-lived auth key or delete the disposable identity.

5. Redact command output and retain only pass/fail evidence. A teardown failure is a failed smoke run and requires manual cleanup before reuse.

The protected gate is a release-manager decision, not a pull-request check; the hermetic testcontrol gate remains the required CI contract.
