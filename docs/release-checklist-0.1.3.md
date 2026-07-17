# v0.1.3 release checklist

Use this checklist only after the release pull request has passed every
required GitHub Actions workflow.

## Before tagging

- Confirm the repository and release assets are public and Pages uses GitHub
  Actions as its source.
- Confirm `HOMEBREW_TAP_GITHUB_TOKEN` can write to
  `rajsinghtech/homebrew-tap`.
- Run the local gates:

  ```sh
  tools/check.sh
  shellcheck scripts/*.sh container/*.sh tools/packaging/*.sh tools/interop-tun*.sh
  tools/packaging/check-release.sh
  tools/packaging/test-install.sh
  tools/packaging/test-first-run.sh
  tools/packaging/test-container.sh
  cargo package --workspace --no-verify --locked
  go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
  ```

- Require a clean Linux installed-first-run acceptance run and Linux glibc
  compatibility execution from the exact release commit.
- Require the trusted-repository `interop-tun` job from the exact release
  commit. Its credential-free preflight must complete before OIDC minting, and
  its focused privileged test must prove Linux TUN kernel state plus a packet
  roundtrip. Do not run the credentialed harness as part of local release
  validation.
- Review `docs/release-first-run.md`. The protected real-control smoke gate is
  manual and requires explicit approval, a disposable identity, and mandatory
  teardown.

## Tag and verify

Tag the exact reviewed, green commit:

```sh
git tag -a v0.1.3 -m "rustscale v0.1.3"
git push origin v0.1.3
```

The release workflow must produce exactly five archives plus `SHA256SUMS`, a
multi-architecture GHCR image tagged `v0.1.3`, `0.1.3`, `0.1`, and `latest`,
and an updated Homebrew formula.

After publication, perform an anonymous clean install on a fresh disposable
Linux VM and verify install → privileged `set --operator` → unprivileged
interactive login → `Running` → service restart → restored `Running` → logout
→ `NeedsLogin` → uninstall. Use only the public v0.1.3 assets and remove the VM
and disks afterward.

Also verify:

```sh
curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | \
  sh -s -- --version v0.1.3 --no-service
rustscale --version
```

Run the equivalent Windows Pages installer with `-Version v0.1.3`. Inspect the
GHCR multi-architecture manifest and verify `rustscale`, `rustscaled`,
`tailscale`, and `tailscaled` command names.

Publishing individual workspace crates to crates.io remains a separate
operation.

The current TUN gate is source-level. Installed systemd service behavior in a
private network namespace and TUN startup from the exact published archive or
container remain explicit release gaps; see `docs/release-first-run.md`.
