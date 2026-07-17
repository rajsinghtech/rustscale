# v0.1.4 release checklist

Use this checklist only after the release pull request has passed every
required GitHub Actions workflow. A local pass is necessary but not sufficient
to tag or publish this release.

## Before tagging

- Confirm the repository and release assets are public and Pages uses GitHub
  Actions as its source.
- Confirm `HOMEBREW_TAP_GITHUB_TOKEN` can write to
  `rajsinghtech/homebrew-tap`.
- Confirm the candidate is based on the current `origin/master`, the worktree
  contains no unrelated/generated files, and issue #75 remains open until the
  exact release commit has passed its required gates.
- Run every local command through the repository's process-group deadline
  wrapper. It sends `TERM`, escalates to `KILL`, and cleans up surviving child
  processes even when the command exits successfully:

  ```bash
  deadline() {
    python3 tools/agent/run-with-deadline.py "$1" -- "${@:2}"
  }

  # Product, compatibility, contributor harnesses, and diff hygiene.
  deadline 3600 tools/check.sh
  deadline 1800 tools/compat/check.sh
  deadline 900 tools/agent/check.sh
  deadline 900 tools/bench/check.sh
  deadline 60 git diff --check

  # Static release policy and portable packaging contracts.
  deadline 300 shellcheck scripts/*.sh container/*.sh \
    tools/packaging/*.sh tools/interop-tun*.sh tools/agent/*.sh \
    tools/compat/*.sh
  deadline 600 tools/packaging/check-release.sh
  deadline 600 tools/packaging/test-install.sh
  deadline 600 tools/packaging/test-container.sh
  deadline 1800 cargo package --workspace --no-verify --locked
  deadline 900 go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12

  # Security policy.
  deadline 900 cargo audit
  deadline 900 cargo deny check
  ```

- On an isolated Linux host with passwordless sudo, run the privileged
  packaging gates separately. A platform/prerequisite `SKIP` is not a pass:

  ```bash
  deadline 1200 tools/packaging/test-first-run.sh
  deadline 1200 env RUSTSCALE_REQUIRE_LINUX_REPLACEMENT=1 \
    RUSTSCALE_LINUX_REPLACEMENT_TIMEOUT=900 \
    tools/packaging/test-linux-replacement.sh
  ```

- Require successful **CI**, **Coverage**, **E2E**, **Pages**, **Audit**, and
  credential-free benchmark-harness validation for the exact release commit.
  CI must include the Linux installed-first-run, compatibility-contract, and
  required **Installed Linux replacement journey** gates. The replacement job
  must report both its systemd journey and pinned-Go kernel-TUN roundtrip as
  `PASS`; a prerequisite `SKIP` is not acceptable.
- Require the trusted-repository cross-client interop job to pass the isolated
  issue #75 one-way application UDP cadence test before its remaining interop
  suite. Also require the `interop-tun` job: its credential-free preflight must
  finish before OIDC minting, and its exact serial test must prove Linux TUN
  kernel state plus a packet roundtrip. Do not run either credentialed harness
  as ordinary local release validation.
- Review `docs/release-first-run.md`. The protected real-control smoke gate is
  manual, requires explicit approval and a disposable identity, and is not a
  substitute for any hermetic gate.

## Tag and verify

Tag only the exact reviewed commit after all pre-tag workflows above are green:

```sh
git tag -a v0.1.4 -m "rustscale v0.1.4"
git push origin refs/tags/v0.1.4
```

Pushing the tag starts `.github/workflows/release.yml`; do not create a second
GitHub release manually. Before publication, its Linux glibc compatibility job
must execute the exact uploaded x86_64 GNU archive in `debian:12-slim`. The
workflow must then produce exactly five archives plus `SHA256SUMS`, a
multi-architecture GHCR image tagged `v0.1.4`, `0.1.4`, `0.1`, and `latest`,
and an updated Homebrew formula.

After publication, perform an anonymous clean install on a fresh disposable
Linux VM and verify install → privileged `set --operator` → unprivileged
interactive login → `Running` → service restart → restored `Running` → logout
→ `NeedsLogin` → uninstall. Use only the public v0.1.4 assets and remove the VM
and disks afterward.

Also verify:

```sh
curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | \
  sh -s -- --version v0.1.4 --no-service
rustscale --version
```

Run the equivalent Windows Pages installer with `-Version v0.1.4`. Inspect the
GHCR multi-architecture manifest and verify `rustscale`, `rustscaled`,
`tailscale`, and `tailscaled` command names. Close issue #75 only after the
published artifacts and release notes are verified.

Publishing individual workspace crates to crates.io remains a separate,
manual operation. Do not publish crates as part of the GitHub patch-release
flow.
