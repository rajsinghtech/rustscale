# v0.1.1 release checklist

Use this checklist only after the release pull request has passed every
required GitHub Actions workflow.

## Before tagging

- Confirm the repository and release assets are public so anonymous one-line,
  Homebrew, and GHCR installation work immediately.
- Confirm Pages is enabled with GitHub Actions as its source.
- Confirm `HOMEBREW_TAP_GITHUB_TOKEN` can write to
  `rajsinghtech/homebrew-tap`.
- Run the local gates:

  ```sh
  tools/check.sh
  shellcheck scripts/*.sh container/*.sh tools/packaging/*.sh
  tools/packaging/check-release.sh
  tools/packaging/test-install.sh
  tools/packaging/test-first-run.sh
  tools/packaging/test-container.sh
  cargo package --workspace --no-verify --locked
  go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
  ```

- Let CI, Coverage, E2E, and Pages complete successfully on the release commit.
  The Windows installer contract runs only on the Windows CI leg.
- Review `docs/release-first-run.md` and, only when explicitly approved, run
  its protected real-control smoke gate with a disposable identity and its
  mandatory teardown. This is never a CI prerequisite.

## Tag and verify

After review, tag the exact green commit:

```sh
git tag -a v0.1.1 -m "rustscale v0.1.1"
git push origin v0.1.1
```

The release workflow must produce exactly five archives plus `SHA256SUMS`, a
multi-architecture GHCR image tagged `v0.1.1`, `0.1.1`, `0.1`, and `latest`,
and—when the repository is public—an updated Homebrew formula.

Smoke-test anonymous installation after publication:

```sh
curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | \
  sh -s -- --version v0.1.1 --no-service
rustscale --version
```

On Windows, run the equivalent Pages installer with `-Version v0.1.1`. Also
pull both GHCR architectures (or inspect the manifest) and verify the
`rustscale`, `rustscaled`, `tailscale`, and `tailscaled` command names.

Publishing the individual workspace crates to crates.io is intentionally a
separate operation. Every workspace crate is package-assembled in CI with
versioned internal dependencies so that future public publication can be
enabled without changing the release asset contract.
