# Phase: 0.1.0 release prep (BLOCKED on phase-windows-port merging)

Goal: cut the first tagged release, `v0.1.0`, using the existing tag-push
release workflow (`.github/workflows/release.yml`). This phase is preparation
and verification only — the actual `git tag v0.1.0 && git push --tags` is done
by the user after review.

## Preconditions

- phase-windows-port merged; Windows CI legs green with continue-on-error removed.
- `tools/check.sh` clean on master.

## Work items

1. **CHANGELOG.md** — create it. Single `## 0.1.0` section summarizing what
   ships in the first release, grouped by area (core stack: control/DERP/
   magicsock/peer-relay/netstack; tsnet embedding API; TUN mode; C FFI;
   CLI + rustscaled daemon with subcommand list; serve/funnel; certs/MagicDNS;
   SSH; taildrop; platform support incl. Windows compile + named pipes).
   Source it from `git log --oneline` and `docs/parity.md` — terse bullet
   points, no marketing language.
2. **Version audit** — confirm `workspace.package.version = "0.1.0"` in the
   root Cargo.toml and that every crate inherits it (`version.workspace = true`);
   fix any crate pinning its own version. Confirm the CLI/daemon `version`
   subcommand reports something sensible for a tagged build (git-describe
   stamping in release.yml assumes full history — verify the version-stamp
   plumbing reads the tag).
3. **Release workflow dry-run audit** — read `.github/workflows/release.yml`
   end to end and verify against the current tree:
   - `BIN_PKGS` covers all binary crates that should ship
     (`rustscale-rustscaled:rustscaled`, `rustscale-cli:rustscale` — anything new?).
   - Windows release artifacts: now that the workspace compiles for
     x86_64-pc-windows-msvc, ADD a windows job producing `rustscale.exe` +
     `rustscaled.exe` zips, mirroring the existing per-target bundle pattern.
     (librustscale.dll is optional — only if the ffi crate builds cleanly for msvc.)
   - Homebrew formula job: paths/binary names still match `scripts/install.sh`
     and the macos bundle layout.
   - SHA256SUMS covers the new windows artifacts.
4. **Release notes draft** — `docs/release-notes-0.1.0.md` with install
   instructions per platform (brew, curl+unzip for linux/windows, from-source),
   distilled from README. This becomes the GitHub release body; check whether
   release.yml auto-generates a body and wire this file in if trivial
   (`gh release create --notes-file` / softprops action `body_path`).
5. **Smoke check** — run the exact commands the release workflow runs for the
   host platform (macOS universal lipo steps) locally to confirm they don't
   error before burning a tag.

## Acceptance criteria

- CHANGELOG.md and docs/release-notes-0.1.0.md exist and are accurate (verify
  claimed features against `docs/parity.md` status, not from memory).
- `tools/check.sh` still clean.
- release.yml updated for windows artifacts; workflow YAML validates
  (`gh workflow list` parses it, or actionlint if available).
- A written summary of anything that will still fail at tag time, if any.

## Out of scope

- Publishing to crates.io.
- Windows installer/MSI, code signing, notarization.
- Actually pushing the tag (user does this).
