# Phase: release-workflow-homebrew-guard

Make the homebrew tap job in `.github/workflows/release.yml` conditional so it
only runs for public repos. The rustscale repo is private, so the homebrew
job's `curl` download of release assets 404s (unauthenticated requests can't
access private-repo release assets). Even if it downloaded successfully,
`brew install` would fail for end users who can't access the private repo.

## Context

The v0.1.0 release workflow (run 29201185452) succeeded for all build jobs
(macos, linux x3, windows) and the `release` job (checksums + GitHub Release
created with all 6 artifacts). Only the `homebrew` job failed — `curl: (22)
The requested URL returned error: 404` on the first asset download.

Root cause: the repo is private (`gh repo view --json isPrivate` → `true`).
The `homebrew` job downloads assets via unauthenticated `curl` to
`https://github.com/{repo}/releases/download/{tag}/{asset}`, which 404s for
private repos.

## Fix

File: `.github/workflows/release.yml`, the `homebrew` job (currently at the
bottom of the file, job key `homebrew:`).

Add an `if:` condition to the job that skips it when the repository is private.
For tag-push events, `github.event.repository.private` is available.

Change the job header from:

```yaml
  homebrew:
    name: Update Homebrew tap
    needs: [release]
    runs-on: ubuntu-latest
    timeout-minutes: 5
```

to:

```yaml
  homebrew:
    name: Update Homebrew tap
    needs: [release]
    if: github.event.repository.private == false
    runs-on: ubuntu-latest
    timeout-minutes: 5
```

This way:
- Private repos: the homebrew job is skipped (shown as a neutral/skipped
  state, not a failure). The release workflow overall succeeds.
- Public repos: the homebrew job runs as before.

Do NOT change any other job. Do NOT remove the homebrew job entirely — it
should still work when the repo is eventually made public.

## Acceptance criteria

1. The `release.yml` workflow YAML is valid (no syntax errors).
2. The `homebrew` job has the `if: github.event.repository.private == false`
   condition.
3. No other jobs are changed.
4. Commit on branch `agent/phase-homebrew-guard`, push, open a PR targeting
   master. Commit as rajsinghtech / rajsinghcpre@gmail.com — NO AI/Claude
   branding.
5. Run `yq` or `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` to validate YAML (if a YAML validator is available; otherwise at least visual inspection).
