---
description: Run the rustscale acceptance gate (build + test + clippy). Silent on success, prints ~50 lines on failure. Pass a crate name to check one crate, or flags --no-test / --no-clippy.
agent: build
---

Run the rustscale verification gate. Execute `tools/check.sh` with the user's arguments ($ARGUMENTS) and report the result. The script is silent on success (prints "ok") and prints only the first ~50 lines of errors on failure, so do NOT run raw `cargo build`/`cargo test`/`cargo clippy` commands that dump full output.

If it fails, read the excerpt, fix the code, and re-run `tools/check.sh` with the same arguments. Do not paste full compiler logs into your replies.

Arguments: $ARGUMENTS
