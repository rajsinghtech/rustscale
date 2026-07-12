---
description: Wait for a backgrounded build/test to finish. Polls internally with a timeout, prints only the final log tail + exit code. Replaces `sleep 5 && ps -p PID && tail log` busy-polling.
agent: build
---

Given a PID and log file, block until the process exits (or timeout), then print the last 30 log lines and the exit status. Usage from a build agent:

```bash
tools/wait-build.sh <pid> <logfile> [timeout_sec]
```

The exit status of the waited process is preserved. Do NOT use `sleep N && ps -p PID && tail log` — that costs multiple agent turns.

Arguments: $ARGUMENTS
