#!/usr/bin/env python3
"""Run one command in a process group and enforce a portable wall-clock deadline."""
import os
import signal
import subprocess
import sys
import time


def process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stop_process_group(process_group: int, grace_seconds: int) -> None:
    """Terminate every process in a child session, then escalate after grace."""
    try:
        os.killpg(process_group, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.monotonic() + grace_seconds
    while process_group_exists(process_group) and time.monotonic() < deadline:
        time.sleep(0.05)
    if process_group_exists(process_group):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        print("usage: run-with-deadline.py <seconds> -- <command> [args...]", file=sys.stderr)
        return 2
    try:
        seconds = int(sys.argv[1])
    except ValueError:
        print("deadline must be a positive integer", file=sys.stderr)
        return 2
    if seconds <= 0:
        print("deadline must be a positive integer", file=sys.stderr)
        return 2
    try:
        grace_seconds = int(os.environ.get("RUSTSCALE_DEADLINE_GRACE_SECONDS", "2"))
    except ValueError:
        print("deadline grace must be an integer from 0 to 300", file=sys.stderr)
        return 2
    if not 0 <= grace_seconds <= 300:
        print("deadline grace must be an integer from 0 to 300", file=sys.stderr)
        return 2

    child = subprocess.Popen(sys.argv[3:], start_new_session=True)
    process_group = child.pid

    def interrupted(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        try:
            return child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            print("[deadline] deadline reached; terminating command process group", file=sys.stderr)
            return 124
        except KeyboardInterrupt:
            return 130
    finally:
        # This runs for timeout, successful child exit with stragglers, SIGTERM,
        # KeyboardInterrupt, and Python exceptions. The child is in a separate
        # session, so this cannot signal the wrapper's own process group.
        stop_process_group(process_group, grace_seconds)
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
