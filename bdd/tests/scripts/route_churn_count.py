#!/usr/bin/env python3
"""Watch the kernel routing table for SECONDS and report churn on PREFIX.

Usage: route_churn_count.py SECONDS PREFIX

Runs `ip -o monitor route` for SECONDS and counts the events whose line
names PREFIX (as a whole word, so 10.0.0.1 does not match 10.0.0.12).
Prints `quiet` when there were none, otherwise `CHURN <n>` followed by
the first few event lines. Always exits 0, so a feature asserts on the
output: `... should not contain "CHURN"`.
"""

import re
import subprocess
import sys
import time


def main() -> int:
    seconds = float(sys.argv[1])
    prefix = sys.argv[2]
    pattern = re.compile(r"(^|\s)" + re.escape(prefix) + r"(/32|/128)?(\s|$)")
    proc = subprocess.Popen(
        ["ip", "-o", "monitor", "route"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    time.sleep(seconds)
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    events = [line for line in out.splitlines() if pattern.search(line)]
    if not events:
        print("quiet")
        return 0
    print(f"CHURN {len(events)}")
    for line in events[:10]:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
