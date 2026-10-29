#!/usr/bin/env python3
"""Record the kernel's route events to a file, and show those for a prefix.

Usage:
  route_monitor.py record FILE SECONDS
  route_monitor.py stop FILE
  route_monitor.py show FILE PREFIX

`record` runs `ip -o monitor route`, writing each event line to FILE as it
arrives, until `stop` or for at most SECONDS; spawn it in the background
before the changes it should see, and stop it before the namespace goes.
Name FILE `*.log` under logs/, so git ignores it and its stop marker.
`show` prints the recorded lines that name PREFIX (as a whole word, so
10.0.0.1 does not match 10.0.0.12), or `none`. A deleted route's line starts
with `Deleted`, so a feature asserts `... should not contain "Deleted"`.
All exit 0.
"""

import os
import re
import subprocess
import sys
import threading
import time


def stop_marker(path: str) -> str:
    return os.path.splitext(path)[0] + ".stop.log"


def record(path: str, seconds: float) -> None:
    stop = stop_marker(path)
    if os.path.exists(stop):
        os.remove(stop)
    proc = subprocess.Popen(
        ["ip", "-o", "monitor", "route"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    def stopper() -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not os.path.exists(stop):
            time.sleep(0.2)
        proc.terminate()

    threading.Thread(target=stopper, daemon=True).start()
    with open(path, "w") as out:
        for line in proc.stdout:
            out.write(line)
            out.flush()
    proc.wait()


def show(path: str, prefix: str) -> None:
    pattern = re.compile(r"(^|\s)" + re.escape(prefix) + r"(\s|$)")
    try:
        with open(path) as f:
            lines = [line.rstrip("\n") for line in f if pattern.search(line)]
    except FileNotFoundError:
        lines = []
    print("\n".join(lines) if lines else "none")


def main() -> int:
    if sys.argv[1] == "record":
        record(sys.argv[2], float(sys.argv[3]))
    elif sys.argv[1] == "stop":
        open(stop_marker(sys.argv[2]), "w").close()
    else:
        show(sys.argv[2], sys.argv[3])
    return 0


if __name__ == "__main__":
    sys.exit(main())
