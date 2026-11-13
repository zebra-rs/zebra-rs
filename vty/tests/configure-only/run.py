#!/usr/bin/env python3
"""Configure-mode commands typed in exec mode say where they belong.

`set` is a bash builtin, so before vty.sh aliased it in exec mode,
`set interface ... address ...` typed there was taken without a word
and nothing reached the daemon; `commit`, `delete` and the rest said
only "command not found". This runs vty.sh under stock bash (the
aliases are vty.sh's own, nothing the vty bash patch provides), with
`stub-vtyhelper` first on PATH standing in for the daemon, and drives
it through a pty as an operator would.

Usage: vty/tests/configure-only/run.py [-v]
"""

import fcntl
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
VTY_SH = HERE.parents[1] / "additions" / "vty.sh"
MESSAGE = "is only available in configure mode; type 'configure' first."

VERBOSE = "-v" in sys.argv[1:]

_SHIM = None


def shim_dir():
    """A PATH entry with the stub as `vtyhelper`, and a `clear` that
    says it ran instead of clearing the screen."""
    global _SHIM
    if _SHIM is None:
        _SHIM = Path(tempfile.mkdtemp(prefix="vty-cfg-shim-"))
        stub = HERE / "stub-vtyhelper"
        os.chmod(stub, 0o755)
        (_SHIM / "vtyhelper").symlink_to(stub)
        clear = _SHIM / "clear"
        clear.write_text("#!/bin/sh\necho SCREEN-CLEARED\n")
        os.chmod(clear, 0o755)
    return _SHIM


class Result:
    def __init__(self, output, calls, timed_out):
        self.output = output
        self.calls = calls
        self.timed_out = timed_out

    def called(self, needle):
        return any(needle in c for c in self.calls)


def run(lines, timeout=15.0):
    """Feed `lines` to an interactive bash with vty.sh as its rcfile."""
    log = tempfile.NamedTemporaryFile(prefix="vty-cfg-", suffix=".log", delete=False)
    log.close()
    env = dict(os.environ)
    env["PATH"] = f"{shim_dir()}:{env['PATH']}"
    env["STUB_LOG"] = log.name
    env["CLI_PAGER"] = "cat"
    env["TERM"] = "dumb"

    master, slave = pty.openpty()

    def preexec():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(
        ["bash", "--rcfile", str(VTY_SH), "-i"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        preexec_fn=preexec,
        close_fds=True,
    )
    os.close(slave)

    out = bytearray()
    deadline = time.time() + timeout
    try:
        for line in lines:
            os.write(master, line.encode() + b"\n")
            time.sleep(0.35)
        while time.time() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                out += data
            elif proc.poll() is not None:
                break
        timed_out = proc.poll() is None
        if timed_out:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait()
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        calls = [c.strip() for c in Path(log.name).read_text().splitlines() if c.strip()]
        os.unlink(log.name)

    text = out.decode("utf-8", "replace").replace("\r", "")
    if VERBOSE:
        print(f"--- output ---\n{text}\n--- calls ---\n" + "\n".join(calls))
    return Result(text, calls, timed_out)


FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}{(': ' + detail) if detail else ''}")
        FAILURES.append(name)


def message_for(output, word):
    return f"% '{word}' {MESSAGE}" in output


def case_set_in_exec_mode():
    # `echo argc=$#` tells whether bash's own `set` ran: it would have
    # made the words of the line the shell's positional parameters.
    r = run(["set interface eth0 ipv6 address 2001:db8::1/64", "echo argc=$#", "exit"])
    check("exec set: says where it belongs", message_for(r.output, "set"), r.output)
    check("exec set: bash's set did not run", "argc=0" in r.output, r.output)
    check("exec set: nothing sent to the daemon", not r.called("set interface"), str(r.calls))
    check("exec set: exit still leaves", not r.timed_out)


def case_other_configure_commands_in_exec_mode():
    words = ["commit", "delete interface eth0", "discard", "load /tmp/x.conf",
             "save", "run show version", "clear isis neighbor"]
    r = run(words + ["exit"])
    for w in words:
        word = w.split()[0]
        check(f"exec {word}: says where it belongs", message_for(r.output, word), r.output)
    check("exec: no command not found", "command not found" not in r.output, r.output)


def case_bare_clear_still_clears():
    r = run(["clear", "exit"])
    check("exec bare clear: clears the screen", "SCREEN-CLEARED" in r.output, r.output)
    check("exec bare clear: no message", not message_for(r.output, "clear"), r.output)


def case_exec_commands_untouched():
    r = run(["show version", "exit"])
    check("exec show: reaches the daemon", r.called("-m exec show version"), str(r.calls))
    check("exec show: no message", MESSAGE not in r.output, r.output)


def case_configure_mode_and_back():
    r = run([
        "_cli_exec configure",
        "set interface eth0 ipv6 address 2001:db8::1/64",
        "commit",
        "exit",
        "set interface eth1",
        "exit",
    ])
    check("configure set: reaches the daemon",
          r.called("-m configure set interface eth0 ipv6 address 2001:db8::1/64"), str(r.calls))
    check("configure commit: reaches the daemon", r.called("-m configure commit"), str(r.calls))
    check("back in exec: set says where it belongs again", message_for(r.output, "set"), r.output)
    check("back in exec: second set not sent", not r.called("set interface eth1"), str(r.calls))
    check("back in exec: exit leaves", not r.timed_out)


def main():
    case_set_in_exec_mode()
    case_other_configure_commands_in_exec_mode()
    case_bare_clear_still_clears()
    case_exec_commands_untouched()
    case_configure_mode_and_back()
    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s)")
        sys.exit(1)
    print("\nall passed")


if __name__ == "__main__":
    main()
