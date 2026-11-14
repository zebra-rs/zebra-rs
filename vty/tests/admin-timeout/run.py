#!/usr/bin/env python3
"""The vty leaves configure mode when the admin role lapses, and says so
when it cannot reach the daemon.

The daemon gives a non-root session the admin role for 900 seconds past
its last admin command, then refuses every configure-mode command, `exit`
included, so an operator left in configure mode could neither work nor
leave. And with the daemon down, the vty said nothing, or "command not
found". `stub-vtyhelper` keeps the daemon's admin rule on a clock of a
few seconds, and stands in for a daemon that is down.

The vty.sh side runs under stock bash, as in CI. When the patched vty
has been built (`make -C vty`), one more case checks what the patch
adds: the notice and the exec-mode prompt appear while the operator is
still at the prompt, without pressing Enter.

Usage: vty/tests/admin-timeout/run.py [-v]
"""

import fcntl
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
VTY_SH = HERE.parents[1] / "additions" / "vty.sh"
VTY = HERE.parents[1] / "build" / "vty"

NOTICE = "% Configuration session timed out; back to exec mode."
UNREACHABLE = "% Cannot connect to zebra-rs at unix:zebra-rs/vty"
EXEC_ONLY = "is only available in configure mode"

VERBOSE = "-v" in sys.argv[1:]

_SHIMS = {}


def shim_dir(group):
    """A PATH entry with the stub as `vtyhelper`, and an `id` that puts
    the user in the zebra-rs group (passwordless `configure`) or not."""
    if group not in _SHIMS:
        shim = Path(tempfile.mkdtemp(prefix="vty-admin-shim-"))
        stub = HERE / "stub-vtyhelper"
        os.chmod(stub, 0o755)
        (shim / "vtyhelper").symlink_to(stub)
        groups = "users zebra-rs" if group else "users"
        idp = shim / "id"
        idp.write_text(f'#!/bin/sh\n[ "$1" = -nG ] && {{ echo {groups}; exit 0; }}\nexec /usr/bin/id "$@"\n')
        os.chmod(idp, 0o755)
        _SHIMS[group] = shim
    return _SHIMS[group]


class Result:
    def __init__(self, output, calls, timed_out, marks):
        self.output = output
        self.calls = calls
        self.timed_out = timed_out
        self.marks = marks

    def called(self, needle):
        return any(needle in c for c in self.calls)

    def count(self, needle):
        return sum(1 for c in self.calls if needle in c)

    def since(self, mark):
        """Output after a ("mark", name) step."""
        return self.output[self.marks[mark]:]


def run(steps, ttl=3, timer=True, group=True, down=False, vty=False, timeout=30.0):
    """Drive an interactive shell through `steps`: a string is typed as a
    line; ("sleep", s) waits; ("raw", s) types without Enter;
    ("down",) makes the daemon unreachable; ("mark", name) remembers
    where the output stands."""
    state = Path(tempfile.mkdtemp(prefix="vty-admin-state-"))
    if down:
        (state / "down").touch()
    log = state / "calls.log"
    home = state / "home"
    home.mkdir()
    env = dict(os.environ)
    env.pop("CLI_SERVER_URL", None)
    env["PATH"] = f"{shim_dir(group)}:{env['PATH']}"
    env["HOME"] = str(home)
    env["STUB_LOG"] = str(log)
    env["STUB_STATE"] = str(state)
    env["STUB_TTL"] = str(ttl)
    if not timer:
        env["STUB_NO_TIMER"] = "1"
    env["CLI_PAGER"] = "cat"
    env["CLI_EXIT_PROMPT_TIMEOUT"] = "2"
    env["TERM"] = "dumb"

    master, slave = pty.openpty()

    def preexec():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    argv = [str(VTY), "-i"] if vty else ["bash", "--rcfile", str(VTY_SH), "-i"]
    proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                            env=env, preexec_fn=preexec, close_fds=True)
    os.close(slave)

    out = bytearray()
    marks = {}

    def pump(seconds):
        end = time.time() + seconds
        while True:
            left = end - time.time()
            if left <= 0:
                return
            ready, _, _ = select.select([master], [], [], min(left, 0.1))
            if ready:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    return
                if not data:
                    return
                out.extend(data)

    try:
        pump(0.5)
        for step in steps:
            if isinstance(step, str):
                os.write(master, step.encode() + b"\n")
                pump(0.5)
            elif step[0] == "sleep":
                pump(step[1])
            elif step[0] == "raw":
                os.write(master, step[1].encode())
                pump(0.5)
            elif step[0] == "down":
                (state / "down").touch()
            elif step[0] == "mark":
                marks[step[1]] = len(out.decode("utf-8", "replace").replace("\r", ""))
        deadline = time.time() + timeout
        while time.time() < deadline and proc.poll() is None:
            pump(0.2)
        pump(0.2)
        timed_out = proc.poll() is None
        if timed_out:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait()
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        calls = [c.strip() for c in log.read_text().splitlines() if c.strip()] if log.exists() else []
        shutil.rmtree(state, ignore_errors=True)

    text = out.decode("utf-8", "replace").replace("\r", "")
    if VERBOSE:
        print(f"--- output ---\n{text}\n--- calls ---\n" + "\n".join(calls))
    return Result(text, calls, timed_out, marks)


FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}{(': ' + detail) if detail else ''}")
        FAILURES.append(name)


def case_idle_lapse():
    # Nothing typed while the role lapses; the timer notices.
    r = run(["configure", ("sleep", 3.5), ("mark", "lapsed"), "",
             "set interface eth0", "exit"], ttl=2)
    check("idle: entered configure mode", r.called("-m exec configure"), str(r.calls))
    check("idle: timer armed", r.called("--timer"), str(r.calls))
    check("idle: notice shown", NOTICE in r.output, r.output)
    check("idle: notice shown once", r.output.count(NOTICE) == 1, r.output)
    check("idle: back in exec mode", EXEC_ONLY in r.since("lapsed"), r.output)
    check("idle: set not sent to the daemon", not r.called("-m configure set"), str(r.calls))
    check("idle: exit leaves", not r.timed_out)


def case_refused_command():
    # No timer: the refusal itself brings the shell back.
    r = run(["configure", ("sleep", 2.5), "set interface eth0", "exit"], ttl=1, timer=False)
    check("refused: command reached the daemon", r.called("-m configure set interface eth0"), str(r.calls))
    check("refused: notice shown", NOTICE in r.output, r.output)
    check("refused: one exit leaves the shell", not r.timed_out)


def case_exit_after_lapse():
    # `exit` in configure mode is refused too; it must not leave the
    # operator stuck there.
    r = run(["configure", ("sleep", 2.5), "exit", "echo still-here", "exit"], ttl=1, timer=False)
    check("exit after lapse: notice shown", NOTICE in r.output, r.output)
    check("exit after lapse: in exec mode, shell still up", "still-here" in r.output, r.output)
    check("exit after lapse: second exit leaves", not r.timed_out)


def case_reenter_after_lapse():
    r = run(["configure", ("sleep", 2.5), "set a", "configure", "set b", "exit", "exit"],
            ttl=2, timer=False)
    check("re-enter: role taken again", r.count("-e") == 2, str(r.calls))
    check("re-enter: command reaches the daemon", r.called("-m configure set b"), str(r.calls))
    check("re-enter: leaves", not r.timed_out)


def case_reenter_within_role_no_password():
    # Not in the group: the root password once, not again on re-entry
    # while the role lives.
    r = run(["configure", "secret", "exit", "configure", "set b", "exit", "exit"],
            ttl=30, group=False)
    check("no second password: one prompt", r.output.count("Root password:") == 1, r.output)
    check("no second password: role taken once", r.count("-e") == 1, str(r.calls))
    check("no second password: in configure mode", r.called("-m configure set b"), str(r.calls))
    check("no second password: leaves", not r.timed_out)


def case_abbreviation_takes_role():
    r = run(["conf", "set b", "exit", "exit"], ttl=30)
    check("conf: takes the role", r.called("-e"), str(r.calls))
    check("conf: enters as configure", r.called("-m exec configure"), str(r.calls))
    check("conf: abbreviation not sent", "-m exec conf" not in r.calls, str(r.calls))
    check("conf: in configure mode", r.called("-m configure set b"), str(r.calls))


def case_piped_refusal():
    # A pipeline runs the command in a subshell; the shell still leaves
    # configure mode.
    r = run(["configure", ("sleep", 2.5), "show running-config | cat", ("mark", "piped"),
             "set x", "exit"], ttl=1, timer=False)
    check("piped: notice shown", NOTICE in r.output, r.output)
    check("piped: back in exec mode", EXEC_ONLY in r.since("piped"), r.output)
    check("piped: set not sent", not r.called("-m configure set x"), str(r.calls))


def case_activity_keeps_role():
    # Commands slide the role; the timer re-arms instead of leaving.
    r = run(["configure", ("sleep", 2.5), "set a", ("sleep", 2.5), "set b",
             ("sleep", 8), "", "exit"], ttl=4)
    check("activity: still in configure mode after the first deadline",
          r.called("-m configure set b"), str(r.calls))
    check("activity: timer re-armed", r.count("--timer") >= 2, str(r.calls))
    check("activity: lapses once idle", NOTICE in r.output, r.output)


def case_disable_stops_timer():
    r = run(["enable", "disable", ("sleep", 3), "", "exit"], ttl=2)
    check("disable: no timeout notice", "timed out" not in r.output, r.output)


def case_unreachable_at_start():
    r = run([("mark", "typed"), "show version", "exit"], down=True)
    check("down at start: warned at once", UNREACHABLE in r.output[:r.marks["typed"]], r.output)
    check("down at start: warned on a command", UNREACHABLE in r.since("typed"), r.output)
    check("down at start: not 'command not found'", "command not found" not in r.output, r.output)
    check("down at start: exit leaves", not r.timed_out)


def case_unreachable_later():
    r = run(["show version", ("down",), ("mark", "down"), "show version", "exit"])
    check("down later: no warning while up", UNREACHABLE not in r.output[:r.marks["down"]], r.output)
    check("down later: warned", UNREACHABLE in r.since("down"), r.output)


def case_unreachable_completion_quiet():
    r = run([("raw", "sh\t\t"), ("raw", "\x15"), "exit"], down=True)
    check("down: TAB stays quiet", r.output.count(UNREACHABLE) == 1, r.output)


def case_configure_unreachable():
    r = run([("down",), ("mark", "down"), "configure", "exit"])
    after = r.since("down")
    check("configure while down: warned", UNREACHABLE in after, r.output)
    check("configure while down: warned once", after.count(UNREACHABLE) == 1, r.output)
    check("configure while down: no access-denied", "access denied" not in after, r.output)


def case_vty_redraws_at_once():
    # The patched vty prints the notice while readline waits, and
    # redraws the half-typed line after the exec-mode prompt.
    if not VTY.exists():
        print(f"SKIP vty redraw: {VTY} not built (run `make -C vty` first)")
        return
    r = run(["configure", ("raw", "set inter"), ("sleep", 3.5), ("mark", "lapsed"),
             ("raw", "\x15"), "exit"], ttl=2, vty=True)
    before_enter = r.output[:r.marks["lapsed"]]
    check("vty: notice before any Enter", NOTICE in before_enter, r.output)
    tail = before_enter.split(NOTICE, 1)[-1]
    check("vty: exec prompt redrawn with the typed text", "teststub>set inter" in tail, repr(tail))
    check("vty: exit leaves", not r.timed_out)


def main():
    case_idle_lapse()
    case_refused_command()
    case_exit_after_lapse()
    case_reenter_after_lapse()
    case_reenter_within_role_no_password()
    case_abbreviation_takes_role()
    case_piped_refusal()
    case_activity_keeps_role()
    case_disable_stops_timer()
    case_unreachable_at_start()
    case_unreachable_later()
    case_unreachable_completion_quiet()
    case_configure_unreachable()
    case_vty_redraws_at_once()
    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s)")
        sys.exit(1)
    print("\nall admin-timeout checks passed")


if __name__ == "__main__":
    main()
