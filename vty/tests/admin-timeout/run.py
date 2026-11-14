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

import atexit
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
        atexit.register(shutil.rmtree, shim, True)
    return _SHIMS[group]


# The stub starts with #!/bin/bash, not env: through env its process
# would be named "bash", and vty.sh rightly takes only a process named
# vtyhelper for its timer.


def stop_timers(state):
    """Stop stub timers still running: they are background jobs in their
    own process groups, out of reach of the shell's group kill."""
    timers = state / "timers"
    if not timers.exists():
        return
    for pid in timers.read_text().split():
        try:
            os.kill(int(pid), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass


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


def run(steps, ttl=3, timer=True, group=True, down=False, vty=False, old=False, deny=False,
        noisy=False, env_extra=None, timeout=30.0):
    """Drive an interactive shell through `steps`: a string is typed as a
    line; ("sleep", s) waits; ("raw", s) types without Enter;
    ("down",) makes the daemon unreachable; ("droprole",) takes the
    admin role away (a daemon restart); ("hostname", name) renames the
    host; ("mark", name) remembers where the output stands."""
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
    if old:
        env["STUB_OLD"] = "1"
    if deny:
        env["STUB_DENY"] = "1"
    if noisy:
        env["STUB_NOISY"] = "1"
    env.update(env_extra or {})
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
            elif step[0] == "droprole":
                (state / "deadline").unlink(missing_ok=True)
            elif step[0] == "hostname":
                (state / "hostname").write_text(step[1] + "\n")
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
        stop_timers(state)
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
    # `exit` needs no role: it leaves configure mode even after the role
    # lapsed, timer or not. The echo's answer is built at run time: the
    # terminal echoes the typed line, which must not contain it.
    r = run(["configure", ("sleep", 2.5), "exit", ("mark", "out"), "echo still-$((40 + 2))",
             "set x", "exit"], ttl=1, timer=False)
    check("exit after lapse: reached the daemon", r.called("-m configure exit"), str(r.calls))
    check("exit after lapse: shell still up", "still-42" in r.output, r.output)
    check("exit after lapse: in exec mode", EXEC_ONLY in r.since("out"), r.output)
    check("exit after lapse: set not sent", not r.called("-m configure set x"), str(r.calls))
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
    # `configure` asks nothing first: the daemon's refusal is the answer.
    check("no second password: no question asked", "-a" not in r.calls, str(r.calls))
    check("no second password: leaves", not r.timed_out)


def case_abbreviation_takes_role():
    # Refused like the whole word (the daemon gates what it resolves
    # to): the role is taken and the line tried again.
    r = run(["conf", "set b", "exit", "exit"], ttl=30)
    check("conf: takes the role", r.called("-e"), str(r.calls))
    check("conf: tried again", r.calls.count("-m exec conf") == 2, str(r.calls))
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


# Prints whether a timer runs as a child of the shell. Asked in the
# shell itself, so that `pgrep -P $$` lists the shell's own children.
# The answer is built at run time: the terminal echoes the typed line,
# which must not contain it.
TIMER_PROBE = ("if pgrep -P $$ -f -- '--timer' >/dev/null; then s=ALIVE; else s=GONE; fi; "
               "echo \"timer:${s}:\"")


def case_disable_stops_timer():
    r = run(["enable", ("mark", "enabled"), TIMER_PROBE, "disable", ("mark", "disabled"),
             TIMER_PROBE, "exit"], ttl=30)
    between = r.output[r.marks["enabled"]:r.marks["disabled"]]
    check("disable: a timer ran while enabled", "timer:ALIVE:" in between, r.output)
    check("disable: the timer is stopped", "timer:GONE:" in r.since("disabled"), r.output)


def case_failed_reenable_keeps_timer():
    # A second `enable` that fails leaves the first one's role, which
    # must still time out.
    r = run(["enable", "secret", "enable", "wrong", ("sleep", 3.5), "", "exit"],
            ttl=2, group=False)
    check("failed re-enable: refused", "authentication failed" in r.output, r.output)
    check("failed re-enable: role still times out", "% Admin role timed out." in r.output, r.output)


def case_configure_unreachable_no_password():
    # Not in the group: no root password asked for a daemon that is
    # not there.
    r = run([("mark", "typed"), "configure", "exit"], down=True, group=False)
    after = r.since("typed")
    check("down, no group: no password prompt", "Root password:" not in r.output, r.output)
    check("down, no group: warned once", after.count(UNREACHABLE) == 1, r.output)


def case_old_daemon_no_second_password():
    # A daemon from before the question cannot say whether the role is
    # held: one password, and none again on re-entry while it lives.
    r = run(["configure", "secret", "exit", "configure", "set b", "exit", "exit"],
            ttl=30, group=False, old=True)
    check("old daemon: one password prompt", r.output.count("Root password:") == 1, r.output)
    check("old daemon: in configure mode again", r.called("-m configure set b"), str(r.calls))
    check("old daemon: no timer it cannot feed", not r.called("--timer"), str(r.calls))


def case_configure_refused_says_so():
    # Refused even with the role just taken: say so.
    r = run(["configure", "exit"], deny=True)
    check("refused after taking the role: says so",
          "% Configuration access denied" in r.output, r.output)


def case_registration_ignores_stderr():
    # Only the command list becomes aliases: what the helper writes to
    # stderr must not.
    r = run(["if alias noise >/dev/null 2>&1; then a=yes; else a=no; fi; echo \"noise-alias:$a\"",
             "exit"], noisy=True)
    check("noisy helper: no alias from stderr", "noise-alias:no" in r.output, r.output)


def case_timer_check_reads_comm_safely():
    # A process that reuses the timer's pid may be anyone's, named
    # anything: its name must neither run as code nor pass for a timer.
    work = Path(tempfile.mkdtemp(prefix="vty-admin-comm-"))
    script = work / "script.sh"
    script.write_text(f"""source {VTY_SH}
cd {work}
( printf '%s' 'a b x[$(>M)]' >/proc/$BASHPID/comm; sleep 3; : ) &
pid=$!
sleep 0.3
echo "comm=[$(cat /proc/$pid/comm)]"
if _cli_admin_timer_alive "$pid"; then r=yes; else r=no; fi
echo "alive:$r"
kill $pid
""")
    env = dict(os.environ)
    env.pop("CLI_SERVER_URL", None)
    env["PATH"] = f"{shim_dir(True)}:{env['PATH']}"
    env["STUB_STATE"] = str(work)
    proc = subprocess.run(["bash", str(script)], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env=env, timeout=20)
    injected = (work / "M").exists()
    shutil.rmtree(work, ignore_errors=True)
    text = proc.stdout.decode("utf-8", "replace")
    if VERBOSE:
        print(f"--- comm script output ---\n{text}")
    check("hostile comm: the name was set", "comm=[a b x[$(>M)]]" in text, text)
    check("hostile comm: not taken for a timer", "alive:no" in text, text)
    check("hostile comm: nothing ran", not injected, text)


def case_transient_failure_keeps_watching():
    # The daemon could not be asked once: ask again, not stop watching.
    # Stock bash runs the trap at the next Enter: one for the timer, one
    # for the retry a second later.
    r = run(["configure", ("sleep", 3), "", ("sleep", 2), "", "exit"], ttl=2,
            env_extra={"STUB_A_FAIL_ONCE": "1", "CLI_ADMIN_RETRY": "1"})
    check("transient: asked again", r.calls.count("-a") >= 2, str(r.calls))
    check("transient: lapse still noticed", NOTICE in r.output, r.output)


def case_disable_in_configure_mode_leaves_it():
    r = run(["configure", "disable", ("mark", "off"), "set x", "exit"], ttl=30)
    check("disable in configure: back in exec mode", EXEC_ONLY in r.since("off"), r.output)
    check("disable in configure: set not sent", not r.called("-m configure set x"), str(r.calls))


def case_role_taken_is_not_a_timeout():
    # A daemon restart takes the role long before its time: say so, and
    # do not blame the clock.
    r = run(["configure", ("droprole",), "set x", "exit"], ttl=30)
    check("role taken: told", "% Admin role no longer held; back to exec mode." in r.output, r.output)
    check("role taken: not a timeout", "timed out" not in r.output, r.output)


def case_failed_take_drops_stale_prompt():
    # `#` from enable, the role taken by a restart, a wrong password at
    # `configure`: the `#` must go.
    r = run(["enable", "secret", ("droprole",), "configure", "wrong", "exit"],
            ttl=30, group=False)
    check("failed take: access denied", "% Configuration access denied" in r.output, r.output)
    check("failed take: stale # dropped", "% Admin role no longer held." in r.output, r.output)


def case_dash_words_reach_the_daemon():
    # The operator's words are not helper options.
    r = run(["configure", "set interface eth0 description -a", "exit", "exit"], ttl=30)
    check("dash word: reached the daemon",
          "RECEIVED:set interface eth0 description -a" in r.output, r.output)


def case_old_helper_still_follows_hostname():
    # A vty rebuilt without reinstalling vtyhelper: no -S, but the
    # prompt still follows the host name.
    r = run([("hostname", "renamed"), "show version", "exit"], env_extra={"STUB_NO_S": "1"})
    check("old helper: prompt renamed", "renamed>" in r.output, r.output)


def case_script_warns_once():
    # Not interactive: the command says the daemon is down; startup does
    # not say it first.
    state = Path(tempfile.mkdtemp(prefix="vty-admin-state-"))
    (state / "down").touch()
    script = state / "script.sh"
    script.write_text(f"source {VTY_SH}\nshow version\n")
    env = dict(os.environ)
    env.pop("CLI_SERVER_URL", None)
    env["PATH"] = f"{shim_dir(True)}:{env['PATH']}"
    env["STUB_STATE"] = str(state)
    proc = subprocess.run(["bash", str(script)], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env=env, timeout=20)
    shutil.rmtree(state, ignore_errors=True)
    text = proc.stdout.decode("utf-8", "replace")
    if VERBOSE:
        print(f"--- script output ---\n{text}")
    check("script: warned once", text.count(UNREACHABLE) == 1, text)


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
    # TAB on an empty line: vty.sh's completion even under stock bash,
    # whose own command completion takes a first word like `sh`.
    r = run([("raw", "\t\t"), ("raw", "\x15"), "exit"], down=True)
    check("down: TAB stays quiet", r.output.count(UNREACHABLE) == 1, r.output)
    # Two at startup (the attempt, then the warning); one per TAB.
    firsts = r.calls.count("-f -m exec")
    check("down: one attempt per TAB", firsts == 4, str(r.calls))


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
             "exit"], ttl=2, vty=True)
    before_enter = r.output[:r.marks["lapsed"]]
    check("vty: notice before any Enter", NOTICE in before_enter, r.output)
    head, _, tail = before_enter.partition(NOTICE)
    check("vty: typed text left above", "teststub#set inter" in head, repr(head))
    # Not carried over: typed for configure mode, `exit` would leave the
    # vty in exec mode.
    check("vty: fresh exec-mode line", tail.rstrip().endswith("teststub>"), repr(tail))
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
    case_failed_reenable_keeps_timer()
    case_configure_unreachable_no_password()
    case_old_daemon_no_second_password()
    case_script_warns_once()
    case_configure_refused_says_so()
    case_transient_failure_keeps_watching()
    case_disable_in_configure_mode_leaves_it()
    case_role_taken_is_not_a_timeout()
    case_failed_take_drops_stale_prompt()
    case_dash_words_reach_the_daemon()
    case_old_helper_still_follows_hostname()
    case_registration_ignores_stderr()
    case_timer_check_reads_comm_safely()
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
