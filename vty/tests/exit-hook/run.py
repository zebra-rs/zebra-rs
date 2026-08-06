#!/usr/bin/env python3
"""Exercise vty.sh's uncommitted-changes exit hook under stock bash.

The hook lives in an EXIT trap and depends on nothing the vty bash patch
provides — that patch touches completion (`bashline.c`), the build, and
the startup-string hook (`shell.c`), while `trap`, `read` and EOF
handling are stock. So the whole matrix runs against the system bash
with `--rcfile vty.sh -i`, with `stub-vtyhelper` first on PATH standing
in for the daemon. No zebra-rs build, no patched bash, seconds to run.

Each case drives a real pty, because the hook's guards (`-t 0`, `-t 2`)
and its `read` timeout only mean anything on a terminal.

Usage: vty/tests/exit-hook/run.py [-v]
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
PROMPT = "You have uncommitted changes"

# Entering configure mode is what arms the hook. Call the alias body
# directly rather than the `configure` shell function, which would
# detour through the enable/password flow that is not under test.
ENTER_CONFIGURE = b"_cli_exec configure\n"

VERBOSE = "-v" in sys.argv[1:]


_SHIM = None


def shim_dir():
    """A PATH entry exposing the stub under the name vty.sh calls."""
    global _SHIM
    if _SHIM is None:
        _SHIM = Path(tempfile.mkdtemp(prefix="vty-shim-"))
        stub = HERE / "stub-vtyhelper"
        os.chmod(stub, 0o755)
        (_SHIM / "vtyhelper").symlink_to(stub)
    return _SHIM


class Result:
    def __init__(self, output, calls, status, timed_out):
        self.output = output
        self.calls = calls
        self.status = status
        self.timed_out = timed_out

    def called(self, needle):
        return any(needle in c for c in self.calls)

    def index_of(self, needle):
        for i, c in enumerate(self.calls):
            if needle in c:
                return i
        return -1


def run(script, env_extra=None, tty=True, timeout=20.0, hup_after=None):
    """Run bash with vty.sh as its rcfile and feed it `script`."""
    log = tempfile.NamedTemporaryFile(prefix="vty-stub-", suffix=".log", delete=False)
    log.close()

    env = dict(os.environ)
    # vty.sh invokes the helper by bare name, so the stub has to be
    # reachable as `vtyhelper` — hence the symlinked shim directory
    # rather than just putting this directory on PATH.
    env["PATH"] = f"{shim_dir()}:{env['PATH']}"
    env["STUB_LOG"] = log.name
    env["CLI_EXIT_PROMPT_TIMEOUT"] = "2"
    # Keep the pager out of the captured output.
    env["CLI_PAGER"] = "cat"
    env.update(env_extra or {})

    argv = ["bash", "--rcfile", str(VTY_SH), "-i"]

    if tty:
        master, slave = pty.openpty()

        def preexec():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            preexec_fn=preexec,
            close_fds=True,
        )
        os.close(slave)
        reader, writer = master, master
    else:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            close_fds=True,
        )
        reader, writer = proc.stdout.fileno(), proc.stdin.fileno()

    out = bytearray()
    deadline = time.time() + timeout
    hup_at = time.time() + hup_after if hup_after else None
    try:
        for chunk in script:
            os.write(writer, chunk)
            time.sleep(0.35)
        if not tty:
            os.close(writer)
        while time.time() < deadline:
            if hup_at and time.time() >= hup_at:
                os.killpg(os.getpgid(proc.pid), signal.SIGHUP)
                hup_at = None
            ready, _, _ = select.select([reader], [], [], 0.2)
            if ready:
                try:
                    data = os.read(reader, 65536)
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
        status = proc.wait()
    finally:
        try:
            os.close(reader)
        except OSError:
            pass
        calls = [
            line.strip()
            for line in Path(log.name).read_text().splitlines()
            if line.strip()
        ]
        os.unlink(log.name)

    text = out.decode("utf-8", "replace")
    if VERBOSE:
        print(f"--- output ---\n{text}\n--- calls ---\n" + "\n".join(calls))
    return Result(text, calls, status, timed_out)


FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}{(': ' + detail) if detail else ''}")
        FAILURES.append(name)


def case_commit():
    r = run([ENTER_CONFIGURE, b"exit\n", b"y\n"], {"STUB_UNCOMMITTED": "0"})
    check("dirty + y prompts", PROMPT in r.output)
    check("dirty + y commits", r.called("-m configure commit"), str(r.calls))
    # Logout must come after the commit: dropping the session first
    # would demote the next RPC to a View session and the commit would
    # be refused.
    check(
        "commit precedes logout",
        0 <= r.index_of("-m configure commit") < r.index_of("-l"),
        str(r.calls),
    )
    check("shell exited", not r.timed_out)


def case_discard():
    r = run([ENTER_CONFIGURE, b"exit\n", b"n\n"], {"STUB_UNCOMMITTED": "0"})
    check("dirty + n discards", r.called("-m configure discard"), str(r.calls))
    check("dirty + n does not commit", not r.called("-m configure commit"))


def case_leave_pending():
    for label, answer in (("enter", b"\n"), ("garbage", b"maybe\n")):
        r = run([ENTER_CONFIGURE, b"exit\n", answer], {"STUB_UNCOMMITTED": "0"})
        check(
            f"dirty + {label} leaves pending",
            not r.called("-m configure commit") and not r.called("-m configure discard"),
            str(r.calls),
        )
        check(f"dirty + {label} still logs out", r.called("-l"), str(r.calls))


def case_timeout():
    r = run([ENTER_CONFIGURE, b"exit\n"], {"STUB_UNCOMMITTED": "0"}, timeout=12)
    check("no answer times out", not r.timed_out, "shell hung at the prompt")
    check(
        "timeout leaves pending",
        not r.called("-m configure commit") and not r.called("-m configure discard"),
    )


def case_ctrl_d():
    # The regression this whole design turns on: tty EOF is not sticky,
    # so without `read -t` the trap's read blocks forever here.
    r = run([ENTER_CONFIGURE, b"\x04"], {"STUB_UNCOMMITTED": "0"}, timeout=12)
    check("ctrl-d prompts", PROMPT in r.output, r.output[-200:])
    check("ctrl-d does not hang", not r.timed_out, "shell hung after EOF")


def case_clean():
    r = run([ENTER_CONFIGURE, b"exit\n"], {"STUB_UNCOMMITTED": "1"}, timeout=12)
    check("clean does not prompt", PROMPT not in r.output)
    check("clean still logs out", r.called("-l"), str(r.calls))


def case_unknown():
    r = run([ENTER_CONFIGURE, b"exit\n"], {"STUB_UNCOMMITTED": "2"}, timeout=12)
    check("unknown does not prompt", PROMPT not in r.output)


def case_never_configured():
    r = run([b"exit\n"], {"STUB_UNCOMMITTED": "0"}, timeout=12)
    check("never configured does not prompt", PROMPT not in r.output)
    check("never configured skips the query", not r.called("-u"), str(r.calls))


def case_commit_denied():
    r = run(
        [ENTER_CONFIGURE, b"exit\n", b"y\n"],
        {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_RC": "1"},
    )
    check("denied commit is reported", "commit failed" in r.output, r.output[-300:])


def case_commit_validation_error():
    r = run(
        [ENTER_CONFIGURE, b"exit\n", b"y\n"],
        {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_OUT": "% mandatory node missing"},
    )
    check("validation errors surface", "mandatory node missing" in r.output, r.output[-300:])
    check("no bare Show marker leaks", "\nShow\n" not in r.output, r.output[-300:])


def case_no_tty():
    r = run([ENTER_CONFIGURE, b"exit\n"], {"STUB_UNCOMMITTED": "0"}, tty=False, timeout=12)
    check("no tty does not prompt", PROMPT not in r.output)
    check("no tty skips the query", not r.called("-u"), str(r.calls))


def case_sighup():
    r = run(
        [ENTER_CONFIGURE],
        {"STUB_UNCOMMITTED": "0"},
        timeout=12,
        hup_after=1.0,
    )
    check("sighup does not hang", not r.timed_out, "shell hung after SIGHUP")


def main():
    if not VTY_SH.exists():
        sys.exit(f"vty.sh not found at {VTY_SH}")
    for fn in (
        case_commit,
        case_discard,
        case_leave_pending,
        case_timeout,
        case_ctrl_d,
        case_clean,
        case_unknown,
        case_never_configured,
        case_commit_denied,
        case_commit_validation_error,
        case_no_tty,
        case_sighup,
    ):
        fn()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} failing: {', '.join(FAILURES)}")
        return 1
    print("all exit-hook checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
