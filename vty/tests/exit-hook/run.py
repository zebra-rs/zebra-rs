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
import re
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
        # What the stub remembers between its calls.
        for suffix in (".state.commits", ".state.clean"):
            try:
                os.unlink(log.name + suffix)
            except FileNotFoundError:
                pass

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


LOST = "the uncommitted changes are lost with this session"


def commits(r):
    return sum(1 for c in r.calls if "-m configure commit" in c)


def case_commit():
    r = run([ENTER_CONFIGURE, b"exit\n", b"y\n"], {"STUB_UNCOMMITTED": "0"})
    check("dirty + y prompts", PROMPT in r.output)
    check("dirty + y commits", r.called("-m configure commit"), str(r.calls))
    check("a commit that is made is asked once", r.output.count(PROMPT) == 1, r.output[-300:])
    check("a commit that is made loses nothing", LOST not in r.output, r.output[-300:])
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
    """The admin role lapsed while the edits waited, and cannot be taken
    again: there is no committing, and the operator who answered `y` is
    told the edits are gone. The Logout drops them."""
    r = run(
        [IN_GROUP, ENTER_CONFIGURE, b"exit\n", b"y\n"],
        {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_SEQ": "denied", "STUB_ENABLE_RC": "1"},
    )
    check("denied commit asks for the role", r.called("-e"), str(r.calls))
    check("denied commit is reported", "admin role is required" in r.output, r.output[-300:])
    check("denied commit says the edits are lost", LOST in r.output, r.output[-300:])
    check("denied commit is not asked again", r.output.count(PROMPT) == 1, r.output[-400:])
    check("denied commit still logs out", r.called("-l"), str(r.calls))
    check("denied commit exits", not r.timed_out)


def case_commit_after_role_lapsed():
    """The role lapsed and is given again: the commit is made after all,
    without a second question."""
    r = run(
        [IN_GROUP, ENTER_CONFIGURE, b"exit\n", b"y\n"],
        {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_SEQ": "denied ok"},
    )
    check("lapsed role is taken again", r.called("-e"), str(r.calls))
    check("lapsed role: no password for the group", "Root password:" not in r.output, r.output[-300:])
    check("lapsed role: commit is repeated", commits(r) == 2, str(r.calls))
    at = [i for i, c in enumerate(r.calls) if "-m configure commit" in c]
    check(
        "lapsed role: the role is taken between the two commits",
        len(at) == 2 and at[0] < r.index_of("-e") < at[1],
        str(r.calls),
    )
    check("lapsed role: nothing is lost", LOST not in r.output, r.output[-300:])
    check("lapsed role: asked once", r.output.count(PROMPT) == 1, r.output[-400:])


# Whoever runs the tests may or may not be in the group that is given
# the role without a password; each case says which it is about.
NOT_IN_GROUP = b"_cli_in_config_group () { return 1; }\n"
IN_GROUP = b"_cli_in_config_group () { return 0; }\n"


def case_commit_role_needs_password():
    """Outside the group the role costs the root password, asked for
    here as `enable` asks. The prompt must not hold a shell that is
    leaving: unanswered, it gives up like the question before it."""
    r = run(
        [NOT_IN_GROUP, ENTER_CONFIGURE, b"exit\n", b"y\n", b"secret\n"],
        {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_SEQ": "denied ok"},
    )
    check("password: asked for", "Root password:" in r.output, r.output[-400:])
    check("password: not echoed", "secret" not in r.output, r.output[-400:])
    check("password: commit is repeated", commits(r) == 2, str(r.calls))
    check("password: nothing is lost", LOST not in r.output, r.output[-300:])

    r = run(
        [NOT_IN_GROUP, ENTER_CONFIGURE, b"exit\n", b"y\n"],
        {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_SEQ": "denied", "STUB_ENABLE_RC": "1"},
        timeout=12,
    )
    check("password unanswered: does not hang", not r.timed_out, "hung at the password")
    check("password unanswered: edits said lost", LOST in r.output, r.output[-300:])
    check("password unanswered: still logs out", r.called("-l"), str(r.calls))


def case_commit_validation_error():
    """A commit the daemon refuses leaves the edits uncommitted. Its
    reason is shown and the question comes back; giving up is said."""
    r = run(
        [ENTER_CONFIGURE, b"exit\n", b"y\n"],
        {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_OUT": "% mandatory node missing"},
        timeout=12,
    )
    check("validation errors surface", "mandatory node missing" in r.output, r.output[-300:])
    check("no bare Show marker leaks", "\nShow\n" not in r.output, r.output[-300:])
    check("refused commit asks again", r.output.count(PROMPT) == 2, r.output[-400:])
    check("refused commit, no answer: edits said lost", LOST in r.output, r.output[-300:])
    check("refused commit does not hang", not r.timed_out)
    check("refused commit still logs out", r.called("-l"), str(r.calls))

    r = run(
        [ENTER_CONFIGURE, b"exit\n", b"y\n", b"n\n"],
        {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_OUT": "% mandatory node missing"},
    )
    check("refused commit then n discards", r.called("-m configure discard"), str(r.calls))
    check("refused commit then n: one commit", commits(r) == 1, str(r.calls))


def case_commit_refused_once():
    """Another session's commit changed a leaf this one edited: the
    daemon refuses the commit once and takes it when it is typed again.
    At exit that second `y` must be possible."""
    refusal = "% Another commit changed what this session has edited."
    r = run(
        [ENTER_CONFIGURE, b"exit\n", b"y\n", b"y\n"],
        {
            "STUB_UNCOMMITTED": "0",
            "STUB_COMMIT_SEQ": "refused ok",
            "STUB_COMMIT_OUT": refusal,
        },
    )
    check("refusal is shown", refusal in r.output, r.output[-400:])
    check("refused once: asked twice", r.output.count(PROMPT) == 2, r.output[-400:])
    check("refused once: committed the second time", commits(r) == 2, str(r.calls))
    check("refused once: nothing is lost", LOST not in r.output, r.output[-300:])
    check(
        "refused once: logout is last",
        r.calls and r.calls[-1] == "-l",
        str(r.calls),
    )


def case_commit_note():
    """A commit that is made may say something (others committed
    meanwhile). That is no refusal."""
    note = "Note: others committed while these edits were pending"
    r = run(
        [ENTER_CONFIGURE, b"exit\n", b"y\n"],
        {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_SEQ": "noted", "STUB_COMMIT_OUT": note},
    )
    check("a commit's note is shown", note in r.output, r.output[-300:])
    check("a noted commit is asked once", r.output.count(PROMPT) == 1, r.output[-400:])
    check("a noted commit loses nothing", LOST not in r.output, r.output[-300:])


def case_commit_unreachable():
    for outcome, said in (("unreachable", "Cannot reach zebra-rs"), ("failed", "stub failure")):
        r = run(
            [ENTER_CONFIGURE, b"exit\n", b"y\n"],
            {"STUB_UNCOMMITTED": "0", "STUB_COMMIT_SEQ": outcome},
        )
        check(f"{outcome}: the helper's reason is shown", said in r.output, r.output[-300:])
        check(f"{outcome}: commit not done is said", "commit not done" in r.output, r.output[-300:])
        check(f"{outcome}: edits said lost", LOST in r.output, r.output[-300:])
        check(f"{outcome}: not asked again", r.output.count(PROMPT) == 1, r.output[-400:])
        check(f"{outcome}: no role is asked for", not r.called("-e"), str(r.calls))


def case_no_tty():
    r = run([ENTER_CONFIGURE, b"exit\n"], {"STUB_UNCOMMITTED": "0"}, tty=False, timeout=12)
    check("no tty does not prompt", PROMPT not in r.output)
    check("no tty skips the query", not r.called("-u"), str(r.calls))


def case_prompt_width():
    """80 columns is the floor to design for — the question is asked on
    whatever terminal the operator happens to be leaving from, and a
    prompt that wraps pushes the answer onto its own line."""
    match = re.search(r'-r -p \\\n\s*"([^"]+)"', VTY_SH.read_text())
    check("prompt string is findable", match is not None)
    if match:
        width = len(match.group(1))
        check(f"prompt fits 80 columns (is {width})", width <= 80)


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
        case_commit_after_role_lapsed,
        case_commit_role_needs_password,
        case_commit_validation_error,
        case_commit_refused_once,
        case_commit_note,
        case_commit_unreachable,
        case_no_tty,
        case_prompt_width,
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
