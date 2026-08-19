#!/usr/bin/env python3
"""Exercise the patched vty binary's --vty-socket option.

Unlike the exit-hook suite, which runs vty.sh under stock bash, these
cases need the patched binary itself: the option is consumed in
shell.c/vtysh.c before bash's own long-option parsing would reject it,
and surfaces as an exported CLI_SERVER_URL by the time vty.sh invokes
vtyhelper. The stub helper on PATH records the CLI_SERVER_URL it
inherits, which is the entire contract under test.

Run after `make -C vty`; exits with a SKIP message when build/vty is
absent so it never gates an unbuilt tree.

Usage: vty/tests/vty-socket/run.py [-v]
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VTY = HERE.parents[1] / "build" / "vty"

VERBOSE = "-v" in sys.argv[1:]

_SHIM = None


def shim_dir():
    global _SHIM
    if _SHIM is None:
        _SHIM = Path(tempfile.mkdtemp(prefix="vty-sock-shim-"))
        stub = HERE / "stub-vtyhelper"
        os.chmod(stub, 0o755)
        (_SHIM / "vtyhelper").symlink_to(stub)
    return _SHIM


def run(args, env_extra=None, interactive=True):
    """Run the patched vty and return (urls_seen, stdout+stderr, rc)."""
    log = tempfile.NamedTemporaryFile(prefix="vty-sock-", suffix=".log", delete=False)
    log.close()

    env = dict(os.environ)
    env.pop("CLI_SERVER_URL", None)
    env["PATH"] = f"{shim_dir()}:{env['PATH']}"
    env["STUB_LOG"] = log.name
    env["CLI_EXIT_PROMPT_TIMEOUT"] = "2"
    env["CLI_PAGER"] = "cat"
    env.update(env_extra or {})

    argv = [str(VTY)] + args + (["-i"] if interactive else [])
    proc = subprocess.run(
        argv,
        input=b"exit\n" if interactive else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        timeout=20,
    )

    urls = [
        line.strip()
        for line in Path(log.name).read_text().splitlines()
        if line.strip()
    ]
    os.unlink(log.name)
    text = proc.stdout.decode("utf-8", "replace")
    if VERBOSE:
        print(f"--- argv {argv}\n--- output ---\n{text}\n--- urls {urls}")
    return urls, text, proc.returncode


FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}{(': ' + detail) if detail else ''}")
        FAILURES.append(name)


def one_url(urls):
    """The URL every helper call in the session saw, or None if mixed."""
    return urls[0] if urls and len(set(urls)) == 1 else None


def case_abstract():
    urls, _, _ = run(["--vty-socket", "unix:custom/sock"])
    check("abstract name reaches helper", one_url(urls) == "unix:custom/sock", str(urls))


def case_path():
    urls, _, _ = run(["--vty-socket", "unix:/tmp/zebra-rs-test"])
    check("filesystem path passes verbatim", one_url(urls) == "unix:/tmp/zebra-rs-test", str(urls))


def case_equals_form():
    urls, _, _ = run(["--vty-socket=unix:eq/sock"])
    check("--vty-socket=VALUE form", one_url(urls) == "unix:eq/sock", str(urls))


def case_explicit_abstract():
    # `@` resolution belongs to the helper's connector; the shell must
    # not strip it.
    urls, _, _ = run(["--vty-socket", "unix:@/tmp/forced-abstract"])
    check("@ passes verbatim", one_url(urls) == "unix:@/tmp/forced-abstract", str(urls))


def case_tcp_daemon_form():
    urls, _, _ = run(["--vty-socket", "tcp:192.0.2.1:2666"])
    check("tcp:HOST:PORT normalized", one_url(urls) == "tcp://192.0.2.1:2666", str(urls))


def case_flag_beats_env():
    urls, _, _ = run(
        ["--vty-socket", "unix:flagwins"],
        {"CLI_SERVER_URL": "unix:fromenv"},
    )
    check("flag beats inherited env", one_url(urls) == "unix:flagwins", str(urls))


def case_env_passthrough():
    urls, _, _ = run([], {"CLI_SERVER_URL": "unix:fromenv"})
    check("env alone still honored", one_url(urls) == "unix:fromenv", str(urls))


def case_default_unset():
    urls, _, _ = run([])
    check("no flag leaves env unset", one_url(urls) == "<unset>", str(urls))


def case_missing_value():
    _, text, rc = run(["--vty-socket"], interactive=False)
    check("missing value exits 2", rc == 2, f"rc={rc}")
    check("missing value reports", "requires an argument" in text, text[-200:])


def case_bad_value():
    _, text, rc = run(["--vty-socket", "bogus", "-c", "echo hi"], interactive=False)
    check("bad value exits 2", rc == 2, f"rc={rc}")
    check("bad value reports forms", "unix:NAME" in text, text[-200:])


def case_noninteractive_consumed():
    _, text, rc = run(
        ["--vty-socket", "unix:foo", "-c", "echo consumed"], interactive=False
    )
    check("option consumed before -c", rc == 0 and "consumed" in text, text[-200:])


def main():
    if not VTY.exists():
        print(f"SKIP: {VTY} not built (run `make -C vty` first)")
        return 0
    for fn in (
        case_abstract,
        case_path,
        case_equals_form,
        case_explicit_abstract,
        case_tcp_daemon_form,
        case_flag_beats_env,
        case_env_passthrough,
        case_default_unset,
        case_missing_value,
        case_bad_value,
        case_noninteractive_consumed,
    ):
        fn()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} failing: {', '.join(FAILURES)}")
        return 1
    print("all vty-socket checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
