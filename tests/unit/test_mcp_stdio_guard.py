"""The stdio guard: argument parsing, byte accounting, rlimits, relay and exit codes."""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from asca.infrastructure.knowledge import mcp_stdio_guard as guard

pytestmark = pytest.mark.unit

ARGS = ["--max-line", "10", "--max-total", "100", "--cpu", "5", "--"]


def test_parse_args_accepts_the_documented_command_line() -> None:
    assert guard.parse_args([*ARGS, "/bin/server", "--flag"]) == (
        10,
        100,
        5,
        ["/bin/server", "--flag"],
    )
    reordered = ["--cpu", "1", "--max-total", "2", "--max-line", "3", "--", "x"]
    assert guard.parse_args(reordered) == (3, 2, 1, ["x"])


@pytest.mark.parametrize(
    "argv",
    [
        ["--max-line", "10", "--max-total", "100", "--cpu", "5", "/bin/server"],
        ARGS,
        ["--max-line", "10", "--max-total", "100", "--", "x"],
        ["--max-line", "10", "--max-line", "10", "--cpu", "5", "--", "x"],
        ["--max-line", "10", "--max-total", "100", "--bogus", "5", "--", "x"],
        ["--max-line", "ten", "--max-total", "100", "--cpu", "5", "--", "x"],
        ["--max-line", "0", "--max-total", "100", "--cpu", "5", "--", "x"],
        ["--max-line", "١٢", "--max-total", "100", "--cpu", "5", "--", "x"],
    ],
)
def test_parse_args_refuses_malformed_command_lines(argv: list[str]) -> None:
    with pytest.raises(guard._UsageError):
        guard.parse_args(argv)


def test_line_counter_tracks_lines_across_chunks() -> None:
    counter = guard.LineCounter(max_line=5, max_total=100)
    assert counter.accept(b"abc")
    assert counter.accept(b"de\nfg")
    assert counter.line == 2
    assert counter.accept(b"h\n\n12345\n")
    assert not counter.accept(b"123456")


def test_line_counter_refuses_a_long_line_inside_one_chunk() -> None:
    assert not guard.LineCounter(max_line=3, max_total=100).accept(b"a\nabcd\nb")
    assert not guard.LineCounter(max_line=3, max_total=100).accept(b"ab\ncdef")
    assert not guard.LineCounter(max_line=3, max_total=100).accept(b"abcd\n")


def test_line_counter_enforces_the_total() -> None:
    counter = guard.LineCounter(max_line=100, max_total=6)
    assert counter.accept(b"ab\ncd\n")
    assert not counter.accept(b"e")


class FakeRlimits:
    RLIM_INFINITY = -1
    RLIMIT_CORE = "core"
    RLIMIT_CPU = "cpu"
    RLIMIT_NOFILE = "nofile"
    RLIMIT_FSIZE = "fsize"
    RLIMIT_AS = "as"

    def __init__(self) -> None:
        self.calls: dict[str, tuple[int, int]] = {}

    def getrlimit(self, kind: str) -> tuple[int, int]:
        return (-1, 128 if kind == "nofile" else -1)

    def setrlimit(self, kind: str, limits: tuple[int, int]) -> None:
        self.calls[kind] = limits


def test_apply_limits_sets_every_limit_without_raising_a_hard_limit() -> None:
    fake = FakeRlimits()
    guard.apply_limits(60, fake)
    assert fake.calls["core"] == (0, 0)
    assert fake.calls["cpu"] == (60, 60)
    assert fake.calls["nofile"] == (128, 128)
    assert fake.calls["fsize"] == (guard.FSIZE, guard.FSIZE)
    if sys.platform.startswith("linux"):
        assert fake.calls["as"] == (guard.ADDRESS_SPACE, guard.ADDRESS_SPACE)


def _child(code: str) -> "subprocess.Popen[bytes]":
    return subprocess.Popen(
        [sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )


def test_relay_copies_output_and_returns_the_child_code(capfd: pytest.CaptureFixture[str]) -> None:
    child = _child("import sys; sys.stdout.write('one\\ntwo\\n'); sys.exit(3)")
    assert guard.relay(child, guard.LineCounter(100, 1000)) == 3
    assert capfd.readouterr().out == "one\ntwo\n"


def test_relay_kills_a_flooding_child(capfd: pytest.CaptureFixture[str]) -> None:
    child = _child(
        "import sys, time; sys.stdout.write('x' * 5000); sys.stdout.flush(); time.sleep(60)"
    )
    started = time.monotonic()
    assert guard.relay(child, guard.LineCounter(1000, 100_000)) == guard.EXIT_OUTPUT_LIMIT
    assert time.monotonic() - started < 30
    assert child.returncode is not None
    assert "x" * 1001 not in capfd.readouterr().out


def test_relay_maps_a_signal_death(capfd: pytest.CaptureFixture[str]) -> None:
    child = _child("import os, signal; os.kill(os.getpid(), signal.SIGTERM)")
    assert guard.relay(child, guard.LineCounter(100, 1000)) == 128 + signal.SIGTERM


def test_relay_stops_the_child_on_a_broken_pipe(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(data: bytes) -> None:
        raise BrokenPipeError

    monkeypatch.setattr(guard, "_write_all", broken)
    child = _child(
        "import sys, time; sys.stdout.write('hi\\n'); sys.stdout.flush(); time.sleep(60)"
    )
    assert guard.relay(child, guard.LineCounter(100, 1000)) == guard.EXIT_BROKEN_PIPE
    assert child.returncode is not None


def test_main_refuses_other_platforms_and_bad_usage() -> None:
    assert guard.main([*ARGS, "x"], limits=lambda cpu: None, platform="nt") == guard.EXIT_PLATFORM
    assert guard.main(["--cpu", "1"], limits=lambda cpu: None) == guard.EXIT_USAGE


def test_main_runs_the_child_with_limits(capfd: pytest.CaptureFixture[str]) -> None:
    applied: list[int] = []
    previous = signal.getsignal(signal.SIGTERM)
    try:
        code = guard.main([*ARGS, sys.executable, "-c", "print('ok')"], limits=applied.append)
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert code == 0
    assert applied == [5]
    assert capfd.readouterr().out == "ok\n"


def test_guard_process_terminates_its_child_on_sigterm(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    code = f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(60)"
    process = subprocess.Popen(
        [sys.executable, "-I", "-m", guard.__name__, *ARGS, sys.executable, "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 20
    while not pid_file.exists() or not pid_file.read_text(encoding="utf-8"):
        assert time.monotonic() < deadline, "the child did not start"
        time.sleep(0.05)
    child_pid = int(pid_file.read_text(encoding="utf-8"))
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=20) == guard.EXIT_SIGTERM
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_guard_process_enforces_the_line_limit() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            guard.__name__,
            *ARGS,
            sys.executable,
            "-c",
            "print('y' * 50)",
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == guard.EXIT_OUTPUT_LIMIT
    assert result.stdout == b""


def _running(pid: int) -> bool:
    """Alive and not a zombie (an orphaned zombie is not reaped on every CI host)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return True
    return stat_text.rsplit(")", 1)[1].split()[0] != "Z"


def _wait_for_pid(path: Path) -> int:
    deadline = time.monotonic() + 20
    while not path.exists() or not path.read_text(encoding="utf-8"):
        assert time.monotonic() < deadline, "the process did not start"
        time.sleep(0.05)
    return int(path.read_text(encoding="utf-8"))


def _gone(pid: int, wait_s: float = 5.0) -> bool:
    deadline = time.monotonic() + wait_s
    while _running(pid):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)
    return True


def _spawn_guard(code: str) -> "subprocess.Popen[bytes]":
    return subprocess.Popen(
        [sys.executable, "-I", "-m", guard.__name__, *ARGS, sys.executable, "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def test_guard_exits_on_sigterm_when_the_child_closed_stdout_but_keeps_running(
    tmp_path: Path,
) -> None:
    """The guard waits in ``child.wait()``; the handler must not deadlock on the same lock."""
    pid_file = tmp_path / "child.pid"
    code = (
        "import os, time\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "os.close(1)\n"
        "time.sleep(60)\n"
    )
    process = _spawn_guard(code)
    child_pid = 0
    try:
        child_pid = _wait_for_pid(pid_file)
        time.sleep(0.5)  # let the guard reach EOF and block in wait()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=8) == guard.EXIT_SIGTERM
        assert _gone(child_pid)
    finally:
        process.kill()
        process.wait()
        if child_pid and _running(child_pid):
            os.kill(child_pid, signal.SIGKILL)


def _server_with_a_helper(helper_file: Path, ending: str) -> str:
    """A server that starts a long-lived background helper, then runs ``ending``."""
    helper = (
        f"import os, time; open({str(helper_file)!r}, 'w').write(str(os.getpid())); time.sleep(60)"
    )
    return (
        "import os, subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {helper!r}], stdout=subprocess.DEVNULL)\n"
        f"while not (os.path.exists({str(helper_file)!r}) and open({str(helper_file)!r}).read()):\n"
        "    time.sleep(0.02)\n"
        f"{ending}\n"
    )


@pytest.mark.parametrize(
    ("ending", "expected"),
    [
        (
            "sys.stdout.write('x' * 5000); sys.stdout.flush(); time.sleep(60)",
            guard.EXIT_OUTPUT_LIMIT,
        ),
        ("sys.exit(0)", 0),
    ],
    ids=["output-limit", "child-exit"],
)
def test_guard_kills_the_descendants_of_the_server(
    tmp_path: Path, ending: str, expected: int
) -> None:
    helper_file = tmp_path / "helper.pid"
    code = _server_with_a_helper(helper_file, ending)
    process = _spawn_guard(code)
    helper_pid = 0
    try:
        helper_pid = _wait_for_pid(helper_file)
        assert process.wait(timeout=20) == expected
        assert _gone(helper_pid), "a descendant of the server outlived the guard"
    finally:
        process.kill()
        process.wait()
        if helper_pid and _running(helper_pid):
            os.kill(helper_pid, signal.SIGKILL)
