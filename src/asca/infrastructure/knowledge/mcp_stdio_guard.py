"""Resource guard between the MCP SDK and a configured stdio server (stdlib only).

Usage::

    python -I -m asca.infrastructure.knowledge.mcp_stdio_guard \\
        --max-line N --max-total N --cpu S -- COMMAND [ARGS...]

The guard sets resource limits on itself (the child inherits them), spawns the server
without a shell, and relays the child's stdout to its own stdout while counting bytes.
A line longer than ``--max-line`` bytes, or more than ``--max-total`` bytes in total,
kills the child and exits 70. The child's stdin is inherited and its stderr discarded.

This is resource protection, not a sandbox: there is no filesystem or network isolation.
The SDK buffers stdout lines without a bound; this relay is what bounds them.
"""

import contextlib
import os
import signal
import subprocess
import sys
from collections.abc import Callable, Sequence
from types import FrameType
from typing import Any, Final

EXIT_USAGE: Final = 64
EXIT_OUTPUT_LIMIT: Final = 70
EXIT_PLATFORM: Final = 78
EXIT_SIGTERM: Final = 143
EXIT_BROKEN_PIPE: Final = 141
READ_CHUNK: Final = 65536
NOFILE: Final = 256
FSIZE: Final = 64 * 1024 * 1024
ADDRESS_SPACE: Final = 2 * 1024 * 1024 * 1024


class _UsageError(Exception):
    """The command line is malformed."""


def parse_args(argv: Sequence[str]) -> tuple[int, int, int, list[str]]:
    """Return ``(max_line, max_total, cpu_s, command)``; raise ``_UsageError`` if malformed."""
    if "--" not in argv:
        raise _UsageError
    split = list(argv).index("--")
    options, command = list(argv[:split]), list(argv[split + 1 :])
    if not command or len(options) != 6:
        raise _UsageError
    values: dict[str, int] = {}
    for name, raw in zip(options[0::2], options[1::2], strict=True):
        if name not in ("--max-line", "--max-total", "--cpu") or name in values:
            raise _UsageError
        if not raw.isascii() or not raw.isdigit() or int(raw) < 1:
            raise _UsageError
        values[name] = int(raw)
    return values["--max-line"], values["--max-total"], values["--cpu"], command


def _limit(rlimits: Any, name: str, value: int) -> None:
    kind = getattr(rlimits, name)
    _soft, hard = rlimits.getrlimit(kind)
    target = value if hard == rlimits.RLIM_INFINITY or hard < 0 else min(value, hard)
    rlimits.setrlimit(kind, (target, target))


def apply_limits(cpu_s: int, rlimits: Any = None) -> None:
    """Core dumps off, CPU seconds, open files, file size, and address space on Linux.

    ``rlimits`` defaults to the POSIX ``resource`` module (a seam for tests).
    """
    if rlimits is None:  # pragma: no cover - the real module only runs in the guard process
        import resource as rlimits

    _limit(rlimits, "RLIMIT_CORE", 0)
    _limit(rlimits, "RLIMIT_CPU", cpu_s)
    _limit(rlimits, "RLIMIT_NOFILE", NOFILE)
    _limit(rlimits, "RLIMIT_FSIZE", FSIZE)
    if sys.platform.startswith("linux"):
        _limit(rlimits, "RLIMIT_AS", ADDRESS_SPACE)


def _stop(child: "subprocess.Popen[bytes]") -> None:
    with contextlib.suppress(OSError):
        child.kill()
    child.wait()


def _exit_code(returncode: int) -> int:
    if returncode < 0:
        return min(128 - returncode, 255)
    return min(returncode, 255)


class LineCounter:
    """Counts bytes since the last newline and in total."""

    def __init__(self, max_line: int, max_total: int) -> None:
        self.max_line = max_line
        self.max_total = max_total
        self.line = 0
        self.total = 0

    def accept(self, chunk: bytes) -> bool:
        """Account for ``chunk``; False when a limit is exceeded."""
        self.total += len(chunk)
        if self.total > self.max_total:
            return False
        parts = chunk.split(b"\n")
        longest = self.line + len(parts[0])
        if len(parts) > 1:
            longest = max(longest, *(len(part) for part in parts[1:-1]), 0)
            self.line = len(parts[-1])
        else:
            self.line = longest
        return longest <= self.max_line and self.line <= self.max_line


def _write_all(data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(1, view)
        view = view[written:]


def relay(child: "subprocess.Popen[bytes]", counter: LineCounter) -> int:
    """Relay the child's stdout to fd 1 until EOF or a limit; return the exit code."""
    stdout = child.stdout
    if stdout is None:  # pragma: no cover - always a pipe
        raise RuntimeError("the child has no stdout pipe")
    fd = stdout.fileno()
    while True:
        chunk = os.read(fd, READ_CHUNK)
        if not chunk:
            return _exit_code(child.wait())
        if not counter.accept(chunk):
            _stop(child)
            return EXIT_OUTPUT_LIMIT
        try:
            _write_all(chunk)
        except BrokenPipeError:
            _stop(child)
            return EXIT_BROKEN_PIPE


def main(
    argv: Sequence[str] | None = None,
    *,
    limits: Callable[[int], None] = apply_limits,
    platform: str = os.name,
) -> int:
    """Run the guard; ``limits`` and ``platform`` are seams for in-process tests."""
    if platform != "posix":
        return EXIT_PLATFORM
    try:
        max_line, max_total, cpu_s, command = parse_args(sys.argv[1:] if argv is None else argv)
    except _UsageError:
        return EXIT_USAGE
    limits(cpu_s)
    child = subprocess.Popen(  # argv list, no shell; the command is config-checked
        command,
        stdin=None,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )

    def on_sigterm(signum: int, frame: FrameType | None) -> None:  # pragma: no cover
        # Runs only in the guard process (tested through a subprocess).
        _stop(child)
        os._exit(EXIT_SIGTERM)

    signal.signal(signal.SIGTERM, on_sigterm)
    return relay(child, LineCounter(max_line, max_total))


if __name__ == "__main__":  # pragma: no cover - exercised through a subprocess
    sys.exit(main())
