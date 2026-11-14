"""Negative tests of the filesystem workspace reader boundary (ADR 0039).

The reader must never follow a symlink below the root, never block on or read a special
file, never read more than its budgets allow, fail closed on every limit and on every
subtree it cannot list, never echo a path or a name in an error, and never return an
absolute or unrepresentable path.
"""

import errno
import os
import socket
import stat
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from workspace_builders import write_tree

from asca.application.errors import IndexFailure, WorkspaceIndexError
from asca.application.ports import (
    DEFAULT_INDEX_LIMITS,
    IndexLimits,
    WorkspaceFile,
    WorkspaceReader,
    WorkspaceSnapshot,
)
from asca.domain.provenance import FileIssueKind, is_relative_path
from asca.infrastructure.indexing.filesystem import (
    DEFAULT_EXCLUDED_DIR_NAMES,
    ROOT_ONLY_EXCLUDED_DIR_NAMES,
    VENV_MARKERS,
    FilesystemWorkspaceReader,
)

pytestmark = pytest.mark.security

SUFFIXES = frozenset({".py"})
SECRET = b"OUTSIDE_SECRET_TOKEN_7f3a"
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX reader")
NEEDS_NON_ROOT = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores permission bits"
)
LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="needs Linux filename rules")


def _read(
    root: Path,
    limits: IndexLimits = DEFAULT_INDEX_LIMITS,
    **options: Any,
) -> WorkspaceSnapshot:
    return FilesystemWorkspaceReader(root, **options).read(SUFFIXES, limits)


def _files(snapshot: WorkspaceSnapshot) -> dict[str, WorkspaceFile]:
    return {item.path: item for item in snapshot.files}


def _issue(snapshot: WorkspaceSnapshot, path: str) -> FileIssueKind | None:
    return _files(snapshot)[path].issue


def _open_fds() -> set[str]:
    return set(os.listdir("/proc/self/fd")) if sys.platform == "linux" else set()


def _assert_failure(
    error: pytest.ExceptionInfo[WorkspaceIndexError], failure: IndexFailure, *echoes: str
) -> None:
    message = str(error.value)
    assert error.value.failure is failure
    assert message == f"workspace indexing failed: {failure.value}"
    for echo in echoes:
        assert echo not in message
    assert error.value.__cause__ is None


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    return root


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    folder = tmp_path / "outside"
    folder.mkdir()
    (folder / "secret.py").write_bytes(b"TOKEN = '" + SECRET + b"'\n")
    return folder


@pytest.fixture
def read_spy(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """Record every chunk returned by ``os.read`` while the reader runs."""
    chunks: list[bytes] = []
    real = os.read

    def spy(fd: int, size: int) -> bytes:
        chunk = real(fd, size)
        chunks.append(chunk)
        return chunk

    monkeypatch.setattr(os, "read", spy)
    return chunks


@pytest.fixture
def open_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the name of every ``os.open`` call while the reader runs."""
    names: list[str] = []
    real = os.open

    def spy(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        names.append(os.fsdecode(path))
        return real(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", spy)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {spy})
    return names


class _StaleListing:
    """A directory listing captured before the filesystem changed under it."""

    def __init__(self, entries: list[Any]) -> None:
        self._entries = entries

    def __enter__(self) -> Iterator[Any]:
        return iter(self._entries)

    def __exit__(self, *exc_info: object) -> None:
        return None


def _change_after_first_listing(
    monkeypatch: pytest.MonkeyPatch, change: Callable[[], None]
) -> None:
    """List the root for real, then apply ``change`` before the reader sees the entries."""
    real = os.scandir
    state = {"done": False}

    def fake(fd: int) -> Any:
        if state["done"]:
            return real(fd)
        state["done"] = True
        with real(fd) as iterator:
            entries = list(iterator)
        change()
        return _StaleListing(entries)

    monkeypatch.setattr(os, "scandir", fake)


def _finishes_within(seconds: float, action: Callable[[], WorkspaceSnapshot]) -> WorkspaceSnapshot:
    result: list[WorkspaceSnapshot] = []
    thread = threading.Thread(target=lambda: result.append(action()), daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "the reader blocked on a special file"
    assert len(result) == 1
    return result[0]


def _bind_socket(directory: Path, name: str, monkeypatch: pytest.MonkeyPatch) -> socket.socket:
    monkeypatch.chdir(directory)  # keep the socket path short
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(name)
    return server


def test_the_reader_satisfies_the_port(workspace: Path) -> None:
    reader: WorkspaceReader = FilesystemWorkspaceReader(workspace)
    assert reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS) == WorkspaceSnapshot((), 0)


# --- symlinks ------------------------------------------------------------------------


@POSIX_ONLY
def test_symlinked_file_to_an_outside_secret_is_reported_and_never_read(
    workspace: Path, outside: Path, read_spy: list[bytes], open_spy: list[str]
) -> None:
    write_tree(workspace, {"ok.py": "x = 1\n"})
    (workspace / "link.py").symlink_to(outside / "secret.py")
    (workspace / "link.txt").symlink_to(outside / "secret.py")

    snapshot = _read(workspace)

    assert _files(snapshot)["link.py"] == WorkspaceFile("link.py", None, FileIssueKind.SYMLINK)
    assert _files(snapshot)["ok.py"].data == b"x = 1\n"
    assert set(_files(snapshot)) == {"link.py", "ok.py"}
    assert snapshot.skipped_entries == 1  # link.txt: a symlink without an indexed suffix
    assert not any(SECRET in chunk for chunk in read_spy)
    assert "link.py" not in open_spy
    assert "secret.py" not in open_spy


@POSIX_ONLY
def test_symlinked_directory_is_never_followed(
    workspace: Path, outside: Path, open_spy: list[str], read_spy: list[bytes]
) -> None:
    write_tree(workspace, {"top.py": "y = 2\n"})
    (workspace / "pkg").symlink_to(outside, target_is_directory=True)

    snapshot = _read(workspace)

    assert [item.path for item in snapshot.files] == ["top.py"]
    assert snapshot.skipped_entries == 1
    assert "pkg" not in open_spy
    assert "secret.py" not in open_spy
    assert not any(SECRET in chunk for chunk in read_spy)


@POSIX_ONLY
def test_a_symlinked_root_is_allowed_because_the_caller_chose_it(
    tmp_path: Path, workspace: Path
) -> None:
    write_tree(workspace, {"m.py": "z = 3\n"})
    alias = tmp_path / "alias"
    alias.symlink_to(workspace, target_is_directory=True)
    assert _read(alias) == _read(workspace)


@POSIX_ONLY
def test_a_file_swapped_for_a_symlink_after_listing_is_reported_and_never_read(
    workspace: Path, outside: Path, monkeypatch: pytest.MonkeyPatch, read_spy: list[bytes]
) -> None:
    write_tree(workspace, {"a.py": "original = 1\n"})
    reader = FilesystemWorkspaceReader(workspace)

    def swap() -> None:
        (workspace / "a.py").unlink()
        (workspace / "a.py").symlink_to(outside / "secret.py")

    _change_after_first_listing(monkeypatch, swap)
    snapshot = reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS)

    assert _issue(snapshot, "a.py") is FileIssueKind.SYMLINK
    assert not any(SECRET in chunk for chunk in read_spy)


@POSIX_ONLY
def test_a_directory_swapped_for_a_symlink_after_listing_is_skipped(
    workspace: Path, outside: Path, monkeypatch: pytest.MonkeyPatch, read_spy: list[bytes]
) -> None:
    write_tree(workspace, {"pkg/inner.py": "inner = 1\n"})
    reader = FilesystemWorkspaceReader(workspace)

    def swap() -> None:
        (workspace / "pkg" / "inner.py").unlink()
        (workspace / "pkg").rmdir()
        (workspace / "pkg").symlink_to(outside, target_is_directory=True)

    _change_after_first_listing(monkeypatch, swap)
    snapshot = reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS)

    assert snapshot == WorkspaceSnapshot((), 1)
    assert not any(SECRET in chunk for chunk in read_spy)


# --- special files -------------------------------------------------------------------


@POSIX_ONLY
def test_fifo_and_unix_socket_named_py_are_not_regular_and_never_block(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.mkfifo(workspace / "pipe.py")
    os.mkfifo(workspace / "pipe.txt")
    server = _bind_socket(workspace, "sock.py", monkeypatch)
    try:
        snapshot = _finishes_within(5.0, lambda: _read(workspace))
    finally:
        server.close()

    assert _issue(snapshot, "pipe.py") is FileIssueKind.NOT_REGULAR
    assert _issue(snapshot, "sock.py") is FileIssueKind.NOT_REGULAR
    assert "pipe.txt" not in _files(snapshot)
    assert snapshot.skipped_entries == 1


@POSIX_ONLY
def test_a_fifo_swapped_in_after_listing_is_opened_non_blocking_and_not_read(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, read_spy: list[bytes]
) -> None:
    write_tree(workspace, {"pipe.py": "x = 1\n"})
    reader = FilesystemWorkspaceReader(workspace)

    def swap() -> None:
        (workspace / "pipe.py").unlink()
        os.mkfifo(workspace / "pipe.py")

    _change_after_first_listing(monkeypatch, swap)
    snapshot = _finishes_within(5.0, lambda: reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS))

    assert _issue(snapshot, "pipe.py") is FileIssueKind.NOT_REGULAR
    assert read_spy == []


@POSIX_ONLY
def test_a_socket_swapped_in_after_listing_is_not_regular(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(workspace, {"sock.py": "x = 1\n"})
    reader = FilesystemWorkspaceReader(workspace)
    servers: list[socket.socket] = []

    def swap() -> None:
        (workspace / "sock.py").unlink()
        servers.append(_bind_socket(workspace, "sock.py", monkeypatch))

    _change_after_first_listing(monkeypatch, swap)
    try:
        snapshot = _finishes_within(5.0, lambda: reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS))
    finally:
        for server in servers:
            server.close()

    assert _issue(snapshot, "sock.py") is FileIssueKind.NOT_REGULAR


# --- size budgets --------------------------------------------------------------------


def test_an_oversized_file_is_too_large_and_never_read(
    workspace: Path, read_spy: list[bytes]
) -> None:
    write_tree(workspace, {"big.py": b"#" * 17})

    snapshot = _read(workspace, IndexLimits(max_file_bytes=16))

    assert _issue(snapshot, "big.py") is FileIssueKind.TOO_LARGE
    assert read_spy == []


def test_a_file_at_the_byte_limit_is_read_whole(workspace: Path) -> None:
    write_tree(workspace, {"edge.py": b"#" * 16})
    snapshot = _read(workspace, IndexLimits(max_file_bytes=16))
    assert _files(snapshot)["edge.py"].data == b"#" * 16


def test_a_file_growing_during_the_read_is_too_large_and_reads_are_bounded(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, read_spy: list[bytes]
) -> None:
    write_tree(workspace, {"grows.py": b"g" * 100_000})
    real = os.fstat

    def stale_size(fd: int) -> os.stat_result:
        status = real(fd)
        if stat.S_ISREG(status.st_mode):
            values = list(status)
            values[stat.ST_SIZE] = 10  # the size seen before the file grew
            return os.stat_result(values)
        return status

    monkeypatch.setattr(os, "fstat", stale_size)
    limits = IndexLimits(max_file_bytes=100)

    snapshot = _read(workspace, limits)

    assert _issue(snapshot, "grows.py") is FileIssueKind.TOO_LARGE
    assert sum(len(chunk) for chunk in read_spy) <= limits.max_file_bytes + 1


def _limit_tree(workspace: Path, failure: IndexFailure) -> IndexLimits:
    if failure is IndexFailure.MAX_FILES:
        write_tree(workspace, {"a.py": "", "b.py": "", "c.py": ""})
        return IndexLimits(max_files=2)
    if failure is IndexFailure.MAX_TOTAL_BYTES:
        write_tree(workspace, {"a.py": "#" * 10, "b.py": "#" * 10})
        return IndexLimits(max_total_bytes=15)
    if failure is IndexFailure.MAX_DIRECTORY_DEPTH:
        write_tree(workspace, {"secret_dir/deeper/deepest/x.py": ""})
        return IndexLimits(max_directory_depth=2)
    write_tree(workspace, {f"secret_{index}.txt": "" for index in range(5)})
    return IndexLimits(max_directory_entries=4)


@pytest.mark.parametrize(
    "failure",
    [
        IndexFailure.MAX_FILES,
        IndexFailure.MAX_TOTAL_BYTES,
        IndexFailure.MAX_DIRECTORY_DEPTH,
        IndexFailure.MAX_DIRECTORY_ENTRIES,
    ],
)
def test_every_limit_fails_closed_without_paths_or_leaked_descriptors(
    workspace: Path, failure: IndexFailure
) -> None:
    limits = _limit_tree(workspace, failure)
    before = _open_fds()

    with pytest.raises(WorkspaceIndexError) as error:
        _read(workspace, limits)

    _assert_failure(error, failure, str(workspace), "secret", ".py")
    assert _open_fds() == before


def test_limits_are_inclusive(workspace: Path) -> None:
    write_tree(
        workspace,
        {"a.py": "#" * 10, "b.py": "#" * 5, "d1/d2/x.py": "", "notes.txt": ""},
    )
    # Entries: a.py, b.py, d1, notes.txt, d2, x.py.
    limits = IndexLimits(
        max_files=3, max_total_bytes=15, max_directory_depth=2, max_directory_entries=6
    )
    snapshot = _read(workspace, limits)
    assert [item.path for item in snapshot.files] == ["a.py", "b.py", "d1/d2/x.py"]


def test_a_symlink_candidate_counts_toward_max_files(workspace: Path, outside: Path) -> None:
    write_tree(workspace, {"a.py": ""})
    (workspace / "b.py").symlink_to(outside / "secret.py")
    with pytest.raises(WorkspaceIndexError) as error:
        _read(workspace, IndexLimits(max_files=1))
    _assert_failure(error, IndexFailure.MAX_FILES)


# --- unreadable directories and files ------------------------------------------------


@NEEDS_NON_ROOT
def test_an_unreadable_directory_fails_closed(workspace: Path) -> None:
    write_tree(workspace, {"locked/hidden.py": "", "ok.py": ""})
    locked = workspace / "locked"
    locked.chmod(0)
    try:
        with pytest.raises(WorkspaceIndexError) as error:
            _read(workspace)
    finally:
        locked.chmod(0o755)
    _assert_failure(error, IndexFailure.DIRECTORY_UNREADABLE, "locked", str(workspace))


@NEEDS_NON_ROOT
def test_an_unreadable_file_is_unreadable(workspace: Path) -> None:
    write_tree(workspace, {"locked.py": "x = 1\n"})
    (workspace / "locked.py").chmod(0)
    assert _issue(_read(workspace), "locked.py") is FileIssueKind.UNREADABLE


def _failing_open(monkeypatch: pytest.MonkeyPatch, name: str, code: int) -> None:
    real = os.open

    def fake(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if path == name and dir_fd is not None:
            raise OSError(code, os.strerror(code))
        return real(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fake)


def test_a_directory_that_cannot_be_opened_fails_closed(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(workspace, {"locked/hidden.py": "", "ok.py": ""})
    reader = FilesystemWorkspaceReader(workspace)
    _failing_open(monkeypatch, "locked", errno.EACCES)
    before = _open_fds()

    with pytest.raises(WorkspaceIndexError) as error:
        reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS)

    _assert_failure(error, IndexFailure.DIRECTORY_UNREADABLE, "locked", str(workspace))
    assert _open_fds() == before


def test_a_directory_that_cannot_be_listed_fails_closed(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(workspace, {"locked/hidden.py": "", "ok.py": ""})
    reader = FilesystemWorkspaceReader(workspace)
    real = os.scandir
    calls = {"count": 0}

    def fake(fd: int) -> Any:
        calls["count"] += 1
        if calls["count"] > 1:
            raise PermissionError(errno.EACCES, "denied")
        return real(fd)

    monkeypatch.setattr(os, "scandir", fake)
    before = _open_fds()

    with pytest.raises(WorkspaceIndexError) as error:
        reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS)

    _assert_failure(error, IndexFailure.DIRECTORY_UNREADABLE, "locked")
    assert _open_fds() == before


def test_a_root_that_cannot_be_listed_is_unavailable(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reader = FilesystemWorkspaceReader(workspace)

    def fake(fd: int) -> Any:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(os, "scandir", fake)
    before = _open_fds()
    with pytest.raises(WorkspaceIndexError) as error:
        reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS)
    _assert_failure(error, IndexFailure.ROOT_UNAVAILABLE, str(workspace))
    assert _open_fds() == before


class _BrokenEntry:
    """A directory entry whose type cannot be determined."""

    name = "broken.py"

    def is_symlink(self) -> bool:
        raise OSError(errno.EIO, "I/O error")


def test_an_entry_whose_type_cannot_be_read_fails_closed(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reader = FilesystemWorkspaceReader(workspace)
    monkeypatch.setattr(os, "scandir", lambda fd: _StaleListing([_BrokenEntry()]))
    with pytest.raises(WorkspaceIndexError) as error:
        reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS)
    _assert_failure(error, IndexFailure.DIRECTORY_UNREADABLE, "broken")


def test_a_file_that_cannot_be_opened_is_unreadable(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(workspace, {"locked.py": "x = 1\n", "ok.py": "y = 2\n"})
    reader = FilesystemWorkspaceReader(workspace)
    _failing_open(monkeypatch, "locked.py", errno.EACCES)

    snapshot = reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS)

    assert _issue(snapshot, "locked.py") is FileIssueKind.UNREADABLE
    assert _files(snapshot)["ok.py"].data == b"y = 2\n"


@pytest.mark.parametrize(
    "code", [errno.ENXIO, errno.EOPNOTSUPP], ids=["linux-socket", "macos-socket"]
)
def test_open_errors_that_mean_a_socket_are_not_regular(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    # Opening a socket fails with ENXIO on Linux and with EOPNOTSUPP on macOS (XNU).
    write_tree(workspace, {"sock.py": "x = 1\n", "ok.py": "y = 2\n"})
    reader = FilesystemWorkspaceReader(workspace)
    _failing_open(monkeypatch, "sock.py", code)

    snapshot = reader.read(SUFFIXES, DEFAULT_INDEX_LIMITS)

    assert _files(snapshot)["sock.py"] == WorkspaceFile("sock.py", None, FileIssueKind.NOT_REGULAR)
    assert _files(snapshot)["ok.py"].data == b"y = 2\n"


def test_a_read_error_makes_the_file_unreadable_and_closes_it(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(workspace, {"bad.py": "x = 1\n"})

    def failing(fd: int, size: int) -> bytes:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, "read", failing)
    before = _open_fds()
    assert _issue(_read(workspace), "bad.py") is FileIssueKind.UNREADABLE
    assert _open_fds() == before


# --- exclusions ----------------------------------------------------------------------


def test_hidden_tool_and_virtual_environment_directories_are_skipped(workspace: Path) -> None:
    excluded = {
        ".git/hooks.py": "",
        ".venv/lib.py": "",
        ".hidden.py": "",
        "__pycache__/c.py": "",
        "node_modules/n.py": "",
        "lib/site-packages/s.py": "",
        "pkg.egg-info/e.py": "",
        "env/pyvenv.cfg": "",
        "env/lib/v.py": "",
        "conda/conda-meta/": "",
        "conda/c.py": "",
        "build/b.py": "",
        "dist/d.py": "",
        "venv/v.py": "",
    }
    kept = {"main.py": "", "src/build/kept.py": "", "src/dist/kept.py": "", "src/venv/kept.py": ""}
    write_tree(workspace, excluded | kept)

    snapshot = _read(workspace)

    assert [item.path for item in snapshot.files] == sorted(kept)
    assert snapshot.skipped_entries == 0
    assert {"__pycache__", "node_modules", "site-packages"} == DEFAULT_EXCLUDED_DIR_NAMES
    assert {"build", "dist", "venv"} == ROOT_ONLY_EXCLUDED_DIR_NAMES
    assert {"pyvenv.cfg", "conda-meta"} == VENV_MARKERS


def test_extra_excluded_directory_names_are_skipped_at_any_depth(workspace: Path) -> None:
    write_tree(workspace, {"vendor/a.py": "", "src/vendor/b.py": "", "src/c.py": ""})
    snapshot = _read(workspace, extra_excluded_dir_names=frozenset({"vendor"}))
    assert [item.path for item in snapshot.files] == ["src/c.py"]


@pytest.mark.parametrize("name", ["", "a/b", "nul\x00"])
def test_invalid_extra_excluded_names_are_rejected_without_echo(workspace: Path, name: str) -> None:
    with pytest.raises(ValueError) as error:
        FilesystemWorkspaceReader(workspace, extra_excluded_dir_names=frozenset({name}))
    assert str(error.value) == "excluded directory names must be non-empty without '/' or NUL"


@pytest.mark.parametrize("suffix", ["", "a/.py", ".p\x00y"])
def test_invalid_suffixes_are_rejected(workspace: Path, suffix: str) -> None:
    reader = FilesystemWorkspaceReader(workspace)
    with pytest.raises(ValueError, match="suffixes must be non-empty strings"):
        reader.read(frozenset({suffix}), DEFAULT_INDEX_LIMITS)


def test_suffix_matching_is_case_sensitive_and_other_files_are_counted(workspace: Path) -> None:
    write_tree(workspace, {"a.py": "", "B.PY": "", "c.pyi": "", "README.md": ""})
    snapshot = _read(workspace)
    assert [item.path for item in snapshot.files] == ["a.py"]
    assert snapshot.skipped_entries == 3


# --- unrepresentable names -----------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "back\\slash.py",
        "new\nline.py",
        "tab\there.py",
        "\u202egnp.py",
        "zero\u200bwidth.py",
        "drive:colon.py",
    ],
    ids=["backslash", "newline", "tab", "rlo", "zero-width", "colon"],
)
@pytest.mark.parametrize("parent", ["", "sub/"], ids=["root", "nested"])
def test_unrepresentable_file_names_are_counted_and_never_echoed(
    workspace: Path, name: str, parent: str, open_spy: list[str]
) -> None:
    # Nested names matter: the domain path check alone only rejects ':' in the first segment.
    write_tree(workspace, {"ok.py": "", f"{parent}keep.txt": ""})
    (workspace / parent / name).write_text("x = 1\n", encoding="utf-8")

    snapshot = _read(workspace)

    assert [item.path for item in snapshot.files] == ["ok.py"]
    assert snapshot.skipped_entries == 2
    assert name not in open_spy


@pytest.mark.parametrize(
    "name", ["bad\ndir", "drive:dir", "back\\slash"], ids=["newline", "colon", "backslash"]
)
@pytest.mark.parametrize("parent", ["", "sub/"], ids=["root", "nested"])
def test_unrepresentable_directory_names_are_never_entered(
    workspace: Path, name: str, parent: str, open_spy: list[str]
) -> None:
    write_tree(workspace, {"ok.py": "", f"{parent}keep.txt": "", f"{parent}{name}/inner.py": ""})
    snapshot = _read(workspace)
    assert [item.path for item in snapshot.files] == ["ok.py"]
    assert snapshot.skipped_entries == 2
    assert name not in open_spy


@LINUX_ONLY
def test_non_utf8_file_names_are_counted_and_never_echoed(workspace: Path) -> None:
    raw = os.path.join(os.fsencode(workspace), b"\xff\xfe.py")
    descriptor = os.open(raw, os.O_WRONLY | os.O_CREAT, 0o644)
    os.close(descriptor)
    write_tree(workspace, {"ok.py": ""})

    snapshot = _read(workspace)

    assert [item.path for item in snapshot.files] == ["ok.py"]
    assert snapshot.skipped_entries == 1


def test_paths_over_500_characters_are_counted_and_never_echoed(workspace: Path) -> None:
    long_path = "d" * 200 + "/" + "e" * 200 + "/" + "f" * 100 + ".py"
    assert len(long_path) > 500
    write_tree(workspace, {long_path: "", "ok.py": ""})

    snapshot = _read(workspace)

    assert [item.path for item in snapshot.files] == ["ok.py"]
    assert snapshot.skipped_entries == 1


# --- root ----------------------------------------------------------------------------


def test_a_missing_root_is_unavailable_without_echoing_the_path(tmp_path: Path) -> None:
    missing = tmp_path / "missing_secret_root"
    with pytest.raises(WorkspaceIndexError) as error:
        _read(missing)
    _assert_failure(error, IndexFailure.ROOT_UNAVAILABLE, "missing_secret_root", str(tmp_path))


def test_a_non_directory_root_is_unavailable_without_echoing_the_path(tmp_path: Path) -> None:
    file_root = tmp_path / "plain_secret.py"
    file_root.write_text("x = 1\n", encoding="utf-8")
    before = _open_fds()
    with pytest.raises(WorkspaceIndexError) as error:
        _read(file_root)
    _assert_failure(error, IndexFailure.ROOT_UNAVAILABLE, "plain_secret", str(tmp_path))
    assert _open_fds() == before


def test_the_constructor_never_touches_the_filesystem(tmp_path: Path) -> None:
    FilesystemWorkspaceReader(tmp_path / "does-not-exist-yet")


@pytest.mark.parametrize(
    "disable",
    ["supports_dir_fd", "supports_fd", "O_NOFOLLOW", "O_DIRECTORY"],
)
def test_platforms_without_fd_relative_no_follow_primitives_are_refused(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, disable: str
) -> None:
    if disable.startswith("supports"):
        monkeypatch.setattr(os, disable, set())
    else:
        monkeypatch.delattr(os, disable)
    with pytest.raises(WorkspaceIndexError) as error:
        FilesystemWorkspaceReader(workspace)
    _assert_failure(error, IndexFailure.PLATFORM_UNSUPPORTED, str(workspace))


# --- device boundary -----------------------------------------------------------------


def _foreign_subdirectories(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every directory except the first one ``fstat`` sees report another device."""
    real = os.fstat
    seen = {"root": False}

    def fake(fd: int) -> os.stat_result:
        status = real(fd)
        if not stat.S_ISDIR(status.st_mode):
            return status
        if not seen["root"]:
            seen["root"] = True
            return status
        values = list(status)
        values[stat.ST_DEV] = status.st_dev + 1
        return os.stat_result(values)

    monkeypatch.setattr(os, "fstat", fake)


def test_one_file_system_skips_directories_on_another_device(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(workspace, {"top.py": "", "mounted/inner.py": ""})
    _foreign_subdirectories(monkeypatch)
    before = _open_fds()

    snapshot = _read(workspace)

    assert [item.path for item in snapshot.files] == ["top.py"]
    assert snapshot.skipped_entries == 0
    assert _open_fds() == before


def test_crossing_devices_is_allowed_only_when_asked(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(workspace, {"top.py": "", "mounted/inner.py": ""})
    _foreign_subdirectories(monkeypatch)
    snapshot = _read(workspace, one_file_system=False)
    assert [item.path for item in snapshot.files] == ["mounted/inner.py", "top.py"]


# --- output shape --------------------------------------------------------------------


def test_output_order_is_deterministic_by_code_point(workspace: Path) -> None:
    write_tree(workspace, {"a.py": "1", "a/b.py": "2", "a-b.py": "3"})
    first = _read(workspace)
    assert [item.path for item in first.files] == ["a-b.py", "a.py", "a/b.py"]
    assert _read(workspace) == first


def test_no_output_path_is_absolute_or_escapes_the_root(tmp_path: Path, workspace: Path) -> None:
    write_tree(
        workspace,
        {"a.py": "", "pkg/__init__.py": "", "pkg/sub/mod.py": "", "pkg/sub/data.json": ""},
    )
    roundabout = tmp_path / "ws" / ".." / "ws"

    snapshot = _read(roundabout)

    paths = [item.path for item in snapshot.files]
    assert paths == ["a.py", "pkg/__init__.py", "pkg/sub/mod.py"]
    for path in paths:
        assert is_relative_path(path)
        assert not os.path.isabs(path)
        assert ".." not in path.split("/")
        assert str(tmp_path) not in path


def test_hard_links_are_read_as_documented(workspace: Path, tmp_path: Path) -> None:
    original = tmp_path / "original.py"
    original.write_text("shared = 1\n", encoding="utf-8")
    os.link(original, workspace / "linked.py")
    assert _files(_read(workspace))["linked.py"].data == b"shared = 1\n"


def test_reading_never_executes_the_workspace(workspace: Path, tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel"
    write_tree(
        workspace,
        {
            "__init__.py": f"open({str(sentinel)!r}, 'w').write('ran')\n",
            "setup.py": "raise SystemExit(7)\n",
        },
    )
    before = set(sys.modules)
    snapshot = _read(workspace)
    assert len(snapshot.files) == 2
    assert not sentinel.exists()
    assert set(sys.modules) == before


def test_successful_reads_leave_no_open_descriptors(workspace: Path) -> None:
    write_tree(workspace, {f"d{depth}/" * depth + "m.py": "" for depth in range(1, 6)})
    before = _open_fds()
    snapshot = _read(workspace)
    assert len(snapshot.files) == 5
    assert _open_fds() == before
