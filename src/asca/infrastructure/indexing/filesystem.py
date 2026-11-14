"""Read-only, fd-relative workspace reader for the symbol index (ADR 0039).

The reader walks one workspace root and returns the bytes of every candidate source file,
or the reason it did not read one. It never follows a symlink below the root, opens files
non-blocking, enforces every ``IndexLimits`` budget and fails closed: a subtree it cannot
list raises instead of looking deleted. It never returns absolute paths, never puts
exception text into its output and never imports or executes anything it reads.

Policies (M2): hard links are read; ``.gitignore`` is not honoured; POSIX only.
"""

import errno
import os
import stat
from dataclasses import dataclass, field
from typing import Final

from asca.application.errors import IndexFailure, WorkspaceIndexError
from asca.application.ports import IndexLimits, WorkspaceFile, WorkspaceSnapshot
from asca.domain.provenance import FileIssueKind, is_relative_path

DEFAULT_EXCLUDED_DIR_NAMES: Final = frozenset({"__pycache__", "node_modules", "site-packages"})
ROOT_ONLY_EXCLUDED_DIR_NAMES: Final = frozenset({"build", "dist", "venv"})
VENV_MARKERS: Final = frozenset({"pyvenv.cfg", "conda-meta"})

_READ_CHUNK: Final = 65_536
#: open() errors for a special file swapped in after listing: a socket gives ENXIO on
#: Linux and EOPNOTSUPP on macOS (XNU); a device without a driver gives ENXIO.
_NOT_REGULAR_OPEN_ERRORS: Final = frozenset({errno.ENXIO, errno.EOPNOTSUPP})
_EXCLUDED_NAME_ERROR: Final = "excluded directory names must be non-empty without '/' or NUL"
_SUFFIX_ERROR: Final = "suffixes must be non-empty strings without '/' or NUL"


def _platform_supported() -> bool:
    return (
        os.open in os.supports_dir_fd
        and os.scandir in os.supports_fd
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
    )


def _valid_name(value: object) -> bool:
    return isinstance(value, str) and bool(value) and "/" not in value and "\x00" not in value


def _accepted_path(prefix: str, name: str) -> str | None:
    """The workspace-relative path of ``name``, or None when the name is unrepresentable."""
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if not name.isprintable() or "\\" in name or ":" in name:
        return None
    path = prefix + name
    return path if is_relative_path(path) else None


@dataclass(slots=True)
class _Frame:
    fd: int
    prefix: str
    depth: int
    entries: list[os.DirEntry[str]] = field(default_factory=list)
    index: int = 0


@dataclass(slots=True)
class _Walk:
    suffixes: tuple[str, ...]
    limits: IndexLimits
    excluded: frozenset[str]
    one_file_system: bool
    root_dev: int = 0
    files: list[WorkspaceFile] = field(default_factory=list)
    skipped_entries: int = 0
    entries_seen: int = 0
    candidates: int = 0
    total_bytes: int = 0

    def listing(self, fd: int) -> list[os.DirEntry[str]]:
        """Sorted entries of an open directory; every listed entry counts toward the budget.

        Raise ``OSError`` when the directory cannot be listed.
        """
        entries: list[os.DirEntry[str]] = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                self.entries_seen += 1
                if self.entries_seen > self.limits.max_directory_entries:
                    raise WorkspaceIndexError(IndexFailure.MAX_DIRECTORY_ENTRIES)
                entries.append(entry)
        entries.sort(key=lambda entry: entry.name)
        return entries

    def visit(self, parent: _Frame, entry: os.DirEntry[str]) -> _Frame | None:
        """Handle one entry of ``parent``; return a frame for a directory to descend into."""
        name = entry.name
        path = _accepted_path(parent.prefix, name)
        if path is None:
            self.skipped_entries += 1
            return None
        if name.startswith("."):
            return None
        try:
            is_symlink = entry.is_symlink()
            is_dir = not is_symlink and entry.is_dir(follow_symlinks=False)
            is_regular = not is_symlink and entry.is_file(follow_symlinks=False)
        except OSError:
            raise WorkspaceIndexError(IndexFailure.DIRECTORY_UNREADABLE) from None
        indexed = name.endswith(self.suffixes)
        if is_symlink:
            if indexed:
                self.count_candidate()
                self.files.append(WorkspaceFile(path, None, FileIssueKind.SYMLINK))
            else:
                self.skipped_entries += 1
            return None
        if is_dir:
            return self.directory(parent, name, path)
        if not indexed:
            self.skipped_entries += 1
            return None
        self.count_candidate()
        result = self.read_file(parent.fd, name) if is_regular else FileIssueKind.NOT_REGULAR
        if isinstance(result, FileIssueKind):
            self.files.append(WorkspaceFile(path, None, result))
            return None
        self.total_bytes += len(result)
        if self.total_bytes > self.limits.max_total_bytes:
            raise WorkspaceIndexError(IndexFailure.MAX_TOTAL_BYTES)
        self.files.append(WorkspaceFile(path, result, None))
        return None

    def count_candidate(self) -> None:
        self.candidates += 1
        if self.candidates > self.limits.max_files:
            raise WorkspaceIndexError(IndexFailure.MAX_FILES)

    def excluded_directory(self, name: str, depth: int) -> bool:
        return (
            name in DEFAULT_EXCLUDED_DIR_NAMES
            or name.endswith(".egg-info")
            or (depth == 0 and name in ROOT_ONLY_EXCLUDED_DIR_NAMES)
            or name in self.excluded
        )

    def directory(self, parent: _Frame, name: str, path: str) -> _Frame | None:
        if self.excluded_directory(name, parent.depth):
            return None
        depth = parent.depth + 1
        if depth > self.limits.max_directory_depth:
            raise WorkspaceIndexError(IndexFailure.MAX_DIRECTORY_DEPTH)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(name, flags, dir_fd=parent.fd)
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                # Swapped for a symlink or a non-directory after listing: never followed.
                self.skipped_entries += 1
                return None
            raise WorkspaceIndexError(IndexFailure.DIRECTORY_UNREADABLE) from None
        keep = False
        try:
            try:
                if self.one_file_system and os.fstat(fd).st_dev != self.root_dev:
                    return None
                entries = self.listing(fd)
            except OSError:
                raise WorkspaceIndexError(IndexFailure.DIRECTORY_UNREADABLE) from None
            if any(entry.name in VENV_MARKERS for entry in entries):
                return None
            keep = True
            return _Frame(fd, path + "/", depth, entries)
        finally:
            if not keep:
                os.close(fd)

    def read_file(self, parent_fd: int, name: str) -> bytes | FileIssueKind:
        """The bytes of one regular file, or the reason it was not read."""
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as error:
            if error.errno == errno.ELOOP:
                return FileIssueKind.SYMLINK
            if error.errno in _NOT_REGULAR_OPEN_ERRORS:
                return FileIssueKind.NOT_REGULAR
            return FileIssueKind.UNREADABLE
        try:
            status = os.fstat(fd)
            if not stat.S_ISREG(status.st_mode):
                return FileIssueKind.NOT_REGULAR
            limit = self.limits.max_file_bytes
            if status.st_size > limit:
                return FileIssueKind.TOO_LARGE
            chunks: list[bytes] = []
            total = 0
            while total <= limit:
                chunk = os.read(fd, min(_READ_CHUNK, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > limit:
                return FileIssueKind.TOO_LARGE
            return b"".join(chunks)
        except OSError:
            return FileIssueKind.UNREADABLE
        finally:
            os.close(fd)


class FilesystemWorkspaceReader:
    """``WorkspaceReader`` over one local directory tree; POSIX only."""

    __slots__ = ("_excluded", "_one_file_system", "_root")

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        extra_excluded_dir_names: frozenset[str] = frozenset(),
        one_file_system: bool = True,
    ) -> None:
        if not _platform_supported():
            raise WorkspaceIndexError(IndexFailure.PLATFORM_UNSUPPORTED)
        if not all(_valid_name(name) for name in extra_excluded_dir_names):
            raise ValueError(_EXCLUDED_NAME_ERROR)
        self._root = os.fspath(root)
        self._excluded = frozenset(extra_excluded_dir_names)
        self._one_file_system = one_file_system

    def read(self, suffixes: frozenset[str], limits: IndexLimits) -> WorkspaceSnapshot:
        """Snapshot every candidate file; raise ``WorkspaceIndexError`` on any limit."""
        if not all(_valid_name(suffix) for suffix in suffixes):
            raise ValueError(_SUFFIX_ERROR)
        walk = _Walk(
            suffixes=tuple(sorted(suffixes)),
            limits=limits,
            excluded=self._excluded,
            one_file_system=self._one_file_system,
        )
        try:
            root_fd = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            raise WorkspaceIndexError(IndexFailure.ROOT_UNAVAILABLE) from None
        stack = [_Frame(root_fd, "", 0)]
        try:
            try:
                walk.root_dev = os.fstat(root_fd).st_dev
                stack[0].entries = walk.listing(root_fd)
            except OSError:
                raise WorkspaceIndexError(IndexFailure.ROOT_UNAVAILABLE) from None
            while stack:
                frame = stack[-1]
                if frame.index == len(frame.entries):
                    stack.pop()
                    os.close(frame.fd)
                    continue
                entry = frame.entries[frame.index]
                frame.index += 1
                child = walk.visit(frame, entry)
                if child is not None:
                    stack.append(child)
        finally:
            for frame in reversed(stack):
                os.close(frame.fd)
        files = tuple(sorted(walk.files, key=lambda item: item.path))
        return WorkspaceSnapshot(files, walk.skipped_entries)
