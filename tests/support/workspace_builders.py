"""Builders for synthetic workspace trees used by the reader and preview CLI tests."""

from collections.abc import Mapping
from pathlib import Path, PurePosixPath


def write_tree(root: Path, files: Mapping[str, str | bytes]) -> None:
    """Write ``files`` (workspace-relative POSIX path -> content) below ``root``.

    ``str`` content is written as UTF-8 and ``bytes`` content verbatim. A key ending with
    ``/`` creates an empty directory. Absolute keys and ``..`` segments are rejected so a
    fixture can never write outside ``root``.
    """
    for relative, content in files.items():
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise ValueError("tree paths must be relative and stay below the root")
        path = root.joinpath(*pure.parts)
        if relative.endswith("/"):
            path.mkdir(parents=True, exist_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
