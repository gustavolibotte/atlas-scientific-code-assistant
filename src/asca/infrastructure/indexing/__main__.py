"""Read-only symbol index preview: ``python -m asca.infrastructure.indexing ROOT``.

It reads one workspace with ``FilesystemWorkspaceReader``, extracts Python symbols and
prints one JSON line with workspace-relative paths, names, spans and fingerprints. It
never touches a database or the network, never prints source text or absolute paths, and
never imports or executes the indexed code.
"""

import argparse
import json
import sys
from collections.abc import Sequence

from asca.application.errors import WorkspaceIndexError
from asca.application.indexing import BuiltIndex, build_index
from asca.application.ports import DEFAULT_INDEX_LIMITS, IndexLimits
from asca.infrastructure.indexing.filesystem import FilesystemWorkspaceReader
from asca.infrastructure.indexing.python_symbols import PythonAstExtractor

PROG = "asca-index"


def _positive_int(text: str) -> int:
    if not (text.isascii() and text.isdigit()) or int(text) < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return int(text)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Preview the Python symbol index of a workspace (read-only).",
    )
    parser.add_argument("root", metavar="ROOT", help="workspace root directory")
    parser.add_argument("--max-files", type=_positive_int, default=DEFAULT_INDEX_LIMITS.max_files)
    parser.add_argument(
        "--max-file-bytes", type=_positive_int, default=DEFAULT_INDEX_LIMITS.max_file_bytes
    )
    parser.add_argument(
        "--max-total-bytes", type=_positive_int, default=DEFAULT_INDEX_LIMITS.max_total_bytes
    )
    return parser


def _summary(built: BuiltIndex, extractor: PythonAstExtractor) -> dict[str, object]:
    return {
        "algorithms": [extractor.algorithm.value],
        "source_digest": built.source_digest,
        "files_seen": built.files_seen,
        "files_indexed": built.files_indexed,
        "skipped_entries": built.skipped_entries,
        "skipped_definitions": built.skipped_definitions,
        "issues": [
            {"file_path": issue.file_path, "kind": issue.kind.value} for issue in built.issues
        ],
        "symbols": [
            {
                "file_path": draft.file_path,
                "qualified_name": draft.qualified_name,
                "kind": draft.kind.value,
                "span": None
                if draft.span is None
                else [draft.span.start_line, draft.span.end_line],
                "fingerprint": draft.fingerprint,
            }
            for draft in built.drafts
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Print the preview as one JSON line; return 0, or 2 on a usage or indexing error."""
    try:
        args = _parser().parse_args(argv)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 2
    limits = IndexLimits(
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
    )
    extractor = PythonAstExtractor()
    try:
        reader = FilesystemWorkspaceReader(args.root)
        snapshot = reader.read(extractor.suffixes, limits)
        built = build_index(snapshot, (extractor,), limits, allow_empty=True)
    except WorkspaceIndexError as error:
        print(f"{PROG}: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            _summary(built, extractor), sort_keys=True, ensure_ascii=True, separators=(",", ":")
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
