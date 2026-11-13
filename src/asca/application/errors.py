"""Application-level errors raised by provenance repositories and workspace indexing."""

from enum import StrEnum


class ProjectNotFoundError(LookupError):
    """The project does not exist."""


class DuplicateProjectError(ValueError):
    """A project with this identifier already exists."""


class ConcurrentModificationError(RuntimeError):
    """The project revision changed since the caller loaded it."""


class StoredGraphIntegrityError(RuntimeError):
    """Stored records failed domain validation on load.

    Always raised ``from`` the original cause, with a generic message.
    """

    def __init__(self) -> None:
        super().__init__("stored provenance failed integrity validation")


class IndexFailure(StrEnum):
    """Why a whole indexing run failed closed; nothing is written."""

    ROOT_UNAVAILABLE = "root_unavailable"
    PLATFORM_UNSUPPORTED = "platform_unsupported"
    DIRECTORY_UNREADABLE = "directory_unreadable"
    MAX_FILES = "max_files"
    MAX_TOTAL_BYTES = "max_total_bytes"
    MAX_DIRECTORY_DEPTH = "max_directory_depth"
    MAX_DIRECTORY_ENTRIES = "max_directory_entries"
    MAX_SYMBOLS = "max_symbols"
    NO_SOURCE_FILES = "no_source_files"


class WorkspaceIndexError(RuntimeError):
    """An indexing run failed closed. The message never contains a path."""

    failure: IndexFailure

    def __init__(self, failure: IndexFailure) -> None:
        self.failure = failure
        super().__init__(f"workspace indexing failed: {failure.value}")
