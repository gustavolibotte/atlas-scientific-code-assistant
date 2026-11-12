"""Application-level errors raised by provenance repositories."""


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
