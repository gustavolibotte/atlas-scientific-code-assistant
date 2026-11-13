"""Process entry points for multi-process store tests.

They live in an importable support module so the ``spawn`` start method, the only
one that behaves the same on Linux and macOS, can pickle them by reference.
"""

from __future__ import annotations

from typing import Any

from asca.infrastructure.persistence import open_sqlite_store


def open_store_at_barrier(url: str, barrier: Any, results: Any) -> None:
    """Wait for every sibling, open (and migrate) the store, and report the outcome."""
    barrier.wait()
    try:
        store = open_sqlite_store(url)
    except Exception as error:
        results.put(f"{type(error).__name__}: {error}")
        return
    store.dispose()
    results.put("ok")
