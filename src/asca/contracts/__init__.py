"""Versioned, handwritten export contracts (standard library only).

The JSON Schemas under ``exports/v1`` are frozen by ``exports/released.json``. Any change
to the set of accepted instances needs a new ``v2`` directory and a new URN.
"""

import json
from importlib import resources
from importlib.resources.abc import Traversable

EXPORT_ARTIFACT_NAMES = ("evidence_manifest", "decision_records", "validation_report")
EXPORT_SCHEMA_VERSION = "1.0.0"
_SCHEMA_MAJOR = "v1"


def schema_id(name: str) -> str:
    """The URN that identifies the v1 schema of export artifact ``name``."""
    return f"urn:asca:schema:{name}:{_SCHEMA_MAJOR}"


def _exports_dir() -> Traversable:
    return resources.files(__name__) / "exports"


def export_schema_resource(name: str) -> Traversable:
    """The packaged schema file of export artifact ``name``."""
    if name not in EXPORT_ARTIFACT_NAMES:
        raise ValueError("unknown export artifact")
    return _exports_dir() / _SCHEMA_MAJOR / f"{name}.schema.json"


def load_export_schema(name: str) -> dict[str, object]:
    """Parse the packaged JSON Schema of export artifact ``name``."""
    document = json.loads(export_schema_resource(name).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("export schema is not a JSON object")
    return document


def released_schema_hashes() -> dict[str, str]:
    """The sha256 of every released schema file, keyed by ``<name>.<major>``."""
    document = json.loads((_exports_dir() / "released.json").read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in document.items()
    ):
        raise ValueError("released.json must map names to hashes")
    return dict(document)
