"""Text hygiene for provider data: line and block cleaning, terminal escaping, query terms.

Provider text is data, never instructions. Cleaning removes control, bidi and invisible
characters so ANSI/OSC sequences and direction overrides become inert text.
"""

import re
import unicodedata
from typing import Final

BIDI_AND_INVISIBLE: Final = frozenset(
    {*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0xFEFF, 0x200E, 0x200F}
)
STOPWORDS: Final = frozenset(
    {
        "a",
        "an",
        "and",
        "andnot",
        "are",
        "as",
        "at",
        "be",
        "but",
        "by",
        "for",
        "if",
        "in",
        "into",
        "is",
        "it",
        "no",
        "not",
        "of",
        "on",
        "or",
        "such",
        "that",
        "the",
        "their",
        "then",
        "there",
        "these",
        "they",
        "this",
        "to",
        "was",
        "will",
        "with",
    }
)
ELLIPSIS: Final = "…"
_TERM_RE = re.compile(r"[a-z0-9][a-z0-9.+-]{0,63}")
_SPACES_RE = re.compile(r" {2,}")
_BLANK_LINES_RE = re.compile(r"\n{4,}")


def is_control(code: int) -> bool:
    """C0 (U+0000-U+001F) and C1 (U+007F-U+009F) control characters."""
    return code <= 0x1F or 0x7F <= code <= 0x9F


def is_forbidden(char: str) -> bool:
    """Characters never allowed in validated provider text (``\\n``/``\\t`` handled by callers)."""
    code = ord(char)
    return is_control(code) or code in BIDI_AND_INVISIBLE


def is_line(value: object) -> bool:
    """Non-blank single line with no control, bidi or invisible characters."""
    return (
        isinstance(value, str)
        and value.strip() != ""
        and not any(is_forbidden(char) for char in value)
    )


def is_block(value: object) -> bool:
    """Like :func:`is_line`, but ``\\n`` and ``\\t`` are allowed."""
    return (
        isinstance(value, str)
        and value.strip() != ""
        and not any(is_forbidden(char) and char not in "\n\t" for char in value)
    )


def _truncate(text: str, max_len: int) -> tuple[str, bool]:
    if len(text) <= max_len:
        return text, False
    return text[: max(max_len - 1, 0)].rstrip() + ELLIPSIS, True


def _clean_chars(raw: str, keep: str) -> str:
    out: list[str] = []
    for char in unicodedata.normalize("NFC", raw):
        if char in keep:
            out.append(char)
        elif char.isspace():
            out.append(" ")
        elif not is_forbidden(char):
            out.append(char)
    return "".join(out)


def clean_line(raw: str, max_len: int) -> tuple[str, bool] | None:
    """Return ``(text, truncated)`` or ``None`` when nothing printable remains."""
    text = " ".join(_clean_chars(raw, "").split())
    if not text:
        return None
    return _truncate(text, max_len)


def clean_block(raw: str, max_len: int) -> str | None:
    """Like :func:`clean_line`, keeping ``\\n`` and ``\\t`` and at most two blank lines."""
    unified = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = [
        _SPACES_RE.sub(" ", line).strip(" ") for line in _clean_chars(unified, "\n\t").split("\n")
    ]
    text = _BLANK_LINES_RE.sub("\n\n\n", "\n".join(lines)).strip(" \n\t")
    if not text:
        return None
    return _truncate(text, max_len)[0]


def terminal_safe(value: str) -> str:
    """Escape every control (except ``\\n``), bidi and invisible character as ``\\uXXXX``."""
    return "".join(
        f"\\u{ord(char):04x}" if char != "\n" and is_forbidden(char) else char for char in value
    )


def query_terms(text: str, max_terms: int = 12) -> tuple[str, ...]:
    """Lowercase search terms without stopwords, de-duplicated in order."""
    seen: dict[str, None] = {}
    for term in _TERM_RE.findall(text.casefold()):
        if len(term) >= 2 and term not in STOPWORDS:
            seen.setdefault(term, None)
    return tuple(seen)[:max_terms]
