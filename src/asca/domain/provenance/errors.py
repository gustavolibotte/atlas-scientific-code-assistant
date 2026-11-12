"""Errors raised by the provenance domain.

Messages may name fields, identifiers, enum values and limits, but never echo free
text such as quotes, titles, statements, rationales, source text or reviewer labels.
"""


class ProvenanceInvariantError(ValueError):
    """A record, graph state or transition violates a provenance rule.

    Rule codes: ``R.<record>.<rule>`` for single records, ``G.<rule>`` for graph state
    invariants and ``T.<rule>`` for transition rules checked only when appending.
    """

    rule: str
    detail: str

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(f"[{rule}] {detail}")
        self.rule = rule
        self.detail = detail


class RecordNotFoundError(LookupError):
    """A record identifier is unknown or names a record of another kind."""

    kind: str
    record_id: str

    def __init__(self, kind: str, record_id: str) -> None:
        super().__init__(f"unknown {kind} {record_id}")
        self.kind = kind
        self.record_id = record_id
