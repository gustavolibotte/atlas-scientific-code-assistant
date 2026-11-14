"""Production clock and identifier factory."""

import uuid
from datetime import UTC, datetime

from asca.domain.provenance import IdKind


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class Uuid4IdFactory:
    def new(self, kind: IdKind) -> str:
        return f"{kind.value}_{uuid.uuid4().hex}"
