"""Test cases, verification links, environment snapshots and validation runs."""

import hashlib
import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from asca.domain.provenance.errors import ProvenanceInvariantError
from asca.domain.provenance.ids import (
    DecisionId,
    EnvironmentId,
    IdKind,
    ProjectId,
    RevisionId,
    RunId,
    SymbolId,
    TestCaseId,
    VerificationLinkId,
    optional_id,
    require_id,
)
from asca.domain.provenance.values import (
    QUOTE_MAX,
    STATEMENT_MAX,
    is_relative_path,
    optional_text,
    require_enum,
    require_text,
    require_utc,
)

NODE_ID_MAX = 500
PACKAGES_MAX = 2000
RESULTS_MAX = 10000
_PACKAGE_NAME_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")
_PYTHON_VERSION_RE = re.compile(r"\d+\.\d+\.\d+([a-z0-9]+)?")


class TestKind(StrEnum):
    __test__ = False

    ANALYTIC = "analytic"
    NUMERICAL = "numerical"
    PROPERTY = "property"
    REGRESSION = "regression"
    UNIT = "unit"
    INTEGRATION = "integration"


def _node_id_is_valid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        require_text("test.node_id", value, max_len=NODE_ID_MAX)
    except ProvenanceInvariantError:
        return False
    path, separator, remainder = value.partition("::")
    return is_relative_path(path) and (not separator or remainder != "")


@dataclass(frozen=True, slots=True)
class TestCase:
    __test__: ClassVar[bool] = False

    id: TestCaseId
    project_id: ProjectId
    node_id: str
    kind: TestKind
    description: str
    created_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.TEST_CASE, self.id, "test.id")
        require_id(IdKind.PROJECT, self.project_id, "test.project_id")
        if not _node_id_is_valid(self.node_id):
            raise ProvenanceInvariantError(
                "R.test.node_id", "node_id must be <relative path>[::<name>] on one line"
            )
        require_enum(TestKind, "test.kind", self.kind)
        require_text("test.description", self.description, max_len=STATEMENT_MAX, multiline=True)
        require_utc("test.created_at", self.created_at)


@dataclass(frozen=True, slots=True)
class VerificationLink:
    id: VerificationLinkId
    project_id: ProjectId
    test_case_id: TestCaseId
    decision_id: DecisionId | None
    symbol_id: SymbolId | None
    created_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.VERIFICATION_LINK, self.id, "verification_link.id")
        require_id(IdKind.PROJECT, self.project_id, "verification_link.project_id")
        require_id(IdKind.TEST_CASE, self.test_case_id, "verification_link.test_case_id")
        optional_id(IdKind.DECISION, self.decision_id, "verification_link.decision_id")
        optional_id(IdKind.SYMBOL, self.symbol_id, "verification_link.symbol_id")
        if (self.decision_id is None) == (self.symbol_id is None):
            raise ProvenanceInvariantError(
                "R.verification.target", "exactly one of decision_id and symbol_id is set"
            )
        require_utc("verification_link.created_at", self.created_at)

    @property
    def target(self) -> str:
        return self.decision_id if self.decision_id is not None else str(self.symbol_id)


@dataclass(frozen=True, slots=True)
class PackagePin:
    name: str
    version: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _PACKAGE_NAME_RE.fullmatch(self.name) is None:
            raise ProvenanceInvariantError(
                "R.package.name", "package name must be PEP 503 normalized"
            )
        require_text("package.version", self.version, max_len=100)


def _canonical_packages(packages: Iterable[PackagePin]) -> tuple[PackagePin, ...]:
    return tuple(sorted(packages, key=lambda pin: pin.name))


def environment_id_for(
    project_id: ProjectId,
    python_version: str,
    implementation: str,
    platform: str,
    packages: Iterable[PackagePin],
) -> EnvironmentId:
    """Content address of an environment snapshot inside one project."""
    document = json.dumps(
        {
            "project_id": project_id,
            "python_version": python_version,
            "implementation": implementation,
            "platform": platform,
            "packages": [[pin.name, pin.version] for pin in _canonical_packages(packages)],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(document.encode("utf-8")).hexdigest()[:32]
    return EnvironmentId(f"{IdKind.ENVIRONMENT.value}_{digest}")


@dataclass(frozen=True, slots=True)
class EnvironmentSnapshot:
    id: EnvironmentId
    project_id: ProjectId
    python_version: str
    implementation: str
    platform: str
    packages: tuple[PackagePin, ...]

    def __post_init__(self) -> None:
        require_id(IdKind.ENVIRONMENT, self.id, "environment.id")
        require_id(IdKind.PROJECT, self.project_id, "environment.project_id")
        if (
            not isinstance(self.python_version, str)
            or _PYTHON_VERSION_RE.fullmatch(self.python_version) is None
        ):
            raise ProvenanceInvariantError(
                "R.environment.python_version", "python_version must look like 3.12.1"
            )
        require_text("environment.implementation", self.implementation, max_len=50)
        require_text("environment.platform", self.platform, max_len=200)
        if (
            not isinstance(self.packages, tuple | list)
            or not all(isinstance(pin, PackagePin) for pin in self.packages)
            or len(self.packages) > PACKAGES_MAX
            or len({pin.name for pin in self.packages}) != len(self.packages)
        ):
            raise ProvenanceInvariantError(
                "R.environment.packages",
                f"at most {PACKAGES_MAX} package pins with unique names",
            )
        object.__setattr__(self, "packages", _canonical_packages(self.packages))
        expected = environment_id_for(
            self.project_id, self.python_version, self.implementation, self.platform, self.packages
        )
        if self.id != expected:
            raise ProvenanceInvariantError(
                "R.environment.content_address", f"environment id must be {expected}"
            )


class TestOutcome(StrEnum):
    __test__ = False

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    XFAILED = "xfailed"
    XPASSED = "xpassed"


class RunOrigin(StrEnum):
    EXECUTED = "executed"
    IMPORTED = "imported"
    SYNTHETIC = "synthetic"


@dataclass(frozen=True, slots=True)
class TestResult:
    __test__: ClassVar[bool] = False

    test_case_id: TestCaseId
    outcome: TestOutcome
    duration_seconds: float | None
    message: str | None

    def __post_init__(self) -> None:
        require_id(IdKind.TEST_CASE, self.test_case_id, "result.test_case_id")
        require_enum(TestOutcome, "result.outcome", self.outcome)
        duration = self.duration_seconds
        if duration is not None:
            if (
                not isinstance(duration, int | float)
                or isinstance(duration, bool)
                or not math.isfinite(duration)
                or duration < 0
            ):
                raise ProvenanceInvariantError(
                    "R.result.duration", "duration_seconds must be finite and >= 0"
                )
            object.__setattr__(self, "duration_seconds", float(duration))
        optional_text("result.message", self.message, max_len=QUOTE_MAX, multiline=True)


@dataclass(frozen=True, slots=True)
class ValidationRun:
    id: RunId
    project_id: ProjectId
    revision_id: RevisionId
    environment_id: EnvironmentId
    origin: RunOrigin
    started_at: datetime
    finished_at: datetime
    results: tuple[TestResult, ...]

    def __post_init__(self) -> None:
        require_id(IdKind.RUN, self.id, "run.id")
        require_id(IdKind.PROJECT, self.project_id, "run.project_id")
        require_id(IdKind.WORKSPACE_REVISION, self.revision_id, "run.revision_id")
        require_id(IdKind.ENVIRONMENT, self.environment_id, "run.environment_id")
        require_enum(RunOrigin, "run.origin", self.origin)
        require_utc("run.started_at", self.started_at)
        require_utc("run.finished_at", self.finished_at)
        if self.finished_at < self.started_at:
            raise ProvenanceInvariantError("R.run.time_order", "finished_at precedes started_at")
        if (
            not isinstance(self.results, tuple | list)
            or not all(isinstance(result, TestResult) for result in self.results)
            or not 1 <= len(self.results) <= RESULTS_MAX
            or len({result.test_case_id for result in self.results}) != len(self.results)
        ):
            raise ProvenanceInvariantError(
                "R.run.results", f"1 to {RESULTS_MAX} results with unique test_case_id"
            )
        object.__setattr__(
            self, "results", tuple(sorted(self.results, key=lambda result: result.test_case_id))
        )

    @property
    def summary(self) -> dict[TestOutcome, int]:
        counts = dict.fromkeys(TestOutcome, 0)
        for result in self.results:
            counts[result.outcome] += 1
        return counts

    def result_for(self, test_case_id: str) -> TestResult | None:
        return next((item for item in self.results if item.test_case_id == test_case_id), None)
