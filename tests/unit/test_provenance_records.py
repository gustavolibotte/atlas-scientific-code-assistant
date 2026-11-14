"""Single-record rules (``R.*``) of the provenance domain."""

import itertools
import subprocess
import sys
from dataclasses import FrozenInstanceError, fields, replace
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from provenance_builders import build_complete_real_project, make_service

from asca.application.demo import DEMO_TIME
from asca.domain.provenance import (
    FILE_ISSUES_MAX,
    RECORD_FIELDS,
    AccessClass,
    Alternative,
    Approval,
    ApprovalVerdict,
    Assumption,
    CheckMethod,
    ClaimCheck,
    ClaimCheckId,
    ClaimCheckOutcome,
    ClaimId,
    CodeSymbol,
    EnvironmentId,
    EnvironmentSnapshot,
    FileIssue,
    FileIssueKind,
    FingerprintAlgorithm,
    PackagePin,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    ScientificDecision,
    SourceAuthority,
    SourceSpan,
    SourceVersion,
    SupersessionDimension,
    SupersessionNotice,
    TestCase,
    TestCaseId,
    TestKind,
    TestOutcome,
    TestResult,
    ValidationRun,
    VerificationLink,
    WorkspaceRevision,
    environment_id_for,
)

pytestmark = pytest.mark.unit

PROJECT = ProjectId("prj_" + "1" * 32)
OTHER_PROJECT = ProjectId("prj_" + "2" * 32)
HASH = "ab" * 32


def _rule(call: object) -> str:
    assert callable(call)
    with pytest.raises(ProvenanceInvariantError) as error:
        call()
    return error.value.rule


@pytest.fixture(scope="module")
def graph() -> ProvenanceGraph:
    service = make_service()
    return service.load(build_complete_real_project(service).project)


def _version(graph: ProvenanceGraph, authority: SourceAuthority) -> SourceVersion:
    return next(item for item in graph.versions if item.authority is authority)


def test_source_version_rules(graph: ProvenanceGraph) -> None:
    published = _version(graph, SourceAuthority.PUBLISHED)
    internal = _version(graph, SourceAuthority.APPROVED_INTERNAL)
    implementation = _version(graph, SourceAuthority.VERIFIED_IMPLEMENTATION)
    cases = [
        (lambda: replace(internal, access_conditions=None), "R.version.access_conditions"),
        (lambda: replace(internal, authority_basis=None), "R.version.authority_basis"),
        (lambda: replace(published, retrieved_at=None), "R.version.retrieval_pair"),
        (lambda: replace(published, content_sha256=None), "R.version.retrieval_pair"),
        (
            lambda: replace(
                published, access_class=AccessClass.INTERNAL, access_conditions="Fixture."
            ),
            "R.version.published_requires_public",
        ),
        (lambda: replace(implementation, version_label="main"), "R.version.commit_label"),
        (
            lambda: replace(published, published_on=datetime(2024, 1, 1, tzinfo=DEMO_TIME.tzinfo)),
            "R.version.published_on",
        ),
        (lambda: replace(published, version_label="x" * 101), "R.text.length"),
        (lambda: replace(published, authority="published"), "R.enum.type"),
        (lambda: replace(published, content_sha256="XYZ"), "R.hash.format"),
    ]
    for call, rule in cases:
        assert _rule(call) == rule
    assert replace(published, published_on=date(2020, 2, 2)).published_on == date(2020, 2, 2)
    assert replace(implementation, version_label="a" * 64).version_label == "a" * 64


def test_supersession_cannot_point_to_itself(graph: ProvenanceGraph) -> None:
    notice = graph.supersessions[0]
    rule = _rule(lambda: replace(notice, superseding_version_id=notice.superseded_version_id))
    assert rule == "R.supersession.self"
    assert notice.dimension is SupersessionDimension.TECHNICAL


@pytest.mark.parametrize(
    ("outcome", "method", "has_hash", "has_detail"),
    list(itertools.product(ClaimCheckOutcome, CheckMethod, (False, True), (False, True))),
)
def test_claim_check_shape_matrix(
    outcome: ClaimCheckOutcome, method: CheckMethod, has_hash: bool, has_detail: bool
) -> None:
    legal = (
        outcome in (ClaimCheckOutcome.SOURCE_TEXT_CHECKED, ClaimCheckOutcome.MISMATCH)
        and method is CheckMethod.NORMALIZED_SUBSTRING
        and has_hash
    ) or (
        outcome is ClaimCheckOutcome.UNAVAILABLE
        and method is CheckMethod.NOT_PERFORMED
        and not has_hash
        and has_detail
    )

    def build() -> ClaimCheck:
        return ClaimCheck(
            ClaimCheckId("chk_" + "3" * 32),
            PROJECT,
            ClaimId("clm_" + "4" * 32),
            1,
            outcome,
            method,
            HASH if has_hash else None,
            "Fixture detail." if has_detail else None,
            DEMO_TIME,
        )

    if legal:
        assert build().state.value == outcome.value
    else:
        assert _rule(build) == "R.check.shape"


def test_verification_link_needs_exactly_one_target(graph: ProvenanceGraph) -> None:
    decision_link = next(link for link in graph.verification_links if link.decision_id)
    symbol = graph.symbols[0].id
    assert _rule(lambda: replace(decision_link, symbol_id=symbol)) == "R.verification.target"
    assert _rule(lambda: replace(decision_link, decision_id=None)) == "R.verification.target"
    assert replace(decision_link, decision_id=None, symbol_id=symbol).target == symbol


def _snapshot(
    packages: tuple[PackagePin, ...], project: ProjectId = PROJECT
) -> EnvironmentSnapshot:
    env_id = environment_id_for(project, "3.12.3", "CPython", "Linux", packages)
    return EnvironmentSnapshot(env_id, project, "3.12.3", "CPython", "Linux", packages)


def test_environment_snapshot_is_content_addressed() -> None:
    snapshot = _snapshot((PackagePin("numpy", "2.1.0"),))
    tampered = EnvironmentId("env_" + "0" * 32)
    assert _rule(lambda: replace(snapshot, id=tampered)) == "R.environment.content_address"
    assert _rule(lambda: replace(snapshot, platform="Other")) == "R.environment.content_address"
    assert _snapshot(snapshot.packages, OTHER_PROJECT).id != snapshot.id
    duplicate = (PackagePin("numpy", "1"), PackagePin("numpy", "2"))
    assert _rule(lambda: _snapshot(duplicate)) == "R.environment.packages"
    assert _rule(lambda: replace(snapshot, python_version="3.12")) == (
        "R.environment.python_version"
    )
    assert _rule(lambda: PackagePin("NumPy", "1")) == "R.package.name"
    assert _rule(lambda: PackagePin("numpy_", "1")) == "R.package.name"


@settings(max_examples=100)
@given(
    st.lists(
        st.tuples(st.from_regex(r"[a-z0-9]{1,8}", fullmatch=True), st.sampled_from(["1", "2.0"])),
        max_size=6,
        unique_by=lambda pair: pair[0],
    ),
    st.randoms(use_true_random=False),
)
def test_environment_id_is_independent_of_package_order(
    pairs: list[tuple[str, str]], rng: object
) -> None:
    packages = [PackagePin(name, version) for name, version in pairs]
    shuffled = list(packages)
    rng.shuffle(shuffled)  # type: ignore[attr-defined]
    first = _snapshot(tuple(packages))
    second = _snapshot(tuple(shuffled))
    assert first == second
    assert [pin.name for pin in first.packages] == sorted(pin.name for pin in packages)


def _result(test: str, outcome: TestOutcome = TestOutcome.PASSED) -> TestResult:
    return TestResult(TestCaseId(test), outcome, None, None)


def test_validation_run_rules(graph: ProvenanceGraph) -> None:
    run = graph.runs[0]
    assert (
        _rule(lambda: replace(run, finished_at=run.started_at - timedelta(seconds=1)))
        == "R.run.time_order"
    )
    duplicate = (run.results[0], run.results[0])
    assert _rule(lambda: replace(run, results=duplicate)) == "R.run.results"
    assert _rule(lambda: replace(run, results=())) == "R.run.results"
    a, b = "tst_" + "a" * 32, "tst_" + "b" * 32
    canonical = replace(run, results=(_result(b), _result(a, TestOutcome.FAILED)))
    assert [item.test_case_id for item in canonical.results] == [a, b]
    assert canonical.summary[TestOutcome.FAILED] == 1
    assert set(canonical.summary) == set(TestOutcome)
    assert canonical.result_for("tst_" + "c" * 32) is None


@pytest.mark.parametrize("duration", [-1.0, float("nan"), float("inf"), True, "1"])
def test_test_result_duration(duration: object) -> None:
    rule = _rule(
        lambda: TestResult(TestCaseId("tst_" + "a" * 32), TestOutcome.PASSED, duration, None)
    )  # type: ignore[arg-type]
    assert rule == "R.result.duration"


def test_test_result_duration_is_normalized_to_float() -> None:
    result = TestResult(TestCaseId("tst_" + "a" * 32), TestOutcome.PASSED, 2, None)
    assert isinstance(result.duration_seconds, float)


def test_rejected_approval_cannot_carry_a_resolution(graph: ProvenanceGraph) -> None:
    rejection = next(item for item in graph.approvals if item.verdict is ApprovalVerdict.REJECTED)
    assert _rule(lambda: replace(rejection, conflict_resolution="Fixture.")) == (
        "R.approval.resolution"
    )
    assert _rule(lambda: replace(rejection, sequence=0)) == "R.int.range"
    assert _rule(lambda: replace(rejection, support_fingerprint="x")) == "R.hash.format"


def test_decision_rules(graph: ProvenanceGraph) -> None:
    decision = graph.decisions[0]
    alternative = Alternative("Option", "Description.", "Reason.")
    assumption = Assumption("Assumed.", None)
    same_label = Alternative("OPTION", "Other.", "Other.")
    assert _rule(lambda: replace(decision, alternatives=(alternative, same_label))) == (
        "R.decision.alternatives"
    )
    assert _rule(lambda: replace(decision, alternatives=(alternative,) * 21)) == (
        "R.decision.alternatives"
    )
    assert _rule(lambda: replace(decision, assumptions=(assumption, assumption))) == (
        "R.decision.assumptions"
    )
    assert _rule(lambda: replace(decision, supersedes_id=decision.id)) == (
        "R.decision.supersedes_self"
    )
    assert _rule(lambda: replace(decision, title="a\nb")) == "R.text.newline"


def test_code_and_test_rules(graph: ProvenanceGraph) -> None:
    symbol = graph.symbols[0]
    assert _rule(lambda: SourceSpan(5, 4)) == "R.span.order"
    assert _rule(lambda: replace(symbol, qualified_name="a..b")) == "R.symbol.qualified_name"
    assert _rule(lambda: replace(symbol, qualified_name="1abc")) == "R.symbol.qualified_name"
    assert _rule(lambda: replace(symbol, file_path="/abs.py")) == "R.path.relative"
    assert _rule(lambda: replace(symbol, span=(1, 2))) == "R.symbol.span"
    revision = graph.revisions[0]
    assert _rule(lambda: replace(revision, symbols_indexed=1)) == "R.bool.type"
    test = graph.test_cases[0]
    for node_id in ("/abs.py::t", "tests/x.py::", "tests/x.py::a\nb", "../x.py"):
        assert _rule(lambda node_id=node_id: replace(test, node_id=node_id)) == "R.test.node_id"
    assert replace(test, node_id="tests/x.py").node_id == "tests/x.py"
    assert replace(test, node_id="tests/x.py::C::t[1]").node_id == "tests/x.py::C::t[1]"


def test_claim_rules(graph: ProvenanceGraph) -> None:
    claim = graph.claims[0]
    assert _rule(lambda: replace(claim, quote="­")) == "R.claim.quote"
    assert _rule(lambda: replace(claim, locator="page=1")) == "R.claim.locator"
    assert _rule(lambda: replace(claim, quote="x" * 5001)) == "R.text.length"


def _all_records(graph: ProvenanceGraph) -> list[object]:
    records: list[object] = [graph.project]
    records += [getattr(graph, name)[0] for name in RECORD_FIELDS.values()]
    decision = graph.get(ScientificDecision, graph.decisions[0].id)
    records += [
        Alternative("Option", "Description.", "Reason."),
        Assumption("Assumed.", None),
        graph.claims[0].locator,
        graph.claims[0].locator.parts[0],
        graph.sources[0].persistent_id,
        graph.environments[0].packages[0],
        graph.runs[0].results[0],
        next(s for s in graph.symbols if s.span is not None).span,
        decision,
    ]
    return records


def test_every_record_type_is_frozen(graph: ProvenanceGraph) -> None:
    records = _all_records(graph)
    assert {type(item) for item in records} >= set(RECORD_FIELDS) | {
        Approval,
        CodeSymbol,
        SupersessionNotice,
        VerificationLink,
        ValidationRun,
    }
    for record in records:
        name = fields(record)[0].name  # type: ignore[arg-type]
        with pytest.raises(FrozenInstanceError):
            setattr(record, name, getattr(record, name))
    with pytest.raises(FrozenInstanceError):
        graph.revision = 99  # type: ignore[misc]


def test_test_named_domain_classes_are_not_collected() -> None:
    for item in (TestCase, TestKind, TestOutcome, TestResult):
        assert item.__test__ is False  # type: ignore[attr-defined]
    assert TestKind.UNIT in TestKind
    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "-W",
            "error::pytest.PytestCollectionWarning",
            str(Path(__file__).resolve()),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_source_authority_letters_and_support(graph: ProvenanceGraph) -> None:
    assert [item.letter for item in SourceAuthority] == ["A", "B", "C", "D", "E"]
    assert [item.can_support for item in SourceAuthority] == [True, True, True, True, False]
    source = graph.sources[0]
    assert _rule(lambda: replace(source, persistent_id="10.5555/x")) == "R.source.persistent_id"
    assert _rule(lambda: replace(graph.test_cases[0], node_id=None)) == "R.test.node_id"


# ---------------------------------------------------------------------- M2 indexing fields


def _indexed_revision(graph: ProvenanceGraph) -> WorkspaceRevision:
    return next(item for item in graph.revisions if item.symbols_indexed)


def test_revision_file_issue_rules(graph: ProvenanceGraph) -> None:
    revision = _indexed_revision(graph)
    first = FileIssue("src/a.py", FileIssueKind.SYNTAX_ERROR)
    second = FileIssue("src/b.py", FileIssueKind.SYMLINK)
    assert revision.file_issues == ()
    assert revision.source_digest is None
    valid = replace(revision, file_issues=(first, second), source_digest=HASH)
    assert valid.issue_for("src/b.py") == second
    assert valid.issue_for("src/a.py") == first
    assert valid.issue_for("src/c.py") is None
    assert valid.issue_for("src/0.py") is None
    assert valid.issue_paths == frozenset({"src/a.py", "src/b.py"})
    cases = [
        ((second, first), "R.revision.file_issues"),
        ((first, first), "R.revision.file_issues"),
        ([first], "R.revision.file_issues"),
        (("src/a.py",), "R.revision.file_issues"),
        ((first, None), "R.revision.file_issues"),
    ]
    for issues, rule in cases:
        assert _rule(lambda issues=issues: replace(revision, file_issues=issues)) == rule
    too_many = tuple(
        FileIssue(f"src/f{index:05d}.py", FileIssueKind.BINARY)
        for index in range(FILE_ISSUES_MAX + 1)
    )
    assert _rule(lambda: replace(revision, file_issues=too_many)) == "R.revision.file_issues"
    assert len(replace(revision, file_issues=too_many[:-1]).file_issues) == FILE_ISSUES_MAX


def test_revision_source_digest_and_unindexed_rules(graph: ProvenanceGraph) -> None:
    revision = _indexed_revision(graph)
    issue = FileIssue("src/a.py", FileIssueKind.SYNTAX_ERROR)
    assert _rule(lambda: replace(revision, source_digest="ABC")) == "R.hash.format"
    assert _rule(lambda: replace(revision, source_digest="A" * 64)) == "R.hash.format"
    unindexed = replace(revision, symbols_indexed=False)
    assert _rule(lambda: replace(unindexed, file_issues=(issue,))) == "R.revision.unindexed"
    assert _rule(lambda: replace(unindexed, source_digest=HASH)) == "R.revision.unindexed"
    assert replace(revision, file_issues=(issue,)).source_digest is None


def test_file_issue_rules() -> None:
    issue = FileIssue("src/a.py", FileIssueKind.BINARY)
    assert issue.kind is FileIssueKind.BINARY
    assert _rule(lambda: FileIssue("/abs.py", FileIssueKind.BINARY)) == "R.path.relative"
    assert _rule(lambda: FileIssue("../a.py", FileIssueKind.BINARY)) == "R.path.relative"
    assert _rule(lambda: FileIssue("src/a.py", "binary")) == "R.enum.type"  # type: ignore[arg-type]
    with pytest.raises(FrozenInstanceError):
        issue.kind = FileIssueKind.TOO_LARGE  # type: ignore[misc]


def test_symbol_fingerprint_algorithm_rules(graph: ProvenanceGraph) -> None:
    symbol = next(item for item in graph.symbols if item.fingerprint is not None)
    assert symbol.fingerprint_algorithm is None
    assert symbol.fingerprint_key == (None, symbol.fingerprint)
    tagged = replace(symbol, fingerprint_algorithm=FingerprintAlgorithm.PYTHON_AST_1)
    assert tagged.fingerprint_key == (FingerprintAlgorithm.PYTHON_AST_1, symbol.fingerprint)
    assert tagged.fingerprint_key != symbol.fingerprint_key
    assert FingerprintAlgorithm.PYTHON_AST_1.language is symbol.language
    assert _rule(lambda: replace(tagged, fingerprint=None)) == "R.symbol.fingerprint_algorithm"
    assert _rule(lambda: replace(symbol, fingerprint_algorithm="python-ast/1")) == "R.enum.type"
    assert replace(symbol, fingerprint=None).fingerprint_key is None
