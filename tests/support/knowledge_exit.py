"""The M3 exit scenario: recorded fixtures, the synthetic local library, and the golden.

The exit run replays only *recorded* fixtures (``synthetic: false``); a synthetic fixture
is refused here. Regenerate the golden after a reviewed re-recording with
``uv run python tests/support/knowledge_exit.py --write-golden`` and review the diff.
"""

from __future__ import annotations

import io
import shutil
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

from http_replay import Fixture, ReplayTransport, load_fixture, replay_factory
from knowledge_adapters import CLOCK, EXIT_QUERY, FIXTURES

from asca.application.knowledge.federation import FederationService
from asca.application.knowledge.models import KnowledgeQuery
from asca.application.ports import Clock
from asca.infrastructure.knowledge import __main__ as cli
from asca.infrastructure.knowledge.factory import build_federation
from asca.infrastructure.knowledge.settings import KnowledgeSettings, LocalLibrarySettings

GOLDEN = Path(__file__).resolve().parents[1] / "contract" / "golden" / "knowledge_search_exit.json"
EXIT_FIXTURES = (
    "inspire/lar_nn_search.json",
    "arxiv/lar_nn_search.json",
    "hepdata/lar_nn_search_blocked.json",
)
EXIT_HOSTS = frozenset({"inspirehep.net", "export.arxiv.org", "www.hepdata.net"})
LOCAL_TITLE = "Synthetic local note on liquid argon energy reconstruction with neural networks"


def recorded(name: str) -> Fixture:
    """A recorded fixture; synthetic fixtures are refused for the exit run."""
    loaded = load_fixture(FIXTURES / name)
    if loaded.synthetic:
        raise AssertionError(f"the exit run uses recorded fixtures only: {name}")
    return loaded


def exit_transport(delays: Mapping[str, float] | None = None) -> ReplayTransport:
    return ReplayTransport([recorded(name) for name in EXIT_FIXTURES], delays=delays)


def exit_query() -> KnowledgeQuery:
    return KnowledgeQuery(EXIT_QUERY, limit=5)


def make_library(root: Path) -> Path:
    """Copy the synthetic local library (one internal note) under ``root``."""
    library = root / "library"
    shutil.copytree(FIXTURES / "local", library)
    return library


def exit_settings(library: Path) -> KnowledgeSettings:
    """The defaults plus the local library."""
    return KnowledgeSettings(local=LocalLibrarySettings(enabled=True, root=str(library)))


def write_config(root: Path, library: Path) -> Path:
    """A permission-checked configuration file equivalent to ``exit_settings``."""
    path = root / "knowledge.toml"
    path.write_text(
        f'format = "asca-knowledge/1"\n[providers.local]\nenabled = true\nroot = "{library}"\n',
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def replay_builder(transport: ReplayTransport) -> cli.FederationBuilder:
    """A CLI builder: the real factory over replay, with an empty environment."""

    def build(settings: KnowledgeSettings, *, live: bool, clock: Clock) -> FederationService:
        return build_federation(
            settings, live=live, clock=clock, client_factory=replay_factory(transport), environ={}
        )

    return build


def run_cli(root: Path, transport: ReplayTransport, *argv: str) -> tuple[int, str, str]:
    """Run the CLI with the exit configuration over ``transport``."""
    library = root / "library"
    if not library.exists():
        make_library(root)
    config = write_config(root, library)
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(
        ["--config", str(config), *argv],
        build=replay_builder(transport),
        environ={},
        clock=CLOCK,
        stdout=out,
        stderr=err,
    )
    return code, out.getvalue(), err.getvalue()


def exit_cli_json(root: Path, transport: ReplayTransport) -> str:
    code, out, err = run_cli(root, transport, "search", EXIT_QUERY, "--live", "--limit", "5")
    if (code, err) != (3, ""):
        raise AssertionError(f"unexpected exit run: code {code}")
    return out


if __name__ == "__main__":  # pragma: no cover - maintainer tool
    if sys.argv[1:] != ["--write-golden"]:
        raise SystemExit("usage: knowledge_exit.py --write-golden")
    with tempfile.TemporaryDirectory() as scratch:
        GOLDEN.write_text(exit_cli_json(Path(scratch), exit_transport()), encoding="utf-8")
