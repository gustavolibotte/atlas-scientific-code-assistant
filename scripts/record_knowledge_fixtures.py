#!/usr/bin/env python3
"""Record public knowledge-provider fixtures (INSPIRE, arXiv, HEPData); never in CI.

Without --live no request is made and the command exits 2; it also exits 2 whenever CI
is set. Scenarios come from a fixed table (no free-form URLs). Fixtures are sanitized
(no abstracts, at most three authors, no challenge bodies) and written under
tests/fixtures/knowledge only after every write check passes. Review the diff before
committing.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from asca.infrastructure.knowledge.recording import SCENARIO_NAMES, run

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "knowledge"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="send the recording requests")
    parser.add_argument(
        "--scenario",
        action="append",
        choices=SCENARIO_NAMES,
        help="record only this scenario (repeatable; default: all)",
    )
    parser.add_argument("--force", action="store_true", help="overwrite existing fixtures")
    args = parser.parse_args(argv)
    return run(
        live=args.live,
        scenarios=args.scenario or SCENARIO_NAMES,
        force=args.force,
        out_dir=FIXTURES,
        environ=os.environ,
    )


if __name__ == "__main__":
    raise SystemExit(main())
