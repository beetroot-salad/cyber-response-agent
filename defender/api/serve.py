#!/usr/bin/env python3
"""Serve the stub API over the demo fakes, for local use.

    python3 defender/api/serve.py [--host 127.0.0.1] [--port 8000]

Then `curl -H 'Authorization: Bearer demo-analyst' localhost:8000/alerts`; the demo tokens are
in `demo.py`. The OpenAPI document is at `/openapi.json` and the interactive docs at `/docs`.
Nothing persists across restarts.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if (_root := str(REPO_ROOT)) not in sys.path:
    sys.path.insert(0, _root)

from defender.scripts._venv import reexec_into_venv  # noqa: E402

if __name__ == "__main__":
    reexec_into_venv(__file__)

import uvicorn  # noqa: E402

from defender._log import configure_from_env  # noqa: E402
from defender.api.app import create_app  # noqa: E402
from defender.api.demo import DEMO_TOKENS, demo_deps  # noqa: E402

_logger = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1",
                        help="the demo tokens are public, so the default is loopback only")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    _logger.info("stub API on http://%s:%d; demo tokens: %s",
                 args.host, args.port, ", ".join(sorted(DEMO_TOKENS)))
    # `log_config=None` keeps uvicorn on the handlers `configure_from_env` installed.
    uvicorn.run(create_app(demo_deps()), host=args.host, port=args.port, log_config=None)
    return 0


if __name__ == "__main__":
    configure_from_env()
    sys.exit(main())
