#!/usr/bin/env python3
"""Serve the stub API over the demo fakes, for local use.

    python3 defender/api/serve.py --tenant <id> [--tenant <id> ...] [--host 127.0.0.1] [--port 8000]

There is no default tenant (#1078): name one or more. The first gets the full demo seed, the
others one alert each, so a second tenant shows the scoping. Each tenant's tokens are
`<id>-analyst` and `<id>-engineer`, e.g. `curl -H 'Authorization: Bearer <id>-analyst'
localhost:8000/alerts`. The OpenAPI document is at `/openapi.json` and the interactive docs at
`/docs`. Nothing persists across restarts.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if (_root := str(REPO_ROOT)) not in sys.path:
    sys.path.insert(0, _root)

from defender._venv import reexec_into_venv  # noqa: E402

if __name__ == "__main__":
    reexec_into_venv(__file__)

import uvicorn  # noqa: E402

from defender._log import configure_from_env  # noqa: E402
from defender.api.app import create_app  # noqa: E402
from defender.api.demo import demo_deps, demo_tokens  # noqa: E402

_logger = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1",
                        help="the demo tokens are public, so the default is loopback only")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--tenant", dest="tenants", action="append", required=True,
                        help="a tenant to seed; repeat for more. The first gets the full seed")
    args = parser.parse_args(argv)
    try:
        deps = demo_deps(args.tenants)
    except ValueError as e:
        parser.error(str(e))
    _logger.info("stub API on http://%s:%d; demo tokens: %s",
                 args.host, args.port, ", ".join(sorted(demo_tokens(args.tenants))))
    # `log_config=None` keeps uvicorn on the handlers `configure_from_env` installed.
    uvicorn.run(create_app(deps), host=args.host, port=args.port, log_config=None)
    return 0


if __name__ == "__main__":
    configure_from_env()
    sys.exit(main())
