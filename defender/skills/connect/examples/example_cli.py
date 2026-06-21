#!/usr/bin/env python3
"""Reference adapter for a generic HTTP read source — the shape `/connect`
copies into `defender/scripts/adapters/{system}_cli.py`.

Pick the query shape before the verbs. Three tiers, best first:

  1. The source has a native query language that AGGREGATES server-side
     (ES|QL, SPL, KQL, SQL). Expose THAT and let the model write it: the
     aggregation runs in the source, exact, and the result is the answer —
     nothing to download and reduce. Always first choice. We prefer native
     aggregation for two compounding reasons: simplicity (the source
     computes it; there is no payload to reduce) and priors (these query
     languages are one family the gather model already knows from training,
     so the instruction surface stays near zero). For an Elasticsearch-class
     deployment — a rich query language — that means the `esql` verb
     (`POST /_query` -> {columns, row_count, values}; see `elastic_cli.py`),
     NOT a Lucene filter that returns raw documents.

  2. The source only FILTERS and returns rows (what this example shows).
     Expose the native filter passthrough and return the rows; the model
     aggregates them downstream with `defender-sql` over the `--raw`
     output — still SQL, a language it knows. This downloads before it
     reduces, so it is the fallback, not the goal. Document the concrete
     recipe for the source's row shape in that system's `execution.md`
     (see `cli-adapter.md` -> "Prefer native aggregation").

  3. The source has NO query language (pure REST / lookup). Key on an
     identifier and return the record.

Never hand-roll a filter DSL or a bespoke adapter-side reducer — that is
the pattern the gather redesign removed.

This example sits at tier 2 and is deliberately environment-agnostic: it
talks to whatever `{EXAMPLE_}URL_BASE` points at and authenticates with
whatever `AUTH_TYPE` config.env declares. Replace `example` with the real
system name, adjust the verbs and the response parsing to the real API,
and keep the contract below intact.

The contract every adapter implements (see `_adapter.py`):

    health-check                          — is the system reachable + authed?
    query '<native query>' [--limit N]    — run a query, return raw results
        [--start ISO] [--end ISO] [--raw]

Subcommands are argparse verbs; `--raw` emits the stable JSON envelope the
gather capture persists. Exit codes: 0 success (0 hits included), 1 query
rejected, 2 unreachable/unauthed/misconfigured, 64 bad invocation.

Transport here is HTTP via urllib. A `docker exec`, SSH, or
existing-CLI-wrapping adapter keeps the same contract but swaps this
`_request` body — that is the only part that should differ.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from _adapter import (
    EXIT_CONN_ERROR,
    EXIT_OK,
    EXIT_QUERY_ERROR,
    AdapterArgumentParser,
    die,
    load_config,
    print_raw,
    resolve_auth,
)

SYSTEM = "example"


def _request(config: dict[str, str], path: str, params: dict[str, str]) -> Any:
    """GET `{URL_BASE}{path}?{params}` with the resolved auth headers and
    the configured timeout. Returns parsed JSON. Maps failures onto the
    contract's exit codes. This is the one method a non-HTTP adapter
    rewrites."""
    base = config.get("URL_BASE")
    if not base:
        die(EXIT_CONN_ERROR,
            f"{SYSTEM}: URL_BASE is not set in config.env.")
    timeout = float(config.get("TIMEOUT_SEC", "10"))
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)

    request = urllib.request.Request(url, headers=resolve_auth(SYSTEM, config))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        # 401/403 are an auth/connectivity problem; other 4xx/5xx mean the
        # request reached the system but was rejected — a query error.
        if exc.code in (401, 403):
            die(EXIT_CONN_ERROR,
                f"{SYSTEM}: authentication failed (HTTP {exc.code}). Check "
                f"the AUTH_TYPE config and the secret env var it names.")
        die(EXIT_QUERY_ERROR, f"{SYSTEM}: query rejected (HTTP {exc.code}): {exc.reason}")
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        die(EXIT_CONN_ERROR,
            f"{SYSTEM}: cannot reach {base} ({exc}). This is a data-source "
            f"outage, not a query problem — do not retry-probe.")
    except json.JSONDecodeError as exc:
        die(EXIT_QUERY_ERROR, f"{SYSTEM}: response was not valid JSON ({exc}).")


def cmd_health_check(config: dict[str, str], _args: Any) -> int:
    _request(config, "/health", {})
    print("connected")
    return EXIT_OK


def cmd_query(config: dict[str, str], args: Any) -> int:
    params = {"q": args.query, "limit": str(args.limit)}
    if args.start:
        params["start"] = args.start
    if args.end:
        params["end"] = args.end
    result = _request(config, "/events", params)
    hits = result.get("hits", []) if isinstance(result, dict) else result

    if args.raw:
        print_raw(SYSTEM, "/events", params, result)
        return EXIT_OK

    # Default output: a short summary plus a few sample rows. The gather
    # subagent prefers --raw; humans read this.
    print(f"{len(hits)} hit(s) for {args.query!r}")
    for hit in hits[:5]:
        print(f"  {json.dumps(hit)}")
    return EXIT_OK


def build_parser() -> AdapterArgumentParser:
    parser = AdapterArgumentParser(
        prog=f"{SYSTEM}_cli.py",
        description=f"Adapter for the {SYSTEM} system of record.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="Check reachability + auth; exit 0/2.")

    # Verb and flag names mirror what a fresh-context Haiku reaches for
    # (positional query, --limit, --start/--end, --raw). The --help example
    # is load-bearing: gather pattern-matches against it, so use a real
    # query shape, not a placeholder.
    q = sub.add_parser(
        "query",
        help="Run a native query and return matching events.",
        epilog="example: query 'status:failed AND service:sshd' --limit 5 --raw",
    )
    q.add_argument("query", help="Native query string, passed through unmodified.")
    q.add_argument("--limit", type=int, default=100, help="Max results (default 100).")
    q.add_argument("--start", help="ISO-8601 UTC lower time bound.")
    q.add_argument("--end", help="ISO-8601 UTC upper time bound.")
    q.add_argument("--raw", action="store_true", help="Emit the JSON capture envelope.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = load_config(SYSTEM)
    handlers = {"health-check": cmd_health_check, "query": cmd_query}
    return handlers[args.subcommand](config, args)


if __name__ == "__main__":
    raise SystemExit(main())
