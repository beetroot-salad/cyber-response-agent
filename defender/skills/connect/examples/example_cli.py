"""Reference adapter for a generic HTTP read source — the shape `/connect`
copies into `defender/scripts/adapters/{system}_cli.py`.

An adapter is NOT a CLI: there is no argparse, no `--help`, no `main()`, and
no `sys.exit`. It is a Python module that exposes a single module-level
`VERBS` mapping — ``{verb-name: function}`` — and nothing else the model can
reach. Each function is a plain annotated verb: it takes a ``VerbContext``
positionally (the run's tree + scrubbed env, handed in by the harness) and
declares every model-supplied param as a KEYWORD-ONLY argument. Those
keyword-only params ARE the param contract — the query tool validates a call
against them and rejects an unknown/missing/mistyped one with exit 64, so the
model never needs a `--help`. A verb RETURNS its JSON payload (a dict or
list); it never prints and never exits.

Failures are RAISED, not exited. Import the fault taxonomy from
``faults.py`` and raise the member that matches the condition — the query
tool turns the fault into the queries-table row and the exit code the circuit
breaker keys on:

    ConfigFault    (2) — config.env missing/incomplete: the system is down.
    TransportFault (2) — the transport failed (unreachable, timeout, 5xx).
    UpstreamFault  (1) — the system was reached and rejected the query (4xx),
                         carrying the vendor's own error body as ``detail``.

Pick the query shape before the verbs. Three tiers, best first:

  1. The source has a native query language that AGGREGATES server-side
     (ES|QL, SPL, KQL, SQL). Expose THAT and let the model write it as one
     ``native_query`` param: the aggregation runs in the source, exact, and
     the result is the answer — nothing to download and reduce. Always first
     choice — these languages are a family the gather model already knows, so
     the instruction surface stays near zero.
  2. The source only FILTERS and returns rows (what this example shows).
     Expose the native filter passthrough and return the rows; the model
     aggregates them downstream with ``defender-sql`` over the returned JSON.
     This downloads before it reduces, so it is the fallback, not the goal.
  3. The source has NO query language (pure REST / lookup). Key on an
     identifier and return the record — like ``get_record`` below.

Never hand-roll a filter DSL or a bespoke adapter-side reducer — that is the
pattern the gather redesign removed.

This example sits at tier 2, is deliberately environment-agnostic (it talks
to whatever ``URL_BASE`` config.env points at), and does its transport with
``urllib``. A ``docker exec``, SSH, or existing-CLI-wrapping adapter keeps the
same VERBS/VerbContext/faults contract and swaps only the ``_request`` body —
that is the only part that should differ per system.
"""

from __future__ import annotations

# Put the workspace root on sys.path so `defender.*` namespace imports resolve
# when the verb registry loads this module BY PATH, not as a package member.
import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[4])) not in _sys.path:
    _sys.path.insert(0, _root)

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from defender.runtime.verbs import VerbContext, verb
from defender.scripts.adapters import faults

SYSTEM = "example"


def _config(ctx: VerbContext) -> dict[str, str]:
    """Read non-secret config from
    ``{ctx.defender_dir}/knowledge/environment/systems/{SYSTEM}/config.env``.

    Resolved from the RUN's tree (``ctx.defender_dir``), never from an
    import-time module constant — a learning-drain worktree or an eval's tmp
    tree must read ITS OWN config.env, not the main checkout's. Shell-style
    ``KEY=value`` lines; secrets are NEVER here, only the names of the env
    vars that hold them."""
    path = ctx.defender_dir / "knowledge" / "environment" / "systems" / SYSTEM / "config.env"
    config: dict[str, str] = {}
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            config[key.strip()] = val.strip().strip('"').strip("'")
    return config


def _request(ctx: VerbContext, path: str, params: dict[str, str] | None = None) -> Any:
    """GET ``{URL_BASE}{path}?{params}`` and return parsed JSON, mapping every
    failure onto the fault taxonomy. This is the one method a non-HTTP adapter
    rewrites (``docker exec``, SSH, a wrapped vendor CLI) — the VERBS surface
    above it does not change with the transport."""
    config = _config(ctx)
    base = config.get("URL_BASE")
    if not base:
        raise faults.ConfigFault(f"{SYSTEM}: URL_BASE is not set in config.env.")
    timeout = float(config.get("TIMEOUT_SEC", "10"))
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        if exc.code in (401, 403):
            raise faults.TransportFault(
                f"{SYSTEM}: authentication failed (HTTP {exc.code}). Check "
                f"AUTH_TYPE and the secret env var it names."
            ) from exc
        # Reached the system and it rejected the call — the agent's own to fix.
        raise faults.UpstreamFault(body or f"{SYSTEM}: query rejected (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise faults.TransportFault(f"{SYSTEM}: cannot reach {base} ({exc}).") from exc


def health_check(ctx: VerbContext) -> dict:
    """Is the system reachable and authed? RETURNS a small status dict — it
    does not print and it does not exit. A failed reach raises a
    ``TransportFault``/``ConfigFault`` from ``_request`` instead."""
    _request(ctx, "/health")
    return {"system": SYSTEM, "status": "connected"}


@verb(engine="lucene", body_param="native_query")
def query(ctx: VerbContext, *, native_query: str, limit: int = 100) -> dict | list:
    """Run a native filter and return the matching rows unmodified. ``native_query``
    passes through untouched (no translation layer); ``limit`` is a real int, so a
    quoted ``"100"`` is rejected with exit 64 before it reaches the arithmetic.

    The ``@verb`` decoration declares this a NATIVE-QUERY verb: ``engine=`` names the
    source's own query language (``lucene`` here — change it to ``esql`` / ``spl`` /
    ``kql`` / ``sql`` to match yours) and ``body_param=`` names the single param the
    query body rides in. It only stamps two attributes and returns the function
    unchanged, so the validator still reads the signature — but it is what lets a
    template put in-body ``${…}`` substitutions into the query text; a param-only
    verb (``get_record`` below) carries no decoration and requires every ``${…}`` to
    be a declared param."""
    return _request(ctx, "/events", {"q": native_query, "limit": str(limit)})


def get_record(ctx: VerbContext, *, id: str) -> dict:
    """Tier-3 lookup: key on an identifier and return the one record."""
    return _request(ctx, f"/records/{id}")


# The whole model-facing surface: a mapping of verb name -> function. A required
# `health-check` plus the verbs this source answers. There is no CLI, no shim.
VERBS = {
    "health-check": health_check,
    "query": query,
    "get-record": get_record,
}
