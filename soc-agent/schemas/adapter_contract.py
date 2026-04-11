"""Adapter contract for security system CLIs.

This module defines the interfaces that `/connect` generates and that the
investigation loop depends on. Implementations are standalone CLI scripts
under `scripts/tools/{system}_cli.py` — not imported as modules. These
ABCs exist for documentation and contract-compliance testing, not runtime
dispatch.

Two contract shapes:

- `AdapterContract` — query-oriented systems. SIEMs, EDRs, log stores,
  anything that exposes "run a query in my native language, get matching
  events back". This is the common case.

- `LookupContract` — identifier-oriented systems. CMDBs, asset databases,
  identity/HR systems, threat intel enrichment endpoints. The client
  hands over a key (hostname, user ID, IOC hash) and gets a single record
  (or nothing). There's no query language — just a key field and a value.

Most connected systems implement `AdapterContract`. Implement `LookupContract`
when the upstream API is fundamentally lookup-shaped and forcing it into a
query DSL would be lossy (e.g., a CMDB where you call `GET /assets/{id}`
not `POST /query`).

CLI subcommand shapes:

    # AdapterContract
    python3 scripts/tools/{system}_cli.py health-check
    python3 scripts/tools/{system}_cli.py query <native_query> [--start ISO] [--end ISO] [--limit N] [--raw] [--run-dir DIR]

    # LookupContract
    python3 scripts/tools/{system}_cli.py health-check
    python3 scripts/tools/{system}_cli.py lookup <key_field> <key_value> [--raw] [--run-dir DIR]

See `docs/design-v3-init-and-connect.md` §3 for the query contract rationale
and §7 (open questions) for the lookup discussion.

The `lookup <key_field> <key_value>` shape is deliberately conventional
rather than mimicking any vendor's DSL — there is no de facto standard
query language for lookup-shaped systems. `/connect` is expected to
validate the shape via an Axis B Haiku probe when generating a lookup
adapter, because convention alone doesn't guarantee a fresh-context agent
will reach for the right call.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class HealthResult:
    """Binary health check result.

    connected: did we reach the system and authenticate?
    error:     optional; None when connected=True. When connected=False,
               a human-readable one-line description of what went wrong
               (connection refused, auth failed, timeout).
    detail:    optional structured extras for debugging (component
               statuses, version strings). Not required for pass/fail.
    """

    connected: bool
    error: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class QueryResult:
    """Result of a native query execution.

    raw:          the system's response, minimally processed. JSON-serializable.
                  No field renaming, no schema normalization. The agent and
                  post-processing Python handle interpretation.
    total_hits:   optional; how many results matched before any limit was
                  applied. None if the system doesn't report this.
    truncated:    True if results were cut off by a limit. The agent needs
                  to know when it's seeing a partial picture.
    query_echo:   the exact query that was executed (for audit and debugging).
    """

    raw: list[dict[str, Any]]
    total_hits: Optional[int] = None
    truncated: bool = False
    query_echo: str = ""


@dataclass
class LookupResult:
    """Result of a single-key lookup.

    found:        True if the upstream returned a record for the key.
    record:       optional; the record the system returned. None when
                  found=False. JSON-serializable, no schema normalization.
    key_field:    the field name that was looked up (e.g. "hostname").
    key_value:    the value that was looked up (echoed for audit).
    error:        optional; populated on upstream error (not "not found",
                  which is a valid result). Human-readable one-liner.
    """

    found: bool
    record: Optional[dict[str, Any]] = None
    key_field: str = ""
    key_value: str = ""
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Contract ABCs
# ---------------------------------------------------------------------------


class AdapterContract(ABC):
    """Interface for query-oriented systems (SIEMs, EDRs, log stores).

    Two operations. Health check tells you if the system is reachable.
    Query executes a native query and returns results. Everything else —
    field enumeration, aggregation, post-processing — the agent does in
    Python after getting raw results.

    The contract is deliberately minimal. Capabilities like field
    enumeration, aggregation, schema normalization, and data freshness
    are excluded because they're either unbounded problems, query-language
    specific, or context-dependent. See the design doc for the reasoning.
    """

    @abstractmethod
    def health_check(self) -> HealthResult:
        """Binary connectivity check.

        Tests: can we reach the endpoint and authenticate?
        Does NOT assess data freshness, index health, or pipeline status.
        Those are unbounded problems — the investigation methodology handles
        them (e.g., checking if zero results means "clean" or "broken").

        CLI exit codes:
            0 — connected
            1 — connection or auth failure (print error to stderr)
        """
        ...

    @abstractmethod
    def query(
        self,
        native_query: str,
        time_start: Optional[str] = None,
        time_end: Optional[str] = None,
        limit: int = 500,
    ) -> QueryResult:
        """Execute a query in the system's native language.

        native_query: the query string as the system understands it.
            Splunk adapter receives SPL. Wazuh adapter receives Lucene.
            Elastic adapter receives KQL. No translation layer.

        time_start / time_end: ISO 8601 UTC. Optional — some systems don't
            support time-bounded queries (e.g., asset databases). Adapters
            that don't use time ranges ignore these parameters.

        limit: max results to return. Adapter handles pagination internally
            and sets truncated=True if total_hits exceeds limit.

        CLI exit codes:
            0 — query executed (even if zero results)
            1 — query execution failed (print error to stderr)
            2 — connection/auth failure (print error to stderr)
        """
        ...


class LookupContract(ABC):
    """Interface for identifier-oriented systems (CMDB, asset DB, threat intel).

    Two operations. Health check tests reachability. Lookup fetches a
    single record by key. No query language — the client hands over a
    field name and a value, the adapter returns the matching record (or
    reports "not found", which is a valid result distinct from an error).

    When to choose LookupContract over AdapterContract:

    - The upstream API is fundamentally lookup-shaped (e.g., a CMDB where
      you call `GET /assets/{id}` rather than `POST /query`).
    - Forcing the system into a query DSL would be lossy or awkward.
    - The data is small and keyed — asset inventory, IAM role records,
      IOC enrichment.

    When to stay with AdapterContract:

    - The system has a native query language, even if most use cases are
      single-record lookups (e.g., Splunk with `index=hosts hostname=x`).
    - You need range queries, aggregation, or time windows.
    """

    @abstractmethod
    def health_check(self) -> HealthResult:
        """Binary connectivity check. Same contract as AdapterContract.health_check."""
        ...

    @abstractmethod
    def lookup(self, key_field: str, key_value: str) -> LookupResult:
        """Fetch a single record by key.

        key_field: the field name the upstream indexes by (e.g. "hostname",
            "user_id", "ioc_sha256"). The adapter may accept multiple key
            fields if the upstream supports it; document which in the
            system's environment knowledge.

        key_value: the value to look up. Passed through to the upstream
            without modification.

        CLI exit codes:
            0 — lookup executed (found or not found, both valid)
            1 — lookup failed (malformed key, unsupported key_field)
            2 — connection/auth failure
        """
        ...


# ---------------------------------------------------------------------------
# Contract compliance: what `/connect` and preflight.py verify
# ---------------------------------------------------------------------------

#: Subcommands an AdapterContract-shaped CLI must expose.
REQUIRED_QUERY_SUBCOMMANDS = ("health-check", "query")

#: Subcommands a LookupContract-shaped CLI must expose.
REQUIRED_LOOKUP_SUBCOMMANDS = ("health-check", "lookup")

#: Flags the `query` subcommand must accept. `--run-dir` is required so
#: the adapter can wrap output in salted untrusted-data delimiters when
#: invoked inside an investigation run.
REQUIRED_QUERY_FLAGS = ("--start", "--end", "--limit", "--raw", "--run-dir")

#: Flags the `lookup` subcommand must accept. Lookup has no time window
#: or limit — one key, one record.
REQUIRED_LOOKUP_FLAGS = ("--raw", "--run-dir")

#: Back-compat alias — older code references the query-shape subcommands
#: as "the" required subcommands. Kept so external scripts don't break.
REQUIRED_SUBCOMMANDS = REQUIRED_QUERY_SUBCOMMANDS

#: Environment knowledge `/connect` scaffolds for every newly-connected
#: system. Preflight does not hard-require every filename (the env layout
#: is flexible — data sources may be organized by data type rather than
#: per-system). These are the defaults `/connect` writes when it has
#: nothing else to go on.
SCAFFOLDED_KNOWLEDGE_ARTIFACTS = (
    "knowledge/environment/systems/{system}/config.env.template",
    "knowledge/environment/systems/{system}/field-notes.md",
    "knowledge/environment/data-sources/{system}.md",
)
