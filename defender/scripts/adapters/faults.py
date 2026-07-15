"""The adapter fault taxonomy: transports RAISE, they never `sys.exit`.

Before #611 an adapter was a subprocess and its exit code WAS its error channel — the
queries table stored it and the circuit breaker keyed on it. In-process that channel is
gone, and `sys.exit` is actively hostile: `SystemExit` is a `BaseException`, so
pydantic-ai's `except Exception` does not catch it and `asyncio.to_thread` re-raises it
to the awaiter — it unwinds straight out of `agent.iter()`, taking the run with it and
writing no row for the very failure the taxonomy exists to record.

So a fault is an exception carrying the two things the row needs:

  - `exit_code` — the code the breaker keys on. The taxonomy is unchanged (2 = the system
    is down, 1 = the query was wrong, 64 = the agent's call was malformed), so
    `circuit_breaker.error_class_for_exit` still derives the class from it and there is
    no second place to disagree about what "infra" means.
  - `detail` — the UPSTREAM diagnosis, verbatim: Elasticsearch's own `verification_exception`
    body, the docker error, the missing config path. It becomes the row's `payload_digest`
    (`exit=N; <detail>`), which is the SOLE input to the pitfalls-curation lane — a curator
    told to skip any failure whose digest names no concrete mistake. A generic `str(e)`
    dries that lane up silently, so the detail is a required constructor arg, not a nicety.

One class per exit code, named for the CONDITION rather than the code, so a transport
author picks the meaning and the code follows:

  - `ConfigFault`  (2) — the config is missing or malformed. Infra: a system with no config
    is definitionally down. (It exited **1** before this issue — a misfiling that filed a
    dead system as an agent-fixable query error, so it never tripped the breaker.)
  - `TransportFault` (2) — the transport itself failed: docker missing, exec timed out, the
    service unreachable, a 5xx. Infra.
  - `UpstreamFault` (1) — the service was reached and rejected the query (a 4xx, a bad
    field name, a malformed query body). The agent's mistake, and the one the pitfalls lane
    learns from — hence the vendor's own body in `detail`.
"""

from __future__ import annotations

# The agent-side call error: an unknown verb, an unknown/missing param. Raised by the query
# tool's own validator, not by a transport — but it lives here because it is the fourth
# member of the one taxonomy, and `circuit_breaker` reserves it (64 never trips the breaker,
# so a model's typo cannot hide a working system).
USAGE_EXIT_CODE = 64


class AdapterFault(Exception):
    """A data-source call failed. Carries the exit code the queries table records and the
    UPSTREAM diagnosis the pitfalls curator reads. Never subclass this to add a new code
    without also asking whether `circuit_breaker.INFRA_EXIT_CODES` should claim it."""

    exit_code: int = 1

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class ConfigFault(AdapterFault):
    """The system's `config.env` is absent or incomplete — the system is down, not the query
    wrong. Infra (2), so the breaker trips and stops the agent re-asking a dead source."""

    exit_code = 2


class TransportFault(AdapterFault):
    """The transport failed: docker CLI missing, `docker exec` timed out, the service
    unreachable, an upstream 5xx. Infra (2).

    A hung verb arrives here too, through the transport's OWN inner `subprocess.run(timeout=)`
    — which is now the only real kill. The outer wall-clock budget the capture subprocess used
    to enforce cannot be reproduced in-process (`asyncio.wait_for` cancels the AWAIT, not the
    thread), so exit 124 is never synthesized again: a row claiming a timeout we did not
    enforce would be a lie about a process that is still running."""

    exit_code = 2


class UpstreamFault(AdapterFault):
    """The service was reached and rejected the query — a 4xx, an unknown column, a malformed
    query body. A query error (1), the agent's own to fix. `detail` MUST be the vendor's body
    (Elasticsearch's `detail` field, the 404's message), because the digest built from it is
    the only thing the pitfalls curator ever sees of this failure."""

    exit_code = 1


__all__ = [
    "USAGE_EXIT_CODE",
    "AdapterFault",
    "ConfigFault",
    "TransportFault",
    "UpstreamFault",
]
