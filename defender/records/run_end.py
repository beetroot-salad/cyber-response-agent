"""How a run ended: the exit-class vocabulary, its one normalizer, and the host-side record."""
from __future__ import annotations

import json
from defender._model import model
from pathlib import Path
from typing import Any

from defender.records import Run, RunPaths

TRUNCATED_BY_REQUEST_LIMIT = "request-limit"
TRUNCATED_BY_RETRY_EXHAUSTED = "retry-exhausted"
TRUNCATED_BY_ABORTED = "aborted"
TRUNCATED_BY_BUDGET = "budget"
TRUNCATED_BY_STORE = "store"
TRUNCATED_BY_DEAD_END = "dead-end"
#: A write of one of the run's two call records failed (A12, #1234): the served ledger (a
#: branched world's `served/<token>.jsonl`) or the query table (`executed_queries.jsonl`).
#: Each value names its record, so a world cut short by one says which write failed.
TRUNCATED_BY_SERVED_LEDGER = "served_ledger"
TRUNCATED_BY_EXECUTED_QUERIES = "executed_queries"
TRUNCATED_BY_TIMED_OUT = "timed-out"
#: A model request kept failing temporarily until its retries ran out (#1243): an infrastructure
#: end like the budget and store ones, so no report is written for it.
TRUNCATED_BY_PROVIDER_DOWN = "provider-down"
#: The provider refused a request for good (a 4xx the retrier does not resend:
#: a request built wrong or too long, or a key, account, permission or model name that no
#: longer works).
#: Resending gets the same answer, so the run ends with no report and the case gets the
#: escalation note. A lead's refusal ends the run only when its status says the setup is broken
#: (`providers.SETUP_STATUSES`); any other ends only that lead, stamped with
#: this word (#1243 r3).
TRUNCATED_BY_PROVIDER_REJECTED = "provider-rejected"
#: The run's box became unusable (#1421 O8): the first command that found it ends the run, with
#: no retry the model cannot act on. The operator's to fix.
TRUNCATED_BY_BOX_LOST = "box-lost"
#: The host fence tripped (#1205, #1421 O9): a process in the box wrote past the in-box helper.
TRUNCATED_BY_BOX_OUTPUT_LIMIT = "box-output-limit"
#: The run lost its access to the credential proxy (#1363 O7, D4): its read token could not be
#: signed, or the proxy answered that our access as a whole is unusable. Ours to fix, not the
#: tenant's: no verdict, no report, no case comment, and no system marked down.
TRUNCATED_BY_PROXY_ACCESS = "proxy-access"
TRUNCATED_BY_VALUES = (
    TRUNCATED_BY_REQUEST_LIMIT, TRUNCATED_BY_RETRY_EXHAUSTED, TRUNCATED_BY_ABORTED,
    TRUNCATED_BY_BUDGET, TRUNCATED_BY_STORE, TRUNCATED_BY_DEAD_END,
    TRUNCATED_BY_SERVED_LEDGER, TRUNCATED_BY_EXECUTED_QUERIES, TRUNCATED_BY_TIMED_OUT,
    TRUNCATED_BY_PROVIDER_DOWN, TRUNCATED_BY_BOX_LOST, TRUNCATED_BY_BOX_OUTPUT_LIMIT,
    TRUNCATED_BY_PROVIDER_REJECTED, TRUNCATED_BY_PROXY_ACCESS,
)


@model(frozen=True)
class ExitClass:
    """What an exit class means past the run-end record: the process exit status a run ended
    by it returns, and whether it is a box ending (the run's box can no longer be trusted)."""

    exit_code: int
    box_ending: bool = False


#: The one exit-class table (#1421): every class whose run exits non-zero, by its own code. A
#: class not here exits 0. Rerun later for provider-down; the operator's box for box-lost and
#: box-output-limit; the operator's model configuration (or a defect) for provider-rejected; the
#: credential proxy and the tenant's setup of it for proxy-access.
#: Each code is non-zero, so a branched sibling that meets one is recorded `did not finish`.
EXIT_CLASSES: dict[str, ExitClass] = {
    TRUNCATED_BY_PROVIDER_DOWN: ExitClass(4),
    TRUNCATED_BY_BOX_LOST: ExitClass(5, box_ending=True),
    TRUNCATED_BY_BOX_OUTPUT_LIMIT: ExitClass(6, box_ending=True),
    TRUNCATED_BY_PROVIDER_REJECTED: ExitClass(7),
    TRUNCATED_BY_PROXY_ACCESS: ExitClass(8),
}

#: A branched sibling refused at run start because its read token for the credential proxy cannot
#: be signed exits with this (#1449). Not an exit class: no run folder exists yet, so there is no
#: ending to record. The branch launcher reads it as the environment's refusal, not the world's:
#: every later sibling would be refused the same way, so none starts.
SIGN_REFUSED_EXIT = 9

#: Endings with no verdict whose case gets the escalation note: a person must look, and a rerun
#: alone will not settle it.
ESCALATED_EXITS = frozenset({TRUNCATED_BY_ABORTED, TRUNCATED_BY_PROVIDER_REJECTED})
#: Endings with no verdict that leave the case open with no comment at all: the infrastructure
#: ends (budget, store, and every class with its own exit code) except the escalated ones.
SILENT_EXITS = frozenset({TRUNCATED_BY_BUDGET, TRUNCATED_BY_STORE, *EXIT_CLASSES}) - ESCALATED_EXITS

#: The endings that leave the run's box possibly alive: a teardown fault on them is logged, never
#: raised over the ending, and skips the post-steps that read the tree.
BOX_ENDINGS = frozenset(word for word, cls in EXIT_CLASSES.items() if cls.box_ending)


def exit_code_of(truncated_by: object) -> int:
    """The exit status of a run that ended with `truncated_by` (normalized first): its class's
    code, else 0."""
    found = EXIT_CLASSES.get(normalized_truncated_by(truncated_by) or "")
    return 0 if found is None else found.exit_code

#: Exits where the model spent its budget without closing, so the host writes an `unresolved`
#: report (otherwise the run dead-letters for a missing report.md). Shared by the driver's
#: forced close and the ticket lane, so a failed forced close still escalates. The driver
#: explains why the breaker, budget kill and store exits are absent.
FORCED_CLOSE_EXITS = frozenset({TRUNCATED_BY_REQUEST_LIMIT, TRUNCATED_BY_RETRY_EXHAUSTED})

#: The records `CallRecordWriteFailed` may name, each the exit class its failure stamps.
CALL_RECORDS = frozenset({TRUNCATED_BY_SERVED_LEDGER, TRUNCATED_BY_EXECUTED_QUERIES})


class ProxyAccessLost(Exception):  # noqa: N818 — named for what it reports, like `RunAborted`
    """The run's access to the credential proxy is lost (#1363 O7, D4): a call met a fault of
    origin `access`, ours for the whole process. Control flow, never an adapter fault: raised by
    the query tool for the first such fault, carried out of lead zero, the gather tools and the
    driver (bare or inside an exception group), and ended as `proxy-access`. `detail` is the
    fault's own; the message names the credential proxy, so the ending's reason does."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"the credential proxy could not be used: {detail}")

    def __reduce__(self) -> tuple[type, tuple[Any, ...]]:
        return self.__class__, (self.detail,)


class CallRecordWriteFailed(Exception):  # noqa: N818 — named for what it reports, like `RunAborted`
    """A write of one of a call's two records failed, so the run must end (A12, #1234).

    `record` is the record whose write failed — `TRUNCATED_BY_SERVED_LEDGER` or
    `TRUNCATED_BY_EXECUTED_QUERIES` — and is the exit class the driver stamps. Raised by the
    served-ledger writer (`Ledger.record`), never swallowed on the way up. Query-row writers
    retain their OSError after recording the call in memory (#1235); they do not stamp a cut."""

    def __init__(self, record: str, detail: str) -> None:
        if record not in CALL_RECORDS:
            raise ValueError(f"not a call record: {record!r} (one of {sorted(CALL_RECORDS)})")
        self.record = record
        super().__init__(f"the {record} write failed: {detail}; the run ends here")


def normalized_truncated_by(value: object) -> str | None:
    """A `truncated_by` value if it is a `TRUNCATED_BY_VALUES` member, else `None`. Every
    reader uses this so they all refuse the same values.

    Strict (unlike `_vocab.normalized_disposition`): no strip or case fold, since the only
    producer is the driver's own constrained stamp. `None` ("not cut short") maps to `None`.
    """
    if not isinstance(value, str):
        return None
    return value if value in TRUNCATED_BY_VALUES else None


@model(frozen=True)
class RunEnd:
    """How one MAIN run ended: its exit class (`None` when it ended cleanly) and whether the
    model had already closed when that exit was stamped."""

    truncated_by: str | None
    closed_before_cut: bool

    def doc(self) -> dict[str, Any]:
        """The record's JSON document."""
        return {"truncated_by": self.truncated_by, "closed_before_cut": self.closed_before_cut}


def sidecar_path(run_dir: Path) -> Path:
    """The host-side run-end record's path, beside `run_dir`. A pure function of the path so
    no box-writable content influences it.
    """
    run_dir = Path(run_dir)
    return RunPaths(run_dir).run_end_sidecar()


def write_sidecar(run: Run, record: RunEnd) -> None:
    """Write the sidecar beside `run_dir`. Written for every run reaching the agent loop,
    clean ones included, so "not cut short" differs from "the host never said". Atomically
    replaces a stale sidecar.
    """
    run.facts.run_end.write(json.dumps(record.doc()))


def parse_record(doc: object) -> RunEnd | None:
    """The record a parsed JSON document holds, or `None`.

    Strict: both fields required, `truncated_by` null or a vocabulary member,
    `closed_before_cut` a real bool. Anything else reads as no record, so a corrupted file
    fails toward "the host said nothing", never toward a verdict. Extra keys are ignored.
    """
    if not isinstance(doc, dict) or {"truncated_by", "closed_before_cut"} - set(doc):
        return None
    truncated_by, closed = doc["truncated_by"], doc["closed_before_cut"]
    if truncated_by is not None and normalized_truncated_by(truncated_by) is None:
        return None
    if not isinstance(closed, bool):
        return None
    return RunEnd(truncated_by, closed)


__all__ = [
    "BOX_ENDINGS",
    "CALL_RECORDS",
    "CallRecordWriteFailed",
    "ESCALATED_EXITS",
    "EXIT_CLASSES",
    "ExitClass",
    "FORCED_CLOSE_EXITS",
    "ProxyAccessLost",
    "TRUNCATED_BY_PROXY_ACCESS",
    "TRUNCATED_BY_ABORTED",
    "TRUNCATED_BY_BOX_LOST",
    "TRUNCATED_BY_BOX_OUTPUT_LIMIT",
    "TRUNCATED_BY_BUDGET",
    "TRUNCATED_BY_DEAD_END",
    "TRUNCATED_BY_EXECUTED_QUERIES",
    "TRUNCATED_BY_PROVIDER_DOWN",
    "TRUNCATED_BY_PROVIDER_REJECTED",
    "TRUNCATED_BY_REQUEST_LIMIT",
    "TRUNCATED_BY_RETRY_EXHAUSTED",
    "TRUNCATED_BY_SERVED_LEDGER",
    "TRUNCATED_BY_STORE",
    "TRUNCATED_BY_TIMED_OUT",
    "TRUNCATED_BY_VALUES",
    "RunEnd",
    "SILENT_EXITS",
    "exit_code_of",
    "normalized_truncated_by",
    "parse_record",
    "sidecar_path",
    "write_sidecar",
]
