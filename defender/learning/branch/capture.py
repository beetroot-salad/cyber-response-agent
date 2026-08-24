"""The family's base tier, taken from the source run's own capture.

#920 defines the base world as **captured, not authored** — "its state across the seven systems
is whatever the real adapters returned during the real run" — so a sibling is that capture plus
a diff. The seam as first built did something narrower: it recorded the base from a LIVE adapter
call made by whichever sibling happened to ask first, mid-episode. On a quiet estate the two
coincide; nothing guarantees they do, and nothing in the table could tell them apart. The
practical cost is replayability: re-running an episode a week later recorded different bytes for
identical questions, so an archived episode's `ΔO` was only ever comparable against itself.

Priming closes that, and it closes the concurrency question as a side effect. The base file is
written ONCE, here, before any sibling forks, and is read-only for the rest of the run — so
parallel siblings never contend for it, and the check-then-act race the ledger used to concede
("both miss, both read live") cannot arise for a captured key at all.

WHAT IT CANNOT DO. A sibling is continuing an investigation, so it asks questions the source
never asked. Those keys have no captured row, each world reads them live, and two worlds can get
two answers. That residual is real and is not hidden: each such read records a `base` row in the
world's own file, and counting them across a family is its size.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from defender._io import append_jsonl, read_jsonl_rows, read_text_soft
from defender._run_paths import RunPaths, contained_payload
from defender.scripts.gather_tools.record_query import is_reserved_query_id

from .ledger import CAPTURED, LedgerError, ServedCall, payload_text


@dataclass(frozen=True)
class PrimeReport:
    """What the capture yielded, and what it did not.

    The skip counts are the point, not bookkeeping. Each one names a key that will reach the
    live estate during the episode instead of replaying, which is the part of the base a primer
    cannot make deterministic — so a caller that logs this is stating the size of the
    non-deterministic surface rather than leaving a reader to assume it was zero.
    """

    primed: int = 0
    duplicates: int = 0
    failed: int = 0
    sentinels: int = 0
    unreadable: int = 0


def prime_base(source_run_dir: Path, base_path: Path) -> PrimeReport:
    """Write `base_path` from `source_run_dir`'s capture. Once, before any sibling exists.

    THE WHOLE CAPTURE, not a slice at the branch point — and the asymmetry with the run dir's
    own evidence, which IS truncated, is deliberate. The two answer different questions. The run
    dir is what the MODEL may read, so it is cut to what the inherited prefix can honestly cite.
    The base ledger is what the ESTATE answers from, and a post-branch captured row is never
    handed to anybody: it is reached only if a sibling independently asks that question, and the
    world's own difference is still applied on top. Slicing it would buy nothing and cost
    determinism on exactly the keys a sibling is most likely to re-ask.
    """
    rows = read_jsonl_rows(RunPaths(Path(source_run_dir)).executed_queries)
    seen: set[str] = set()
    out: list[dict] = []
    counts = {"duplicates": 0, "failed": 0, "sentinels": 0, "unreadable": 0}
    for row in rows:
        call = _captured_call(Path(source_run_dir), row, counts)
        if call is None:
            continue
        # FIRST KEY WINS, the rule the ledger's memo folds a file under. Two rules would let the
        # file and the memo disagree about which of two recordings of one question is the
        # answer, which is the invariance the family tier exists to buy.
        if call.key in seen:
            counts["duplicates"] += 1
            continue
        seen.add(call.key)
        out.append(call.row())
    if not out:
        # `branch.validate` already refuses a source that captured nothing that reached a system,
        # so an empty prime means the capture is PRESENT and unreadable. Continuing would leave
        # every key to the live estate while the run stayed green — the fail-open shape #920
        # names as its fourth trap, reached through the one step that exists to prevent it.
        raise LedgerError(
            f"{source_run_dir} primed no base rows ({counts}) — its capture is present but "
            "nothing in it could be read back, so every sibling would read the live estate for "
            "every key with nothing in the record to say so")
    base_path.parent.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — episode archive under the learning state root, host-side, outside every box mount
    append_jsonl(  # lint-unguarded-tree-write: ok — episode archive under the learning state root, host-side, outside every box mount
        base_path, out)
    return PrimeReport(primed=len(out), **counts)


def _captured_call(run_dir: Path, row: dict, counts: dict) -> ServedCall | None:
    """One capture row as a family-tier `ServedCall`, or `None` with `counts` advanced.

    SUCCESSFUL ANSWERS ONLY, and that is a property of the tier rather than a simplification.
    When an adapter raises, the exception propagates out of the verb body before the base row is
    ever written, and the estate seam files it in the WORLD tier as a fault — so the family tier
    has never held a failure and there is no representation of one to prime. The alternatives
    are both worse than skipping: priming the error digest as a payload hands
    `"exit=1; HTTP 404 ..."` to the applier as a successful response, which is silent scenario
    injection; and refusing to prime a capture that contains any error makes the one real
    fixture unbranchable, since it holds a cmdb 404.

    The cost, stated rather than hidden: a captured failure is re-attempted live by each world
    and may not fail the same way twice. It is bounded — a `1` exit is `agent-fixable` and not an
    INFRA code, so a replayed failure cannot trip the circuit breaker in one sibling and not its
    base — and `PrimeReport.failed` is its size.
    """
    if is_reserved_query_id(str(row.get("query_id", ""))):
        # A `∅.`-prefixed row is a writer-only record of a call that never reached a system of
        # record. There is no estate answer behind it to replay.
        counts["sentinels"] += 1
        return None
    if row.get("exit_code") != 0:
        counts["failed"] += 1
        return None
    sidecar = contained_payload(run_dir, row.get("payload_path"))
    if sidecar is None:
        counts["unreadable"] += 1
        return None
    text = read_text_soft(sidecar)[0]
    if text is None:
        counts["unreadable"] += 1
        return None
    canonical = _canonical_payload(text)
    if canonical is None:
        counts["unreadable"] += 1
        return None
    system, verb = str(row.get("system", "")), str(row.get("verb", ""))
    params = row.get("params")
    if not system or not verb or not isinstance(params, dict):
        counts["unreadable"] += 1
        return None
    return ServedCall(
        system=system, verb=verb, params=params,
        payload_text=canonical, source=CAPTURED, world_id=None,
    )


def _canonical_payload(text: str) -> str | None:
    """One captured sidecar re-spelled in the ledger's own canonical form, or `None`.

    THE PARSE AND THE CANONICALISATION ARE ONE CONSTRUCTION, which is why they live in one
    function and why nothing in between ever holds the deserialized value: what this seam owes
    its caller is bytes the ledger will recognise, not a tree.

    RE-DUMPED, never copied verbatim, and this is the subtle half of priming. `query_tool` wrote
    the sidecar with `json.dumps(payload, default=str)` and NO `sort_keys`, while the ledger
    canonicalises with it — so a primer that copied the sidecar's bytes would write a row whose
    text is a different spelling of the same answer. Every live serve of that key would then miss
    the base tier and read the estate, on a run that stayed green and a base file that looked
    full. `payload_text` is imported from the ledger rather than respelled for exactly that
    reason: the two spellings must be one.
    """
    try:
        return payload_text(json.loads(text))
    except ValueError:
        return None
