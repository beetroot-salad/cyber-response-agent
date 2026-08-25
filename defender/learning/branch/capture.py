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

from defender._io import append_jsonl, read_text_soft
from defender.learning.lead_repository import QueryRow, load_queries_report

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
    # ONCE IS A REFUSAL, NOT A NARRATION. `append_jsonl` opens `"a"`, so a second prime into the
    # same episode stacked a second capture underneath the first — and `_absorb` is
    # first-row-wins, so the EARLIER source's answers stayed the estate for every sibling of the
    # later episode while `PrimeReport` reported a clean prime of the new one. Green run, wrong
    # capture, nothing in the record to say so: the same shape the empty-prime raise below
    # refuses, arriving through the door beside it. Retrying a partly-failed episode is the
    # ordinary way in — `materialize_run_dir` exits on an existing run dir, which invites
    # exactly the re-run — so this is the common path, not the exotic one.
    if base_path.exists() or base_path.is_symlink():
        raise LedgerError(
            f"{base_path} already holds a primed base — a family's capture is written once, "
            "before any sibling forks, and priming over it merges two runs' estates under "
            "first-row-wins with nothing in the table to tell them apart. Name a fresh "
            "episode id, or remove the episode directory to re-prime it")
    # THROUGH `lead_repository`, which `defender/CLAUDE.md` names as "the single read/join
    # surface … consumers never re-parse the artifacts". Hand-decoded here, the primer was a
    # second reader of a thirteen-column row with ONE writer, and it had already drifted:
    # `row.get("exit_code") != 0` treats a `"0"` written as a string as a failure where
    # `load_queries` coerces it through `_as_int` and reads it as the success it is — so the two
    # readers disagreed about which captures exist, in the direction that silently leaves keys
    # to the live estate.
    rows, table_unreadable = load_queries_report(Path(source_run_dir))
    seen: set[str] = set()
    out: list[dict] = []
    counts = {
        "duplicates": 0, "failed": 0, "sentinels": 0,
        "unreadable": table_unreadable,
    }
    for row in rows:
        call = _captured_call(row, counts)
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
        # so an empty prime means the capture is PRESENT and every row was SKIPPED. Continuing
        # would leave every key to the live estate while the run stayed green — the fail-open
        # shape #920 names as its fourth trap, reached through the one step that exists to
        # prevent it.
        #
        # THE COUNTS NAME WHICH SKIP, and the message must not guess: `validate` screens only
        # reserved query ids, never `exit_code`, so a short source whose every real capture
        # errored (the one shipped fixture holds a cmdb 404) reaches here with `failed=N` and
        # nothing unreadable at all. Told "nothing in it could be read back", an operator goes
        # looking for a corrupt sidecar that does not exist.
        raise LedgerError(
            f"{source_run_dir} primed no base rows — every row in its capture was skipped "
            f"({counts}), so every sibling would read the live estate for every key with "
            "nothing in the record to say so. The counts name which rule skipped them: "
            "`failed` is a non-zero exit, `sentinels` never reached a system, `unreadable` is "
            "a payload this episode could not read back")
    # NO mkdir HERE: `append_jsonl` makes the parent itself, and the `if not out` raise above
    # means it can never take its empty-rows early return. A second copy of the same call was a
    # second `lint-unguarded-tree-write` waiver to re-audit for one write.
    append_jsonl(  # lint-unguarded-tree-write: ok — the episode archive is `runs_base/episodes/<id>/`, a sibling of the run dirs rather than one of them, so it is not bound into any box  # noqa: E501
        base_path, out)
    return PrimeReport(primed=len(out), **counts)


def _captured_call(row: QueryRow, counts: dict) -> ServedCall | None:
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

    A `QueryRow`, not a raw dict: the sentinel predicate, the `exit_code` coercion and the
    containment check on `payload_path` are `lead_repository`'s, so this seam holds only the
    rules that are the TIER's. `params` arrives already coerced to `{}` when the stored value is
    not a dict, which is also exactly what `request_key` does with one — so the primed key and
    the key a live serve would compute agree, where skipping such a row left the two readers of
    one malformed line disagreeing about whether it exists.
    """
    if row.is_sentinel:
        # A `∅.`-prefixed row is a writer-only record of a call that never reached a system of
        # record. There is no estate answer behind it to replay.
        counts["sentinels"] += 1
        return None
    if row.exit_code != 0:
        counts["failed"] += 1
        return None
    if row.raw_ref is None:
        counts["unreadable"] += 1
        return None
    text = read_text_soft(row.raw_ref)[0]
    if text is None:
        counts["unreadable"] += 1
        return None
    canonical = _canonical_payload(text)
    if canonical is None:
        counts["unreadable"] += 1
        return None
    system, verb = row.system, row.verb
    if not system or not verb:
        counts["unreadable"] += 1
        return None
    return ServedCall(
        system=system, verb=verb, params=row.params,
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

    `RecursionError` BESIDE `ValueError`, because "unreadable" is a COUNT here and not a fault:
    the caller's whole contract is that a sidecar this episode cannot read back advances
    `PrimeReport.unreadable` and the run states the size of its non-deterministic surface.
    `json.loads` raises `RecursionError` — not a `ValueError` — on a deeply nested payload, and
    adapter output is arbitrary vendor JSON, so one such row escaped every frame up to
    `cli.main` and killed the episode before a world forked, with a traceback naming neither
    the row nor the file.
    """
    try:
        return payload_text(json.loads(text))
    except (ValueError, RecursionError):
        return None
