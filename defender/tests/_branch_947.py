"""Shared machinery for the #947 turn-N foundations spec — NO test scripts.

#947 makes T0 — the branch point's own moment — a REQUIRED coordinate of a branch: `BranchSpec`
carries `as_of`, and `validate` refuses a spec whose moment disagrees with what
`branch_point_time` derives from the prefix it forks at. That turns a `BranchSpec(...)` literal
into a two-step construction, and it is a two-step construction at every call site in three
suites — so it is spelled once, here.

Three things live here and nothing else:

1. **`branch_mod()`** — `defender.runtime.branch`, imported per test (the `_session_store_705`
   idiom), so a missing target is one failure per test rather than one collection error.
2. **`spec_at`** — the LEGAL spec for a branch point: it derives `as_of` through the runtime's
   own `branch_point_time` rather than choosing a moment of its own, so a caller that means
   "the spec this branch point admits" cannot accidentally pin a T0 the derivation disagrees
   with. Its `as_of=` override is for the arms whose subject IS that disagreement.
3. **`legal_source`** — a finished run a branch may legally be taken from: a case pointer, a
   prefix of complete pairs, an `append_block` turn carrying the document, and a captured
   query. The three preconditions `validate` reads (a capture, an open frontier, a complete
   pair at the branch point) are all satisfied by it, so a test that means to fail one of them
   fails exactly that one.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import importlib
from pathlib import Path
from typing import Any

from defender.tests._session_store_705 import (
    complete_pair,
    make_store,
    runs_base,
    store_mod,
    tool_call_response,
    tool_return_request,
    user_request,
)

DEFENDER = Path(__file__).resolve().parents[1]

#: The document every legality fixture branches over — read off the tree rather than authored
#: inline, for `test_920_branch_seam`'s reason: an invlang document whose frontier is non-empty
#: needs vertices carrying live `??` cells, which is not a string one improvises.
GOLDEN_INVESTIGATION = DEFENDER / "fixtures-e2e" / "golden-v2sshd" / "investigation.md"

#: The case input every real run dir holds: `materialize_run_dir` copies it in before anything
#: else happens, so a source run without one is not a shape a branch is ever taken from — and
#: the sibling investigates the SAME alert, which is why it crosses over verbatim.
ALERT_DOC = (
    '{"rule": "Adding ssh keys to authorized_keys", "host": "canary-1", '
    '"timestamp": "2026-05-25T15:16:00Z"}\n'
)

#: One captured query — the evidence `validate` refuses a branch without. `payload_status: ok`
#: and a real `query_id`, so it is a CAPTURE rather than a `∅.`-prefixed sentinel.
CAPTURED_QUERY_ROW = (
    '{"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "esql", '
    '"query_id": "elastic.sshd-failed-by-srcip", "params": {}, '
    '"payload_status": "ok"}\n'
)

#: The moment a DRAFT spec carries while its real one is being derived. Aware UTC, so building
#: the draft never trips the shape check that `as_of` is one — the draft exists only to be
#: handed to `branch_point_time`, which reads the run and the message id and nothing else.
DRAFT_MOMENT = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)

#: "Derive T0 from the store", as a value `as_of` can never legitimately hold. NOT `None`:
#: `None` is one of the shapes `validate` has to refuse, and a helper that read it as "derive"
#: would hand the arm testing that refusal a perfectly good spec — the arm then passes on an
#: implementation that accepts `None`, which is the one direction a spec check must not fail in.
DERIVE = object()


def branch_mod():
    """`defender.runtime.branch`, imported per test."""
    return importlib.import_module("defender.runtime.branch")


def spec_at(store: Any, run_dir: Path, message_id: int, *,
            prompt: str = "continue", as_of: Any = DERIVE):
    """The `BranchSpec` this branch point admits, T0 included.

    Two steps, because the two coordinates are not independent: `branch_point_time` reads the
    prefix the spec names, and `validate` then refuses any spec whose `as_of` is not what that
    derivation answered. A test that built a spec with a moment of its own would be refused for
    a reason it was not written about.

    `as_of=` overrides the derivation for the arms whose subject is exactly that refusal — and
    it is compared against `DERIVE` rather than against `None`, so an arm may pass `None`, or any
    other falsy non-moment, and get exactly what it asked for.
    """
    branch = branch_mod()
    draft = branch.BranchSpec(
        source_run_dir=Path(run_dir), branch_message_id=message_id,
        continuation_prompt=prompt, as_of=DRAFT_MOMENT,
    )
    moment = (  # lint-default: ok — a sentinel-defaulted override, not an optional re-coalesced in the body  # noqa: E501
        branch.branch_point_time(store, Path(run_dir), message_id)
        if as_of is DERIVE else as_of)
    return dataclasses.replace(draft, as_of=moment)


def legal_source(
    tmp_path: Path, *, investigation: str | None, queries: str | None = CAPTURED_QUERY_ROW,
    case_id: str = "case-source", name: str = "run-source-001",
):
    """A finished run a branch may legally be taken from.

    Returns `(store, run_dir, session_id, path_ids)`. `path_ids[-1]` is the `append_block`
    turn's RETURN — a complete pair, which is the shape `validate` admits — and `path_ids[3]`
    is the CALL one row before it.

    The `append_block` call carries the DOCUMENT as its `text`, which is what a real append
    that authored this file would have sent: `fence_count_at` reads the appended text, so a
    placeholder there would land a document the store says holds no fences.

    `investigation=None` writes no document (the empty-frontier fixture) and `queries=None`
    writes no table (the no-capture fixture), so each precondition can be failed on its own.
    """
    ss = store_mod()
    store = make_store(tmp_path, case_id=case_id)
    run_dir = runs_base(tmp_path) / name
    run_dir.mkdir(parents=True, exist_ok=True)
    ss.write_case_pointer(run_dir, case_id=case_id, store_path=store.path)
    (run_dir / "alert.json").write_text(ALERT_DOC, encoding="utf-8")
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request("investigate the alert"), *complete_pair()],
                 agent_id="main")
    store.append(session_id, [tool_call_response("append_block", {"text": investigation or ""},
                                                 tool_call_id="ab1")], agent_id="main")
    store.append(session_id, [tool_return_request("append_block", "ok", tool_call_id="ab1")],
                 agent_id="main")
    if investigation is not None:
        (run_dir / "investigation.md").write_text(investigation, encoding="utf-8")
    if queries is not None:
        (run_dir / "executed_queries.jsonl").write_text(queries, encoding="utf-8")
    return store, run_dir, session_id, ss.path_row_ids(store, session_id)
