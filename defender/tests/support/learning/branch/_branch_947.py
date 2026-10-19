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
3. **`legal_source`** — a finished run a branch could legally be taken from BEFORE #1255: a
   case pointer, a prefix of complete pairs, an `append_block` turn carrying the document, and
   a captured query, all written straight into the store. After #1255 it is the shape of a run
   recorded before the fork snapshot existed (N4: refused); see its docstring.

#1255 FIXTURE RULE (design rev 5, C2; contract review R1). `legal_source` STAYS SNAPSHOT-LESS:
it is the contract's N4 fixture (`tests/e2e/test_1255_snapshot_restore.py::test_n4_…`) and
must never gain a fork snapshot. A suite that needs a hand-planted source an arm IS admitted
from uses `planted_source` (the same shape) instead; any snapshot-planting helper the implementer
adds for that one is FIXTURE-ONLY
(it builds test inputs, it is not evidence the driver records snapshots), lives outside the
`_1255_snapshot` helper, and no `test_1255_snapshot_*` module may import it — those observe the
snapshot only through driven runs.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import dataclasses
import datetime as dt
import importlib
from pathlib import Path
from typing import Any

from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.storage._session_store_705 import (
    complete_pair,
    make_store,
    runs_base,
    store_mod,
    tool_call_response,
    tool_return_request,
    user_request,
)

DEFENDER = Path(__file__).resolve().parents[4]

#: The document every legality fixture branches over — read off the tree rather than authored
#: inline, for `test_920_branch_seam`'s reason: an invlang document whose frontier is non-empty
#: needs vertices carrying live `??` cells, which is not a string one improvises.
GOLDEN_INVESTIGATION = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd" / "investigation.md"

#: The case input every real run dir holds: `materialize_run` copies it in before anything
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


#: The field #1255 (D1, P4) removes from `BranchSpec`: an arm is told nothing on arrival.
RETIRED_PROMPT_FIELD = "continuation_prompt"


def declares_retired_prompt() -> bool:
    """Does this tree's `BranchSpec` still declare `continuation_prompt` (pre-#1255 code)?

    Read off the class rather than assumed, so the spec builder below stays usable on both
    sides of #1255: before it, a spec without the field is refused at construction and every
    branch test would go red on that one construction error instead of reaching its own
    assertion; after it, passing the field would be refused instead. Whether the field is GONE
    is a demand of its own (`test_920_branch_seam::test_branch_spec_carries_no_continuation_
    prompt`), never answered here. Delete this, and the `prompt` parameter below, once #1255
    has landed."""
    return RETIRED_PROMPT_FIELD in {f.name for f in dataclasses.fields(branch_mod().BranchSpec)}


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

    `prompt` reaches the spec ONLY while `BranchSpec` still declares the continuation prompt
    (`declares_retired_prompt`). #1255 (D1, P4) removes the field: an arm resumes with no user
    message at all, so on a tree past #1255 `prompt` is dropped here and a test still asserting
    the prompt reached the model fails on its own assertion — which is the reversal it should
    report, not a construction error.
    """
    branch = branch_mod()
    coordinates: dict[str, Any] = {
        "source_run_dir": Path(run_dir), "branch_message_id": message_id, "as_of": DRAFT_MOMENT,
    }
    if declares_retired_prompt():
        coordinates[RETIRED_PROMPT_FIELD] = prompt
    draft = branch.BranchSpec(**coordinates)
    moment = (  # lint-default: ok — a sentinel-defaulted override, not an optional re-coalesced in the body  # noqa: E501
        branch.branch_point_time(store, Path(run_dir), message_id, source_run=_run_handle_1165(Path(run_dir)))
        if as_of is DERIVE else as_of)
    return dataclasses.replace(draft, as_of=moment)


def legal_source(
    tmp_path: Path, *, investigation: str | None, queries: str | None = CAPTURED_QUERY_ROW,
    case_id: str = "case-source", name: str = "run-source-001",
):
    """A finished run a branch WAS legally taken from before #1255 — store rows written
    directly, no driver.

    #1255 CHANGES WHAT THIS IS. A source is branchable only at a MAIN response that called tools
    (D1) and only if production recorded a fork snapshot for that response while the run was
    driven (P2); a run with no snapshot is a run recorded before the change, and forking one is
    refused (N4). Nothing here drives a run, so after #1255 every branch from this fixture is
    the N4 case — `tests/e2e/test_1255_snapshot_restore.py` uses it as exactly that. A test that
    needs a source a branch is ADMITTED from drives one: `tests/_1255_snapshot.drive_source`.

    Returns `(store, run_dir, session_id, path_ids)`:

    - `path_ids[3]` is the `append_block` CALL (a tool-calling response, but taken BEFORE the
      document landed, so its frontier is empty);
    - `path_ids[LEGACY_BRANCH_CALL]` (= 5) is a trailing `bash` CALL, after the document
      landed — the D1 shape with an open frontier, the branch point a caller re-pointed by
      #1255 uses;
    - `path_ids[-1]` is that call's RETURN — a complete pair, the shape `validate` admitted
      before #1255 and refuses after it.

    STAYS SNAPSHOT-LESS (module docstring): every branch from it is N4's after #1255, wherever
    the snapshot is checked (C2: the fork command; the arm launch).

    The `append_block` call carries the DOCUMENT as its `text`, which is what a real append
    that authored this file would have sent: `fence_count_at` reads the appended text, so a
    placeholder there would land a document the store says holds no fences.

    `investigation=None` writes no document (the empty-frontier fixture) and `queries=None`
    writes no table (the no-capture fixture), so each precondition can be failed on its own.
    """
    return _hand_planted_source(tmp_path, investigation=investigation, queries=queries,
                                case_id=case_id, name=name)


def planted_source(
    tmp_path: Path, *, investigation: str | None, queries: str | None = CAPTURED_QUERY_ROW,
    case_id: str = "case-source", name: str = "run-source-001",
):
    """A hand-planted source an arm is meant to be ADMITTED from — `legal_source`'s exact shape
    (same rows, same `path_ids` indexes, same files), but NOT the N4 fixture.

    For the suites that need a source whose prefix they write row by row (state a driven run
    cannot reach, e.g. a lead's rows with no claim for it: `test_1235_run_state_e2e`,
    `test_repeat_breaker_807`). After #1255 an arm forks only a source with a fork snapshot,
    so the implementer's fixture-only snapshot-planting helper MAY — and, for those suites to
    run, must — snapshot this source at its branch points. That helper builds test inputs; it
    is not evidence the driver records snapshots, and no `test_1255_snapshot_*` module imports
    this builder or the helper (they observe snapshots only through driven runs).
    `legal_source` stays snapshot-less: it is N4's fixture and never the helper's input.

    Snapshotted here, as of the files this builder planted, for every tool-calling response
    (`_fork_snapshot_plant`, #1255 deferred verification 4)."""
    from defender.tests.support.runtime.state._fork_snapshot_plant import plant_fork_snapshots

    planted = _hand_planted_source(tmp_path, investigation=investigation, queries=queries,
                                   case_id=case_id, name=name)
    store, run_dir, session_id, _path_ids = planted
    plant_fork_snapshots(store, session_id, run_dir)
    return planted


def _hand_planted_source(tmp_path: Path, *, investigation: str | None, queries: str | None,
                         case_id: str, name: str):
    """The one body `legal_source` and `planted_source` share (see each for what it is).

    It plants NO fork snapshot, and it never may: a snapshot planted here would land on
    `legal_source` too and dissolve N4. Snapshot planting belongs on `planted_source`'s own
    layer (the implementer's fixture-only helper, applied to what this returns), never here."""
    ss = store_mod()
    store = make_store(tmp_path, case_id=case_id)
    run_dir = runs_base(tmp_path) / name
    run_dir.mkdir(parents=True, exist_ok=True)
    ss.write_case_pointer(_run_handle_1165(run_dir), case_id=case_id, store_path=store.path)
    plant_alert(run_dir, ALERT_DOC.encode("utf-8"))
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request("investigate the alert"), *complete_pair()],
                 agent_id="main")
    store.append(session_id, [tool_call_response("append_block", {"text": investigation or ""},
                                                 tool_call_id="ab1")], agent_id="main")
    store.append(session_id, [tool_return_request("append_block", "ok", tool_call_id="ab1")],
                 agent_id="main")
    # A trailing pathless, always-granted call AFTER the document landed: the D1 branch point
    # (#1255) of this source, whose prefix holds the document. Behaviour-neutral before #1255:
    # it appends no fence and its return closes the pair.
    store.append(session_id, [tool_call_response("bash", {"command": "echo held"},
                                                 tool_call_id="b1")], agent_id="main")
    store.append(session_id, [tool_return_request("bash", "held", tool_call_id="b1")],
                 agent_id="main")
    if investigation is not None:
        (run_dir / "investigation.md").write_text(investigation, encoding="utf-8")
    if queries is not None:
        (run_dir / "executed_queries.jsonl").write_text(queries, encoding="utf-8")
    path_ids = ss.path_row_ids(store, session_id)
    assert len(path_ids) == LEGACY_BRANCH_CALL + 2, path_ids
    return store, run_dir, session_id, path_ids


#: `legal_source`'s path index of its trailing `bash` CALL — the D1 branch point taken after the
#: document landed (see `legal_source`).
LEGACY_BRANCH_CALL = 5
