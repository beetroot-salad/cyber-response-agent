"""Shared machinery for the #947 turn-N foundations spec — NO test scripts."""
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
    """The `BranchSpec` this branch point admits, T0 included."""
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
    directly, no driver."""
    return _hand_planted_source(tmp_path, investigation=investigation, queries=queries,
                                case_id=case_id, name=name)


def planted_source(
    tmp_path: Path, *, investigation: str | None, queries: str | None = CAPTURED_QUERY_ROW,
    case_id: str = "case-source", name: str = "run-source-001",
):
    """A hand-planted source an arm is meant to be ADMITTED from — `legal_source`'s exact shape
    (same rows, same `path_ids` indexes, same files), but NOT the N4 fixture."""
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
    from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape

    run_id = name if is_fixture_uuid_shape(name) else fixture_uuid(name)
    run_dir = runs_base(tmp_path) / run_id
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
