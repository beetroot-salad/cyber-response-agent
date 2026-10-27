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

#: The document every legality fixture branches over. Read off the tree, not authored inline: a
#: non-empty frontier needs vertices carrying live `??` cells.
GOLDEN_INVESTIGATION = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd" / "investigation.md"

#: The case input every real run dir holds (`materialize_run` copies it in first). The sibling
#: investigates the same alert, so it crosses over verbatim.
ALERT_DOC = (
    '{"rule": "Adding ssh keys to authorized_keys", "host": "canary-1", '
    '"timestamp": "2026-05-25T15:16:00Z"}\n'
)

#: One captured query, the evidence `validate` refuses a branch without: `payload_status: ok`
#: and a real `query_id`, not a `∅.`-prefixed sentinel.
CAPTURED_QUERY_ROW = (
    '{"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "esql", '
    '"query_id": "elastic.sshd-failed-by-srcip", "params": {}, '
    '"payload_status": "ok"}\n'
)

#: Placeholder `as_of` for the draft spec handed to `branch_point_time` (which reads only the run
#: and the message id); aware UTC so the draft passes the shape check.
DRAFT_MOMENT = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)

#: "Derive T0 from the store". Not `None`: `validate` must refuse `as_of=None`, and reading
#: `None` as "derive" would hand the test of that refusal a valid spec.
DERIVE = object()


def branch_mod():
    """`defender.investigation.branch`, imported per test."""
    return importlib.import_module("defender.investigation.branch")


#: The field #1255 removed from `BranchSpec` (an arm is told nothing on arrival).
RETIRED_PROMPT_FIELD = "continuation_prompt"


def declares_retired_prompt() -> bool:
    """Whether `BranchSpec` still declares `continuation_prompt`. False since #1255 landed: this
    check and `spec_at`'s `prompt` parameter are vestigial and can be removed."""
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
    """A finished source run planted straight into the store (no driver) with no fork snapshot:
    the pre-#1255 shape an arm must refuse."""
    return _hand_planted_source(tmp_path, investigation=investigation, queries=queries,
                                case_id=case_id, name=name)


def planted_source(
    tmp_path: Path, *, investigation: str | None, queries: str | None = CAPTURED_QUERY_ROW,
    case_id: str = "case-source", name: str = "run-source-001",
):
    """`legal_source`'s exact shape (same rows, `path_ids` and files) plus fork snapshots, so an
    arm is admitted from it."""
    from defender.tests.support.runtime.state._fork_snapshot_plant import plant_fork_snapshots

    planted = _hand_planted_source(tmp_path, investigation=investigation, queries=queries,
                                   case_id=case_id, name=name)
    store, run_dir, session_id, _path_ids = planted
    plant_fork_snapshots(store, session_id, run_dir)
    return planted


def _hand_planted_source(tmp_path: Path, *, investigation: str | None, queries: str | None,
                         case_id: str, name: str):
    """The body `legal_source` and `planted_source` share. It must plant no fork snapshot: one
    here would land on `legal_source` too and void the no-snapshot refusal test."""
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
    # A trailing pathless, always-granted call after the document landed: this source's branch
    # point (#1255 D1), whose prefix holds the document.
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


#: Path index of the planted source's trailing `bash` call, its branch point.
LEGACY_BRANCH_CALL = 5
