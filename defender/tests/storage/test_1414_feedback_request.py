"""#1414 F1: a run's end queues an open-issue request when the tenant's feedback setting lists its outcome.
"""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from defender import run as run_py
from defender.box import _scrub as scrub_mod
from defender.records import RunPaths, run_end
from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of, set_state_dir
from defender.tests.support.sandbox._spec791 import (
    SpecTail,
    author_markers,
    drive_tail,
    loop_paths,
    make_run_dir,
    plant_alert,
    satisfy_entrypoint_keys,
)
from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, set_up_tenant

HELD_OUT_ALERT = json.dumps({"rule": {"id": "9999"}, "held": "out"}).encode("utf-8")
#: Every outcome word of the setting's vocabulary (design: "Outcome vocabulary for the setting").
VOCABULARY = ["benign", "malicious", "inconclusive", "unresolved", "aborted", "provider-rejected",
              "unreadable"]
LOOKUP = {"actor": "svc-backup", "host": "db-07.prod", "pattern": "pg_dump --all as root"}


@pytest.fixture
def tenant(tmp_path, monkeypatch):
    """The run end's tenant (`set_up_tenant`, as test_791's `state`), its learning root made."""
    set_state_dir(monkeypatch, tmp_path / "legacy-state")
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    accepted = set_up_tenant(current_data_root())
    location_path(accepted.learning).mkdir(exist_ok=True)
    return accepted


@pytest.fixture
def state(tmp_path, tenant):
    return replace(loop_paths(tmp_path), state_dir=location_path(tenant.learning))


def _set(tenant, outcomes: list[str] | None) -> None:
    path = Path(location_path(tenant.settings)) / S.SETTING_FILE
    if outcomes is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(S.setting_text(outcomes), encoding="utf-8")


def _run(name: str, *, disposition: str = "inconclusive", report: str | None = None,
         alert_bytes: bytes | None = None, certify: bool = True) -> Path:
    planted = curation_run_dir(name)
    run_dir = make_run_dir(planted.parent, name=planted.name, disposition=disposition,
                           alert_bytes=alert_bytes)
    if report is not None:
        (run_dir / "report.md").write_text(report, encoding="utf-8")
    if certify:
        scrub_mod.scrub(run_dir)
    return run_dir


def _accepted(run_dir: Path):
    from defender import _paths
    from defender.tenancy import _tenant

    run = run_of(run_dir)
    return run, _tenant.accept_tenant(fixture_data_root(_tenant.resolve_data_root()), run.tenant_id,
                                      defender_dir=_paths.process_defender_dir())


def _enqueue(run_dir: Path, **kw) -> bool:
    run, accepted = _accepted(run_dir)
    return S.enqueue_feedback_issue(run, RunPaths(run_dir).alert, tenant=accepted, **kw)


def _curation(run_dir: Path, **kw) -> bool:
    from defender import run_common

    run, accepted = _accepted(run_dir)
    return run_common.enqueue_curation(run, RunPaths(run_dir).alert, tenant=accepted, **kw)


def _outcomes(state) -> list[str]:
    return sorted(r["outcome"] for r in S.open_issue_requests(state).values())


def test_1414_a_listed_escalated_outcome_opens_an_issue_the_curation_gate_refuses(tenant, state):
    """An `aborted` run listed in the setting queues one request naming the case and the escalated word, where curation refuses it. O1/F1."""
    _set(tenant, ["inconclusive", "aborted"])
    run_dir = _run("f1-aborted")

    assert _enqueue(run_dir, truncated_by="aborted") is True
    assert _curation(run_dir, truncated_by="aborted") is False, "premise: the learning gate refuses a truncation"

    [request] = S.open_issue_requests(state).values()
    assert request["outcome"] == "aborted"
    assert request["run_id"] == str(run_of(run_dir).id)
    assert request["tenant_id"] == str(tenant.id)
    assert author_markers(state) == []


def test_1414_only_listed_outcomes_open_an_issue(tenant, state):
    """A disposition the setting does not list queues nothing; one it lists does (positive control on the same channel). O1."""
    _set(tenant, ["inconclusive"])
    assert _enqueue(_run("f1-benign", disposition="benign")) is False
    assert S.open_issue_requests(state) == {}

    assert _enqueue(_run("f1-inconclusive", disposition="inconclusive")) is True
    assert _outcomes(state) == ["inconclusive"]


def test_1414_a_forced_close_with_a_verdict_opens_on_its_disposition(tenant, state):
    """A forced-close truncation that reached a verdict is its disposition, and is not refused as truncated. O1/F1 (C18)."""
    _set(tenant, ["inconclusive"])

    assert _enqueue(_run("f1-forced"), truncated_by="request-limit") is True
    assert _outcomes(state) == ["inconclusive"]


def test_1414_an_unparsable_report_is_the_unreadable_outcome(tenant, state):
    """A report the ticket cannot parse is outcome `unreadable`, never its planted disposition. O1."""
    _set(tenant, ["unreadable"])
    run_dir = _run("f1-unreadable", report="this is no report\n")

    assert _enqueue(run_dir) is True
    assert _outcomes(state) == ["unreadable"]


def test_1414_the_outcome_function_is_the_tickets(tenant, state):
    """One function names a run's outcome: the escalated word unless closed before the cut, else the disposition, else `unreadable`. O1 (C2, C21)."""
    run, _ = _accepted(_run("f1-words", disposition="malicious"))
    unreadable, _ = _accepted(_run("f1-words-unreadable", report="no frontmatter\n"))

    assert S.run_outcome(run, truncated_by="provider-rejected", closed_before_cut=False) == "provider-rejected"
    assert S.run_outcome(run, truncated_by="aborted", closed_before_cut=True) == "malicious"
    assert S.run_outcome(run, truncated_by=None, closed_before_cut=False) == "malicious"
    assert S.run_outcome(unreadable, truncated_by=None, closed_before_cut=False) == "unreadable"


@pytest.mark.parametrize("truncated_by", sorted(run_end.SILENT_EXITS))
def test_1414_a_silent_exit_opens_no_issue(tenant, state, truncated_by):
    """A run cut short silently (every member of the silent exits) opens nothing, whatever the setting lists. O1."""
    _set(tenant, VOCABULARY)

    assert _enqueue(_run(f"f1-silent-{truncated_by}"), truncated_by=truncated_by) is False
    assert S.open_issue_requests(state) == {}


def test_1414_an_absent_or_unknown_setting_opens_nothing(tenant, state):
    """No setting opens nothing (#1390 P4); a setting naming an unknown outcome is refused at run end and by `tenant check`. O1."""
    run_dir = _run("f1-setting")
    _set(tenant, None)
    assert _enqueue(run_dir) is False

    _set(tenant, ["inconclusive", "escalated"])
    assert _enqueue(run_dir) is False
    assert S.open_issue_requests(state) == {}
    found = S.feedback_setting_findings(Path(location_path(tenant.knowledge)))
    assert any("escalated" in f for f in found), found

    _set(tenant, ["inconclusive"])
    assert S.feedback_setting_findings(Path(location_path(tenant.knowledge))) == []
    assert _enqueue(run_dir) is True, "positive control: the same run with a valid setting opens one"


def test_1414_held_out_and_unverified_runs_open_nothing(tmp_path, tenant, state):
    """F1's predicate refuses a held-out fixture copy and an unverified box tree, and admits an ordinary run. F1."""
    _set(tenant, ["inconclusive"])
    fixtures = tmp_path / "held-out"
    (fixtures / "m01").mkdir(parents=True)
    (fixtures / "m01" / "alert.json").write_bytes(HELD_OUT_ALERT)

    assert _enqueue(_run("f1-held", alert_bytes=HELD_OUT_ALERT), fixtures_dir=fixtures) is False
    assert _enqueue(_run("f1-unverified", certify=False), fixtures_dir=fixtures) is False
    assert S.open_issue_requests(state) == {}
    assert _enqueue(_run("f1-ordinary"), fixtures_dir=fixtures) is True


def _row(lead: str, seq: int, params: dict, *, exit_code: int = 0, system: str = "tacit-knowledge",
         verb: str = "lookup") -> dict:
    from defender.investigation.record_query import QUERY_ROW_COLUMNS

    row = dict.fromkeys(QUERY_ROW_COLUMNS)
    row.update(lead_id=lead, seq=seq, system=system, verb=verb, query_id=f"q-{lead}-{seq}",
               params=params, exit_code=exit_code)
    return row


def test_1414_the_request_carries_the_successful_lookups_from_the_runs_memory(tenant, state):
    """The request's lookups are the run state's successful string-valued registry lookups, de-duplicated across leads; refused, non-string and other calls are not. F1/P3 (C17, C23)."""
    from defender.investigation.run_state import RunState

    _set(tenant, ["inconclusive"])
    run_dir = _run("f1-lookups")
    other = {"actor": "svc-backup", "host": "db-03.prod", "pattern": LOOKUP["pattern"]}
    run_state = RunState(run_dir, str(run_of(run_dir).id))
    run_state.rows.update({
        "l-001": [_row("l-001", 0, LOOKUP), _row("l-001", 1, other, exit_code=2)],
        "l-002": [_row("l-002", 0, dict(LOOKUP)),
                  _row("l-002", 1, {"actor": ["svc-backup"], "host": "db-07.prod", "pattern": "x"}),
                  _row("l-002", 2, LOOKUP, system="cmdb", verb="get-host")],
    })
    # The box-writable run folder says otherwise: it is never read for this (C16).
    (run_dir / "executed_queries.jsonl").write_text(json.dumps(_row("l-009", 0, other)) + "\n",
                                                    encoding="utf-8")

    assert S.captured_lookups(run_state) == [LOOKUP]
    assert _enqueue(run_dir, run_state=run_state) is True
    [request] = S.open_issue_requests(state).values()
    assert request["lookups"] == [LOOKUP]


def test_1414_run_end_queues_the_request_beside_curation(tmp_path, tenant, state):
    """The real entry point queues the request for an escalated run, which files no curation; `--no-learn` queues neither. F1."""
    _set(tenant, ["aborted"])
    suppressed = SpecTail(state, truncated_by="aborted")
    assert drive_tail(run_py.main, plant_alert(tmp_path / "suppressed"), suppressed, "--no-learn") == 0
    assert S.open_issue_requests(state) == {}

    aborted = SpecTail(state, truncated_by="aborted")
    assert drive_tail(run_py.main, plant_alert(tmp_path / "aborted"), aborted) == 0
    assert _outcomes(state) == ["aborted"]
    assert author_markers(state) == [], "premise: an escalated run feeds no curation"
