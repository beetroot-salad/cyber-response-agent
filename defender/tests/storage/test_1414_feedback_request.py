"""#1414 F1/O1: a run's end queues an open-issue request when the run's own feedback setting lists its outcome.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from defender import run as run_py
from defender.box import _scrub as scrub_mod
from defender.records import RunPaths, run_end
from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of, set_state_dir
from defender.tests.support.sandbox._spec791 import (
    author_markers,
    drive_tail,
    loop_paths,
    make_run_dir,
    plant_alert,
    satisfy_entrypoint_keys,
)
from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, set_up_tenant
from defender.tests.support.storage import _feedback1414 as F
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

HELD_OUT_ALERT = json.dumps({"rule": {"id": "9999"}, "held": "out"}).encode("utf-8")
LOOKUP, LOOKUP_2 = S.LOOKUP, S.LOOKUP_2
OTHER = {"actor": "svc-backup", "host": "db-03.prod", "pattern": LOOKUP["pattern"]}
FORCED_CLOSE = sorted(run_end.FORCED_CLOSE_EXITS)


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


def _drive(tmp_path, state, tag: str, *args: str, **tail_kw) -> F.FeedbackTail:
    """Drive the real entry over one alert (the same bytes every time: one case) with the tail `tail_kw` describes."""
    tail = F.FeedbackTail(state, **tail_kw)
    drive_tail(run_py.main, plant_alert(tmp_path / tag), tail, *args)
    return tail


def _outcomes(state) -> list[str]:
    return sorted(r["outcome"] for r in S.open_issue_requests(state).values())


def _run_id(tail: F.FeedbackTail) -> str:
    return str(run_of(tail.run_dirs[-1]).id)


# ---------------------------------------------------------------- the outcome, through the real entry

@pytest.mark.parametrize("outcome", F.VOCABULARY)
def test_1414_every_outcome_word_opens_exactly_when_listed(tmp_path, tenant, state, outcome):
    """Each word of the vocabulary, listed, queues one request naming the case, run and word; unlisted it queues none. O1/A5."""
    _set(tenant, [w for w in F.VOCABULARY if w != outcome])
    _drive(tmp_path, state, "unlisted", plan=F.plan_for(outcome))
    assert S.open_issue_requests(state) == {}

    _set(tenant, [outcome])
    tail = _drive(tmp_path, state, "listed", plan=F.plan_for(outcome))
    [request] = S.open_issue_requests(state).values()
    assert (request["outcome"], request["run_id"], request["tenant_id"]) == (
        outcome, _run_id(tail), str(tenant.id))
    assert request["case_id"]


def test_1414_an_escalated_run_files_no_curation_but_a_disposition_run_does(tmp_path, tenant, state):
    """The request is beside curation, not through its gate: an escalated run feeds no corpus. O1/F1 (C18)."""
    _set(tenant, ["aborted", "benign"])
    _drive(tmp_path, state, "esc", plan=F.plan_for("aborted"))
    assert _outcomes(state) == ["aborted"]
    assert author_markers(state) == []

    _drive(tmp_path, state, "disp", plan=F.plan_for("benign"))
    assert author_markers(state), "control: curation fires for the disposition run"


@pytest.mark.parametrize("exit_class", FORCED_CLOSE)
def test_1414_a_forced_close_is_its_disposition_or_unreadable(tmp_path, tenant, state, exit_class):
    """A forced close with a readable report is its disposition; with an unparsable one it is `unreadable`. O1/A5 (C21)."""
    _set(tenant, ["unresolved", "unreadable"])
    _drive(tmp_path, state, "read", plan=F.Plan(exit_class, "unresolved"))
    assert _outcomes(state) == ["unresolved"]

    _drive(tmp_path, state, "unread", plan=F.Plan(exit_class, "unresolved", F.UNPARSABLE))
    assert _outcomes(state) == ["unreadable"], "the same case's later run replaced the earlier request"


@pytest.mark.parametrize("exit_class", sorted(run_end.SILENT_EXITS))
def test_1414_a_silent_exit_opens_no_issue(tmp_path, tenant, state, exit_class):
    """A run cut short silently opens nothing, whatever the setting lists; an ordinary run under the same setting does. O1."""
    _set(tenant, F.VOCABULARY)
    _drive(tmp_path, state, "silent", plan=F.Plan(exit_class, "inconclusive"))
    assert S.open_issue_requests(state) == {}

    _drive(tmp_path, state, "ordinary")
    assert _outcomes(state) == ["inconclusive"]


@pytest.mark.parametrize("exit_class", sorted(run_end.SILENT_EXITS))
def test_1414_a_silent_exit_after_a_verdict_opens_with_the_disposition(tmp_path, tenant, state, exit_class):
    """A silent cut after the run reached its verdict opens, with the disposition as outcome, as the case ticket comments on it. O1/A8."""
    _set(tenant, F.VOCABULARY)
    tail = _drive(tmp_path, state, "verdict", plan=F.Plan(exit_class, "benign"), closed_before_cut=True)

    [request] = S.open_issue_requests(state).values()
    assert (request["outcome"], request["run_id"]) == ("benign", _run_id(tail))


def test_1414_runs_whose_post_steps_never_run_open_nothing(tmp_path, tenant, state):
    """An exception out of the lifecycle and a box whose teardown faulted skip F1; the ordinary run does not. O1 (C22)."""
    _set(tenant, F.VOCABULARY)
    with pytest.raises(RuntimeError):
        _drive(tmp_path, state, "raised", raises=RuntimeError("the lifecycle broke"))
    _drive(tmp_path, state, "faulted", plan=F.plan_for("aborted"), teardown_faulted=True)
    assert S.open_issue_requests(state) == {}

    _drive(tmp_path, state, "ordinary")
    assert _outcomes(state) == ["inconclusive"]


def test_1414_no_learn_and_an_unverified_tree_open_nothing(tmp_path, tenant, state):
    """`--no-learn` and a tree with no scan verdict queue nothing; the same run without either queues one. F1."""
    _set(tenant, ["aborted"])
    _drive(tmp_path, state, "nolearn", "--no-learn", plan=F.plan_for("aborted"))
    _drive(tmp_path, state, "unverified", plan=F.plan_for("aborted"), certify=False)
    assert S.open_issue_requests(state) == {}

    _drive(tmp_path, state, "ordinary", plan=F.plan_for("aborted"))
    assert _outcomes(state) == ["aborted"]


def test_1414_a_later_run_of_the_case_replaces_the_earlier_request(tmp_path, tenant, state):
    """Two runs of one case leave one request, the later run's with its outcome. O1 (C3)."""
    _set(tenant, ["aborted", "benign"])
    first = _drive(tmp_path, state, "first", plan=F.plan_for("aborted"))
    assert _outcomes(state) == ["aborted"]
    second = _drive(tmp_path, state, "second", plan=F.plan_for("benign"))

    [request] = S.open_issue_requests(state).values()
    assert (request["outcome"], request["run_id"]) == ("benign", _run_id(second))
    assert _run_id(first) != _run_id(second)


def test_1414_a_later_run_whose_outcome_is_not_listed_leaves_the_earlier_request(tmp_path, tenant, state):
    """The case's later run ending in an unlisted outcome does not replace or remove the earlier queued request. O1/A8."""
    _set(tenant, ["aborted"])
    first = _drive(tmp_path, state, "first", plan=F.plan_for("aborted"))
    _drive(tmp_path, state, "second", plan=F.plan_for("benign"))

    [request] = S.open_issue_requests(state).values()
    assert (request["outcome"], request["run_id"]) == ("aborted", _run_id(first))


# ---------------------------------------------------------------- the setting: absent, unknown, the run's copy

def test_1414_an_absent_setting_opens_nothing(tmp_path, tenant, state):
    """No `settings/feedback.yaml` opens nothing (#1390 P4); with one listing the outcome, the same run opens. O1."""
    _set(tenant, None)
    _drive(tmp_path, state, "absent", plan=F.plan_for("aborted"))
    assert S.open_issue_requests(state) == {}

    _set(tenant, ["aborted"])
    _drive(tmp_path, state, "listed", plan=F.plan_for("aborted"))
    assert _outcomes(state) == ["aborted"]


@pytest.mark.parametrize("word", F.REFUSED_WORDS)
def test_1414_a_setting_with_an_unknown_word_is_refused_at_run_end(tmp_path, tenant, state, word):
    """A setting naming any word outside the vocabulary opens nothing, not even for its valid entries. O1."""
    _set(tenant, ["aborted", word])
    _drive(tmp_path, state, "unknown", plan=F.plan_for("aborted"))
    assert S.open_issue_requests(state) == {}


def _tenant_folder(tmp_path: Path, outcomes: list[str] | None) -> Path:
    folder = tmp_path / "tenant"
    shutil.copytree(H.FIXTURE, folder, symlinks=True)
    H.write_tenant_id_file(folder, H.TID, None)
    shutil.rmtree(folder / "settings" / "systems" / "case-history", ignore_errors=True)
    if outcomes is not None:
        (folder / "settings" / S.SETTING_FILE).write_text(S.setting_text(outcomes), encoding="utf-8")
    return folder


def test_1414_tenant_check_passes_the_whole_vocabulary_and_no_setting(tmp_path):
    """`tenant check --folder` is clean for a setting listing every word, and for none at all. O1."""
    from defender.cli import tenant as tenant_py

    H.assert_clean(H.check(tenant_py, None, "--folder", str(_tenant_folder(tmp_path / "all", F.VOCABULARY))))
    H.assert_clean(H.check(tenant_py, None, "--folder", str(_tenant_folder(tmp_path / "none", None))))


@pytest.mark.parametrize("word", F.REFUSED_WORDS)
def test_1414_tenant_check_refuses_an_unknown_word_naming_it(tmp_path, word):
    """`tenant check --folder` refuses a setting with an unknown word, naming the file and the word. O1."""
    from defender.cli import tenant as tenant_py

    folder = _tenant_folder(tmp_path, ["benign", word])
    H.assert_refused(H.check(tenant_py, None, "--folder", str(folder)), S.SETTING_FILE, word)


@pytest.mark.parametrize(("before", "edit", "opens"), [
    (["aborted"], ["benign"], True),
    (["benign"], ["aborted"], False),
])
def test_1414_the_setting_is_read_from_the_runs_copy_not_the_working_tree(
        tmp_path, tenant, state, before, edit, opens):
    """An edit to the clone's setting after the run's copy was taken changes nothing; the run's copy decides. O1/A5."""
    _set(tenant, before)
    tail = _drive(tmp_path, state, "edited", plan=F.plan_for("aborted"), mid_run=lambda: _set(tenant, edit))

    assert tail.copy_text == S.setting_text(before), "premise: the run's copy holds the pre-launch setting"
    assert (Path(location_path(tenant.settings)) / S.SETTING_FILE).read_text(encoding="utf-8") == S.setting_text(edit)
    assert _outcomes(state) == (["aborted"] if opens else [])


# ---------------------------------------------------------------- the outcome function

def _planned_run(name: str, outcome: str):
    plan = F.plan_for(outcome)
    planted = curation_run_dir(name)
    run_dir = make_run_dir(planted.parent, name=planted.name, disposition=plan.disposition)
    if plan.report is not None:
        (run_dir / "report.md").write_text(plan.report, encoding="utf-8")
    scrub_mod.scrub(run_dir)
    return run_of(run_dir)


@pytest.mark.parametrize("outcome", F.VOCABULARY)
def test_1414_the_outcome_function_names_every_vocabulary_word(outcome):
    """The shared function maps each way a run can end to its word. O1/A5 (C2, C21)."""
    plan = F.plan_for(outcome)
    run = _planned_run(f"outcome-{outcome}", outcome)
    assert S.run_outcome(run, truncated_by=plan.truncated_by, closed_before_cut=False) == outcome


def test_1414_the_outcome_function_prefers_a_verdict_to_an_exit(tmp_path):
    """A verdict reached before the cut is its disposition, whatever the exit class. O1."""
    run = _planned_run("outcome-verdict", "malicious")
    for exit_class in (*sorted(run_end.ESCALATED_EXITS), *FORCED_CLOSE):
        assert S.run_outcome(run, truncated_by=exit_class, closed_before_cut=True) == "malicious"
        if exit_class in FORCED_CLOSE:
            assert S.run_outcome(run, truncated_by=exit_class, closed_before_cut=False) == "malicious"
    unreadable = _planned_run("outcome-verdict-unreadable", "unreadable")
    for exit_class in FORCED_CLOSE:
        assert S.run_outcome(unreadable, truncated_by=exit_class, closed_before_cut=False) == "unreadable"


# ---------------------------------------------------------------- captured lookups

def _state(rows: dict[str, list[dict]]):
    from defender.investigation.run_state import RunState

    run_state = RunState(Path("/run/lookups"), "r-lookups")
    run_state.rows.update(rows)
    return run_state


_BAD_ROWS = {
    "refused": F.lookup_row("l-1", 1, OTHER, exit_code=2),
    "config fault": F.lookup_row("l-1", 1, OTHER, exit_code=3),
    "another system": F.lookup_row("l-1", 1, OTHER, system="cmdb"),
    "another verb": F.lookup_row("l-1", 1, OTHER, verb="list"),
    "no pattern": F.lookup_row("l-1", 1, {"actor": "a", "host": "h"}),
    **{f"{field} a {name}": F.lookup_row("l-1", 1, {**OTHER, field: value})
       for field in ("actor", "host", "pattern")
       for name, value in (("list", ["x"]), ("number", 7), ("null", None), ("map", {"a": 1}), ("bool", True))},
}


@pytest.mark.parametrize("why", sorted(_BAD_ROWS))
def test_1414_only_successful_string_lookups_are_captured(why):
    """A refused, foreign or non-string call is not captured; the good lookup beside it is. P3 (C17, C23)."""
    run_state = _state({"l-1": [F.lookup_row("l-1", 0, LOOKUP), _BAD_ROWS[why]]})
    assert S.captured_lookups(run_state) == [LOOKUP]


def test_1414_captured_lookups_are_deduplicated_across_leads():
    """One lookup made by two leads, twice by one, is captured once. P3."""
    run_state = _state({
        "l-1": [F.lookup_row("l-1", 0, LOOKUP), F.lookup_row("l-1", 1, dict(LOOKUP)),
                F.lookup_row("l-1", 2, LOOKUP_2)],
        "l-2": [F.lookup_row("l-2", 0, dict(LOOKUP_2)), F.lookup_row("l-2", 1, dict(LOOKUP))]})
    assert sorted(S.captured_lookups(run_state), key=json.dumps) == sorted([LOOKUP, LOOKUP_2], key=json.dumps)


def test_1414_the_request_carries_the_lookups_from_the_runs_memory_not_the_box_file(tmp_path, tenant, state):
    """Through `run.main` the request's lookups are the run state's, not the box-writable queries file's. F1/P3 (C16, C17)."""
    _set(tenant, ["aborted"])
    rows = {"l-001": [F.lookup_row("l-001", 0, LOOKUP), F.lookup_row("l-001", 1, OTHER, exit_code=2)],
            "l-002": [F.lookup_row("l-002", 0, dict(LOOKUP_2))]}
    tail = _drive(tmp_path, state, "lookups", plan=F.plan_for("aborted"), rows=rows,
                  box_planted=F.box_row(F.lookup_row("l-009", 0, OTHER)))

    assert tail.run_state is not None, "run.py handed the lifecycle no RunState to carry the run's calls"
    assert (tail.run_state.run_dir, tail.run_state.run_id) == (tail.run_dirs[-1], _run_id(tail))
    [request] = S.open_issue_requests(state).values()
    assert sorted(request["lookups"], key=json.dumps) == sorted([LOOKUP, LOOKUP_2], key=json.dumps)


def test_1414_the_run_state_run_py_hands_the_enqueue_is_the_one_the_investigation_receives(tmp_path, tenant, state):
    """Through production's lifecycle, the state the investigation is handed is the one the enqueue reads: rows the investigation leaves in it reach the request. F1/P3 (C17)."""
    from defender.investigation.run_state import RunState

    _set(tenant, ["aborted"])
    plan = F.plan_for("aborted")
    handed: list[RunState] = []

    def investigate(**kw):
        given = next((v for v in kw.values() if isinstance(v, RunState)), None)
        assert given is not None, "production's lifecycle handed the investigation no RunState"
        handed.append(given)
        given.rows.update({"l-001": [F.lookup_row("l-001", 0, LOOKUP)]})
        return {"output": "feedback1414", "requests": 1, "truncated_by": plan.truncated_by, "closed_before_cut": False}

    tail = _drive(tmp_path, state, "threaded", plan=plan, investigate=investigate)

    assert len(handed) == 1, "the investigation was not handed a RunState"
    assert handed[0] is tail.run_state
    [request] = S.open_issue_requests(state).values()
    assert request["lookups"] == [LOOKUP]


# ---------------------------------------------------------------- the predicate, called directly

def _certified_run(name: str, *, certify: bool = True, alert_bytes: bytes | None = None) -> Path:
    planted = curation_run_dir(name)
    run_dir = make_run_dir(planted.parent, name=planted.name, disposition="inconclusive", alert_bytes=alert_bytes)
    if certify:
        scrub_mod.scrub(run_dir)
    return run_dir


def _enqueue(tmp_path, tenant, run_dir: Path, **kw) -> bool:
    """`enqueue_feedback_issue` over the run's tenant: a `RunTenant` whose settings are a separate copy of the clone's."""
    from defender import _paths
    from defender.tenancy import _tenant

    run = run_of(run_dir)
    accepted = _tenant.accept_tenant(fixture_data_root(_tenant.resolve_data_root()), run.tenant_id,
                                     defender_dir=_paths.process_defender_dir())
    copy = tmp_path / "settings-copy"
    shutil.rmtree(copy, ignore_errors=True)
    shutil.copytree(location_path(tenant.settings), copy)
    return S.enqueue_feedback_issue(run, RunPaths(run_dir).alert,
                                    tenant=T1106.run_tenant(accepted, settings_root=copy), **kw)


def test_1414_a_held_out_copy_and_an_unverified_tree_open_nothing(tmp_path, tenant, state):
    """F1's predicate refuses a held-out alert copy and an unverified tree, and admits an ordinary run. F1."""
    _set(tenant, ["inconclusive"])
    fixtures = tmp_path / "held-out"
    (fixtures / "m01").mkdir(parents=True)
    (fixtures / "m01" / "alert.json").write_bytes(HELD_OUT_ALERT)

    held = _certified_run("f1-held", alert_bytes=HELD_OUT_ALERT)
    assert _enqueue(tmp_path, tenant, held, fixtures_dir=fixtures) is False
    assert _enqueue(tmp_path, tenant, _certified_run("f1-unverified", certify=False), fixtures_dir=fixtures) is False
    assert S.open_issue_requests(state) == {}
    assert _enqueue(tmp_path, tenant, _certified_run("f1-ordinary"), fixtures_dir=fixtures) is True
