"""#1414 F1/O1: a run's end queues an open-issue request when the run's own feedback setting lists its outcome.
"""
from __future__ import annotations

import functools
import json
import os
import random
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from defender import run as run_py
from defender import run_common
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
from defender.tests.support.sandbox._curation_store1278 import reach_store
from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, set_up_tenant
from defender.tests.support.storage import _feedback1414 as F
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

HELD_OUT_ALERT = json.dumps({"rule": {"id": "9999"}, "held": "out"}).encode("utf-8")
LOOKUP, LOOKUP_2 = S.LOOKUP, S.LOOKUP_2
OTHER = {"actor": "svc-backup", "host": "db-03.prod", "pattern": LOOKUP["pattern"]}
FORCED_CLOSE = sorted(run_end.FORCED_CLOSE_EXITS)


pytestmark = pytest.mark.postgres


@pytest.fixture
def tenant(tmp_path, monkeypatch, migrated_database):  # noqa: F811 — the imported fixture
    """The run end's tenant (`set_up_tenant`, as test_791's `state`), active in the database the run end files into
    (A4: the request is a `feedback_issues` row; D10: the tenant has no `learning` folder)."""
    set_state_dir(monkeypatch, tmp_path / "legacy-state")
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    accepted = set_up_tenant(current_data_root())
    reach_store(migrated_database, monkeypatch, accepted)
    return accepted


@pytest.fixture
def state(tmp_path, tenant):
    from defender.learning.core.config import LoopPaths

    return replace(LoopPaths.for_tenant(tenant), repo_root=loop_paths(tmp_path).repo_root)


def _requests(paths) -> dict[str, dict]:
    """The tenant's requests with no issue yet (`feedback_issues` rows), by run id: the store, not a queue folder."""
    import os

    tid = str(paths.tenant.id)
    rows = S.store_call(os.environ["DEFENDER_DATABASE_DSN"], "feedback_issues", tid)
    return {r.run_id: {"tenant_id": str(r.tenant_id), "case_id": r.case_id, "run_id": r.run_id,
                       "outcome": r.outcome, "lookups": list(r.lookups)}
            for r in rows if r.issue_number is None}


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
    return sorted(r["outcome"] for r in _requests(state).values())


def _run_id(tail: F.FeedbackTail) -> str:
    return str(run_of(tail.run_dirs[-1]).id)


# ---------------------------------------------------------------- the outcome, through the real entry

@pytest.mark.parametrize("outcome", F.VOCABULARY)
def test_1414_every_outcome_word_opens_exactly_when_listed(tmp_path, tenant, state, outcome):
    """Each word of the vocabulary, listed, queues one request naming the case, run and word; unlisted it queues none. O1/A5."""
    _set(tenant, [w for w in F.VOCABULARY if w != outcome])
    _drive(tmp_path, state, "unlisted", plan=F.plan_for(outcome))
    assert _requests(state) == {}

    _set(tenant, [outcome])
    tail = _drive(tmp_path, state, "listed", plan=F.plan_for(outcome))
    [request] = _requests(state).values()
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
    """A forced close with a readable report is its disposition; with an unparsable one it is `unreadable`. O1/A5 (C21).
    One request per run: each run's request carries its own outcome, found by run id."""
    _set(tenant, ["unresolved", "unreadable"])
    read = _drive(tmp_path, state, "read", plan=F.Plan(exit_class, "unresolved"))
    assert _outcomes(state) == ["unresolved"]

    unread = _drive(tmp_path, state, "unread", plan=F.Plan(exit_class, "unresolved", F.UNPARSABLE))
    by_run = {r["run_id"]: r["outcome"] for r in _requests(state).values()}
    assert by_run.get(_run_id(read)) == "unresolved", by_run
    assert by_run.get(_run_id(unread)) == "unreadable", by_run


@pytest.mark.parametrize("exit_class", sorted(run_end.SILENT_EXITS))
def test_1414_a_silent_exit_opens_no_issue(tmp_path, tenant, state, exit_class):
    """A run cut short silently opens nothing, whatever the setting lists; an ordinary run under the same setting does. O1."""
    _set(tenant, F.VOCABULARY)
    _drive(tmp_path, state, "silent", plan=F.Plan(exit_class, "inconclusive"))
    assert _requests(state) == {}

    _drive(tmp_path, state, "ordinary")
    assert _outcomes(state) == ["inconclusive"]


@pytest.mark.parametrize("exit_class", sorted(run_end.SILENT_EXITS))
def test_1414_a_silent_exit_after_a_verdict_opens_with_the_disposition(tmp_path, tenant, state, exit_class):
    """A silent cut after the run reached its verdict opens, with the disposition as outcome, as the case ticket comments on it. O1/A8."""
    _set(tenant, F.VOCABULARY)
    tail = _drive(tmp_path, state, "verdict", plan=F.Plan(exit_class, "benign"), closed_before_cut=True)

    [request] = _requests(state).values()
    assert (request["outcome"], request["run_id"]) == ("benign", _run_id(tail))


def test_1414_runs_whose_post_steps_never_run_open_nothing(tmp_path, tenant, state):
    """An exception out of the lifecycle and a box whose teardown faulted skip F1; the ordinary run does not. O1 (C22)."""
    _set(tenant, F.VOCABULARY)
    with pytest.raises(RuntimeError):
        _drive(tmp_path, state, "raised", raises=RuntimeError("the lifecycle broke"))
    _drive(tmp_path, state, "faulted", plan=F.plan_for("aborted"), teardown_faulted=True)
    assert _requests(state) == {}

    _drive(tmp_path, state, "ordinary")
    assert _outcomes(state) == ["inconclusive"]


def test_1414_no_learn_and_an_unverified_tree_open_nothing(tmp_path, tenant, state):
    """`--no-learn` and a tree with no scan verdict queue nothing; the same run without either queues one. F1."""
    _set(tenant, ["aborted"])
    _drive(tmp_path, state, "nolearn", "--no-learn", plan=F.plan_for("aborted"))
    _drive(tmp_path, state, "unverified", plan=F.plan_for("aborted"), certify=False)
    assert _requests(state) == {}

    _drive(tmp_path, state, "ordinary", plan=F.plan_for("aborted"))
    assert _outcomes(state) == ["aborted"]


def test_1414_each_listed_run_of_a_case_queues_its_own_request(tmp_path, tenant, state):
    """Two listed runs of one case leave two requests, each run's with its own outcome: each run gets its own issue. O1/O2
    (ruling 2026-11-09: one issue per run; supersedes C3's later-replaces-earlier for this queue)."""
    _set(tenant, ["aborted", "benign"])
    first = _drive(tmp_path, state, "first", plan=F.plan_for("aborted"))
    assert _outcomes(state) == ["aborted"]
    second = _drive(tmp_path, state, "second", plan=F.plan_for("benign"))

    assert _run_id(first) != _run_id(second)
    assert sorted((r["run_id"], r["outcome"]) for r in _requests(state).values()) == sorted(
        [(_run_id(first), "aborted"), (_run_id(second), "benign")])


def test_1414_a_later_run_whose_outcome_is_not_listed_leaves_the_earlier_request(tmp_path, tenant, state):
    """The case's later run ending in an unlisted outcome does not replace or remove the earlier queued request. O1/A8."""
    _set(tenant, ["aborted"])
    first = _drive(tmp_path, state, "first", plan=F.plan_for("aborted"))
    _drive(tmp_path, state, "second", plan=F.plan_for("benign"))

    [request] = _requests(state).values()
    assert (request["outcome"], request["run_id"]) == ("aborted", _run_id(first))



def test_1414_run_end_files_curation_before_the_feedback_request(tmp_path, tenant, state):
    """Run end's feedback enqueue runs after curation has filed its marker, and the run page follows it. F1."""
    seen = []

    def watching(*_a, **_kw):
        seen.append(bool(author_markers(state)))
        return False

    _set(tenant, ["benign"])
    tail = F.FeedbackTail(state, plan=F.plan_for("benign"))
    assert drive_tail(functools.partial(run_py.main, enqueue_feedback=watching), plant_alert(tmp_path / "w"), tail) == 0
    assert seen == [True], "the feedback enqueue ran before curation filed its marker"
    assert tail.visualized, "control: the run page was drawn"


def test_1414_the_feedback_enqueue_never_raises(tmp_path, caplog):
    """A failure of any kind inside the feedback enqueue is logged and answered False, never raised to run end, where
    it would cost the run its page. F1."""
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    run = make_run_dir(tmp_path, name=fixture_uuid("never-raises"))

    class Broken:
        @property
        def tenant(self):
            raise RuntimeError("the tenant handle broke")

    with caplog.at_level("ERROR"):
        assert run_common.enqueue_feedback_issue(run_of(run), tenant=Broken()) is False
    assert any("the tenant handle broke" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------- F1's flow predicate, through the real entry

def _held_set(tmp_path: Path) -> Path:
    """A held-out fixture set holding one member the digest walk reads (`m01/alert.json`)."""
    fixtures = tmp_path / "held-out"
    (fixtures / "m01").mkdir(parents=True)
    (fixtures / "m01" / "alert.json").write_bytes(HELD_OUT_ALERT)
    return fixtures


def _main_with(fixtures: Path):
    """`run.main` whose feedback enqueue judges the held-out set `fixtures` (the seam `main` exposes)."""
    #: FC: `run.main(enqueue_feedback=...)` is the seam through which run end's feedback enqueue is injected. The test needs
    #: it because the held-out rows judge against a planted `fixtures_dir`, which `main` has no other way to be handed.
    return functools.partial(run_py.main, enqueue_feedback=functools.partial(
        run_common.enqueue_feedback_issue, fixtures_dir=fixtures))


def _drive_main(main, alert: Path, tail: F.FeedbackTail, *args: str) -> None:
    drive_tail(main, alert, tail, *args)


def _drive_sibling(tmp_path, tenant, tail: F.FeedbackTail) -> None:
    """The sibling's door (`--episode <id> --world b`) over a held episode of the run's own tenant."""
    from defender.records._episode_handle import Episode
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv, in_process_publish
    from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as P

    source = P.source_run(Path(location_path(tenant.runs)))
    manifest = P.family_for(source)
    with Episode.open(manifest.parent) as held:
        T.episode_view(held, tenant=tenant).close()
    argv = ["--tenant", str(tenant.id), "--episode", manifest.parent.name, "--world", "b"]
    run_py.main(argv, lifecycle=tail.lifecycle, visualize=tail.visualize, ticket_writer=tail,
                preflight=lambda *a, **k: 0, publish=in_process_publish(), directory=directory_for_argv(argv))


_REFUSED_ENDS = ["sibling world", "--no-learn", "held-out by path", "held-out by digest", "unverified tree"]


@pytest.mark.parametrize("row", _REFUSED_ENDS)
def test_1414_a_run_end_curation_refuses_opens_no_issue_through_the_real_entry(tmp_path, tenant, state, row):
    """A sibling world, `--no-learn`, a held-out alert (by path or by digest) and an unverified tree queue nothing, though the
    setting lists the outcome; the ordinary run beside them queues one. F1 (flow predicate, as curation's refusals)."""
    _set(tenant, ["aborted"])
    fixtures = _held_set(tmp_path)
    main = _main_with(fixtures)
    plan = F.plan_for("aborted")
    refused = F.FeedbackTail(state, plan=plan, certify=row != "unverified tree")
    if row == "sibling world":
        _drive_sibling(tmp_path, tenant, refused)
    elif row == "--no-learn":
        _drive_main(main, plant_alert(tmp_path / "x"), refused, "--no-learn")
    elif row == "held-out by path":
        # inside the set, but not at `<slug>/alert.json`, so the digest walk never reads it: only the path arm refuses
        planted = fixtures / "m02" / "note.json"
        planted.parent.mkdir()
        planted.write_bytes(json.dumps({"rule": {"id": "4242"}}).encode("utf-8"))
        _drive_main(main, planted, refused)
    else:
        held = HELD_OUT_ALERT if row == "held-out by digest" else None
        _drive_main(main, plant_alert(tmp_path / "x", alert_bytes=held), refused)
    assert len(refused.run_dirs) == 1, f"{row}: the run did not reach its end"
    assert _requests(state) == {}, f"{row}: a refused end queued an open-issue request"

    other = {"alert_bytes": json.dumps({"rule": {"id": "5711"}}).encode("utf-8")}
    tail = F.FeedbackTail(state, plan=plan)
    _drive_main(main, plant_alert(tmp_path / "ordinary", **other), tail)
    [request] = _requests(state).values()
    assert (request["outcome"], request["run_id"]) == ("aborted", _run_id(tail)), "control: the live run queues one"


# ---------------------------------------------------------------- the setting: absent, unknown, the run's copy

def test_1414_an_absent_setting_opens_nothing(tmp_path, tenant, state):
    """No `settings/feedback.yaml` opens nothing (#1390 P4); with one listing the outcome, the same run opens. O1."""
    _set(tenant, None)
    _drive(tmp_path, state, "absent", plan=F.plan_for("aborted"))
    assert _requests(state) == {}

    _set(tenant, ["aborted"])
    _drive(tmp_path, state, "listed", plan=F.plan_for("aborted"))
    assert _outcomes(state) == ["aborted"]


@pytest.mark.parametrize("word", F.REFUSED_WORDS)
def test_1414_a_setting_with_an_unknown_word_is_refused_at_run_end(tmp_path, tenant, state, word):
    """A setting naming any word outside the vocabulary opens nothing, not even for its valid entries. O1."""
    _set(tenant, ["aborted", word])
    _drive(tmp_path, state, "unknown", plan=F.plan_for("aborted"))
    assert _requests(state) == {}


def _tenant_folder(tmp_path: Path, outcomes: list[str] | None, *, raw: str | None = None) -> Path:
    folder = tmp_path / "tenant"
    shutil.copytree(H.FIXTURE, folder, symlinks=True)
    H.write_tenant_id_file(folder, H.TID, None)
    shutil.rmtree(folder / "settings" / "systems" / "case-history", ignore_errors=True)
    if outcomes is not None:
        (folder / "settings" / S.SETTING_FILE).write_text(S.setting_text(outcomes), encoding="utf-8")
    if raw is not None:
        (folder / "settings" / S.SETTING_FILE).write_text(raw, encoding="utf-8")
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


#: Settings whose keys cannot stand: a key written twice (the later would silently win) and a key nothing reads (a typo
#: that would silently list nothing). Each names the key the refusal must name.
_BAD_KEYS = {
    "duplicate key": ("open_issue_on:\n  - benign\nopen_issue_on:\n  - aborted\n", "open_issue_on"),
    "unknown key": ("open_issue_on:\n  - aborted\nopen_issues_on:\n  - benign\n", "open_issues_on"),
}


@pytest.mark.parametrize("why", sorted(_BAD_KEYS))
def test_1414_a_setting_with_a_duplicate_or_unknown_key_is_refused_at_run_end(tmp_path, tenant, state, caplog, why):
    """A setting repeating a key or holding one nothing reads opens nothing at run end and is logged as refused, naming the key. O1."""
    import logging

    text, key = _BAD_KEYS[why]
    (Path(location_path(tenant.settings)) / S.SETTING_FILE).write_text(text, encoding="utf-8")
    with caplog.at_level(logging.INFO):
        _drive(tmp_path, state, "bad-keys", plan=F.plan_for("aborted"))
    assert _requests(state) == {}
    refusals = [r.getMessage() for r in caplog.records if "NOT enqueuing" in r.getMessage()]
    assert any(key in line for line in refusals), refusals


@pytest.mark.parametrize("why", sorted(_BAD_KEYS))
def test_1414_tenant_check_refuses_a_duplicate_or_unknown_key_naming_it(tmp_path, why):
    """`tenant check --folder` refuses a setting repeating a key or holding an unread one, naming the file and the key. O1."""
    from defender.cli import tenant as tenant_py

    text, key = _BAD_KEYS[why]
    folder = _tenant_folder(tmp_path, None, raw=text)
    H.assert_refused(H.check(tenant_py, None, "--folder", str(folder)), S.SETTING_FILE, key)


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
    #: A4 change 3: the store cannot hold U+0000, so a lookup holding it is not captured (the run keeps its other lookups).
    **{f"{field} holds NUL": F.lookup_row("l-1", 1, {**OTHER, field: "a\x00b"}) for field in ("actor", "host", "pattern")},
}


@pytest.mark.parametrize("why", sorted(_BAD_ROWS))
def test_1414_only_successful_string_lookups_are_captured(why):
    """A refused, foreign or non-string call is not captured; the good lookup beside it is. P3 (C17, C23)."""
    run_state = _state({"l-1": [F.lookup_row("l-1", 0, LOOKUP), _BAD_ROWS[why]]})
    assert S.captured_lookups(run_state) == [LOOKUP]


@pytest.mark.parametrize("seed", [1414, 7, 20261109])
def test_1414_captured_lookups_are_the_distinct_qualifying_triples_in_first_seen_order(seed):
    """Over generated rows (repeats across and within leads, refused, foreign, non-string and non-UTF-8 calls), the captured list is
    the distinct (actor, host, pattern) triples of the qualifying rows in first-seen order. P3 (C17, C23).

    FC: first-seen order is the order the captured lookups are listed, so the indices the model answers with stay stable.
    FC: a lookup holding text that is not valid UTF-8 (a lone surrogate) is not captured: it could never be sent to Forgejo.
    A4: nor one holding U+0000, which the store cannot hold."""
    rng = random.Random(seed)
    actors, hosts, patterns = ("ann", "svc-backup", "root"), ("db-03", "web-01"), ("rm -rf", "curl x", "id")
    spoilers = [{"exit_code": 2}, {"exit_code": 3}, {"system": "cmdb"}, {"verb": "list"}]
    spoiled_values = [["x"], 7, None, {"a": 1}, True, "\ud800", "ok\udfff", "a\x00b"]
    rows: dict[str, list[dict]] = {}
    expected: list[dict] = []
    for lead in (f"l-{n}" for n in rng.sample(range(1, 9), 4)):
        rows[lead] = []
        for seq in range(rng.randint(3, 9)):
            triple = {"actor": rng.choice(actors), "host": rng.choice(hosts), "pattern": rng.choice(patterns)}
            kw: dict = {}
            kind = rng.random()
            if kind < 0.2:
                kw = rng.choice(spoilers)
            elif kind < 0.3:
                triple[rng.choice(sorted(triple))] = rng.choice(spoiled_values)
            elif kind < 0.35:
                del triple[rng.choice(sorted(triple))]
            else:
                if triple not in expected:
                    expected.append(dict(triple))
            rows[lead].append(F.lookup_row(lead, seq, triple, **kw))
    assert len(expected) > 3, "premise: several distinct triples"
    assert sum(map(len, rows.values())) > len(expected) + 3, "premise: repeats and spoilers occur"

    assert S.captured_lookups(_state(rows)) == expected


def test_1414_the_request_carries_the_lookups_from_the_runs_memory_not_the_box_file(tmp_path, tenant, state):
    """Through `run.main` the request's lookups are the run state's, not the box-writable queries file's. F1/P3 (C16, C17)."""
    _set(tenant, ["aborted"])
    rows = {"l-001": [F.lookup_row("l-001", 0, LOOKUP), F.lookup_row("l-001", 1, OTHER, exit_code=2)],
            "l-002": [F.lookup_row("l-002", 0, dict(LOOKUP_2))]}
    tail = _drive(tmp_path, state, "lookups", plan=F.plan_for("aborted"), rows=rows,
                  box_planted=F.box_row(F.lookup_row("l-009", 0, OTHER)))

    assert tail.run_state is not None, "run.py handed the lifecycle no RunState to carry the run's calls"
    assert (tail.run_state.run_dir, tail.run_state.run_id) == (tail.run_dirs[-1], _run_id(tail))
    [request] = _requests(state).values()
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
    [request] = _requests(state).values()
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
    assert _requests(state) == {}
    assert _enqueue(tmp_path, tenant, _certified_run("f1-ordinary"), fixtures_dir=fixtures) is True


def test_1414_a_request_for_another_tenant_than_the_runs_or_for_a_handle_with_no_tenant_is_refused(tmp_path, tenant, state, monkeypatch):
    """The enqueue refuses a tenant whose id is not the run's, and a run handle carrying no tenant address; the run's own tenant is admitted. F1.

    Design detail, not user-visible: fail closed. Run end queues a request only for the run's own tenant, so a request can
    never be filed into another tenant's queue."""
    from defender import _paths
    from defender.records import Run
    from defender.learning.core.config import LoopPaths
    from defender.tenancy import _tenant
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    _set(tenant, ["inconclusive"])
    root = fixture_data_root(_tenant.resolve_data_root())
    other = set_up_tenant(current_data_root(), fixture_uuid("feedback-other-tenant"))
    reach_store(os.environ["DEFENDER_DATABASE_DSN"], monkeypatch, other)
    copy = tmp_path / "settings-copy"
    shutil.copytree(location_path(tenant.settings), copy)

    def ask(run, accepted) -> bool:
        return S.enqueue_feedback_issue(run, RunPaths(run.run_dir).alert,
                                        tenant=T1106.run_tenant(accepted, settings_root=copy))

    run_dir = _certified_run("f1-tenant")
    run = run_of(run_dir)
    assert str(other.id) != run.tenant_id
    assert ask(run, other) is False
    assert ask(Run.at(run_dir), tenant) is False
    assert _requests(state) == {}
    assert _requests(LoopPaths.for_tenant(other)) == {}, "the refused request was written to the handed tenant"
    assert [r.run_id for r in S.store_call(os.environ["DEFENDER_DATABASE_DSN"], "feedback_issues", str(other.id))] == []
    accepted = _tenant.accept_tenant(root, run.tenant_id, defender_dir=_paths.process_defender_dir())
    assert ask(run, accepted) is True, "control: the run's own tenant queues"


# ---------------------------------------------------------------- A4 F1: the request goes through the store

def _filed(tmp_path, tenant, name: str) -> tuple[bool, Path]:
    _set(tenant, ["inconclusive"])
    run_dir = _certified_run(name)
    return _enqueue(tmp_path, tenant, run_dir), run_dir


def test_1414_the_request_is_filed_through_the_stores_blocking_door_as_one_row(tmp_path, tenant, state, monkeypatch):
    """Run end opens `blocking(dsn)` at `DEFENDER_DATABASE_DSN` and calls `enqueue_feedback_issue` with the run's tenant, run and case ids; one `feedback_issues` row with no issue number results. A4 F1."""
    import contextlib

    import defender.learning.store as store_mod

    seen: list[tuple] = []
    real = store_mod.blocking

    class Spy:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            target = getattr(self._inner, name)
            if name != "enqueue_feedback_issue":
                return target

            def spied(*a, **kw):
                seen.append((a, kw))
                return target(*a, **kw)
            return spied

    @contextlib.contextmanager
    def spying(dsn, **knobs):
        with real(dsn, **knobs) as inner:
            yield Spy(inner)

    monkeypatch.setattr(store_mod, "blocking", spying)  # lint-monkeypatch: ok — the store opener is a module-level door run end reaches itself
    queued, run_dir = _filed(tmp_path, tenant, "f1-door")

    assert queued is True
    [(args, _kw)] = seen
    assert args[0] == str(tenant.id)
    assert str(run_of(run_dir).id) in args
    [(run_id, request)] = _requests(state).items()
    assert run_id == str(run_of(run_dir).id)
    assert request["outcome"] == "inconclusive"


def test_1414_a_run_filed_twice_is_one_row_and_the_second_filing_is_a_no_op(tmp_path, tenant, state):
    """Filing the same run again adds no row and changes none; the store answers False the second time. A4 F1 (`enqueue_feedback_issue -> bool`)."""
    _queued, run_dir = _filed(tmp_path, tenant, "f1-twice")
    [before] = S.store_call(os.environ["DEFENDER_DATABASE_DSN"], "feedback_issues", str(tenant.id))
    again = S.store_call(os.environ["DEFENDER_DATABASE_DSN"], "enqueue_feedback_issue", str(tenant.id),
                         str(run_of(run_dir).id), "another-case", outcome="aborted", lookups=[])
    _enqueue(tmp_path, tenant, run_dir)

    assert again is False
    assert S.store_call(os.environ["DEFENDER_DATABASE_DSN"], "feedback_issues", str(tenant.id)) == [before]


def test_1414_a_store_that_cannot_take_the_request_costs_only_the_request(tmp_path, tenant, state, caplog, monkeypatch):
    """No DSN, an unreachable store and a tenant off active each answer False on the 'NOT enqueuing a feedback issue' channel, raise nothing, and leave no row. A4 F1."""
    from defender.tests.support.jobs._jobs1342 import move_tenant

    dsn = os.environ["DEFENDER_DATABASE_DSN"]
    _set(tenant, ["inconclusive"])
    for how in ("unset", "unreachable", "inactive"):
        run_dir = _certified_run(f"f1-down-{how}")
        caplog.clear()
        with monkeypatch.context() as m:
            if how == "unset":
                m.delenv("DEFENDER_DATABASE_DSN")
            elif how == "unreachable":
                m.setenv("DEFENDER_DATABASE_DSN", "postgresql://nobody:x@127.0.0.1:1/none?connect_timeout=2")
            else:
                move_tenant(dsn, str(tenant.id), state="offboarding")
            with caplog.at_level("INFO"):
                assert _enqueue(tmp_path, tenant, run_dir) is False, how
        assert any("NOT enqueuing a feedback issue" in r.getMessage() for r in caplog.records), how
    assert S.store_call(dsn, "feedback_issues", str(tenant.id)) == []
    move_tenant(dsn, str(tenant.id), state="active")
    assert _enqueue(tmp_path, tenant, _certified_run("f1-up-again")) is True, "control: the store takes it once it is reachable and active"
