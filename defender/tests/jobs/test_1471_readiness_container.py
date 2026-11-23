"""#1471 slice B: the readiness container entry (`run.readiness_main`) judges the tenant's systems, the case system and
the census over the helper's published copy, and writes one of `refused`, `ready` or `failed` (R13-1.3, R13-1.4, R13-3).
Driven through the real helper over a container stand-in whose process is the entry. Premise runs are real investigations
of the same tenant (green at the base)."""
from __future__ import annotations

import dataclasses
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import listing
from defender.tests.support.jobs._readiness1471 import (
    OPERATOR_WORDS,
    SECOND_TENANT,
    WARNING_KINDS,
    assert_refused_shape,
    grants_text,
    investigate,
    judged_by_an_investigation,
    listed_runs,
    norm,
    planted_code_tree,
    readiness,
    readiness_scene,
)

process_state = J.process_state
from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: E402, F401 — fixtures the helper's store seams take
from defender.tests.support.shared._openbao1163 import openbao  # noqa: E402, F401 — fixture

pytestmark = [pytest.mark.postgres, pytest.mark.garage, pytest.mark.openbao,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

ALL = J.ALL_SYSTEMS


def _R() -> Any:
    from defender.tests.support.tenancy import _systems1366 as R

    return R


def _warnings(ran: Any) -> list[dict[str, str]]:
    """The ready record's warnings, after asserting the record is exactly `{outcome: ready, warnings}` of known kinds."""
    record = ran.result()
    assert set(record) == {"outcome", "warnings"}
    assert record["outcome"] == "ready", f"not a ready record: {ran.said()}"
    assert isinstance(record["warnings"], list)
    for w in record["warnings"]:
        assert set(w) == {"kind", "sentence"}, w
        assert w["kind"] in WARNING_KINDS, f"an unknown warning kind: {w}"
        assert isinstance(w["sentence"], str)
        assert w["sentence"].strip(), w
        assert not [x for x in OPERATOR_WORDS if x in w["sentence"]], f"an operator command in {w}"
    return record["warnings"]


def _of(warnings: list[dict[str, str]], kind: str) -> str:
    return "\n".join(w["sentence"] for w in warnings if w["kind"] == kind)


def test_r3_a_tenant_whose_launch_is_clean_reads_ready_with_no_warnings_and_leaves_no_file_in_its_runs_folder(
        tmp_path, monkeypatch, migrated_database):
    """A tenant everything of which is usable: `ready` with an empty list, the launch publish run once, the knowledge
    record at the published commit, and a runs folder holding nothing of the check's (its two records are staged facts, A-O2, D5), still listed. (R3, R13-1.7, P-1)"""
    from defender import run_common
    from defender.records import job_lane
    from defender.tests.support.jobs._container_entry1170 import ThreadCalls

    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL) as scene:
        premise = judged_by_an_investigation(scene, monkeypatch)
        assert premise["started"]
        assert premise["down"] == {}, f"premise: the tenant is launchable and all up: {premise}"
        assert investigate(scene).started
        runs_before = listing(scene.runs)
        with ThreadCalls({"materialize_run": run_common.materialize_run,
                          "check_launch": job_lane.JobLane.check_launch}) as calls:
            ran = readiness(scene)

        assert _warnings(ran) == [], ran.said()
        assert ran.ran.publishes == 1, "readiness publishes at launch"
        assert ran.knowledge["commit"] == scene.t.commit
        assert ran.knowledge["status"] == "current"  # the staged served shape (#1546: `fresh` maps to `current`)
        assert (calls.helper("materialize_run"), calls.container("materialize_run"),
                calls.helper("check_launch"), calls.container("check_launch")) == (0, 0, 0, 0)
        added = sorted(set(listing(scene.runs)) - set(runs_before))
        assert added == [], f"a check wrote a file into the runs folder (A-O2, D5: its two records are staged facts): {added}"
        assert set(ran.staged()) >= {"result", "knowledge"}, ran.said()
        assert not list((scene.root / scene.tenant / "run-knowledge").glob("*")), "the check's copy was left behind"
        assert [r for r in listed_runs(scene) if r == ran.rid] == [], "a check is not a run"
        (scene.runs / "stray.unknown.json").write_text("{}", encoding="utf-8")
        with pytest.raises(Exception, match="stray"):
            listed_runs(scene)


@pytest.mark.parametrize("how", ["default", "one-unconfigured"])
def test_r4_each_system_the_systems_check_finds_down_is_a_warning_with_its_cause_and_no_other_is(
        tmp_path, monkeypatch, migrated_database, how):
    """The systems a real investigation's container judges down are exactly the `system_down` warnings, each with its
    cause, and the tenant still reads `ready`. (R4, P-1)"""
    proxied, records = ((("identity", "ticket")), None) if how == "default" else (
        ALL, lambda spec: _R().edited(spec, "cmdb", settings={}, access=""))
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=proxied, records=records) as scene:
        premise = judged_by_an_investigation(scene, monkeypatch)
        assert premise["started"]
        assert premise["down"], f"premise: some system is down and the launch goes on: {premise}"
        ran = readiness(scene)

        warnings = _warnings(ran)
        down = [w for w in warnings if w["kind"] == "system_down"]
        assert {s for s in premise["down"] if any(s in w["sentence"] for w in down)} == set(premise["down"]), warnings
        assert len(down) == len(premise["down"]), f"a warning for a system that is up, or twice: {warnings}"
        for system, reason in premise["down"].items():
            mine = [w for w in down if system in w["sentence"]]
            assert mine
            assert reason in mine[0]["sentence"], f"{system}: no sentence with its cause {reason!r}: {down}"
        assert {w["kind"] for w in warnings} == {"system_down"}, warnings


def test_r4_p1_a_tenant_whose_every_granted_system_is_down_reads_refused_at_the_systems_step(
        tmp_path, monkeypatch, migrated_database):
    """No usable system: `refused` at `systems` with the run's own sentence, nothing after it judged. (R4, R13-1.4)"""
    def edit(d: dict[str, Any]) -> None:
        for system in list(d):
            del d[system]
        d["identity"] = {"can-access": {"roles": ["gather"]}, "health-check": {"roles": ["gather"]}}
        d["tacit-knowledge"] = {"health-check": {"roles": ["gather"]}}

    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=(), files=_table(edit)) as scene:
        premise = judged_by_an_investigation(scene, monkeypatch)
        assert not premise["started"]
        assert "no granted system is usable" in (premise["exit"] or ""), premise
        ran = readiness(scene)

        sentence = assert_refused_shape(ran.result(), "systems")
        assert "no granted system is usable" in sentence, sentence
        assert isinstance(ran.knowledge, dict), "a refusal at a container step carries the helper's knowledge record"


@pytest.mark.parametrize(("edit", "why"), [
    (lambda s: _R().edited(s, "cmdb", enabled=False), "its record is disabled"),
    (lambda s: _R().without(s, "cmdb"), "it has no current record"),
], ids=["disabled", "unrecorded"])
def test_r4_c9_a_grant_the_verdict_ignores_is_a_warning_with_the_verdicts_own_reason_naming_no_command(
        tmp_path, monkeypatch, migrated_database, edit, why):
    """Grants on a disabled or unrecorded system are ignored by the launch and warned of with the verdict's reason, not
    the logged line that names `tenant check`. (R4, C9)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL, records=edit) as scene:
        assert judged_by_an_investigation(scene, monkeypatch)["started"], "premise: the launch goes on without it"
        warnings = _warnings(readiness(scene))

        ignored = _of(warnings, "grant_ignored")
        assert "cmdb" in ignored
        assert why in ignored, warnings
        assert {w["kind"] for w in warnings} == {"grant_ignored"}, warnings


def test_r4_a_grant_on_a_system_the_catalog_lacks_is_refused_at_the_systems_step_not_warned_of(
        tmp_path, monkeypatch, migrated_database):
    """A grant naming a system no adapter exists for is kept by the verdict and refused by the systems check (surface §5,
    B6): `refused` at `systems` with the run's own sentence, where a grant on a catalog system with no enabled record is a
    `grant_ignored` warning. (R4, R13-1.4)"""
    def edit(d: dict[str, Any]) -> None:
        d["nonesuchsys"] = {"health-check": {"roles": ["gather"]}}

    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL, files=_table(edit)) as scene:
        premise = judged_by_an_investigation(scene, monkeypatch)
        assert not premise["started"], f"premise: the launch is refused: {premise}"
        assert "nonesuchsys" in (premise["exit"] or ""), premise
        ran = readiness(scene)

        sentence = assert_refused_shape(ran.result(), "systems")
        assert "nonesuchsys" in sentence, sentence
        assert isinstance(ran.knowledge, dict)


# --- the census: one planted fault per kind -----------------------------------------------------------------------------

def _table(edit: Any) -> dict[str, Any]:
    return {"settings/verb-grants.yaml": grants_text(edit)}


def _drop_row(d: dict[str, Any]) -> None:
    del d["cmdb"]["get-host"]


def _phantom(d: dict[str, Any]) -> None:
    d["cmdb"]["bogus-verb"] = {"roles": [], "reason": "kept for the census"}


REGISTRY_BROKEN = "sanctions:\n  - id: tk-misfiled\n"
CENSUS_CASES = {
    "verb_undecided": (_table(_drop_row), "cmdb.get-host"),
    "verb_undeclared": (_table(_phantom), "cmdb.bogus-verb"),
    "tacit_registry": ({"agent/skills/tacit-knowledge/registry.yaml": REGISTRY_BROKEN}, None),
    "tacit_grant": ({"agent/skills/tacit-knowledge/registry.yaml": None}, None),
    "feedback_setting": ({"settings/feedback.yaml": "open_issue_on: [bogus-outcome]\n"}, "bogus-outcome"),
    "retired_file": ({"settings/lead-zero.yaml": "system: elastic\n"}, "lead-zero.yaml"),
}


@pytest.mark.parametrize("kind", list(CENSUS_CASES))
def test_r4_r13_3_each_census_gap_of_the_published_copy_is_a_warning_of_its_kind_and_the_tenant_reads_ready(
        tmp_path, monkeypatch, migrated_database, kind):
    """A planted gap, which a real investigation launches over unrefused, is exactly one warning kind on a `ready`
    result, quoting the tenant's own value where it has one. (R4, R13-3)"""
    files, needle = CENSUS_CASES[kind]
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL, files=files) as scene:
        assert judged_by_an_investigation(scene, monkeypatch)["started"], "premise: the investigation launches"
        warnings = _warnings(readiness(scene))

        assert [w["kind"] for w in warnings] == [kind], f"exactly one warning, as the census has one line: {warnings}"
        if needle:
            assert needle in _of(warnings, kind), warnings


@pytest.mark.parametrize("name", ["systems", "case-record.yaml", "lead-zero.yaml"])
def test_r4_every_retired_leftover_file_is_reported(tmp_path, monkeypatch, migrated_database, name):
    """Each of the retired `settings/` parts is a `retired_file` warning naming it. (R4)"""
    files = {f"settings/{name}" if name != "systems" else "settings/systems/old.yaml": "system: ticket\n"}
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL, files=files) as scene:
        assert investigate(scene).started, "premise: the investigation launches"
        warnings = _warnings(readiness(scene))
        assert name in _of(warnings, "retired_file"), warnings


def test_r13_3_the_census_reads_the_published_copy_not_the_host_clone(tmp_path, monkeypatch, migrated_database):
    """The host clone and the published copy diverge in a census input: a retired file only the copy holds is warned, one
    only the clone holds is not (R13-3 "over the published copy"; R4: the copy trailing the clone is no longer reported).
    Both census halves diverge: `settings/` (the retired files) and `agent/` (a tacit registry broken in the clone only).
    Controls: each warns when it is in the copy (`test_r4_every_retired_leftover_file_is_reported`,
    `test_r4_r13_3_each_census_gap_of_the_published_copy_is_a_warning_of_its_kind_and_the_tenant_reads_ready`).
    (repair 5 and 6, G3)"""
    files = {"settings/case-record.yaml": "system: ticket\n"}
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL, files=files) as scene:
        clone_settings = Path(scene.t.clone) / "settings"
        (clone_settings / "case-record.yaml").unlink()  # the copy holds it, the clone no longer does
        (clone_settings / "lead-zero.yaml").write_text("system: elastic\n", encoding="utf-8")  # the clone only
        registry = Path(scene.t.clone) / "agent" / "skills" / "tacit-knowledge" / "registry.yaml"
        assert registry.is_file(), "premise: the clone holds the tacit registry the copy holds"
        registry.write_text(REGISTRY_BROKEN, encoding="utf-8")  # the clone only: the copy's stays sound
        ran = readiness(scene)
        warnings = _warnings(ran)
        retired = _of(warnings, "retired_file")
        assert ran.facts is not None, "premise: the container was handed its facts"
        assert "case-record.yaml" in retired, f"the copy's retired file is not warned: {ran.said()}"
        assert "lead-zero.yaml" not in retired, f"the host clone was censused, not the published copy: {ran.said()}"
        assert not [w for w in warnings if w["kind"].startswith("tacit_")], (
            f"the host clone's agent half was censused, not the published copy's: {ran.said()}")
        assert Path(ran.facts["run_copy"]) != Path(scene.t.clone), "premise: the copy is not the clone"


@pytest.mark.parametrize("recorded", [True, False], ids=["recorded", "unrecorded"])
def test_r13_3_a_verb_left_undecided_on_a_system_the_tenant_has_no_record_of_is_not_its_warning(
        tmp_path, monkeypatch, migrated_database, recorded):
    """The census is narrowed to the tenant's systems: the undecided verb of `cmdb` is warned of while `cmdb` is
    recorded and silent once it is not (that tenant is told of the ignored grants instead). (R4, R13-3)"""
    records = None if recorded else (lambda s: _R().without(s, "cmdb"))
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL, files=_table(_drop_row),
                         records=records) as scene:
        warnings = _warnings(readiness(scene))
        assert ("cmdb.get-host" in _of(warnings, "verb_undecided")) is recorded, warnings


def test_r13_3_a_withheld_verb_with_no_reason_is_the_launchs_refusal_not_a_census_warning(
        tmp_path, monkeypatch, migrated_database):
    """The grant table loader refuses a `roles: []` row with no reason, so it reads `refused` at `run_tenant`; no table
    that loads can leave `verb_unreasoned` to the census (R13-3, sort-3 group 2)"""
    def edit(d: dict[str, Any]) -> None:
        d["cmdb"]["list-roles"] = {"roles": []}

    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL, files=_table(edit)) as scene:
        assert investigate(scene).refused
        sentence = assert_refused_shape(readiness(scene, container=lambda c: 0).result(), "run_tenant")
        assert "no reason" in norm(sentence)


VALUE = '<script>alert("x")</script>&'


def test_p2_d7_a_tenant_value_with_markup_in_a_warning_reaches_its_sentence_verbatim_in_one_well_formed_record(
        tmp_path, monkeypatch, migrated_database):
    """The feedback setting quoting `<script>` text is stored as our sentence in valid JSON of exactly the ready shape;
    escaping is the page's. (P-2, D7)"""
    files = {"settings/feedback.yaml": f"open_issue_on: ['{VALUE}']\n"}
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL, files=files) as scene:
        ran = readiness(scene)
        ran.result()
        record = ran.result()
        assert set(record) == {"outcome", "warnings"}
        assert record["outcome"] == "ready", ran.said()
        assert [w["kind"] for w in record["warnings"]] == ["feedback_setting"]
        assert VALUE in record["warnings"][0]["sentence"], (
            f"the tenant's value does not reach the warning's sentence verbatim: {record['warnings']}")


# --- W8: the case verdict --------------------------------------------------------------------------------------------

def _case(system_id: str | None) -> Any:
    def edit(spec: Any) -> Any:
        return dataclasses.replace(spec, case=None if system_id is None else _R().CaseSpec(system_id=system_id))
    return edit


@pytest.mark.parametrize(("case", "warned", "needle"), [
    ("ticket", False, None), (None, False, None), ("  ", True, "must name the case system"), ("nonesuch", True, "nonesuch"),
], ids=["usable", "no-record", "unparseable", "names-no-system"])
def test_w8_the_case_verdict_runs_when_a_case_record_exists_and_a_fault_is_a_warning_never_a_refusal(
        tmp_path, monkeypatch, migrated_database, case, warned, needle):
    """No case record: no warning and no verdict run; a record that does not parse, or names no system, is judged and
    warned of (`case_system`); a usable one gives none. All through `run._case_at_start`. (W8, C3)"""
    from defender import run as run_py
    from defender.tests.support.jobs._container_entry1170 import ThreadCalls

    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL, records=_case(case)) as scene:
        premise = judged_by_an_investigation(scene, monkeypatch)
        assert premise["started"]
        assert premise["down"] == {}, premise
        with ThreadCalls({"case_at_start": run_py._case_at_start}) as calls:
            ran = readiness(scene)

        warnings = _warnings(ran)
        assert calls.container("case_at_start") == (0 if case is None else 1), calls.by_thread
        assert bool(_of(warnings, "case_system")) is warned, warnings
        if needle:
            assert needle in _of(warnings, "case_system"), warnings
        assert {w["kind"] for w in warnings} <= {"case_system"}, warnings


# --- R13-1.4: the exit rule ----------------------------------------------------------------------------------------------

def _hand(scene: Any, rid: str, mutate: Any) -> Any:
    """A container process that runs `readiness_main` against a socket answering the helper's own launch facts changed
    by `mutate(facts)` (None: unchanged, the control; `"silent"`: no socket to answer)."""
    from defender import run as run_py
    from defender.job_socket import SOCKET_ENV
    from defender.tests.support.jobs._socket_standin1170 import SocketStandIn

    def container(c: Any) -> int:
        facts = c.request("launch")
        if mutate == "silent":
            env = {**c.env, SOCKET_ENV: str(scene.root / "no-such-socket")}
            return int(run_py.readiness_main(["--readiness", rid, "--tenant", scene.tenant], environ=env))
        handed = set(facts)
        if mutate is not None:
            mutate(facts)
        with SocketStandIn(scene.tenant, launch=facts, forward=c.request) as stand_in:  # the rest of the verbs: the real helper's
            for gone in handed - set(facts):  # the stand-in fills `tenant`/`tenant_state` by default: serve the removal
                stand_in.launch.pop(gone, None)
            env = {**c.env, SOCKET_ENV: str(stand_in.path)}
            return int(run_py.readiness_main(["--readiness", rid, "--tenant", scene.tenant], environ=env))
    return container


def _set(key: str, value: Any) -> Any:
    return lambda facts: facts.__setitem__(key, value)


HANDOVER = {
    "silent-helper": "silent",
    "other-kind": _set("kind", "investigation"),
    "other-tenant": _set("tenant", str(uuid.UUID(int=1471))),
    "other-job": _set("job", str(uuid.UUID(int=1472))),
    "other-copy": _set("run_copy", "/nowhere/run-knowledge/x"),
    "records-not-parsing": _set("records", {"systems": "not a mapping"}),
    "records-missing": lambda facts: facts.pop("records"),
}


@pytest.mark.parametrize("name", list(HANDOVER))
def test_r13_1_4_an_exit_that_judges_whether_the_helper_and_container_agree_is_failed_handover_with_its_control(
        tmp_path, monkeypatch, migrated_database, name):
    """Facts that are not this request's, a copy at another path, handed records that do not parse, or a helper that does
    not answer: `{failed, handover}`; the same route with the helper's own facts reads `ready`. (R13-1.3, R13-1.4)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL) as scene:
        rid = str(uuid.uuid4())
        ran = readiness(scene, rid=rid, container=_hand(scene, rid, HANDOVER[name]))
        if name == "silent-helper":
            # #1546 A-O2: a record reaches the store only through the helper (the `result` verb); a container with no helper
            # to answer stages nothing, and the worker's end reads none.
            assert ran.record is None, ran.said()
        else:
            assert ran.result() == {"outcome": "failed", "reason": "handover"}, ran.said()
    with readiness_scene(tmp_path / "ctl", monkeypatch, migrated_database, proxied=ALL, tenant_id=SECOND_TENANT) as scene:
        rid = str(uuid.uuid4())
        ran = readiness(scene, rid=rid, container=_hand(scene, rid, None))
        assert ran.result()["outcome"] == "ready", f"control: the stand-in route with the real facts: {ran.said()}"


#: The keys of the readiness launch facts (surface §4), spelled once; the helper's own facts are checked against them.
FACT_KEYS = ("kind", "tenant", "job", "tenant_state", "export_commit", "knowledge", "run_copy", "records", "inputs_dir")
#: Keys the design's handover list does not name (R13-1.4): the honest entry may read them or not.
UNNAMED_KEYS = ("export_commit", "knowledge")
#: Keys the container's `JobTenant` is built from (#1546 design "JobTenant ... from the launch facts"): a missing or
#: wrong-typed one may also be the container's refusal of its tenant, at `container_tenant`.
TENANT_KEYS = ("tenant_state", "inputs_dir")


def _wrong_typed(value: Any) -> Any:
    return ["not", "a", "mapping"] if isinstance(value, dict) else ("1471" if not isinstance(value, str) else 1471)


@pytest.mark.parametrize("how", ["removed", "wrong-type"])
@pytest.mark.parametrize("key", FACT_KEYS)
def test_r13_1_4_launch_facts_missing_a_key_or_holding_a_value_of_another_type_end_in_a_record_never_a_crash(
        tmp_path, monkeypatch, migrated_database, key, how):
    """Generated over every key of the facts the real helper hands, each removed and each of another type: `{failed,
    handover}`, the container's tenant refusal for `tenant_state`, or the honest `ready` for a key the handover list
    does not name; never a crash or an exit with no record. (R13-1.4; repair 5)"""
    def mutate(facts: dict[str, Any]) -> None:
        assert set(facts) == set(FACT_KEYS), f"premise: the helper hands exactly the surface's keys: {sorted(facts)}"
        if how == "removed":
            facts.pop(key)
        else:
            facts[key] = _wrong_typed(facts[key])

    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL) as scene:
        rid = str(uuid.uuid4())
        ran = readiness(scene, rid=rid, container=_hand(scene, rid, mutate))
        result = ran.result()

    handover = {"outcome": "failed", "reason": "handover"}
    if key in TENANT_KEYS:
        assert result == handover or (result["outcome"], result.get("step")) == ("refused", "container_tenant"), ran.said()
    elif key in UNNAMED_KEYS:
        assert result == handover or result["outcome"] == "ready", ran.said()
    else:
        assert result == handover, ran.said()


def test_r13_1_4_launch_facts_saying_the_tenant_is_not_active_are_refused_at_the_containers_tenant_step(
        tmp_path, monkeypatch, migrated_database):
    """A tenant-state exit is `refused` at its step, not a handover: `container_tenant`, carrying the knowledge record.
    (R13-1.4)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL) as scene:
        rid = str(uuid.uuid4())
        ran = readiness(scene, rid=rid, container=_hand(scene, rid, _set("tenant_state", "offboarding")))

        assert_refused_shape(ran.result(), "container_tenant")
        assert isinstance(ran.knowledge, dict)


# Retired (#1546 D4/A-O9): `test_r13_1_4_launch_facts_saying_active_over_a_tenant_folder_the_container_refuses_are_refused_at_
# container_tenant`. The container no longer reads the host's tenant folder: it builds a `JobTenant` over its job root and
# inputs, and "`accept_tenant` stays the host's ... the knowledge-clone, `.tenant-id` and settings-vs-mount checks have no
# job-side counterpart" (design, JobTenant). The host-side refusal survives in the helper's admission (`test_1546_job_tenant`).


@pytest.mark.parametrize("blind", [True, False], ids=["blind-adapter", "readable-tree"])
def test_r13_3_a_census_that_cannot_be_taken_is_failed_census_unavailable_never_ready_over_an_untaken_census(
        tmp_path, monkeypatch, migrated_database, blind):
    """The container's code tree holds an adapter the cold verb reader sees no verb in (recorded by no system of the
    tenant, so the launch itself is clean): `{failed, census_unavailable}`; the readable copy of the same tree reads
    `ready`. Driven through `readiness_main(defender_dir=)`. (R13-3, surface §4)"""
    from defender.cli import _tenant_census

    tree = planted_code_tree(tmp_path / "tree", blind=blind)
    if blind:
        with pytest.raises(_tenant_census.CensusUnavailable):
            _tenant_census.take_census(tree)
    else:
        assert _tenant_census.take_census(tree).systems, "premise: the copy is censused"
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=ALL) as scene:
        ran = readiness(scene, defender_dir=tree)

        if blind:
            assert ran.result() == {"outcome": "failed", "reason": "census_unavailable"}, ran.said()
        else:
            assert _warnings(ran) == [], ran.said()
