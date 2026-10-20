"""#791 part 3 — catalog curation gets its own trigger at the investigation boundary.
"""
from __future__ import annotations

import inspect
import json
from dataclasses import replace
from pathlib import Path

import pytest

from defender.run_repository import RunPaths
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, set_up_tenant
from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender import run as run_py  # noqa: E402
from defender import run_common
from defender.records import _alert_input  # noqa: E402
from defender.learning.core import drains  # noqa: E402
from defender.box import _scrub as scrub_mod  # noqa: E402
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of, set_state_dir  # noqa: E402
from defender.tests.support.sandbox._spec791 import (  # noqa: E402
    TAIL_SEAM,
    SpecBranch,
    SpecTail,
    author_markers,
    drive_tail,
    loop_paths,
    make_run_dir,
    marker_body,
    noop_scrub,
    noop_start_box,
    noop_stop_box,
    plant_alert,
    require_tail_seam,
    satisfy_entrypoint_keys,
)

HELD_OUT_ALERT = json.dumps({"rule": {"id": "9999"}, "held": "out"}).encode("utf-8")


@pytest.fixture
def state(tmp_path, monkeypatch):
    """#1186 O2: run-end uses its tenant's queue, despite an ambient legacy root."""
    set_state_dir(monkeypatch, tmp_path / "legacy-state")
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    tenant = set_up_tenant(current_data_root())
    tenant.learning.mkdir(exist_ok=True)
    return replace(loop_paths(tmp_path), state_dir=tenant.learning)


def _certified_run(*, name="case-791", alert_bytes=None, tenant_id=None) -> Path:
    """A finished, certified natural run `name`, where run setup leaves one (#1105 PR 2):
`<data root>/<T>/runs/<name>` under a real tenant (`curation_run_dir`), so the curation row
it files is an address the drain can rehydrate. Hand it to run end as `run_of(run_dir)`."""
    planted = curation_run_dir(name, tenant_id=tenant_id)
    run_dir = make_run_dir(planted.parent, name=planted.name, disposition="benign",
                           alert_bytes=alert_bytes)
    scrub_mod.scrub(run_dir)
    return run_dir



def _opened(body: dict) -> Path:
    """The run folder a curation row's address opens to, the way the drain rehydrates it: its
    tenant accepted under the data root, the run resolved through that tenant's repository."""
    from defender import _paths
    from defender.tenancy import _tenant
    from defender.run_repository import RunAddress

    tenant = _tenant.accept_tenant(_tenant.resolve_data_root(), body["tenant_id"],
                                   defender_dir=_paths.process_defender_dir())
    return tenant.runs_repository().resolve(RunAddress(body["tenant_id"], body["run_id"])).run_dir


def _held_out_set(tmp_path, alert_bytes: bytes) -> Path:
    """A held-out fixture set with one real member, planted because the shipped corpus holds a
    single README: its digest set is EMPTY, so the content-keyed net refuses nothing and a test
    that leans on the shipped set asserts nothing at all (PR2b)."""
    fixtures = tmp_path / "held-out"
    member = fixtures / "m01-planted"
    member.mkdir(parents=True)
    (member / "alert.json").write_bytes(alert_bytes)
    return fixtures


def test_791_the_investigation_tail_takes_its_dependencies_through_a_seam(tmp_path, state):
    require_tail_seam(run_py.main)
    params = inspect.signature(run_py.main).parameters
    for name in TAIL_SEAM:
        assert params[name].default is not inspect.Parameter.empty, (
            f"main's {name} seam has no production default — every existing caller, the "
            "entrypoint's own `__main__` included, now has to supply one"
        )
    assert "enqueue_curation" not in params, (
        "the curation trigger is injectable, so every demand about the trigger can be "
        "satisfied by a double instead of by the queue"
    )

    tail = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "seam"), tail, "--update-ticket") == 0
    assert tail.run_dirs, "main never drove the injected lifecycle"
    run_dir = tail.run_dirs[0]
    assert run_dir.is_dir(), "the lifecycle was handed a run dir that does not exist"
    assert RunPaths(run_dir).alert.is_file(), \
        "the lifecycle was handed a run dir the entrypoint had not materialized the alert into"
    for step in ("open_case_ticket", "lifecycle", "record_case_ticket", "visualize"):
        assert step in tail.names, f"the tail never reached {step} (ran {tail.names})"


def test_791_finished_investigation_drives_catalog_curation(tmp_path, state):
    """curation_trigger_at_the_investigation_boundary — a finished investigation asks for
    catalog curation at its own boundary, and the lane that serves the request RUNS."""
    run_dir = _certified_run()
    assert run_common.enqueue_curation(run_of(run_dir), run_dir / "alert.json") is True

    assert author_markers(state), "the investigation boundary asked for no curation"

    served: list[Path] = []
    branch = SpecBranch(tmp_path / "worktrees")
    rc = drains.lead_author_drain(
        state,
        run_lead_author=lambda _paths, _state, run, *, box=None, **_kw: served.append(run.run_dir),
        run_pitfalls=lambda *_a, **_kw: 0,
        branch=branch, start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
    )
    assert rc == 0
    assert served == [run_dir.resolve()], \
        f"the curation lane never ran over the investigation's run dir (saw {served})"
    assert author_markers(state) == [], "the served request was left on the queue"


def test_791_the_curation_marker_names_the_case_and_the_run_dir(tmp_path, state):
    """curation_marker_shape — the curation request names the CASE it speaks for and carries a
    resolvable investigation run directory."""
    run_dir = _certified_run()
    run_common.enqueue_curation(run_of(run_dir), run_dir / "alert.json")

    markers = sorted((state.state_root / "author-queue").glob("*.json"))
    assert len(markers) == 1
    body = marker_body(markers[0])

    assert body.get("case_id"), f"the curation request names no case: {body}"
    # #1105 PR 2 declared change 8: the request carries the run's address, where it carried
    # its folder; "resolvable" is the drain's own rehydration of that address.
    assert body.get("tenant_id"), f"the curation request names no tenant: {body}"
    assert body.get("run_id"), f"the curation request names no run: {body}"
    assert _opened(body).is_dir(), "the run the drain would hand the curator is gone"
    assert _opened(body).resolve() == run_dir.resolve()


def test_1186_run_end_keeps_identical_cases_in_their_runs_tenant_queues(tmp_path, state, monkeypatch):
    """O2: run identity selects state; equal case digests cannot coalesce across tenants."""
    first_root = current_data_root()
    other_root = tmp_path / "other-data"
    other = set_up_tenant(other_root, fixture_uuid("tenant:other-1186"))
    other.learning.mkdir(exist_ok=True)
    alert = b'{"rule":{"id":"1186"},"case":"same-alert"}'
    first = _certified_run(name="tenant-a", alert_bytes=alert)
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(other_root))
    second = _certified_run(name="tenant-b", alert_bytes=alert, tenant_id=str(other.id))
    for root, run_dir in ((first_root, first), (other_root, second)):
        monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
        assert run_common.enqueue_curation(run_of(run_dir), run_dir / "alert.json") is True
    queues = [state.state_root / "author-queue", other.learning / "author-queue"]
    markers = [list(queue.glob("*.json")) for queue in queues]
    assert [len(items) for items in markers] == [1, 1]
    bodies = [marker_body(items[0]) for items in markers]
    assert bodies[0]["case_id"] == bodies[1]["case_id"]
    assert [(body["tenant_id"], body["run_id"]) for body in bodies] == [
        (run_dir.parent.parent.name, run_dir.name) for run_dir in (first, second)]
    assert not (tmp_path / "legacy-state" / "author-queue").exists()


def test_791_a_retried_investigation_coalesces_onto_one_curation_request(tmp_path, state):
    """curation_request_is_keyed_on_the_case — two investigations of ONE case leave exactly one
    curation request, and it points at the later run."""
    alert = json.dumps({"rule": {"id": "5710"}, "case": "one-and-the-same"}).encode("utf-8")
    first = _certified_run(name="run-a", alert_bytes=alert)
    second = _certified_run(name="run-b", alert_bytes=alert)

    run_common.enqueue_curation(run_of(first), first / "alert.json")
    run_common.enqueue_curation(run_of(second), second / "alert.json")

    markers = sorted((state.state_root / "author-queue").glob("*.json"))
    assert len(markers) == 1, \
        f"a retry added a second curation request instead of coalescing: {[m.name for m in markers]}"
    body = marker_body(markers[0])
    assert _opened(body).resolve() == second.resolve(), \
        "the coalesced request still points at the run the retry replaced"


def test_791_a_curation_re_ask_issued_mid_drain_is_not_destroyed(tmp_path, state):
    """curation_claim_and_serve_is_atomic — a curation request that arrives while the lane is
    already curating that case survives."""
    alert = json.dumps({"rule": {"id": "5710"}, "case": "one-and-the-same"}).encode("utf-8")
    first = _certified_run(name="run-a", alert_bytes=alert)
    second = _certified_run(name="run-b", alert_bytes=alert)
    run_common.enqueue_curation(run_of(first), first / "alert.json")

    served: list[Path] = []

    def serve_and_re_ask(_paths, _state, run, *, box=None, **_kw):
        served.append(run.run_dir)
        if len(served) == 1:
            # The operator re-investigates the case while the lane is curating it.
            run_common.enqueue_curation(run_of(second), second / "alert.json")

    def drain() -> None:
        drains.lead_author_drain(
            state, run_lead_author=serve_and_re_ask, run_pitfalls=lambda *_a, **_kw: 0,
            branch=SpecBranch(tmp_path / "worktrees"),
            start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
        )

    drain()
    assert served[:1] == [first.resolve()], f"the first pass served {served}, not the queued run"
    drain()
    assert served == [first.resolve(), second.resolve()], (
        "the re-ask issued while the lane was curating this case was destroyed: the drain "
        f"unlinked a marker it never read, and the served set is {served}"
    )
    assert author_markers(state) == [], "the served re-ask was left on the queue"


def test_791_a_failed_curation_write_costs_the_investigation_nothing(tmp_path, state):
    """curation_write_is_isolated — a curation request that cannot be written costs the
    investigation nothing."""
    run_dir = _certified_run()
    (state.state_root / "author-queue").parent.mkdir(parents=True, exist_ok=True)
    (state.state_root / "author-queue").write_text("not a directory\n", encoding="utf-8")

    assert run_common.enqueue_curation(run_of(run_dir), run_dir / "alert.json") is False, \
        "a failed curation write did not report itself"

    broken = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "broken"), broken) == 0, \
        "a curation request that could not be written changed the investigation's exit status"
    assert "visualize" in broken.names, \
        "the failed curation write took the render step with it — the investigation lost its " \
        "human-facing output to an optimisation over a corpus"

    (state.state_root / "author-queue").unlink()
    working = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "working"), working) == 0
    assert working.step("visualize").curation_requests, \
        "the render step ran BEFORE the curation request existed: the trigger is sited below " \
        "the render, so its failure can no longer be the last word"


def test_791_curation_refuses_a_held_out_alert_copy_by_content(tmp_path, state):
    fixtures = _held_out_set(tmp_path, HELD_OUT_ALERT)
    copied = _certified_run(name="scored-alert", alert_bytes=HELD_OUT_ALERT)
    alert = RunPaths(copied).alert

    assert run_common.is_held_out_fixture(alert, fixtures) is False, \
        "the run's own alert copy is inside the fixtures dir — the path net would catch it " \
        "here and this test would not be about the digest at all"
    assert _alert_input.digest_of(alert.read_bytes()) in run_common.held_out_alert_digests(fixtures)

    assert run_common.enqueue_curation(run_of(copied), alert, fixtures_dir=fixtures) is False
    assert author_markers(state) == [], "a held-out alert copy reached the committed catalog"

    ordinary = _certified_run(name="ordinary")
    assert run_common.enqueue_curation(
        run_of(ordinary), RunPaths(ordinary).alert, fixtures_dir=fixtures
    ) is True, "the net starves curation of ordinary runs"


def test_791_no_learn_suppresses_curation_too(tmp_path, state):
    """curation_honours_no_learn — the operator's `--no-learn` suppresses catalog curation as
    well as learning."""
    suppressed = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "suppressed"), suppressed, "--no-learn") == 0
    assert author_markers(state) == [], "--no-learn left a curation request behind"

    allowed = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "allowed"), allowed) == 0
    assert author_markers(state), \
        "the boundary never fires at all — the suppressed arm above proves nothing"

    for marker in (state.state_root / "author-queue").glob("*.json"):
        marker.unlink()
    scoring = SpecTail(state)
    assert drive_tail(
        run_py.main, plant_alert(tmp_path / "scored", alert_bytes=HELD_OUT_ALERT), scoring, "--no-learn"
    ) == 0
    assert author_markers(state) == [], \
        "the held-out eval's own documented invocation started feeding the committed catalog"


def test_791_enqueue_curation_cannot_be_called_unguarded(tmp_path, state):
    fixtures = _held_out_set(tmp_path, HELD_OUT_ALERT)
    unverified = curation_run_dir("u")
    for label, run_dir, kw in (
        ("truncated", _certified_run(name="t"), {"truncated_by": "budget"}),
        ("held-out-copy",
         _certified_run(name="h", alert_bytes=HELD_OUT_ALERT), {}),
        ("unverified", make_run_dir(unverified.parent, name=unverified.name,
                                    disposition="benign"), {}),
    ):
        assert run_common.enqueue_curation(
            run_of(run_dir), run_dir / "alert.json", fixtures_dir=fixtures, **kw
        ) is False, f"{label}: the unguarded call went through"
    assert author_markers(state) == [], "an unguarded call reached the committed catalog"

    import inspect

    params = set(inspect.signature(run_common.enqueue_curation).parameters)
    assert not (params & {"force", "skip_refusals", "unguarded", "check", "gate"}), \
        f"the curation enqueue offers a way to bypass its own guard: {sorted(params)}"



def test_791_the_curation_trigger_joins_the_scrub_ordering_property(tmp_path, state):
    tail = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "ordered"), tail, "--update-ticket") == 0
    for consumer in ("record_case_ticket", "visualize"):
        assert tail.step(consumer).tree_certified, \
            f"{consumer} read the run dir BEFORE the lifecycle certified it"
    assert author_markers(state), \
        "no curation request was written at all, so the refusal below proves nothing"

    for marker in (state.state_root / "author-queue").glob("*.json"):
        marker.unlink()
    uncertified = SpecTail(state, certify=False)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "uncertified"), uncertified) == 0
    assert author_markers(state) == [], \
        "a run whose tree carries no scan verdict was handed to the curation lane anyway"
