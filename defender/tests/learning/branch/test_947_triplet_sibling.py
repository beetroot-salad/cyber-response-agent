"""#947 — a sibling is a `run.py --episode` PROCESS (M6, M7, O6, O9, O10)."""
from __future__ import annotations

from defender.tests.storage.ids_1187 import _spec1187 as S

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_lifecycle_1165

import json
from typing import Any

import pytest

from defender.episodes._episode_handle import Episode
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.run_repository import RunPaths
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.oracle.live_contracts import _spec1224 as S1224

TOKEN_B = T.fixture_world_id("b")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots point inside `tmp_path`: a scenario that takes its runs base from
    `tmp_path` while the code under test resolves the production one asserts about two different
    directories, and writes its debris into the developer's and CI's real roots."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


def _run():
    return T.mod("run")


def _no_preflight(*_args, **_kw) -> int:
    """`T.no_preflight`'s neutralised role preflight, taking the `branching=` keyword #1224's
    `run.py` passes."""
    return 0


def _sibling_argv(manifest, world="b", tenant=T.SOURCE_TENANT):
    """A sibling's command line — naming its tenant, as every run does (#1078), and its episode
    by id (#1105 PR 2, declared change 6: the episode whose manifest is `manifest`, opened by id
    under the tenant's `<T>/episodes/`, #1187)."""
    return ["--tenant", tenant, "--episode", manifest.parent.name, "--world", world]


def _episode(tmp_path, src):
    """The episode a sibling opens by id, its manifest naming the source run `src`. #1187
    (Layout A, R1, R2, O9; declared changes 5, 6 and 10): under its tenant's
    `<T>/episodes/<uuid>` (`T.episode`'s default root), with no container record and no
    episodes variable; the launcher's RUNS step (`start_runs`, through `T.episode_view`) makes
    `runs/` and writes the arm roster the sibling reads its arm id from (O4b)."""
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    with Episode.open(ep) as held:
        T.episode_view(held).close()
    return ep


class _Recorder:
    """The lifecycle seam as a recorder: what `main` handed it, and in what order."""

    def __init__(self, order: list[str]) -> None:
        self.order = order
        self.kwargs: dict = {}

    def __call__(self, **kw):
        self.order.append("lifecycle")
        self.kwargs = {**kw, "run_dir": kw["run"].run_dir}
        run_dir = kw["run"].run_dir
        (run_dir / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
        return {"output": "done", "requests": 1, "truncated_by": None}


# the argument surface


def test_947_resume_makes_the_positional_alert_illegal(tmp_path):
    manifest = T.write_family(tmp_path / "ep")
    alert = tmp_path / "alert.json"
    alert.write_text("{}", encoding="utf-8")
    import contextlib
    import io

    assert _run().parse_args(_sibling_argv(manifest)).world == "b"
    err = io.StringIO()
    with contextlib.redirect_stderr(err), pytest.raises(SystemExit) as bad:
        _run().parse_args([str(alert), *_sibling_argv(manifest)])
    assert bad.value.code == 2
    assert "alert" in err.getvalue()
    assert "--episode" in err.getvalue()


def test_947_sibling_runs_from_manifest_and_what_it_points_at(tmp_path):
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    order: list[str] = []
    rc = _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=_Recorder(order),
                     visualize=lambda p, **kw: None, preflight=_no_preflight)
    assert rc == 0
    assert order == ["lifecycle"]


def test_947_resume_run_returns_its_own_run_dir_and_verdict(tmp_path):
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    rec = _Recorder([])
    rc = _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=rec,
                     visualize=lambda p, **kw: None, preflight=_no_preflight)
    run_dir = rec.kwargs["run_dir"]
    assert rc == 0
    assert (run_dir / "report.md").is_file()
    assert T.sym("box._scrub", "verdict_path")(run_dir).parent == run_dir.parent


def test_947_resume_with_a_world_the_manifest_does_not_declare_refuses_before_materialize(tmp_path):
    """A world label the manifest does not declare refuses before the run dir is materialised
    and before any box starts: nothing is written under the runs base at all."""
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    before = sorted(p.name for p in base.iterdir())
    with pytest.raises(SystemExit) as bad:
        _run().main(_sibling_argv(ep / "family.yaml", world="zzz"),
                    lifecycle=_Recorder([]), visualize=lambda p, **kw: None,
                    preflight=_no_preflight)
    assert "zzz" in str(bad.value)
    assert sorted(p.name for p in base.iterdir()) == before


def test_947_resume_refuses_update_ticket(tmp_path, d9_tenant):
    """The resume path refuses the ticket flag outright rather than accepting and ignoring it:
    the two ticket calls are ordered around the curation marker, so suppressing one of them
    would break the pairing instead of the obligation. (The requested tenant exists, so the
    refusal is the flag's, not the tenant's — and #1187: the episode is a UUID folder under
    that tenant's `<T>/episodes/`, past RUNS (its roster written), so the refusal is not the
    episode's either.)"""
    _base, src = T.runs_base(tmp_path, tenant_id=d9_tenant)
    manifest = _episode(tmp_path, src) / "family.yaml"
    assert _run().parse_args(_sibling_argv(manifest)).update_ticket is False
    with pytest.raises(SystemExit) as bad:
        _run().main([*_sibling_argv(manifest, tenant=d9_tenant), "--update-ticket"],
                    lifecycle=_Recorder([]), visualize=lambda p, **kw: None,
                    preflight=_no_preflight)
    assert "--update-ticket" in str(bad.value)


# O6 — the two lanes a sibling must not take, and the control that proves the channel


def test_947_a_sibling_run_writes_no_ticket_row(tmp_path):
    """A sibling run writes no ticket row on any of its exits: the writer seam records nothing
    for a resumed run, on the opening call and on the closing one alike."""
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)

    class Writer:
        def __init__(self):
            self.calls: list[str] = []
            self.tenants: list[Any] = []

        def open_case_ticket(self, run_dir, *, tenant, defender_dir, env):
            self.calls.append("open")
            self.tenants.append(tenant)

        def record_case_ticket(self, run_dir, *, tenant, defender_dir, env, **_kw):
            self.calls.append("record")
            self.tenants.append(tenant)

    writer = Writer()
    _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=_Recorder([]),
                visualize=lambda p, **kw: None, preflight=_no_preflight, ticket_writer=writer)
    assert writer.calls == []


def test_947_a_sibling_run_writes_no_queue_marker(tmp_path):
    """A sibling run reaches the curation lane on none of its exits"""
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    roster = {w: S.new_id() for w in T.WORLDS}
    S.write_roster(ep, roster)
    seen: list[str] = []
    rec = _Recorder([])
    _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p, **kw: None,
                preflight=_no_preflight,
                enqueue=lambda run_dir, alert, truncated_by=None: seen.append(run_dir.name))
    assert seen == [], "a sibling reached the curation lane"
    assert rec.kwargs["run_dir"] == ep / "runs" / roster["b"], (
        "the sibling did not run at its roster id (#1187 declared change 2)")


# threading the world through the run


def test_947_resume_path_builds_a_world_registry_and_world_ledger(tmp_path):
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    seen: dict = {}
    _run()._drive_investigation(
        alert_path=RunPaths(src).alert, run=_fixture_run_1165(src),
        defender_dir=T.DEFENDER, model_name="m", model_override=None, box=None,
        tenant=T1106.fixture_run_tenant(),
        world=_run().resume_world(
        Episode.open(ep), "b", tenant=T1106.fixture_run_tenant),
        episode=Episode.open(ep), serving=S1224.serving(), source=T.open_source(src),
        investigate=lambda **kw: seen.update(kw) or {},
    )
    registry = seen["verbs"]
    assert type(registry).__name__ == "WorldRegistry"
    assert registry.ledger.path == ep / "served" / f"{TOKEN_B}.jsonl"


def test_947_resume_path_never_constructs_the_production_registry(tmp_path):
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    built: list[str] = []

    class Watching(T.mod("runtime.verbs").ModuleVerbRegistry):
        def __init__(self, *a, **kw):
            built.append("production")
            super().__init__(*a, **kw)

    _run()._drive_investigation(
        alert_path=RunPaths(src).alert, run=_fixture_run_1165(src),
        defender_dir=T.DEFENDER, model_name="m", model_override=None, box=None,
        tenant=T1106.fixture_run_tenant(),
        world=_run().resume_world(
        Episode.open(ep), "b", tenant=T1106.fixture_run_tenant),
        episode=Episode.open(ep), serving=S1224.serving(), source=T.open_source(src),
        registry_cls=Watching, investigate=lambda **kw: {})
    assert built == []


def test_a_sibling_resumes_through_its_requested_tenant(tmp_path):
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    lifecycle = _Recorder([])
    rc = _run().main([*_sibling_argv(ep / "family.yaml"), "--no-learn"],
                     lifecycle=lifecycle, visualize=lambda p, **kw: None, preflight=_no_preflight)
    assert rc == 0
    assert lifecycle.kwargs["world"].family.served_systems == T.SERVED_SYSTEMS
    assert lifecycle.kwargs["tenant"].tenant_id == T1106.PLAYGROUND_ID


def test_947_every_comparing_site_reads_the_same_world_token(tmp_path):
    ledger_mod = T.mod("learning.branch.ledger")
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    world = _run().resume_world(
        Episode.open(ep), "b", tenant=T1106.fixture_run_tenant)
    assert world.label == "b"
    assert world.world_id == TOKEN_B
    assert world.ledger_path.name == f"{TOKEN_B}.jsonl"
    with Episode.open(ep) as episode:
        assert ledger_mod.Ledger.for_world(episode, world.world_id).path == world.ledger_path


# the sibling's own lifecycle, stamp and identity


def test_947_resume_keeps_preflight_materialize_lifecycle_verdict_order(tmp_path):
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    order: list[str] = []
    rec = _Recorder(order)
    # #1187 (R1): no `_tenant.json` — a run's tenant is the one whose folder holds it.
    tenant_id = base.parent.name
    made: list[Any] = []

    def materialize(*_a, **_kw):
        # #1110: the seam answers the run's tenant-bound HANDLE, built the way the real builder
        # builds it (#1187: `Run.under(container, id, tenant_id=)`, `Run.for_tenant` being
        # retired with the record it read) — `main` keeps it for the post-run page render and
        # reads the run dir off it.
        order.append("materialize")
        run_dir = T.sibling_run_dir(base, "b", stamp=False)
        made.append(run_dir)
        return T.sym("run_repository", "Run").under(base, run_dir.name, tenant_id=tenant_id)

    _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p, **kw: None,
                preflight=lambda m, **_kw: order.append("preflight") or 0,
                materialize=materialize)
    assert order == ["preflight", "materialize", "lifecycle"]
    assert made, "the materialize seam was never called"
    assert rec.kwargs["run_dir"] == made[0], (
        "the lifecycle was not handed the run dir of the handle the builder answered")


def test_947_each_sibling_runs_the_runtime_box_lifecycle(tmp_path):
    """Each sibling runs the runtime's own box lifecycle IN ORDER and leaves a scrub verdict beside its run dir"""
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    events: list[str] = []
    run_dir = base / fixture_uuid("947-sibling-lifecycle-b")  # #1187: a run id is a uuid4
    (run_dir / "gather_raw").mkdir(parents=True)
    _run()._run_investigation_lifecycle(
        run=_run_handle_lifecycle_1165(run_dir), model="m", model_override=None, defender_dir=T.DEFENDER,
        world=_run().resume_world(
        Episode.open(ep), "b", tenant=T1106.fixture_run_tenant),
        tenant=T1106.fixture_run_tenant(),
        investigate=lambda **kw: events.append("investigate") or {},
        start_box=lambda *a, **kw: events.append("start") or object(),
        stop_box=lambda *a, **kw: events.append("stop"),
        scrub=lambda tree, **kw: events.append("scrub"))
    assert events == ["start", "investigate", "stop", "scrub"]


def test_947_each_sibling_captures_its_own_provenance_stamp(tmp_path):
    """Each sibling captures its OWN provenance stamp inside its own process, written into its
    own run dir before any agent exists — never a stamp hoisted once above the family."""
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    rec = _Recorder([])
    _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p, **kw: None,
                preflight=_no_preflight)
    stamp = rec.kwargs["run_dir"] / "provenance.json"
    assert stamp.is_file()
    assert "commit" in json.loads(stamp.read_text(encoding="utf-8"))


def test_947_sibling_run_id_is_episode_id_dash_x_beside_the_source(tmp_path):
    """A sibling's run id is the one the host wrote for its world, and its run dir carries that
    name, in its episode's own `runs/`.

    #1187 declared change 2 (O3, R2): the id is no longer the episode id joined to the world
    label. It is the canonical UUID the launcher minted into the episode's arm roster
    (`arms.json`, planted here as the launcher writes it at RUNS) for that label, and the arm
    folder `<ep>/runs/<roster id>` holds neither the label nor the episode id. (Name kept.)"""
    from defender.tests.storage.ids_1187 import _spec1187 as S

    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    roster = {w: S.new_id() for w in T.WORLDS}
    S.write_roster(ep, roster)
    rec = _Recorder([])
    _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p, **kw: None,
                preflight=_no_preflight)
    run_dir = rec.kwargs["run_dir"]
    assert run_dir == ep / "runs" / roster["b"], (
        f"the sibling ran at {run_dir}, not at its roster id {roster['b']}")
    assert S.is_canonical_uuid(run_dir.name), run_dir.name
    assert ep.name not in run_dir.name, f"{run_dir.name} carries the episode id"
    assert not run_dir.name.endswith("-b"), f"{run_dir.name} carries the label"
    assert T.sym("records._run_id", "is_valid_run_id")(run_dir.name)


def test_947_run_py_screens_the_source_alert_before_reading_it(tmp_path):
    base, src = T.runs_base(tmp_path)
    secret = tmp_path / "secret.json"
    secret.write_text('{"stolen": true}', encoding="utf-8")
    RunPaths(src).alert.unlink()
    RunPaths(src).alert.symlink_to(secret)
    ep = _episode(tmp_path, src)
    with pytest.raises(SystemExit) as bad:
        _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=_Recorder([]),
                    visualize=lambda p, **kw: None, preflight=_no_preflight)
    assert "alert" in str(bad.value)
