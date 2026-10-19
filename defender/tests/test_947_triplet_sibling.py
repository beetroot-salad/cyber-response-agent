"""#947 — a sibling is a `run.py --episode` PROCESS (M6, M7, O6, O9, O10)."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _fixture_run_1165

from defender.tests._spec1077 import fixture_run as _run_handle_lifecycle_1165

import json
from typing import Any

import pytest

from defender._episode_handle import Episode
from defender.tests import _tenants1106 as T1106
from defender.run_repository import RunPaths
from defender.tests import _triplet_947 as T
from defender.tests.live_oracle_1224 import _spec1224 as S1224

TOKEN_B = T.world_token("b")


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
    by id (#1105 PR 2, declared change 6: the episode whose manifest is `manifest`, opened under
    the configured episodes base)."""
    return ["--tenant", tenant, "--episode", manifest.parent.name, "--world", world]


def _episode(tmp_path, src, *, container=T.SOURCE_TENANT):
    """The episode a sibling opens by id"""
    from defender import _tenant

    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)),
                   root=tmp_path / "episodes-root")
    if container is not None:
        (ep / "runs").mkdir(exist_ok=True)
        _tenant.ensure_runs_base_record(ep / "runs", container)
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
    assert T.sym("runtime.scrub", "verdict_path")(run_dir).parent == run_dir.parent


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
    """The resume path refuses the ticket flag outright rather than accepting and ignoring it"""
    from defender import _tenant

    manifest = T.write_family(tmp_path / "episodes-root" / "ep")
    (manifest.parent / "runs").mkdir()
    _tenant.ensure_runs_base_record(manifest.parent / "runs", d9_tenant)
    assert _run().parse_args(_sibling_argv(manifest)).update_ticket is False
    with pytest.raises(SystemExit) as bad:
        _run().main([*_sibling_argv(manifest), "--update-ticket"],
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
    seen: list[str] = []
    rec = _Recorder([])
    _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p, **kw: None,
                preflight=_no_preflight,
                enqueue=lambda run_dir, alert, truncated_by=None: seen.append(run_dir.name))
    assert seen == [], "a sibling reached the curation lane"
    assert rec.kwargs["run_dir"].name == f"{T.EPISODE_ID}-b"


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


def test_a_sibling_whose_runs_base_names_another_tenant_than_the_episodes_is_refused(
        tmp_path):
    """A sibling runs on the EPISODE's tenant — the one its request names, which the source run's runs-base record agrees with."""
    from defender import _tenant

    base, src = T.runs_base(tmp_path)
    assert _tenant.read_tenant(base).tenant_id == T1106.PLAYGROUND_ID
    ep = _episode(tmp_path, src, container=None)
    other = ep / "runs"
    other.mkdir(exist_ok=True)
    _tenant.ensure_runs_base_record(other, "acme")
    lifecycle = _Recorder([])
    with pytest.raises(SystemExit) as refused:
        _run().main([*_sibling_argv(ep / "family.yaml"), "--no-learn"],
                    lifecycle=lifecycle, visualize=lambda p, **kw: None, preflight=_no_preflight)
    text = str(refused.value)
    assert "'acme'" in text, text
    assert repr(T1106.PLAYGROUND_ID) in text, text
    assert lifecycle.order == []


def test_947_every_comparing_site_reads_the_same_world_token(tmp_path):
    ledger_mod = T.mod("learning.branch.ledger")
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    world = _run().resume_world(
        Episode.open(ep), "b", tenant=T1106.fixture_run_tenant)
    assert world.token == TOKEN_B
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
    tenant = T.mod("_tenant").read_tenant(base)

    def materialize(*_a, **_kw):
        order.append("materialize")
        run_dir = T.sibling_run_dir(base, "b", stamp=False)
        return T.sym("run_repository", "Run").for_tenant(
            tenant.tenant_id, run_dir.name, runs_base=base)

    _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p, **kw: None,
                preflight=lambda m, **_kw: order.append("preflight") or 0,
                materialize=materialize)
    assert order == ["preflight", "materialize", "lifecycle"]
    assert rec.kwargs["run_dir"] == base / f"{T.EPISODE_ID}-b", (
        "the lifecycle was not handed the run dir of the handle the builder answered")


def test_947_each_sibling_runs_the_runtime_box_lifecycle(tmp_path):
    """Each sibling runs the runtime's own box lifecycle IN ORDER and leaves a scrub verdict beside its run dir"""
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    events: list[str] = []
    run_dir = base / f"{T.EPISODE_ID}-b"
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
    """A sibling's run id is the episode id joined to its world label, and its run dir carries
    that name — a grammar every naming rule between the manifest and the alias already admits."""
    base, src = T.runs_base(tmp_path)
    ep = _episode(tmp_path, src)
    rec = _Recorder([])
    _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p, **kw: None,
                preflight=_no_preflight)
    assert rec.kwargs["run_dir"].name == f"{T.EPISODE_ID}-b"
    assert T.sym("_run_id", "is_valid_run_id")(f"{T.EPISODE_ID}-b")


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
