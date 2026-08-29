"""#947 — a sibling is a `run.py --resume` PROCESS (M6, M7, O6, O9, O10).

D1's whole content: the launcher writes the manifest, stages the corpus and starts N processes;
learning never executes the driver in its own process. So `run.py` grows `--resume <manifest>
--world X` and otherwise runs an ordinary run — its own preflight, run-dir materialisation and
stamp, box, scrub and verdict, in that order — while the resume path refuses the ticket flag and
forces the no-learn branch so a synthetic sibling never writes a ticket row or a queue marker.

O6 is currently satisfied by OMISSION and nothing asserts it (G19, refuted): the launcher simply
never calls the two lanes. Routing a sibling through `run.py`'s own `main` acquires both of them,
so the discharge here is a POSITIVE refusal on the resume path, not an absence.

Five signatures carry `world`, not three (G4, refuted): the argument parser and `main`'s own
lifecycle call as well as the protocol, the drive function and the lifecycle.

RED against b8a63e66: `run.py` has no resume argument at all (C3/PO-C29) and
`runtime/branch/_family.py` does not exist (X16).
"""
from __future__ import annotations

import inspect
import json

import pytest

from defender.tests import _triplet_947 as T

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


def _resume_argv(manifest, world="b"):
    return ["--resume", str(manifest), "--world", world]


class _Recorder:
    """The lifecycle seam as a recorder: what `main` handed it, and in what order."""

    def __init__(self, order: list[str]) -> None:
        self.order = order
        self.kwargs: dict = {}

    def __call__(self, **kw):
        self.order.append("lifecycle")
        self.kwargs = kw
        run_dir = kw["run_dir"]
        (run_dir / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
        return {"output": "done", "requests": 1, "truncated_by": None}


# ---------------------------------------------------------------------------------------
# the argument surface
# ---------------------------------------------------------------------------------------


def test_947_run_py_accepts_resume_manifest_and_world(tmp_path):
    """The sibling entry point accepts a manifest path and a world label, and the parsed
    namespace carries both, so a family's manifest is the whole of what a sibling is told."""
    manifest = T.write_family(tmp_path / "ep")
    ns = _run().parse_args(_resume_argv(manifest))
    assert ns.resume == manifest
    assert ns.world == "b"


def test_947_resume_makes_the_positional_alert_illegal(tmp_path):
    """Under the resume flag the positional alert is illegal: supplying both refuses at the
    parser, naming the conflict, because the manifest already names the source run the alert
    would come from."""
    manifest = T.write_family(tmp_path / "ep")
    alert = tmp_path / "alert.json"
    alert.write_text("{}", encoding="utf-8")
    import contextlib
    import io

    assert _run().parse_args(_resume_argv(manifest)).world == "b"
    err = io.StringIO()
    with contextlib.redirect_stderr(err), pytest.raises(SystemExit) as bad:
        _run().parse_args([str(alert), *_resume_argv(manifest)])
    assert bad.value.code == 2
    assert "alert" in err.getvalue()
    assert "--resume" in err.getvalue()


def test_947_sibling_runs_from_manifest_and_what_it_points_at(tmp_path):
    """A sibling runs from the manifest and what it points at and nothing hand-supplied: given
    only the manifest path and a world label it resolves the episode dir, the source run, the
    branch point and its own world, and completes."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    order: list[str] = []
    rc = _run().main(_resume_argv(ep / "family.yaml"), lifecycle=_Recorder(order),
                     visualize=lambda p: None, preflight=T.no_preflight)
    assert rc == 0
    assert order == ["lifecycle"]


def test_947_resume_run_returns_its_own_run_dir_and_verdict(tmp_path):
    """A resumed run returns the same contract an ordinary run does: a zero status, its own run
    dir on disk carrying the report, and its scrub verdict written at the sidecar path beside
    that directory."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    rec = _Recorder([])
    rc = _run().main(_resume_argv(ep / "family.yaml"), lifecycle=rec,
                     visualize=lambda p: None, preflight=T.no_preflight)
    run_dir = rec.kwargs["run_dir"]
    assert rc == 0
    assert (run_dir / "report.md").is_file()
    assert T.sym("runtime.scrub", "verdict_path")(run_dir).parent == run_dir.parent


def test_947_resume_with_a_world_the_manifest_does_not_declare_refuses_before_materialize(tmp_path):
    """A world label the manifest does not declare refuses before the run dir is materialised
    and before any box starts: nothing is written under the runs base at all."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    before = sorted(p.name for p in base.iterdir())
    with pytest.raises(SystemExit) as bad:
        _run().main(_resume_argv(ep / "family.yaml", world="zzz"),
                    lifecycle=_Recorder([]), visualize=lambda p: None,
                    preflight=T.no_preflight)
    assert "zzz" in str(bad.value)
    assert sorted(p.name for p in base.iterdir()) == before


def test_947_resume_refuses_update_ticket(tmp_path):
    """The resume path refuses the ticket flag outright rather than accepting and ignoring it:
    the two ticket calls are ordered around the curation marker, so suppressing one of them
    would break the pairing instead of the obligation."""
    manifest = T.write_family(tmp_path / "ep")
    assert _run().parse_args(_resume_argv(manifest)).update_ticket is False
    with pytest.raises(SystemExit) as bad:
        _run().main([*_resume_argv(manifest), "--update-ticket"],
                    lifecycle=_Recorder([]), visualize=lambda p: None,
                    preflight=T.no_preflight)
    assert "--update-ticket" in str(bad.value)


# ---------------------------------------------------------------------------------------
# O6 — the two lanes a sibling must not take, and the control that proves the channel
# ---------------------------------------------------------------------------------------


def test_947_a_sibling_run_writes_no_ticket_row(tmp_path):
    """A sibling run writes no ticket row on any of its exits: the writer seam records nothing
    for a resumed run, on the opening call and on the closing one alike."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))

    class Writer:
        def __init__(self):
            self.calls: list[str] = []

        def open_case_ticket(self, run_dir):
            self.calls.append("open")

        def close_case_ticket(self, run_dir):
            self.calls.append("close")

    writer = Writer()
    _run().main(_resume_argv(ep / "family.yaml"), lifecycle=_Recorder([]),
                visualize=lambda p: None, preflight=T.no_preflight, ticket_writer=writer)
    assert writer.calls == []


def test_947_a_sibling_run_writes_no_queue_marker(tmp_path):
    """A sibling run reaches the curation lane on none of its exits: the resume path forces the
    no-learn branch, so the enqueue seam records nothing at all for a sibling — asserted on the
    SAME seam the positive control below drives, because a directory that does not exist is
    empty of a sibling's marker whatever the resume path did."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    seen: list[str] = []
    rec = _Recorder([])
    _run().main(_resume_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p: None,
                preflight=T.no_preflight,
                enqueue=lambda run_dir, alert, truncated_by=None: seen.append(run_dir.name))
    assert seen == [], "a sibling reached the curation lane"
    assert rec.kwargs["run_dir"].name == f"{T.EPISODE_ID}-b"


def test_947_an_ordinary_run_still_enqueues_for_curation(tmp_path):
    """The positive control for the queue negative: an ordinary run with the learning flag
    unset still reaches the curation lane, so the sibling's silence is a refusal rather than a
    channel that never carries anything."""
    base, src = T.runs_base(tmp_path)
    seen: list[str] = []
    _run().main([str(src / "alert.json")], lifecycle=_Recorder([]),
                visualize=lambda p: None, preflight=T.no_preflight,
                enqueue=lambda run_dir, alert, truncated_by=None: seen.append(run_dir.name))
    assert seen, "an ordinary run reached no curation lane"


# ---------------------------------------------------------------------------------------
# threading the world through the run
# ---------------------------------------------------------------------------------------


def test_947_world_is_threaded_through_investigate_drive_and_lifecycle(tmp_path):
    """The world reaches the investigation through every signature on the path: the argument
    parser, the investigate protocol, the drive function, the lifecycle and the call `main`
    makes to it — five sites, so a world declared on the command line cannot be dropped between
    any two of them."""
    run = _run()
    for fn in (run._drive_investigation, run._run_investigation_lifecycle):
        assert "world" in inspect.signature(fn).parameters, fn.__name__
    assert "world" in inspect.signature(run._Investigate.__call__).parameters
    assert "world" in inspect.signature(run.parse_args).parameters or \
        "--world" in (T.DEFENDER / "run.py").read_text(encoding="utf-8")
    src = (T.DEFENDER / "run.py").read_text(encoding="utf-8")
    assert "world=" in src.split("summary = lifecycle(")[1].split(")")[0]


def test_947_resume_path_builds_a_world_registry_and_world_ledger(tmp_path):
    """On the resume path the drive function builds a world registry over the world's own
    ledger file and the world's overlay, and hands it to the driver as the injected verb
    registry."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    seen: dict = {}
    _run()._drive_investigation(
        alert_path=src / "alert.json", run_dir=src, run_id=src.name,
        defender_dir=T.DEFENDER, model_name="m", model_override=None, box=None,
        world=_run().resume_world(ep / "family.yaml", "b"),
        investigate=lambda **kw: seen.update(kw) or {},
    )
    registry = seen["verbs"]
    assert type(registry).__name__ == "WorldRegistry"
    assert registry.ledger.path == ep / "served" / f"{TOKEN_B}.jsonl"


def test_947_resume_path_never_constructs_the_production_registry(tmp_path):
    """The resume path never constructs the production module registry: a sibling's queries go
    through its world registry, so no post-branch query can reach a real adapter body by way of
    the registry the ordinary path builds."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    built: list[str] = []

    class Watching(T.mod("runtime.verbs").ModuleVerbRegistry):
        def __init__(self, *a, **kw):
            built.append("production")
            super().__init__(*a, **kw)

    _run()._drive_investigation(
        alert_path=src / "alert.json", run_dir=src, run_id=src.name,
        defender_dir=T.DEFENDER, model_name="m", model_override=None, box=None,
        world=_run().resume_world(ep / "family.yaml", "b"),
        registry_cls=Watching, investigate=lambda **kw: {})
    assert built == []


def test_947_without_a_world_the_production_registry_is_built_exactly_as_now(tmp_path):
    """The parity control: with no world the drive function builds the production module
    registry exactly as it does today, over the adapters tree and the gather grant — the
    constraint the resume path adds is enforced on the resume path only."""
    base, src = T.runs_base(tmp_path)
    seen: dict = {}
    _run()._drive_investigation(
        alert_path=src / "alert.json", run_dir=src, run_id=src.name,
        defender_dir=T.DEFENDER, model_name="m", model_override=None, box=None,
        world=None, investigate=lambda **kw: seen.update(kw) or {})
    registry = seen["verbs"]
    assert type(registry).__name__ == "ModuleVerbRegistry"
    assert registry.grant is T.mod("runtime.driver").GATHER_DEF.verb_grant


def test_947_episode_dir_is_derived_as_the_manifest_parent(tmp_path):
    """A sibling derives the episode dir as the manifest's own parent, which is what makes the
    world ledger resolve: the ledger it writes is the file beside the family's primed base
    recording, wherever the manifest lives."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    world = _run().resume_world(ep / "family.yaml", "b")
    assert world.episode_dir == ep
    assert world.ledger_path == ep / "served" / f"{TOKEN_B}.jsonl"


def test_947_every_comparing_site_reads_the_same_world_token(tmp_path):
    """Every site that compares a world reads ONE spelling of the world token: the alias name's
    head, the world ledger's filename, the ledger rows a sibling writes, and the registry's own
    recorded identity all carry the same composed token."""
    confinement = T.mod("scripts.adapters.confinement")
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    world = _run().resume_world(ep / "family.yaml", "b")
    assert world.token == TOKEN_B
    assert confinement.world_view(T.EVENTS_PATTERN, world.token).startswith(f"wv-{TOKEN_B}-")
    assert world.ledger_path.name == f"{TOKEN_B}.jsonl"
    assert confinement.is_world_view(f"wv-{TOKEN_B}-logs-", T.CONFIGURED, world.token)


def test_947_world_applier_compares_the_same_world_token_the_other_three_sites_use(tmp_path):
    """The applier compares the SAME world token the other three sites do: a call it stages
    carries the composed token, and a call carrying the short label alone is not this world's."""
    applier_mod = T.mod("learning.branch.estate.applier")
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    world = _run().resume_world(ep / "family.yaml", "b")
    applier = applier_mod.WorldApplier()
    prepared = applier.prepare("elastic", "query", {"index": T.EVENTS_PATTERN}, world, None)
    assert prepared["index"] == f"wv-{TOKEN_B}-logs-"
    assert applier._staging_world(world, "elastic") == TOKEN_B


# ---------------------------------------------------------------------------------------
# the sibling's own lifecycle, stamp and identity
# ---------------------------------------------------------------------------------------


def test_947_resume_keeps_preflight_materialize_lifecycle_verdict_order(tmp_path):
    """A resumed run keeps `main`'s own order — role preflight, run-dir materialisation with
    its stamp, the box lifecycle, then the verdict — so the sibling is an ordinary run in every
    respect but where its evidence comes from."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    order: list[str] = []
    rec = _Recorder(order)
    _run().main(_resume_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p: None,
                preflight=lambda m: order.append("preflight") or 0,
                materialize=lambda *a, **kw: order.append("materialize") or
                T.sibling_run_dir(base, "b", stamp=False))
    assert order == ["preflight", "materialize", "lifecycle"]


def test_947_each_sibling_runs_the_runtime_box_lifecycle(tmp_path):
    """Each sibling runs the runtime's own box lifecycle IN ORDER and leaves a scrub verdict
    beside its run dir: the box is started before the investigation, reaped after it, and the
    scan runs on the reaped tree — four events in that sequence, because a run that started a
    box first and then did anything else at all is not the lifecycle O9 names."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    events: list[str] = []
    run_dir = base / f"{T.EPISODE_ID}-b"
    (run_dir / "gather_raw").mkdir(parents=True)
    _run()._run_investigation_lifecycle(
        run_dir=run_dir, model="m", model_override=None, defender_dir=T.DEFENDER,
        world=_run().resume_world(ep / "family.yaml", "b"),
        investigate=lambda **kw: events.append("investigate") or {},
        start_box=lambda *a: events.append("start") or object(),
        stop_box=lambda *a, **kw: events.append("stop"),
        scrub=lambda tree: events.append("scrub"))
    assert events == ["start", "investigate", "stop", "scrub"]


def test_947_each_sibling_captures_its_own_provenance_stamp(tmp_path):
    """Each sibling captures its OWN provenance stamp inside its own process, written into its
    own run dir before any agent exists — never a stamp hoisted once above the family."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    rec = _Recorder([])
    _run().main(_resume_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p: None,
                preflight=T.no_preflight)
    stamp = rec.kwargs["run_dir"] / "provenance.json"
    assert stamp.is_file()
    assert "commit" in json.loads(stamp.read_text(encoding="utf-8"))


def test_947_sibling_run_id_is_episode_id_dash_x_beside_the_source(tmp_path):
    """A sibling's run id is the episode id joined to its world label, and its run dir carries
    that name — a grammar every naming rule between the manifest and the alias already admits."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    rec = _Recorder([])
    _run().main(_resume_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda p: None,
                preflight=T.no_preflight)
    assert rec.kwargs["run_dir"].name == f"{T.EPISODE_ID}-b"
    assert T.sym("_run_id", "is_valid_run_id")(f"{T.EPISODE_ID}-b")


def test_947_run_py_screens_the_source_alert_before_reading_it(tmp_path):
    """The resume path screens the source run's alert before reading it: the source run dir is a
    prior box's writable bind, so a link planted at the alert's name is refused rather than
    followed into this run's evidence."""
    base, src = T.runs_base(tmp_path)
    secret = tmp_path / "secret.json"
    secret.write_text('{"stolen": true}', encoding="utf-8")
    (src / "alert.json").unlink()
    (src / "alert.json").symlink_to(secret)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    with pytest.raises(SystemExit) as bad:
        _run().main(_resume_argv(ep / "family.yaml"), lifecycle=_Recorder([]),
                    visualize=lambda p: None, preflight=T.no_preflight)
    assert "alert" in str(bad.value)
