"""#947 — the archive, its two derived readers, and where a sibling's artifacts may live (M8, O4, O7"""
from __future__ import annotations

import os
from defender.tests.support.learning.judge import _judge_921 as J

import json

import pytest

from defender.episodes._episode_handle import Episode
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.run_repository import RunPaths
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root
from defender.tests.support.shared._fixture_uuid import fixture_uuid


def _archive():
    return T.mod("learning.branch.archive")


def _tenant_paths():
    """#1078: the tenant `T.runs_base` (or `d9_tenant`) already created."""
    return T.current_tenant()


def _episode():
    return T.mod("learning.branch.episode")


def _accepted(tmp_path, *, outcome="accepted", reason="every fact world calibrated"):
    """An episode pre-flight recorded (`outcome.yaml`, through its production writer): the
    readers compare only an `accepted` family (#1224 M05=A) carrying the family stamp (PR #1232
    round 7), so every reader scenario that is not about those gates starts from one."""
    ep = T.episode(tmp_path)
    with Episode.open(ep) as episode:
        T.mod("learning.branch.outcome").write_outcome(episode, outcome, reason=reason)
    if outcome == "accepted":
        # PR #1232 round 7: the readers compare only a family `verify_family` stamped.
        from defender.tests.support.learning.judge._judge_921 import comparable_family_stamp

        comparable_family_stamp(ep)
    return ep


def _archived(tmp_path, worlds=T.WORLDS, **kw):
    ep = _accepted(tmp_path)
    for w in worlds:
        T.archived_world(ep, w, **kw)
    return ep


# M8 — what lands in the archive, and how it got there


def test_947_each_archived_world_carries_every_declared_artifact(tmp_path):
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = {w: T.sibling_run_dir(base, w) for w in T.WORLDS}
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    for w in T.WORLDS:
        world = ep / "worlds" / T.world_id(ep, w)
        for name in ("report.md", "investigation.md", "executed_queries.jsonl", "gather_raw",
                     "provenance.json", "scrub_verdict.json"):
            assert (world / name).exists(), f"{w} is missing {name}"
        assert not os.path.lexists(world / "run_dir"), f"{w}: the run_dir pointer was written"


def test_947_archive_copies_tables_through_stage_tables_and_artifact_file(tmp_path):
    """The archive copies through the existing screened paths and never through a raw copy"""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    run_dir = T.sibling_run_dir(base, "b")
    secret = tmp_path / "secret.md"
    secret.write_text("ROOT-PRIVATE-KEY", encoding="utf-8")
    (run_dir / "report.md").unlink()
    (run_dir / "report.md").symlink_to(secret)
    with Episode.open(ep) as episode, pytest.raises(T.refusals()):
        _archive().archive_episode(episode, {T.world_id(episode.dir, 'b'): run_dir})
    assert not (ep / "worlds" / T.world_id(ep, "b") / "report.md").exists()
    src_text = (T.DEFENDER / "learning" / "branch" / "archive.py").read_text(encoding="utf-8")
    assert "stage_tables" in src_text
    assert "artifact_file" in src_text


def test_947_archive_reads_the_scrub_verdict_at_its_sidecar_path(tmp_path):
    """The archive reads each sibling's scrub verdict at the sidecar path beside the run dir, through the same regular-file screen every other artifact..."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    run_dir = T.sibling_run_dir(base, "b", scrub_ran=True)
    assert not (run_dir / "scrub-verdict.json").exists()
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, 'b'): run_dir})
    copied = json.loads((ep / "worlds" / T.world_id(ep, "b") / "scrub_verdict.json").read_text(encoding="utf-8"))
    assert copied["ran"] is True


def test_947_the_archived_run_dir_pointer_is_never_followed(tmp_path):
    """No run-dir pointer is archived (R8): nothing is written at `worlds/<label>/run_dir`, and
    both derived readers answer identically when the arms they were archived from are gone.
    #1187 declared change 12
    """
    base, src = T.runs_base(tmp_path)
    ep = _accepted(tmp_path)
    dirs = {w: T.sibling_run_dir(base, w) for w in T.WORLDS}
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    pointer = ep / "worlds" / T.world_id(ep, "b") / "run_dir"
    assert not os.path.lexists(pointer), "the archive wrote the run_dir pointer"
    before = J.through_view(ep, _episode().verdicts)
    import shutil

    for d in dirs.values():
        shutil.rmtree(d)
    assert J.through_view(ep, _episode().verdicts) == before


def test_947_readers_compute_from_the_episode_dir_with_run_dirs_removed(tmp_path):
    import shutil

    base, src = T.runs_base(tmp_path)
    ep = _accepted(tmp_path)
    dirs = {w: T.sibling_run_dir(base, w) for w in T.WORLDS}
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    T.base_capture(ep, [T.captured_row(key="k1")])
    (ep / "served" / f"{T.fixture_world_id('b')}.jsonl").write_text(
        json.dumps(T.captured_row(key="k1", payload={"hits": [{"_id": "planted"}]})) + "\n",
        encoding="utf-8")
    before = (J.through_view(ep, _episode().delta_o), J.through_view(ep, _episode().verdicts))
    for d in dirs.values():
        shutil.rmtree(d)
    assert (J.through_view(ep, _episode().delta_o), J.through_view(ep, _episode().verdicts)) == before


def test_947_no_episode_reader_opens_a_siblings_run_dir(tmp_path):
    """Neither derived reader opens a sibling's run dir on any path: a run dir replaced by a
    directory that raises on every read is never touched, and both readers still answer."""
    base, src = T.runs_base(tmp_path)
    ep = _archived(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1")])
    src_text = "".join(
        (T.DEFENDER / "learning" / "branch" / "episode.py").read_text(encoding="utf-8"))
    assert "runs_base" not in src_text
    assert "resolve_runs_base" not in src_text
    assert J.through_view(ep, _episode().verdicts)
    assert J.through_view(ep, _episode().delta_o) is not None


# the two derived readers


def test_947_delta_o_returns_class_per_shared_correlation_key(tmp_path):
    ep = _archived(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1"), T.captured_row(key="k2")])
    (ep / "served" / f"{T.fixture_world_id('b')}.jsonl").write_text(
        json.dumps(T.captured_row(key="k1")) + "\n" +
        json.dumps(T.captured_row(key="k2", payload={"hits": [{"_id": "planted"}]})) + "\n",
        encoding="utf-8")
    out = J.through_view(ep, _episode().delta_o, invoke=T.FakeAgent("mutation"))
    assert out["b"]["k1"] == "same"
    assert out["b"]["k2"] in {"mutation", "undeclared"}


def test_947_delta_o_subtracts_the_controls_drift_keys(tmp_path):
    ep = _archived(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1"), T.captured_row(key="k2")])
    drifted = json.dumps(T.captured_row(key="k1", payload={"hits": [{"_id": "drift"}]}))
    for world in ("a", "b"):
        (ep / "served" / f"{T.fixture_world_id(world)}.jsonl").write_text(
            drifted + "\n" + json.dumps(T.captured_row(key="k2")) + "\n", encoding="utf-8")
    out = J.through_view(ep, _episode().delta_o, invoke=T.FakeAgent(*["mutation"] * 6))
    assert "k1" not in out.get("b", {})


def test_947_verdicts_returns_disposition_per_world(tmp_path):
    """The per-world reader returns one disposition per archived world, read from that world's
    own archived report."""
    ep = _accepted(tmp_path)
    T.archived_world(ep, "a", disposition="benign")
    T.archived_world(ep, "b", disposition="malicious")
    assert J.through_view(ep, _episode().verdicts) == {"a": "benign", "b": "malicious"}


def test_947_verdicts_refuses_disposition_outside_enum(tmp_path):
    """The per-world reader inherits the shipped disposition membership gate rather than
    re-implementing it: an archived report naming a value outside that vocabulary refuses."""
    ep = _accepted(tmp_path)
    T.archived_world(ep, "a", disposition="probably-bad")
    with pytest.raises(T.refusals()) as bad:
        J.through_view(ep, _episode().verdicts)
    assert "probably-bad" in str(bad.value)


def test_947_readers_over_an_episode_with_no_archived_worlds_return_empty(tmp_path):
    ep = _accepted(tmp_path)
    (ep / "worlds").mkdir(exist_ok=True)
    assert J.through_view(ep, _episode().verdicts) == {}
    assert J.through_view(ep, _episode().delta_o) == {}


@pytest.mark.parametrize("outcome", ["unusable", "refused", None])
def test_947_the_derived_readers_refuse_to_compare_an_incomplete_episode(tmp_path, outcome):
    """The derived readers refuse to compare an episode whose recorded outcome is anything but `accepted` — `unusable`, `refused`, or no record at all..."""
    if outcome is None:
        ep = T.episode(tmp_path)
    else:
        ep = _accepted(tmp_path, outcome=outcome, reason="two worlds failed calibration")
    for w in ("a", "b"):
        T.archived_world(ep, w)
    for reader in (_episode().delta_o, _episode().verdicts):
        with pytest.raises(T.refusals()) as bad:
            J.through_view(ep, reader)
        assert (outcome or "no outcome record") in str(bad.value), reader.__name__


# §7 FORK-13 + §7 round 2 (F5-EPISODE-ROOT) — containment, and where the episodes root lives


def _clean_checkout(tmp_path):
    """A real, committed git checkout carrying `_provenance.CODE_SCOPE` — the tree a sibling's
    stamp is taken over. Committed, so `capture_tree` over it answers `dirty: False` until
    something puts an untracked file inside it."""
    import subprocess

    checkout = tmp_path / "workspace"
    (checkout / T.sym("records._provenance", "CODE_SCOPE")).mkdir(parents=True)
    (checkout / T.sym("records._provenance", "CODE_SCOPE") / "run.py").write_text("x\n", encoding="utf-8")
    for argv in (["init", "-q", "-b", "main"], ["add", "-A"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"]):
        subprocess.run(["git", *argv], cwd=checkout, check=True, capture_output=True)
    return checkout


def _relocated(tmp_path, monkeypatch):
    """The relocated layout, built through the production resolver: a runs base holding only the
    source run, and an episode `runs.create_episode()` claims under the tenant's own
    `<T>/episodes/`, with this episode's three sibling arms in its own container at the ids its
    roster names (`view.start_runs`) — the container the child processes are handed."""
    from defender.tests.storage.ids_1187 import _spec1187 as S

    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    tenant = _tenant_paths()
    with tenant.runs_repository().create_episode() as view:
        ep = S.episodes_dir(tenant.data_root, str(tenant.id)) / view.episode_id
        T.write_family(ep, T.family_doc(episode_id=view.episode_id))
        arms = view.start_runs([T.world_id(ep, label) for label in T.WORLDS])
    for w in T.WORLDS:
        T.sibling_run_dir(ep / "runs", w, arm_id=str(arms[T.world_id(ep, w)]))
    return base, src, root, ep


def _arm(ep, world_id):
    """The arm folder the episode's roster (`arms.json`) names for `world_id`."""
    return ep / "runs" / T.read_roster(ep)[T.world_id(ep, world_id)]


def test_947_no_sibling_artifact_is_reachable_by_a_runs_base_walk(tmp_path, monkeypatch):
    """No sibling artifact is reachable by a walk of the runs base"""
    base, src, root, ep = _relocated(tmp_path, monkeypatch)
    for w in T.WORLDS:
        T.archived_world(ep, w)
    assert ep != base
    assert base not in ep.parents
    for name in ("investigation.md", "provenance.json", "executed_queries.jsonl"):
        found = sorted(str(p.relative_to(base)) for p in base.rglob(name))
        assert found == [f"{T.SOURCE_RUN_ID}/{name}"], f"{name}: {found}"
    assert not list(base.rglob("family.yaml"))


def test_947_a_runs_base_walk_still_finds_an_ordinary_run(tmp_path, monkeypatch):
    base, src, root, ep = _relocated(tmp_path, monkeypatch)
    # The source's tenant, by its tenant location `<root>/<T>/runs/<id>` (#1105 PR 2: the
    # run-folder-to-tenant derivation `tenant_of_run_dir` is gone, F-13).
    tenant_id = src.parent.parent.name
    ordinary = T.mod("run_common").materialize_run(
        RunPaths(src).alert, fixture_uuid("947-archive-ordinary-run"),
        tenant=T1106.accept(current_data_root(), tenant_id)).run_dir
    assert ordinary.parent == base
    found = sorted(p.parent.name for p in base.rglob("provenance.json"))
    assert found == sorted([T.SOURCE_RUN_ID, ordinary.name])


def test_947_the_episode_dir_is_outside_the_runs_base(tmp_path, monkeypatch):
    """The episode dir is outside the runs base AND outside the checkout: every recursive walker
    of the base descends into every directory under it, and an untracked directory inside the
    checkout is what a sibling's own provenance stamp reports as a dirty tree."""
    from defender.tests.storage.ids_1187 import _spec1187 as S

    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    tenant = _tenant_paths()
    episodes = S.episodes_dir(tenant.data_root, str(tenant.id))
    repo_root = T.mod("run_common").REPO_ROOT
    # configured_layout now returns the REAL tenant episodes root, so use a distinct decoy.
    for bad in (tmp_path / "retired-episodes-root", base / "episodes", repo_root / "episodes"):
        existed = os.path.lexists(bad)
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(bad))
        with tenant.runs_repository().create_episode() as view:
            ep = episodes / view.episode_id
        assert ep.is_dir(), f"with the variable at {bad}, no episode was claimed under {episodes}"
        assert base not in ep.parents, f"{ep} was claimed inside the runs base"
        assert repo_root not in ep.parents, f"{ep} was claimed inside the checkout"
        assert os.path.lexists(bad) == existed, f"the variable's folder {bad} was created"


def test_947_the_episodes_root_is_read_from_configuration_not_the_runs_base(tmp_path, monkeypatch):
    """The episodes root is NEVER derived from the runs base: with the tenant held fixed,
    re-pointing the runs base does not move where an episode is claimed, and the episode lands
    beside the runs base, never inside it.

    #1187 declared change 5: the root is no longer read from configuration either. It is the
    accepted tenant's own `<T>/episodes/`, claimed by `runs.create_episode()`, and
    `DEFENDER_EPISODES_BASE` is ignored — so the configured root stays empty and an unset
    variable is no refusal (the `episode_dir` resolver and its refusals are retired; pinned by
    `ids_1187/test_1187_layout_isolation.py::test_the_episodes_variable_changes_nothing_and_no_episodes_root_refusal_fires`).
    (Name kept.)
    """
    from defender.tests.storage.ids_1187 import _spec1187 as S

    base, src, _actual_root = T.configured_layout(tmp_path, monkeypatch)
    root = tmp_path / "retired-episodes-root"
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(root))
    tenant = _tenant_paths()
    episodes = S.episodes_dir(tenant.data_root, str(tenant.id))
    with tenant.runs_repository().create_episode() as view:
        before = view.episode_id
    assert (episodes / before).is_dir(), f"the episode was not claimed under {episodes}"
    assert base not in (episodes / before).parents, "the episode was claimed inside the runs base"
    elsewhere = tmp_path / "somewhere-else"
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(elsewhere))
    monkeypatch.delenv(T.EPISODES_BASE_ENV, raising=False)  # review-3 F35: nothing need set it (#1187 O9)
    with tenant.runs_repository().create_episode() as view:
        after = view.episode_id
    assert sorted(os.listdir(episodes)) == sorted([before, after]), (
        "re-pointing the runs base (or unsetting the episodes variable) moved the episode")
    assert not os.path.lexists(elsewhere), "an episode was claimed under the re-pointed runs base"
    assert not os.path.lexists(root) or os.listdir(root) == [], (
        "an episode was claimed under the configured episodes root")


def test_947_the_episode_dirs_placement_never_dirties_a_siblings_stamp(tmp_path, monkeypatch):
    """An episode's own placement never dirties a sibling's provenance stamp: with the runs base
    inside a checkout — the shape the devcontainer documents — the episode dir, its manifest and
    its sibling run dirs all land outside that checkout, so a stamp captured over it still reads
    a clean tree and the family completes without the dirty override."""
    from defender.tests.storage.ids_1187 import _spec1187 as S

    checkout = _clean_checkout(tmp_path)
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(checkout / ".defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(checkout / "episodes-root"))
    tenant = _tenant_paths()
    with tenant.runs_repository().create_episode() as view:
        ep = S.episodes_dir(tenant.data_root, str(tenant.id)) / view.episode_id
        T.write_family(ep, T.family_doc(episode_id=view.episode_id))
    T.write_family(ep)
    S.make_run(ep / "runs", S.new_id())
    assert ep.is_dir(), ep
    assert checkout not in ep.parents
    assert not os.path.lexists(checkout / "episodes-root"), (
        "the episodes variable's folder inside the checkout was created")
    capture_tree = T.sym("records._provenance", "capture_tree")
    stamp = capture_tree(checkout)
    assert stamp.dirty is False, f"the episode dirtied the checkout: {stamp.dirty_paths}"
    assert stamp.unavailable is None
    (checkout / T.sym("records._provenance", "CODE_SCOPE") / "untracked.txt").write_text(
        "x\n", encoding="utf-8")
    assert capture_tree(checkout).dirty is True, (
        "positive control: an untracked file inside the checkout reads dirty")


def test_947_a_sibling_run_dir_lives_under_the_episode_not_the_runs_base(tmp_path, monkeypatch):
    """A sibling's run dir lives under its own episode rather than beside the source run: the
    child process is handed its EPISODE by id (#1105 PR 2, declared change 6: `--episode <ep>`),
    which it opens under the configured episodes root and whose container (`<episode>/runs`, made
    with the tenant's record before the first sibling) is its runs base.

    #1078 D2 (brief R2, settled s104): the launcher sets NO `DEFENDER_RUNS_BASE` of its own. A
    child's value is the parent's, inherited unchanged (J46) — the stale configured base here —
    never one the launcher composed."""
    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    spawn = T.FakeSpawn()
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src.resolve())))
    with Episode.open(ep) as episode:
        # The launcher makes the container before the first sibling (#1105 PR 2).
        T.episode_view(episode)
        T.mod("learning.branch.cli").start_family(
            episode, [T.world_id(ep, label) for label in T.WORLDS], spawn=spawn, tenant_id=T.SOURCE_TENANT)
    assert spawn.launches, "no sibling was started"
    for launch in spawn.launches:
        assert launch["env"].get("DEFENDER_RUNS_BASE") == str(base), (
            "the launcher composed a runs base of its own for a sibling: "
            f"{launch['env'].get('DEFENDER_RUNS_BASE')}")
        argv = launch["argv"]
        assert argv[argv.index("--episode") + 1] == ep.name, argv


def test_947_the_lesson_tracer_counts_no_sibling_as_an_in_context_case(tmp_path, monkeypatch):
    """The lesson tracer counts no sibling as an in-context case"""
    base, src, root, ep = _relocated(tmp_path, monkeypatch)
    trace = T.mod("cli.learning.trace_lesson")
    T.lesson_row(src)
    for w in T.WORLDS:
        T.lesson_row(_arm(ep, w))
    # #1105 PR 2 (declared change 10, J8): the tracer walks the tenant's own runs, by id.
    runs = trace.tenant_runs(base.parent.name)
    assert [hit.case_id for hit in trace.in_context_cases("L1", None, runs)] == [T.SOURCE_RUN_ID]


def test_947_the_invlang_corpus_counts_no_sibling_and_no_archived_world(tmp_path, monkeypatch):
    """The orientation corpus counts no sibling and no archived world"""
    base, src, root, ep = _relocated(tmp_path, monkeypatch)
    corpus = T.mod("skills.invlang.corpus")
    T.corpus_document(src)
    for w in T.WORLDS:
        T.corpus_document(_arm(ep, w))
        T.corpus_document(T.archived_world(ep, w))
    companions, report = corpus.load_corpus(base)
    assert [c.case_id for c in companions] == [T.SOURCE_RUN_ID]
    assert report.scanned == 1, f"the walk descended into the episode: {report.scanned} documents"
