"""#947 — the archive, its two derived readers, and where a sibling's artifacts may live (M8, O4, O7"""
from __future__ import annotations

import json

import pytest

from defender import _episode_handle as EH
from defender._episode_handle import Episode
from defender.tests import _tenants1106 as T1106
from defender.run_repository import RunPaths
from defender.tests._alert_plant import plant_alert
from defender.tests import _triplet_947 as T
from defender.tests._data_root_1078 import current_data_root


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
        from defender.tests._judge_921 import comparable_family_stamp

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
        _archive().archive_episode(episode, dirs)
    for w in T.WORLDS:
        world = ep / "worlds" / w
        for name in ("report.md", "investigation.md", "executed_queries.jsonl", "gather_raw",
                     "provenance.json", "scrub_verdict.json", "run_dir"):
            assert (world / name).exists(), f"{w} is missing {name}"


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
        _archive().archive_episode(episode, {"b": run_dir})
    assert not (ep / "worlds" / "b" / "report.md").exists()
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
        _archive().archive_episode(episode, {"b": run_dir})
    copied = json.loads((ep / "worlds" / "b" / "scrub_verdict.json").read_text(encoding="utf-8"))
    assert copied["ran"] is True


def test_947_the_archived_run_dir_pointer_is_never_followed(tmp_path):
    """The archived run-dir pointer is informational only: it is a text file, not a link, and
    both derived readers answer identically when the path it names no longer exists."""
    base, src = T.runs_base(tmp_path)
    ep = _accepted(tmp_path)
    dirs = {w: T.sibling_run_dir(base, w) for w in T.WORLDS}
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, dirs)
    pointer = ep / "worlds" / "b" / "run_dir"
    assert not pointer.is_symlink()
    before = _episode().verdicts(ep)
    import shutil

    for d in dirs.values():
        shutil.rmtree(d)
    assert _episode().verdicts(ep) == before


def test_947_readers_compute_from_the_episode_dir_with_run_dirs_removed(tmp_path):
    import shutil

    base, src = T.runs_base(tmp_path)
    ep = _accepted(tmp_path)
    dirs = {w: T.sibling_run_dir(base, w) for w in T.WORLDS}
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, dirs)
    T.base_capture(ep, [T.captured_row(key="k1")])
    (ep / "served" / f"{T.world_token('b')}.jsonl").write_text(
        json.dumps(T.captured_row(key="k1", payload={"hits": [{"_id": "planted"}]})) + "\n",
        encoding="utf-8")
    before = (_episode().delta_o(ep), _episode().verdicts(ep))
    for d in dirs.values():
        shutil.rmtree(d)
    assert (_episode().delta_o(ep), _episode().verdicts(ep)) == before


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
    assert _episode().verdicts(ep)
    assert _episode().delta_o(ep) is not None


# the two derived readers


def test_947_delta_o_returns_class_per_shared_correlation_key(tmp_path):
    ep = _archived(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1"), T.captured_row(key="k2")])
    (ep / "served" / f"{T.world_token('b')}.jsonl").write_text(
        json.dumps(T.captured_row(key="k1")) + "\n" +
        json.dumps(T.captured_row(key="k2", payload={"hits": [{"_id": "planted"}]})) + "\n",
        encoding="utf-8")
    out = _episode().delta_o(ep, invoke=T.FakeAgent("mutation"))
    assert out["b"]["k1"] == "same"
    assert out["b"]["k2"] in {"mutation", "undeclared"}


def test_947_delta_o_subtracts_the_controls_drift_keys(tmp_path):
    ep = _archived(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1"), T.captured_row(key="k2")])
    drifted = json.dumps(T.captured_row(key="k1", payload={"hits": [{"_id": "drift"}]}))
    for world in ("a", "b"):
        (ep / "served" / f"{T.world_token(world)}.jsonl").write_text(
            drifted + "\n" + json.dumps(T.captured_row(key="k2")) + "\n", encoding="utf-8")
    out = _episode().delta_o(ep, invoke=T.FakeAgent(*["mutation"] * 6))
    assert "k1" not in out.get("b", {})


def test_947_verdicts_returns_disposition_per_world(tmp_path):
    """The per-world reader returns one disposition per archived world, read from that world's
    own archived report."""
    ep = _accepted(tmp_path)
    T.archived_world(ep, "a", disposition="benign")
    T.archived_world(ep, "b", disposition="malicious")
    assert _episode().verdicts(ep) == {"a": "benign", "b": "malicious"}


def test_947_verdicts_refuses_disposition_outside_enum(tmp_path):
    """The per-world reader inherits the shipped disposition membership gate rather than
    re-implementing it: an archived report naming a value outside that vocabulary refuses."""
    ep = _accepted(tmp_path)
    T.archived_world(ep, "a", disposition="probably-bad")
    with pytest.raises(T.refusals()) as bad:
        _episode().verdicts(ep)
    assert "probably-bad" in str(bad.value)


def test_947_readers_over_an_episode_with_no_archived_worlds_return_empty(tmp_path):
    ep = _accepted(tmp_path)
    (ep / "worlds").mkdir(exist_ok=True)
    assert _episode().verdicts(ep) == {}
    assert _episode().delta_o(ep) == {}


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
            reader(ep)
        assert (outcome or "no outcome record") in str(bad.value), reader.__name__


# §7 FORK-13 + §7 round 2 (F5-EPISODE-ROOT) — containment, and where the episodes root lives


def _clean_checkout(tmp_path):
    """A real, committed git checkout carrying `_provenance.CODE_SCOPE` — the tree a sibling's
    stamp is taken over. Committed, so `capture_tree` over it answers `dirty: False` until
    something puts an untracked file inside it."""
    import subprocess

    checkout = tmp_path / "workspace"
    (checkout / T.sym("_provenance", "CODE_SCOPE")).mkdir(parents=True)
    (checkout / T.sym("_provenance", "CODE_SCOPE") / "run.py").write_text("x\n", encoding="utf-8")
    for argv in (["init", "-q", "-b", "main"], ["add", "-A"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"]):
        subprocess.run(["git", *argv], cwd=checkout, check=True, capture_output=True)
    return checkout


def _relocated(tmp_path, monkeypatch):
    """The relocated layout, built through the production resolver"""
    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    ep = EH.episode_dir(_tenant_paths().data_root, T.EPISODE_ID)
    for w in T.WORLDS:
        T.sibling_run_dir(ep / "runs", w)
    return base, src, root, ep


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
        RunPaths(src).alert, "20260728t170000z-other",
        tenant=T1106.accept(current_data_root(), tenant_id)).run_dir
    assert ordinary.parent == base
    found = sorted(p.parent.name for p in base.rglob("provenance.json"))
    assert found == sorted([T.SOURCE_RUN_ID, ordinary.name])


def test_947_the_episode_dirs_placement_never_dirties_a_siblings_stamp(tmp_path, monkeypatch):
    """An episode's own placement never dirties a sibling's provenance stamp"""
    checkout = _clean_checkout(tmp_path)
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(checkout / ".defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    ep = EH.episode_dir(_tenant_paths().data_root, T.EPISODE_ID)
    T.write_family(ep)
    T.sibling_run_dir(ep / "runs", "b")
    assert ep != checkout
    assert checkout not in ep.parents
    stamp = T.sym("_provenance", "capture_tree")(checkout)
    assert stamp.dirty is False, f"the episode dirtied the checkout: {stamp.dirty_paths}"
    assert stamp.unavailable is None


def test_947_the_held_out_index_never_selects_a_sibling_for_a_fixture_slug(tmp_path, monkeypatch):
    """The held-out index never selects a sibling for a fixture slug, whatever world label was chosen"""
    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    held_out = T.mod("evals.held_out")
    slug = "web-1-suspicious-binary"
    (base / slug).mkdir(parents=True)
    plant_alert(base / slug, {"rule": {"id": slug}})
    ep = EH.episode_dir(_tenant_paths().data_root, T.EPISODE_ID)
    for label in ("a", "b", slug):
        (ep / "runs" / f"{slug}-n3-{label}").mkdir(parents=True)
    resolved = held_out.index_runs([slug], base)
    assert resolved[slug].name == slug


def test_947_the_lesson_tracer_counts_no_sibling_as_an_in_context_case(tmp_path, monkeypatch):
    """The lesson tracer counts no sibling as an in-context case"""
    base, src, root, ep = _relocated(tmp_path, monkeypatch)
    trace = T.mod("learning.ops.trace_lesson")
    T.lesson_row(src)
    for w in T.WORLDS:
        T.lesson_row(ep / "runs" / f"{T.EPISODE_ID}-{w}")
    # #1105 PR 2 (declared change 10, J8): the tracer walks the tenant's own runs, by id.
    runs = trace.tenant_runs(base.parent.name)
    assert [hit.case_id for hit in trace.in_context_cases("L1", None, runs)] == [T.SOURCE_RUN_ID]


def test_947_the_invlang_corpus_counts_no_sibling_and_no_archived_world(tmp_path, monkeypatch):
    """The orientation corpus counts no sibling and no archived world"""
    base, src, root, ep = _relocated(tmp_path, monkeypatch)
    corpus = T.mod("skills.invlang.corpus")
    T.corpus_document(src)
    for w in T.WORLDS:
        T.corpus_document(ep / "runs" / f"{T.EPISODE_ID}-{w}")
        T.corpus_document(T.archived_world(ep, w))
    companions, report = corpus.load_corpus(base)
    assert [c.case_id for c in companions] == [T.SOURCE_RUN_ID]
    assert report.scanned == 1, f"the walk descended into the episode: {report.scanned} documents"
