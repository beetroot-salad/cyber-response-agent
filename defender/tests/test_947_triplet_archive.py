"""#947 — the archive, its two derived readers, and where a sibling's artifacts may live
(M8, O4, O7; §7 FORK-13).

D3: the episode dir is self-contained. After the runs it holds, per world, the report, the
investigation document, the two tables, the stamp and the scrub verdict; `delta_o` and the
verdicts compute from that directory alone, with no re-run and no path outside it.

**The scrub verdict is a SIDECAR beside the run dir** (G17, refuted): `verdict_path(tree)` is
`tree.parent / f"{tree.name}.scrub-verdict.json"`, sited outside the tree it judges on purpose.
So the archive reaches a runs-base path, not a run-dir one — a copy written against the design's
"inside the run dir" sentence would copy a file that is never there.

**Sibling artifacts move OUT of the runs base**, and the episode dir with them (§7 FORK-13,
resolved by the human on 48-consumers-probe and 4a-relocation-probe, both executed). At §7
round 2 the human moved the episodes root further still: it is a CONFIGURED location, outside
both the runs base and the checkout, and is NEVER derived from the runs base — deriving it is
what put `episodes/` back inside the tree the corpus walker descends and inside the checkout a
sibling's own stamp is taken over. Three consumers walk that base and cannot tell a synthetic
sibling from a real run:

* `evals/held_out.py::index_runs` — under the launch convention `held_out.py` itself prescribes,
  every sibling claims the real run's slug by prefix and mtime recency hands the score to the
  newest, so a sibling DISPLACES the real run. Dormant only because the fixture set is committed
  empty.
* `learning/ops/trace_lesson.py::in_context_cases` — admits all three siblings; one episode
  turns one investigation into four hits.
* `skills/invlang/corpus.py::load_corpus` — in NO census before this run, reached through the
  `defender-invlang` shim at every ordinary run's ORIENT: one episode moved the printed
  denominator 2 → 5 and multiplied every ranked count fourfold, because siblings inherit the
  source's alert and document prefix byte for byte.

The three consumer demands are REGRESSION witnesses in the relocated layout, not the per-reader
filter the human refused: each builds the layout through the production resolver and asserts the
walker is unaffected. Adding sibling-filtering logic to `held_out.py`, `trace_lesson.py` or
`invlang/corpus.py` is option (C), and option (C) is not the answer this seam took.

RED against b8a63e66: `learning/branch/archive.py` and `learning/branch/episode.py` do not exist
(X16), the episode dir is built INSIDE the runs base (`cli.py:146`), and there is no configured
episodes root at all.
"""
from __future__ import annotations

import json

import pytest

from defender.tests import _triplet_947 as T


def _archive():
    return T.mod("learning.branch.archive")


def _episode():
    return T.mod("learning.branch.episode")


def _archived(tmp_path, worlds=T.WORLDS, **kw):
    ep = T.episode(tmp_path)
    for w in worlds:
        T.archived_world(ep, w, **kw)
    return ep


# ---------------------------------------------------------------------------------------
# M8 — what lands in the archive, and how it got there
# ---------------------------------------------------------------------------------------


def test_947_each_archived_world_carries_every_declared_artifact(tmp_path):
    """Each archived world carries every artifact the archived-world row declares: the report,
    the investigation document, the two tables, the stamp, the scrub verdict and the run-dir
    pointer — six roles, none sourced from another."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = {w: T.sibling_run_dir(base, w) for w in T.WORLDS}
    _archive().archive_episode(ep, dirs)
    for w in T.WORLDS:
        world = ep / "worlds" / w
        for name in ("report.md", "investigation.md", "executed_queries.jsonl", "gather_raw",
                     "provenance.json", "scrub_verdict.json", "run_dir"):
            assert (world / name).exists(), f"{w} is missing {name}"


def test_947_archive_copies_tables_through_stage_tables_and_artifact_file(tmp_path):
    """The archive copies through the existing screened paths and never through a raw copy: the
    two tables go through the repository's own staging helper, and each single file through the
    regular-file screen — so a link planted at an artifact's name in a model-writable run dir is
    refused rather than followed."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    run_dir = T.sibling_run_dir(base, "b")
    secret = tmp_path / "secret.md"
    secret.write_text("ROOT-PRIVATE-KEY", encoding="utf-8")
    (run_dir / "report.md").unlink()
    (run_dir / "report.md").symlink_to(secret)
    with pytest.raises(T.refusals()):
        _archive().archive_episode(ep, {"b": run_dir})
    assert not (ep / "worlds" / "b" / "report.md").exists()
    src_text = (T.DEFENDER / "learning" / "branch" / "archive.py").read_text(encoding="utf-8")
    assert "stage_tables" in src_text
    assert "artifact_file" in src_text


def test_947_archive_reads_the_scrub_verdict_at_its_sidecar_path(tmp_path):
    """The archive reads each sibling's scrub verdict at the sidecar path beside the run dir,
    through the same regular-file screen every other artifact goes through — the verdict is
    deliberately written OUTSIDE the tree it judges, so a run-dir-scoped copy would find
    nothing and archive a world with no verdict at all."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    run_dir = T.sibling_run_dir(base, "b", scrub_ran=True)
    assert not (run_dir / "scrub-verdict.json").exists()
    _archive().archive_episode(ep, {"b": run_dir})
    copied = json.loads((ep / "worlds" / "b" / "scrub_verdict.json").read_text(encoding="utf-8"))
    assert copied["ran"] is True


def test_947_the_archived_run_dir_pointer_is_never_followed(tmp_path):
    """The archived run-dir pointer is informational only: it is a text file, not a link, and
    both derived readers answer identically when the path it names no longer exists."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = {w: T.sibling_run_dir(base, w) for w in T.WORLDS}
    _archive().archive_episode(ep, dirs)
    pointer = ep / "worlds" / "b" / "run_dir"
    assert not pointer.is_symlink()
    before = _episode().verdicts(ep)
    import shutil

    for d in dirs.values():
        shutil.rmtree(d)
    assert _episode().verdicts(ep) == before


def test_947_readers_compute_from_the_episode_dir_with_run_dirs_removed(tmp_path):
    """Both derived readers compute from the episode dir alone: with every sibling's run dir
    removed from disk, the per-key classification and the per-world disposition are still
    produced, unchanged."""
    import shutil

    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = {w: T.sibling_run_dir(base, w) for w in T.WORLDS}
    _archive().archive_episode(ep, dirs)
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


# ---------------------------------------------------------------------------------------
# the two derived readers
# ---------------------------------------------------------------------------------------


def test_947_delta_o_returns_class_per_shared_correlation_key(tmp_path):
    """The per-key reader returns one class for every correlation key the base and a world both
    hold: equal canonical text answers `same`, and a difference is classified by the comparator
    against the world's own declared axis."""
    ep = _archived(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1"), T.captured_row(key="k2")])
    (ep / "served" / f"{T.world_token('b')}.jsonl").write_text(
        json.dumps(T.captured_row(key="k1")) + "\n" +
        json.dumps(T.captured_row(key="k2", payload={"hits": [{"_id": "planted"}]})) + "\n",
        encoding="utf-8")
    out = _episode().delta_o(ep, invoke=T.FakeAgent("mutation"))
    assert out["b"]["k1"] == "same"
    assert out["b"]["k2"] in {"mutation", "undeclared"}


def test_947_delta_o_pairs_on_asked_form_not_run_form(tmp_path):
    """The per-key reader pairs on the form ASKED, never on the prepared form: a staged world's
    prepared parameters differ from the base's by construction, so a pairing keyed on them would
    match nothing at all."""
    ep = _archived(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1", params={"index": T.EVENTS_PATTERN})])
    staged = T.captured_row(key="k1", params={"index": f"wv-{T.world_token('b')}-logs-"})
    staged["asked_params"] = {"index": T.EVENTS_PATTERN}
    (ep / "served" / f"{T.world_token('b')}.jsonl").write_text(
        json.dumps(staged) + "\n", encoding="utf-8")
    out = _episode().delta_o(ep, invoke=T.FakeAgent("mutation"))
    assert "k1" in out["b"], "the staged row never paired with its base row"


def test_947_delta_o_subtracts_the_controls_drift_keys(tmp_path):
    """The per-key reader subtracts the control's drift keys the way the review does: a key the
    control world also differs on is not reported as a world's own difference, or the one
    measurement the downstream judge consumes becomes noise."""
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
    ep = T.episode(tmp_path)
    T.archived_world(ep, "a", disposition="benign")
    T.archived_world(ep, "b", disposition="malicious")
    assert _episode().verdicts(ep) == {"a": "benign", "b": "malicious"}


def test_947_verdicts_refuses_disposition_outside_enum(tmp_path):
    """The per-world reader inherits the shipped disposition membership gate rather than
    re-implementing it: an archived report naming a value outside that vocabulary refuses."""
    ep = T.episode(tmp_path)
    T.archived_world(ep, "a", disposition="probably-bad")
    with pytest.raises(T.refusals()) as bad:
        _episode().verdicts(ep)
    assert "probably-bad" in str(bad.value)


def test_947_readers_over_an_episode_with_no_archived_worlds_return_empty(tmp_path):
    """Both readers answer EMPTY on an archived episode holding no worlds rather than raising:
    an episode rejected before step 5 is a legitimate archived state, and the episode's own
    recorded outcome is what tells "no worlds" apart from "no differences"."""
    ep = T.episode(tmp_path)
    (ep / "worlds").mkdir(exist_ok=True)
    assert _episode().verdicts(ep) == {}
    assert _episode().delta_o(ep) == {}


def test_947_the_derived_readers_refuse_to_compare_an_incomplete_episode(tmp_path):
    """The derived readers refuse to compare an episode whose recorded outcome is incomplete:
    the family stamp was withheld, so the worlds that ARE archived are not comparable and a
    silent per-key answer over them would read as a measurement."""
    ep = _archived(tmp_path, worlds=("a", "b"))
    (ep / "review.yaml").write_text(
        json.dumps({"episode": {"outcome": "incomplete", "reason": "one scrub unverified"}}),
        encoding="utf-8")
    with pytest.raises(T.refusals()) as bad:
        _episode().delta_o(ep)
    assert "incomplete" in str(bad.value)


# ---------------------------------------------------------------------------------------
# §7 FORK-13 + §7 round 2 (F5-EPISODE-ROOT) — containment, and where the episodes root lives
#
# The human's round-1 answer was RELOCATION, not a per-reader filter, and round 2 moved the
# episodes root further: it is a CONFIGURED location, outside both the runs base and the
# checkout, and is never derived from the runs base. So the three consumer demands below are
# REGRESSION witnesses in the relocated layout — each builds the layout through the production
# resolver and asserts the walker is unaffected — and not the filtering demands the human
# refused. Every scenario here is rooted in `tmp_path` through the two configured roots: a
# fixture that mixed a tmp runs base with a production episode dir asserts about two different
# worlds and is true whatever the implementation does.
# ---------------------------------------------------------------------------------------


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
    """The relocated layout, built through the production resolver: a runs base holding only the
    source run, and an episode dir `episode_dir_for` places under the CONFIGURED episodes root,
    with this episode's three sibling run dirs under the runs root the child processes are handed.

    Nothing here hand-places an episode: the whole point of the demand is WHERE the production
    resolver puts one, so a fixture that chose the path itself would assert about its own
    arithmetic.
    """
    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    ep = T.mod("learning.branch.cli").episode_dir_for(T.EPISODE_ID)
    for w in T.WORLDS:
        T.sibling_run_dir(ep / "runs", w)
    return base, src, root, ep


def test_947_no_sibling_artifact_is_reachable_by_a_runs_base_walk(tmp_path, monkeypatch):
    """No sibling artifact is reachable by a walk of the runs base: with an episode's three
    siblings run and archived, a recursive walk of the base finds the source run's own document,
    stamp and queries table and NOTHING of the episode — no sibling run dir, no archived world,
    and no episode directory for a walker to descend into."""
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
    """The positive control for the containment negative: an ORDINARY run materialised into the
    same base by the same production writer IS found by the same walk, so the emptiness above is
    a relocated episode rather than a walk that sees nothing."""
    base, src, root, ep = _relocated(tmp_path, monkeypatch)
    ordinary = T.mod("run_common").materialize_run_dir(src / "alert.json", "20260728T170000Z-other")
    assert ordinary.parent == base
    found = sorted(p.parent.name for p in base.rglob("provenance.json"))
    assert found == sorted([T.SOURCE_RUN_ID, ordinary.name])


def test_947_the_episode_dir_is_outside_the_runs_base(tmp_path, monkeypatch):
    """The episode dir is outside the runs base AND outside the checkout: every recursive walker
    of the base descends into every directory under it, and an untracked directory inside the
    checkout is what a sibling's own provenance stamp reports as a dirty tree — so the episodes
    root is refused if it resolves inside either."""
    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    cli = T.mod("learning.branch.cli")
    ep = cli.episode_dir_for(T.EPISODE_ID)
    assert ep != base
    assert base not in ep.parents
    assert T.mod("run_common").REPO_ROOT not in ep.parents
    for bad in (base / "episodes", T.mod("run_common").REPO_ROOT / "episodes"):
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(bad))
        with pytest.raises(T.refusals()) as refusal:
            cli.episode_dir_for(T.EPISODE_ID)
        assert str(bad) in str(refusal.value)


def test_947_the_episodes_root_is_read_from_configuration_not_the_runs_base(tmp_path, monkeypatch):
    """The episodes root is READ FROM CONFIGURATION and never derived from the runs base: with
    the configuration held fixed, re-pointing the runs base does not move a single episode dir,
    and with the configuration absent the launcher refuses rather than inventing a location
    under the runs base."""
    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    cli = T.mod("learning.branch.cli")
    before = cli.episode_dir_for(T.EPISODE_ID)
    assert before.parent == root
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "somewhere-else"))
    assert cli.episode_dir_for(T.EPISODE_ID) == before
    monkeypatch.delenv(T.EPISODES_BASE_ENV)
    with pytest.raises(T.refusals()) as refusal:
        cli.episode_dir_for(T.EPISODE_ID)
    assert T.EPISODES_BASE_ENV in str(refusal.value)


def test_947_the_episode_dirs_placement_never_dirties_a_siblings_stamp(tmp_path, monkeypatch):
    """An episode's own placement never dirties a sibling's provenance stamp: with the runs base
    inside a checkout — the shape the devcontainer documents — the episode dir, its manifest and
    its sibling run dirs all land outside that checkout, so a stamp captured over it still reads
    a clean tree and the family completes without the dirty override."""
    checkout = _clean_checkout(tmp_path)
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(checkout / ".defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    ep = T.mod("learning.branch.cli").episode_dir_for(T.EPISODE_ID)
    T.write_family(ep)
    T.sibling_run_dir(ep / "runs", "b")
    assert ep != checkout
    assert checkout not in ep.parents
    stamp = T.sym("_provenance", "capture_tree")(checkout)
    assert stamp.dirty is False, f"the episode dirtied the checkout: {stamp.dirty_paths}"
    assert stamp.unavailable is None


def test_947_a_sibling_run_dir_lives_under_the_episode_not_the_runs_base(tmp_path, monkeypatch):
    """A sibling's run dir lives under its own episode rather than beside the source run: the
    child process is handed a runs base inside the episode dir, and the source's own store still
    resolves because the manifest names the source run by absolute path."""
    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    spawn = T.FakeSpawn()
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src.resolve())))
    T.mod("learning.branch.cli").start_family(ep, ["a", "b", "c"], spawn=spawn)
    assert spawn.launches, "no sibling was started"
    for launch in spawn.launches:
        child_base = launch["env"]["DEFENDER_RUNS_BASE"]
        assert child_base.startswith(str(ep)), child_base
        assert not child_base.startswith(str(base) + "/")


def test_947_the_held_out_index_never_selects_a_sibling_for_a_fixture_slug(tmp_path, monkeypatch):
    """The held-out index never selects a sibling for a fixture slug, whatever world label was
    chosen: with the real run named after the fixture slug in the runs base and an episode's
    three siblings in the relocated layout — including one whose label re-claims the slug, the
    arm that displaces the real run by mtime recency — the index still resolves the slug to the
    real run."""
    base, src, root = T.configured_layout(tmp_path, monkeypatch)
    held_out = T.mod("evals.held_out")
    slug = "web-1-suspicious-binary"
    (base / slug).mkdir(parents=True)
    ep = T.mod("learning.branch.cli").episode_dir_for(T.EPISODE_ID)
    for label in ("a", "b", slug):
        (ep / "runs" / f"{slug}-n3-{label}").mkdir(parents=True)
    resolved = held_out.index_runs([slug], base)
    assert resolved[slug].name == slug


def test_947_the_lesson_tracer_counts_no_sibling_as_an_in_context_case(tmp_path, monkeypatch):
    """The lesson tracer counts no sibling as an in-context case: one investigation plus one
    episode's three siblings, each carrying the same loaded-lesson row, is ONE hit and not four,
    so the printed index reports the number of investigations that loaded a lesson rather than
    the number of processes that did."""
    base, src, root, ep = _relocated(tmp_path, monkeypatch)
    trace = T.mod("learning.ops.trace_lesson")
    T.lesson_row(src)
    for w in T.WORLDS:
        T.lesson_row(ep / "runs" / f"{T.EPISODE_ID}-{w}")
    assert [hit.case_id for hit in trace.in_context_cases("L1", None, base)] == [T.SOURCE_RUN_ID]


def test_947_the_invlang_corpus_counts_no_sibling_and_no_archived_world(tmp_path, monkeypatch):
    """The orientation corpus counts no sibling and no archived world: the shim's recursive walk
    for companion documents under the runs base loads ONE case where one investigation happened,
    so an episode cannot move the denominator every ordinary run's orientation is ranked against
    — the walker that relocation alone does not contain, because it descends rather than lists."""
    base, src, root, ep = _relocated(tmp_path, monkeypatch)
    corpus = T.mod("skills.invlang.corpus")
    T.corpus_document(src)
    for w in T.WORLDS:
        T.corpus_document(ep / "runs" / f"{T.EPISODE_ID}-{w}")
        T.corpus_document(T.archived_world(ep, w))
    companions, report = corpus.load_corpus(base)
    assert [c.case_id for c in companions] == [T.SOURCE_RUN_ID]
    assert report.scanned == 1, f"the walk descended into the episode: {report.scanned} documents"
