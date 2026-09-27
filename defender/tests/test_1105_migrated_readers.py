"""#1105 D4 — learning and the judge become callers of the run service (O1), and a PRESENT but BAD
tenant record now refuses the migrated readers that never read it before (O4.1).

The readers are driven through their own entry points — the lesson tracer's `in_context_cases`,
the lead author's `write_done_sentinel` / `run`, `archive_episode`, `stage_tables`, the
`lead_repository` readers, the judge's `grade_family` and `sibling_union` — over real run
directories. The one `run.py`-free timing hook is `PruneOnCompare` (p041): a `created_at` value
(the tracer's own argument) whose first comparison REALLY deletes a listed run, so "a run
pruned between listing and opening" is a real rmtree at a real moment, not a faked listing.

Refuted claims respected: the tracer RAISES on an unreadable lessons file where the judge walk
degrades (adv-PO6), so nothing here pins a degrade for the tracer; the session store lives at
`<runs_base>/../sessions` (author-P19), so p046's co-tenant is an entry this test plants itself;
the design's Key-flows order for run end is refuted (G11) and not asserted here.

RED against ed5386bc: the readers still compose paths (no refusal on a bad record), the tracer
still walks every directory (O4.2), `archive_episode` wipes a deleted sibling's copies (lc-O5,
J16 fix) and accepts a non-case-stable sibling (J19), and `defender.run_service` does not exist.
"""
from __future__ import annotations

import datetime as dt
import json
import shutil
import types
from pathlib import Path

import pytest

from defender.tests import _spec1105 as S
from defender.tests import _triplet_947 as T
from defender.tests._by_path import load_trace_lesson


def _tracer(tag: str):
    return load_trace_lesson(f"trace_lesson_1105_{tag}")


def _hits(base: Path, tag: str, *, since=None) -> list[str]:
    return [h.case_id for h in _tracer(tag).in_context_cases("L1", since, base)]


def _archive():
    return S.mod("learning.branch.archive")


def _sibling(base: Path, label: str) -> Path:
    """A finished sibling run dir under `base` (the episode's own runs base, FORK-13) with every
    role the archive copies: the #947 builder's report/investigation/stamp/scrub sidecar, plus a
    run-end sidecar, the alert, the lessons table, one captured call with its payload and lead
    sidecar, and one gather summary."""
    sib = T.sibling_run_dir(base, label)
    (base / f"{sib.name}.run-end.json").write_text(json.dumps({"truncated_by": None}),
                                                   encoding="utf-8")
    (sib / "alert.json").write_text("{}", encoding="utf-8")
    (sib / "lessons_loaded.jsonl").write_text("", encoding="utf-8")
    T.capture_call(sib)
    (sib / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"goal": "g", "what_to_summarize": []}), encoding="utf-8")
    (sib / "gather_summaries").mkdir()
    (sib / "gather_summaries" / "l-001.md").write_text("summary of l-001\n", encoding="utf-8")
    return sib


#: What `archive_episode` wrote for `_sibling`'s run at ed5386bc (probe e/p_misc.py) — the
#: seven single-file roles, both sidecars re-homed, the two tables, the summaries and the pointer.
ARCHIVED_TREE = sorted([
    "alert.json", "executed_queries.jsonl", "gather_raw", "gather_raw/l-001",
    "gather_raw/l-001.lead.json", "gather_raw/l-001/0.json", "gather_summaries",
    "gather_summaries/l-001.md", "investigation.md", "lessons_loaded.jsonl", "provenance.json",
    "report.md", "run_dir", "run_end.json", "scrub_verdict.json",
])


def _tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")) if root.exists() else []


def _files(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()} \
        if root.exists() else {}


# ---------------------------------------------------------------------------------------
# the lesson tracer (O4.1, O4.2)
# ---------------------------------------------------------------------------------------


def test_1105_tracer_skips_names_that_could_never_be_run_ids(tmp_path):
    """`in_context_cases` over a runs base with lesson-loaded runs in directories named
    `has space`, `.hidden`, `_x` and `héllo` reports no hits from them. The positive control: a
    validly named run (including a non-case-stable one such as `caseA`) with the same
    `lessons_loaded` rows is reported.
    """
    base = tmp_path / "runs"
    for name in (*S.NEVER_IDS, S.FIXTURE_ID, "ok-run"):
        S.make_run(base, name, lessons=["L1"])
    assert _hits(base, "skip") == [S.FIXTURE_ID, "ok-run"]


def test_1105_tracer_refuses_a_present_bad_tenant_record(tmp_path):
    """with a corrupt `tenant_record` under the runs base, the lesson tracer raises
    `TenantRecordCorrupt` rather than returning hits. With no record it returns the same hits it
    returns today.
    """
    base = tmp_path / "runs"
    for name in (S.CASE_STABLE_ID, S.FIXTURE_ID):
        S.make_run(base, name, lessons=["L1"])
    assert _hits(base, "refuse_ok") == sorted([S.CASE_STABLE_ID, S.FIXTURE_ID])
    S.plant_bad_record(base, "corrupt", elsewhere=tmp_path / "elsewhere")
    e = S.refusal(lambda: _hits(base, "refuse_bad"))
    assert S.type_name(e) == "TenantRecordCorrupt", (S.type_name(e), e)


def test_1105_tracer_hit_order_over_mixed_case_and_punctuated_names(tmp_path):
    """Hits appear in `list_run_ids`' sorted-name order (`Upper-Run` before lower-case names,
    ASCII order), identical to today's order for these names.
    """
    base = tmp_path / "runs"
    names = ("b-run", "a_run", "a.run", "Upper-Run", "a-run")
    for name in names:
        S.make_run(base, name, lessons=["L1"])
    expected = ["Upper-Run", "a-run", "a.run", "a_run", "b-run"]
    assert _hits(base, "order") == expected
    assert list(S.sym("list_run_ids")(base)) == expected


class PruneOnCompare(dt.datetime):
    """The tracer's own `created_at` argument, whose FIRST comparison deletes `victim` — a real
    rmtree of a run the tracer has already listed, at the moment it is reading an earlier run.
    It injects the timing only; what a vanished run MEANS is the tracer's to decide."""

    victim: Path | None = None

    def _prune(self) -> None:
        victim = type(self).victim
        if victim is not None and victim.exists():
            shutil.rmtree(victim)

    def __gt__(self, other):  # `ts < since` reflects here for a datetime subclass
        self._prune()
        return super().__gt__(other)

    def __le__(self, other):
        self._prune()
        return super().__le__(other)


def test_1105_tracer_run_pruned_between_listing_and_opening_non_case_stable(tmp_path):
    """when a run that `list_run_ids` returned is removed before the tracer's `open_run` on it,
    the trace skips that run and continues. It does so alike for the non-case-stable `caseA`,
    where `open_run` raises `ValueError`, and for a case-stable twin, where `open_run` returns a
    handle and the lessons file is absent: both give the same output, no row for the pruned run
    and the rows for the rest. A present bad tenant record still stops the trace with
    `TenantRecordCorrupt`, and so does a present directory for which `open_run` raises
    `ValueError` for another reason (a record naming another tenant), so the skip keys on the
    directory being gone, never on the exception type.
    """
    outputs = []
    for victim in (S.FIXTURE_ID, "case-b"):
        base = tmp_path / victim / "runs"
        for name in ("aaa-first", victim, "zzz-last"):
            S.make_run(base, name, lessons=["L1"])
        cls = type(f"Prune_{victim.replace('-', '_')}", (PruneOnCompare,),
                   {"victim": base / victim})
        since = cls(2026, 1, 1, tzinfo=dt.UTC)
        outputs.append(_hits(base, f"prune_{victim.replace('-', '_')}", since=since))
        assert not (base / victim).exists(), "the timing hook never fired — nothing was pruned"
    assert outputs[0] == outputs[1] == ["aaa-first", "zzz-last"], outputs

    for shape, expected in (("corrupt", "TenantRecordCorrupt"), ("other_tenant", "ValueError")):
        base = tmp_path / f"present-{shape}" / "runs"
        for name in ("aaa-first", S.FIXTURE_ID, "zzz-last"):
            S.make_run(base, name, lessons=["L1"])
        S.plant_bad_record(base, shape, elsewhere=tmp_path / f"present-{shape}" / "elsewhere")
        e = S.refusal(lambda base=base, shape=shape: _hits(base, f"present_{shape}"))
        assert S.type_name(e) == expected, (shape, S.type_name(e), e)


# ---------------------------------------------------------------------------------------
# the lead author (O4.1)
# ---------------------------------------------------------------------------------------


class _HeldLock:
    """The lead author's `deps=` seam, reduced to the two calls `run` makes before it reads the
    run's state folder: the queue lock is taken and released, nothing else is asked."""

    def __init__(self) -> None:
        self.released = 0

    def acquire_queue_lock(self):
        return object()

    def release_queue_lock(self, _lock) -> None:
        self.released += 1


def test_1105_lead_author_refuses_a_present_bad_tenant_record(tmp_path):
    """the lead author, resolving its state folder through `run.documents.lead_author.path`,
    raises `TenantRecordCorrupt` when the runs base holds a corrupt `tenant_record` — at its
    sentinel write and at `run`'s done check. With no record it uses `<run_dir>/lead_author` as
    today: the sentinel lands there, and a run already done returns 0.
    """
    la = S.mod("learning.leads.lead_author")
    base = tmp_path / "runs"
    run_dir = S.make_run(base, S.CASE_STABLE_ID)

    la.write_done_sentinel(run_dir, "abc1234")
    done = run_dir / "lead_author" / "done"
    assert done.is_file()
    assert 'abc1234' in done.read_text(encoding='utf-8')
    deps = _HeldLock()
    assert la.run(run_dir, deps=deps) == 0, "a run whose sentinel is present is already done"

    S.plant_bad_record(base, "corrupt", elsewhere=tmp_path / "elsewhere")
    e = S.refusal(lambda: la.write_done_sentinel(run_dir, "abc1234"))
    assert S.type_name(e) == "TenantRecordCorrupt", (S.type_name(e), e)
    e = S.refusal(lambda: la.run(run_dir, deps=_HeldLock()))
    assert S.type_name(e) == "TenantRecordCorrupt", (S.type_name(e), e)


# ---------------------------------------------------------------------------------------
# staging and archive, source side (O4.1, J11, J16, J19)
# ---------------------------------------------------------------------------------------


def test_1105_staging_and_archive_source_refuse_a_present_bad_tenant_record(tmp_path):
    """`archive_episode`, given a sibling run whose runs base holds a corrupt `tenant_record`,
    raises `TenantRecordCorrupt` from its `open_run` on that sibling and copies nothing from it;
    `stage_tables` is never reached (no table lands in the world). With a valid default record
    it copies the same files as today, including both sidecars.
    """
    ep = T.episode(tmp_path / "bad")
    sib = _sibling(ep / "runs", "b")
    S.plant_bad_record(ep / "runs", "corrupt", elsewhere=tmp_path / "elsewhere")
    e = S.refusal(lambda: _archive().archive_episode(ep, {"b": sib}))
    assert S.type_name(e) == "TenantRecordCorrupt", (S.type_name(e), e)
    world = ep / "worlds" / "b"
    assert not [p for p in world.rglob("*") if p.is_file()] if world.exists() else True, (
        _tree(world))

    good = T.episode(tmp_path / "good")
    sib = _sibling(good / "runs", "b")
    S.write_record(good / "runs")
    _archive().archive_episode(good, {"b": sib})
    assert _tree(good / "worlds" / "b") == ARCHIVED_TREE
    for sidecar in ("run_end.json", "scrub_verdict.json"):
        assert (good / "worlds" / "b" / sidecar).is_file(), sidecar


def test_1105_archive_copies_gather_raw_and_summaries_through_lead_repository_with_unchanged_destinations(  # noqa: E501
        tmp_path, capsys):
    """`archive_episode` produces the same file tree for a sibling run as at the base commit:
    `worlds/<label>/gather_raw` and `worlds/<label>/gather_summaries`, with the same contents. A
    symlinked entry at any depth of either source is still refused and reported, now through a
    path-taking `lead_repository` reader, and its target's bytes never land in the archive.
    """
    ep = T.episode(tmp_path)
    sib = _sibling(ep / "runs", "b")
    S.write_record(ep / "runs")
    secret = tmp_path / "secret.txt"
    secret.write_text("ROOT-SECRET", encoding="utf-8")
    (sib / "gather_raw" / "l-001" / "deep").mkdir()
    (sib / "gather_raw" / "l-001" / "deep" / "planted.json").symlink_to(secret)
    (sib / "gather_summaries" / "nested").mkdir()
    (sib / "gather_summaries" / "nested" / "planted.md").symlink_to(secret)

    _archive().archive_episode(ep, {"b": sib})
    world = ep / "worlds" / "b"
    archived = _files(world)
    for rel in ("gather_raw/l-001/0.json", "gather_raw/l-001.lead.json",
                "gather_summaries/l-001.md"):
        assert archived[rel] == (sib / rel).read_bytes(), rel
    assert not any(b"ROOT-SECRET" in data for data in archived.values())
    assert not [p for p in world.rglob("*") if p.is_symlink()]
    err = capsys.readouterr().err
    assert 'planted.json' in err, err
    assert 'planted.md' in err, err


def test_1105_existing_stage_tables_callers_passing_a_plain_path(tmp_path):
    """`stage_tables` still takes a run directory path: a caller passing a plain path copies the
    same tables as at base. `archive_episode` opens each sibling source with `open_run` and
    passes `run.run_dir` to `stage_tables`, so under a good record `stage_tables` reads the same
    directory it read at base: the archived queries table is the source's own bytes.
    """
    lr = S.mod("learning.lead_repository")
    src = _sibling(tmp_path / "runs", "b")
    dst = tmp_path / "staged"
    refused = lr.stage_tables(src, dst)
    assert refused == []
    assert (dst / "executed_queries.jsonl").read_bytes() == \
        (src / "executed_queries.jsonl").read_bytes()
    assert (dst / "gather_raw" / "l-001" / "0.json").read_bytes() == \
        (src / "gather_raw" / "l-001" / "0.json").read_bytes()

    ep = T.episode(tmp_path / "ep")
    sib = _sibling(ep / "runs", "b")
    S.write_record(ep / "runs")
    _archive().archive_episode(ep, {"b": sib})
    assert (ep / "worlds" / "b" / "executed_queries.jsonl").read_bytes() == \
        (sib / "executed_queries.jsonl").read_bytes()


def test_1105_verify_family_and_archive_episode_invoked_a_second_time(tmp_path, capsys):
    """re-archiving an episode after one sibling's run directory was deleted leaves that
    sibling's already archived copies untouched, archives the other siblings, and reports the
    skipped sibling by label; no archived file is lost — whether the second pass is
    `archive_episode` itself or `verify_family` over the same siblings. The positive control: a
    second pass over unchanged run directories leaves an identical archive tree (idempotent).
    """
    labels = ("alpha", "beta", "gamma")
    ep = T.episode(tmp_path / "rerun")
    dirs = {w: _sibling(ep / "runs", w) for w in labels}
    S.write_record(ep / "runs")
    _archive().archive_episode(ep, dirs)
    first = _files(ep / "worlds")
    _archive().archive_episode(ep, dirs)
    assert _files(ep / "worlds") == first, "a second pass over unchanged runs changed the archive"

    capsys.readouterr()
    shutil.rmtree(dirs["gamma"])
    (dirs["beta"] / "report.md").write_text(T.report_text("benign"), encoding="utf-8")
    _archive().archive_episode(ep, dirs)
    second = _files(ep / "worlds")
    gamma = {k: v for k, v in first.items() if k.startswith("gamma/")}
    assert {k: v for k, v in second.items() if k.startswith("gamma/")} == gamma, (
        "the deleted sibling's archived copies were touched")
    assert second["beta/report.md"] == T.report_text("benign").encode(), "beta was not re-archived"
    assert "gamma" in capsys.readouterr().err, "the skipped sibling was not reported by label"

    verified = T.episode(tmp_path / "verify")
    vdirs = [_sibling(verified / "runs", w) for w in labels]
    S.write_record(verified / "runs")
    S.cli().verify_family(verified, vdirs, source=T.provenance_record())
    before = _files(verified / "worlds")
    shutil.rmtree(vdirs[-1])
    S.cli().verify_family(verified, vdirs, source=T.provenance_record())
    after = _files(verified / "worlds")
    lost = sorted(k for k in before if k.startswith("gamma/") and after.get(k) != before[k])
    assert not lost, f"the second verify pass lost archived files: {lost}"


def test_1105_archive_with_a_fixture_sibling_id_that_is_not_case_stable(tmp_path):
    """`verify_family` and `archive_episode`, handed a family whose sibling directory name is
    valid but not case-stable (a hand-built fixture such as `ep-Label`), refuse at their top with
    a message naming that id, before copying anything: the archive holds no file from any
    sibling afterwards — not even from the case-stable sibling that sorts first. (The archive's
    world key is the case-stable `odd`, so the refusal is the sibling id's, not the world
    label's own rule.)
    """
    for entry in ("archive", "verify"):
        ep = T.episode(tmp_path / entry)
        base = ep / "runs"
        S.write_record(base)
        good = _sibling(base, "a")
        odd = base / "ep-Label"
        shutil.copytree(_sibling(tmp_path / f"{entry}-proto", "z"), odd)
        (base / "ep-Label.scrub-verdict.json").write_text(json.dumps({"ran": True}),
                                                          encoding="utf-8")
        if entry == "archive":
            e = S.refusal(lambda ep=ep, good=good, odd=odd:
                          _archive().archive_episode(ep, {"a": good, "odd": odd}))
        else:
            e = S.refusal(lambda ep=ep, good=good, odd=odd:
                          S.cli().verify_family(ep, [good, odd], source=T.provenance_record()))
        assert "ep-Label" in str(e), (entry, S.type_name(e), e)
        worlds = ep / "worlds"
        assert not [p for p in worlds.rglob("*") if p.is_file()] if worlds.exists() else True, (
            entry, _tree(worlds))


def test_1105_verify_family_over_a_sibling_that_never_materialized(tmp_path):
    """`verify_family` over a family in which one sibling never materialized — its case-stable
    run id names no directory and no scrub-verdict sidecar, the shape a sibling whose `run.py
    --resume` died before materialize leaves (RG-2's loser) — under a default `tenant_record`
    behaves as at base: `open_run` hands back that id's handle without checking a directory,
    and verify returns and records in `review.yaml` the outcome `incomplete` with a reason naming
    that sibling's label, and archives both finished siblings' worlds in full. The positive
    control: the same family with the third sibling finished is `accepted` and archives all three.
    """
    import yaml

    for shape in ("never", "finished"):
        ep = T.episode(tmp_path / shape)
        runs = ep / "runs"
        S.write_record(runs)
        dirs = [_sibling(runs, w) for w in ("a", "b")]
        third = _sibling(runs, "c") if shape == "finished" else runs / f"{T.EPISODE_ID}-c"
        assert S.is_case_stable(third.name), third.name
        if shape == "never":
            assert not third.exists(), third
            assert not (runs / f"{third.name}.scrub-verdict.json").exists(), "a sidecar exists"
        report = S.cli().verify_family(ep, [*dirs, third], source=T.provenance_record())
        review = yaml.safe_load((ep / "review.yaml").read_text(encoding="utf-8")) or {}
        recorded = review.get("episode") or {}
        assert recorded.get("outcome") == report["outcome"], (shape, recorded, report)
        assert recorded.get("reason") == report.get("reason"), (shape, recorded, report)
        worlds = ep / "worlds"
        archived = sorted(p.name for p in worlds.iterdir()) if worlds.exists() else []
        if shape == "never":
            assert report["outcome"] == "incomplete", report
            assert "['c']" in str(report.get("reason")), report
            assert archived == ["a", "b"], _tree(worlds)
        else:
            assert report["outcome"] == "accepted", report
            assert archived == ["a", "b", "c"], _tree(worlds)
        for label in archived:
            assert _tree(worlds / label) == ARCHIVED_TREE, (shape, label, _tree(worlds / label))


# ---------------------------------------------------------------------------------------
# the readers every D4 site keeps (O4 parity)
# ---------------------------------------------------------------------------------------


def test_1105_migrated_readers_read_the_same_paths_under_an_absent_or_default_record(
        tmp_path, monkeypatch):
    """under an absent or default `tenant_record`, the questioner, the tracer, the lead author
    and `archive_episode` (which hands `run.run_dir` to `stage_tables`) read the same files
    through `open_run` as the base commit's composed paths do, for both a case-stable run and
    `caseA` (X9) — except `archive_episode` over `caseA`, which J19 refuses (p059's test).
    """
    S.configure_roots(tmp_path, monkeypatch)
    la = S.mod("learning.leads.lead_author")
    for record in ("absent", "default"):
        base = tmp_path / record / "runs"
        for run_id in (S.CASE_STABLE_ID, S.FIXTURE_ID):
            S.make_run(base, run_id, lessons=["L1"])
        if record == "default":
            S.write_record(base)
        assert _hits(base, f"parity_{record}") == sorted([S.CASE_STABLE_ID, S.FIXTURE_ID])
        for run_id in (S.CASE_STABLE_ID, S.FIXTURE_ID):
            la.write_done_sentinel(base / run_id, "cafe123")
            assert (base / run_id / "lead_author" / "done").is_file(), (record, run_id)

        ep = T.episode(tmp_path / record / "ep")
        sib = _sibling(ep / "runs", "b")
        if record == "default":
            S.write_record(ep / "runs")
        _archive().archive_episode(ep, {"b": sib})
        assert _tree(ep / "worlds" / "b") == ARCHIVED_TREE, record

    for run_id in (T.SOURCE_RUN_ID.casefold(), S.FIXTURE_ID):
        _base, src = T.runs_base(tmp_path / f"q-{run_id}", source_run_id=run_id)
        agent = T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c"))
        rc, _ep = S.launch(tmp_path, src, questioner=agent)
        assert rc == 0, run_id
        frontier = T.branchable_investigation().split("```invlang\n", 1)[1].split("```", 1)[0]
        assert frontier.strip(), run_id
        assert frontier.strip() in agent.prompts[0], run_id


def test_1105_lead_repository_readers_stay_path_taking_for_runs_and_archived_worlds(tmp_path):
    """the `lead_repository` readers accept a plain path. Given `run.run_dir` from `open_run` they
    return today's rows — the capture's primer counts the same captured call — and given an
    archived world directory (family.py's call, C10) they return the same rows as today.
    """
    lr = S.mod("learning.lead_repository")
    capture = S.mod("learning.branch.capture")
    ep = T.episode(tmp_path)
    sib = _sibling(ep / "runs", "b")
    S.write_record(ep / "runs")
    run = S.sym("open_run")(ep / "runs", sib.name)

    def rows(where: Path) -> list[tuple[str, int]]:
        return [(j.lead_id, len(j.queries)) for j in lr.joined(where)]

    assert rows(run.run_dir) == rows(sib) == [("l-001", 1)]
    report = capture.prime_base(run.run_dir, tmp_path / "base.jsonl")
    assert report.primed == 1, report

    _archive().archive_episode(ep, {"b": sib})
    world = ep / "worlds" / "b"
    assert rows(world) == [("l-001", 1)]
    assert sorted(S.mod("learning.judge.family").leads_by_id(world)) == ["l-001"]


def test_1105_unmigrated_learning_readers_and_the_migrated_tracer_over_one_bad_record_base(
        tmp_path):
    """over one learning runs dir that holds a corrupt `_tenant.json`, the migrated tracer
    refuses with `TenantRecordCorrupt`, while `disposition_for`, `load_run_context`,
    `_resolves_inside_runs_dir` and `build_questioner_config` each read the same paths and return
    the same values as at base, refusing nothing: they are the named N-f deferral, not migrated
    readers.
    """
    runs = tmp_path / "state" / "runs"
    run_dir = S.make_run(runs, S.CASE_STABLE_ID, lessons=["L1"])
    (run_dir / "source_refs.yaml").write_text("normalized_disposition: malicious\n",
                                              encoding="utf-8")
    (run_dir / "investigation.md").write_text("# investigation\n", encoding="utf-8")
    S.plant_bad_record(runs, "corrupt", elsewhere=tmp_path / "elsewhere")

    lessons_run = S.mod("learning.author.lessons.run")
    forward = S.mod("learning.author.verify_forward.forward")
    drain = S.mod("learning.author.drain")
    questioner_run = S.mod("learning.author.questioner.run")
    config = S.mod("learning.core.config")

    assert lessons_run.disposition_for(types.SimpleNamespace(runs_dir=runs),
                                       S.CASE_STABLE_ID) == "malicious"
    assert forward.load_run_context(S.CASE_STABLE_ID, runs_dir=runs) == (
        "# investigation\n", "malicious")
    assert drain._resolves_inside_runs_dir(runs, S.CASE_STABLE_ID) is True
    paths = config.LoopPaths(repo_root=S.WORKTREE, state_dir=tmp_path / "state")
    assert questioner_run.build_questioner_config(paths).runs_dir == paths.runs_dir == runs

    e = S.refusal(lambda: _hits(runs, "nf"))
    assert S.type_name(e) == "TenantRecordCorrupt", (S.type_name(e), e)


# ---------------------------------------------------------------------------------------
# the judge (D4: run_exists for the collision probe, bound_runs for the sibling walk)
# ---------------------------------------------------------------------------------------


def _judge_refused():
    return S.mod("learning.judge").JudgeRefused


def test_1105_judge_collision_probe_refuses_a_colliding_label_and_is_silent_without_a_base(
        tmp_path, monkeypatch):
    """the judge's family pass raises `JudgeRefused` when a world label equals an entry that
    `run_exists` sees under the resolved runs base — here a dangling link, which `is_dir()`
    would never see. It returns silently when `resolve_runs_base()` raises (X14): with the runs
    base configured onto the learning state root, the pass grades instead of refusing.
    """
    family = S.mod("learning.judge.family")
    runs = tmp_path / "defender-runs"
    runs.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learn"))
    ep = T.episode(tmp_path)
    doc = T.family_doc()

    assert family.grade_family(ep, manifest=doc, review={}, samples={}) is not None
    (runs / "b").symlink_to(tmp_path / "nowhere")
    with pytest.raises(_judge_refused()) as refused:
        family.grade_family(ep, manifest=doc, review={}, samples={})
    assert "'b'" in str(refused.value)

    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "learn"))
    assert family.grade_family(ep, manifest=doc, review={}, samples={}) is not None


def test_1105_world_label_equal_to_a_runs_base_co_tenant_name(tmp_path, monkeypatch):
    """A world label equal to a non-run entry under the resolved runs base makes `run_exists`
    report it present, so the judge refuses the label as colliding — as today. The entry is
    planted by the test (a plain file and a non-run directory): the session store is NOT a
    runs-base co-tenant (author-P19), so nothing else puts one there.
    """
    family = S.mod("learning.judge.family")
    for entry in ("file", "dir"):
        runs = tmp_path / entry / "defender-runs"
        runs.mkdir(parents=True)
        monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))
        monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learn"))
        if entry == "file":
            (runs / "notes").write_text("not a run", encoding="utf-8")
        else:
            (runs / "notes").mkdir()
        assert S.sym("run_exists")(runs, "notes") is True
        doc = T.family_doc(worlds=[T.base_world(), T.world_doc("notes"), T.world_doc("c")])
        ep = T.episode(tmp_path / entry, doc=doc)
        with pytest.raises(_judge_refused()) as refused:
            family.grade_family(ep, manifest=doc, review={}, samples={})
        assert "'notes'" in str(refused.value), refused.value


_UNION_WITH_UNREADABLE = """
    import json
    from pathlib import Path
    from defender.learning.judge import render
    out = {}
    for label, base in json.loads(BASES).items():
        rows, notes = render.sibling_union(Path(base), alert_id="A1", source_run_id="src-run")
        out[label] = {"rows": rows, "notes": notes,
                      "view": render._render_siblings(rows, notes)}
    print(json.dumps(out))
"""


def test_1105_bound_runs_when_the_source_run_is_among_the_entries(tmp_path):
    """the judge's sibling union over a runs base that holds the source run's own directory and
    one unreadable run records `source_run_excluded` for the source (the judge knows its id) and
    counts the unreadable one `skipped_unreadable`, and the rendered judge prompt carries the
    same notes as at base, including the "nobody looked" rendering for a missing or unreadable
    base.
    """
    base = tmp_path / "runs"
    for run_id, disposition in (("src-run", "malicious"), ("run-2", "benign"),
                                ("run-shut", "benign")):
        d = S.make_run(base, run_id, report=T.report_text(disposition))
        (d / "alert.json").write_text(json.dumps({"alert_id": "A1"}), encoding="utf-8")
    (base / "run-shut").chmod(0)
    unlistable = tmp_path / "unlistable"
    unlistable.mkdir()
    unlistable.chmod(0)
    bases = {"base": str(base), "missing": str(tmp_path / "no-such-base"),
             "unlistable": str(unlistable)}
    with S.restoring_modes(base / "run-shut", unlistable):
        got = S.unprivileged(_UNION_WITH_UNREADABLE.replace("BASES", repr(json.dumps(bases))),
                             cwd=tmp_path)
    walked = got["base"]
    assert walked["rows"] == [{"run_id": "run-2", "disposition": "benign"}], walked
    assert walked["notes"]["source_run_excluded"] == "src-run", walked
    assert walked["notes"]["skipped_unreadable"] == 1, walked
    assert "(the source run 'src-run' this episode branched from is excluded)" in walked["view"]
    assert "- run-2: disposition=benign" in walked["view"]
    assert got["missing"]["notes"]["runs_base_missing"] is True, got["missing"]
    assert ("(the runs base named for this pass is not a directory, so the sibling union was "
            "never attempted") in got["missing"]["view"]
    assert got["unlistable"]["notes"]["runs_base_unreadable"], got["unlistable"]
    assert "could not be listed" in got["unlistable"]["view"]
    assert "first-run alert" not in got["missing"]["view"] + got["unlistable"]["view"]
