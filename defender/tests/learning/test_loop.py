from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.learning import loop

RunUnprocessable = loop.RunUnprocessable
LoopPaths = loop.LoopPaths

from defender.learning.core import drains as drains  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.core import markers as markers  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.core import persist as persist  # type: ignore[import-not-found]  # noqa: E402
from defender import _io as _io  # type: ignore[import-not-found]  # noqa: E402
from defender.learning import lead_repository as lr  # type: ignore[import-not-found]  # noqa: E402


def _qr(query_id, params=None, *, seq=0, raw_ref=None, lead_id="l-001"):
    return lr.QueryRow(
        lead_id=lead_id, seq=seq, system="", verb="", query_id=query_id,
        params=params or {}, raw_command="", exit_code=0, error_class=None,
        payload_status="ok", payload_digest="", raw_ref=raw_ref,
    )


def _jl(lead_id="l-001", goal=None, wts=(), queries=()):
    return lr.JoinedLead(
        lead_id=lead_id, goal=goal, what_to_summarize=wts, queries=list(queries),
    )














def _esql_sample(body: str) -> str:
    return f"### Raw Sample Events (first 3)\n\n```json\n{body}\n```\n"






















































def _full_judge_doc(**overrides):
    doc = {
        "outcome": "caught",
        "outcome_rationale": "Lead l-001 refuted the projection.",
        "encounter_analysis": "lead-by-lead walkthrough.",
        "defender_findings": [
            {
                "type": "detection-confirmed",
                "subject_anchor": "l-001",
                "subject_topic": "falco container scan",
                "finding": "lead caught the story.",
                "citations": [{"source": "investigation", "quote": "q"}],
            }
        ],
        "confidence": "high.",
    }
    doc.update(overrides)
    return doc




























def test_strip_yaml_fence_passes_through_plain_yaml():
    assert loop.strip_yaml_fence("outcome: caught\nconfidence: high\n") == (
        "outcome: caught\nconfidence: high"
    )


def test_strip_yaml_fence_strips_yaml_code_fence():
    fenced = "```yaml\noutcome: caught\n```\n"
    assert loop.strip_yaml_fence(fenced) == "outcome: caught"


def test_strip_yaml_fence_strips_trailing_close_tag():
    text = "outcome: caught\nconfidence: high\n</content>\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


def test_strip_yaml_fence_strips_full_xml_envelope():
    text = "<content>\noutcome: caught\nconfidence: high\n</content>\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


def test_strip_yaml_fence_strips_dangling_close_fence():
    text = "outcome: caught\nconfidence: high\n```\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


def test_strip_yaml_fence_strips_thinking_prelude():
    text = (
        "outcome: caught\n(reasoning trace…)\n</thinking>\n"
        "outcome: survived\nconfidence: high\n"
    )
    assert loop.strip_yaml_fence(text) == "outcome: survived\nconfidence: high"


def test_strip_yaml_fence_strips_system_thinking_variant():
    text = (
        "outcome: caught\n(reasoning trace…)\n</system_thinking>\n"
        "outcome: survived\nconfidence: high\n"
    )
    assert loop.strip_yaml_fence(text) == "outcome: survived\nconfidence: high"


def test_strip_yaml_fence_passes_through_when_no_thinking_tag():
    text = "outcome: caught\nconfidence: high\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"




def _judge_doc(outcome: str, observations: list[dict] | None) -> dict:
    doc: dict = {"outcome": outcome}
    if observations is not None:
        doc["actor_observations"] = observations
    return doc


def _obs(i: int) -> dict:
    return {
        "type": "misprediction",
        "subject_anchor": f"anchor-{i}",
        "subject_topic": f"topic phrase {i}",
        "observation": f"observation paragraph {i}\n",
    }


def _read_jsonl(path: Path) -> list[dict]:
    return _io.read_jsonl_rows(path)


def _noop_start_box(request, **_kw):
    """A no-op box lifecycle for drain tests predating #665's box wiring — these tests exercise
    the worktree/branch/queue mechanics, not the (separately spec'd) box lifecycle."""
    from types import SimpleNamespace

    return SimpleNamespace(name=request.name)


def _noop_stop_box(_box, **_kw):
    pass


def _noop_scrub(_path, **_kw):
    pass


def _isolate(tmp_path: Path) -> tuple[object, Path]:
    paths = LoopPaths(repo_root=tmp_path)
    learning_run_dir = paths.runs_dir / "case-x"
    learning_run_dir.mkdir(parents=True)
    return paths, learning_run_dir




















def test_rotate_queue_locked_preserves_concurrent_appends(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    pending = paths.pending_file
    pending.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {"finding_id": "r/0", "v": "f1"},
        {"finding_id": "r/1", "v": "f2"},
        {"finding_id": "r/2", "v": "f3-new-arrival"},
    ]
    pending.write_text("".join(json.dumps(r) + "\n" for r in rows))

    held = [{"finding_id": "r/1", "v": "f2", "held_reason": "no_ground_truth"}]
    consumed = [{"finding_id": "r/0", "v": "f1", "consumed_category": "consumed_committed"}]
    persist.rotate_queue_locked(
        pending_file=pending,
        consumed_file=paths.pending_dir / "consumed.jsonl",
        lock_file=paths.findings_lock_file,
        id_key="finding_id",
        held=held,
        consumed=consumed,
        commit_sha="abc123",
    )

    survivors = _read_jsonl(pending)
    assert {s["finding_id"] for s in survivors} == {"r/1", "r/2"}
    held_row = next(s for s in survivors if s["finding_id"] == "r/1")
    assert held_row["held_reason"] == "no_ground_truth"
    consumed_rows = _read_jsonl(paths.pending_dir / "consumed.jsonl")
    assert consumed_rows[0]["consumed_commit"] == "abc123"
    assert "consumed_at" in consumed_rows[0]


def test_enqueue_for_authoring_writes_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-a"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    spec = json.loads((paths.author_queue_dir / "case-a.json").read_text())
    assert spec == {"run_id": "case-a", "run_dir": str(run_dir.resolve())}


class _FakeBranch:

    def __init__(self, *, prefix: str = "lessons/", pr_exists: bool = False, commits: int = 1):
        self.branch_prefix = prefix
        self._pr_exists = pr_exists
        self._commits = commits
        self.events: list[str] = []

    def open_pr_exists(self) -> bool:
        self.events.append("lease-check")
        return self._pr_exists

    def start_batch(self, batch_id: str) -> Path:
        self.events.append("start")
        return Path(f"/tmp/wt-{batch_id}")

    def finish_batch(self, batch_id: str, wt: Path):
        self.events.append("finish")
        return f"PR/{batch_id}" if self._commits else None

    def cleanup(self, wt: Path) -> None:
        self.events.append("cleanup")


def _seed_curator_findings(paths, n: int = 5) -> None:
    paths.pending_file.parent.mkdir(parents=True, exist_ok=True)
    with paths.pending_file.open("w") as fh:
        for i in range(n):
            fh.write(json.dumps({"finding_id": f"f{i}"}) + "\n")




def test_author_drain_triggers_all_curators(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    triggered: list[str] = []
    drains.author_drain(
        paths,
        trigger_author=lambda paths, pending_file, env, module, label, **_kw: triggered.append(module),
        branch=_FakeBranch(),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert triggered == [
        # ONE CURATOR SINCE #922 — the three observation channels lost their producer
        # with the old pipeline's judge, and their curators went with them.
        "author",
    ]


def test_author_drain_skips_when_lease_held(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    triggered: list = []
    branch = _FakeBranch(pr_exists=True)
    rc = drains.author_drain(
        paths,
        trigger_author=lambda *a, **_kw: triggered.append(a),
        branch=branch,
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert rc == 0
    assert triggered == []
    assert "start" not in branch.events


def test_author_drain_skips_when_no_work(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    triggered: list = []
    branch = _FakeBranch()
    rc = drains.author_drain(
        paths,
        trigger_author=lambda *a, **_kw: triggered.append(a),
        branch=branch,
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert rc == 0
    assert branch.events == []
    assert triggered == []


def test_author_drain_no_commits_opens_no_pr_but_cleans_up(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    branch = _FakeBranch(commits=0)
    rc = drains.author_drain(paths, trigger_author=lambda *a, **_kw: None, branch=branch, start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert rc == 0
    assert "finish" in branch.events
    assert branch.events[-1] == "cleanup"


def test_author_drain_singleton_lock_exits_without_work(tmp_path: Path):
    import fcntl

    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    paths.author_drain_lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = paths.author_drain_lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        worked: list[str] = []
        rc = drains.author_drain(
            paths,
            trigger_author=lambda *a, **_kw: worked.append("trigger"),
            branch=_FakeBranch(),
            start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
        )
        assert rc == 0
        assert worked == []
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()




def test_lead_author_drain_runs_lead_author_then_clears_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-b"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    seen: list[tuple[Path, Path]] = []
    branch = _FakeBranch(prefix="lead-author/")
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd, **_kw: seen.append((wt_paths.repo_root, rd)),
        branch=branch,
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert [rd for _, rd in seen] == [run_dir.resolve()]
    assert str(seen[0][0]).startswith("/tmp/wt-")
    assert not (paths.author_queue_dir / "case-b.json").exists()
    assert branch.events == ["lease-check", "start", "finish", "cleanup"]


def test_lead_author_drain_runs_pitfalls_after_markers(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-p"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    order: list[str] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd, **_kw: order.append("marker"),
        run_pitfalls=lambda wt_paths, **_kw: (order.append("pitfalls"), 0)[1],
        branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert order == ["marker", "pitfalls"]


def test_has_lead_author_work_fires_on_pitfalls_threshold(tmp_path: Path, monkeypatch):
    from defender.learning.core import persist
    paths, _ = _isolate(tmp_path)
    assert drains._has_lead_author_work(paths) is False
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    # Digest-less rows stay two distinct MISTAKES post-#840: an absent diagnosis is not a
    # shared one, so `pitfall_key` keys each such row to itself rather than folding them.
    persist.append_pitfalls(
        [{"pitfall_id": f"r:{i}", "system": "elastic"} for i in range(2)], paths=paths
    )
    assert drains._has_lead_author_work(paths) is True


def test_lead_author_drain_marks_artifact_missing(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-real"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    gone = tmp_path / "tmprun" / "case-gone"
    markers.enqueue_for_authoring(gone, paths)
    seen: list[Path] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd, **_kw: seen.append(rd),
        branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert seen == [run_dir.resolve()]
    assert not (paths.author_queue_dir / "case-gone.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-gone.json"
    assert json.loads(failed.read_text())["failed"] == "artifact-missing"


@pytest.mark.parametrize(
    "body",
    [
        "{not valid json",
        "null",
        '["case-broken"]',
        '{"run_id": "case-broken", "run_dir": null}',
        '{"run_id": "case-broken", "run_dir": 7}',
        '{"run_id": "case-broken"}',
    ],
    ids=["torn", "null", "list", "run_dir-null", "run_dir-number", "run_dir-absent"],
)
def test_lead_author_drain_dead_letters_an_unservable_marker(tmp_path: Path, body: str):
    """A marker this pass cannot READ is dead-lettered, never left in the queue.

    Four shapes are unservable. Bytes that do not parse, and bytes that parse to something
    that is not a mapping (`null`, a list) — the second still answers `spec.get("run_dir")`
    with an AttributeError that unwinds the whole drain. Then the two #852 F-18 halves, a
    mapping whose `run_dir` is not a path: a non-string value raised a TypeError out of the
    claim generator — past every dead-letter path below it, so the drain stayed wedged on the
    file until a human removed it — and an ABSENT `run_dir` (the shape this module's own
    `unreadable` dead letter writes) coerced to `Path("")`, i.e. the process CWD, and was
    SERVED against whatever directory the drain happened to be started from.

    Either way, leaving the marker where it was means the reclaim hands it straight back next
    tick, it fails again, and `_has_lead_author_work` stays true on its presence forever, so
    the drain wakes every tick to re-fail on the same file. The healthy sibling in the same
    pass must still be served."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-real"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    paths.author_queue_dir.mkdir(parents=True, exist_ok=True)
    (paths.author_queue_dir / "case-broken.json").write_text(body, encoding="utf-8")

    seen: list[Path] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd, **_kw: seen.append(rd),
        branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )

    assert seen == [run_dir.resolve()], "the healthy request in the same pass was not served"
    assert not (paths.author_queue_dir / "case-broken.json").exists()
    assert not (paths.author_queue_dir / "inflight" / "case-broken.json").exists(), \
        "the unservable marker was left claimed — the next tick reclaims and re-fails on it"
    failed = paths.author_queue_dir / "failed" / "case-broken.json"
    assert json.loads(failed.read_text())["failed"].startswith("unreadable")
    assert drains._has_lead_author_work(paths) is False, \
        "the queue still reports work on a request nothing can ever serve"


def test_lead_author_drain_skips_when_lease_held(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-lease"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    seen: list = []
    branch = _FakeBranch(prefix="lead-author/", pr_exists=True)
    rc = drains.lead_author_drain(
        paths, run_lead_author=lambda wt_paths, rd, **_kw: seen.append(rd),
        branch=branch, start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert rc == 0
    assert seen == []
    assert "start" not in branch.events
    assert (paths.author_queue_dir / "case-lease.json").exists()


def test_lead_author_drain_singleton_lock_distinct_from_lessons(tmp_path: Path):
    import fcntl

    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-d"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    paths.author_drain_lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = paths.author_drain_lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        seen: list = []
        rc = drains.lead_author_drain(
            paths,
            run_lead_author=lambda wt_paths, rd, **_kw: seen.append(rd),
            branch=_FakeBranch(prefix="lead-author/"),
            start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
        )
        assert rc == 0
        assert seen == [run_dir.resolve()]
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_lead_author_drain_quarantines_poison_run_dir(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    poison = tmp_path / "tmprun" / "case-poison"
    poison.mkdir(parents=True)
    good = tmp_path / "tmprun" / "case-good"
    good.mkdir(parents=True)
    markers.enqueue_for_authoring(poison, paths)
    markers.enqueue_for_authoring(good, paths)
    seen: list[Path] = []

    def maybe_boom(wt_paths, rd: Path, *, box=None) -> None:
        if rd.name == "case-poison":
            raise RuntimeError("lead-author blew up")
        seen.append(rd)

    drains.lead_author_drain(
        paths, run_lead_author=maybe_boom, branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert seen == [good.resolve()]
    assert not (paths.author_queue_dir / "case-poison.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-poison.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_quarantines_on_nonzero_rc(tmp_path: Path, monkeypatch):
    import defender.learning.leads.lead_author as la

    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-rc"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    # lint-monkeypatch: ok — drives the real _invoke_lead_author; _run_curator_module
    monkeypatch.setattr(la, "run", lambda rd, paths=None, box=None: 2)  # lint-monkeypatch: ok
    drains.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/"), start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert not (paths.author_queue_dir / "case-rc.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-rc.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_bounded_retry_then_quarantine(tmp_path: Path, monkeypatch):
    import defender.learning.leads.lead_author as la

    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-transient"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "3")

    def boom(rd, paths=None, box=None):
        raise OSError("disk hiccup")

    # lint-monkeypatch: ok — same intentional seam as the rc=2 test above: drives the
    monkeypatch.setattr(la, "run", boom)  # lint-monkeypatch: ok
    marker = paths.author_queue_dir / "case-transient.json"
    failed = paths.author_queue_dir / "failed" / "case-transient.json"

    for expected in (1, 2):
        drains.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/"), start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
        assert marker.exists()
        assert json.loads(marker.read_text())["attempts"] == expected
        assert not failed.exists()

    drains.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/"), start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert not marker.exists()
    assert json.loads(failed.read_text())["failed"].startswith("transient-exhausted")


def test_lead_author_drain_opens_distinct_lead_author_pr(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-pr"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    _, work = _origin_work(tmp_path)
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/77")
    branch = ab.AuthorBranch(
        forge=forge, repo_root=work, branch_prefix="lead-author/",
        pr_title=drains._lead_author_pr_title, pr_body=drains._lead_author_pr_body,
        worktree_base=tmp_path / "wt",
    )

    def _author(wt_paths, rd, *, box=None):
        f = wt_paths.repo_root / "defender" / "skills" / "note.md"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("edit\n")
        _real(wt_paths.repo_root, "add", "-A")
        _real(wt_paths.repo_root, "commit", "-q", "-m", "lead edit")

    rc = drains.lead_author_drain(paths, run_lead_author=_author, branch=branch, start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert rc == 0
    assert forge.open_calls[0]["head"].startswith("lead-author/")
    assert not forge.open_calls[0]["head"].startswith("lessons/")
    assert forge.list_calls == ["lead-author/"]


def test_lead_author_drain_resets_worktree_between_markers(tmp_path: Path):
    wt = tmp_path / "wt"
    catalog = wt / "defender" / "skills" / "gather" / "queries" / "wazuh"
    catalog.mkdir(parents=True)
    (catalog / "auth-events.md").write_text("---\nstatus: established\n---\n")
    _real(wt, "init", "-q", "-b", "main")
    _real(wt, "config", "user.email", "t@e.com")
    _real(wt, "config", "user.name", "T")
    _real(wt, "add", "-A")
    _real(wt, "commit", "-q", "-m", "seed")

    paths = LoopPaths(repo_root=wt, state_dir=tmp_path / "state")
    poison = tmp_path / "runs" / "case-a-poison"
    good = tmp_path / "runs" / "case-b-good"
    poison.mkdir(parents=True)
    good.mkdir(parents=True)
    markers.enqueue_for_authoring(poison, paths)
    markers.enqueue_for_authoring(good, paths)

    clean_at_entry: dict[str, bool] = {}

    def run_lead_author(p, rd: Path, *, box=None) -> None:
        st = _subprocess.run(
            ["git", "-C", str(p.repo_root), "status", "--porcelain"],
            capture_output=True, text=True,
        )
        clean_at_entry[rd.name] = st.stdout.strip() == ""
        if rd.name == "case-a-poison":
            (p.repo_root / "defender" / "skills" / "gather" / "queries"
             / "wazuh" / "auth-events.md").unlink()
            raise RuntimeError("scope-gate boom")

    drains._drain_lead_author_markers(paths, run_lead_author)

    assert clean_at_entry["case-a-poison"] is True
    assert clean_at_entry["case-b-good"] is True
    end = _subprocess.run(["git", "-C", str(wt), "status", "--porcelain"],
                          capture_output=True, text=True)
    assert end.stdout.strip() == ""
    assert (paths.author_queue_dir / "failed" / "case-a-poison.json").exists()
    assert not (paths.author_queue_dir / "case-b-good.json").exists()





























import subprocess as _subprocess  # noqa: E402

from defender.learning.author import branch as ab  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.author import forge as _forge  # type: ignore[import-not-found]  # noqa: E402


class _FakeForge:

    def __init__(self, *, pr_rows=None, create_ref="https://pr/1", raises=False,
                 list_raises=False):
        self.pr_rows = pr_rows or []
        self.create_ref = create_ref
        self.raises = raises
        self.list_raises = list_raises
        self.list_calls: list[str] = []
        self.head_calls: list[str] = []
        self.open_calls: list[dict] = []

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        self.list_calls.append(head_prefix)
        if self.list_raises:
            raise _forge.ForgeError("gh boom")
        return self.pr_rows

    def list_prs_for_head(self, head: str) -> list[dict]:
        self.head_calls.append(head)
        if self.list_raises:
            raise _forge.ForgeError("gh boom")
        return [r for r in self.pr_rows if str(r.get("headRefName", "")) == head]

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        self.open_calls.append({"base": base, "head": head, "title": title, "body": body})
        if self.raises:
            raise _forge.ForgeError("gh boom")
        return self.create_ref


def _real(cwd: Path, *args: str):
    return _subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


def _origin_work(tmp_path: Path, *, lessons: dict[str, str] | None = None) -> tuple[Path, Path]:
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    _real(tmp_path, "init", "--bare", "-q", str(origin), "-b", "main")
    _real(tmp_path, "clone", "-q", str(origin), str(work))
    _real(work, "config", "user.email", "t@e.com")
    _real(work, "config", "user.name", "T")
    (work / "seed.md").write_text("seed\n")
    for rel, content in (lessons or {}).items():
        p = work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    _real(work, "add", "-A")
    _real(work, "commit", "-q", "-m", "seed")
    _real(work, "push", "-q", "origin", "main")
    return origin, work


def test_author_branch_lease_true_on_open_pr():
    forge = _FakeForge(pr_rows=[{"number": 1, "headRefName": "lessons/abc"}])
    assert ab.AuthorBranch(forge=forge).open_pr_exists() is True
    assert forge.list_calls == ["lessons/"]


def test_author_branch_lease_false_when_no_matching_pr():
    forge = _FakeForge(pr_rows=[{"number": 2, "headRefName": "feature/x"}])
    assert ab.AuthorBranch(forge=forge).open_pr_exists() is False


def test_author_branch_lease_keyed_on_prefix():
    forge = _FakeForge(pr_rows=[{"number": 3, "headRefName": "lessons/abc"}])
    b = ab.AuthorBranch(forge=forge, branch_prefix="lead-author/")
    assert b.open_pr_exists() is False
    assert forge.list_calls == ["lead-author/"]


def test_author_branch_start_adds_worktree_off_origin_main(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    assert wt == tmp_path / "wt" / "lessons-abc123"
    assert wt.is_dir()
    assert _real(wt, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "lessons/abc123"
    assert (_real(wt, "rev-parse", "HEAD").stdout.strip()
            == _real(work, "rev-parse", "origin/main").stdout.strip())


def test_author_branch_start_cleans_up_partial_worktree_on_add_failure(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    wt_base = tmp_path / "wt"
    occupied = wt_base / "lessons-abc123"
    occupied.mkdir(parents=True)
    (occupied / "in_the_way.txt").write_text("x")
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=wt_base)
    with pytest.raises(ab.BranchError):
        b.start_batch("abc123")
    assert "lessons-abc123" not in _real(work, "worktree", "list").stdout


def test_author_branch_finish_no_commits_returns_none(tmp_path: Path):
    origin, work = _origin_work(tmp_path)
    forge = _FakeForge()
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    assert b.finish_batch("abc123", wt) is None
    assert forge.open_calls == []
    assert not _real(work, "ls-remote", "--heads", "origin", "lessons/abc123").stdout.strip()


def test_author_branch_finish_pushes_and_opens_pr(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/9")
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    (wt / "added.md").write_text("from worktree\n")
    _real(wt, "add", "-A")
    _real(wt, "commit", "-q", "-m", "wt edit")
    assert b.finish_batch("abc123", wt) == "https://github.com/o/r/pull/9"
    assert forge.open_calls[0]["base"] == "main"
    assert forge.open_calls[0]["head"] == "lessons/abc123"
    assert _real(work, "ls-remote", "--heads", "origin", "lessons/abc123").stdout.strip()


def test_author_branch_finish_raises_on_gh_failure(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    b = ab.AuthorBranch(forge=_FakeForge(raises=True), repo_root=work,
                        worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    (wt / "added.md").write_text("x\n")
    _real(wt, "add", "-A")
    _real(wt, "commit", "-q", "-m", "edit")
    with pytest.raises(ab.BranchError):
        b.finish_batch("abc123", wt)


def test_author_branch_cleanup_removes_worktree(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    assert wt.is_dir()
    b.cleanup(wt)
    assert not wt.exists()


def test_author_branch_worktree_lifecycle_real_git(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    forge = _FakeForge(create_ref="https://pr/lead/1")
    b = ab.AuthorBranch(forge=forge, repo_root=work, branch_prefix="lead-author/",
                        worktree_base=tmp_path / "wt")
    head_before = _real(work, "rev-parse", "HEAD").stdout.strip()
    wt = b.start_batch("xyz789")
    (wt / "added.md").write_text("from worktree\n")
    _real(wt, "add", "-A")
    _real(wt, "commit", "-q", "-m", "wt edit")
    assert b.finish_batch("xyz789", wt) == "https://pr/lead/1"
    b.cleanup(wt)
    assert not wt.exists()
    assert _real(work, "rev-parse", "HEAD").stdout.strip() == head_before




def test_author_branch_revert_lesson_pr_removes_and_opens_pr(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad lesson\n"})
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/42")
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    ref_before = _real(work, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://github.com/o/r/pull/42"
    assert forge.open_calls[0]["head"] == "lessons/revert-bad"
    assert forge.open_calls[0]["title"] == "revert lesson: bad"
    assert _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()
    assert _real(work, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == ref_before
    assert not (tmp_path / "wt" / "lessons-revert-bad").exists()


def test_author_branch_revert_succeeds_with_dirty_dev_tree(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    (work / "dirty.txt").write_text("uncommitted\n")
    b = ab.AuthorBranch(forge=_FakeForge(create_ref="https://pr/1"),
                        repo_root=work, worktree_base=tmp_path / "wt")
    head_before = _real(work, "rev-parse", "HEAD").stdout.strip()
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://pr/1"
    assert (work / "dirty.txt").read_text() == "uncommitted\n"
    assert _real(work, "rev-parse", "HEAD").stdout.strip() == head_before


def test_author_branch_revert_reclaims_leftover_nonworktree_dir(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    wt_base = tmp_path / "wt"
    stale = wt_base / "lessons-revert-bad"
    stale.mkdir(parents=True)
    (stale / "leftover.txt").write_text("crashed-revert debris\n")
    b = ab.AuthorBranch(forge=_FakeForge(create_ref="https://pr/9"),
                        repo_root=work, worktree_base=wt_base)
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://pr/9"
    assert _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_author_branch_revert_refuses_missing_lesson_on_base(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=tmp_path / "wt")
    head_before = _real(work, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(ab.BranchError):
        b.revert_lesson_pr("defender/lessons/ghost.md", "ghost")
    assert _real(work, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not _real(work, "branch", "--list", "lessons/revert-ghost").stdout.strip()


def test_author_branch_revert_returns_existing_open_pr_idempotently(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(
        pr_rows=[{"number": 3, "headRefName": "lessons/revert-bad", "url": "https://pr/existing"}],
        create_ref="https://pr/new",
    )
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://pr/existing"
    assert forge.open_calls == []
    assert forge.head_calls == ["lessons/revert-bad"]
    assert forge.list_calls == []
    assert not _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_author_branch_revert_ignores_unrelated_open_lessons_pr(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(
        pr_rows=[{"number": 5, "headRefName": "lessons/abc123batch", "url": "https://pr/batch"}],
        create_ref="https://pr/1",
    )
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://pr/1"
    assert forge.open_calls[0]["head"] == "lessons/revert-bad"
    assert _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_author_branch_revert_fails_fast_on_stranded_remote_branch(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    _real(work, "checkout", "-q", "-b", "tmp-div", "origin/main")
    (work / "divergent.txt").write_text("stranded prior revert\n")
    _real(work, "add", "-A")
    _real(work, "commit", "-q", "-m", "divergent")
    _real(work, "push", "-q", "origin", "tmp-div:lessons/revert-bad")
    _real(work, "checkout", "-q", "main")
    _real(work, "branch", "-q", "-D", "tmp-div")
    b = ab.AuthorBranch(forge=_FakeForge(pr_rows=[]), repo_root=work, worktree_base=tmp_path / "wt")
    with pytest.raises(ab.BranchError, match="stale revert branch"):
        b.revert_lesson_pr("defender/lessons/bad.md", "bad")


def test_author_branch_revert_wraps_forge_list_error_as_branch_error(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(list_raises=True)
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    with pytest.raises(ab.BranchError, match="gh boom"):
        b.revert_lesson_pr("defender/lessons/bad.md", "bad")
    assert forge.open_calls == []
    assert not _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_author_branch_revert_idempotent_return_falls_back_to_head_without_url(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(pr_rows=[{"number": 8, "headRefName": "lessons/revert-bad"}])
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "lessons/revert-bad"
    assert forge.open_calls == []
    assert not _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_revert_cli_holds_drain_lock_and_calls_through(tmp_path: Path):
    from defender.learning.ops import revert_lesson as rl  # type: ignore[import-not-found]
    paths = LoopPaths(repo_root=tmp_path)
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(create_ref="https://pr/7")
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    assert rl.revert("bad", branch=b, paths=paths) == 0
    assert forge.open_calls[0]["head"] == "lessons/revert-bad"


def test_revert_cli_skips_when_drain_lock_held(tmp_path: Path):
    import fcntl as _fcntl

    from defender.learning.ops import revert_lesson as rl  # type: ignore[import-not-found]
    paths = LoopPaths(repo_root=tmp_path)
    lock = paths.author_drain_lock_file
    lock.parent.mkdir(parents=True, exist_ok=True)
    holder = lock.open("a+")
    _fcntl.flock(holder.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    try:
        forge = _FakeForge()
        b = ab.AuthorBranch(forge=forge, repo_root=tmp_path)
        assert rl.revert("bad", branch=b, paths=paths) == 3
        assert forge.open_calls == []
    finally:
        _fcntl.flock(holder.fileno(), _fcntl.LOCK_UN)
        holder.close()




def _make_run_dir(tmp_path: Path, *, disposition="benign", with_payload=True) -> Path:
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    (run / "alert.json").write_text(json.dumps({"rule": {"id": "r1"}}))
    (run / "report.md").write_text(f"---\ndisposition: {disposition}\n---\nbody\n")
    qrow = {
        "lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "search",
        "query_id": "elastic.auth", "params": {"host": "h1"}, "raw_command": "x",
        "exit_code": 0, "payload_status": "ok", "payload_digest": "d",
        "payload_path": "gather_raw/l-001/0.json",
    }
    (run / "executed_queries.jsonl").write_text(json.dumps(qrow) + "\n")
    (run / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"goal": "check auth", "what_to_summarize": ["accepted vs failed"]})
    )
    if with_payload:
        events = [{"user": "dev.dana", "outcome": "success"}]
        payload = (
            "### Summary\n3 events\n\n### Raw Sample Events\n\n"
            "```json\n" + json.dumps(events) + "\n```\n"
        )
        (run / "gather_raw" / "l-001" / "0.json").write_text(payload)
    return run


_COMPANION = {
    "hypothesize": {"hypotheses": [{"id": "h-mal", "name": "malicious-cred-validation", "weight": "+"}]},
    "findings": [{
        "id": "l-001",
        "resolutions": [{
            "hypothesis": "h-mal", "before": "+", "after": "--",
            "reasoning": "2s cadence => conclusively scripted automation => benign",
        }],
        "outcome": {"authorization_resolutions": [
            {"resolved_by_lead": "l-001", "fulfills": "ac1", "verdict": "authorized"},
        ]},
    }],
    "conclude": {"disposition": "benign"},
}




















