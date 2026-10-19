from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from defender._yaml import safe_load
from defender.learning import loop

RunUnprocessable = loop.RunUnprocessable
LoopPaths = loop.LoopPaths

from defender.learning.core import drains as drains  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.core.state import AUTHOR_DRAIN_LOCK, FINDINGS  # noqa: E402
from defender.tests.support.learning.core._state1135 import curation_run_dir, enqueue_run, state_for_paths  # noqa: E402
from defender.learning.core import persist as persist  # type: ignore[import-not-found]  # noqa: E402
from defender import _io as _io  # type: ignore[import-not-found]  # noqa: E402


def test_reply_document_text_passes_through_plain_yaml():
    """Shape 1: a bare document comes back stripped and unchanged (#1018 M1 step 5)."""
    assert loop.reply_document_text("outcome: caught\nconfidence: high\n") == (
        "outcome: caught\nconfidence: high"
    )


def test_reply_document_text_unwraps_a_whole_string_yaml_fence():
    """Shape 2: exactly one fenced block, nothing around it, is the document it holds (#1018
    M1 step 4 — the one deliberate leniency)."""
    fenced = "```yaml\noutcome: caught\n```\n"
    assert loop.reply_document_text(fenced) == "outcome: caught"


def test_reply_document_text_leaves_a_trailing_close_tag_for_the_loader_to_refuse():
    text = "outcome: caught\nconfidence: high\n</content>\n"
    assert loop.reply_document_text(text) == text.strip()
    with pytest.raises(yaml.YAMLError):
        safe_load(loop.reply_document_text(text))


def test_reply_document_text_refuses_a_dangling_close_fence():
    """#1018 M4 ("no dangling-closer trim"): a lone column-0 ``` after a plain document is "a
    fence inside the reply" — `MalformedReply`, not a trim. Would fail: the closer is trimmed."""
    text = "outcome: caught\nconfidence: high\n```\n"
    with pytest.raises(loop.MalformedReply):
        loop.reply_document_text(text)


def test_reply_document_text_strips_thinking_prelude():
    """Shape 13 / E8: a column-0 `</thinking>` line ends a prelude that has no opening tag —
    the recorded live shape (#1018 M1 step 2)."""
    text = (
        "outcome: caught\n(reasoning trace…)\n</thinking>\n"
        "outcome: survived\nconfidence: high\n"
    )
    assert loop.reply_document_text(text) == "outcome: survived\nconfidence: high"


def _read_jsonl(path: Path) -> list[dict]:
    return _io.read_jsonl_rows(path)


def _noop_start_box(request, **_kw):
    """A no-op box lifecycle for drain tests predating #665's box wiring — these tests exercise
    the worktree/branch/queue mechanics, not the (separately spec'd) box lifecycle."""
    from types import SimpleNamespace

    return SimpleNamespace(name=request.name, sandboxed=False)


def _noop_stop_box(_box, **_kw):
    pass


def _noop_scrub(_path, **_kw):
    pass


def _isolate(tmp_path: Path) -> tuple[object, Path]:
    paths = LoopPaths(repo_root=tmp_path)
    learning_run_dir = paths.state_root / "runs" / "case-x"
    learning_run_dir.mkdir(parents=True)
    paths.state_root.mkdir(parents=True, exist_ok=True)  # the root is never created lazily (#1135)
    return paths, learning_run_dir


def test_rotate_preserves_concurrent_appends(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    pending = paths.state_root / FINDINGS.queue
    pending.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {"finding_id": "r/0", "v": "f1"},
        {"finding_id": "r/1", "v": "f2"},
        {"finding_id": "r/2", "v": "f3-new-arrival"},
    ]
    pending.write_text("".join(json.dumps(r) + "\n" for r in rows))

    held = [{"finding_id": "r/1", "v": "f2", "held_reason": "no_ground_truth"}]
    consumed = [{"finding_id": "r/0", "v": "f1", "consumed_category": "consumed_committed"}]
    state_for_paths(paths).rotate(FINDINGS, held, consumed, "abc123")

    survivors = _read_jsonl(pending)
    assert {s["finding_id"] for s in survivors} == {"r/1", "r/2"}
    held_row = next(s for s in survivors if s["finding_id"] == "r/1")
    assert held_row["held_reason"] == "no_ground_truth"
    consumed_rows = _read_jsonl(paths.state_root / FINDINGS.consumed)
    assert consumed_rows[0]["consumed_commit"] == "abc123"
    assert "consumed_at" in consumed_rows[0]


def test_enqueue_for_authoring_writes_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-a")
    enqueue_run(state_for_paths(paths), run_dir)
    spec = json.loads((paths.state_root / "author-queue" / "case-a.json").read_text())
    # The row is the run's address (#1105 PR 2 declared change 8), where it named its folder.
    assert spec == {"case_id": "case-a", "tenant_id": run_dir.parent.parent.name,
                    "run_id": "case-a"}


class _FakeBranch:

    def __init__(
        self, *, prefix: str = "lessons/", pr_exists: bool = False, commits: int = 1,
        worktree: Path | None = None,
    ):
        self.branch_prefix = prefix
        self._pr_exists = pr_exists
        self._commits = commits
        self._worktree = worktree
        self.events: list[str] = []

    def branch_name(self, batch_id: str) -> str:
        # The real `AuthorBranch.branch_name`, verbatim: #952's failure log names the local
        # branch the commit was retained on, so the fake has to answer for it.
        return f"{self.branch_prefix}{batch_id}"

    def open_pr_exists(self) -> bool:
        self.events.append("lease-check")
        return self._pr_exists

    def start_batch(self, batch_id: str) -> Path:
        self.events.append("start")
        return self._worktree if self._worktree is not None else Path(f"/tmp/wt-{batch_id}")

    def finish_batch(self, batch_id: str, wt: Path):
        self.events.append("finish")
        return f"PR/{batch_id}" if self._commits else None

    def cleanup(self, wt: Path) -> None:
        self.events.append("cleanup")


def _declarable_worktree(tmp_path: Path) -> Path:
    """A committed tree declaring one system, for `_FakeBranch(worktree=...)`."""
    from defender.tests.support.runtime.engine._declared869 import seed_tree

    return seed_tree(tmp_path, name="wt", adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",))


def _seed_curator_findings(paths, n: int = 5) -> None:
    (paths.state_root / FINDINGS.queue).parent.mkdir(parents=True, exist_ok=True)
    with (paths.state_root / FINDINGS.queue).open("w") as fh:
        for i in range(n):
            fh.write(json.dumps({"finding_id": f"f{i}"}) + "\n")


def test_author_drain_triggers_all_curators(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    triggered: list[str] = []
    drains.author_drain(
        paths,
        trigger_author=lambda paths, state, channel, env, module, label, **_kw: triggered.append(module),
        branch=_FakeBranch(),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert triggered == [
        "author",
        "questioner_curator",
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
    (paths.state_root / AUTHOR_DRAIN_LOCK.file).parent.mkdir(parents=True, exist_ok=True)
    holder = (paths.state_root / AUTHOR_DRAIN_LOCK.file).open("a+")
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
    run_dir = curation_run_dir("case-b")
    enqueue_run(state_for_paths(paths), run_dir)
    seen: list[tuple[Path, Path]] = []
    branch = _FakeBranch(prefix="lead-author/")
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, state, run, **_kw: seen.append(
            (wt_paths.repo_root, run.run_dir)),
        branch=branch,
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert [rd for _, rd in seen] == [run_dir.resolve()]
    assert str(seen[0][0]).startswith("/tmp/wt-")
    assert not (paths.state_root / "author-queue" / "case-b.json").exists()
    assert branch.events == ["lease-check", "start", "finish", "cleanup"]


def test_lead_author_drain_runs_pitfalls_after_markers(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-p")
    enqueue_run(state_for_paths(paths), run_dir)
    order: list[str] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, state, rd, **_kw: order.append("marker"),
        run_pitfalls=lambda wt_paths, state, **_kw: (order.append("pitfalls"), 0)[1],
        branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert order == ["marker", "pitfalls"]


def test_has_lead_author_work_fires_on_pitfalls_threshold(tmp_path: Path, monkeypatch):
    from defender.learning.core import persist
    paths, _ = _isolate(tmp_path)
    assert drains._has_lead_author_work(state_for_paths(paths)) is False
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    # Digest-less rows stay two distinct MISTAKES post-#840: an absent diagnosis is not a
    # shared one, so `pitfall_key` keys each such row to itself rather than folding them.
    persist.append_pitfalls(
        [{"pitfall_id": f"r:{i}", "system": "elastic"} for i in range(2)], state=state_for_paths(paths)
    )
    assert drains._has_lead_author_work(state_for_paths(paths)) is True


def test_lead_author_drain_marks_artifact_missing(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-real")
    enqueue_run(state_for_paths(paths), run_dir)
    # A row naming a run its tenant's repository cannot open (#1105 PR 2): the address is
    # well-formed, the run folder was never made.
    gone = run_dir.parent / "case-gone"
    enqueue_run(state_for_paths(paths), gone)
    seen: list[Path] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, state, run, **_kw: seen.append(run.run_dir),
        branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert seen == [run_dir.resolve()]
    assert not (paths.state_root / "author-queue" / "case-gone.json").exists()
    failed = paths.state_root / "author-queue" / "failed" / "case-gone.json"
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
    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-real")
    enqueue_run(state_for_paths(paths), run_dir)
    (paths.state_root / "author-queue").mkdir(parents=True, exist_ok=True)
    (paths.state_root / "author-queue" / "case-broken.json").write_text(body, encoding="utf-8")

    seen: list[Path] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, state, run, **_kw: seen.append(run.run_dir),
        branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )

    assert seen == [run_dir.resolve()], "the healthy request in the same pass was not served"
    assert not (paths.state_root / "author-queue" / "case-broken.json").exists()
    assert not (paths.state_root / "author-queue" / "inflight" / "case-broken.json").exists(), \
        "the unservable marker was left claimed — the next tick reclaims and re-fails on it"
    failed = paths.state_root / "author-queue" / "failed" / "case-broken.json"
    assert json.loads(failed.read_text())["failed"].startswith("unreadable")
    assert drains._has_lead_author_work(state_for_paths(paths)) is False, \
        "the queue still reports work on a request nothing can ever serve"


def test_lead_author_drain_skips_when_lease_held(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-lease")
    enqueue_run(state_for_paths(paths), run_dir)
    seen: list = []
    branch = _FakeBranch(prefix="lead-author/", pr_exists=True)
    rc = drains.lead_author_drain(
        paths, run_lead_author=lambda wt_paths, state, run, **_kw: seen.append(run.run_dir),
        branch=branch, start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert rc == 0
    assert seen == []
    assert "start" not in branch.events
    assert (paths.state_root / "author-queue" / "case-lease.json").exists()


def test_lead_author_drain_singleton_lock_distinct_from_lessons(tmp_path: Path):
    import fcntl

    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-d")
    enqueue_run(state_for_paths(paths), run_dir)
    (paths.state_root / AUTHOR_DRAIN_LOCK.file).parent.mkdir(parents=True, exist_ok=True)
    holder = (paths.state_root / AUTHOR_DRAIN_LOCK.file).open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        seen: list = []
        rc = drains.lead_author_drain(
            paths,
            run_lead_author=lambda wt_paths, state, run, **_kw: seen.append(run.run_dir),
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
    poison = curation_run_dir("case-poison")
    good = curation_run_dir("case-good")
    enqueue_run(state_for_paths(paths), poison)
    enqueue_run(state_for_paths(paths), good)
    seen: list[Path] = []

    def maybe_boom(wt_paths, state, run, *, box=None, **_kw) -> None:
        if run.run_dir.name == "case-poison":
            raise RuntimeError("lead-author blew up")
        seen.append(run.run_dir)

    drains.lead_author_drain(
        paths, run_lead_author=maybe_boom, branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert seen == [good.resolve()]
    assert not (paths.state_root / "author-queue" / "case-poison.json").exists()
    failed = paths.state_root / "author-queue" / "failed" / "case-poison.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_quarantines_on_nonzero_rc(tmp_path: Path, monkeypatch):
    import defender.learning.leads.lead_author as la

    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-rc")
    enqueue_run(state_for_paths(paths), run_dir)
    # lint-monkeypatch: ok — drives the real _invoke_lead_author; _run_curator_module
    monkeypatch.setattr(la, "run_under_held_queue_lock", lambda rd, paths=None, box=None, **_kw: 2)  # lint-monkeypatch: ok
    branch = _FakeBranch(prefix="lead-author/", worktree=_declarable_worktree(tmp_path))
    drains.lead_author_drain(paths, branch=branch, start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert not (paths.state_root / "author-queue" / "case-rc.json").exists()
    failed = paths.state_root / "author-queue" / "failed" / "case-rc.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_bounded_retry_then_quarantine(tmp_path: Path, monkeypatch):
    import defender.learning.leads.lead_author as la

    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-transient")
    enqueue_run(state_for_paths(paths), run_dir)
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "3")

    def boom(rd, paths=None, box=None, **_kw):
        raise OSError("disk hiccup")

    # lint-monkeypatch: ok — same intentional seam as the rc=2 test above: drives the
    monkeypatch.setattr(la, "run_under_held_queue_lock", boom)  # lint-monkeypatch: ok
    marker = paths.state_root / "author-queue" / "case-transient.json"
    failed = paths.state_root / "author-queue" / "failed" / "case-transient.json"
    wt = _declarable_worktree(tmp_path)

    for expected in (1, 2):
        drains.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/", worktree=wt), start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
        assert marker.exists()
        assert json.loads(marker.read_text())["attempts"] == expected
        assert not failed.exists()

    drains.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/", worktree=wt), start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert not marker.exists()
    assert json.loads(failed.read_text())["failed"].startswith("transient-exhausted")


def test_lead_author_drain_opens_distinct_lead_author_pr(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-pr")
    enqueue_run(state_for_paths(paths), run_dir)
    _, work = _origin_work(tmp_path)
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/77")
    branch = ab.AuthorBranch(
        forge=forge, repo_root=work, branch_prefix="lead-author/",
        pr_title=drains._lead_author_pr_title, pr_body=drains._lead_author_pr_body,
        worktree_base=tmp_path / "wt",
    )

    def _author(wt_paths, state, run, *, box=None, **_kw):
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


def test_lead_author_drain_delivers_a_retained_branch_on_the_next_tick(tmp_path: Path, capsys):
    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-pr")
    enqueue_run(state_for_paths(paths), run_dir)
    origin, work = _origin_work(tmp_path)
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/78", raises=True)
    branch = ab.AuthorBranch(
        forge=forge, repo_root=work, branch_prefix="lead-author/",
        pr_title=drains._lead_author_pr_title, pr_body=drains._lead_author_pr_body,
        worktree_base=tmp_path / "wt",
    )
    served: list[Path] = []

    def _author(wt_paths, state, run, *, box=None, **_kw):
        served.append(run.run_dir)
        f = wt_paths.repo_root / "defender" / "skills" / "note.md"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("edit\n")
        _real(wt_paths.repo_root, "add", "-A")
        _real(wt_paths.repo_root, "commit", "-q", "-m", "lead edit")

    assert drains.lead_author_drain(
        paths, run_lead_author=_author, branch=branch,
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    ) == 0
    assert len(forge.open_calls) == 1
    head = forge.open_calls[0]["head"]
    records = sorted((paths.state_root / "_pending_delivery").glob("*.json"))
    assert [json.loads(r.read_text())["branch"] for r in records] == [head]
    assert not (paths.state_root / "author-queue" / "case-pr.json").exists(), "the served run was re-queued"
    assert _real(work, "rev-parse", "--verify", f"refs/heads/{head}").returncode == 0
    capsys.readouterr()

    forge.raises = False
    assert drains.lead_author_drain(
        paths, run_lead_author=_author, branch=branch,
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    ) == 0

    assert len(served) == 1, "the retained batch's run was served again"
    assert [c["head"] for c in forge.open_calls] == [head, head]
    assert forge.head_calls == [head], "delivery must look for an open PR before opening one"
    assert list((paths.state_root / "_pending_delivery").glob("*.json")) == []
    remote = _real(work, "ls-remote", "--heads", str(origin), head).stdout
    assert head in remote, "the retained branch never reached origin"
    err = capsys.readouterr().err
    assert f"delivered retained branch {head}: opened PR https://github.com/o/r/pull/78" in err


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
    poison = curation_run_dir("case-a-poison")
    good = curation_run_dir("case-b-good")
    enqueue_run(state_for_paths(paths), poison)
    enqueue_run(state_for_paths(paths), good)

    clean_at_entry: dict[str, bool] = {}

    def run_lead_author(p, state, run, *, box=None, **_kw) -> None:
        st = _subprocess.run(
            ["git", "-C", str(p.repo_root), "status", "--porcelain"],
            capture_output=True, text=True,
        )
        clean_at_entry[run.run_dir.name] = st.stdout.strip() == ""
        if run.run_dir.name == "case-a-poison":
            (p.repo_root / "defender" / "skills" / "gather" / "queries"
             / "wazuh" / "auth-events.md").unlink()
            raise RuntimeError("scope-gate boom")

    drains._drain_lead_author_markers(paths, state_for_paths(paths), run_lead_author,
                                      data_root=drains._data_root())

    assert clean_at_entry["case-a-poison"] is True
    assert clean_at_entry["case-b-good"] is True
    end = _subprocess.run(["git", "-C", str(wt), "status", "--porcelain"],
                          capture_output=True, text=True)
    assert end.stdout.strip() == ""
    assert (paths.state_root / "author-queue" / "failed" / "case-a-poison.json").exists()
    assert not (paths.state_root / "author-queue" / "case-b-good.json").exists()


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
    assert rl.revert("bad", state=state_for_paths(paths), branch=b) == 0
    assert forge.open_calls[0]["head"] == "lessons/revert-bad"


def test_revert_cli_skips_when_drain_lock_held(tmp_path: Path):
    import fcntl as _fcntl

    from defender.learning.ops import revert_lesson as rl  # type: ignore[import-not-found]
    paths = LoopPaths(repo_root=tmp_path)
    lock = paths.state_root / AUTHOR_DRAIN_LOCK.file
    lock.parent.mkdir(parents=True, exist_ok=True)
    holder = lock.open("a+")
    _fcntl.flock(holder.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    try:
        forge = _FakeForge()
        b = ab.AuthorBranch(forge=forge, repo_root=tmp_path)
        assert rl.revert("bad", state=state_for_paths(paths), branch=b) == 3
        assert forge.open_calls == []
    finally:
        _fcntl.flock(holder.fileno(), _fcntl.LOCK_UN)
        holder.close()
