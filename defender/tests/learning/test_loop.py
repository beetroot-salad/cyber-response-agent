from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path


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
from defender.tests.support.shared._fixture_uuid import fixture_uuid
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


def _isolate(tmp_path: Path) -> tuple[object, Path]:
    paths = LoopPaths(repo_root=tmp_path, state_dir=tmp_path / "defender" / "learning")
    learning_run_dir = location_path(paths.state_root) / "runs" / "case-x"
    learning_run_dir.mkdir(parents=True)
    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)  # the root is never created lazily (#1135)
    return paths, learning_run_dir


def test_rotate_preserves_concurrent_appends(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    pending = location_path(paths.state_root) / FINDINGS.queue
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
    consumed_rows = _read_jsonl(location_path(paths.state_root) / FINDINGS.consumed)
    assert consumed_rows[0]["consumed_commit"] == "abc123"
    assert "consumed_at" in consumed_rows[0]


def test_enqueue_for_authoring_writes_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = curation_run_dir("case-a")
    enqueue_run(state_for_paths(paths), run_dir)
    # #1187: the run's id is a uuid (`curation_run_dir` derives it from the label), and
    # `enqueue_run` names the request for the run itself.
    rid = run_dir.name
    spec = json.loads((location_path(paths.state_root) / "author-queue" / f"{rid}.json").read_text())
    # The row is the run's address (#1105 PR 2 declared change 8), where it named its folder.
    assert spec == {"case_id": rid, "tenant_id": run_dir.parent.parent.name, "run_id": rid}


@pytest.fixture
def tenant(tmp_path, data_root):
    """The fixture tenant published for real, its forge bound: #1108 P4's drains batch into the
    tenant repo (flow 4), so every drain case below runs over it."""
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        yield t


def _tenant_paths(t, tmp_path: Path):
    """The tenant's learning paths over a scratch product checkout, its state root made."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths, product_repo

    paths = drain_paths(t, product_repo(tmp_path))
    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)
    return paths


def _seams(t) -> dict:
    """The drain's delivery and box seams over the tenant (assumed seams, #1108 P4: the
    tenant forge fake's client, an identity over its issuer fake, a no-op box)."""
    return {"client": t.forge.client, "identity": t.vault.identity(),
            "start_box": _noop_start_box, "stop_box": _noop_stop_box}


def _seed_curator_findings(paths, n: int = 5) -> None:
    (location_path(paths.state_root) / FINDINGS.queue).parent.mkdir(parents=True, exist_ok=True)
    with (location_path(paths.state_root) / FINDINGS.queue).open("w") as fh:
        for i in range(n):
            fh.write(json.dumps({"finding_id": f"f{i}"}) + "\n")


def test_author_drain_triggers_all_curators(tenant, tmp_path: Path):
    t = tenant
    paths = _tenant_paths(t, tmp_path)
    _seed_curator_findings(paths)
    triggered: list[str] = []
    drains.author_drain(
        paths,
        trigger_author=lambda paths, state, channel, env, module, label, **_kw: triggered.append(module),
        **_seams(t),
    )
    assert triggered == [
        "author",
        "questioner_curator",
    ]


def test_author_drain_skips_when_no_work(tenant, tmp_path: Path):
    t = tenant
    paths = _tenant_paths(t, tmp_path)
    triggered: list = []
    rc = drains.author_drain(
        paths,
        trigger_author=lambda *a, **_kw: triggered.append(a),
        **_seams(t),
    )
    assert rc == 0
    assert triggered == []
    from defender.tests.tenancy.tenant_1108_p4._drain_support import draft_entries, remote_branches

    assert draft_entries(t) == [], "a batch was started with nothing queued"
    assert remote_branches(t.remote, "") == {"main": t.origin_main()}
    assert t.forge.creates == []


def test_author_drain_singleton_lock_exits_without_work(tenant, tmp_path: Path):
    import fcntl

    t = tenant
    paths = _tenant_paths(t, tmp_path)
    _seed_curator_findings(paths)
    (location_path(paths.state_root) / AUTHOR_DRAIN_LOCK.file).parent.mkdir(parents=True, exist_ok=True)
    holder = (location_path(paths.state_root) / AUTHOR_DRAIN_LOCK.file).open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        worked: list[str] = []
        rc = drains.author_drain(
            paths,
            trigger_author=lambda *a, **_kw: worked.append("trigger"),
            **_seams(t),
        )
        assert rc == 0
        assert worked == []
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_lead_author_drain_runs_lead_author_then_clears_marker(tenant, tmp_path: Path):
    t = tenant
    paths = _tenant_paths(t, tmp_path)
    run_dir = curation_run_dir("case-b")
    enqueue_run(state_for_paths(paths), run_dir)
    seen: list[tuple[Path, Path]] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, state, run, **_kw: seen.append(
            (wt_paths.repo_root, run.run_dir)),
        **_seams(t),
    )
    assert [rd for _, rd in seen] == [run_dir.resolve()]
    assert not (location_path(paths.state_root) / "author-queue" / f"{run_dir.name}.json").exists()


def test_lead_author_drain_runs_pitfalls_after_markers(tenant, tmp_path: Path):
    t = tenant
    paths = _tenant_paths(t, tmp_path)
    run_dir = curation_run_dir("case-p")
    enqueue_run(state_for_paths(paths), run_dir)
    order: list[str] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, state, rd, **_kw: order.append("marker"),
        run_pitfalls=lambda wt_paths, state, **_kw: (order.append("pitfalls"), 0)[1],
        **_seams(t),
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


def test_lead_author_drain_marks_artifact_missing(tenant, tmp_path: Path):
    t = tenant
    paths = _tenant_paths(t, tmp_path)
    run_dir = curation_run_dir("case-real")
    enqueue_run(state_for_paths(paths), run_dir)
    # A row naming a run its tenant's repository cannot open (#1105 PR 2): the address is
    # well-formed, the run folder was never made.
    gone = run_dir.parent / fixture_uuid("case-gone")
    enqueue_run(state_for_paths(paths), gone)
    seen: list[Path] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, state, run, **_kw: seen.append(run.run_dir),
        **_seams(t),
    )
    assert seen == [run_dir.resolve()]
    assert not (location_path(paths.state_root) / "author-queue" / f"{gone.name}.json").exists()
    failed = location_path(paths.state_root) / "author-queue" / "failed" / f"{gone.name}.json"
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
def test_lead_author_drain_dead_letters_an_unservable_marker(tenant, tmp_path: Path, body: str):
    t = tenant
    paths = _tenant_paths(t, tmp_path)
    run_dir = curation_run_dir("case-real")
    enqueue_run(state_for_paths(paths), run_dir)
    (location_path(paths.state_root) / "author-queue").mkdir(parents=True, exist_ok=True)
    (location_path(paths.state_root) / "author-queue" / "case-broken.json").write_text(body, encoding="utf-8")

    seen: list[Path] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, state, run, **_kw: seen.append(run.run_dir),
        **_seams(t),
    )

    assert seen == [run_dir.resolve()], "the healthy request in the same pass was not served"
    assert not (location_path(paths.state_root) / "author-queue" / "case-broken.json").exists()
    assert not (location_path(paths.state_root) / "author-queue" / "inflight" / "case-broken.json").exists(), \
        "the unservable marker was left claimed — the next tick reclaims and re-fails on it"
    failed = location_path(paths.state_root) / "author-queue" / "failed" / "case-broken.json"
    assert json.loads(failed.read_text())["failed"].startswith("unreadable")
    assert drains._has_lead_author_work(state_for_paths(paths)) is False, \
        "the queue still reports work on a request nothing can ever serve"


def test_lead_author_drain_singleton_lock_distinct_from_lessons(tenant, tmp_path: Path):
    import fcntl

    t = tenant
    paths = _tenant_paths(t, tmp_path)
    run_dir = curation_run_dir("case-d")
    enqueue_run(state_for_paths(paths), run_dir)
    (location_path(paths.state_root) / AUTHOR_DRAIN_LOCK.file).parent.mkdir(parents=True, exist_ok=True)
    holder = (location_path(paths.state_root) / AUTHOR_DRAIN_LOCK.file).open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        seen: list = []
        rc = drains.lead_author_drain(
            paths,
            run_lead_author=lambda wt_paths, state, run, **_kw: seen.append(run.run_dir),
            **_seams(t),
        )
        assert rc == 0
        assert seen == [run_dir.resolve()]
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_lead_author_drain_quarantines_poison_run_dir(tenant, tmp_path: Path):
    t = tenant
    paths = _tenant_paths(t, tmp_path)
    poison = curation_run_dir("case-poison")
    good = curation_run_dir("case-good")
    enqueue_run(state_for_paths(paths), poison)
    enqueue_run(state_for_paths(paths), good)
    seen: list[Path] = []

    def maybe_boom(wt_paths, state, run, *, box=None, **_kw) -> None:
        if run.run_dir.name == poison.name:
            raise RuntimeError("lead-author blew up")
        seen.append(run.run_dir)

    drains.lead_author_drain(
        paths, run_lead_author=maybe_boom, **_seams(t),
    )
    assert seen == [good.resolve()]
    assert not (location_path(paths.state_root) / "author-queue" / f"{poison.name}.json").exists()
    failed = location_path(paths.state_root) / "author-queue" / "failed" / f"{poison.name}.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_quarantines_on_nonzero_rc(tenant, tmp_path: Path, monkeypatch):
    import defender.learning.leads.lead_author as la

    t = tenant
    paths = _tenant_paths(t, tmp_path)
    run_dir = curation_run_dir("case-rc")
    enqueue_run(state_for_paths(paths), run_dir)
    # lint-monkeypatch: ok — drives the real _invoke_lead_author; _run_curator_module
    monkeypatch.setattr(la, "run_under_held_queue_lock", lambda rd, paths=None, box=None, **_kw: 2)  # lint-monkeypatch: ok
    drains.lead_author_drain(paths, **_seams(t))
    assert not (location_path(paths.state_root) / "author-queue" / f"{run_dir.name}.json").exists()
    failed = location_path(paths.state_root) / "author-queue" / "failed" / f"{run_dir.name}.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_bounded_retry_then_quarantine(tenant, tmp_path: Path, monkeypatch):
    import defender.learning.leads.lead_author as la

    t = tenant
    paths = _tenant_paths(t, tmp_path)
    run_dir = curation_run_dir("case-transient")
    enqueue_run(state_for_paths(paths), run_dir)
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "3")

    def boom(rd, paths=None, box=None, **_kw):
        raise OSError("disk hiccup")

    # lint-monkeypatch: ok — same intentional seam as the rc=2 test above: drives the
    monkeypatch.setattr(la, "run_under_held_queue_lock", boom)  # lint-monkeypatch: ok
    marker = location_path(paths.state_root) / "author-queue" / f"{run_dir.name}.json"
    failed = location_path(paths.state_root) / "author-queue" / "failed" / f"{run_dir.name}.json"

    for expected in (1, 2):
        drains.lead_author_drain(paths, **_seams(t))
        assert marker.exists()
        assert json.loads(marker.read_text())["attempts"] == expected
        assert not failed.exists()

    drains.lead_author_drain(paths, **_seams(t))
    assert not marker.exists()
    assert json.loads(failed.read_text())["failed"].startswith("transient-exhausted")
