"""The learning-state handle: constructor/root, the refusal contract (links, FIFOs, planted
entries) per operation kind, conversion of core refusals, ordinary errors, rotate and lock opens."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import contextlib
import errno
import fcntl
import json
import logging
import os
import threading
import time
from pathlib import Path

import pytest

from defender import _io
from defender.learning.author import drain as author_drain_mod
from defender.learning.core import config, drains, faults
from defender.learning.core.cli import _run_stage
from defender.learning.core.config import FatalConfigError, LoopPaths
from defender.tests.support.shared.filesystem import _umask
from defender.tests.learning.state_contracts import _spec1135 as S

ENV = "DEFENDER_LEARNING_STATE_DIR"


def _finding(fid: str, **extra) -> dict:
    return {"finding_id": fid, "run_id": fid.split("/")[0], "direction": "adversarial", **extra}


def _pitfall(pid: str) -> dict:
    return {"pitfall_id": pid, "system": "elastic", "failure": "a failing query"}


def _drain_stage(data_root: Path, shape: str) -> tuple[int | None, BaseException | None, Path]:
    """One curator-drain stage through `_run_stage` over a tenant (#1108 P4 flow 4: the drain
    serves an accepted tenant's own learning root) whose learning root has `shape` — `missing`,
    `not-a-folder` or a `dangling` link — every non-state seam faked (no model, no box; the
    forge and issuer P3's fakes): `(exit code, what escaped _run_stage, the root's spelling)`.
    The tenant is a second one under the test's data root, its scratch kept outside `tmp_path`,
    so the test's own snapshots and D9's runs are untouched."""
    import tempfile

    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        BoxSpy, author_drain, drain_paths, product_repo)
    from defender.tests.tenancy.tenant_1108_p4._support import (
        OTHER_TENANT_ID, bind_forge, published_tenant)

    scratch = Path(tempfile.mkdtemp(prefix="p4-drain-stage-", dir=data_root.parent))
    out: dict[str, int] = {}
    with published_tenant(scratch / "forge", root=data_root, tenant_id=OTHER_TENANT_ID,
                          repo_name="stage") as t:
        bind_forge(t)
        root = Path(location_path(t.tenant.learning))
        if shape == "not-a-folder":
            root.write_text("a file, not a folder\n", encoding="utf-8")
        elif shape == "dangling":
            root.symlink_to(scratch / "gone" / "learning")
        paths = drain_paths(t, product_repo(scratch))

        def stage() -> None:
            out["rc"] = author_drain(t, paths, trigger=None, box=BoxSpy())

        escaped = S.caught(stage)
        kind = S.entry_kind(root)
    assert kind == {"missing": "absent", "not-a-folder": "file", "dangling": "link"}[shape], \
        f"the tenant's {shape} learning root was created or replaced: {kind}"
    if shape == "dangling":
        assert S.entry_kind(scratch / "gone") == "absent", "something was created at the target"
    return out.get("rc"), escaped, root


def _critical_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.CRITICAL]


def _claim_all(state) -> list:
    """One whole claim pass, every claim held (as a pass holds them)."""
    return list(state.claim("case_id"))


def test_state_refused_is_a_systemic_fault_no_oserror_arm_holds(tmp_path: Path, caplog):
    # rejected: a StateRefused subclassing OSError (every `except OSError` arm would catch it;
    # X2 shows today's arms swallow the core's refusal exactly that way)
    paths = S.built_paths(tmp_path)
    S.plant(location_path(paths.state_root) / "_pending" / "findings.jsonl", "symlink", target=S.outside(tmp_path))
    state = S.LearningState.open(paths)
    refused = S.caught(lambda: state.rows(S.coined("FINDINGS")))

    assert S.is_refusal(refused), f"a planted queue link did not raise StateRefused: {refused!r}"
    assert not isinstance(refused, OSError), "StateRefused must not be an OSError"
    assert "findings.jsonl" in str(refused.record), "StateRefused does not carry the refused record"
    assert refused.reason, "StateRefused does not carry its reason"
    assert S.StateRefused in faults.SYSTEMIC_FAULTS, "StateRefused is not a SYSTEMIC_FAULTS member"
    assert not isinstance(refused, author_drain_mod.RETIRE_SET), "StateRefused is in RETIRE_SET"

    def boom() -> None:
        raise refused

    dead_lettered: list[Exception] = []
    escaped = S.caught(lambda: faults.run_or_dead_letter(boom, dead_lettered.append))
    assert escaped is refused, "run_or_dead_letter did not re-raise the refusal"
    assert dead_lettered == [], "run_or_dead_letter dead-lettered a refusal"

    caplog.set_level(logging.INFO)
    escaped = S.caught(lambda: drains._run_curator_module("author", lambda mod: boom()))
    assert escaped is refused, "_run_curator_module swallowed a refusal"
    assert not any("continuing" in r.getMessage() for r in caplog.records), \
        "_run_curator_module logged a refusal as a crash it continues past"

    caplog.clear()
    assert _run_stage(boom) == 2, "_run_stage did not map the refusal to exit 2"
    assert any("findings.jsonl" in line for line in _critical_lines(caplog)), \
        "the stage's CRITICAL line does not name the refused record"


def test_open_holds_the_resolved_existing_scratch_root(tmp_path: Path):
    # Explicit scratch paths retain the handle's resolved-once semantics.
    real = tmp_path / "real"
    elsewhere = tmp_path / "elsewhere"
    real.mkdir()
    elsewhere.mkdir()
    link = tmp_path / "spelled"
    link.symlink_to(real)
    paths = LoopPaths(repo_root=tmp_path / "repo", state_dir=link)

    state = S.LearningState.open(paths)
    link.unlink()
    link.symlink_to(elsewhere)  # the spelling moves after open; the held root must not
    state.append(S.coined("PITFALLS"), [_pitfall("p-1")])

    assert S.jsonl_rows(real / "_pending_pitfalls" / "pitfalls.jsonl") == [_pitfall("p-1")], \
        "the write did not land in the root the spelling named at open"
    assert S.tree_snapshot(elsewhere) == {}, "the handle re-resolved the root after open"

    factories = {
        name for name, member in vars(S.LearningState).items()
        if not name.startswith("_") and isinstance(member, (classmethod, staticmethod))
    }
    assert factories == {"open"}, f"LearningState has another constructor: {sorted(factories)}"


@pytest.mark.parametrize("shape", ["missing", "not-a-folder"])
def test_a_missing_root_is_an_error_and_is_never_created(tmp_path: Path, data_root: Path,
                                                         monkeypatch, caplog, shape):
    from defender import run_common
    from defender.box import _scrub as scrub_mod
    from defender.tests.support.sandbox._spec791 import make_run_dir

    parent = tmp_path / "nested"
    root = parent / "learning-state"
    if shape == "not-a-folder":
        parent.mkdir()
        root.write_text("a file, not a folder\n", encoding="utf-8")
    before = S.tree_snapshot(tmp_path)
    paths = LoopPaths(repo_root=tmp_path / "repo", state_dir=root)

    opened = S.caught(lambda: S.LearningState.open(paths))
    assert isinstance(opened, FatalConfigError), f"open answered {opened!r}"
    assert str(root.resolve()) in str(opened), f"the error does not name the root: {opened}"

    # The run's tenant (D9's, set up by `curation_run_dir` on a FRESH data root) is made before
    # the drain stage publishes its second tenant under the same data root: set-up refuses a
    # data root that already holds another tenant.
    planted = S.curation_run_dir("case-r15")
    run_dir = make_run_dir(planted.parent, name=planted.name, disposition="benign")
    scrub_mod.scrub(run_dir)

    caplog.set_level(logging.INFO)
    rc, escaped, tenant_root = _drain_stage(data_root, shape)
    assert escaped is None, f"the drain stage raised {escaped!r}"
    assert rc == 2, f"the drain stage answered rc={rc}"
    assert any(str(tenant_root) in line for line in _critical_lines(caplog)), \
        "the stage's CRITICAL line does not name the tenant's learning root"

    caplog.clear()
    # The run-end fault belongs to the run's tenant, independent of the scratch root above.
    run_state = run_dir.parent.parent / "learning"
    if run_state.exists():
        run_state.rmdir()
    if shape == "not-a-folder":
        run_state.write_text("a file, not a folder\n", encoding="utf-8")
    monkeypatch.setenv(ENV, str(run_state))  # safe input for the pre-#1186 implementation
    answered: list[bool] = []
    enqueued = S.caught(lambda: answered.append(
        run_common.enqueue_curation(S.run_of(run_dir), run_dir / "alert.json")))
    assert enqueued is None, f"the run-end enqueue raised {enqueued!r} into the investigation"
    assert answered == [False], f"the run-end enqueue answered {answered!r}"
    assert any(str(run_state) in r.getMessage() for r in caplog.records), "E1 did not log the tenant root error"

    created = {k for k in S.tree_snapshot(tmp_path) if k not in before and k.split(os.sep)[0]
               not in ("runs", "worktrees")}
    assert not created, f"a missing root was created, or written below: {sorted(created)}"
    assert {k: v for k, v in S.tree_snapshot(tmp_path).items() if k in before} == before, \
        "an entry that existed before was changed"
    assert S.entry_kind(root) == ("absent" if shape == "missing" else "file"), \
        "the spelled root was created or replaced"


def test_1135_root_is_a_dangling_link(tmp_path: Path, data_root: Path, monkeypatch, caplog):
    from defender.learning.frontend import serialize_queues

    target = tmp_path / "gone" / "learning-state"
    link = tmp_path / "state-link"
    link.symlink_to(target)
    paths = LoopPaths(repo_root=tmp_path / "repo", state_dir=link)

    opened = S.caught(lambda: S.LearningState.open(paths))
    assert isinstance(opened, FatalConfigError), f"a dangling root answered {opened!r}"
    assert not S.is_refusal(opened), f"a dangling root answered a refusal {opened!r}"
    assert str(target) in str(opened), f"the error does not name the resolved root: {opened}"

    caplog.set_level(logging.INFO)
    rc, escaped, tenant_root = _drain_stage(data_root, "dangling")
    assert escaped is None, f"the drain stage raised {escaped!r}"
    assert rc == 2, f"the drain stage answered rc={rc}"
    assert any(str(tenant_root) in line or "gone" in line for line in _critical_lines(caplog)), \
        "the stage's CRITICAL line does not name the tenant's learning root"

    page: dict[str, object] = {}
    built = S.caught(lambda: page.update(serialize_queues.stamped_view(paths)))
    assert isinstance(built, FatalConfigError), f"the page build over a dangling root raised {built!r}"
    assert not page, f"the page built over a dangling root ({sorted(page)[:4]}…)"
    assert S.entry_kind(tmp_path / "gone") == "absent", "something was created at the target"


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_1135_unset_and_empty_state_env_keep_the_explicit_tenant_root(data_root, monkeypatch, value):
    """#1186 O1: absence of the retired override never selects the code package."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    tenant = set_up_tenant(data_root)
    location_path(tenant.learning).mkdir(parents=True, exist_ok=True)
    if value is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, value)
    package = S.DEFENDER / "learning"
    listing = sorted(os.listdir(package))
    paths = config.LoopPaths.for_tenant(tenant)
    assert location_path(paths.state_root) == location_path(tenant.learning)
    with S.LearningState.open(paths) as state:
        described = state.describe(S.coined("FINDINGS"))
        assert described == str(location_path(tenant.learning) / "_pending" / "findings.jsonl")
    assert sorted(os.listdir(package)) == listing, "opening tenant state changed the package"



@pytest.mark.parametrize("at", ["queue-file", "holding-folder"])
def test_a_linked_queue_read_raises_and_never_reads_as_empty(tmp_path: Path, at):
    # rejected: N14 — a refused read is never folded to empty outside E1-E3
    paths = S.built_paths(tmp_path)
    outside_dir = tmp_path / "outside"
    payload = (json.dumps(_finding("x/0")) + "\n").encode()
    with S.fifo_holding(outside_dir / "findings.jsonl", payload) as unread:
        if at == "queue-file":
            planted = S.plant(location_path(paths.state_root) / "_pending" / "findings.jsonl", "symlink",
                              target=outside_dir / "findings.jsonl")
        else:
            planted = S.plant(location_path(paths.state_root) / "_pending", "symlink", target=outside_dir)
        before = S.tree_snapshot(outside_dir)

        state = S.LearningState.open(paths)
        answer: list = []
        finished, _, refused = S.within(
            10, lambda: answer.append(state.rows(S.coined("FINDINGS"))))
        assert finished, "the read blocked on the link's target: it opened and read through the link"
        assert unread(), "the link's target was read: its row is no longer in the pipe"

    assert S.is_refusal(refused), f"rows() answered {answer!r} / raised {refused!r}"
    assert answer == [], "a refused read returned rows"
    assert "_pending" in str(refused), "the refusal does not name the queue"
    assert S.tree_snapshot(outside_dir) == before, "the link's target was touched"
    assert S.entry_kind(planted) == "link", "the planted link was not left in place"


def test_a_plain_queue_reads_its_rows_and_an_absent_one_reads_empty(tmp_path: Path):
    paths = S.built_paths(tmp_path)
    state = S.LearningState.open(paths)
    findings = S.coined("FINDINGS")

    absent: list = []
    raised = S.caught(lambda: absent.append(state.rows(findings)))
    assert raised is None, f"an absent queue raised {raised!r}"
    assert len(absent) == 1, f"an absent queue answered {absent!r}"
    assert S.rows_of(absent[0]) == [], f"an absent queue answered {absent!r}"
    assert S.entry_kind(location_path(paths.state_root) / "_pending") == "absent", "a read created _pending/"

    rows = [_finding("a/0"), _finding("a/1")]
    S.write_jsonl(location_path(paths.state_root) / "_pending" / "findings.jsonl", rows)
    assert S.rows_of(state.rows(findings)) == rows, "a plain queue did not read its rows"


@pytest.mark.parametrize(("mode", "at"), [("replace", "record"), ("replace", "holding-folder"),
                                     ("create", "record")])
def test_a_linked_write_target_raises_in_either_mode_and_is_never_slot_taken(tmp_path: Path,
                                                                            mode, at):
    paths = S.built_paths(tmp_path)
    S.seed_request(paths, "case-x", S.curation_run_dir("run-a"))
    state = S.LearningState.open(paths)
    claims = _claim_all(state)
    assert len(claims) == 1, f"the plain request was not claimed: {claims!r}"
    claim = claims[0]
    queue = location_path(paths.state_root) / "author-queue"
    target = S.outside(tmp_path, "case-x.json", '{"outside": true}\n')
    if at == "holding-folder":
        (queue / "inflight" / "case-x.json").unlink()
        (queue / "inflight").rmdir()
        planted = S.plant(queue / "inflight", "symlink", target=target.parent)
    elif mode == "replace":
        (queue / "inflight" / "case-x.json").unlink()
        planted = S.plant(queue / "inflight" / "case-x.json", "symlink", target=target)
    else:
        planted = S.plant(queue / "case-x.json", "symlink", target=target)
    before = S.tree_snapshot(tmp_path / "outside")

    answer: list = []
    if mode == "replace":
        refused = S.caught(lambda: answer.append(state.stamp(claim, {**claim.spec, "attempts": 1})))
    else:
        refused = S.caught(lambda: answer.append(state.requeue(claim)))

    assert S.is_refusal(refused), f"the {mode} write answered {answer!r} / raised {refused!r}"
    assert False not in answer, "a refused slot was answered 'slot taken'"
    assert S.tree_snapshot(tmp_path / "outside") == before, "a write went through the link"
    assert S.entry_kind(planted) == "link", "the planted link was not left in place"


def test_a_plain_write_lands_in_either_mode(tmp_path: Path):
    paths = S.built_paths(tmp_path)
    S.seed_request(paths, "case-x", S.curation_run_dir("run-a"))
    state = S.LearningState.open(paths)
    claims = _claim_all(state)
    assert len(claims) == 1, f"the plain request was not claimed: {claims!r}"
    claim = claims[0]
    queue = location_path(paths.state_root) / "author-queue"
    stamped = {**claim.spec, "attempts": 1}

    state.stamp(claim, stamped)
    assert json.loads((queue / "inflight" / "case-x.json").read_text(encoding="utf-8")) == stamped, \
        "stamp did not replace the claim's record"

    requeued = state.requeue(claim)
    assert requeued is True, f"a requeue into a free slot answered {requeued!r}"
    slot = queue / "case-x.json"
    assert S.entry_kind(slot) == "file", "the requeued record is not a plain file"
    assert os.lstat(slot).st_nlink == 1, "the requeued record is not single-linked"
    assert json.loads(slot.read_text(encoding="utf-8"))["case_id"] == "case-x", \
        "the requeued record is not the claim's request"
    assert not [p.name for p in queue.iterdir() if p.name.startswith(".")], \
        "a staging leftover sits beside the requeued record"


@pytest.mark.parametrize("at", ["channel-file", "holding-folder"])
def test_a_linked_append_target_raises_and_its_target_is_untouched(tmp_path: Path, at):
    paths = S.built_paths(tmp_path)
    target = S.outside(tmp_path, "pitfalls.jsonl", "")
    if at == "channel-file":
        S.plant(location_path(paths.state_root) / "_pending_pitfalls" / "pitfalls.jsonl", "symlink", target=target)
    else:
        S.plant(location_path(paths.state_root) / "_pending_pitfalls", "symlink", target=target.parent)

    state = S.LearningState.open(paths)
    refused = S.caught(lambda: state.append(S.coined("PITFALLS"), [_pitfall("p-1")]))

    assert S.is_refusal(refused), f"append through a planted link answered {refused!r}"
    assert "_pending_pitfalls" in str(refused), "the refusal does not name the channel entry"
    assert target.read_text(encoding="utf-8") == "", "a row was written into the link's target"


def test_a_plain_append_returns_todays_counts_and_encoding(tmp_path: Path):
    paths = S.built_paths(tmp_path)
    state = S.LearningState.open(paths)

    pit = state.append(S.coined("PITFALLS"), [_pitfall("p-1"), _pitfall("p-1")])
    pit_file = location_path(paths.state_root) / "_pending_pitfalls" / "pitfalls.jsonl"
    assert tuple(pit) == (2, 0), f"the read-free pitfalls append answered {pit!r}"
    assert pit_file.read_text(encoding="utf-8") == (json.dumps(_pitfall("p-1")) + "\n") * 2, \
        "the pitfalls append deduplicated or re-encoded its rows"

    queue = location_path(paths.state_root) / "_pending" / "findings.jsonl"
    a, b = _finding("a/0"), _finding("a/1")
    queue.parent.mkdir(parents=True)
    queue.write_text(json.dumps(a) + "\n" + '{"torn": ', encoding="utf-8")
    answer = state.append(S.coined("FINDINGS"), [a, b], dedup_key="finding_id")
    assert tuple(answer) == (1, 1), f"(appended, malformed) was {answer!r}"
    assert queue.read_text(encoding="utf-8") == (
        json.dumps(a) + "\n" + '{"torn": ' + "\n" + json.dumps(b) + "\n"), \
        "the torn tail was concatenated onto, or the duplicate was written"


def test_a_linked_inflight_folder_stops_the_claim_before_any_move(tmp_path: Path):
    paths = S.built_paths(tmp_path)
    queued = S.seed_request(paths, "case-x", S.curation_run_dir("run-a"))
    body = queued.read_bytes()
    elsewhere = tmp_path / "outside" / "inflight"
    elsewhere.mkdir(parents=True)
    S.plant(location_path(paths.state_root) / "author-queue" / "inflight", "symlink", target=elsewhere)

    state = S.LearningState.open(paths)
    refused = S.caught(lambda: _claim_all(state))

    assert S.is_refusal(refused), f"the claim through a linked inflight/ answered {refused!r}"
    assert S.entry_kind(queued) == "file", "the queued request left its top-level name"
    assert queued.read_bytes() == body, "the queued request changed"
    assert list(elsewhere.iterdir()) == [], "a request was moved through the link"


def test_a_plain_claim_moves_the_request_into_inflight(tmp_path: Path):
    paths = S.built_paths(tmp_path)
    run_a, run_b = S.curation_run_dir("run-a"), S.curation_run_dir("run-b")
    S.seed_request(paths, "case-a", run_a)
    S.seed_request(paths, "case-b", run_b, inflight=True)  # an orphan of a dead pass
    queue = location_path(paths.state_root) / "author-queue"

    state = S.LearningState.open(paths)
    claims = _claim_all(state)

    assert [c.key for c in claims] == ["case-b", "case-a"], \
        f"orphans are not claimed first: {[c.key for c in claims]}"
    assert [c.spec for c in claims] == [S.request_body("case-b", run_b),
                                        S.request_body("case-a", run_a)], \
        "a Claimed does not carry its request's spec"
    assert S.entry_kind(queue / "case-a.json") == "absent", "the top-level slot was not freed"
    assert S.entry_kind(queue / "inflight" / "case-a.json") == "file", "the claim is not in inflight/"


def test_a_linked_lock_name_raises_for_a_try_once_role_and_creates_no_target(tmp_path: Path):
    paths = S.built_paths(tmp_path)
    absent_target = tmp_path / "outside" / "never-made.lock"
    S.plant(location_path(paths.state_root) / ".author-drain.lock", "symlink", target=absent_target)
    state = S.LearningState.open(paths)
    answers: list = []

    def take() -> None:
        with state.lock(S.coined("AUTHOR_DRAIN_LOCK"), wait=S.coined("TRY_ONCE")) as taken:
            answers.append(taken)

    finished, _, refused = S.within(10, take)
    assert finished, "the lock open blocked on a planted link"
    assert S.is_refusal(refused), f"a planted lock name answered {answers!r} / {refused!r}"
    assert answers == [], "a refused lock open answered taken / not taken"
    assert S.entry_kind(absent_target) == "absent", "the lock open created the link's target"


def test_a_plain_lock_role_is_taken_refused_while_held_and_released(tmp_path: Path):
    # rejected: N8 — no lease or claim-epoch model; locks stay flock
    paths = S.built_paths(tmp_path)
    state = S.LearningState.open(paths)
    drain_lock = location_path(paths.state_root) / "_pending" / ".lock"
    repo_lock = location_path(paths.state_root) / "_author.lock"
    try_once = S.coined("TRY_ONCE")
    seen: dict[str, object] = {}

    def drain_half() -> None:
        with state.lock(S.coined("CURATOR_DRAIN_LOCK"), wait=try_once) as taken:
            seen["taken"] = taken
            seen["made"] = S.entry_kind(drain_lock)
            with state.lock(S.coined("CURATOR_DRAIN_LOCK"), wait=try_once) as again:
                seen["again"] = again
        seen["free_after"] = S.entry_kind(drain_lock) == "file" and S.flock_free(drain_lock)

    def repo_half() -> None:
        with state.lock(S.coined("REPO_LOCK"), wait=5):
            seen["deadline"] = S.caught(lambda: state.lock(S.coined("REPO_LOCK"), wait=0.3)
                                        .__enter__())
        seen["repo_free_after"] = S.entry_kind(repo_lock) == "file" and S.flock_free(repo_lock)

    finished, _, err = S.within(20, drain_half)
    assert finished, "the try-once half did not complete"
    assert err is None, f"the try-once half raised {err!r}"
    assert seen.get("taken") is True, f"the free lock was not taken: {seen!r}"
    assert seen.get("made") == "file", f"the lock file and its folder were not made: {seen!r}"
    assert seen.get("again") is False, "a second try-once take of a held lock was answered taken"
    assert seen.get("free_after") is True, "the lock was not released on exit"

    finished, _, err = S.within(20, repo_half)
    assert finished, "the deadline half did not complete"
    assert err is None, f"the deadline half raised {err!r}"
    assert isinstance(seen.get("deadline"), TimeoutError), \
        f"a deadline take of a held lock answered {seen.get('deadline')!r}"
    assert seen.get("repo_free_after") is True, "the repo lock was not released on exit"

    lead_lock = location_path(paths.state_root) / "_pending_leads" / ".lock"
    holding = threading.Event()

    def hold_then_release() -> None:  # another holder, as a second process's open would be
        with S.held_flock(lead_lock):
            holding.set()
            time.sleep(0.6)
            seen["released_at"] = time.monotonic()

    def block_half() -> None:
        holder = threading.Thread(target=hold_then_release, daemon=True)
        holder.start()
        assert holding.wait(5), "the other holder never took the lead queue lock"
        with state.lock(S.coined("LEAD_QUEUE_LOCK"), wait=S.coined("BLOCK")):
            seen["block_taken_at"] = time.monotonic()
            seen["block_holds"] = not S.flock_free(lead_lock)
        holder.join(5)
        seen["lead_free_after"] = S.flock_free(lead_lock)

    finished, _, err = S.within(20, block_half)
    assert finished, "a block take did not take the lead queue lock once its holder released it"
    assert err is None, f"a block take of a held lock raised {err!r}"
    taken_at, released_at = seen.get("block_taken_at"), seen.get("released_at")
    assert isinstance(released_at, float), f"the other holder never released: {seen!r}"
    assert isinstance(taken_at, float), f"the block take never recorded taking the lock: {seen!r}"
    assert taken_at >= released_at, (
        f"a block take answered {released_at - taken_at:.2f}s before the holder released: it did "
        "not wait")
    assert taken_at - released_at < 5, \
        f"a block take waited {taken_at - released_at:.1f}s after the holder released"
    assert seen.get("block_holds") is True, "inside the block take the lead queue lock was free"
    assert seen.get("lead_free_after") is True, "the lead queue lock was not released on exit"


def test_1135_a_zero_repo_lock_wait_is_try_once(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "0")
    paths = S.built_paths(tmp_path)
    state = S.LearningState.open(paths)
    wait = config.repo_lock_wait_seconds()
    assert wait == 0, f"the knob read {wait!r}, not 0"

    def take() -> str:
        with state.lock(S.coined("REPO_LOCK"), wait=wait):
            return "taken"

    with S.held_flock(location_path(paths.state_root) / "_author.lock"):
        t0 = time.monotonic()
        finished, answer, err = S.within(10, take)
        spent = time.monotonic() - t0
    assert finished, "a zero wait blocked on a held repo lock"
    assert spent < 5, f"a zero wait waited {spent:.1f}s on a held repo lock"
    assert isinstance(err, TimeoutError), f"a zero wait on a held lock answered {answer!r} / {err!r}"

    finished, answer, err = S.within(10, take)
    assert finished, "a zero-wait take of a free repo lock blocked"
    assert err is None, f"a zero-wait take of a free repo lock raised {err!r}"
    assert answer == "taken", "a free repo lock was not taken"


@pytest.mark.parametrize("shape", S.SHAPES)
def test_a_non_plain_entry_at_a_record_name_halts_when_the_claim_opens_it(tmp_path: Path, shape):
    paths = S.built_paths(tmp_path)
    queue = location_path(paths.state_root) / "author-queue"
    queue.mkdir()
    body = (json.dumps(S.request_body("case-x", S.curation_run_dir("run-x"))) + "\n").encode()
    with contextlib.ExitStack() as stack:
        if shape == "symlink":
            target = tmp_path / "outside" / "case-x.json"
            unread = stack.enter_context(S.fifo_holding(target, body))
        else:
            target = S.outside(tmp_path, "case-x.json", body.decode())
            unread = None
        planted = S.plant(queue / "case-x.json", shape,
                          target=target if shape in ("symlink", "hardlink") else None)
        before = S.tree_snapshot(tmp_path / "outside")
        kind = S.entry_kind(planted)
        state = S.LearningState.open(paths)

        finished, has_work, err = S.within(10, state.has_requests)
        assert finished, "has_requests() blocked on the planted entry"
        assert err is None, f"has_requests() raised {err!r}"
        assert has_work is True, f"has_requests() dropped the record name (answered {has_work!r})"
        finished, _, refused = S.within(10, lambda: _claim_all(state))
        assert finished, "the claim blocked on the planted entry"
        assert unread is None or unread(), "the link's target was read: its body left the pipe"
    assert S.is_refusal(refused), f"the claim answered {refused!r} for a planted {shape}"
    assert "case-x.json" in str(refused), f"the refusal does not name the record: {refused!r}"
    assert S.entry_kind(planted) == kind, "the planted entry was not left in place"
    assert S.tree_snapshot(tmp_path / "outside") == before, "the link's target was touched"
    inflight = queue / "inflight"
    assert S.entry_kind(inflight) == "absent" or not list(inflight.iterdir()), \
        "the planted entry reached inflight/"


def test_a_listing_keeps_record_names_and_never_opens_a_foreign_name(tmp_path: Path, caplog):
    # rejected: halting on a non-plain entry at a foreign name (3.1 D: O2 holds because nothing
    # follows it)
    paths = S.built_paths(tmp_path)
    queue = location_path(paths.state_root) / "author-queue"
    queue.mkdir()
    (queue / "README").write_text("operator notes\n", encoding="utf-8")
    (queue / ".case-z.json.requeue.4242").write_text("{}\n", encoding="utf-8")
    S.plant(queue / "notes.txt", "symlink", target=S.outside(tmp_path, "notes.txt", "secret\n"))
    S.plant(queue / "x.fifo", "fifo")
    foreign = ("README", ".case-z.json.requeue.4242", "notes.txt", "x.fifo")
    before = S.tree_snapshot(queue)
    outside_before = S.tree_snapshot(tmp_path / "outside")
    caplog.set_level(logging.DEBUG)

    state = S.LearningState.open(paths)
    finished, only_foreign, err = S.within(10, state.has_requests)
    assert finished, "has_requests() blocked on a foreign name"
    assert err is None, f"has_requests() over foreign names raised {err!r}"
    assert only_foreign is False, f"foreign names counted as work: {only_foreign!r}"

    S.seed_request(paths, "case-a", S.curation_run_dir("run-a"))
    S.seed_request(paths, "case-b", S.curation_run_dir("run-b"), inflight=True)
    finished, has_work, err = S.within(10, state.has_requests)
    assert finished, "has_requests() blocked beside foreign names"
    assert err is None, f"has_requests() raised {err!r}"
    assert has_work is True, f"has_requests() missed a plain record: {has_work!r}"
    finished, claims, err = S.within(10, lambda: _claim_all(state))
    assert finished, "the pass blocked on a foreign FIFO"
    assert err is None, f"the pass raised {err!r}"
    assert sorted(c.key for c in claims or []) == ["case-a", "case-b"], \
        f"the pass did not claim exactly the two records: {claims!r}"

    assert {k: v for k, v in S.tree_snapshot(queue).items() if k in before} == before, \
        "a foreign entry was moved, changed or removed"
    assert S.tree_snapshot(tmp_path / "outside") == outside_before, "a foreign link was followed"
    named = [r.getMessage() for r in caplog.records
             if any(name in r.getMessage() for name in foreign)]
    assert named == [], f"a foreign name was reported: {named}"


#: The core's refusal shapes (X1, G8, G9), each planted at the read verb's queue (rows) and the
#: write verb's claimed record (stamp): (verb, where, shape).
_CONVERSION = [
    ("rows", "leaf", "symlink"),         # NotPlainEntry, ELOOP (link at the leaf)
    ("rows", "leaf", "hardlink"),        # NotPlainEntry, EMLINK (hard link)
    ("rows", "leaf", "fifo"),            # a refused Bound read's reason (`other` at the name)
    ("rows", "leaf", "folder"),          # `other` entry at a record name
    ("rows", "folder", "symlink"),       # plain OSError(ELOOP): a linked holding folder
    ("rows", "folder", "file"),          # NotADirectoryError(ENOTDIR) on the walk (R16)
    ("stamp", "leaf", "symlink"),
    ("stamp", "leaf", "hardlink"),
    ("stamp", "folder", "symlink"),
    ("stamp", "folder", "file"),
]


@pytest.mark.parametrize(("verb", "where", "shape"), _CONVERSION)
def test_every_core_refusal_shape_surfaces_as_state_refused(tmp_path: Path, verb, where, shape):
    paths = S.built_paths(tmp_path)
    target = S.outside(tmp_path, "entry.json", '{"outside": true}\n')
    state = S.LearningState.open(paths)
    if verb == "rows":
        folder = location_path(paths.state_root) / "_pending"
        leaf = folder / "findings.jsonl"
    else:
        S.seed_request(paths, "case-x", S.curation_run_dir("run-a"))
        claims = _claim_all(state)
        assert len(claims) == 1, f"the plain request was not claimed: {claims!r}"
        folder = location_path(paths.state_root) / "author-queue" / "inflight"
        leaf = folder / "case-x.json"
        leaf.unlink()
    if where == "leaf":
        S.plant(leaf, shape, target=target if shape in ("symlink", "hardlink") else None)
    else:
        if folder.exists():
            folder.rmdir()
        if shape == "symlink":
            S.plant(folder, "symlink", target=target.parent)
        else:
            folder.write_text("a file where a folder belongs\n", encoding="utf-8")
    before = S.tree_snapshot(tmp_path / "outside")

    answer: list = []
    if verb == "rows":
        escaped = S.caught(lambda: answer.append(state.rows(S.coined("FINDINGS"))))
    else:
        escaped = S.caught(lambda: answer.append(state.stamp(claims[0], {"attempts": 1})))

    assert not isinstance(escaped, OSError), f"the core's refusal escaped as {escaped!r}"
    assert S.is_refusal(escaped), f"{verb} over a {where} {shape} answered {answer!r} / {escaped!r}"
    assert answer == [], "a refused read was folded to empty"
    assert S.tree_snapshot(tmp_path / "outside") == before, "the link's target was touched"


def test_ordinary_io_errors_are_not_converted_to_refusals(tmp_path: Path):
    paths = S.built_paths(tmp_path)
    S.seed_request(paths, "case-x", S.curation_run_dir("run-a"))
    state = S.LearningState.open(paths)
    claims = _claim_all(state)
    assert len(claims) == 1, f"the plain request was not claimed: {claims!r}"
    fresher = S.seed_request(paths, "case-x", S.curation_run_dir("run-b"))  # a re-ask mid-serve
    body = fresher.read_bytes()
    answer = state.requeue(claims[0])
    assert answer is False, f"a requeue into an occupied slot answered {answer!r}"
    assert fresher.read_bytes() == body, "the requeue overwrote the fresher request"
    state.done(claims[0])
    fresher.unlink()

    S.seed_request(paths, "case-p", S.curation_run_dir("run-p"))
    S.seed_request(paths, "case-q", S.curation_run_dir("run-q"))
    served: list = []
    passed = S.caught(lambda: served.extend(_vanishing_pass(state, paths)))
    assert passed is None, f"the pass raised {passed!r}"
    assert [c.key for c in served] == ["case-p"], \
        f"a request that vanished mid-pass was not skipped: {[c.key for c in served]}"

    move_at = S.core_fn("move_at")
    with _io.hold(location_path(paths.state_root)) as held:
        missing = S.caught(lambda: move_at(held, "author-queue/nope.json",
                                           "author-queue/inflight/nope.json"))
    assert isinstance(missing, FileNotFoundError), f"move_at on a missing source answered {missing!r}"
    assert not S.is_refusal(missing), f"move_at on a missing source answered a refusal {missing!r}"


def _vanishing_pass(state, paths: LoopPaths):
    """A claim pass during which a second queued request is deleted (by another actor) after the
    pass has started and before it reaches that request."""
    claims = iter(state.claim("case_id"))
    for claim in claims:
        (location_path(paths.state_root) / "author-queue" / "case-q.json").unlink(missing_ok=True)
        yield claim


def test_a_request_whose_identity_is_already_claimed_this_pass_waits_a_pass(tmp_path: Path):
    # rejected: revision 2's newest-wins removal of the orphan (R5, superseded by R14); N2 —
    # request record bodies are unchanged
    paths = S.built_paths(tmp_path)
    run_a, run_b = S.curation_run_dir("run-a"), S.curation_run_dir("run-b")
    orphan = S.seed_request(paths, "case-x", run_a, inflight=True)
    fresher = S.seed_request(paths, "case-x", run_b)
    orphan_body, fresher_body = orphan.read_bytes(), fresher.read_bytes()

    state = S.LearningState.open(paths)
    first = _claim_all(state)
    assert [c.spec.get("run_id") for c in first] == [run_a.name], \
        f"the pass served {[c.spec for c in first]}, not exactly run A's orphan"
    assert S.entry_kind(fresher) == "file", "run B's request left its top-level name"
    assert fresher.read_bytes() == fresher_body, "run B's request changed"
    assert orphan.read_bytes() == orphan_body, "the fresher request overwrote the orphan's claim"

    state.done(first[0])
    second = _claim_all(state)
    assert [c.spec.get("run_id") for c in second] == [run_b.name], \
        "the next pass did not claim run B's request"


def test_a_refused_ledger_stops_rotate_before_the_queue_is_replaced(tmp_path: Path):
    # rejected: closing the crash window between the queue replace and the ledger append
    # (unchanged, O3; X11)
    paths = S.built_paths(tmp_path)
    queue = location_path(paths.state_root) / "_pending" / "findings.jsonl"
    keep, done = _finding("a/0"), _finding("a/1")
    S.write_jsonl(queue, [keep, done])
    queue_bytes = queue.read_bytes()
    ledger_target = S.outside(tmp_path, "consumed.jsonl", "")
    S.plant(location_path(paths.state_root) / "_pending" / "consumed.jsonl", "symlink", target=ledger_target)

    state = S.LearningState.open(paths)
    refused = S.caught(lambda: state.rotate(S.coined("FINDINGS"), [keep], [done], "abc123",
                                            timeout=5))

    assert S.is_refusal(refused), f"rotate over a planted ledger answered {refused!r}"
    assert queue.read_bytes() == queue_bytes, "the queue was replaced before the refusal"
    assert ledger_target.read_text(encoding="utf-8") == "", "a row went through the ledger link"


def test_move_at_renames_under_the_held_root(tmp_path: Path):
    # rejected: a hard-linked, FIFO, link or folder destination enumeration (R17: no host-actor
    # edge enumeration; #20 is the move guard)
    move_at = S.core_fn("move_at")
    paths = S.built_paths(tmp_path)
    root = location_path(paths.state_root)
    (root / "author-queue").mkdir()
    (root / "author-queue" / "case-a.json").write_text('{"a": 1}\n', encoding="utf-8")
    (root / "author-queue" / "case-b.json").write_text('{"b": 1}\n', encoding="utf-8")
    (root / "old").mkdir()
    (root / "old" / "case-b.json").write_text('{"stale": 1}\n', encoding="utf-8")

    with _io.hold(root) as held:
        move_at(held, "author-queue/case-a.json", "author-queue/inflight/case-a.json")
        move_at(held, "author-queue/case-b.json", "old/case-b.json")
        missing = S.caught(lambda: move_at(held, "author-queue/gone.json", "old/gone.json"))

    assert S.entry_kind(root / "author-queue" / "case-a.json") == "absent", "src is still there"
    assert (root / "author-queue" / "inflight" / "case-a.json").read_text(encoding="utf-8") \
        == '{"a": 1}\n', "dst's holding folder was not made, or the move lost the bytes"
    assert (root / "old" / "case-b.json").read_text(encoding="utf-8") == '{"b": 1}\n', \
        "a plain destination was not replaced"
    assert isinstance(missing, FileNotFoundError), f"a missing src answered {missing!r}"
    assert not S.is_refusal(missing), f"a missing src answered a refusal {missing!r}"
    (root / "author-queue" / "inflight" / "case-a.json").write_text(
        json.dumps(S.request_body("case-a", S.curation_run_dir("run-a"))) + "\n",
        encoding="utf-8")
    state = S.LearningState.open(paths)
    assert [c.key for c in _claim_all(state)] == ["case-a"], \
        "the handle's claim does not see the record at the inflight/ name move_at moved it to"


def test_open_lock_at_opens_a_plain_lock_without_truncating(tmp_path: Path):
    # rejected: N13 — a lock mode looser than 0644 is not kept; the hard-link/FIFO lock cases
    # (R17)
    open_lock_at = S.core_fn("open_lock_at")
    paths = S.built_paths(tmp_path)
    root = location_path(paths.state_root)
    (root / "_author.lock").write_text("held-by: someone\n", encoding="utf-8")

    opened: list = []  # closed in `finally`, whichever of the three opens (or an assert) fails
    try:
        with _umask.umask(0o022), _io.hold(root) as held:
            fresh = open_lock_at(held, "_pending_leads/.lock")
            opened.append(fresh)
            existing = open_lock_at(held, "_author.lock")
            opened.append(existing)
            second = open_lock_at(held, "_pending_leads/.lock")
            opened.append(second)
        lock = root / "_pending_leads" / ".lock"
        assert S.entry_kind(lock) == "file", "the absent lock file was not made with its holding folder"
        assert (os.lstat(lock).st_mode & 0o777) == 0o644, "the absent lock file was not made 0644 under umask 022"
        assert (root / "_author.lock").read_text(encoding="utf-8") == "held-by: someone\n", \
            "opening an existing lock file truncated it"
        fcntl.flock(fresh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        excluded = S.caught(lambda: fcntl.flock(second.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB))
        assert isinstance(excluded, BlockingIOError), f"two opens of one lock name did not exclude: {excluded!r}"
        assert excluded.errno in (errno.EWOULDBLOCK, errno.EAGAIN), \
            f"the second flock failed for another reason: {excluded!r}"
        fcntl.flock(existing.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = S.LearningState.open(paths)
        finished, _, held_out = S.within(
            10, lambda: state.lock(S.coined("REPO_LOCK"), wait=0).__enter__())
        assert finished, "the handle's repo lock blocked on a zero wait"
        assert isinstance(held_out, TimeoutError), \
            "the handle's repo lock role is not the lock file open_lock_at opens at _author.lock"
    finally:
        for fh in opened:
            if hasattr(fh, "close"):
                fh.close()
