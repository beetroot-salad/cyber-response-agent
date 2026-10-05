"""#1135 — the handle itself: its constructor and root (R11, R15), the refusal contract (#0,
3.1 B), one guard plus positive control per operation kind (R17: read, write, append, move, lock
open, list), the conversion of every core refusal shape, ordinary errors on today's routes, R14's
one fix (C20), D8's rotate, D2's two core functions, and the root's distinguished spellings.

Every plant is a real entry made on disk in the test (a symlink, a hard link, a FIFO, a folder or
a file where a folder belongs, a missing or dangling root). Every oracle reads the tree by today's
record names (R14) through `lstat`/`readlink`, never through the verb under test. Shared
machinery and the names this suite coins are in `_spec1135.py`.
"""
from __future__ import annotations

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
from defender.tests import _umask
from defender.tests.e2e import _box665 as B
from defender.tests.learning_state_1135 import _spec1135 as S

ENV = "DEFENDER_LEARNING_STATE_DIR"


# ---------------------------------------------------------------------------------------------
# helpers (this file only)
# ---------------------------------------------------------------------------------------------


def _finding(fid: str, **extra) -> dict:
    return {"finding_id": fid, "run_id": fid.split("/")[0], "direction": "adversarial", **extra}


def _pitfall(pid: str) -> dict:
    return {"pitfall_id": pid, "system": "elastic", "failure": "a failing query"}


def _drain_stage(tmp_path: Path, paths: LoopPaths) -> tuple[int | None, BaseException | None]:
    """One curator-drain stage through `_run_stage`, every non-state seam faked (no git, no box,
    no model): `(exit code, what escaped _run_stage)`."""
    rec = B.BoxLifecycleRecorder()
    out: dict[str, int] = {}

    def stage() -> None:
        out["rc"] = _run_stage(lambda: drains.author_drain(
            paths, branch=B.RecordingBranch(tmp_path / "worktrees"),
            start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub))

    escaped = S.caught(stage)
    return out.get("rc"), escaped


def _critical_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.CRITICAL]


def _claim_all(state) -> list:
    """One whole claim pass, every claim held (as a pass holds them)."""
    return list(state.claim("case_id"))


# ---------------------------------------------------------------------------------------------
# #0 — the refusal contract
# ---------------------------------------------------------------------------------------------


def test_state_refused_is_a_systemic_fault_no_oserror_arm_holds(tmp_path: Path, caplog):
    """StateRefused(record, reason) carries the refused record and its reason. It is not an
    OSError subclass, it is a member of faults.SYSTEMIC_FAULTS, and it is not in
    author/drain.RETIRE_SET. So run_or_dead_letter re-raises it and never dead-letters or
    quarantines it (the on_dead_letter callback is never called); _run_curator_module lets it
    propagate instead of logging "crashed (continuing)"; _run_stage returns 2 with a CRITICAL line
    whose text names the refused record. The narrowing to StateRefused happens only at
    _drain_one_curator, RF4's recorder catches and _tick's arm (#30-#32); everywhere else it is
    just another systemic fault.

    The refusal is a real one: the handle's read of a findings queue that is a planted symlink."""
    # rejected: a StateRefused subclassing OSError (every `except OSError` arm would catch it;
    # X2 shows today's arms swallow the core's refusal exactly that way)
    paths = S.built_paths(tmp_path)
    S.plant(paths.state_root / "_pending" / "findings.jsonl", "symlink", target=S.outside(tmp_path))
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


# ---------------------------------------------------------------------------------------------
# The root (R11, R15, 3.1 C) and its distinguished spellings
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("spelled", ["env", "loop_paths"])
def test_open_holds_the_resolved_existing_root(tmp_path: Path, monkeypatch, spelled):
    """LearningState.open(paths) is the handle's only constructor. It resolves paths.state_root
    once to its real path and holds it. A root spelled through a symlink is followed at open, so
    the handle's writes land in the link's target (R11, C27); a link below the root is refused
    (the guards). No other public constructor or path-taking factory exists.

    Two spellings of one root through a link: DEFENDER_LEARNING_STATE_DIR read by
    config._env_state_dir (`env`), and a LoopPaths whose state_dir is the link itself
    (`loop_paths`). After open the link is re-pointed; the held root does not move."""
    # rejected: N1 — the root does not move or become per-tenant here (D11, #1186)
    real = tmp_path / "real"
    elsewhere = tmp_path / "elsewhere"
    real.mkdir()
    elsewhere.mkdir()
    link = tmp_path / "spelled"
    link.symlink_to(real)
    if spelled == "env":
        monkeypatch.setenv(ENV, str(link))
        paths = config.loop_paths()
    else:
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
def test_a_missing_root_is_an_error_and_is_never_created(tmp_path: Path, monkeypatch, caplog,
                                                         shape):
    """With state_root absent: LearningState.open(paths) raises FatalConfigError, whose message
    names both the resolved root and DEFENDER_LEARNING_STATE_DIR, and creates nothing, neither
    the root nor any parent; a drain stage run through _run_stage returns 2 with a CRITICAL line
    naming them, where today it would report "nothing to do" with exit 0; the run-end enqueue
    (E1, run_common.enqueue_curation) logs the error and returns False with nothing created, and
    the investigation continues. A second row: a root that exists but is not a folder (a regular
    file at the spelled path) takes the same route — FatalConfigError naming
    DEFENDER_LEARNING_STATE_DIR and the resolved root, exit 2 through _run_stage, nothing
    created — not the core's bare NotADirectoryError. E3's route for the same error is in #35.
    Lock files and holding folders below an existing root are still created as today (#17, #23).

    The root is spelled through the env var, so config._env_state_dir resolves it (as every
    entry point's route does)."""
    # rejected: a lazy bootstrap that creates a missing root on first write (R15 supersedes
    # R4/RF5's writer/opener split); the core's bare FileNotFoundError (3.1 C chose
    # FatalConfigError); for a non-folder root, the core's bare NotADirectoryError, which does
    # not name the variable (JF18 reading B, declined by the owner)
    from defender import run_common
    from defender.runtime import scrub as scrub_mod
    from defender.tests._spec791 import make_run_dir

    parent = tmp_path / "nested"
    root = parent / "learning-state"
    if shape == "not-a-folder":
        parent.mkdir()
        root.write_text("a file, not a folder\n", encoding="utf-8")
    before = S.tree_snapshot(tmp_path)
    monkeypatch.setenv(ENV, str(root))
    paths = config.loop_paths()

    opened = S.caught(lambda: S.LearningState.open(paths))
    assert isinstance(opened, FatalConfigError), f"open answered {opened!r}"
    assert str(root.resolve()) in str(opened), f"the error does not name the root: {opened}"
    assert ENV in str(opened), f"the error does not name {ENV}: {opened}"

    caplog.set_level(logging.INFO)
    rc, escaped = _drain_stage(tmp_path, paths)
    assert escaped is None, f"the drain stage raised {escaped!r}"
    assert rc == 2, f"the drain stage answered rc={rc}"
    assert any(str(root.resolve()) in line and ENV in line for line in _critical_lines(caplog)), \
        "the stage's CRITICAL line does not name the root and the env var"

    caplog.clear()
    runs = tmp_path / "runs"
    run_dir = make_run_dir(runs, name="case-r15", disposition="benign")
    scrub_mod.scrub(run_dir)
    answered: list[bool] = []
    enqueued = S.caught(lambda: answered.append(
        run_common.enqueue_curation(run_dir, run_dir / "alert.json")))
    assert enqueued is None, f"the run-end enqueue raised {enqueued!r} into the investigation"
    assert answered == [False], f"the run-end enqueue answered {answered!r}"
    assert any(ENV in r.getMessage() for r in caplog.records), "E1 did not log the root error"

    created = {k for k in S.tree_snapshot(tmp_path) if k not in before and k.split(os.sep)[0]
               not in ("runs", "worktrees")}
    assert not created, f"a missing root was created, or written below: {sorted(created)}"
    assert {k: v for k, v in S.tree_snapshot(tmp_path).items() if k in before} == before, \
        "an entry that existed before was changed"
    assert S.entry_kind(root) == ("absent" if shape == "missing" else "file"), \
        "the spelled root was created or replaced"


def test_1135_root_is_a_dangling_link(tmp_path: Path, monkeypatch, caplog):
    """A root that is a link to nothing is a missing root: the entry point resolves the spelling
    once and follows a link at or above the root once (R11), so the resolved root does not exist
    and the error is FatalConfigError naming the resolved root and DEFENDER_LEARNING_STATE_DIR
    (3.1 C). The drain stage (_run_stage) exits 2; the page build (build_view, through
    `serialize_queues.stamped_view(paths)`, what `frontend/build.main` calls) does not produce an
    empty page; nothing is created at the link's target (R15). It is not a link refusal, which
    R11 limits to links below the root."""
    from defender.learning.frontend import serialize_queues

    target = tmp_path / "gone" / "learning-state"
    link = tmp_path / "state-link"
    link.symlink_to(target)
    monkeypatch.setenv(ENV, str(link))
    paths = config.loop_paths()

    opened = S.caught(lambda: S.LearningState.open(paths))
    assert isinstance(opened, FatalConfigError), f"a dangling root answered {opened!r}"
    assert not S.is_refusal(opened), f"a dangling root answered a refusal {opened!r}"
    assert str(target) in str(opened), f"the error does not name the resolved root: {opened}"
    assert ENV in str(opened), f"the error does not name {ENV}: {opened}"

    caplog.set_level(logging.INFO)
    rc, escaped = _drain_stage(tmp_path, paths)
    assert escaped is None, f"the drain stage raised {escaped!r}"
    assert rc == 2, f"the drain stage answered rc={rc}"

    page: dict[str, object] = {}
    built = S.caught(lambda: page.update(serialize_queues.stamped_view(paths)))
    assert isinstance(built, FatalConfigError), f"the page build over a dangling root raised {built!r}"
    assert not page, f"the page built over a dangling root ({sorted(page)[:4]}…)"
    assert S.entry_kind(tmp_path / "gone") == "absent", "something was created at the target"


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_1135_unset_and_empty_state_dir_open_the_package_folder(monkeypatch, value):
    """With DEFENDER_LEARNING_STATE_DIR unset, and again set to the empty string,
    config.loop_paths() names the package folder defender/learning/ as state_root (GT1: both read
    as None), and LearningState.open(paths) holds it and creates nothing. The empty string is not
    read as the launching directory, which Path("").resolve() would be. One parametrized test,
    two rows; the variable is set through the env fixture the suite already uses (no
    monkeypatch.setattr)."""
    if value is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, value)
    package = S.DEFENDER / "learning"
    listing = sorted(os.listdir(package))

    paths = config.loop_paths()
    assert paths.state_root == package, f"loop_paths() named {paths.state_root}, not the package folder"
    assert paths.state_root != Path("").resolve(), "the empty string was read as the launching directory"
    state = S.LearningState.open(paths)
    described = state.describe(S.coined("FINDINGS"))

    assert isinstance(described, str), f"describe() answered {described!r}"
    assert described == str(package / "_pending" / "findings.jsonl"), \
        f"the handle does not hold the package folder: {described!r}"
    assert sorted(os.listdir(package)) == listing, "opening the default root created something"


# ---------------------------------------------------------------------------------------------
# read (R17 pair 1)
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("at", ["queue-file", "holding-folder"])
def test_a_linked_queue_read_raises_and_never_reads_as_empty(tmp_path: Path, at):
    """With a symlink planted at a channel's queue file, or at its holding folder _pending/,
    pointing outside the root: rows(channel) raises StateRefused naming the queue, and never
    returns [] or (rows, malformed); the link's target is untouched and unread, and the link is
    left in place.

    The target is a FIFO already holding one row (`_spec1135.fifo_holding`), so "unread" is
    observable: a read through the link consumes the row, and a read to end of file blocks."""
    # rejected: N14 — a refused read is never folded to empty outside E1-E3
    paths = S.built_paths(tmp_path)
    outside_dir = tmp_path / "outside"
    payload = (json.dumps(_finding("x/0")) + "\n").encode()
    with S.fifo_holding(outside_dir / "findings.jsonl", payload) as unread:
        if at == "queue-file":
            planted = S.plant(paths.state_root / "_pending" / "findings.jsonl", "symlink",
                              target=outside_dir / "findings.jsonl")
        else:
            planted = S.plant(paths.state_root / "_pending", "symlink", target=outside_dir)
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
    """On a plain queue file rows(channel) returns its rows. On an absent queue file (and an
    absent _pending/) it returns no rows and raises nothing. Absent and refused are
    distinguishable."""
    paths = S.built_paths(tmp_path)
    state = S.LearningState.open(paths)
    findings = S.coined("FINDINGS")

    absent: list = []
    raised = S.caught(lambda: absent.append(state.rows(findings)))
    assert raised is None, f"an absent queue raised {raised!r}"
    assert len(absent) == 1, f"an absent queue answered {absent!r}"
    assert S.rows_of(absent[0]) == [], f"an absent queue answered {absent!r}"
    assert S.entry_kind(paths.state_root / "_pending") == "absent", "a read created _pending/"

    rows = [_finding("a/0"), _finding("a/1")]
    S.write_jsonl(paths.state_root / "_pending" / "findings.jsonl", rows)
    assert S.rows_of(state.rows(findings)) == rows, "a plain queue did not read its rows"


# ---------------------------------------------------------------------------------------------
# write (R17 pair 2)
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("mode", "at"), [("replace", "record"), ("replace", "holding-folder"),
                                     ("create", "record")])
def test_a_linked_write_target_raises_in_either_mode_and_is_never_slot_taken(tmp_path: Path,
                                                                            mode, at):
    """With a symlink planted at a request record (or its holding folder): a replace write
    (stamp) raises StateRefused; a create-if-absent write (requeue into the top-level slot)
    raises StateRefused and never answers False ("slot taken"); the link's target is untouched
    and nothing is written through it."""
    paths = S.built_paths(tmp_path)
    S.seed_request(paths, "case-x", tmp_path / "runs" / "run-a")
    state = S.LearningState.open(paths)
    claims = _claim_all(state)
    assert len(claims) == 1, f"the plain request was not claimed: {claims!r}"
    claim = claims[0]
    queue = paths.state_root / "author-queue"
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
    """On plain entries: stamp(claimed, spec) replaces the claim's record in inflight/ with the
    new spec; requeue(claimed) into a free top-level slot creates a complete single-linked
    record and returns True."""
    paths = S.built_paths(tmp_path)
    S.seed_request(paths, "case-x", tmp_path / "runs" / "run-a")
    state = S.LearningState.open(paths)
    claims = _claim_all(state)
    assert len(claims) == 1, f"the plain request was not claimed: {claims!r}"
    claim = claims[0]
    queue = paths.state_root / "author-queue"
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


# ---------------------------------------------------------------------------------------------
# append (R17 pair 3)
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("at", ["channel-file", "holding-folder"])
def test_a_linked_append_target_raises_and_its_target_is_untouched(tmp_path: Path, at):
    """With a symlink planted at a channel file whose append reads nothing first (the pitfalls
    channel's read-free append, or the gap ledger), or at its holding folder, append raises
    StateRefused naming it. No row is written into the link's target."""
    paths = S.built_paths(tmp_path)
    target = S.outside(tmp_path, "pitfalls.jsonl", "")
    if at == "channel-file":
        S.plant(paths.state_root / "_pending_pitfalls" / "pitfalls.jsonl", "symlink", target=target)
    else:
        S.plant(paths.state_root / "_pending_pitfalls", "symlink", target=target.parent)

    state = S.LearningState.open(paths)
    refused = S.caught(lambda: state.append(S.coined("PITFALLS"), [_pitfall("p-1")]))

    assert S.is_refusal(refused), f"append through a planted link answered {refused!r}"
    assert "_pending_pitfalls" in str(refused), "the refusal does not name the channel entry"
    assert target.read_text(encoding="utf-8") == "", "a row was written into the link's target"


def test_a_plain_append_returns_todays_counts_and_encoding(tmp_path: Path):
    """On plain channel files (the same pitfalls channel #18 plants at, plus a judge findings
    channel), append(channel, rows, dedup_key=...) keeps today's channel semantics (D3): it
    returns (appended, malformed); each row is written as one json.dumps line; the judge
    channels' torn-tail and dedup read are unchanged; append_pitfalls' read-free append is
    unchanged (and makes the channel's missing holding folder below the root)."""
    paths = S.built_paths(tmp_path)
    state = S.LearningState.open(paths)

    pit = state.append(S.coined("PITFALLS"), [_pitfall("p-1"), _pitfall("p-1")])
    pit_file = paths.state_root / "_pending_pitfalls" / "pitfalls.jsonl"
    assert tuple(pit) == (2, 0), f"the read-free pitfalls append answered {pit!r}"
    assert pit_file.read_text(encoding="utf-8") == (json.dumps(_pitfall("p-1")) + "\n") * 2, \
        "the pitfalls append deduplicated or re-encoded its rows"

    queue = paths.state_root / "_pending" / "findings.jsonl"
    a, b = _finding("a/0"), _finding("a/1")
    queue.parent.mkdir(parents=True)
    queue.write_text(json.dumps(a) + "\n" + '{"torn": ', encoding="utf-8")
    answer = state.append(S.coined("FINDINGS"), [a, b], dedup_key="finding_id")
    assert tuple(answer) == (1, 1), f"(appended, malformed) was {answer!r}"
    assert queue.read_text(encoding="utf-8") == (
        json.dumps(a) + "\n" + '{"torn": ' + "\n" + json.dumps(b) + "\n"), \
        "the torn tail was concatenated onto, or the duplicate was written"


# ---------------------------------------------------------------------------------------------
# move (R17 pair 4)
# ---------------------------------------------------------------------------------------------


def test_a_linked_inflight_folder_stops_the_claim_before_any_move(tmp_path: Path):
    """With author-queue/inflight planted as a symlink to a folder outside the root and one plain
    queued request, the claim raises StateRefused: the queued request is still at its top-level
    name, and nothing appears in the link's target folder."""
    paths = S.built_paths(tmp_path)
    queued = S.seed_request(paths, "case-x", tmp_path / "runs" / "run-a")
    body = queued.read_bytes()
    elsewhere = tmp_path / "outside" / "inflight"
    elsewhere.mkdir(parents=True)
    S.plant(paths.state_root / "author-queue" / "inflight", "symlink", target=elsewhere)

    state = S.LearningState.open(paths)
    refused = S.caught(lambda: _claim_all(state))

    assert S.is_refusal(refused), f"the claim through a linked inflight/ answered {refused!r}"
    assert S.entry_kind(queued) == "file", "the queued request left its top-level name"
    assert queued.read_bytes() == body, "the queued request changed"
    assert list(elsewhere.iterdir()) == [], "a request was moved through the link"


def test_a_plain_claim_moves_the_request_into_inflight(tmp_path: Path):
    """On plain entries, the claim moves each queued request into inflight/ through move_at
    (orphans first), reads it and yields a Claimed that carries its spec and request key. The
    top-level slot is free afterwards, so a later enqueue lands there.

    The orphan's name (case-b) sorts AFTER the queued request's (case-a), so orphans-first and
    a plain alphabetical order give different answers (R14: today's claim_markers serves
    [*orphans, *queued])."""
    paths = S.built_paths(tmp_path)
    run_a, run_b = tmp_path / "runs" / "run-a", tmp_path / "runs" / "run-b"
    S.seed_request(paths, "case-a", run_a)
    S.seed_request(paths, "case-b", run_b, inflight=True)  # an orphan of a dead pass
    queue = paths.state_root / "author-queue"

    state = S.LearningState.open(paths)
    claims = _claim_all(state)

    assert [c.key for c in claims] == ["case-b", "case-a"], \
        f"orphans are not claimed first: {[c.key for c in claims]}"
    assert [c.spec for c in claims] == [S.request_body("case-b", run_b),
                                        S.request_body("case-a", run_a)], \
        "a Claimed does not carry its request's spec"
    assert S.entry_kind(queue / "case-a.json") == "absent", "the top-level slot was not freed"
    assert S.entry_kind(queue / "inflight" / "case-a.json") == "file", "the claim is not in inflight/"


# ---------------------------------------------------------------------------------------------
# lock open (R17 pair 5)
# ---------------------------------------------------------------------------------------------


def test_a_linked_lock_name_raises_for_a_try_once_role_and_creates_no_target(tmp_path: Path):
    """With a symlink planted at a try-once role's lock name (.author-drain.lock) pointing at an
    absent file outside the root, lock(role, wait=try-once) raises StateRefused: it never answers
    "not taken", so the drain cannot exit 0 silently; the link's target is not created."""
    paths = S.built_paths(tmp_path)
    absent_target = tmp_path / "outside" / "never-made.lock"
    S.plant(paths.state_root / ".author-drain.lock", "symlink", target=absent_target)
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
    """On an existing root, lock(role, wait=...) on a plain or absent lock name keeps today's
    semantics: it creates the lock file and its holding folder below the root; it takes the
    lock; while held, a second try-once take answers not taken and a deadline take raises
    TimeoutError; on exit it releases the lock. A block take (wait=BLOCK) of a lock another
    descriptor holds waits until that holder releases, then takes the lock, and releases it on
    exit.

    The try-once half on the curator drain lock (`_pending/.lock`, holding folder absent), the
    deadline half on the repo lock (`_author.lock`), the block half on the lead queue lock
    (`_pending_leads/.lock`, held by today's name from another descriptor for 0.6 s; the whole
    half is capped, so a block that never ends fails instead of hanging)."""
    # rejected: N8 — no lease or claim-epoch model; locks stay flock
    paths = S.built_paths(tmp_path)
    state = S.LearningState.open(paths)
    drain_lock = paths.state_root / "_pending" / ".lock"
    repo_lock = paths.state_root / "_author.lock"
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

    lead_lock = paths.state_root / "_pending_leads" / ".lock"
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
    """With LEARNING_REPO_LOCK_WAIT_SECONDS at 0 and the repo lock held by another descriptor,
    the handle's repo-lock verb raises TimeoutError at once rather than waiting out the
    1800-second default; with the lock free it is taken (the control). The zero is not swallowed
    by a `wait or DEFAULT` coercion in lock(role, wait). The test is bounded (a short
    wall-clock cap)."""
    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "0")
    paths = S.built_paths(tmp_path)
    state = S.LearningState.open(paths)
    wait = config.repo_lock_wait_seconds()
    assert wait == 0, f"the knob read {wait!r}, not 0"

    def take() -> str:
        with state.lock(S.coined("REPO_LOCK"), wait=wait):
            return "taken"

    with S.held_flock(paths.state_root / "_author.lock"):
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


# ---------------------------------------------------------------------------------------------
# list (R17 pair 6; firm, 3.1 D)
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape", S.SHAPES)
def test_a_non_plain_entry_at_a_record_name_halts_when_the_claim_opens_it(tmp_path: Path, shape):
    """A non-plain entry is planted at a record name in author-queue/, parametrized over the four
    shapes revision 3.1 D names: a symlink case-x.json to an entry outside, a FIFO, a folder, and
    a hard link to a file outside. The listing keeps the entry because its name is a record name;
    has_requests() does not drop it. When the claim reaches it, it is judged at open and claim()
    raises StateRefused naming that entry. The entry is left in place, its target is unread, and
    nothing reaches inflight/.

    The symlink's target is a FIFO already holding a request body (`_spec1135.fifo_holding`),
    so a read through the link is observable: it consumes the body. The hard link's target is a
    plain file (a hard link to a FIFO would be a FIFO)."""
    paths = S.built_paths(tmp_path)
    queue = paths.state_root / "author-queue"
    queue.mkdir()
    body = (json.dumps(S.request_body("case-x", tmp_path)) + "\n").encode()
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
    """On plain entries, has_requests() and the claim see every *.json record in author-queue/
    and author-queue/inflight/. Entries at foreign names are never opened, followed, counted or
    reported: a plain one (a README, or today's .<name>.requeue.<pid> staging file) and a
    non-plain one (a symlink notes.txt to a file outside, or a FIFO x.fifo). The pass completes,
    no log line names them, and nothing blocks on the FIFO."""
    # rejected: halting on a non-plain entry at a foreign name (3.1 D: O2 holds because nothing
    # follows it)
    paths = S.built_paths(tmp_path)
    queue = paths.state_root / "author-queue"
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

    S.seed_request(paths, "case-a", tmp_path / "runs" / "run-a")
    S.seed_request(paths, "case-b", tmp_path / "runs" / "run-b", inflight=True)
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


# ---------------------------------------------------------------------------------------------
# conversion and ordinary errors (JF2 A)
# ---------------------------------------------------------------------------------------------

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
    """Each refusal shape the core produces reaches a handle verb's caller as StateRefused, never
    as an OSError and never folded to absent or empty: NotPlainEntry at the leaf (link ELOOP,
    hard link EMLINK); the plain OSError(ELOOP) of a linked holding folder; the
    NotADirectoryError(ENOTDIR) of a file where a holding folder belongs (R16); a refused Bound
    read's reason; an `other` entry at a record name. Every other non-ok read answer is an
    ordinary failure on today's route (JF2 A).

    One read verb (rows) and one write verb (stamp), as the hint says suffices."""
    paths = S.built_paths(tmp_path)
    target = S.outside(tmp_path, "entry.json", '{"outside": true}\n')
    state = S.LearningState.open(paths)
    if verb == "rows":
        folder = paths.state_root / "_pending"
        leaf = folder / "findings.jsonl"
    else:
        S.seed_request(paths, "case-x", tmp_path / "runs" / "run-a")
        claims = _claim_all(state)
        assert len(claims) == 1, f"the plain request was not claimed: {claims!r}"
        folder = paths.state_root / "author-queue" / "inflight"
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
    """Ordinary I/O outcomes keep today's routing and are never StateRefused: a requeue into a
    plain occupied top-level slot returns False (C3); a queued request that vanished between the
    listing and its move is skipped by the claim, as today's FileNotFoundError arm does; move_at
    on a missing source raises FileNotFoundError."""
    paths = S.built_paths(tmp_path)
    S.seed_request(paths, "case-x", tmp_path / "runs" / "run-a")
    state = S.LearningState.open(paths)
    claims = _claim_all(state)
    assert len(claims) == 1, f"the plain request was not claimed: {claims!r}"
    fresher = S.seed_request(paths, "case-x", tmp_path / "runs" / "run-b")  # a re-ask mid-serve
    body = fresher.read_bytes()
    answer = state.requeue(claims[0])
    assert answer is False, f"a requeue into an occupied slot answered {answer!r}"
    assert fresher.read_bytes() == body, "the requeue overwrote the fresher request"

    S.seed_request(paths, "case-p", tmp_path / "runs" / "run-p")
    S.seed_request(paths, "case-q", tmp_path / "runs" / "run-q")
    served: list = []
    passed = S.caught(lambda: served.extend(_vanishing_pass(state, paths)))
    assert passed is None, f"the pass raised {passed!r}"
    assert [c.key for c in served] == ["case-p"], \
        f"a request that vanished mid-pass was not skipped: {[c.key for c in served]}"

    move_at = S.core_fn("move_at")
    with _io.hold(paths.state_root) as held:
        missing = S.caught(lambda: move_at(held, "author-queue/nope.json",
                                           "author-queue/inflight/nope.json"))
    assert isinstance(missing, FileNotFoundError), f"move_at on a missing source answered {missing!r}"
    assert not S.is_refusal(missing), f"move_at on a missing source answered a refusal {missing!r}"


def _vanishing_pass(state, paths: LoopPaths):
    """A claim pass during which a second queued request is deleted (by another actor) after the
    pass has started and before it reaches that request."""
    claims = iter(state.claim("case_id"))
    for claim in claims:
        (paths.state_root / "author-queue" / "case-q.json").unlink(missing_ok=True)
        yield claim


# ---------------------------------------------------------------------------------------------
# R14's one fix, D8's rotate
# ---------------------------------------------------------------------------------------------


def test_a_request_whose_identity_is_already_claimed_this_pass_waits_a_pass(tmp_path: Path):
    """A claim pass runs over author-queue/inflight/case-x.json (an orphan for run A) and a
    top-level author-queue/case-x.json (a fresher request for run B), holding every claim as a
    pass does. The pass yields exactly one claim, run A's orphan. Run B's request stays at its
    top-level name with its bytes unchanged, and the orphan's inflight/ record is never
    overwritten by it. After done on the orphan, the next pass claims run B's request. Identity
    is the record name's stem (JF7)."""
    # rejected: revision 2's newest-wins removal of the orphan (R5, superseded by R14); N2 —
    # request record bodies are unchanged
    paths = S.built_paths(tmp_path)
    run_a, run_b = tmp_path / "runs" / "run-a", tmp_path / "runs" / "run-b"
    orphan = S.seed_request(paths, "case-x", run_a, inflight=True)
    fresher = S.seed_request(paths, "case-x", run_b)
    orphan_body, fresher_body = orphan.read_bytes(), fresher.read_bytes()

    state = S.LearningState.open(paths)
    first = _claim_all(state)
    assert [c.spec.get("run_dir") for c in first] == [str(run_a.resolve())], \
        f"the pass served {[c.spec for c in first]}, not exactly run A's orphan"
    assert S.entry_kind(fresher) == "file", "run B's request left its top-level name"
    assert fresher.read_bytes() == fresher_body, "run B's request changed"
    assert orphan.read_bytes() == orphan_body, "the fresher request overwrote the orphan's claim"

    state.done(first[0])
    second = _claim_all(state)
    assert [c.spec.get("run_dir") for c in second] == [str(run_b.resolve())], \
        "the next pass did not claim run B's request"


def test_a_refused_ledger_stops_rotate_before_the_queue_is_replaced(tmp_path: Path):
    """With a symlink planted at a channel's consumed ledger: rotate(channel, held, consumed,
    sha, timeout=...) raises StateRefused before any write; the queue file's bytes are unchanged
    (not replaced), and nothing is appended through the link (D8: both files are judged before
    either is written)."""
    # rejected: closing the crash window between the queue replace and the ledger append
    # (unchanged, O3; X11)
    paths = S.built_paths(tmp_path)
    queue = paths.state_root / "_pending" / "findings.jsonl"
    keep, done = _finding("a/0"), _finding("a/1")
    S.write_jsonl(queue, [keep, done])
    queue_bytes = queue.read_bytes()
    ledger_target = S.outside(tmp_path, "consumed.jsonl", "")
    S.plant(paths.state_root / "_pending" / "consumed.jsonl", "symlink", target=ledger_target)

    state = S.LearningState.open(paths)
    refused = S.caught(lambda: state.rotate(S.coined("FINDINGS"), [keep], [done], "abc123",
                                            timeout=5))

    assert S.is_refusal(refused), f"rotate over a planted ledger answered {refused!r}"
    assert queue.read_bytes() == queue_bytes, "the queue was replaced before the refusal"
    assert ledger_target.read_text(encoding="utf-8") == "", "a row went through the ledger link"


# ---------------------------------------------------------------------------------------------
# D2: the two core functions beside Held
# ---------------------------------------------------------------------------------------------


def test_move_at_renames_under_the_held_root(tmp_path: Path):
    """move_at(held, src, dst) renames a plain src to dst across two folders below the held root:
    it makes dst's holding folders; onto a plain destination it replaces it, as os.replace does;
    a missing src raises FileNotFoundError."""
    # rejected: a hard-linked, FIFO, link or folder destination enumeration (R17: no host-actor
    # edge enumeration; #20 is the move guard)
    move_at = S.core_fn("move_at")
    paths = S.built_paths(tmp_path)
    root = paths.state_root
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
    (root / "runs" / "run-a").mkdir(parents=True)
    (root / "author-queue" / "inflight" / "case-a.json").write_text(
        json.dumps(S.request_body("case-a", root / "runs" / "run-a")) + "\n", encoding="utf-8")
    state = S.LearningState.open(paths)
    assert [c.key for c in _claim_all(state)] == ["case-a"], \
        "the handle's claim does not see the record at the inflight/ name move_at moved it to"


def test_open_lock_at_opens_a_plain_lock_without_truncating(tmp_path: Path):
    """open_lock_at(held, name) returns an open file at name for flock: it makes the holding
    folders; under umask 022 it creates an absent lock file with mode 0o644 (R8/D9); it never
    truncates an existing lock file's content; two opens of one name exclude each other under
    flock LOCK_EX|LOCK_NB (C7); timing stays in _flock.take/release."""
    # rejected: N13 — a lock mode looser than 0644 is not kept; the hard-link/FIFO lock cases
    # (R17)
    open_lock_at = S.core_fn("open_lock_at")
    paths = S.built_paths(tmp_path)
    root = paths.state_root
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


# ---------------------------------------------------------------------------------------------
# A18: the regression tier's absence oracles read what the handle writes
# ---------------------------------------------------------------------------------------------


def test_1135_an_absence_assert_reads_through_an_oracle_the_handle_no_longer_writes(
        tmp_path: Path):
    """O3: the regression tier asserts the same behaviour after the change, so an absence assert
    (a channel's dead-letter file, stuck report, consumed ledger or queue is empty or unchanged
    after a tick) must still discriminate: it fails if the tick wrote that record, including when
    the code under test wrote into a different root (the checkout's default root, which R15 and
    O4 rule out) or when the test spells a record name the handle spells differently.

    Observed as the property the design guarantees (R14 keeps every record name): each record the
    handle writes for the findings channel — the queue (append), the consumed ledger (rotate) and
    the dead-letter graveyard (deadletter) — lands under the held root at the name the regression
    tier's oracles spell today, and nothing lands under the checkout's default root. The stuck
    report's name is pinned the same way by the drain tests' by-name oracles (#31, #32)."""
    default_pending = S.DEFENDER / "learning" / "_pending"
    default_before = S.tree_snapshot(default_pending)
    paths = S.built_paths(tmp_path)
    pending = paths.state_root / "_pending"
    a, b, c = _finding("a/0"), _finding("a/1"), _finding("a/2")
    findings = S.coined("FINDINGS")

    state = S.LearningState.open(paths)
    state.append(findings, [a, b, c], dedup_key="finding_id")
    assert S.jsonl_rows(pending / "findings.jsonl") == [a, b, c], "the queue is not at _pending/findings.jsonl"
    state.rotate(findings, [a], [b], "abc123", timeout=5)
    assert [r["finding_id"] for r in S.jsonl_rows(pending / "consumed.jsonl")] == ["a/1"], \
        "the consumed ledger is not at _pending/consumed.jsonl"
    state.deadletter(findings, [{**c, "reason": "unkeyable"}])
    assert [r["finding_id"] for r in S.jsonl_rows(pending / "findings.deadletter.jsonl")] \
        == ["a/2"], "the graveyard is not at the name the regression tier reads"

    assert S.tree_snapshot(default_pending) == default_before, \
        "the handle wrote under the checkout's default root"
