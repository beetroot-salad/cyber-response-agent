"""#1135 — the drain tick: the halt on a refused entry, and today's containment of everything else.

Every test drives the REAL corpus drain, `drains.author_drain`, through the REAL stage runner
`cli._run_stage`, over a CREATED state root (R15) and a real git repo. The default
`trigger_author` runs the real curators: the gate, the closing rotation and the stuck recorder
are production code. Rows are chosen so no model is ever called: a family defender row whose
`judge_outcome` is `caught` is consumed by the findings gate (`consumed_family_skip`), and a
world row a committed `lessons-questioner/` lesson already cites is consumed by the questioner
gate (`consumed_idempotent`) — so "the questioner curator ran" is observable as its consumed
ledger gaining that row. The fakes are `author_drain`'s own seams (`branch=`, `start_box=`,
`stop_box=`, `scrub=`), which record and decide nothing; one test (s_d7) also needs the
`trigger_author=` seam, see its docstring.

Oracles read the tree by today's record names (R14), never through the handle under test; each
test also reads the queue back through the handle (`rows`), which must agree.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from defender.learning.core import drains
from defender.learning.core.cli import _run_stage
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL,
    LEAD_AUTHOR_DRAIN_LABEL,
    LoopPaths,
    StageAbort,
)
from defender.tests import _drain719 as D
from defender.tests.e2e import _box665 as B
from defender.tests.learning_state_1135 import _spec1135 as S

#: The world row the committed questioner lesson already cites (consumed with no model call).
SEEN_WORLD_ID = "ep-1/b/0/0"

#: Lock files a tick creates below an existing root, as today (R15: "lock files and holding
#: folders below an existing root are still created as today"). Empty files; never data.
LOCK_NAMES = {
    ".author-drain.lock", "_author.lock", "_pending/.lock", "_pending/.findings.lock",
    "_pending/.questioner_findings.lock",
}


# ---------------------------------------------------------------------------------------------
# The world: a repo with both corpora, a created state root, both thresholds at 1
# ---------------------------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout


def _world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, LoopPaths]:
    """`(repo, root, paths)`: `_drain719.make_repo` plus a `lessons-questioner/` corpus whose one
    committed lesson cites `SEEN_WORLD_ID`, and `LoopPaths` over a CREATED root."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    repo = D.make_repo(tmp_path)
    corpus = repo / "defender" / "lessons-questioner"
    corpus.mkdir(parents=True, exist_ok=True)
    (corpus / "seen.md").write_text(
        f"---\nname: seen\nsource_finding_ids:\n- {SEEN_WORLD_ID}\n---\n\nbody\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "questioner corpus")
    paths = S.built_paths(tmp_path, repo_root=repo)
    return repo, tmp_path / "learning-state", paths


def _defender_row(fid: str, judge_outcome: str) -> dict:
    """A family defender row (`_gate_family`): `caught` is consumed unauthored, `survived` is
    admitted for authoring."""
    return dict(D.finding_row(fid, run_id="ep-1", direction="family"), subject="defender",
                type="lead-set", judge_outcome=judge_outcome, subject_anchor="l-001",
                subject_topic="coverage", source_run_dir="episodes/ep-1/worlds/b")


def _held_row(fid: str) -> dict:
    """An adversarial row with no `source_refs.yaml` under its run: the gate HOLDS it."""
    return D.finding_row(fid, run_id="ep-9", direction="adversarial")


def _world_row(fid: str = SEEN_WORLD_ID) -> dict:
    return dict(D.finding_row(fid, run_id="ep-1", direction="world"), subject="world",
                type="story-overlay-gap", world="b", judge_outcome="gradable",
                source_run_dir="episodes/ep-1")


def _queue(root: Path) -> Path:
    return root / "_pending" / "findings.jsonl"


def _seed(root: Path, findings: list[dict], questioner: list[dict] | None = None) -> None:
    """Seed both channels' queues by today's names (the fixture's write, not the handle's)."""
    S.write_jsonl(_queue(root), findings)
    S.write_jsonl(root / "_pending" / "questioner_findings.jsonl",
                  [_world_row()] if questioner is None else questioner)


class _RepoBranch(B.RecordingBranch):
    """`author_drain`'s `branch=` seam over the REAL repo (as e2e/test_922_spine's RepoBranch):
    the batch's worktree is the repo itself, so a corpus commit is a real `git commit`; the
    push/PR step is recorded (`finish_batch:<id>` in `events`), never performed."""

    def __init__(self, repo: Path, **kw: Any) -> None:
        super().__init__(repo.parent, **kw)
        self._repo = repo

    def start_batch(self, batch_id: str) -> Path:
        self.events.append(f"start_batch:{batch_id}")
        return self._repo


def _tick(paths: LoopPaths, repo: Path, *, trigger_author: Any = None) -> tuple[int, list[str]]:
    """One corpus-drain tick through the stage runner: `(exit status, branch/box events)`."""
    rec = B.BoxLifecycleRecorder()
    branch = _RepoBranch(repo, events=rec.events)
    extra = {} if trigger_author is None else {"trigger_author": trigger_author}
    rc = _run_stage(lambda: drains.author_drain(
        paths, branch=branch, start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub,
        **extra))
    return rc, rec.events


def _lines(caplog: pytest.LogCaptureFixture, level: int) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == level]


def _changed(before: dict, after: dict) -> set[str]:
    return {k for k in set(before) | set(after) if before.get(k) != after.get(k)}


def _stuck(root: Path, queue: str = "findings") -> list[dict]:
    return S.jsonl_rows(root / "_pending" / f"{queue}.stuck.jsonl")


def _handle_rows(paths: LoopPaths) -> list[dict]:
    """The findings queue read back through the handle's `rows` verb."""
    state = S.LearningState.open(paths)
    return S.rows_of(state.rows(S.coined("FINDINGS")))


# ---------------------------------------------------------------------------------------------
# #30 — the halt
# ---------------------------------------------------------------------------------------------


def test_a_refusal_in_the_first_curator_halts_the_tick_with_exit_2(tmp_path, monkeypatch, caplog):
    """A curator-drain tick runs through _run_stage with a symlink planted at the findings
    channel's consumed ledger (`_pending/consumed.jsonl`, pointing at a file outside the root).
    That plant is reached by rotate inside _tick's stuck-guarded body (the gate consumes the
    tick's one row, so the closing rotation appends it to the ledger), so the refusal crosses
    every changed catch site. Then: the stage returns 2 with a CRITICAL line naming the refused
    entry, and no second "...it displaced" CRITICAL line (JF15: a lone refusal is one CRITICAL
    line; the core error the handle converted is not a displaced fault); the entry and its
    target are untouched; no queue, ledger or request is rewritten, and
    nothing is dead-lettered, retired or bumped; no stuck record is written on either channel
    (_tick's arm skips it for StateRefused, 3.1 A, and _drain_one_curator records nothing); the
    questioner curator does not run in that tick (R12 narrowed by R16 and 3.1 B). The only
    entries the tick may add are lock files, created below the existing root as today.

    JF1 (owner, §7) is a clause: the halt line naming the batch's branch is not asserted here."""
    # rejected: N11 — no recovery scan; N14 — no skip or report-and-continue; N15 — earlier
    # writes in the tick are not rolled back; the by-hand CLIs get an uncaught traceback, not
    # exit 2 — declared, not fixed
    caplog.set_level(logging.INFO)
    repo, root, paths = _world(tmp_path, monkeypatch)
    row = _defender_row("ep-1/b/0/1", "caught")
    _seed(root, [row])
    target = S.outside(tmp_path, "ledger.jsonl")
    ledger = S.plant(root / "_pending" / "consumed.jsonl", "symlink", target=target)
    before, target_bytes = S.tree_snapshot(root), target.read_bytes()

    rc, _events = _tick(paths, repo)

    assert rc == 2, f"a refused consumed ledger did not halt the tick: exit {rc}"
    critical = _lines(caplog, logging.CRITICAL)
    assert any("consumed.jsonl" in line for line in critical), \
        f"no CRITICAL line names the refused entry: {critical}"
    displaced = [line for line in critical if line.startswith("...it displaced")]
    assert not displaced, (
        "the halt printed a second CRITICAL line that labels the converted core error a "
        f"displaced fault (JF15: no new line): {displaced}")
    assert S.entry_kind(ledger) == "link", "the planted entry was not left in place"
    assert os.readlink(ledger) == str(target), "the planted entry was re-pointed"
    assert target.read_bytes() == target_bytes, "the rotation wrote through the planted link"
    changed = _changed(before, S.tree_snapshot(root))
    assert changed <= LOCK_NAMES, (
        f"the halted tick wrote records below the root (queue, ledger, graveyard, stuck report, "
        f"the sibling's ledger): {sorted(changed - LOCK_NAMES)}")
    assert _stuck(root) == [], "a findings stuck record was written for the refusal"
    assert _stuck(root, "questioner_findings") == [], \
        "a questioner stuck record was written for the refusal"
    assert S.entry_kind(root / "_pending" / "questioner_consumed.jsonl") == "absent", \
        "the questioner curator ran in the halted tick"
    assert _handle_rows(paths) == S.jsonl_rows(_queue(root)) == [row], \
        "the queue read back through the handle is not the queue the tick left"


# ---------------------------------------------------------------------------------------------
# #31 — a non-refusal systemic fault keeps today's containment
# ---------------------------------------------------------------------------------------------


def test_a_non_refusal_fault_in_the_first_curator_stays_contained(tmp_path, monkeypatch, caplog):
    """An existing SYSTEMIC_FAULTS member that is not a StateRefused is raised at the same site
    as #30, inside _tick's stuck-guarded body. It keeps today's containment: exactly one stuck
    record is written on that channel (by _tick's arm; _drain_one_curator sees it already
    recorded); the fault does not reach _run_stage; the questioner curator still runs in the
    same tick. Revisions 3 and 3.1 B narrow only the curator, recorder and _tick catches, and
    only to StateRefused.

    The fault is a real input through real code, in place of the seed's StageAbort-from-the-gate
    (no real input makes the gate raise StageAbort): the tick's one row is admitted for authoring
    (`judge_outcome: survived`), and `LEARNING_VERIFIER_MODEL` names a model no provider serves,
    so the drain's verifier-key preflight raises `FatalConfigError` — a SYSTEMIC_FAULTS member —
    inside _tick's body, before any model is spawned (config.source_first_party_key)."""
    caplog.set_level(logging.INFO)
    monkeypatch.setenv("LEARNING_VERIFIER_MODEL", "no-such-provider-model-1135")
    repo, root, paths = _world(tmp_path, monkeypatch)
    row = _defender_row("ep-1/b/0/2", "survived")
    _seed(root, [row])
    queue_bytes = _queue(root).read_bytes()

    rc, _events = _tick(paths, repo)

    assert rc == 0, f"a contained systemic fault reached _run_stage: exit {rc}"
    assert _lines(caplog, logging.CRITICAL) == [], "the contained fault was reported CRITICAL"
    stuck = _stuck(root)
    assert [r["fault_class"] for r in stuck] == ["FatalConfigError"], \
        f"expected exactly one stuck record for the contained fault: {stuck}"
    assert stuck[0]["row_ids"] == [row["finding_id"]], f"the stuck record names other rows: {stuck}"
    assert [r["finding_id"] for r in S.jsonl_rows(root / "_pending" / "questioner_consumed.jsonl")] \
        == [SEEN_WORLD_ID], "the questioner curator did not run after the contained fault"
    assert _queue(root).read_bytes() == queue_bytes, "the contained fault's row was rewritten"
    assert _handle_rows(paths) == [row], \
        "the queue read back through the handle is not the row the fault left queued"


# ---------------------------------------------------------------------------------------------
# #32 — RF4's recorder catch re-raises a refusal
# ---------------------------------------------------------------------------------------------


def test_a_refused_stuck_report_raises_instead_of_logging_not_written(
        tmp_path, monkeypatch, caplog):
    """When a non-retiring fault in run_batch/_tick/_handle_retire is recorded and the channel's
    stuck report is a planted symlink, the recorder catch re-raises the StateRefused (RF4,
    narrowed by R16): it does not log "stuck record NOT written", and nothing is appended to the
    link's target.

    Driven at the recorder itself: the folded drain body `author/drain.run_batch` over the
    regression tier's findings config (`_drain719.cfg_for`), with the channel's forward check
    restored and `LEARNING_VERIFIER_MODEL` naming a model no provider serves, so #31's real
    `FatalConfigError` (a non-retiring fault) is raised inside _tick and handed to the recorder.
    Not through `author_drain`: `_drain_one_curator` reads the stuck report's count before the
    curator runs, so a refusal there would be met before any recorder catch is reached. The
    stuck report `_pending/findings.stuck.jsonl` is a link to a file outside the root (X5:
    today's recorder follows it and appends the record into the target)."""
    from defender.learning.author import drain as author_drain_body
    from defender.learning.author.verify_forward.checks import FINDINGS_CHECK

    caplog.set_level(logging.INFO)
    monkeypatch.setenv("LEARNING_VERIFIER_MODEL", "no-such-provider-model-1135")
    repo, root, paths = _world(tmp_path, monkeypatch)
    row = _defender_row("ep-1/b/0/3", "survived")
    _seed(root, [row])
    target = S.outside(tmp_path, "stuck.jsonl")
    report = S.plant(root / "_pending" / "findings.stuck.jsonl", "symlink", target=target)
    target_bytes = target.read_bytes()
    agent = D.recording(D.committing("never"))
    cfg = D.cfg_for(paths, "findings", invoke_agent=agent, forward_check=FINDINGS_CHECK)

    escaped = S.caught(lambda: author_drain_body.run_batch(cfg=cfg, hold_committed=True))

    assert target.read_bytes() == target_bytes, \
        "the stuck record was appended through the planted link"
    not_written = [m for m in _lines(caplog, logging.ERROR) if "NOT written" in m]
    assert not not_written, \
        f"the refused stuck report was logged as 'not written' instead of re-raised: {not_written}"
    assert S.is_refusal(escaped), \
        f"the recorder catch did not re-raise the refusal; {escaped!r} escaped run_batch"
    assert "findings.stuck.jsonl" in str(escaped), \
        f"the refusal does not name the refused stuck report: {escaped}"
    assert agent.calls == [], "the model was spawned: the fault was not the preflight's"
    assert S.entry_kind(report) == "link", "the planted stuck report was not left in place"
    assert os.readlink(report) == str(target), "the planted stuck report was re-pointed"
    assert _handle_rows(paths) == [row], "the faulted row did not stay queued"


# ---------------------------------------------------------------------------------------------
# s_d7 — the second curator's non-refusal systemic fault, after the first committed
# ---------------------------------------------------------------------------------------------


class _FirstCommitsSecondFaults:
    """The `trigger_author=` seam — the one seam through which a curator's MODEL can be faked
    (no real input commits a lesson without a model). For the lessons curator it runs the REAL
    folded drain body (`author/drain.run_batch`: gate, commit, closing rotation) over the
    regression tier's own config builder (`_drain719.cfg_for`), with only the model faked
    (`_drain719.committing`); for the questioner curator it raises `StageAbort`, a
    SYSTEMIC_FAULTS member that is not a refusal, at the seam — C32's executed shape (a
    non-OSError systemic fault raised in trigger_author is contained).

    SIGNATURE-AGNOSTIC: the design reshapes this seam to take the handle (O5); this fake finds
    the curator's module name among its arguments by value and the batch worktree's `LoopPaths`
    by type, and pins nothing else about the call."""

    def __init__(self) -> None:
        self.modules: list[str] = []

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        values = [*args, *kwargs.values()]
        module = next(v for v in values if v in ("author", "questioner_curator"))
        self.modules.append(module)
        if module == "questioner_curator":
            raise StageAbort("questioner curator: a systemic fault that is not a refusal")
        wt_paths = next((v for v in values if isinstance(v, LoopPaths)), None)
        assert wt_paths is not None, (
            "the trigger_author seam carries no worktree LoopPaths — this fake needs the batch "
            "worktree to build the curator's config (rename the lookup here)")
        from defender.learning.author import drain as author_drain_body

        cfg = D.cfg_for(wt_paths, "findings", invoke_agent=D.committing("family-lesson"))
        author_drain_body.run_batch(cfg=cfg, hold_committed=True, box=kwargs.get("box"))


def test_1135_second_curator_meets_a_non_refusal_systemic_fault_after_the_first_committed(
        tmp_path, monkeypatch, caplog):
    """A systemic fault that is not a refusal keeps today's containment (3.1 B, R16: the curator
    catch re-raises StateRefused only): the second curator's failure is recorded on its channel's
    stuck report and the tick returns without exit 2. The first curator's committed work is as it
    is today: its batch is pushed and its PR opened in the same tick, and its committed rows stay
    queued (hold_committed) until the lesson is on origin/main — nothing is consumed by the tick,
    and nothing is left on an unpushed branch.

    PJ1C is the probed today; PJ1R refutes "the first curator's rows are consumed"."""
    caplog.set_level(logging.INFO)
    repo, root, paths = _world(tmp_path, monkeypatch)
    row = _defender_row("ep-1/b/0/4", "survived")
    _seed(root, [row])
    head_before = _git(repo, "rev-parse", "HEAD").strip()
    trigger = _FirstCommitsSecondFaults()

    rc, events = _tick(paths, repo, trigger_author=trigger)

    assert trigger.modules == ["author", "questioner_curator"], trigger.modules
    assert rc == 0, f"a contained systemic fault in the second curator halted the tick: {rc}"
    assert _lines(caplog, logging.CRITICAL) == [], "the contained fault was reported CRITICAL"
    assert [r["fault_class"] for r in _stuck(root, "questioner_findings")] == ["StageAbort"], \
        "the second curator's fault was not recorded once on its own channel"
    assert _stuck(root) == [], "a stuck record was written on the first curator's channel"
    landed = _git(repo, "diff", "--name-only", f"{head_before}..HEAD").split()
    assert any(n.startswith("defender/lessons/family-lesson-") for n in landed), \
        f"the first curator's lesson was not committed in the tick: {landed}"
    assert any(e.startswith("finish_batch:") for e in events), \
        f"the first curator's batch was not delivered (pushed, PR opened) in the tick: {events}"
    assert S.tree_snapshot(root / "_pending_delivery") == {}, \
        "a delivery record was left: the batch sits on an undelivered branch"
    assert [r["finding_id"] for r in S.jsonl_rows(_queue(root))] == [row["finding_id"]], \
        "the first curator's committed row did not stay queued (hold_committed)"
    assert row["finding_id"] not in [
        r.get("finding_id") for r in S.jsonl_rows(root / "_pending" / "consumed.jsonl")], \
        "the tick consumed the first curator's committed row"
    assert [r["finding_id"] for r in _handle_rows(paths)] == [row["finding_id"]], \
        "the queue read back through the handle is not the queue the tick left"


# ---------------------------------------------------------------------------------------------
# s_d15 — a halt releases every lock it held
# ---------------------------------------------------------------------------------------------


def test_1135_locks_of_a_halted_tick_are_free_for_the_next_tick(tmp_path, monkeypatch, caplog):
    """After a tick halts on a refused entry, every lock it held (the repo lock, the drain lock,
    a channel's append lock) is released: the same process's next tick takes each of them (O3:
    lock semantics are unchanged and a halt unwinds through the lock holders like any exception).

    The halt is #30's (a link at the findings channel's consumed ledger). After it: each lock
    file is free to another holder; the handle takes the repo lock and the drain locks; and once
    the planted entry is removed, the next tick in this process runs through and consumes."""
    caplog.set_level(logging.INFO)
    repo, root, paths = _world(tmp_path, monkeypatch)
    row = _defender_row("ep-1/b/0/5", "caught")
    _seed(root, [row])
    ledger = S.plant(root / "_pending" / "consumed.jsonl", "symlink",
                     target=S.outside(tmp_path, "ledger.jsonl"))

    rc, _events = _tick(paths, repo)
    assert rc == 2, f"the planted ledger did not halt the first tick: exit {rc}"

    for name in (".author-drain.lock", "_author.lock", "_pending/.lock",
                 "_pending/.findings.lock"):
        assert S.entry_kind(root / name) == "file", f"{name} was never taken by the tick"
        assert S.flock_free(root / name), f"the halted tick still holds {name}"

    state = S.LearningState.open(paths)
    for role, wait in (("REPO_LOCK", 0), ("AUTHOR_DRAIN_LOCK", S.coined("TRY_ONCE")),
                       ("CURATOR_DRAIN_LOCK", S.coined("TRY_ONCE"))):
        def take(role: str = role, wait: Any = wait) -> Any:
            with state.lock(S.coined(role), wait=wait) as taken:
                return taken
        finished, taken, error = S.within(10, take)
        assert finished, f"{role}: the take did not return within 10 s after the halt"
        assert error is None, f"{role}: not taken after the halt ({error!r})"
        assert taken is not False, f"{role}: answered 'not taken' after the halt"

    ledger.unlink()
    rc2, _events = _tick(paths, repo)
    assert rc2 == 0, f"the next tick did not run through: exit {rc2}"
    assert [r["finding_id"] for r in S.jsonl_rows(root / "_pending" / "consumed.jsonl")] \
        == [row["finding_id"]], "the next tick did not take the locks and consume"


# ---------------------------------------------------------------------------------------------
# s_d19 — an ordinary write failure in each phase under the stuck guard (a child process)
# ---------------------------------------------------------------------------------------------

#: The file-size ceiling the child runs under (RLIMIT_FSIZE). A file already past it cannot
#: grow by a byte (EFBIG, "File too large"): a real full-file failure, root or not.
FSIZE_LIMIT = 256 * 1024

_TICK_CHILD = r'''
import json, logging, resource, signal, sys
from pathlib import Path

spec = json.loads(sys.argv[1])
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)   # the write fails with EFBIG instead of a kill
from defender.learning.core import drains
from defender.learning.core.cli import _run_stage
from defender.learning.core.config import LoopPaths
from defender.tests.e2e import _box665 as B
from defender.tests.learning_state_1135.test_1135_drain_halt import _RepoBranch

lines = []
class Keep(logging.Handler):
    def emit(self, r):
        lines.append([r.levelname, r.getMessage()])
logging.getLogger().addHandler(Keep())
logging.getLogger().setLevel(logging.INFO)
repo = Path(spec["repo"])
paths = LoopPaths(repo_root=repo, state_dir=Path(spec["root"]))
rec = B.BoxLifecycleRecorder()
resource.setrlimit(resource.RLIMIT_FSIZE, (spec["limit"], resource.RLIM_INFINITY))
rc = _run_stage(lambda: drains.author_drain(
    paths, branch=_RepoBranch(repo, events=rec.events), start_box=rec.start_box,
    stop_box=rec.stop_box, scrub=rec.scrub))
print(json.dumps({"rc": rc, "lines": lines}))
'''


def _grown(p: Path, unit: str) -> bytes:
    """Fill `p` past `FSIZE_LIMIT` with whole lines of `unit`, and return its bytes."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(unit * (FSIZE_LIMIT // len(unit) + 64), encoding="utf-8")
    return p.read_bytes()


def _tick_in_child(tmp_path: Path, repo: Path, root: Path) -> dict:
    script = tmp_path / "tick_child.py"
    script.write_text(_TICK_CHILD, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(script),
         json.dumps({"repo": str(repo), "root": str(root), "limit": FSIZE_LIMIT})],
        capture_output=True, text=True, timeout=180, env=S.child_env(),
        cwd=str(S.DEFENDER))
    assert proc.returncode == 0, f"the tick's child process failed:\n{proc.stderr[-3000:]}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("phase", ["retire_unkeyable", "rotation_ledger_append", "held_report"])
def test_1135_ordinary_write_failure_at_each_phase_under_the_stuck_guard(
        tmp_path, monkeypatch, phase):
    """Each phase fails as it does today (R16, O3): an ordinary write failure (a full volume) in
    the retirement of unkeyable rows, the rotation's ledger append or the held-report write is
    caught by the tick's stuck guard, recorded and routed as before, with the rows in flight in
    each phase unchanged. The handle's verbs do not convert an ordinary write failure into
    StateRefused, and no phase loses a row that today survives.

    The failure is real: the tick runs in a child process under RLIMIT_FSIZE, and the phase's
    one file — the graveyard `findings.deadletter.jsonl`, the ledger `consumed.jsonl`, or the
    held report `findings.held_report.log` — is already past the ceiling, so its append fails
    with EFBIG while every other write of the tick fits. Write-side failures carry an errno
    (G8); _tick's arm records any fault outside RETIRE_SET, an OSError included (X21), and the
    curator frame contains an OSError as today. The questioner curator still runs."""
    repo, root, paths = _world(tmp_path, monkeypatch)
    pending = root / "_pending"
    caught = _defender_row("ep-1/b/0/6", "caught")
    held = _held_row("ep-9/a/0/1")
    if phase == "retire_unkeyable":
        unkeyable = {k: v for k, v in _defender_row("ep-1/b/0/7", "caught").items()
                     if k != "finding_id"}
        rows = [unkeyable, caught]
        grown = pending / "findings.deadletter.jsonl"
        unit = json.dumps({"finding_id": "old", "deadletter_reason": "x"}) + "\n"
    elif phase == "rotation_ledger_append":
        rows = [caught, held]
        grown = pending / "consumed.jsonl"
        unit = json.dumps({"finding_id": "old", "consumed_category": "x"}) + "\n"
    else:
        rows = [held]
        grown = pending / "findings.held_report.log"
        unit = "2026-01-01T00:00:00Z batch=old gate_held=1\n"
    _seed(root, rows)
    grown_bytes = _grown(grown, unit)
    queue_bytes = _queue(root).read_bytes()

    out = _tick_in_child(tmp_path, repo, root)

    assert out["rc"] == 0, f"an ordinary write failure halted the tick: {out}"
    assert not [m for lvl, m in out["lines"] if lvl == "CRITICAL"], out["lines"]
    assert grown.read_bytes() == grown_bytes, f"{grown.name} grew past the ceiling"
    stuck = _stuck(root)
    assert len(stuck) == 1, f"the stuck guard did not record the {phase} failure: {stuck}"
    assert stuck[0]["fault_class"] == "OSError", \
        f"the ordinary failure was not recorded as itself: {stuck[0]}"
    assert "File too large" in stuck[0]["reason"], \
        f"the stuck record does not carry the ordinary failure's reason: {stuck[0]}"
    assert [r["finding_id"] for r in S.jsonl_rows(pending / "questioner_consumed.jsonl")] \
        == [SEEN_WORLD_ID], "the ordinary failure was not contained: the questioner did not run"
    queued = S.jsonl_rows(_queue(root))
    if phase == "retire_unkeyable":
        assert _queue(root).read_bytes() == queue_bytes, \
            "the graveyard failure lost rows the queue held"
    elif phase == "rotation_ledger_append":
        assert held["finding_id"] in [r.get("finding_id") for r in queued], \
            "the held row did not survive the failed ledger append"
    else:
        assert [r.get("finding_id") for r in queued] == [held["finding_id"]], \
            "the held row was not written back before the held-report failure"
    assert S.rows_of(S.LearningState.open(paths).rows(S.coined("FINDINGS"))) == queued, \
        "the queue read back through the handle disagrees with the queue on disk"


# ---------------------------------------------------------------------------------------------
# s_i7 — a planted entry at the repo lock's name
# ---------------------------------------------------------------------------------------------


def test_1135_a_deadline_lock_name_is_a_planted_entry_when_run_batch_takes_the_repo_lock(
        tmp_path, monkeypatch, caplog):
    """A planted entry at the repo lock's name is a refusal and not a busy or timed-out lock:
    StateRefused is not an OSError and is not received by run_batch's TimeoutError arm ("repo
    lock unavailable ... queue intact", which returns 0). The tick halts with exit 2 and a
    CRITICAL line naming the lock entry (a lock-open refusal raises for every role, O2), with no
    second "...it displaced" CRITICAL line (JF15: no new line); no lock target is created and
    the queue is untouched.

    The plant is a symlink at `_author.lock` to an absent file outside the root (C10: today's
    lock open follows it and creates the target)."""
    caplog.set_level(logging.INFO)
    repo, root, paths = _world(tmp_path, monkeypatch)
    row = _defender_row("ep-1/b/0/8", "caught")
    _seed(root, [row])
    queue_bytes = _queue(root).read_bytes()
    target = tmp_path / "outside" / "repo.lock"
    target.parent.mkdir()  # the link's target is absent; its folder exists (C10's shape)
    lock = S.plant(root / "_author.lock", "symlink", target=target)

    rc, _events = _tick(paths, repo)

    assert S.entry_kind(target) == "absent", "the repo lock's open created the link's target"
    assert not [m for m in _lines(caplog, logging.WARNING) if "repo lock unavailable" in m], \
        "the refused repo lock was answered as a busy lock"
    assert rc == 2, f"a planted repo lock did not halt the tick: exit {rc}"
    critical = _lines(caplog, logging.CRITICAL)
    assert any("_author.lock" in m for m in critical), \
        "no CRITICAL line names the refused lock entry"
    displaced = [m for m in critical if m.startswith("...it displaced")]
    assert not displaced, (
        "the halt printed a second CRITICAL line that labels the converted core error a "
        f"displaced fault (JF15: no new line): {displaced}")
    assert S.entry_kind(lock) == "link", "the planted lock entry was not left in place"
    assert os.readlink(lock) == str(target), "the planted lock entry was re-pointed"
    assert _queue(root).read_bytes() == queue_bytes, "the queue was touched"
    assert S.entry_kind(root / "_pending" / "questioner_consumed.jsonl") == "absent", \
        "the questioner curator ran in the halted tick"
    assert _handle_rows(paths) == [row], "the queue read back through the handle is not the seeded queue"


# ---------------------------------------------------------------------------------------------
# s_i18 — a planted entry at a stage folder
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape", ["symlink", "file"])
@pytest.mark.parametrize(("lane", "folder"), [(AUTHOR_DRAIN_LABEL, "_pending"),
                                            (LEAD_AUTHOR_DRAIN_LABEL, "_pending_leads")])
def test_1135_the_stage_dir_lane_folder_is_a_planted_entry(
        tmp_path, caplog, lane, folder, shape):
    """A planted link or file at a stage folder is refused when the handle makes the folder for
    the stage (stage_dir makes it through the held root, D1): StateRefused, exit 2 with a
    CRITICAL line naming the lane folder, before the stage harness runs; nothing is created
    through the link and no stage record is written.

    Driven as a stage under the real stage runner: the stage asks the handle for its lane's
    folder (`stage_dir(lane)`, the lane a drain label config spells once) and only then would
    run its harness."""
    caplog.set_level(logging.INFO)
    paths = S.built_paths(tmp_path)
    root = tmp_path / "learning-state"
    outside_dir = tmp_path / "outside-stage"
    outside_dir.mkdir()
    at = root / folder
    if shape == "symlink":
        S.plant(at, "symlink", target=outside_dir)
    else:
        at.write_text("not a folder\n", encoding="utf-8")
    before = S.tree_snapshot(root)
    state = S.LearningState.open(paths)
    harness_ran: list[Any] = []

    def stage() -> int:
        harness_ran.append(state.stage_dir(lane))
        return 0

    rc = _run_stage(stage)

    assert rc == 2, f"a planted {shape} at {folder} did not halt the stage: exit {rc}"
    assert harness_ran == [], "the stage harness ran past the refused stage folder"
    assert any(folder in m for m in _lines(caplog, logging.CRITICAL)), \
        f"no CRITICAL line names the lane folder {folder}"
    assert S.tree_snapshot(outside_dir) == {}, "something was created through the link"
    assert S.tree_snapshot(root) == before, "a stage record was written below the root"


# ---------------------------------------------------------------------------------------------
# s_a12 — everyday failures keep today's routing (a child process)
# ---------------------------------------------------------------------------------------------

_VERB_CHILD = r'''
import json, logging, os, sys
from pathlib import Path

spec = json.loads(sys.argv[1])
from defender.learning.core.config import LoopPaths
from defender.tests.learning_state_1135 import _spec1135 as S
import defender.run_common as run_common

lines = []
class Keep(logging.Handler):
    def emit(self, r):
        lines.append([r.levelname, r.getMessage()])
logging.getLogger().addHandler(Keep())
logging.getLogger().setLevel(logging.INFO)


def cell(name, root):
    paths = LoopPaths(repo_root=Path(spec["repo"]), state_dir=Path(root))
    out = {"raised": None, "errno": None, "refusal": False, "oserror": False, "answer": None}
    try:
        if name == "e1":
            os.environ["DEFENDER_LEARNING_STATE_DIR"] = root
            run_dir = Path(spec["run_dir"])
            out["answer"] = run_common.enqueue_curation(run_dir, run_dir / "alert.json")
            return out
        state = S.LearningState.open(paths)
        if name == "append":
            out["answer"] = repr(state.append(S.coined("FINDINGS"), [spec["row"]],
                                              dedup_key="finding_id"))
        elif name in ("rotate", "rotate_unreadable"):
            state.rotate(S.coined("FINDINGS"), [], [spec["row"]], None, timeout=1)
        elif name == "move":
            out["answer"] = [repr(c) for c in state.claim("case_id")]
        elif name == "lock":
            with state.lock(S.coined("AUTHOR_DRAIN_LOCK"), wait=S.coined("TRY_ONCE")) as taken:
                out["answer"] = repr(taken)
        elif name == "read":
            out["answer"] = repr(state.rows(S.coined("FINDINGS")))
    except Exception as e:
        out.update(raised=type(e).__name__, errno=getattr(e, "errno", None),
                   refusal=S.is_refusal(e), oserror=isinstance(e, OSError))
    return out


for name, root in spec["warm"].items():   # every lazy import happens here, as the owner
    cell(name, root)
if spec["drop"]:
    os.setgroups([])
    os.setresgid(65534, 65534, 65534)
    os.setresuid(65534, 65534, 65534)
lines.clear()
results = {name: cell(name, root) for name, root in spec["cells"].items()}
print(json.dumps({"results": results, "lines": lines, "uid": os.geteuid()}))
'''


#: The second row of the unreadable queue: a rotate that read the queue as empty and replaced
#: it from nothing would lose it (92 F1's data-loss tail).
_KEPT_ROW_ID = "ep-1/b/0/10"


def _unreadable_queue_rows(row: dict) -> list[dict]:
    return [row, _defender_row(_KEPT_ROW_ID, "caught")]


def _verb_tree(base: Path, name: str, row: dict, run_dir: Path) -> Path:
    """One cell's root, with the one folder its operation writes made unwritable (mode 0555,
    owned by whoever made it — the child drops to an unprivileged user when that is root), or,
    for the two read-side cells, the findings queue file itself made unreadable (mode 000)
    while its folder and append lock stay writable."""
    root = base / name
    root.mkdir(mode=0o755)
    if name in ("read", "rotate_unreadable"):
        queue = root / "_pending" / "findings.jsonl"
        S.write_jsonl(queue, _unreadable_queue_rows(row))
        (root / "_pending" / ".findings.lock").touch()
        os.chmod(root / "_pending" / ".findings.lock", 0o666)
        os.chmod(root / "_pending", 0o777)
        os.chmod(queue, 0o000)
    elif name == "append":
        (root / "_pending").mkdir(mode=0o755)
        os.chmod(root / "_pending", 0o555)
    elif name == "rotate":
        S.write_jsonl(root / "_pending" / "findings.jsonl", [row])
        (root / "_pending" / ".findings.lock").touch()
        os.chmod(root / "_pending" / ".findings.lock", 0o644)
        os.chmod(root / "_pending", 0o555)
    elif name == "move":
        queue = root / "author-queue"
        (queue / "inflight").mkdir(parents=True, mode=0o777)
        os.chmod(queue / "inflight", 0o777)
        (queue / "case-a.json").write_text(
            json.dumps(S.request_body("case-a", run_dir)) + "\n", encoding="utf-8")
        os.chmod(queue, 0o555)
    elif name == "lock":
        os.chmod(root, 0o555)
    elif name == "e1":
        (root / "author-queue").mkdir(mode=0o755)
        os.chmod(root / "author-queue", 0o555)
    return root


def _assert_an_unreadable_queue_never_reads_as_empty(
        results: dict[str, Any], after: dict[str, Any], row: dict[str, Any]) -> None:
    """The read-side cells of s_a12 (JF2 A): a queue that cannot be read fails as an ordinary
    OSError, answers no rows, and a rotate over it keeps the queue's bytes and makes no ledger."""
    for name in ("read", "rotate_unreadable"):
        got = results[name]
        assert got["raised"] is not None, (
            f"{name}: a queue that cannot be read answered {got['answer']!r} instead of failing "
            "(JF2 A: an ordinary failure, never an empty read)")
        assert got["refusal"] is False, f"{name}: an ordinary read failure became a StateRefused"
        assert got["oserror"] is True, \
            f"{name}: the unreadable queue's failure is not an OSError on today's route: {got}"
        assert got["answer"] is None, f"{name}: the failed read still answered {got['answer']!r}"
    assert after.get("unreadable_queue") == "".join(
        json.dumps(r) + "\n" for r in _unreadable_queue_rows(row)).encode(), (
        "the rotate over an unreadable queue replaced it: a row was lost "
        f"({after.get('unreadable_queue')!r})")
    assert after.get("unreadable_ledger") == "absent", \
        "the rotate over an unreadable queue appended to the consumed ledger"


def test_1135_an_everyday_failure_writing_moving_or_locking_a_state_record(tmp_path, monkeypatch):
    """Ordinary I/O errors keep today's routing (R16, O3): a read, write, append, move or lock
    open that fails for an ordinary reason gives each caller what it saw before. The run-end
    enqueue logs "could not enqueue" and returns, the investigation unchanged (E1's OSError
    arm); a rotation, a claim's move and a drain lock fail as today, and the error is not
    converted to StateRefused or folded into "not taken" for a try-once lock. A queue that
    cannot be read is an ordinary failure, never an empty read (JF2 A): rows() raises an OSError
    that is not a StateRefused and answers no rows, and a rotate over that queue raises before it
    writes, so the queue keeps its bytes (no row is lost) and the consumed ledger is not made.

    The everyday failure driven here is a permission refusal, made real, and the operations run
    in a child process that, when this process is root (root ignores permission bits), drops to
    an unprivileged user first. Cells: the run-end enqueue (a write: `run_common.enqueue_curation`
    logs at ERROR and returns False), the handle's `append`, its `rotate`, a claim's move out of
    an unwritable `author-queue/`, and a try-once drain lock whose file cannot be created — each
    with its one folder at mode 0555 — and a read and a rotate of a findings queue whose file is
    mode 000 while its folder and append lock stay writable (so a rotate that read the queue as
    empty could replace it). Each write-side handle cell raises the ordinary `PermissionError`
    (EACCES); each read-side cell raises an OSError (the core's read answer keeps only a reason
    string, so no errno is pinned there). Never a StateRefused, never an empty answer, never
    "not taken". Not driven here: a full volume is s_d19's (EFBIG); read-only volume, quota and
    lock-service refusals are not driven (R17: one ordinary failure per operation kind)."""
    base = Path(tempfile.mkdtemp(prefix="ls1135-everyday-", dir="/tmp"))
    os.chmod(base, 0o755)
    try:
        run_dir = base / "run" / "case-a"
        run_dir.mkdir(parents=True)
        (run_dir / "alert.json").write_text('{"rule": {"name": "everyday"}}\n', encoding="utf-8")
        from defender.runtime import scrub as scrub_mod

        scrub_mod.scrub(run_dir)  # a certified tree: the enqueue's refusal gate passes it
        for p in (base / "run", run_dir):
            os.chmod(p, 0o755)
        row = _defender_row("ep-1/b/0/9", "caught")
        names = ("e1", "append", "rotate", "move", "lock", "read", "rotate_unreadable")
        cells = {n: str(_verb_tree(base / "cells", n, row, run_dir))
                 for n in names if (base / "cells").mkdir(exist_ok=True, mode=0o755) or True}
        warm = {}
        for n in names:  # writable copies, so the child imports everything before it drops
            w = base / "warm" / n
            w.mkdir(parents=True)
            warm[n] = str(w)
        for p in (base / "cells", base / "warm"):
            os.chmod(p, 0o755)
        script = base / "verb_child.py"
        script.write_text(_VERB_CHILD, encoding="utf-8")
        os.chmod(script, 0o644)
        spec = {"cells": cells, "warm": warm, "row": row, "run_dir": str(run_dir),
                "repo": str(base / "repo"), "drop": os.geteuid() == 0}
        proc = subprocess.run([sys.executable, str(script), json.dumps(spec)],
                              capture_output=True, text=True, timeout=120,
                              env=S.child_env(), cwd="/")
        assert proc.returncode == 0, f"the child failed:\n{proc.stderr[-3000:]}"
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        # Read back through the handle (this process's privilege ignores the 0555 folders): the
        # failed rotation kept the queued row, and the failed claim left the request queued.
        after: dict[str, Any] = {}

        def read_back() -> None:
            repo = base / "repo"
            rotated = S.LearningState.open(LoopPaths(repo_root=repo, state_dir=Path(cells["rotate"])))
            after["queue"] = S.rows_of(rotated.rows(S.coined("FINDINGS")))
            claimed = S.LearningState.open(LoopPaths(repo_root=repo, state_dir=Path(cells["move"])))
            after["queued"] = claimed.has_requests()

        # The rotate over the unreadable queue, by today's record names (R14): made readable
        # again first (this process may not be root), never through the handle under test.
        unreadable = Path(cells["rotate_unreadable"]) / "_pending"
        os.chmod(unreadable / "findings.jsonl", 0o644)
        after["unreadable_queue"] = (unreadable / "findings.jsonl").read_bytes()
        after["unreadable_ledger"] = S.entry_kind(unreadable / "consumed.jsonl")
        read_failed = S.caught(read_back)
    finally:
        for dirpath, dirnames, _files in os.walk(base):
            for d in dirnames:
                os.chmod(Path(dirpath, d), 0o755)
        os.chmod(base, 0o755)
        shutil.rmtree(base, ignore_errors=True)

    assert out["uid"] != 0, "the child still ran as root: permission bits would not bite"
    results = out["results"]
    e1 = results["e1"]
    assert e1["raised"] is None, f"the run-end enqueue raised on an everyday failure: {e1}"
    assert e1["answer"] is False, \
        f"the run-end enqueue did not answer False on an everyday failure: {e1}"
    assert any(lvl == "ERROR" and "Permission denied" in m for lvl, m in out["lines"]), \
        f"the run-end enqueue's failure was not logged: {out['lines']}"
    for name in ("append", "rotate", "move", "lock"):
        got = results[name]
        assert got["raised"] == "PermissionError", \
            f"{name}: an everyday permission failure did not surface as itself: {got}"
        assert got["errno"] == 13, f"{name}: the permission failure lost its errno: {got}"
        assert got["refusal"] is False, f"{name}: an ordinary failure became a StateRefused"
    _assert_an_unreadable_queue_never_reads_as_empty(results, after, row)
    assert read_failed is None, f"reading the failed cells back through the handle raised {read_failed!r}"
    assert after.get("queue") == [row], \
        f"the failed rotation did not leave the queued row in place: {after.get('queue')!r}"
    assert after.get("queued") is True, "the failed claim did not leave the request queued"
