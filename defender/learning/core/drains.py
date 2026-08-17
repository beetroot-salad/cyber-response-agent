from __future__ import annotations

import contextlib
import functools
import importlib
import subprocess
import uuid
from pathlib import Path
from typing import Any
from collections.abc import Callable

from defender.learning.core.config import (
    DEFAULT_PATHS,
    LoopPaths,
    _log,
    author_max_attempts,
    env_int,
    merge_mode,
    pitfalls_threshold,
)
from defender import _git
from defender.runtime import box as box_mod
from defender.learning.author import drain
from defender.learning.author import shared as _author_shared
from defender.learning.core.directions import BY_NAME
from defender.learning.author.branch import AuthorBranch, BranchError
from defender.learning.core.faults import run_or_dead_letter
from defender.learning.core.markers import (
    ClaimedMarker,
    claim_markers,
    marker_identity,
    quarantine_marker,
    requeue_marker,
)
from defender.learning.core.persist import (
    merge_pitfalls,
    pitfalls_lane_is_open,
    read_pitfalls,
)
from defender.learning.core.quarantine import preserve_tainted_tree


class _LeadAuthorRetry(Exception):
    pass


class _LeadAuthorSkipped(Exception):
    """The serve did not happen: another lead-author tick holds the per-author queue lock.

    Distinct from `_LeadAuthorRetry` because the disposition is different (#852 F-03). A
    retry is a FAILED attempt — it bumps `spec["attempts"]` and dead-letters the request
    after `LEAD_AUTHOR_MAX_RETRIES`, which is right for work that keeps breaking and wrong
    for work nothing has tried yet: one manual `lead_author.py` run held across three ticks
    would quarantine three healthy batches. A skip costs the request nothing at all."""


def _invoke_lead_author(paths: LoopPaths, run_dir: Path, *, box: Any = None) -> None:
    from defender.learning.leads.lead_extraction import LeadAuthorError
    from defender.learning.leads.lead_author import QUEUE_LOCK_SKIP_RC

    _log("step=lead-author")
    rc = _run_curator_module("lead_author", lambda mod: mod.run(run_dir, paths=paths, box=box))
    # BEFORE the rc-is-a-fault test below, and before the success path: a lock skip used to
    # arrive as rc=0 and was indistinguishable from a completed serve, so the drain unlinked
    # every marker it had claimed in the pass — the whole batch deleted, no work done, no
    # dead letter, no retry (#852 F-03).
    if rc == QUEUE_LOCK_SKIP_RC:
        raise _LeadAuthorSkipped(
            f"lead-author for {run_dir.name} skipped: another tick holds the queue lock"
        )
    if rc not in (0, None):
        raise LeadAuthorError(f"lead-author for {run_dir.name} returned rc={rc}")
    if rc is None:
        raise _LeadAuthorRetry("lead-author hit a swallowed transient (rc=None)")


def _maybe_trigger_author(
    paths: LoopPaths,
    pending_file: Path,
    threshold_env: str,
    module_name: str,
    pending_label: str,
    *,
    box: Any = None,
) -> None:
    threshold = env_int(threshold_env, 5)
    pending_count = _pending_queue_count(pending_file)
    if pending_count < threshold:
        _log(f"{pending_label}={pending_count} threshold={threshold} — {module_name} not invoked")
        return
    _log(f"step={module_name} {pending_label}={pending_count} threshold={threshold}")
    rc = _run_curator_module(
        module_name, lambda mod: mod.run_batch(hold_committed=True, paths=paths, box=box)
    )
    if rc not in (0, None):
        _log(f"{module_name} returned rc={rc} (queue intact, retry next tick)")


_CURATOR_MODULES = {
    "lead_author": "defender.learning.leads.lead_author",
    "pitfalls_curator": "defender.learning.leads.pitfalls_curator",
    "author": "defender.learning.author.lessons.run",
    "author_actor": "defender.learning.author.malicious_actor.run",
    "author_actor_benign": "defender.learning.author.benign_actor.run",
    "author_actor_env": "defender.learning.author.benign_actor.env",
}


def _run_curator_module(module_name: str, call: Callable[[Any], int]):
    mod = importlib.import_module(_CURATOR_MODULES[module_name])
    try:
        return call(mod)
    except (subprocess.SubprocessError, OSError) as e:
        _log(f"{module_name} crashed: {e!r} (continuing)")
        return None


def _curator_queue_checks(paths: LoopPaths) -> list[tuple[Path, str]]:
    checks = [(paths.pending_file, "LEARNING_AUTHOR_THRESHOLD")]
    for direction in BY_NAME.values():
        for t in (direction.obs_trigger, *direction.extra_obs_triggers):
            checks.append((t.pending_file(paths), t.threshold_env))
    return checks


def _pending_queue_count(pending_file: Path) -> int:
    if not pending_file.is_file():
        return 0
    return sum(1 for line in pending_file.read_text(encoding="utf-8").splitlines() if line.strip())


def _has_curator_work(paths: LoopPaths) -> bool:
    return any(
        _pending_queue_count(pending_file) >= env_int(env, 5)
        for pending_file, env in _curator_queue_checks(paths)
    )


def _has_lead_author_work(paths: LoopPaths) -> bool:
    threshold = pitfalls_threshold()
    qdir = paths.author_queue_dir
    if qdir.is_dir() and any(qdir.glob("*.json")):
        return True
    # A marker stranded in `inflight/` by a drain that died mid-serve is still work: the
    # drainer reclaims it, so this gate has to wake for it or it never runs again.
    inflight = qdir / "inflight"
    if inflight.is_dir() and any(inflight.glob("*.json")):
        return True
    # The same arrival condition `run_pitfalls` gates on, asked through the same function
    # (#840 + #870 FK-3) — a wake gate that counted rows, or that answered a different
    # question from the tick's, would spin the drain up for a curation that then declines to
    # run, or (worse) never wake for work the tick would have taken.
    return pitfalls_lane_is_open(merge_pitfalls(read_pitfalls(paths)), threshold)


def _drain_curators(
    paths: LoopPaths,
    trigger_author: Callable[..., None],
    *,
    box: Any = None,
) -> None:
    trigger_author(
        paths, paths.pending_file, "LEARNING_AUTHOR_THRESHOLD", "author", "pending", box=box,
    )
    for direction in BY_NAME.values():
        for t in (direction.obs_trigger, *direction.extra_obs_triggers):
            trigger_author(
                paths, t.pending_file(paths), t.threshold_env, t.module_name, t.pending_label,
                box=box,
            )


def _discard_worktree_changes(repo_root: Path) -> None:
    if not (repo_root / ".git").exists():
        return
    for args in (["reset", "--hard", "--quiet"], ["clean", "-fdq"]):
        _git.git(args, cwd=repo_root, check=False)


def _quarantine_lead_author_failure(
    spec: dict, marker: Path, queue_dir: Path, e: Exception
) -> None:
    quarantine_marker(spec, marker, queue_dir, f"lead-author-error: {e!r}")


def _requeue_or_drop(claim: ClaimedMarker, *, note: str) -> None:
    """Hand one claimed request back to the queue, then release the claim.

    The re-queue lands at the TOP level — never at `claim.path`, the slot a reclaimed orphan
    was read from and this pass is about to unlink — and it is CREATE-IF-ABSENT. A fresher
    request for the same case that arrived while this one was claimed already occupies that
    slot, and the queue's contract is that the later run wins (#791), so the older spec is
    dropped rather than atomically written over it (#852 F-04).

    The spec comes off the CLAIM rather than as its own argument: what goes back on the
    queue and what is unlinked from `inflight/` are two halves of one hand-back, and a
    caller able to pass a spec belonging to some other claim could split them."""
    if requeue_marker(claim.queued_path, claim.spec):
        _log(f"lead_author_drain: {note} — left queued for retry")
    else:
        _log(
            f"lead_author_drain: {note} — a fresher request for the same case landed "
            "while it was claimed and supersedes it; dropping this one"
        )
    with contextlib.suppress(OSError):
        claim.path.unlink()


def _drain_lead_author_markers(
    paths: LoopPaths,
    run_lead_author: Callable[..., None],
    *,
    box: Any = None,
) -> None:
    qdir = paths.author_queue_dir
    max_retries = env_int("LEAD_AUTHOR_MAX_RETRIES", 3)
    # `case_id`: this queue's live writer (`enqueue_case_for_curation`) mints the filename
    # from the case, so that is what an unreadable row's dead letter is keyed on.
    claims = claim_markers(
        qdir, identity_key="case_id", label="lead_author_drain", noun="lead-author",
    )
    for claim in claims:
        claimed, spec, run_dir = claim.path, claim.spec, claim.run_dir
        # Where a request that is NOT served goes back — the top level, create-if-absent, and
        # never the claim slot this pass is about to unlink — is `_requeue_or_drop`'s, in one
        # place for both the skip and the retry.
        try:
            drained = run_or_dead_letter(
                functools.partial(run_lead_author, paths, run_dir, box=box),
                functools.partial(
                    _quarantine_lead_author_failure, spec, claimed, paths.author_queue_dir
                ),
                propagate=(_LeadAuthorRetry, _LeadAuthorSkipped),
            )
        except _LeadAuthorSkipped as e:
            # NOTHING was tried for this request, so it costs nothing: the spec goes back
            # untouched — no `attempts` bump, no dead letter — and the pass stops. Every
            # marker still queued would meet the same held lock, and claiming them only to
            # hand them straight back is churn against a queue another process is reading.
            _requeue_or_drop(
                claim, note=f"{marker_identity(spec, claimed)} not served: {e}",
            )
            break
        except _LeadAuthorRetry as e:
            attempts = int(spec.get("attempts", 0)) + 1
            if attempts >= max_retries:
                quarantine_marker(
                    spec, claimed, paths.author_queue_dir,
                    f"transient-exhausted after {attempts} attempt(s): {e!r}",
                )
            else:
                spec["attempts"] = attempts
                _requeue_or_drop(
                    claim,
                    note=f"transient on {marker_identity(spec, claimed)} "
                         f"(attempt {attempts}/{max_retries})",
                )
            continue
        finally:
            _discard_worktree_changes(paths.repo_root)
        if drained:
            with contextlib.suppress(OSError):
                claimed.unlink()


def _invoke_pitfalls(paths: LoopPaths, *, box: Any = None) -> int:
    _log("step=pitfalls-curation")
    rc = _run_curator_module(
        "pitfalls_curator", lambda mod: mod.run_pitfalls(paths=paths, box=box)
    )
    return rc if rc is not None else 0


def _retire_pitfalls_batch(paths: LoopPaths, batch_ids: list[str], e: Exception) -> None:
    _log(f"lead_author_drain: pitfalls curation error: {e!r}; discarding edits")
    if not batch_ids:
        return
    drain.retire(
        channel=paths.pitfalls,
        batch_ids=batch_ids,
        # `batch-error:<class>`, not `str(e)` (#870 FK-11): two writers append to one
        # `pitfalls.deadletter.jsonl`, and a raw exception message beside
        # `_graveyard_dropped_rows`' three named classes leaves a human triaging that file
        # with three classes and a traceback string. This is the shape a REDUCER row most
        # plausibly gets — its system is neither missing nor malformed nor undeclared, it is
        # `""` by design — so the class name is what keeps the vocabulary closed at four.
        reason=f"batch-error:{type(e).__name__}",
        max_attempts=author_max_attempts(),
    )


def _drain_pitfalls(
    paths: LoopPaths,
    run_pitfalls: Callable[..., int],
    *,
    box: Any = None,
) -> None:
    # "The batch" is the id set fixed at THIS read, before the leg runs — a pitfall
    # appended while the curation was in flight is outside it and must not be bumped.
    batch_ids = [str(r["pitfall_id"]) for r in read_pitfalls(paths) if r.get("pitfall_id")]
    try:
        run_or_dead_letter(
            lambda: run_pitfalls(paths, box=box),
            functools.partial(_retire_pitfalls_batch, paths, batch_ids),
        )
    finally:
        _discard_worktree_changes(paths.repo_root)


def _drain_lead_author(
    paths: LoopPaths,
    run_lead_author: Callable[..., None],
    run_pitfalls: Callable[..., int],
    *,
    box: Any = None,
) -> None:
    _drain_lead_author_markers(paths, run_lead_author, box=box)
    _drain_pitfalls(paths, run_pitfalls, box=box)


def _validate_merge_mode() -> None:
    merge_mode()


# Trigger module → the LoopPaths attribute that already owns that curator's corpus dir. The
# directory NAMES live in `DefenderPaths` alone (`_paths.py`); re-spelling them here would let
# a rename there turn every drain box into an absent-bind-source create failure.
_CORPUS_ATTR_FOR_TRIGGER_MODULE = {
    "author_actor": "lessons_actor_dir",
    "author_actor_benign": "lessons_environment_dir",
    "author_actor_env": "lessons_environment_dir",
}


def _drain_triggered_corpora(paths: LoopPaths) -> tuple[Path, ...]:
    """R6 — decide-all-triggered before the box is created: the base lessons corpus is the
    one `author_drain`'s has_work gate always answers for (`_has_curator_work`'s primary
    check); the actor/environment siblings join only when THEIR own threshold independently
    fires. Evaluated once, before `_run_worktree_batch` composes the drain box's mount set —
    never a static union of all three (M1).

    Corpus dirs come off `paths`, so pass the WORKTREE-rooted LoopPaths: `with_repo_root`
    preserves `state_root`, so the queue counts are the same files either way."""
    triggered = [paths.lessons_dir]
    for direction in BY_NAME.values():
        for t in (direction.obs_trigger, *direction.extra_obs_triggers):
            threshold = env_int(t.threshold_env, 5)
            if _pending_queue_count(t.pending_file(paths)) >= threshold:
                attr = _CORPUS_ATTR_FOR_TRIGGER_MODULE.get(t.module_name)
                if attr is None:
                    continue
                corpus_dir = getattr(paths, attr)
                if corpus_dir not in triggered:
                    triggered.append(corpus_dir)
    return tuple(triggered)


def _drain_box_request(
    wt: Path, batch_id: str, label: str, paths: LoopPaths,
) -> box_mod.BoxRequest:
    """The drain box's geography (M1/S3/S4): infra ro over the whole worktree leaf (it carries
    `<wt>/defender` and is both drain roles' cwd_anchor), rw ONLY over what this batch actually
    needs — the triggered lesson corpora for `author_drain`, `<wt>/defender/skills` for
    `lead_author_drain` — never a static union (M1), never anything outside the leaf (S3)."""
    wt_paths = paths.with_repo_root(wt)
    mounts = [box_mod.Mount(source=wt, target=wt, writable=False)]
    if label == "lead_author_drain":
        rw_dirs: tuple[Path, ...] = (wt_paths.skills_dir,)
    else:
        rw_dirs = _drain_triggered_corpora(wt_paths)
    for d in rw_dirs:
        mounts.append(box_mod.Mount(source=d, target=d, writable=True))
    return box_mod.BoxRequest(
        name=f"defender-drain-{batch_id}", mounts=tuple(mounts), workdir=wt, env={},
    )


def _run_worktree_batch(
    paths: LoopPaths,
    branch: AuthorBranch,
    *,
    label: str,
    has_work: Callable[[LoopPaths], bool],
    do_work: Callable[..., None],
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> int:
    if not has_work(paths):
        _log(f"{label}: nothing queued and no curator at threshold — skipping")
        return 0

    try:
        if branch.open_pr_exists():
            _log(f"{label}: an open {branch.branch_prefix} PR holds the writer lease — skipping")
            return 0
        batch_id = uuid.uuid4().hex[:12]
        wt = branch.start_batch(batch_id)
    except BranchError as e:
        _log(f"{label}: cannot start batch worktree: {e} — skipping")
        return 0

    # M1: the box is created after the worktree exists AND after the threshold checks that
    # decide which curators wake, over exactly this batch's needs — never a static union. A
    # startup fault here unwinds the worktree/branch resources already minted (M1 consequence).
    try:
        box = start_box(_drain_box_request(wt, batch_id, label, paths))
    except BaseException:
        with contextlib.suppress(Exception):
            branch.cleanup(wt)
        raise

    wt_paths = paths.with_repo_root(wt)
    pr = None
    try:
        # O7/S7 (#741): the box is torn down and the written tree scanned on ANY exit from
        # do_work, ordinary or exceptional. Both halves live in `stop_and_scrub`, which owns
        # the ordering (teardown first — the rw bind must be released before the walk, or the
        # scan races a live writer), the only-scrub-a-provably-dead-box rule, and the
        # exception preference. The scan lands BEFORE finish_batch's commit+push+PR
        # supply-chain step ever reads the tree (decision 8); a failed teardown blocks both
        # the scan and finish_batch (R2).
        work_ok = False
        try:
            do_work(wt_paths, box=box)
            work_ok = True
        finally:
            box_mod.stop_and_scrub(
                box, wt, stop_box=stop_box, scrub_tree=scrub, in_flight=not work_ok,
            )
        try:
            pr = branch.finish_batch(batch_id, wt)
        except BranchError as e:
            _log(f"{label}: finish_batch failed: {e} — work stays queued, retry next tick")
    except box_mod.RunTainted as taint:
        # #747: the `finally` below destroys this tree, and on the taint path it is the ONLY
        # copy — the scrub raises before finish_batch, so nothing was ever committed or
        # pushed (decision 8), and the curator's edits plus whatever the box planted exist
        # nowhere else. `box.py` lets a taint outrank the work's own failure on the grounds
        # that the crash-path tree "is the one a human then opens by hand"; without this
        # handler that justification was false here, because the tree was gone before anyone
        # read the traceback.
        #
        # An except clause rather than a check inside the `finally`: handlers run BEFORE the
        # finally, which is exactly the ordering needed, and the intent reads off the
        # structure. The re-raise is load-bearing — preserving the tree must not swallow the
        # signal that it is tainted.
        preserve_tainted_tree(
            wt, branch.quarantine_dir,
            batch_id=batch_id, branch=branch.branch_name(batch_id), label=label, taint=taint,
        )
        raise
    finally:
        # A cleanup failure leaves a worktree that is both possibly-tainted and, if do_work
        # raised before the scan could clear it, never walked. Suppressed so it cannot mask
        # the real failure, but never silent — that silence was the whole residue #741 named.
        # The git-level failure is logged where it is SWALLOWED (`AuthorBranch.cleanup` runs
        # `git worktree remove` under its own suppression, so it never reaches this handler);
        # this catch is the backstop for everything else a cleanup implementation can raise.
        try:
            branch.cleanup(wt)
        except Exception as e:  # noqa: BLE001 — best-effort cleanup; the real fault outranks it
            _log(f"{label}: worktree cleanup failed: {e} — {wt} leaked, scrub state unknown")

    if pr is None:
        _log(f"{label}: batch produced no commits — no PR opened")
        return 0
    _log(f"{label}: opened PR {pr}")
    if merge_mode() == "auto_on_green":
        _log(f"{label}: merge_mode=auto_on_green — green-bar auto-merge not yet "
             "wired (PR C); leaving PR for review")
    return 0


def _lead_author_pr_title(batch_id: str) -> str:
    return f"learning: lead-author catalog/skill batch {batch_id}"


def _lead_author_pr_body(branch: str) -> str:
    return (
        "Automated gather-catalog / system-skill curation from the lead-author drain "
        f"(branch `{branch}`, off freshly-fetched `origin/main`). May also fold "
        "agent-fixable execution failures into per-system `execution.md` "
        "`## Common pitfalls`. Touches `defender/skills/` only — distinct from the "
        "lessons PR."
    )


def author_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    # `(paths, pending_file, threshold_env, module_name, pending_label, *, box)` — `box=` is
    # threaded per call (R1), so the seam is not the old fixed 5-positional signature.
    trigger_author: Callable[..., None] | None = None,
    branch: AuthorBranch | None = None,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> int:
    _validate_merge_mode()
    if trigger_author is None:
        trigger_author = _maybe_trigger_author
    if branch is None:
        branch = AuthorBranch(repo_root=paths.repo_root)

    with _author_shared.flock_or_skip(paths.author_drain_lock_file) as locked:
        if not locked:
            _log("author_drain: another drainer holds the lock — exiting")
            return 0
        return _run_worktree_batch(
            paths, branch, label="author_drain",
            has_work=_has_curator_work,
            do_work=lambda wt_paths, *, box=None: _drain_curators(
                wt_paths, trigger_author, box=box
            ),
            start_box=start_box, stop_box=stop_box, scrub=scrub,
        )


def lead_author_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    run_lead_author: Callable[..., None] | None = None,
    run_pitfalls: Callable[..., int] | None = None,
    branch: AuthorBranch | None = None,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> int:
    _validate_merge_mode()
    if run_lead_author is None:
        run_lead_author = _invoke_lead_author
    if run_pitfalls is None:
        run_pitfalls = _invoke_pitfalls
    if branch is None:
        branch = AuthorBranch(
            repo_root=paths.repo_root,
            branch_prefix="lead-author/",
            pr_title=_lead_author_pr_title,
            pr_body=_lead_author_pr_body,
        )

    with _author_shared.flock_or_skip(paths.lead_author_drain_lock_file) as locked:
        if not locked:
            _log("lead_author_drain: another drainer holds the lock — exiting")
            return 0
        return _run_worktree_batch(
            paths, branch, label="lead_author_drain",
            has_work=_has_lead_author_work,
            do_work=lambda wt_paths, *, box=None: _drain_lead_author(
                wt_paths, run_lead_author, run_pitfalls, box=box
            ),
            start_box=start_box, stop_box=stop_box, scrub=scrub,
        )
