"""The lead-author: offline curation of the gather query catalog and the system skills.

  * `_handoff` — the queue lock, what a handoff contains, and dispatching the agent.
  * `_rules`   — the verification rules a produced edit has to survive before it lands.

This module is the drain itself: acquire the lock, build the handoffs, run, verify, commit.
"""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import functools
import logging
import string
import sys
from collections.abc import Callable, Mapping
from defender._model import model
from defender.records import Run, RunPaths
from pathlib import Path
from types import MappingProxyType
from typing import Any
from uuid import uuid4

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.knowledge import _corpus
from defender import _git
from defender.knowledge import _scaffold_rules
from defender._io import Held
from defender._untrusted import wrap
from defender.learning.core import config as _loop_config
from defender.learning.core.lane_trees import DrainTrees, TreeFor, open_drain_trees
from defender.learning.core import persist as _loop_persist
from defender.learning.core.state import LEAD_QUEUE_LOCK, TRY_ONCE, LearningState
from defender.learning._prompt import stage_user_message, structured_json_body
from defender.learning.leads import lead_neighbors
from defender.learning.author._config import GIT_TIMEOUT_SECONDS
from defender.learning.author.version_control import DeliveryRefused
from defender.learning.leads import lead_render
from defender import box as _box
from defender.runtime.verbs import engine_for

from defender.learning.leads.path_validation import (  # noqa: F401  (re-exported)
    CATALOG_PREFIX,
    LEARNING_DIR,
    REPO_ROOT,
    SKILLS_PREFIX,
    _draft_twin,
    _is_catalog_path,
    _is_catalog_template,
    _is_draft_readme,
    _is_in_scope,
    _is_schema_md,
    _is_system_file,
    _is_system_skill_draft,
    _is_system_skill_md,
    _under_draft,
)
from defender.learning.leads.draft_synthesis import (  # noqa: F401  (re-exported)
    _SAFE_ID_SEGMENT,
    _draft_basename,
    _draft_candidate_segments,
    _draft_skeleton,
    _executed_query,
    answered_identities,
    synthesize_drafts,
)
from defender.learning.leads.lead_extraction import (  # noqa: F401  (re-exported)
    _VALID_PAYLOAD_STATUSES,
    ExecutedLead,
    LeadAuthorError,
    collect_general_failures,
    extract,
    extract_from_joined,
)
from ._handoff import (
    LEAD_AUTHOR_PROMPT,
    QUEUE_LOCK_SKIP_RC,
    _DRAFT_README_NAMES,
    _draft_contradicts_skill,
    _lift_threshold,
    _templates_by_identity,
    build_handoff,
    build_system_draft_handoffs,
    discover_system_drafts,
    invoke_agent,
)
from ._rules import (
    _NO_MINTED,
    _answered_after_batch,
    _check_promoted_template,
    _covers_rule,
    _departed_drafts,
    _frontmatter_id,
    _loop_commit_message,
    _membership_segment,
    _minted_identities,
    _refuse,
    _refuse_half_promote,
    _refuse_lost_provenance,
    _repairs_the_id,
    _skills_content_rule,
    _skills_path_rule,
    _skills_rule,
    _template_at_head,
    _verify_skills_state,
)
from defender.learning.leads._lead_spine import (
    _loop_commit_body,
    _spawn_author_agent,
    _verify_corpus_scope,
    lane_skills,
)

_logger = logging.getLogger(__name__)


def _state_dir(run_dir: Path) -> Path:
    return RunPaths(run_dir).lead_author


def _done_sentinel(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "done"


def _write_state(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def done_sentinel_text(sha: str | None) -> str:
    """The body of the per-run `done` sentinel — the one producer of it.

    @owns done_sentinel — `commit: <sha|none>`, when it was written, and whether a commit was
    made. `at:` is when the run was recorded done, which under the drain is after the scrub."""
    return (
        f"commit: {sha or 'none'}\nat: {_loop_config.now_iso()}\n"
        f"commit_made: {sha is not None}\n"
    )


def write_done_sentinel(run_dir: Path, sha: str | None) -> None:
    """The one writer of `<run_dir>/lead_author/done`, which `_run_locked` short-circuits on.
    Under `on_done` the drain writes it only after the scrub, so a tainted batch's run is
    served again rather than recorded done. `run_dir` is the folder of the run the lead author
    was handed (an opened run's `run.run_dir`, #1105 PR 2)."""
    _write_state(_done_sentinel(run_dir), done_sentinel_text(sha))


#: Where a clean exit reports the run done: called with the commit sha (`None` for a run
#: recorded done with no commit). The default sink writes the sentinel under the run dir.
DoneSink = Callable[[str | None], None]




@model(frozen=True)
class LeadAuthorDeps:
    #: The product checkout (`repo_root`: its adapters, #1172) and the learning state's
    #: spelling; never the lane's corpus, which is `root`'s (#1108 P4 OD16).
    paths: _loop_config.LoopPaths
    #: The learning state handle: the queue lock and the pitfalls queue are reached through it.
    state: LearningState
    #: The declared systems (adapter glob ∪ committed marker), resolved once before the agent
    #: is spawned and never re-derived by a consumer.
    systems: frozenset[str]
    invoke_agent: Callable[..., int]
    extract: Callable[[Path], tuple[list, list[ExecutedLead]]]
    synthesize: Callable[..., list[Path]]
    build_handoff: Callable[..., list[dict]]
    discover_system_drafts: Callable[[], list[Path]]
    #: The lane's held `skills/` mount (`lane_skills`): every host read and write of the catalog
    #: and the system skills goes through it or its view (#1134). Lives only as long as the
    #: `DrainTrees` it came from.
    skills: Held
    #: The lane's `DrainTrees.tree_for`, for the post-agent rules, which hold repo-relative
    #: `agent/skills/...` names under `root`.
    tree_for: TreeFor
    #: The tree the lane's repo-relative names are under: the batch's draft root (holding the
    #: `agent/` its box writes), or `paths.repo_root` for deps built with no batch.
    root: Path
    #: The lane's `skills/` folder, spelled as the held mount `skills` is: `root/agent/skills`
    #: for a batch, `paths.skills_dir` without one.
    skills_dir: Path
    #: The tick's batch (P3's `Batch`): its claim (`change_set`), its base, its commit-maker and
    #: its per-claim reset. `None` for deps built over a bare tree, which cannot commit.
    batch: Any = None
    #: Kept for the drain's call shape; the lane runs no git (#1108 P4 O7).
    git_timeout: float = GIT_TIMEOUT_SECONDS


def build_lead_author_deps(
    paths: _loop_config.LoopPaths, *, state: LearningState, trees: DrainTrees,
    batch: Any = None, git_timeout: float = GIT_TIMEOUT_SECONDS,
) -> LeadAuthorDeps:
    """The lane's seams over `batch`'s draft (#1108 P4 O7, OD16), reading and writing `skills/`
    through `trees`, the lane's held mounts (`open_drain_trees`): `trees` must hold the draft's
    `agent/skills` itself (`paths.skills_dir` with no batch), else `LeadAuthorError`. `paths`
    names the product checkout, whose adapters declare the systems with the markers the
    batch's base commits. The deps must not outlive `trees`."""
    from defender.learning.leads.declared_systems import declared_systems

    if batch is not None:
        root = Path(batch.draft_root)
        skills_dir = root / SKILLS_PREFIX
        base = batch.base()
    else:
        root, skills_dir, base = paths.repo_root, paths.skills_dir, None
    skills = lane_skills(trees, paths, skills_dir=skills_dir)
    systems = declared_systems(paths.repo_root, agent=base)
    return LeadAuthorDeps(
        paths=paths,
        state=state,
        systems=systems,
        invoke_agent=functools.partial(invoke_agent, repo_root=root),
        extract=extract,
        synthesize=synthesize_drafts,
        build_handoff=functools.partial(
            build_handoff, repo_root=root, skills=skills.view(), where=skills_dir,
        ),
        discover_system_drafts=functools.partial(
            discover_system_drafts, skills=skills.view(), where=skills_dir, systems=systems,
        ),
        skills=skills,
        tree_for=trees.tree_for,
        root=root,
        skills_dir=skills_dir,
        batch=batch,
        git_timeout=git_timeout,
    )


def run(  # noqa: PLR0913 — the by-hand entry: the run, its lane, and each seam it may be handed
    run: Run,
    *,
    label: _loop_config.DrainLabel,
    paths: _loop_config.LoopPaths | None = None,
    state: LearningState | None = None,
    batch: Any = None,
    deps: LeadAuthorDeps | None = None,
    box: Any = None,
    on_done: DoneSink | None = None,
) -> int:
    """Serve one run under the per-author queue lock, over `batch`'s draft (`deps.batch` when
    deps are given)."""
    if deps is None and paths is None:
        raise TypeError("run takes paths= (or deps=)")
    # The lane's grant is read before anything else: a non-member label never reaches the
    # queue lock (#1179).
    lane_batch = getattr(deps, "batch", None) if deps is not None else batch
    writable = (
        label.draft_trees(lane_batch) if lane_batch is not None
        else label.writable_trees(deps.paths if deps is not None else paths)  # type: ignore[arg-type]
    )
    run_dir = Path(run.run_dir)
    sink = on_done if on_done is not None else functools.partial(write_done_sentinel, run_dir)

    # Take the lock before building `deps`: resolving membership is subprocess work, and a
    # tick about to skip on a contended lock should neither pay for it nor fail on a tree the
    # resolver can't read yet.
    if deps is not None:
        skills_dir = getattr(deps, "skills_dir", None) or deps.paths.skills_dir
        if skills_dir not in writable:
            raise LeadAuthorError(
                f"refused: the {str(label)!r} lane does not mount {skills_dir}"
            )
        with deps.state.lock(LEAD_QUEUE_LOCK, wait=TRY_ONCE) as locked:
            if not locked:
                return QUEUE_LOCK_SKIP_RC
            return _run_locked(run_dir, deps, box=box, on_done=sink)

    assert paths is not None  # the guard above: without `deps`, `paths` is required
    with contextlib.ExitStack() as owned:
        if state is None:
            state = owned.enter_context(LearningState.open(paths))
        with state.lock(LEAD_QUEUE_LOCK, wait=TRY_ONCE) as locked:
            if not locked:
                return QUEUE_LOCK_SKIP_RC
            with open_drain_trees(paths, label, batch=batch) as trees:
                deps = build_lead_author_deps(paths, state=state, trees=trees, batch=batch)
                return _run_locked(run_dir, deps, box=box, on_done=sink)


def run_under_held_queue_lock(  # noqa: PLR0913 — the drain's call shape: the run, its held lock and trees, and its seams
    run: Run, *, paths: _loop_config.LoopPaths, state: LearningState, trees: DrainTrees,
    box: Any = None, on_done: DoneSink, git_timeout: float = GIT_TIMEOUT_SECONDS,
    batch: Any = None, deps: LeadAuthorDeps | None = None,
) -> int:
    """`run` for a caller that already holds the per-author queue lock (the drain holds it for
    its whole tick, since it defers the done sentinel) and the lane's held mounts, `trees` (the
    drain's work step opens them over `batch`'s draft). Never skips. `run` is the run the drain
    opened from the claim's address; `deps` given are used as built, else they are built over
    `batch`."""
    if deps is None:
        deps = build_lead_author_deps(paths, state=state, trees=trees, batch=batch,
                                      git_timeout=git_timeout)
    return _run_locked(Path(run.run_dir), deps, box=box, on_done=on_done)


def _run_locked(
    run_dir: Path, deps: LeadAuthorDeps, *, box: Any = None, on_done: DoneSink,
) -> int:
    if _done_sentinel(run_dir).is_file():
        _logger.info("already processed (done sentinel exists) — nothing to do")
        return 0

    if not deps.systems:
        # An empty declared set would refuse every path one by one and report a clean no-op;
        # refuse loudly before spawning instead.
        raise LeadAuthorError(
            f"lead-author refused: {deps.paths.repo_root} declares no systems (empty "
            "adapter glob and no committed execution.md in the tenant's agent/skills); "
            "refusing to run the lane"
        )

    try:
        joined_leads, executed = deps.extract(run_dir)
    except (FileNotFoundError, ValueError) as e:
        _logger.critical(f"cannot extract leads: {e}")
        return 2

    skills_dir = deps.skills_dir
    catalog = lead_neighbors.load_lane_catalog(deps.skills.view(), where=skills_dir)

    synth = deps.synthesize(
        executed, skills=deps.skills, where=skills_dir, catalog=catalog, systems=deps.systems,
    )
    if synth:
        _logger.info(
            f"synthesized {len(synth)} draft(s) for uncatalogued verbs: "
            + ", ".join(p.name for p in synth)
        )
    # Captured before the agent runs: these drafts are in no base, so if the agent removes one
    # nothing else records the identities it held.
    minted = _minted_identities(deps.skills.view(), synth, where=skills_dir)

    collected_marker = _state_dir(run_dir) / "pitfalls_collected"
    if not collected_marker.is_file():
        failures = collect_general_failures(executed, run_dir, catalog=catalog)
        if failures:
            _loop_persist.append_pitfalls(failures, state=deps.state)
            # Both numbers: a large gap between failures and this run's distinct mistakes
            # signals a looping lead. (The curation threshold merges across the whole queue.)
            distinct = len(_loop_persist.merge_pitfalls(failures))
            _logger.info(
                f"collected {len(failures)} general failure(s) into the queue "
                f"({distinct} distinct mistake(s) in this run)"
            )
        _write_state(collected_marker, _loop_config.now_iso() + "\n")

    if synth:
        catalog = lead_neighbors.load_lane_catalog(deps.skills.view(), where=skills_dir)
    handoffs, pending_drafts, rc = _prepare_handoffs(
        run_dir, deps, executed, joined_leads, catalog=catalog, on_done=on_done,
    )
    if rc is not None:
        return rc
    _logger.info(
        f"built {len(handoffs)} executed-template handoff(s) and "
        f"{len(pending_drafts)} pending system-skill draft(s)"
    )

    rc, sha = _spawn_and_commit(run_dir, deps, handoffs, pending_drafts, minted, box=box)
    if rc != 0:
        return rc
    on_done(sha)
    _logger.info(f"done; commit_made={sha is not None} commit={(sha or 'none')[:12]}")
    return 0


def _spawn_and_commit(  # noqa: PLR0913 — one claim: its run, deps, the two handoff lists, the mint, the box
    run_dir: Path, deps: LeadAuthorDeps, handoffs: list, pending_drafts: list,
    minted: Mapping[Path, tuple[str, ...]], *, box: Any,
) -> tuple[int, str | None]:
    """Spawn the agent, then commit the claim it left: `(0, commit or None)`, or `(2, None)`
    when the spawn failed. The box runs for the spawn only, and is stopped before the gate
    reads what it wrote (#1195). A failed claim — the spawn's non-zero exit, a gate rejection,
    a commit-maker refusal — is reset out of the draft, which is left at the batch's base
    (#1108 P4 O7, U10); a systemic fault propagates as it is, the drain discarding the draft."""
    try:
        with _box.box_for_run(box) as run_box:
            rc = deps.invoke_agent(run_dir, handoffs, pending_drafts, box=run_box)
        if rc != 0:
            _logger.critical(f"lead-author spawn exited rc={rc}; see the trace under {run_dir} (drain will quarantine)")
            if deps.batch is not None:
                deps.batch.reset()
            return 2, None
        return 0, _commit_claim(run_dir, deps, minted)
    except (LeadAuthorError, DeliveryRefused) as fault:
        if deps.batch is not None:
            _reset_after(deps.batch, fault)
        raise


def _reset_after(batch: Any, fault: BaseException) -> None:
    """Reset the claim out of the draft after `fault`, which a failed reset never displaces:
    it is logged, and the drain's own per-claim reset is the next to try (#1108 P4 O7)."""
    try:
        batch.reset()
    except Exception as unreset:  # noqa: BLE001 — never replaces the claim's own fault
        _logger.error(f"the claim's draft was NOT reset: {unreset!r} (the claim's fault: {fault!r})")


def _commit_claim(
    run_dir: Path, deps: LeadAuthorDeps, minted: Mapping[Path, tuple[str, ...]],
) -> str | None:
    """The claim — the draft against the batch's base, derived before anything reads what the
    box wrote (a link, FIFO or out-of-lane entry refuses it whole, `DeliveryRefused`) — judged
    by the gate and committed by the batch's commit-maker; `None` when the spawn changed
    nothing. Deps naming no batch have nowhere to commit, and refuse."""
    batch = deps.batch
    if batch is None:
        raise LeadAuthorError(
            "lead-author refused: these deps name no batch, and the lane commits only into a "
            "tenant batch's draft (#1108 P4) — nothing is committed"
        )
    change_set = batch.change_set()
    changed = _verify_skills_state(
        deps.root, change_set=change_set, systems=deps.systems, minted=minted,
        tree_for=deps.tree_for, base=batch.base(), defender_dir=deps.paths.defender_dir,
    )
    if not changed:
        return None
    return batch.commit(change_set, _loop_commit_message(run_dir, changed))


def _prepare_handoffs(
    run_dir: Path, deps: LeadAuthorDeps,
    executed: list | None = None, joined_leads: list | None = None,
    *, catalog: list | None = None, on_done: DoneSink | None = None,
) -> tuple[list, list, int | None]:
    # Optional only for tests that drive this frame directly; `_run_locked` always passes it.
    record_done = on_done if on_done is not None else functools.partial(write_done_sentinel, run_dir)
    pending_drafts_raw = deps.discover_system_drafts()
    threshold = _lift_threshold()
    contradicting = [
        d for d in pending_drafts_raw
        if _draft_contradicts_skill(deps.skills.view(), d, where=deps.skills_dir)
    ]
    if len(pending_drafts_raw) < threshold and not contradicting:
        if pending_drafts_raw:
            _logger.info(
                f"lift queue below threshold "
                f"(n={len(pending_drafts_raw)}, threshold={threshold}) — "
                "skipping lift"
            )
        pending_drafts: list[dict] = []
    else:
        if contradicting and len(pending_drafts_raw) < threshold:
            _logger.info(
                f"lift queue below threshold (n={len(pending_drafts_raw)}, "
                f"threshold={threshold}) but {len(contradicting)} draft(s) contradict "
                "shipped SKILL.md content — bypassing threshold"
            )
        pending_drafts = build_system_draft_handoffs(pending_drafts_raw, repo_root=deps.root)

    if executed is None:
        try:
            joined_leads, executed = deps.extract(run_dir)
        except (FileNotFoundError, ValueError) as e:
            _logger.critical(f"cannot extract leads: {e}")
            return [], [], 2

    if not executed:
        if not pending_drafts:
            _logger.info("no executed leads and no pending drafts — nothing to do")
            return [], [], 0
        _logger.info(
            "no executed leads with on-disk payloads — proceeding with "
            f"{len(pending_drafts)} pending system-skill draft(s) only"
        )
        return [], pending_drafts, None

    try:
        handoffs = deps.build_handoff(run_dir, executed, joined_leads, catalog=catalog)
    except LeadAuthorError as e:
        _logger.critical(f"cannot build handoffs: {e}")
        return [], [], 2

    if not handoffs and not pending_drafts:
        _logger.info(
            f"none of the {len(executed)} extracted lead(s) resolved to a catalog "
            "template (unresolved query_id, or a `∅.` sentinel routed to the pitfalls "
            "residue) and there are no pending drafts — nothing to do"
        )
        record_done(None)
        return [], [], 0

    return handoffs, pending_drafts, None




#: Substituted at the parser with the owner's record names — a template rather than a
#: module-level f-string, so the prompt-frame lint doesn't read it as a prompt boundary.
#:
#: `string.Template`, not `str.format`: path placeholders like `{system}` in this prose would
#: raise `KeyError` at `--help`, while `safe_substitute` leaves an unknown `$x` as written.
_HELP_EPILOG = string.Template("""\
The agent runs no git; the loop commits. Invoked directly this commits onto the
current branch/worktree's HEAD — in production the lead-author drain
(``loop.py --lead-author-drain``) runs it inside a fresh ``lead-author/<id>``
worktree and opens the PR.

Preconditions
  * No other lead-author tick may be running (per-author queue lock at
    _pending_leads/.lock under the learning state root, held by the drain for its whole tick —
    serve, pitfalls curation, scrub, push, PR). Violating it is not silent: this
    returns rc=3 without serving, and a drain tick that finds the lock held skips
    before claiming any request rather than counting the skip as a serve.
  * ``<run_dir>/$EXECUTED_QUERIES`` and ``<run_dir>/$RAW_MARKER/``
    (the two tables) must exist — written live during the run by
    record_query.py + record_lead.py.

State files written under ``<run_dir>/$LEAD_AUTHOR_DIRNAME/``
  done           sentinel on successful completion; makes the run a no-op. Written
                 here at once when invoked by hand; under the drain, only once the
                 batch's tree has passed the scrub (its commit is then on a local
                 branch the drain delivers, retrying the push and PR on later ticks
                 without re-serving anything).

On a per-run fault this returns rc=2 and the lead-author drain quarantines the run's
marker to the author-queue's ``failed/`` dir (surfaced for a human, not dropped); the
per-spawn RequestLogger trace under the run dir is the diagnostic. (A systemic config
fault — no key / unroutable model / bad effort — propagates from the in-process engine
as exit 2 instead, halting the drain rather than quarantining every marker.)

Environment
  LEAD_AUTHOR_MODEL                          in-process model id (default glm-5.3; any
                                             provider providers.provider_for routes)
  LEAD_AUTHOR_EFFORT                          reasoning effort (default medium)
  LEAD_AUTHOR_TIMEOUT_SECONDS                per-spawn wall-clock ceiling (default 1800)
  LEAD_AUTHOR_REQUEST_LIMIT                   tool-loop request cap (default 250)
  LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD        min pending-draft count to fire the
                                             system-skill lift queue (default 5)
""")


def _record_names() -> dict[str, str]:
    """The record names this help text shows, asked of `RunPaths` at call time so a rename
    there reaches the help text with nothing to update here."""
    names = RunPaths(Path("<run_dir>"))
    return {
        "EXECUTED_QUERIES": names.executed_queries.name,
        "RAW_MARKER": names.gather_raw.name,
        "LEAD_AUTHOR_DIRNAME": names.lead_author.name,
    }


def main(argv: list[str]) -> int:
    names = _record_names()
    p = argparse.ArgumentParser(
        prog="lead_author",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
        description="Fold lessons from one defender run into the executed-side "
                    "query template catalog.",
        epilog=_HELP_EPILOG.safe_substitute(names),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--tenant", required=True,
                   help="the tenant whose run is served; required, with no default")
    p.add_argument("run_id",
                   help=f"the defender run, by its id — its folder holds "
                        f"{names['EXECUTED_QUERIES']} + {names['RAW_MARKER']}/")
    args = p.parse_args(argv)
    from defender.tenancy._command_line_run import open_command_line_run

    # The request's tenant, accepted under the configured data root, and its run opened by id
    # through that tenant's repository (a link at the run's name is never followed). A refusal
    # is printed, not logged: a log level must never hide it.
    opened = open_command_line_run(args.tenant, args.run_id)
    if isinstance(opened, str):
        print(f"lead_author: {opened}", file=sys.stderr)  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
        return 2
    # By hand this serves the lead-author lane's own queue under its lock, so it names that lane.
    tenant, run_ = opened
    return run(run_, label=_loop_config.LEAD_AUTHOR_DRAIN_LABEL,
               paths=_loop_config.LoopPaths.for_tenant(tenant))


#: Re-exports: callers import these names from here; their real homes are the source
#: modules.
__all__ = [
    "Any",
    "CATALOG_PREFIX",
    "Callable",
    "DoneSink",
    "ExecutedLead",
    "LEAD_AUTHOR_PROMPT",
    "LEARNING_DIR",
    "LeadAuthorDeps",
    "LeadAuthorError",
    "Mapping",
    "MappingProxyType",
    "Path",
    "QUEUE_LOCK_SKIP_RC",
    "REPO_ROOT",
    "SKILLS_PREFIX",
    "_DRAFT_README_NAMES",
    "_NO_MINTED",
    "_SAFE_ID_SEGMENT",
    "_VALID_PAYLOAD_STATUSES",
    "_answered_after_batch",
    "_check_promoted_template",
    "_corpus",
    "_covers_rule",
    "_departed_drafts",
    "_done_sentinel",
    "_draft_basename",
    "_draft_candidate_segments",
    "_draft_contradicts_skill",
    "_draft_skeleton",
    "_draft_twin",
    "_executed_query",
    "_frontmatter_id",
    "_git",
    "_is_catalog_path",
    "_is_catalog_template",
    "_is_draft_readme",
    "_is_in_scope",
    "_is_schema_md",
    "_is_system_file",
    "_is_system_skill_draft",
    "_is_system_skill_md",
    "_lift_threshold",
    "_loop_commit_body",
    "_loop_commit_message",
    "_loop_config",
    "_loop_persist",
    "_membership_segment",
    "_minted_identities",
    "_prepare_handoffs",
    "_refuse",
    "_refuse_half_promote",
    "_refuse_lost_provenance",
    "_repairs_the_id",
    "_run_locked",
    "_scaffold_rules",
    "_skills_content_rule",
    "_skills_path_rule",
    "_skills_rule",
    "_spawn_author_agent",
    "_state_dir",
    "_template_at_head",
    "_templates_by_identity",
    "_under_draft",
    "_verify_corpus_scope",
    "_verify_skills_state",
    "_write_state",
    "done_sentinel_text",
    "answered_identities",
    "argparse",
    "build_handoff",
    "build_lead_author_deps",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    "build_system_draft_handoffs",
    "collect_general_failures",
    "dataclass",
    "discover_system_drafts",
    "engine_for",
    "extract",
    "extract_from_joined",
    "functools",
    "invoke_agent",
    "lead_neighbors",
    "lead_render",
    "main",
    "write_done_sentinel",
    "run",
    "run_under_held_queue_lock",
    "stage_user_message",
    "structured_json_body",
    "synthesize_drafts",
    "sys",
    "uuid4",
    "wrap",
]
