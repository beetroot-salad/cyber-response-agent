"""The lead-author: offline curation of the gather query catalog and the system skills.

Split into two modules when this file reached 1017 lines:

  * `_handoff` — the queue lock, what a handoff contains, and dispatching the agent.
  * `_rules`   — the verification rules a produced edit has to survive before it is
                    allowed to land.

What stays here is the drain itself: acquire the lock, build the handoffs, run, verify,
commit.
"""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import functools
import string
import sys
from collections.abc import Callable, Mapping
from defender._model import model
from defender._run_paths import RunPaths
from pathlib import Path
from types import MappingProxyType
from typing import Any
from uuid import uuid4

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import shared as _author_shared
from defender import _corpus
from defender import _git
from defender import _scaffold_rules
from defender._untrusted import wrap
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist
from defender.learning._prompt import stage_user_message, structured_json_body
from defender.learning.leads import lead_neighbors
from defender.learning.leads import lead_render
from defender.runtime.verbs import engine_for

from defender.learning.leads.path_validation import (  # noqa: F401  (re-exported)
    CATALOG_DIR,
    CATALOG_REL,
    LEARNING_DIR,
    REPO_ROOT,
    SKILLS_DIR,
    SKILLS_REL,
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
    QUEUE_LOCK_FILE,
    QUEUE_LOCK_SKIP_RC,
    _DRAFT_README_NAMES,
    _draft_contradicts_skill,
    _lift_threshold,
    _templates_by_identity,
    acquire_queue_lock,
    build_handoff,
    build_system_draft_handoffs,
    discover_system_drafts,
    invoke_agent,
    queue_lock_file,
    release_queue_lock,
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
    PENDING_DIR,
    _log,
    _loop_commit_body,
    _spawn_author_agent,
    _verify_corpus_scope,
)


def _state_dir(run_dir: Path) -> Path:
    return RunPaths(run_dir).lead_author


def _done_sentinel(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "done"


def _write_state(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def done_sentinel_text(sha: str | None) -> str:
    """The body of the per-run `done` sentinel — the one producer of it.

    @owns done_sentinel — `commit: <sha|none>`, the time it was WRITTEN, and whether a commit
    was made. Rendered by `write_done_sentinel` alone, so `at:` is when the run was recorded
    done however it was served — by hand at once, or by the drain once its batch had passed
    the scrub (#952)."""
    return (
        f"commit: {sha or 'none'}\nat: {_loop_config.now_iso()}\n"
        f"commit_made: {sha is not None}\n"
    )


def write_done_sentinel(run_dir: Path, sha: str | None) -> None:
    """The one writer of `<run_dir>/lead_author/done` — the file `_run_locked` short-circuits
    on. `run` writes it itself by default; under `on_done` the drain writes it here once the
    batch's tree passed the scrub (#952), so a run whose batch was tainted is served again
    next tick instead of being recorded as done."""
    _write_state(_done_sentinel(run_dir), done_sentinel_text(sha))


#: Where a clean exit reports the run done: called with the commit sha (`None` for a run
#: recorded done with no commit). The default sink writes the sentinel under the run dir.
DoneSink = Callable[[str | None], None]




@model(frozen=True)
class LeadAuthorDeps:
    paths: _loop_config.LoopPaths
    #: The UNION (adapter glob ∪ committed marker) resolved ONCE at the boundary — before the
    #: agent is ever spawned — and threaded non-Optional into every path-composition consumer
    #: on this lane. Never re-derived by a consumer.
    systems: frozenset[str]
    invoke_agent: Callable[..., int]
    extract: Callable[[Path], tuple[list, list[ExecutedLead]]]
    synthesize: Callable[..., list[Path]]
    build_handoff: Callable[..., list[dict]]
    discover_system_drafts: Callable[[], list[Path]]
    acquire_queue_lock: Callable[[], Any]
    release_queue_lock: Callable[[Any], None]


def build_lead_author_deps(
    paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS,
) -> LeadAuthorDeps:
    from defender.learning.leads.declared_systems import declared_systems

    systems = declared_systems(paths.repo_root)
    return LeadAuthorDeps(
        paths=paths,
        systems=systems,
        invoke_agent=functools.partial(invoke_agent, repo_root=paths.repo_root),
        extract=extract,
        synthesize=synthesize_drafts,
        build_handoff=functools.partial(
            build_handoff, repo_root=paths.repo_root, catalog_dir=paths.catalog_dir
        ),
        discover_system_drafts=functools.partial(
            discover_system_drafts, skills_dir=paths.skills_dir, systems=systems
        ),
        acquire_queue_lock=functools.partial(acquire_queue_lock, paths),
        release_queue_lock=release_queue_lock,
    )


def run(
    run_dir: Path,
    *,
    paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS,
    deps: LeadAuthorDeps | None = None,
    box: Any = None,
    on_done: DoneSink | None = None,
) -> int:
    """Serve one run under the per-author queue lock. `on_done` is the consumption switch
    (#952 M4): left `None`, a clean exit writes the `done` sentinel under the run dir at once
    — the CLI's contract; given, the commit sha is handed to the callable instead and nothing
    is written under the run dir, so the drain can record the run as done only once its
    batch has passed the scrub. The `pitfalls_collected` marker and the pitfalls rows are
    written either way — they are facts about the run, not about a commit."""
    if not run_dir.is_dir():
        _log(f"FATAL: run_dir not found: {run_dir}")
        return 2
    # Resolved ONCE, here at the boundary; every write site below takes the sink as given.
    sink = on_done if on_done is not None else functools.partial(write_done_sentinel, run_dir)

    # The lock is checked BEFORE `deps` is built when the caller supplied none: resolving
    # membership is real subprocess work, and a tick about to skip on a contended lock should
    # not pay for it, nor fail hard on a tree the resolver cannot yet read — a skip must never
    # present as anything but the skip rc.
    if deps is not None:
        queue_lock = deps.acquire_queue_lock()
        if queue_lock is None:
            return QUEUE_LOCK_SKIP_RC
        try:
            return _run_locked(run_dir, deps, box=box, on_done=sink)
        finally:
            deps.release_queue_lock(queue_lock)

    queue_lock = acquire_queue_lock(paths)
    if queue_lock is None:
        return QUEUE_LOCK_SKIP_RC
    try:
        deps = build_lead_author_deps(paths)
        return _run_locked(run_dir, deps, box=box, on_done=sink)
    finally:
        release_queue_lock(queue_lock)


def run_under_held_queue_lock(
    run_dir: Path, *, paths: _loop_config.LoopPaths, box: Any = None, on_done: DoneSink,
) -> int:
    """`run` for a caller that ALREADY holds the per-author queue lock — the drain, which
    takes it once around its whole tick (#952 M5) because the sentinel it defers is what
    `_run_locked` short-circuits on, and a by-hand run in the gap would otherwise re-serve
    the run. Never skips: the lock is the caller's, so there is nothing to contend on."""
    if not run_dir.is_dir():
        _log(f"FATAL: run_dir not found: {run_dir}")
        return 2
    return _run_locked(run_dir, build_lead_author_deps(paths), box=box, on_done=on_done)


def _run_locked(
    run_dir: Path, deps: LeadAuthorDeps, *, box: Any = None, on_done: DoneSink,
) -> int:
    if _done_sentinel(run_dir).is_file():
        _log("already processed (done sentinel exists) — nothing to do")
        return 0

    if not deps.systems:
        # An empty declared set is not spendable as an ordinary membership "no": that would
        # refuse every path one at a time and the tick would report a clean no-op. Refused
        # loudly instead, before the agent is ever spawned.
        raise LeadAuthorError(
            f"lead-author refused: {deps.paths.repo_root} declares no systems (empty "
            "adapter glob and no committed execution.md); refusing to run the lane"
        )

    try:
        joined_leads, executed = deps.extract(run_dir)
    except (FileNotFoundError, ValueError) as e:
        _log(f"FATAL: cannot extract leads: {e}")
        return 2

    catalog = lead_neighbors.load_catalog(deps.paths.catalog_dir)

    synth = deps.synthesize(
        executed, catalog_dir=deps.paths.catalog_dir, catalog=catalog, systems=deps.systems,
    )
    if synth:
        _log(
            f"synthesized {len(synth)} draft(s) for uncatalogued verbs: "
            + ", ".join(p.name for p in synth)
        )
    # Captured between the mint and the agent: these drafts are UNTRACKED, so if the agent
    # removes one the commit gate has neither a `git status` record nor a HEAD pre-image to
    # recover the identities it recorded (`_departed_drafts`).
    minted = _minted_identities(synth)

    collected_marker = _state_dir(run_dir) / "pitfalls_collected"
    if not collected_marker.is_file():
        failures = collect_general_failures(
            executed, run_dir, catalog_dir=deps.paths.catalog_dir, catalog=catalog
        )
        if failures:
            _loop_persist.append_pitfalls(failures, paths=deps.paths)
            # Both numbers: the failures are what the run did, the distinct count is how many
            # mistakes THIS RUN made once its repeats collapse — not what the curation
            # threshold will see, which merges this run's rows against every row already
            # queued. A lead that loops makes the gap large, and that gap is the signal.
            distinct = len(_loop_persist.merge_pitfalls(failures))
            _log(
                f"collected {len(failures)} general failure(s) into the queue "
                f"({distinct} distinct mistake(s) in this run)"
            )
        _write_state(collected_marker, _loop_config.now_iso() + "\n")

    repo_root = deps.paths.repo_root
    baseline_stray = _author_shared.changes_outside(repo_root, SKILLS_REL)

    if synth:
        catalog = lead_neighbors.load_catalog(deps.paths.catalog_dir)
    handoffs, pending_drafts, rc = _prepare_handoffs(
        run_dir, deps, executed, joined_leads, catalog=catalog, on_done=on_done,
    )
    if rc is not None:
        return rc
    _log(
        f"built {len(handoffs)} executed-template handoff(s) and "
        f"{len(pending_drafts)} pending system-skill draft(s)"
    )

    rc = deps.invoke_agent(run_dir, handoffs, pending_drafts, box=box)
    if rc != 0:
        _log(f"FATAL: lead-author spawn exited rc={rc}; see the trace under {run_dir} (drain will quarantine)")
        return 2

    changed = _verify_skills_state(
        repo_root, baseline_stray, systems=deps.systems, minted=minted
    )
    sha = _author_shared.commit_corpus(
        repo_root, repo_root / "defender" / "skills",
        _loop_commit_message(run_dir, changed),
    )
    on_done(sha)
    _log(f"done; commit_made={sha is not None} commit={(sha or 'none')[:12]}")
    return 0


def _prepare_handoffs(
    run_dir: Path, deps: LeadAuthorDeps,
    executed: list | None = None, joined_leads: list | None = None,
    *, catalog: list | None = None, on_done: DoneSink | None = None,
) -> tuple[list, list, int | None]:
    # Optional HERE ALONE, for the tests that drive this frame directly; `run` resolves the
    # sink once at its boundary and `_run_locked` always passes it.
    record_done = on_done if on_done is not None else functools.partial(write_done_sentinel, run_dir)
    pending_drafts_raw = deps.discover_system_drafts()
    threshold = _lift_threshold()
    contradicting = [d for d in pending_drafts_raw if _draft_contradicts_skill(d)]
    if len(pending_drafts_raw) < threshold and not contradicting:
        if pending_drafts_raw:
            _log(
                f"lift queue below threshold "
                f"(n={len(pending_drafts_raw)}, threshold={threshold}) — "
                "skipping lift"
            )
        pending_drafts: list[dict] = []
    else:
        if contradicting and len(pending_drafts_raw) < threshold:
            _log(
                f"lift queue below threshold (n={len(pending_drafts_raw)}, "
                f"threshold={threshold}) but {len(contradicting)} draft(s) contradict "
                "shipped SKILL.md content — bypassing threshold"
            )
        pending_drafts = build_system_draft_handoffs(
            pending_drafts_raw, repo_root=deps.paths.repo_root
        )

    if executed is None:
        try:
            joined_leads, executed = deps.extract(run_dir)
        except (FileNotFoundError, ValueError) as e:
            _log(f"FATAL: cannot extract leads: {e}")
            return [], [], 2

    if not executed:
        if not pending_drafts:
            _log("no executed leads and no pending drafts — nothing to do")
            return [], [], 0
        _log(
            "no executed leads with on-disk payloads — proceeding with "
            f"{len(pending_drafts)} pending system-skill draft(s) only"
        )
        return [], pending_drafts, None

    try:
        handoffs = deps.build_handoff(run_dir, executed, joined_leads, catalog=catalog)
    except LeadAuthorError as e:
        _log(f"FATAL: cannot build handoffs: {e}")
        return [], [], 2

    if not handoffs and not pending_drafts:
        _log(
            f"none of the {len(executed)} extracted lead(s) resolved to a catalog "
            "template (unresolved query_id, or a `∅.` sentinel routed to the pitfalls "
            "residue) and there are no pending drafts — nothing to do"
        )
        record_done(None)
        return [], [], 0

    return handoffs, pending_drafts, None




#: Substituted at the parser with the owner's record names (#1077 D1) — a template, not a
#: module-level f-string, so the prompt-frame lint does not read it as a prompt boundary.
#:
#: `string.Template`, NOT `str.format`. This is operator prose that names paths, and the two
#: spellings a path takes in this repo — `defender/skills/{system}/SKILL.md`, `{run_id}` — are
#: both braces. Under `.format` the first such edit raises `KeyError` at `--help`, i.e. only
#: once it is in an operator's hands and never in a test. `safe_substitute` cannot raise at
#: all: an unrecognized `$x` is left as written, so the failure mode is a visibly unsubstituted
#: word in help text rather than a dead command.
_HELP_EPILOG = string.Template("""\
The agent runs no git; the loop commits. Invoked directly this commits onto the
current branch/worktree's HEAD — in production the lead-author drain
(``loop.py --lead-author-drain``) runs it inside a fresh ``lead-author/<id>``
worktree and opens the PR.

Preconditions
  * No other lead-author tick may be running (per-author queue lock at
    defender/learning/_pending_leads/.lock, held by the drain for its whole tick —
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
    """The three record names this help text shows an operator, ASKED OF THE OWNER at call
    time rather than imported (#1077 D7). `.name` off an accessor built on a placeholder root
    is the only spelling this module ever sees, so a rename through the owner reaches the help
    text with nothing here to update — and there is no module-level copy for a rename to
    strand."""
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
    p.add_argument("run_dir", type=Path,
                   help=f"defender run dir containing {names['EXECUTED_QUERIES']} "
                        f"+ {names['RAW_MARKER']}/")
    args = p.parse_args(argv)
    return run(args.run_dir)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))


#: Everything imported above is a RE-EXPORT: the name's real home is the module it
#: comes from. Kept because a reader already imports it from here.
__all__ = [
    "Any",
    "CATALOG_DIR",
    "CATALOG_REL",
    "Callable",
    "DoneSink",
    "ExecutedLead",
    "LEAD_AUTHOR_PROMPT",
    "LEARNING_DIR",
    "LeadAuthorDeps",
    "LeadAuthorError",
    "Mapping",
    "MappingProxyType",
    "PENDING_DIR",
    "Path",
    "QUEUE_LOCK_FILE",
    "QUEUE_LOCK_SKIP_RC",
    "REPO_ROOT",
    "SKILLS_DIR",
    "SKILLS_REL",
    "_DRAFT_README_NAMES",
    "_NO_MINTED",
    "_SAFE_ID_SEGMENT",
    "_VALID_PAYLOAD_STATUSES",
    "_answered_after_batch",
    "_author_shared",
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
    "_log",
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
    "acquire_queue_lock",
    "done_sentinel_text",
    "queue_lock_file",
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
    "release_queue_lock",
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
