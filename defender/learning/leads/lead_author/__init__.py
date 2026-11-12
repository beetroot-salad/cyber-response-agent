"""The lead-author: offline curation of the gather query catalog and the system skills.

  * `_handoff` — what a handoff contains, and dispatching the agent.
  * `_rules`   — the verification rules a produced edit has to survive before it lands.

This module serves one claimed run: build the handoffs, run, verify, commit.
"""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import functools
import logging
import sys
from collections.abc import Callable, Mapping
from defender._model import model
from defender.records import Run, RunPaths
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _git
from defender._io import Held
from defender._untrusted import wrap
from defender.learning.core import config as _loop_config
from defender.learning.core.lane_trees import DrainTrees, TreeFor, open_drain_trees
from defender.learning.core import persist as _loop_persist
from defender.learning._prompt import stage_user_message, structured_json_body
from defender.learning.leads import lead_neighbors
from defender.learning.author._config import GIT_TIMEOUT_SECONDS
from defender.learning.author.version_control import DeliveryRefused
from defender.learning.leads import lead_render
from defender import box as _box
from defender.systems.verbs import engine_for

if TYPE_CHECKING:
    from defender.systems.catalog import Catalog, TenantSystems

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
    #: The product checkout (`repo_root`: its adapters, #1172); never the lane's corpus,
    #: which is `root`'s (#1108 P4 OD16).
    paths: _loop_config.LoopPaths
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
    #: Where the run files the pitfalls it collects: the learning store's pitfall items (#1278).
    #: `None`: the deps name nowhere to file them, and a run that collects some is refused.
    file_pitfalls: Callable[[list[dict]], int] | None = None


def build_lead_author_deps(  # noqa: PLR0913 — the lane's seams, plus where its pitfalls go and the tenant's systems
    paths: _loop_config.LoopPaths, *, trees: DrainTrees,
    batch: Any = None, git_timeout: float = GIT_TIMEOUT_SECONDS,
    file_pitfalls: Callable[[list[dict]], int] | None = None,
    make_model: Callable[..., Any] | None = None,
    systems: TenantSystems | Catalog,
) -> LeadAuthorDeps:
    """The lane's seams over `batch`'s draft (#1108 P4 O7, OD16), reading and writing `skills/`
    through `trees`, the lane's held mounts (`open_drain_trees`): `trees` must hold the draft's
    `agent/skills` itself (`paths.skills_dir` with no batch), else `LeadAuthorError`. `paths`
    names the product checkout. The deps must not outlive `trees`.

    The lane's systems are handed, never defaulted (#1366 O1, DC7, R16): the tenant's
    `TenantSystems` (its current enabled records the product checkout's catalog carries, plus the
    platform-served ones), built once by the entry that admitted the tenant, or the whole
    `Catalog` from a caller with no tenant. Only a caller with no tenant, handing the catalog, has
    the batch's committed markers declare systems beside it. The spawned author's write and `rm`
    lanes are drawn over the same set."""
    from defender.learning.leads.declared_systems import declared_systems_over, lane_names
    from defender.systems.catalog import Catalog

    if batch is not None:
        root = Path(batch.draft_root)
        skills_dir = root / SKILLS_PREFIX
        base = batch.base()
    else:
        root, skills_dir, base = paths.repo_root, paths.skills_dir, None
    skills = lane_skills(trees, paths, skills_dir=skills_dir)
    declared = (declared_systems_over(systems.roster, agent=base) if isinstance(systems, Catalog)
                else lane_names(systems))
    invoke_kw: dict[str, Any] = {"repo_root": root, "systems": tuple(sorted(lane_names(systems)))}
    if make_model is not None:
        invoke_kw["spawn"] = functools.partial(_spawn_author_agent, make_model=make_model)
    return LeadAuthorDeps(
        paths=paths,
        systems=declared,
        invoke_agent=functools.partial(invoke_agent, **invoke_kw),
        extract=extract,
        synthesize=synthesize_drafts,
        build_handoff=functools.partial(
            build_handoff, repo_root=root, skills=skills.view(), where=skills_dir,
        ),
        discover_system_drafts=functools.partial(
            discover_system_drafts, skills=skills.view(), where=skills_dir, systems=declared,
        ),
        skills=skills,
        tree_for=trees.tree_for,
        root=root,
        skills_dir=skills_dir,
        batch=batch,
        git_timeout=git_timeout,
        file_pitfalls=file_pitfalls,
    )


def run(  # noqa: PLR0913 — the run, its lane, and each seam a caller may hand it
    run: Run,
    *,
    label: _loop_config.DrainLabel,
    paths: _loop_config.LoopPaths | None = None,
    batch: Any = None,
    deps: LeadAuthorDeps | None = None,
    box: Any = None,
    on_done: DoneSink | None = None,
    file_pitfalls: Callable[[list[dict]], int] | None = None,
    systems: TenantSystems | Catalog | None = None,
) -> int:
    """Serve one run over `batch`'s draft (`deps.batch` when deps are given), for a caller that
    already holds the lane (the drain, through its store claim). #1278 A3: there is no by-hand
    entry and no file queue lock. The lane's grant is read first: a label whose lane does not
    mount the skills tree is refused before anything is built. Without `file_pitfalls` the run's
    pitfalls are filed in the learning store. Without deps, `systems` are the lane's systems
    (`build_lead_author_deps`)."""
    if deps is None and paths is None:
        raise TypeError("run takes paths= (or deps=)")
    lane_batch = getattr(deps, "batch", None) if deps is not None else batch
    writable = (
        label.draft_trees(lane_batch) if lane_batch is not None
        else label.writable_trees(deps.paths if deps is not None else paths)  # type: ignore[arg-type]
    )
    run_dir = Path(run.run_dir)
    sink = on_done if on_done is not None else functools.partial(write_done_sentinel, run_dir)
    if deps is not None:
        skills_dir = getattr(deps, "skills_dir", None) or deps.paths.skills_dir
        if skills_dir not in writable:
            raise LeadAuthorError(f"refused: the {str(label)!r} lane does not mount {skills_dir}")
        return _run_locked(run_dir, deps, box=box, on_done=sink)
    assert paths is not None  # the guard above
    with open_drain_trees(paths, label, batch=batch) as trees:
        deps = build_lead_author_deps(
            paths, trees=trees, batch=batch,
            file_pitfalls=file_pitfalls if file_pitfalls is not None else _store_pitfalls(paths),
            systems=_handed(systems))
        return _run_locked(run_dir, deps, box=box, on_done=sink)


def _handed(systems: TenantSystems | Catalog | None) -> TenantSystems | Catalog:
    """The lane's handed systems; a lane building its deps with none is refused (#1366 R16: never defaulted)."""
    if systems is None:
        raise LeadAuthorError("the lead-author lane was handed no systems: its entry hands the tenant's (or, with no "
                              "tenant, the whole catalog)")
    return systems


def run_under_held_queue_lock(  # noqa: PLR0913 — the drain's call shape: the run, its held lock and trees, and its seams
    run: Run, *, paths: _loop_config.LoopPaths, trees: DrainTrees,
    box: Any = None, on_done: DoneSink, git_timeout: float = GIT_TIMEOUT_SECONDS,
    batch: Any = None, deps: LeadAuthorDeps | None = None,
    items: Any = None, feedback: str | None = None,  # noqa: ARG001 — the drain's store seam; the run names its own leads
    outcomes: dict[tuple[str, str], Any] | None = None,  # noqa: ARG001 — the drain decides a served request's fate
    make_model: Callable[..., Any] | None = None,
    systems: TenantSystems | Catalog | None = None,
) -> int:
    """`run` for a caller that already holds the lane (the drain: its store claim, #1278) and the
    lane's held mounts, `trees` (the drain's work step opens them over `batch`'s draft). Never skips.
    `run` is the run the drain opened from the claim's address; `deps` given are used as built, else
    they are built over `batch`, the run's pitfalls filed in the learning store, `make_model` the
    spawn's model seam, and over `systems`."""
    if deps is None:
        deps = build_lead_author_deps(
            paths, trees=trees, batch=batch, git_timeout=git_timeout,
            file_pitfalls=_store_pitfalls(paths), make_model=make_model, systems=_handed(systems))
    return _run_locked(Path(run.run_dir), deps, box=box, on_done=on_done)


def _store_pitfalls(paths: _loop_config.LoopPaths) -> Callable[[list[dict]], int]:
    """Where a run served over the learning store files the pitfalls it collects: the selected
    tenant's pitfall items (`LearningStore.add_pitfall`, through the store's sync facade)."""
    if paths.tenant is None:
        raise LeadAuthorError("lead-author refused: no tenant is selected to file the run's pitfalls for")
    tenant_id = str(paths.tenant.id)

    def file_pitfalls(rows: list[dict]) -> int:
        from defender.learning.core.store_tick import opened_store

        with opened_store() as store:
            return sum(1 for row in rows if store.add_pitfall(tenant_id, row))

    return file_pitfalls


def _run_locked(  # noqa: C901 — one served run, its pitfalls filed where the deps say
    run_dir: Path, deps: LeadAuthorDeps, *, box: Any = None, on_done: DoneSink,
) -> int:
    if _done_sentinel(run_dir).is_file():
        _logger.info("already processed (done sentinel exists) — nothing to do")
        return 0

    from defender.learning.leads.declared_systems import declares_no_system

    if declares_no_system(deps.systems):
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
            if deps.file_pitfalls is not None:
                deps.file_pitfalls(failures)
            else:
                raise LeadAuthorError("lead-author refused: these deps name nowhere to file the run's pitfalls")
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
    "REPO_ROOT",
    "SKILLS_PREFIX",
    "_DRAFT_README_NAMES",
    "_NO_MINTED",
    "_SAFE_ID_SEGMENT",
    "_VALID_PAYLOAD_STATUSES",
    "_answered_after_batch",
    "_check_promoted_template",
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
