#!/usr/bin/env python3
from __future__ import annotations

import difflib
import logging
import re
import sys
from collections.abc import Callable
from functools import partial
from pathlib import Path

from uuid import uuid4
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _git
from defender._corpus import _FENCE_RE
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender.learning.author import drain as _author_drain
from defender.learning.author import shared as _author_shared
from defender._io import ENTRY_FILE
from defender._untrusted import wrap
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist
from defender.learning.core import pitfalls_disposition as _disposition
from defender.learning.core.lane_trees import DrainTrees, TreeFor, kind_at, read_at
from defender.learning.core.state import PITFALLS, LearningState
from defender._claim_git import ClaimGit
from defender.learning.author._config import GIT_TIMEOUT_SECONDS
from defender.learning.leads._lead_spine import (
    _loop_commit_body,
    _spawn_author_agent,
    _verify_corpus_scope,
    lane_skills,
)
from defender.learning.leads.declared_systems import (
    ADAPTERS_REL,
    adapter_declared_systems,
)
from defender.runtime import box as _box
from defender.runtime.verbs import is_system_name
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning._prompt import stage_user_message, structured_json_body
from defender.learning.leads.path_validation import (
    LEARNING_DIR,
    SKILLS_REL,
    _is_system_execution_md,
)

_logger = logging.getLogger(__name__)

LEAD_PITFALLS_PROMPT = LEARNING_DIR / "leads" / "lead_pitfalls.md"

#: The reducer surface: the one literal `_pitfalls_path_rule` admits beyond a declared system's
#: `execution.md`. `skills/gather/SKILL.md` has the gather subagent read it before writing SQL —
#: the same before-the-attempt criterion that put system pitfalls in `execution.md`.
REDUCER_REL = "defender/skills/gather/defender-sql.md"

#: The one section a curator addition may land in, on either surface. `_pitfalls_content_rule`
#: enforces it on the reducer surface; the prompt asks for it on both.
PITFALLS_SECTION = "## Common pitfalls"

#: A setext heading's underline (`===` for H1, `---` for H2). Both outrank `## Common pitfalls`,
#: so `_outline` closes the section on them as on their ATX spellings; matched only after a
#: non-blank, non-heading line, which separates it from a thematic break.
_SETEXT_UNDERLINE_RE = re.compile(r"^(?:=+|-+)[ \t]*$")


#: Whether a queued row is the reducer's mistake rather than a system's. Owned by `persist`
#: because the merge key and the arrival gate ask it too; restating it here would let the
#: three disagree on how one row is routed.
_is_reducer_row = _loop_persist.is_reducer_row


def _failures_of(records: list[dict], *, keep_goal: bool = True) -> list[dict]:
    # `merge_pitfalls` stamps `occurrences` on every record. Most-repeated first, so the
    # curator's context budget is spent severity-first.
    #
    # `keep_goal=False` for the reducer surface: the goal is the lead's model-authored purpose
    # ("reduce the <system> envelope"), which would re-attribute a `defender-sql` lesson to that
    # system. The key stays so one shape serves both surfaces; a reduce failure is identified
    # by its `executed_query` and `stderr_digest` anyway.
    return [
        {
            "query_id": f.get("query_id", ""),
            "goal": f.get("goal", "") if keep_goal else "",
            "executed_query": f.get("executed_query", ""),
            "stderr_digest": f.get("stderr_digest", ""),
            "occurrences": f["occurrences"],
        }
        for f in sorted(records, key=lambda f: f["occurrences"], reverse=True)
    ]


def _build_pitfalls_handoffs(rows: list[dict], *, systems: frozenset[str]) -> list[dict]:
    """One entry per surface, one failure per distinct mistake.

    Two shapes, told apart by `surface`:

        {"surface": "system",  "system": "<name>", "path": "…/<name>/execution.md", "failures": […]}
        {"surface": "reducer",                     "path": "…/gather/defender-sql.md", "failures": […]}

    `system` is omitted from the reducer shape, so a `defender-sql` lesson provoked by one
    system's envelope is written without naming it (the attribution survives in
    `executed_queries`). At most one reducer entry, sorted after the system entries, because
    `lead_pitfalls.md` reads entries in order.

    Merges the rows itself (idempotent): this is the last seam before the prompt, so the
    curator never sees N copies of one bullet. `occurrences` orders each failure list.

    `systems` is the adapter-declared set; a row naming anything else yields no handoff. The
    `is_system_name` shape check runs first, so a traversal-shaped name is never looked up. A
    reducer row is routed by its `query_id`, so `gather` need not be a declared system.
    """
    by_system: dict[str, list[dict]] = {}
    reducer: list[dict] = []
    for r in _loop_persist.merge_pitfalls(rows):
        if _is_reducer_row(r):
            reducer.append(r)
            continue
        system = str(r.get("system") or "").strip()
        # `is_system_name("")` is already False, so there is no separate empty check.
        if not is_system_name(system) or system not in systems:
            continue
        by_system.setdefault(system, []).append(r)
    out: list[dict] = [
        {
            "surface": "system",
            "system": system,
            "path": f"{SKILLS_REL}{system}/execution.md",
            "failures": _failures_of(by_system[system]),
        }
        for system in sorted(by_system)
    ]
    if reducer:
        out.append({
            "surface": "reducer",
            "path": REDUCER_REL,
            "failures": _failures_of(reducer, keep_goal=False),
        })
    return out


def _invoke_pitfalls_agent(
    handoffs: list[dict], *, state: LearningState, repo_root: Path,
    spawn: Callable[..., int] = _spawn_author_agent,
    salt: str | None = None,
    box=None,
) -> int:
    stage_salt = salt if salt is not None else uuid4().hex
    user_prompt = stage_user_message(
        stage_salt,
        wrap(f"skills_dir: {SKILLS_REL}", "pitfalls_context", stage_salt),
        wrap(structured_json_body(handoffs), "pitfalls_handoffs", stage_salt),
    )
    return spawn(
        system_prompt_file=LEAD_PITFALLS_PROMPT,
        batch_id="pitfalls",
        user_prompt=user_prompt,
        repo_root=repo_root,
        learning_run_dir=state.stage_dir(_loop_config.LEAD_AUTHOR_DRAIN_LABEL),
        log_label="pitfalls curator",
        salt=stage_salt, box=box,
    )


def _pitfalls_path_rule(xy: str, path: str, *, systems: frozenset[str]) -> None:
    # The reducer literal is matched before both branches, since each would refuse it (`gather`
    # isn't a declared system; the surface isn't an `execution.md`). It falls through to the
    # delete check rather than returning, so it isn't exempt from that.
    if path != REDUCER_REL:
        if not _is_system_execution_md(path):
            raise LeadAuthorError(
                f"pitfalls curator edited a non-execution.md skills path ({path}); "
                "refusing to commit (its scope is execution.md and the reducer surface "
                f"{REDUCER_REL})"
            )
        # An `execution.md` under an undeclared directory would mint a new system one file at
        # a time. Creating the file in a declared system's dir stays legal (it may not exist
        # yet), so this checks the directory's membership, not the file's existence.
        system = Path(path).parent.name
        if system not in systems:
            raise LeadAuthorError(
                f"pitfalls curator wrote {path} under an undeclared system ({system!r}); "
                "refusing to commit (execution.md lands in a declared system's dir, never "
                "mints a new one)"
            )
    if "D" in xy:
        raise LeadAuthorError(
            f"pitfalls curator deleted {path}; refusing to commit "
            "(a pitfalls surface is pruned in place, never removed)"
        )


def _frontmatter_block(text: str) -> str | None:
    """The document's frontmatter block verbatim, or None when it has none.

    Compared raw rather than parsed: text that differs but parses to the same mapping is still
    a metadata rewrite."""
    try:
        return split_frontmatter(text)[1]
    except FrontmatterError:
        return None


def _outline(lines: list[str]) -> tuple[list[tuple[int, str]], list[str | None]]:
    """The document's `##` headings as `(line index, text)`, and the section each line sits in.

    One pass for both so they can't disagree; takes the split lines because the section index
    is positional.

    Fence-aware via `_corpus._FENCE_RE`: fenced content is prose, so a heading re-planted
    inside a ``` block doesn't count as surviving. Headings are `startswith("## ")` rather than
    `_corpus._HEADING_RE`, so a bare `## ` line still closes the section.

    A section also closes on any heading that outranks it — ATX `# ` or a setext underline —
    since markdown renders those as a new top-level section. Otherwise an untrusted bullet could
    plant `# How to read this file` at the end and be certified as under `## Common pitfalls`;
    closing makes such a line land in no section, which the placement rule refuses. A setext
    underline closes from its title line, so that line's entry is corrected in place.
    """
    headings: list[tuple[int, str]] = []
    sections: list[str | None] = []
    section: str | None = None
    fenced = False
    for i, line in enumerate(lines):
        if _FENCE_RE.match(line.lstrip()):
            fenced = not fenced
        elif fenced:
            pass
        elif line.startswith("## "):
            section = line.strip()
            headings.append((i, line))
        elif line.startswith("# "):
            section = None
        elif (
            _SETEXT_UNDERLINE_RE.match(line)
            and i
            and lines[i - 1].strip()
            and not lines[i - 1].startswith("#")
        ):
            # Only after a non-blank, non-ATX line: after a blank line, `---`/`===` is a
            # thematic break, not a heading.
            section = None
            sections[-1] = None
        sections.append(section)
    return headings, sections


def _line_ops(
    old: list[str], new: list[str],
) -> tuple[list[int], list[int], list[tuple[int, int]]]:
    """Indices this edit added (in `new`), removed (in `old`), and `(old, new)` pairs of the
    lines it kept. A replaced line counts as both added and removed."""
    added: list[int] = []
    removed: list[int] = []
    kept: list[tuple[int, int]] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
        a=old, b=new, autojunk=False,
    ).get_opcodes():
        if tag in ("insert", "replace"):
            added.extend(range(j1, j2))
        if tag in ("delete", "replace"):
            removed.extend(range(i1, i2))
        if tag == "equal":
            kept.extend((i1 + k, j1 + k) for k in range(i2 - i1))
    return added, removed, kept


def _readable_pair(repo_root: Path, path: str, *, tree_for: TreeFor) -> tuple[str, str]:
    """The document as committed and as the curator left it, or this rule's refusal. Also
    compares frontmatter, the one check that reads raw text rather than lines.

    The working-copy side is read through the lane's held `skills/` mount (`tree_for`), so a link
    at the name or at a holding folder is refused, never followed (#1134).
    """
    committed = _git.git_show_file(repo_root, "HEAD", path)
    if committed is None:
        raise LeadAuthorError(
            f"pitfalls curator created {path}; refusing to commit (the reducer surface is a "
            "committed document this lane amends in place, never mints)"
        )
    if kind_at(repo_root, tree_for, path) != ENTRY_FILE:
        raise LeadAuthorError(
            f"pitfalls curator left {path} unreadable as a file; refusing to commit"
        )
    # A refused read (undecodable bytes, a hard link, an entry swapped since the kind probe) is
    # this rule's own error rather than escaping into the batch-retire path.
    current, reason = read_at(repo_root, tree_for, path)
    if current is None:
        raise LeadAuthorError(
            f"pitfalls curator left {path} unreadable as UTF-8 text ({reason}); refusing to commit"
        )
    if _frontmatter_block(current) != _frontmatter_block(committed):
        raise LeadAuthorError(
            f"pitfalls curator rewrote {path}'s frontmatter block; refusing to commit "
            "(the reducer surface's metadata is not a pitfalls edit)"
        )
    return committed, current


def _pitfalls_content_rule(repo_root: Path, xy: str, path: str, *, tree_for: TreeFor) -> None:
    """The content half of the gate (mirror of `lead_author._skills_content_rule`): is what the
    curator wrote still the document?

    Scoped to the reducer surface, the one corpus write target with no correspondence audit,
    scaffold rule or other content rule. A tick must preserve the frontmatter block, every
    committed `##` section, every non-blank line those sections held, and the boundary of
    `## Common pitfalls` over existing lines; everything added must land under that section (at
    its real markdown extent, created at the end if absent). Outside that section the document
    is append-only in both directions.

    Markdown inside a bullet is not sanitized — the same exposure exists on every
    `execution.md`. The prompt instead requires a reducer bullet to name the payload shape it
    applies to, since every system's reduce reads this file before every attempt.
    """
    if path != REDUCER_REL or "D" in xy:
        return
    committed, current = _readable_pair(repo_root, path, tree_for=tree_for)
    lines, committed_lines = current.splitlines(), committed.splitlines()
    survived, sections = _outline(lines)
    committed_headings, committed_sections = _outline(committed_lines)
    survived_text = [h for _, h in survived]
    lost = [h for _, h in committed_headings if h not in survived_text]
    if lost:
        raise LeadAuthorError(
            f"pitfalls curator dropped section(s) {lost} from {path}; refusing to commit "
            "(a pitfall is appended, never written over the document)"
        )
    added, removed, kept = _line_ops(committed_lines, lines)
    stray = sorted({
        lines[i] for i in added
        if lines[i].strip() and sections[i] != PITFALLS_SECTION
    })
    if stray:
        raise LeadAuthorError(
            f"pitfalls curator added {stray} to {path} outside `{PITFALLS_SECTION}`; "
            f"refusing to commit (a pitfall lands in that section, created if absent)"
        )
    # Surviving headings say nothing about what stood under them: without this a tick could
    # empty every section, leave the headings as stubs, and add one bullet. Pruning is legal
    # only inside `## Common pitfalls`, the section this lane owns.
    erased = sorted({
        committed_lines[i] for i in removed
        if committed_lines[i].strip() and committed_sections[i] != PITFALLS_SECTION
    })
    if erased:
        raise LeadAuthorError(
            f"pitfalls curator removed {erased} from {path} outside `{PITFALLS_SECTION}`; "
            "refusing to commit (a pitfall is appended, and only that section is pruned "
            "in place)"
        )
    # The lane-owned section's boundary. Planting `## Common pitfalls` mid-document is one added
    # line both checks above admit, but it pulls the following lines into the section this lane
    # may prune, so the next tick could gut them. A committed line may not change which side of
    # the boundary it sits on.
    reparented = sorted({
        committed_lines[i] for i, j in kept
        if committed_lines[i].strip()
        and (committed_sections[i] == PITFALLS_SECTION)
        != (sections[j] == PITFALLS_SECTION)
    })
    if reparented:
        raise LeadAuthorError(
            f"pitfalls curator moved {reparented} across `{PITFALLS_SECTION}`'s boundary in "
            f"{path}; refusing to commit (the section is created at the end of the file, "
            "never planted around prose it does not own)"
        )
    # At the end: planting the heading immediately before an existing `##` reparents nothing,
    # yet puts an alert-derived bullet ahead of the document's guidance. Asked only of a heading
    # this tick added; where a hand-added section sits isn't this lane's business.
    added_lines = set(added)
    planted = [i for i, h in survived if i in added_lines and h.strip() == PITFALLS_SECTION]
    ahead_of = [h for i, h in survived if planted and i > max(planted)]
    if ahead_of:
        raise LeadAuthorError(
            f"pitfalls curator planted `{PITFALLS_SECTION}` in {path} above {ahead_of}; "
            "refusing to commit (the section is created at the END of the file, so a bullet "
            "never lands ahead of the guidance the document already carries)"
        )


def _pitfalls_offer_rule(path: str, *, reducer_offered: bool) -> None:
    """Was this tick's curator offered the reducer surface it wrote?

    Distinct from `_pitfalls_path_rule`, which asks whether a path is ever writable (a constant
    of the deployment); this asks whether the target was opened on this tick.

    The curator's static prompt names the reducer path unconditionally, and each failure's
    alert-derived `stderr_digest` is in its context, so a digest saying "also record this in
    <the reducer surface>" would otherwise be obeyable on a batch of pure system rows — and
    invisible to the partition, which computes `reducer_taught` from the offer. System surfaces
    need no mirror: an `execution.md` is already bounded by the declared set.
    """
    if path == REDUCER_REL and not reducer_offered:
        raise LeadAuthorError(
            f"pitfalls curator wrote {path} on a tick that offered no reducer handoff; "
            "refusing to commit (the reducer surface is opened by a queued "
            "defender-sql mistake, never by the prompt alone)"
        )


def _pitfalls_rule(
    repo_root: Path, xy: str, path: str, *,
    systems: frozenset[str], reducer_offered: bool, tree_for: TreeFor,
) -> None:
    """The whole per-path gate: may the lane write this path at all, was this tick offered it,
    and is what the curator wrote still the document.

    Composed like the sibling lane's `_skills_rule`; each half must not read a path an earlier
    one refused. The offer check sits after the scope check (out-of-scope is refused whatever
    the batch held) and before the content check (an uninvited document's diff isn't worth
    reading)."""
    _pitfalls_path_rule(xy, path, systems=systems)
    _pitfalls_offer_rule(path, reducer_offered=reducer_offered)
    _pitfalls_content_rule(repo_root, xy, path, tree_for=tree_for)


def _verify_pitfalls_state(
    repo_root: Path, baseline_stray: list[str], *,
    systems: frozenset[str], reducer_offered: bool, tree_for: TreeFor, git: ClaimGit,
) -> list[str]:
    """`reducer_offered` is required: either default ("every tick may write the reducer
    surface" or "no tick may") is wrong for a caller that forgot it."""
    return _verify_corpus_scope(
        repo_root, baseline_stray, actor="pitfalls curator",
        rule=partial(
            _pitfalls_rule, repo_root,
            systems=systems, reducer_offered=reducer_offered, tree_for=tree_for,
        ),
        tree_for=tree_for,
        git=git,
    )


def _pitfalls_commit_message(changed: list[str]) -> str:
    """Names the surfaces this tick actually taught. With the graveyard shown only on the
    queue page, this and the operator log are the lane's routine human-visible records."""
    has_system = any(_is_system_execution_md(p) for p in changed)
    has_reducer = REDUCER_REL in changed
    if has_system and has_reducer:
        scope, where = (
            "execution.md + defender-sql pitfalls",
            f"per-system execution.md and the reducer surface ({REDUCER_REL})",
        )
    elif has_reducer:
        scope, where = (
            "defender-sql pitfalls", f"the reducer surface ({REDUCER_REL})",
        )
    else:
        scope, where = "execution.md pitfalls", "per-system execution.md"
    return _loop_commit_body(
        f"learning(lead-author): {scope}",
        f"Folded agent-fixable general failures into {where} "
        f"{PITFALLS_SECTION}; loop-committed (the agent runs no git).",
        changed,
    )


def _require_adapter_declared_systems(repo_root: Path) -> frozenset[str]:
    """The adapter half alone, resolved once at the pitfalls lane's own boundary — refusing
    loudly rather than spending an empty set as an ordinary per-row membership "no"."""
    systems = adapter_declared_systems(repo_root)
    if not systems:
        message = (
            f"pitfalls curation refused: {repo_root / ADAPTERS_REL} declares no systems; "
            "refusing to run the pitfalls lane against an empty declared set"
        )
        _logger.error(message)
        raise LeadAuthorError(message)
    return systems


def _split_batch_by_membership(
    rows: list[dict], batch_ids: list[str], kept: set[str],
    *, reducer_offered: bool, changed: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """The tick's partition into curated, dropped and held ids, asymmetric by row class.

    A system row is curated iff its system is in `kept`; otherwise nothing about it could ever
    be taught, and it is dropped on the first tick.

    A reducer row is curated only when the offer was made and taken — a reducer handoff was
    emitted and `changed` carries the reducer literal. Otherwise it is held: a no-edit tick is a
    legitimate outcome (`lead_pitfalls.md`: "skip that failure; never invent one"), and
    rotating the row out under an unrelated commit's sha would lose the only record of the
    mistake.

    `reducer_offered` is passed in rather than re-derived from the handoffs, so the commit gate
    (`_pitfalls_offer_rule`) and this partition read one derivation.
    """
    reducer_taught = reducer_offered and REDUCER_REL in changed
    committed_ids: list[str] = []
    held_ids: set[str] = set()
    for r in rows:
        pid = r.get("pitfall_id")
        if not pid:
            continue
        if _is_reducer_row(r):
            if reducer_taught:
                committed_ids.append(str(pid))
            else:
                held_ids.add(str(pid))
        elif str(r.get("system") or "").strip() in kept:
            committed_ids.append(str(pid))
    curated = set(committed_ids)
    dropped_ids = [i for i in batch_ids if i not in curated and i not in held_ids]
    # A duplicate `pitfall_id` on disk could put one id on both sides; a curated row must not
    # also be rotated as held.
    return committed_ids, dropped_ids, sorted(held_ids - curated)


def _deadletter_reason(row: dict) -> str:
    """Why this row is leaving the queue uncurated — the only thing the graveyard record offers
    a human, so each class gets a true reason. The undeclared class carries the name, since
    deployment skew and an invented name look identical from inside a tick."""
    system = str(row.get("system") or "").strip()
    if not system:
        return "no-system"
    if not is_system_name(system):
        return "malformed-system"
    return f"undeclared-system:{system}"


def _graveyard_dropped_rows(
    state: LearningState, rows: list[dict], dropped_ids: list[str],
) -> None:
    """Graveyard dropped rows for human review. Terminal: `drain.retire`'s ceiling doesn't apply,
    since an undeclared name is refused on the first tick, never retried."""
    if not dropped_ids:
        return
    ids = set(dropped_ids)
    key = PITFALLS.id_key
    entries = [
        {key: r[key], "deadletter_reason": _deadletter_reason(r), "row": r,
         **_author_drain.retirement_stamp()}
        for r in rows if r.get(key) in ids
    ]
    if entries:
        state.deadletter(PITFALLS, entries)


#: Re-exported from `core/pitfalls_disposition`, which holds the success-path consumption and
#: the held rows' offer ceiling beside the drain that carries them. The ceiling's helper is not
#: re-exported: `apply` binds it in `core/`, so patching a name here would not reach it.
HELD_CEILING_REASON = _disposition.HELD_CEILING_REASON
OFFERS_DECLINED_KEY = _disposition.OFFERS_DECLINED_KEY
PitfallsDisposition = _disposition.PitfallsDisposition


def run_pitfalls(  # noqa: PLR0913, C901 — one tick's whole injection surface
    *,
    paths: _loop_config.LoopPaths | None = None,
    state: LearningState | None = None,
    trees: DrainTrees,
    invoke: Callable[..., int] | None = None,
    box=None,
    on_curated: Callable[[PitfallsDisposition], None] | None = None,
    lock_wait_seconds: int | None = None,
    git_timeout: float = GIT_TIMEOUT_SECONDS,
) -> int:
    """One curation tick over the pitfalls queue.

    `on_curated` is the consumption switch. Left `None`, the tick consumes what it taught as
    soon as its commit exists. Given, the tick still commits but hands the `PitfallsDisposition`
    to the callable instead of applying it, so the caller can wait for the batch's tree to pass
    the scrub before the queue forgets the rows. Only the success-path consumption is
    switchable.

    `lock_wait_seconds` bounds every wait on the queue's append lock this tick makes. The drain
    passes its configured wait, since it holds the tick's locks meanwhile; `None` is
    unbounded.

    `git_timeout` bounds every git call over the worktree (the tick's `ClaimGit`, #1175); one
    that overruns raises `GitOverran`, a systemic `GitError`.

    `trees` are the lane's held mounts (the drain's work step opens them for its label): the
    commit gate reads the working copy through them (#1134). Checked before any work: they must
    hold `paths.skills_dir` itself as a mount point, else `LeadAuthorError`."""
    # An entry point on its own (by hand) opens the handle; the drain hands its own in.
    if paths is None:
        paths = _loop_config.loop_paths()
    if state is None:
        with LearningState.open(paths) as own:
            return run_pitfalls(
                paths=paths, state=own, trees=trees, invoke=invoke, box=box,
                on_curated=on_curated, lock_wait_seconds=lock_wait_seconds,
                git_timeout=git_timeout)
    lane_skills(trees, paths)
    rows = _loop_persist.read_pitfalls(state)
    # The gate counts distinct mistakes, not rows: the queue keeps one row per failure, so a
    # looping lead would otherwise clear the threshold on a single lesson.
    records = _loop_persist.merge_pitfalls(rows)
    threshold = _loop_config.pitfalls_threshold()
    if not _loop_persist.pitfalls_lane_is_open(records, threshold):
        if records:
            _logger.info(
                f"pitfalls queue below threshold (n={len(records)} distinct mistake(s) "
                f"in {len(rows)} row(s), threshold={threshold}) — skipping curation"
            )
        return 0
    # From the raw rows: rotation must name every row that fed a record, not just the merge's
    # exemplar.
    batch_ids = [str(r["pitfall_id"]) for r in rows if r.get("pitfall_id")]
    repo_root = paths.repo_root
    # The worktree's sources, not the process's checkout: this run commits into `repo_root`.
    # Resolved once, before the agent is spawned.
    systems = _require_adapter_declared_systems(repo_root)
    handoffs = _build_pitfalls_handoffs(records, systems=systems)
    # One derivation of "was the reducer surface offered this tick", read by the commit gate,
    # the partition and the hold's ceiling.
    reducer_offered = any(h.get("surface") == "reducer" for h in handoffs)
    # The `surface` filter makes the subscript safe: the reducer entry omits `system`.
    kept = {str(h["system"]) for h in handoffs if h.get("surface") == "system"}
    # A reducer row is routed by its `query_id`, so even one carrying an attributed system was
    # never asked a membership question and must not be reported as undeclared.
    dropped = sorted({
        s for r in records
        if not _is_reducer_row(r)
        and (s := str(r.get("system") or "").strip()) and s not in kept
    })
    if dropped:
        # Named, never dropped quietly: a batch that silently loses a system reads like one
        # that had nothing to teach. Names the adapter source, the only one this lane reads.
        _logger.warning(
            f"pitfalls: dropped {len(dropped)} queued system(s) not in the declared adapter "
            f"set ({repo_root / ADAPTERS_REL}): {dropped}"
        )

    if not handoffs:
        # Nothing in this batch could ever be taught, so there is no offer to hold rows
        # against and the whole batch retires.
        _, dropped_ids, _ = _split_batch_by_membership(
            rows, batch_ids, kept, reducer_offered=reducer_offered, changed=[],
        )
        _logger.warning(
            f"{len(records)} queued pitfall(s) in {len(batch_ids)} row(s) but none named a "
            f"system the adapter set at {repo_root / ADAPTERS_REL} declares — dropping"
        )
        _graveyard_dropped_rows(state, rows, dropped_ids)
        _loop_persist.rotate_pitfalls(
            dropped_ids, None, state=state, category="consumed_unattributable",
            timeout_seconds=lock_wait_seconds,
        )
        return 0
    git = ClaimGit(repo_root, SKILLS_REL, timeout=git_timeout)
    baseline_stray = git.changed_outside_corpus()
    # A queue row is one occurrence, so `len(rows)` is the failure count. Surfaces are named
    # rather than systems, since a reducer-only tick has no system names.
    _logger.info(
        f"pitfalls curation: {len(records)} distinct mistake(s) "
        f"({len(rows)} failure(s)) offered across {len(handoffs)} surface(s): "
        f"{[h['path'] for h in handoffs]}"
    )

    # The box runs for the spawn only, and is stopped before the gate reads what it wrote
    # (#1195).
    with _box.box_for_run(box) as run_box:
        rc = (invoke or _invoke_pitfalls_agent)(
            handoffs, state=state, repo_root=repo_root, box=run_box)
    if rc != 0:
        # Raised, not returned: a returned rc goes uninspected. `AuthorError` is in the drain's
        # retire set, so a repeatedly failing batch reaches the bounded retirement.
        raise _author_shared.AuthorError(
            f"pitfalls curator exited rc={rc}; leaving queue intact"
        )

    changed = _verify_pitfalls_state(
        repo_root, baseline_stray, systems=systems, reducer_offered=reducer_offered,
        tree_for=trees.tree_for, git=git,
    )
    sha = None
    if changed:
        sha = git.commit(changed, _pitfalls_commit_message(changed))
    else:
        _logger.info("pitfalls curator made no corpus edits (valid no-edit tick)")
    # After the commit: a reducer row's criterion needs the confirmed edit, which only
    # `changed` carries.
    committed_ids, dropped_ids, held_ids = _split_batch_by_membership(
        rows, batch_ids, kept, reducer_offered=reducer_offered, changed=changed,
    )
    # Unattributable rows leave now whatever `on_curated` is: no scrub can make an undeclared
    # system teachable, and deferring would re-graveyard them on the retry.
    if dropped_ids:
        _graveyard_dropped_rows(state, rows, dropped_ids)
        _loop_persist.rotate_pitfalls(
            dropped_ids, None, state=state, category="consumed_unattributable",
            timeout_seconds=lock_wait_seconds,
        )
    disposition = PitfallsDisposition(
        committed_ids=tuple(committed_ids), sha=sha, held_ids=tuple(held_ids),
    )
    if on_curated is not None:
        on_curated(disposition)
        # Reports what this tick did; the rotation and decline bump belong to whoever judges
        # the commit sound.
        _logger.info(
            f"pitfalls curation done; commit={(sha or 'none')[:12]}, "
            f"taught {len(changed)} surface(s): {changed}, "
            f"{len(set(dropped_ids))} unattributable row(s) rotated out; "
            f"{len(set(committed_ids))} committed and {len(held_ids)} held row(s) handed "
            "to the drain to consume once the batch passes the scrub"
        )
        return 0
    retired = disposition.apply(state, timeout_seconds=lock_wait_seconds)
    # Distinct id sets throughout, since a `pitfall_id` may repeat in the queue file.
    rotated = set(committed_ids) | set(dropped_ids)
    # Retired rows left this tick, so they are excluded from the held count.
    _logger.info(
        f"pitfalls curation done; commit={(sha or 'none')[:12]}, "
        f"taught {len(changed)} surface(s): {changed}, "
        f"rotated {len(rotated) + retired} row(s) out of the queue "
        f"({len(set(dropped_ids))} unattributable, "
        f"{len(held_ids) - retired} held for a later tick"
        + (f", {retired} retired at the hold ceiling" if retired else "")
        + ")"
    )
    return 0
