#!/usr/bin/env python3
from __future__ import annotations

import difflib
import logging
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from functools import partial
from typing import Any
from pathlib import Path

from uuid import uuid4
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.knowledge import FENCE_LINE_RE
from defender.knowledge import AGENT_REL, REDUCER_PITFALLS
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender._io import ENTRY_FILE
from defender._paths import process_defender_dir
from defender._untrusted import wrap
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist
from defender.learning.core import pitfalls_disposition as _disposition
from defender.learning.core.lane_trees import DrainTrees, TreeFor, kind_at, read_at
from defender.learning.author._config import GIT_TIMEOUT_SECONDS
from defender.learning.author.version_control import ChangeSet
from defender.learning.leads._lead_spine import (
    _loop_commit_body,
    _spawn_author_agent,
    _verify_corpus_scope,
    committed_text,
    draft_view,
    lane_skills,
)
from defender.learning.leads.declared_systems import (
    ADAPTERS_REL,
    adapter_declared_systems,
    with_platform_systems,
)
from defender import box as _box
from defender.kit.verbs import is_system_name
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning._prompt import stage_user_message, structured_json_body
from defender.learning.leads.path_validation import (
    LEARNING_DIR,
    SKILLS_PREFIX,
    _is_system_execution_md,
)

_logger = logging.getLogger(__name__)

LEAD_PITFALLS_PROMPT = LEARNING_DIR / "leads" / "lead_pitfalls.md"

#: The reducer surface: the one literal `_pitfalls_path_rule` admits beyond a declared system's
#: `execution.md` — the tenant's pitfalls add-on to the product's `defender-sql` page
#: (`knowledge.REDUCER_PITFALLS`, the same name the gather dispatch hands the subagent, which
#: reads it beside the product page before writing SQL). The product page itself is never
#: written (#1108 P4 O1, O7).
REDUCER_REL = f"{AGENT_REL}/{REDUCER_PITFALLS}"  # lint-stage-frame: ok — a path

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
            # The mistake's exemplar row, as the claim keys it: what the curator was handed.
            "pitfall_id": f.get("pitfall_id", ""),
            "query_id": f.get("query_id", ""),
            "goal": f.get("goal", "") if keep_goal else "",
            "executed_query": f.get("executed_query", ""),
            "stderr_digest": f.get("stderr_digest", ""),
            "occurrences": f["occurrences"],
        }
        for f in sorted(records, key=lambda f: f["occurrences"], reverse=True)
    ]


def _build_pitfalls_handoffs(rows: list[dict], *, systems: frozenset[str]) -> list[dict]:
    """One entry per surface, one failure per distinct mistake."""
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
            "path": f"{SKILLS_PREFIX}{system}/execution.md",
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


def _invoke_pitfalls_agent(  # noqa: PLR0913 — the spawn's handoffs, its folder, its tree and its seams
    handoffs: list[dict], *, run_dir: Path, repo_root: Path,
    spawn: Callable[..., int] = _spawn_author_agent,
    salt: str | None = None,
    box=None,
    feedback: str | None = None,
    make_model: Callable[..., Any] | None = None,
) -> int:
    """Spawn the pitfalls curator over the draft at `repo_root`, its run folder `run_dir` (the call's
    own folder, #1278 A1). `feedback` is a replacement's framed review text (H13); `make_model` the
    stage's model seam."""
    stage_salt = salt if salt is not None else uuid4().hex
    view = draft_view(run_dir, repo_root)
    context = (f"draft_root: {view.to_model(repo_root)}\n"
               f"skills_dir: {view.to_model(repo_root / SKILLS_PREFIX)}")
    user_prompt = stage_user_message(
        stage_salt,
        wrap(context, "pitfalls_context", stage_salt),
        wrap(structured_json_body(handoffs), "pitfalls_handoffs", stage_salt),
        *([wrap(feedback, "review_feedback", stage_salt)] if feedback else []),
    )
    return spawn(
        system_prompt_file=LEAD_PITFALLS_PROMPT,
        batch_id="pitfalls",
        user_prompt=user_prompt,
        repo_root=repo_root,
        learning_run_dir=run_dir,
        log_label="pitfalls curator",
        salt=stage_salt, box=box,
        **({"make_model": make_model} if make_model is not None else {}),
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
    """The document's `##` headings as `(line index, text)`, and the section each line sits in."""
    headings: list[tuple[int, str]] = []
    sections: list[str | None] = []
    section: str | None = None
    fenced = False
    for i, line in enumerate(lines):
        if FENCE_LINE_RE.match(line.lstrip()):
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


def _readable_pair(
    repo_root: Path, path: str, *, tree_for: TreeFor, base: Mapping[str, bytes] | None = None,
) -> tuple[str, str]:
    """The document as the batch's `base` commits it and as the curator left it, or this rule's
    refusal. Also compares frontmatter, the one check that reads raw text rather than lines.

    The draft's side is read through the lane's held `skills/` mount (`tree_for`), so a link
    at the name or at a holding folder is refused, never followed (#1134).
    """
    committed = committed_text(repo_root, path, base=base)
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


def _pitfalls_content_rule(
    repo_root: Path, xy: str, path: str, *, tree_for: TreeFor,
    base: Mapping[str, bytes] | None = None,
) -> None:
    """The content half of the gate (mirror of `lead_author._skills_content_rule`): is what the
    curator wrote still the document?"""
    if path != REDUCER_REL or "D" in xy:
        return
    committed, current = _readable_pair(repo_root, path, tree_for=tree_for, base=base)
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
    """Was this tick's curator offered the reducer surface it wrote?"""
    if path == REDUCER_REL and not reducer_offered:
        raise LeadAuthorError(
            f"pitfalls curator wrote {path} on a tick that offered no reducer handoff; "
            "refusing to commit (the reducer surface is opened by a queued "
            "defender-sql mistake, never by the prompt alone)"
        )


def _pitfalls_rule(  # noqa: PLR0913 — the path, the tick's offer, and the two trees it reads
    repo_root: Path, xy: str, path: str, *,
    systems: frozenset[str], reducer_offered: bool, tree_for: TreeFor,
    base: Mapping[str, bytes] | None = None,
) -> None:
    """The whole per-path gate: may the lane write this path at all, was this tick offered it,
    and is what the curator wrote still the document.

    Composed like the sibling lane's `_skills_rule`; each half must not read a path an earlier
    one refused. The offer check sits after the scope check (out-of-scope is refused whatever
    the batch held) and before the content check (an uninvited document's diff isn't worth
    reading)."""
    _pitfalls_path_rule(xy, path, systems=systems)
    _pitfalls_offer_rule(path, reducer_offered=reducer_offered)
    _pitfalls_content_rule(repo_root, xy, path, tree_for=tree_for, base=base)


def _verify_pitfalls_state(  # noqa: PLR0913 — the claim, its base, and the tick's three facts
    repo_root: Path, *, change_set: ChangeSet,
    systems: frozenset[str], reducer_offered: bool, tree_for: TreeFor,
    base: Mapping[str, bytes] | None = None,
) -> list[str]:
    """The lane's gate over one claim (`change_set`, the batch's draft against its `base`; no
    base given, `committed_text`'s fallback), its paths `agent/skills/...` under the draft's `repo_root`
    (#1108 P4 O7, OD6). `reducer_offered` is required: either default ("every tick may write
    the reducer surface" or "no tick may") is wrong for a caller that forgot it."""
    return _verify_corpus_scope(
        repo_root, change_set, actor="pitfalls curator",
        rule=partial(
            _pitfalls_rule, repo_root,
            systems=systems, reducer_offered=reducer_offered, tree_for=tree_for, base=base,
        ),
        tree_for=tree_for,
        base=base,
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
    """The systems the pitfalls lane admits: the adapter half alone, resolved once at the lane's
    own boundary — refusing loudly rather than spending an empty set as an ordinary per-row
    membership "no" — plus the platform-served names."""
    systems = adapter_declared_systems(repo_root)
    if not systems:
        message = (
            f"pitfalls curation refused: {repo_root / ADAPTERS_REL} declares no systems; "
            "refusing to run the pitfalls lane against an empty declared set"
        )
        _logger.error(message)
        raise LeadAuthorError(message)
    return with_platform_systems(systems)


def _split_batch_by_membership(
    rows: list[dict], batch_ids: list[str], kept: set[str],
    *, reducer_offered: bool, changed: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """The tick's partition into curated, dropped and held ids, asymmetric by row class."""
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


#: Re-exported from `core/pitfalls_disposition`, which holds the success-path consumption and
#: the held rows' offer ceiling beside the drain that carries them. The ceiling's helper is not
#: re-exported: `apply` binds it in `core/`, so patching a name here would not reach it.
HELD_CEILING_REASON = _disposition.HELD_CEILING_REASON
OFFERS_DECLINED_KEY = _disposition.OFFERS_DECLINED_KEY
PitfallsDisposition = _disposition.PitfallsDisposition


def _claimed_rows(
    items: Sequence[tuple[str, str, dict[str, Any]]], outcomes: dict[tuple[str, str], Any],
) -> tuple[list[dict], dict[str, tuple[str, str]]]:
    """The claim's pitfall rows that carry a `pitfall_id`, and each id's item; a row with none is dead
    at once (unkeyable, D1), named by the key the store gave it."""
    from defender.learning.store import Outcome

    rows: list[dict] = []
    item_of: dict[str, tuple[str, str]] = {}
    for kind, key, payload in items:
        pid = payload.get("pitfall_id")
        if not isinstance(pid, str) or not pid or pid in item_of:
            outcomes[(kind, key)] = Outcome.dead("row carries no value under 'pitfall_id'")
            continue
        rows.append(dict(payload))
        item_of[pid] = (kind, key)
    return rows, item_of


def _skip_dropped(
    rows: list[dict], dropped_ids: list[str], item_of: dict[str, tuple[str, str]],
    outcomes: dict[tuple[str, str], Any],
) -> None:
    """The rows no surface can teach (no system, a malformed one, one the adapters do not declare):
    skipped, the reason naming the system (D9). Terminal: no retry makes one teachable."""
    from defender.learning.store import Outcome

    dropped = set(dropped_ids)
    for r in rows:
        if r["pitfall_id"] in dropped:
            outcomes[item_of[r["pitfall_id"]]] = Outcome.skipped(_deadletter_reason(r))


def run_pitfalls(  # noqa: PLR0913 — one claim's whole injection surface
    *,
    paths: _loop_config.LoopPaths,
    trees: DrainTrees,
    batch: Any = None,
    invoke: Callable[..., int] | None = None,
    box=None,
    on_curated: Callable[[PitfallsDisposition], None] | None = None,
    lock_wait_seconds: int | None = None,  # noqa: ARG001 — the drain's call shape; the store's claim is the lane's lock
    git_timeout: float = GIT_TIMEOUT_SECONDS,  # noqa: ARG001 — the drain's call shape; the lane runs no git
    items: Sequence[tuple[str, str, dict[str, Any]]] = (),
    outcomes: dict[tuple[str, str], Any] | None = None,
    feedback: str | None = None,
    make_model: Callable[..., Any] | None = None,
) -> int:
    """One curation over a learning store claim's pitfalls (`items`, #1278 D1/D9), into `batch`'s
    draft (#1108 P4 O7): the claim is the draft against the batch's base, judged by the lane's gate
    and committed by the batch's commit-maker. `paths` names the product checkout (adapters).
    `outcomes` is filled with the fates decided here: a row with no id is dead, a row no declared
    surface can teach is skipped naming its system. The pitfalls the commit took are handed to
    `on_curated` (they stay in the batch); the rest are left unnamed (the drain returns them to
    waiting). `feedback` is a replacement's framed review text (H13)."""
    outcomes = outcomes if outcomes is not None else {}
    root = Path(batch.draft_root) if batch is not None else paths.repo_root
    lane_skills(trees, paths, skills_dir=root / SKILLS_PREFIX if batch is not None else None)
    rows, item_of = _claimed_rows(items, outcomes)
    if not rows:
        _logger.info("pitfalls: no keyed pitfall in the claim — nothing to curate")
        return 0
    # The claim already decided there is work (its threshold is the store's); the handoffs count
    # distinct mistakes, not rows: the queue keeps one row per failure.
    records = _loop_persist.merge_pitfalls(rows)
    batch_ids = [str(r["pitfall_id"]) for r in rows]
    # The running checkout's adapters: the same tree the stage's permission gate declares its
    # writable systems from (`lead_author_engine`, bound over `process_defender_dir()`), so the
    # handoffs offer no surface the gate would refuse. Resolved once, before the agent is spawned.
    repo_root = process_defender_dir().parent
    systems = _require_adapter_declared_systems(repo_root)
    handoffs = _build_pitfalls_handoffs(records, systems=systems)
    # One derivation of "was the reducer surface offered this tick", read by the commit gate and
    # the partition.
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
            f"pitfalls: dropped {len(dropped)} claimed system(s) not in the declared adapter "
            f"set ({repo_root / ADAPTERS_REL}): {dropped}"
        )

    if not handoffs:
        # Nothing in this claim could ever be taught, so there is no offer to make.
        _, dropped_ids, _ = _split_batch_by_membership(
            rows, batch_ids, kept, reducer_offered=reducer_offered, changed=[],
        )
        _logger.warning(
            f"{len(records)} claimed pitfall(s) in {len(batch_ids)} row(s) but none named a "
            f"system the adapter set at {repo_root / ADAPTERS_REL} declares — skipping them"
        )
        _skip_dropped(rows, dropped_ids, item_of, outcomes)
        return 0
    if batch is None:
        raise LeadAuthorError(
            "pitfalls curation refused: no batch was handed, and the lane commits only into a "
            "tenant batch's draft (#1108 P4) — nothing is curated"
        )
    # A row is one occurrence, so `len(rows)` is the failure count. Surfaces are named rather
    # than systems, since a reducer-only claim has no system names.
    _logger.info(
        f"pitfalls curation: {len(records)} distinct mistake(s) "
        f"({len(rows)} failure(s)) offered across {len(handoffs)} surface(s): "
        f"{[h['path'] for h in handoffs]}"
    )

    from defender.learning.call_folders import call_folder

    # The call's own folder (#1278 A1), made before the box runs; the box runs for the spawn only,
    # and is stopped before the gate reads what it wrote (#1195).
    run_dir = call_folder(batch.tenant, str(batch.id), "pitfalls", 1, make=True)
    with _box.box_for_run(box) as run_box:
        rc = (invoke or _invoke_pitfalls_agent)(
            handoffs, run_dir=run_dir, repo_root=root, box=run_box, feedback=feedback,
            make_model=make_model)
    if rc != 0:
        # Not raised: an `AuthorError` halts the drain's tick, and a stage fault is this curation's
        # alone. The claim's items take what the batch's commits show (the draft is reset by the
        # drain's claim).
        _logger.error(f"pitfalls curator exited rc={rc}; nothing committed")
        return 2

    # The claim, derived before anything reads what the box wrote (a link, FIFO or out-of-lane
    # entry refuses it whole, `DeliveryRefused`); the gate judges it, the commit-maker commits.
    change_set = batch.change_set()
    changed = _verify_pitfalls_state(
        root, change_set=change_set, systems=systems, reducer_offered=reducer_offered,
        tree_for=trees.tree_for, base=batch.base(),
    )
    sha = None
    if changed:
        sha = batch.commit(change_set, _pitfalls_commit_message(changed))
    else:
        _logger.info("pitfalls curator made no corpus edits (valid no-edit claim)")
    # After the commit: a reducer row's criterion needs the confirmed edit, which only
    # `changed` carries.
    committed_ids, dropped_ids, held_ids = _split_batch_by_membership(
        rows, batch_ids, kept, reducer_offered=reducer_offered, changed=changed,
    )
    _skip_dropped(rows, dropped_ids, item_of, outcomes)
    disposition = PitfallsDisposition(
        committed_ids=tuple(committed_ids), sha=sha, held_ids=tuple(held_ids),
    )
    if on_curated is not None:
        on_curated(disposition)
    _logger.info(
        f"pitfalls curation done; commit={(sha or 'none')[:12]}, "
        f"taught {len(changed)} surface(s): {changed}, "
        f"{len(set(dropped_ids))} unattributable row(s) skipped; "
        f"{len(set(committed_ids))} committed row(s) stay in the batch and {len(held_ids)} offered "
        "and declined row(s) wait again"
    )
    return 0
