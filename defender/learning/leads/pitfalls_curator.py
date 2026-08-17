#!/usr/bin/env python3
from __future__ import annotations

import difflib
import sys
from collections.abc import Callable
from functools import partial
from pathlib import Path

from uuid import uuid4
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _git
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender.learning.author import drain as _author_drain
from defender.learning.author import shared as _author_shared
from defender._io import append_jsonl
from defender._untrusted import wrap
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist
from defender.learning.leads._lead_spine import (
    PENDING_DIR,
    _log,
    _loop_commit_body,
    _spawn_author_agent,
    _verify_corpus_scope,
)
from defender.learning.leads.declared_systems import (
    ADAPTERS_REL,
    adapter_declared_systems,
)
from defender.runtime.verbs import is_system_name
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.pipeline._prompt import stage_user_message, structured_json_body
from defender.learning.leads.path_validation import (
    LEARNING_DIR,
    SKILLS_REL,
    _is_system_execution_md,
)
from defender.scripts.gather_tools.record_query import BASH_SHIM_QUERY_ID

LEAD_PITFALLS_PROMPT = LEARNING_DIR / "leads" / "lead_pitfalls.md"

#: The REDUCER SURFACE — the second edit target this lane gained (#870 M6), and the one
#: literal `_pitfalls_path_rule` admits beyond a declared system's `execution.md`. Chosen
#: because `skills/gather/SKILL.md` tells the gather subagent to Read it BEFORE it writes the
#: SQL — the same before-the-attempt criterion that put system pitfalls in `execution.md`.
REDUCER_REL = "defender/skills/gather/defender-sql.md"

#: The one section a curator addition may land in, on either surface. `_pitfalls_content_rule`
#: enforces it on the reducer surface; the prompt asks for it on both.
PITFALLS_SECTION = "## Common pitfalls"


def _is_reducer_row(row: dict) -> bool:
    """Is this queued row the REDUCER's mistake rather than a system's?

    EQUALITY with the reserved sentinel (U3), the same predicate `collect_general_failures`
    routes on — and unconditional in the row's `system`, because a `defender-sql` mistake
    belongs to `defender-sql` however the reduce happened to be attributed (F1)."""
    return str(row.get("query_id") or "") == BASH_SHIM_QUERY_ID


def _failures_of(records: list[dict], *, keep_goal: bool = True) -> list[dict]:
    # `occurrences` is stamped on every record `merge_pitfalls` returns, so it is read here as
    # a key, not coalesced a second time. Most-repeated first: the curator's context budget is
    # spent severity-first.
    #
    # `keep_goal=False` on the reducer shape, and it is N7's decline rather than a saving: the
    # goal is the LEAD's own model-authored purpose ("reduce the <system> envelope"), the one
    # field through which the attributed system re-enters a lesson this round decided is
    # `defender-sql`'s and not that system's. The KEY stays — one failure shape serves both
    # surfaces — and the mistake is still fully recoverable, because a reduce failure is named
    # by its `executed_query` and its `stderr_digest`, never by the investigation it served.
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
    """One entry per SURFACE, one failure per distinct MISTAKE (#840).

    Two shapes, told apart by `surface` (#870 M6):

        {"surface": "system",  "system": "<name>", "path": "…/<name>/execution.md", "failures": […]}
        {"surface": "reducer",                     "path": "…/gather/defender-sql.md", "failures": […]}

    `system` is OMITTED from the reducer shape rather than emptied (N7): the attributed system
    is declined at this seam and survives in the run's `executed_queries` table anyway, so a
    `defender-sql` lesson provoked by one system's envelope is written without naming it.
    AT MOST ONE reducer entry per tick — one surface, one entry, however many mistakes it
    collects — and it sorts LAST, after the system entries' by-name order, because
    `lead_pitfalls.md` reads the entries in order.

    Merges the rows itself rather than trusting its caller to have merged them — the merge
    is idempotent, and this is the last seam before the prompt, so no reader of the queue
    can hand the curator N copies of one bullet. `occurrences` rides along and orders the
    list, so the mistake a lead made eight times is the first failure the curator weighs,
    not the eighth copy it has to notice is a copy.

    `systems` is the threaded membership value (NF2's adapter half alone) — a queued row
    naming a system nothing declares yields no handoff, which is the M6 gate #869 exists for.
    The shape check (`is_system_name`) runs regardless of what `systems` contains, so a
    traversal-shaped name is never a set lookup (FK-5). It is asked only of the SYSTEM half:
    a reducer row is routed by its `query_id`, so no membership question is put to it and
    `gather` never has to be a declared system for its surface to be reachable (C11).
    """
    by_system: dict[str, list[dict]] = {}
    reducer: list[dict] = []
    for r in _loop_persist.merge_pitfalls(rows):
        if _is_reducer_row(r):
            reducer.append(r)
            continue
        system = str(r.get("system") or "").strip()
        # No `not system` arm: `is_system_name("")` is already False (the pattern needs one
        # `[a-z0-9]`), and a second spelling of "the empty string is not a name" is one more
        # place for the two to disagree — which is the whole of what #914 was about.
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
    handoffs: list[dict], *, repo_root: Path,
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
        learning_run_dir=PENDING_DIR,
        log_label="pitfalls curator",
        salt=stage_salt, box=box,
    )


def _pitfalls_path_rule(xy: str, path: str, *, systems: frozenset[str]) -> None:
    # #870 M7 — ONE literal allowance, compared as a literal and matched BEFORE both branches
    # below. `gather` is not in the adapter set (C11) and the reducer surface is not an
    # `execution.md` (C7), so either branch would refuse the one path this round exists to
    # open. It FALLS THROUGH to the delete branch rather than returning: that branch is this
    # rule's LAST, so an early return would exempt the new path from U4 — the one negative
    # universal the doc assumed it would inherit for free.
    if path != REDUCER_REL:
        if not _is_system_execution_md(path):
            raise LeadAuthorError(
                f"pitfalls curator edited a non-execution.md skills path ({path}); "
                "refusing to commit (its scope is execution.md and the reducer surface "
                f"{REDUCER_REL})"
            )
        # The LAST gate on the same phantom-system class the handoff filters (#855 F-06): an
        # `execution.md` under an UNDECLARED directory is not a system's execution surface, it
        # is a new system directory being minted one file at a time. Creating the FILE stays
        # legal — a declared system may have no `execution.md` yet and the curator's job is to
        # write the first one — so this asks about the directory's membership, not the file's
        # existence.
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
    """The document's frontmatter, verbatim, or None when it has none.

    Through the shared parser (#591's one grammar, one fence). The RAW block rather than the
    parsed mapping: two documents whose YAML happens to parse to the same dict but whose text
    differs are still a rewrite of this file's metadata, and this rule is about the document
    surviving the tick."""
    try:
        return split_frontmatter(text)[1]
    except FrontmatterError:
        return None


def _headings(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.startswith("## ")]


def _added_lines(before: str, after: str) -> list[int]:
    """The indices, in `after`, of the lines this edit ADDED.

    A replaced line counts as an addition: the point of the rule below is where new prose
    lands, and prose that overwrote an existing line landed exactly where that line was."""
    old, new = before.splitlines(), after.splitlines()
    added: list[int] = []
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(
        a=old, b=new, autojunk=False,
    ).get_opcodes():
        if tag in ("insert", "replace"):
            added.extend(range(j1, j2))
    return added


def _pitfalls_content_rule(repo_root: Path, xy: str, path: str) -> None:
    """The content half of the gate (#870 FK-2), the mirror of `lead_author._skills_content_
    rule`: everything above answers "may the curator touch this path", this answers "is what
    it wrote still the document".

    Scoped to the REDUCER SURFACE, because that is the target this round opens and it is the
    one corpus write target with no correspondence audit (C13, refuted — it is not a
    `verb_roster.model_read_surface`), no scaffold rule (FF-12, `_scaffold_rules` is scoped to
    `skills/{system}/SKILL.md`) and, until now, no lane content rule. Three things must
    survive a curator's tick: the YAML frontmatter block, every `##` section the committed
    file already carried, and the placement of everything added — under `## Common pitfalls`,
    created if absent.

    Markdown INSIDE a bullet is deliberately NOT sanitized. The same untrusted-text-to-corpus
    laundering already exists on every `execution.md` and re-keying it is a round of its own;
    what this round takes instead is the prompt requirement that a reducer bullet name the
    payload shape it applies to, since this is the one file EVERY system's reduce reads before
    EVERY attempt.
    """
    if path != REDUCER_REL or "D" in xy:
        return
    committed = _git.git_show_file(repo_root, "HEAD", path)
    if committed is None:
        raise LeadAuthorError(
            f"pitfalls curator created {path}; refusing to commit (the reducer surface is a "
            "committed document this lane amends in place, never mints)"
        )
    full = repo_root / path
    if not full.is_file():
        raise LeadAuthorError(
            f"pitfalls curator left {path} unreadable as a file; refusing to commit"
        )
    current = full.read_text(encoding="utf-8")
    if _frontmatter_block(current) != _frontmatter_block(committed):
        raise LeadAuthorError(
            f"pitfalls curator rewrote {path}'s frontmatter block; refusing to commit "
            "(the reducer surface's metadata is not a pitfalls edit)"
        )
    survived = _headings(current)
    lost = [h for h in _headings(committed) if h not in survived]
    if lost:
        raise LeadAuthorError(
            f"pitfalls curator dropped section(s) {lost} from {path}; refusing to commit "
            "(a pitfall is appended, never written over the document)"
        )
    section: str | None = None
    lines = current.splitlines()
    sections = []
    for line in lines:
        if line.startswith("## "):
            section = line.strip()
        sections.append(section)
    stray = sorted({
        lines[i] for i in _added_lines(committed, current)
        if lines[i].strip() and sections[i] != PITFALLS_SECTION
    })
    if stray:
        raise LeadAuthorError(
            f"pitfalls curator added {stray} to {path} outside `{PITFALLS_SECTION}`; "
            f"refusing to commit (a pitfall lands in that section, created if absent)"
        )


def _pitfalls_rule(repo_root: Path, xy: str, path: str, *, systems: frozenset[str]) -> None:
    """The whole per-path gate: the path half, then the content half on what it admitted.

    Composed rather than folded, exactly as the sibling lane's `_skills_rule` is: the two
    halves ask different questions, and the content half must not read a path the path half
    has already refused."""
    _pitfalls_path_rule(xy, path, systems=systems)
    _pitfalls_content_rule(repo_root, xy, path)


def _verify_pitfalls_state(
    repo_root: Path, baseline_stray: list[str], *, systems: frozenset[str],
) -> list[str]:
    return _verify_corpus_scope(
        repo_root, baseline_stray, actor="pitfalls curator",
        rule=partial(_pitfalls_rule, repo_root, systems=systems),
    )


def _pitfalls_commit_message(changed: list[str]) -> str:
    """Names what this tick actually taught (#870 FK-6).

    It said "per-system execution.md" unconditionally, which on a reducer-only tick describes
    a commit that touched no `execution.md` at all — and with the graveyard unread until #903,
    this string and the operator log are the only human-visible records this lane produces."""
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
    """NF2's second resolution point, resolved once at the pitfalls lane's own boundary
    (adapter half alone), refusing loudly rather than spending an empty set as an ordinary
    per-row membership "no" (RF6)."""
    systems = adapter_declared_systems(repo_root)
    if not systems:
        message = (
            f"pitfalls curation refused: {repo_root / ADAPTERS_REL} declares no systems; "
            "refusing to run the pitfalls lane against an empty declared set"
        )
        _log(message)
        raise LeadAuthorError(message)
    return systems


def _split_batch_by_membership(
    rows: list[dict], batch_ids: list[str], kept: set[str],
    *, handoffs: list[dict], changed: list[str],
) -> tuple[list[str], list[str]]:
    """The tick's three-way partition, ASYMMETRIC by row class (#870 M8 / FK-7).

    A SYSTEM row keeps `kept`-membership, unchanged: its lesson either had a handoff or it had
    nothing that could ever be taught, and an undeclared name is refused on the first tick.

    A REDUCER row is curated only when the offer was made AND taken — a reducer handoff was
    emitted and the commit's changed set carries the reducer literal. A row that meets neither
    is in NEITHER returned list: it stays in the queue, because a handoff is an offer and
    `lead_pitfalls.md`'s "skip that failure; never invent one" rule makes a no-edit tick a
    first-class outcome. Under the loose reading ("a handoff was emitted and the tick
    committed something") a shim row would rotate out stamped with the sha of a commit
    containing nothing about it — and its queue row is the only record the mistake ever
    produced.

    F3 — WHICH SEAM CARRIES THE CRITERION — IS RESOLVED HERE AS THE HANDOFF LIST (the judge's
    provisional). The alternatives were a `reducer_emitted: bool` and a builder-computed
    curated id set; the list keeps the criterion a question about the OFFER THAT WAS ACTUALLY
    MADE rather than about a re-derivation of it, and leaves this function the single place
    that answers "was this row curated". `changed` is the second conjunct and rides beside it
    under either reading.
    """
    reducer_taught = (
        any(h.get("surface") == "reducer" for h in handoffs) and REDUCER_REL in changed
    )
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
    return committed_ids, dropped_ids


def _deadletter_reason(row: dict) -> str:
    """Why THIS row is leaving the queue uncurated (#870 M9).

    One string served all three classes and was false of two of them: a systemless row names
    no system to be undeclared, and `../evil` is attacker-shaped and read identically to an
    ordinary onboarding miss. The reason is the only thing the graveyard record offers a
    human, so a false one is worse than a coarse one — and the undeclared class carries the
    NAME, because from inside a tick deployment skew and an invented name are
    indistinguishable and both go to human review."""
    system = str(row.get("system") or "").strip()
    if not system:
        return "no-system"
    if not is_system_name(system):
        return "malformed-system"
    return f"undeclared-system:{system}"


def _graveyard_dropped_rows(paths, rows: list[dict], dropped_ids: list[str]) -> None:
    """FK-2: a dropped row is TERMINAL and leaves a durable record for human review — the
    queue's own bump-and-retire ceiling (`drain.retire`) does not apply, since an undeclared
    name is refused on the FIRST tick, never retried."""
    if not dropped_ids:
        return
    ids = set(dropped_ids)
    key = paths.pitfalls.id_key
    entries = [
        {key: r[key], "deadletter_reason": _deadletter_reason(r), "row": r}
        for r in rows if r.get(key) in ids
    ]
    if entries:
        append_jsonl(  # lint-unguarded-tree-write: ok — learning_queue sidecar, host-side, outside every box mount
            _author_drain.graveyard_file(paths.pitfalls), entries,
        )


def run_pitfalls(
    *,
    paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS,
    invoke: Callable[..., int] | None = None,
    box=None,
) -> int:
    rows = _loop_persist.read_pitfalls(paths)
    # The gate counts DISTINCT MISTAKES, not rows (#840). The queue keeps one row per
    # failure, so a looping lead used to clear a threshold of 3 on a single lesson — and the
    # threshold is #823 O3's evidence that the channel learned N things, which a count of
    # failures is not.
    records = _loop_persist.merge_pitfalls(rows)
    threshold = _loop_config.pitfalls_threshold()
    if not _loop_persist.pitfalls_lane_is_open(records, threshold):
        if records:
            _log(
                f"pitfalls queue below threshold (n={len(records)} distinct mistake(s) "
                f"in {len(rows)} row(s), threshold={threshold}) — skipping curation"
            )
        return 0
    # From the RAW rows: rotation is what empties the queue, so it has to name every row
    # that fed a record, not just the exemplar the merge kept.
    batch_ids = [str(r["pitfall_id"]) for r in rows if r.get("pitfall_id")]
    repo_root = paths.repo_root
    # The WORKTREE's own sources, not the process's own checkout: this run commits into
    # `repo_root`, so this is the tree a handoff path may name. NF2's second resolution
    # point — the ADAPTER HALF ALONE — resolved ONCE here, before the agent is ever spawned.
    systems = _require_adapter_declared_systems(repo_root)
    handoffs = _build_pitfalls_handoffs(records, systems=systems)
    # `.get`, never a bare subscript: the reducer entry OMITS `system` (FK-9), so `kept` is
    # built from the SYSTEM half alone and a reducer handoff contributes no name to it.
    kept = {str(h["system"]) for h in handoffs if h.get("surface") == "system"}
    # A REDUCER row is excluded from this set whatever it is attributed to: it is routed by
    # its `query_id`, so its system name was never asked a membership question and reporting
    # it as "not in the declared adapter set" would be false of the one row this round
    # exists to teach. (The population is real — rows queued under an attributed system
    # before M5' deployed still carry one, F2.)
    dropped = sorted({
        s for r in records
        if not _is_reducer_row(r)
        and (s := str(r.get("system") or "").strip()) and s not in kept
    })
    if dropped:
        # Named, never dropped quietly: a batch that silently loses a system reads exactly
        # like one that had nothing to teach it. Names the ONE source this lane consulted
        # (NF2) — never the marker source, which this lane never reads.
        _log(
            f"pitfalls: dropped {len(dropped)} queued system(s) not in the declared adapter "
            f"set ({repo_root / ADAPTERS_REL}): {dropped}"
        )

    if not handoffs:
        # Nothing in this batch could ever be taught — no system entry and no reducer entry —
        # so there is no offer to hold rows against and the whole batch retires.
        _, dropped_ids = _split_batch_by_membership(
            rows, batch_ids, kept, handoffs=handoffs, changed=[],
        )
        _log(
            f"{len(records)} queued pitfall(s) in {len(batch_ids)} row(s) but none named a "
            f"system the adapter set at {repo_root / ADAPTERS_REL} declares — dropping"
        )
        _graveyard_dropped_rows(paths, rows, dropped_ids)
        _loop_persist.rotate_pitfalls(
            dropped_ids, None, paths=paths, category="consumed_unattributable",
        )
        return 0
    baseline_stray = _author_shared.changes_outside(repo_root, SKILLS_REL)
    # `len(rows)`, not `sum(occurrences)`: a queue row IS one occurrence, so the two are the
    # same number and only one of them costs a pass over the records. The SURFACES are named
    # rather than counted: a reducer-only tick is systemless by construction, so a line built
    # from attributed system names alone would tell an operator nothing happened (FK-6).
    _log(
        f"pitfalls curation: {len(records)} distinct mistake(s) "
        f"({len(rows)} failure(s)) offered across {len(handoffs)} surface(s): "
        f"{[h['path'] for h in handoffs]}"
    )

    rc = (invoke or _invoke_pitfalls_agent)(handoffs, repo_root=repo_root, box=box)
    if rc != 0:
        # RAISED, not returned (#719). The rc was the pitfalls channel's dominant failure
        # and nothing ever inspected it, so a repeatedly failing batch was discarded
        # silently and forever. `AuthorError` is a member of the drain's retire set, so
        # the fault now reaches the same bounded retirement every other queue has.
        raise _author_shared.AuthorError(
            f"pitfalls curator exited rc={rc}; leaving queue intact"
        )

    changed = _verify_pitfalls_state(repo_root, baseline_stray, systems=systems)
    sha = None
    if changed:
        sha = _author_shared.commit_corpus(
            repo_root, repo_root / "defender" / "skills",
            _pitfalls_commit_message(changed),
        )
    else:
        _log("pitfalls curator made no corpus edits (valid no-edit tick)")
    # AFTER the commit, not before it: FK-7's criterion for a reducer row is the handoff AND
    # the confirmed edit, and `changed` is the only place the second conjunct exists.
    committed_ids, dropped_ids = _split_batch_by_membership(
        rows, batch_ids, kept, handoffs=handoffs, changed=changed,
    )
    if committed_ids:
        _loop_persist.rotate_pitfalls(
            committed_ids, sha, paths=paths, category="consumed_committed",
        )
    if dropped_ids:
        _graveyard_dropped_rows(paths, rows, dropped_ids)
        _loop_persist.rotate_pitfalls(
            dropped_ids, None, paths=paths, category="consumed_unattributable",
        )
    held = len(batch_ids) - len(set(committed_ids)) - len(set(dropped_ids))
    _log(
        f"pitfalls curation done; commit={(sha or 'none')[:12]}, "
        f"taught {len(changed)} surface(s): {changed}, "
        f"rotated {len(set(committed_ids)) + len(set(dropped_ids))} row(s) out of the queue "
        f"({len(dropped_ids)} unattributable, {held} held for a later tick)"
    )
    return 0
