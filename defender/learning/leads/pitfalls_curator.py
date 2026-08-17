#!/usr/bin/env python3
from __future__ import annotations

import difflib
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
from defender._io import TEXT_READ_ERRORS, append_jsonl, read_text_utf8
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

LEAD_PITFALLS_PROMPT = LEARNING_DIR / "leads" / "lead_pitfalls.md"

#: The REDUCER SURFACE — the second edit target this lane gained (#870 M6), and the one
#: literal `_pitfalls_path_rule` admits beyond a declared system's `execution.md`. Chosen
#: because `skills/gather/SKILL.md` tells the gather subagent to Read it BEFORE it writes the
#: SQL — the same before-the-attempt criterion that put system pitfalls in `execution.md`.
REDUCER_REL = "defender/skills/gather/defender-sql.md"

#: The one section a curator addition may land in, on either surface. `_pitfalls_content_rule`
#: enforces it on the reducer surface; the prompt asks for it on both.
PITFALLS_SECTION = "## Common pitfalls"

#: A setext heading's underline — `Title` on one line, `===` (H1) or `---` (H2) on the next.
#: Both outrank `## Common pitfalls`, so `_outline` has to close the section on them the same
#: way it does on their ATX spellings; matched only after a non-blank, non-heading line, which
#: is what separates a setext underline from a thematic break.
_SETEXT_UNDERLINE_RE = re.compile(r"^(?:=+|-+)[ \t]*$")


#: Is this queued row the REDUCER's mistake rather than a system's? THE lane predicate, and
#: bound here rather than restated: `persist` owns it because the merge key and the arrival
#: gate ask it too, and three modules spelling one question three ways is what let a pre-M5′
#: attributed reducer row be routed to the reducer surface here, refused the lane there, and
#: split per-system by the merge (#870, review). Re-exported under the module's own name so
#: this file's readers still find it where they look for it.
_is_reducer_row = _loop_persist.is_reducer_row


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


def _outline(lines: list[str]) -> tuple[list[tuple[int, str]], list[str | None]]:
    """The document's `##` headings as `(line index, text)`, and the section each of its
    lines sits in.

    One pass for both, because they are one reading of the same structure and two walks are
    two places for the answers to disagree. Takes the SPLIT lines rather than the text: the
    section index is positional, so every reader of it already holds the same list and a
    second split is a second chance for the indices to mean different lines.

    FENCE-AWARE through `_corpus._FENCE_RE`, the corpus walk's own fence, and that is a rule
    and not a nicety: a fenced block's contents are prose. A curator that retired a real
    heading and re-planted its text inside a ``` block under `## Common pitfalls` would
    otherwise have that line counted as the heading surviving — the surviving-sections check
    passing on a document that no longer carries the section. The HEADING test stays
    `startswith("## ")` rather than `_corpus._HEADING_RE`: the regex needs a non-empty title,
    so a bare `## ` line would leave the section open and admit prose after it, and this gate
    wants the stricter reading.

    A SECTION ALSO CLOSES ON ANYTHING THAT OUTRANKS IT, and that is what makes the placement
    rule below true rather than nearly true. A walk that only ever opened a section on `## `
    reads every line after `## Common pitfalls` as being inside it — including an `# H1`, or a
    setext `Title` over `===`/`---`, which markdown renders as a NEW top-level section that the
    `##` above no longer owns. That is the whole escape: a bullet is untrusted text on the one
    file every reduce reads before every attempt, so a curator (or the alert-derived digest
    driving it) could plant `# How to read this file` at the end and have the gate certify it
    as landing "under `## Common pitfalls`". Closing on the higher-ranked heading makes such a
    line land in NO section, which is exactly what the placement rule refuses. A setext
    underline closes the section from its TITLE line, which this walk has already passed, so
    the title's own entry is corrected in place.

    The heading's INDEX rides beside its text because the placement rule below asks WHERE a
    heading sits, not just whether it survived — and a second scan for `## ` over the same
    lines would be a second reading of this structure, i.e. the drift this one pass exists to
    prevent (a fenced `## …` line is prose here and would be a heading there).
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
            # Only after a non-blank, non-ATX line: a `---` or `===` run that follows a blank
            # line is a thematic break, not a heading, and reading it as one would refuse an
            # ordinary edit.
            section = None
            sections[-1] = None
        sections.append(section)
    return headings, sections


def _line_ops(
    old: list[str], new: list[str],
) -> tuple[list[int], list[int], list[tuple[int, int]]]:
    """The indices this edit ADDED (in `new`), the ones it REMOVED (in `old`), and the
    `(old, new)` index pairs of the lines it KEPT.

    A replaced line counts as BOTH added and removed: the rule below is about where new prose
    lands and about what it displaced, and prose that overwrote an existing line landed
    exactly where that line was and took it with it. The kept pairs are the third answer the
    same walk already knows — which surviving line is which — and the re-parenting check needs
    it to ask where a line that did not change now SITS."""
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


def _readable_pair(repo_root: Path, path: str) -> tuple[str, str]:
    """The document as COMMITTED and as the curator left it, or this rule's own refusal.

    Split out of `_pitfalls_content_rule` so the structural comparisons below read as one
    list of invariants rather than as a list with a four-branch read in front of it: this half
    asks only "are there two documents to compare", and every one of its answers is the same
    refusal shape. The frontmatter rides here because it is the one comparison that reads the
    RAW text rather than the line walk — the rest of the rule works off `splitlines()`.
    """
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
    # Through the pinned reader, and NARROWED: a curator that leaves bytes this gate cannot
    # decode has failed the same way it fails by leaving a directory, and the refusal has to
    # reach the caller as this rule's own error rather than as a `UnicodeDecodeError` escaping
    # the gate into the batch-retire path.
    try:
        current = read_text_utf8(full)
    except TEXT_READ_ERRORS as e:
        raise LeadAuthorError(
            f"pitfalls curator left {path} unreadable as UTF-8 text ({e}); refusing to commit"
        ) from e
    if _frontmatter_block(current) != _frontmatter_block(committed):
        raise LeadAuthorError(
            f"pitfalls curator rewrote {path}'s frontmatter block; refusing to commit "
            "(the reducer surface's metadata is not a pitfalls edit)"
        )
    return committed, current


def _pitfalls_content_rule(repo_root: Path, xy: str, path: str) -> None:
    """The content half of the gate (#870 FK-2), the mirror of `lead_author._skills_content_
    rule`: everything above answers "may the curator touch this path", this answers "is what
    it wrote still the document".

    Scoped to the REDUCER SURFACE, because that is the target this round opens and it is the
    one corpus write target with no correspondence audit (C13, refuted — it is not a
    `verb_roster.model_read_surface`), no scaffold rule (FF-12, `_scaffold_rules` is scoped to
    `skills/{system}/SKILL.md`) and, until now, no lane content rule. Five things must
    survive a curator's tick: the YAML frontmatter block, every `##` section the committed
    file already carried, every non-blank line those sections already held, the placement of
    everything added — under `## Common pitfalls`, created AT THE END if absent, where "under"
    is read at the section's real markdown extent, so an added `# H1` or setext heading is
    OUTSIDE it rather than a line the section swallows — and the BOUNDARY of
    that section over the lines the document already had. The document is APPEND-ONLY outside
    that one section, in both directions: a rule that watched only what arrived would admit a
    tick that emptied every section it left the heading of, and one that watched both but not
    the boundary would admit a two-tick edit that moved the boundary first.

    Markdown INSIDE a bullet is deliberately NOT sanitized. The same untrusted-text-to-corpus
    laundering already exists on every `execution.md` and re-keying it is a round of its own;
    what this round takes instead is the prompt requirement that a reducer bullet name the
    payload shape it applies to, since this is the one file EVERY system's reduce reads before
    EVERY attempt.
    """
    if path != REDUCER_REL or "D" in xy:
        return
    committed, current = _readable_pair(repo_root, path)
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
    # The other half of "appended, never written over", and it is not the heading check
    # restated: the headings surviving says nothing about what stood UNDER them. Without this
    # a tick may empty every existing section, leave the three headings as bare stubs, and
    # land one bullet under `## Common pitfalls` — a gutted document on the one file EVERY
    # system's reduce reads before EVERY attempt, admitted by a gate whose whole claim is that
    # the document survives. Pruning stays legal exactly where the prompt grants it: inside
    # `## Common pitfalls`, the section this lane owns.
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
    # The BOUNDARY of the lane-owned section, and without it the two checks above are asked
    # about a scope the curator itself just moved. Planting `## Common pitfalls` mid-document
    # is ONE added line and both checks admit it — a heading's own section is itself, and no
    # committed line was touched — but every line between it and the next `##` is now INSIDE
    # the one section this lane may prune, so the NEXT tick empties a section whose heading
    # survives and the gutted-document refusal above never fires. So: a line the committed
    # document already carried may not change which side of that boundary it sits on. Says
    # nothing about where a HAND-added section lands, which is what keeps the rule reading the
    # real document rather than a constant.
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
    # AT THE END, which is what the refusal above already says and what `lead_pitfalls.md`
    # asks for — and until now only the reparenting half of it was enforced. Planting the
    # heading IMMEDIATELY BEFORE an existing `##` reparents nothing (the next heading closes
    # it on the same line the committed document already closed it), so the boundary check
    # admits it and an alert-derived bullet lands ahead of the guidance this document exists
    # to give — on the one file EVERY system's reduce reads before EVERY attempt, where order
    # is what the reader spends its attention in. Asked ONLY of a heading THIS TICK ADDED:
    # where a HAND-added section sits is not this lane's business, the same scope the boundary
    # check keeps.
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
    """Was this tick's curator offered the surface it wrote (#870, review)?

    Asked of the REDUCER LITERAL alone, and it is a different question from the path half's.
    `_pitfalls_path_rule` adjudicates the lane's VOCABULARY — is this string a path the lane
    may ever write — and its answer is a constant of the deployment. This asks whether the
    target was opened on THIS TICK, which is a fact about the batch, so it is neither a
    property of the path nor something the path rule's signature should have to carry.

    Why it exists: the literal allowance made the reducer surface writable on every tick,
    including one whose batch held no reducer row at all. The curator's static prompt names
    that path unconditionally, and each failure's `stderr_digest` — alert-derived text, on the
    one corpus file EVERY system's reduce reads before EVERY attempt — is in its context. A
    digest carrying "also record this in <the reducer surface>" was therefore obeyable on a
    batch of pure system rows, admitted by the gate on the literal, and invisible to FK-7 (which
    computes `reducer_taught` from the offer and so sees none). Before this round the same
    path was refused outright. The system half needs no mirror of this: an `execution.md` is
    already bounded by the DECLARED set, and a curator writing a declared system's file on a
    tick that did not queue that system is writing a legal document to a legal target.
    """
    if path == REDUCER_REL and not reducer_offered:
        raise LeadAuthorError(
            f"pitfalls curator wrote {path} on a tick that offered no reducer handoff; "
            "refusing to commit (the reducer surface is opened by a queued "
            "defender-sql mistake, never by the prompt alone)"
        )


def _pitfalls_rule(
    repo_root: Path, xy: str, path: str, *,
    systems: frozenset[str], reducer_offered: bool,
) -> None:
    """The whole per-path gate: may the lane write this path at all, was this tick offered it,
    and is what the curator wrote still the document.

    Composed rather than folded, exactly as the sibling lane's `_skills_rule` is: the halves
    ask different questions, and each must not read a path an earlier one has already refused.
    The OFFER half sits between them — after the vocabulary check, because a path outside the
    lane's scope is refused by scope whatever the batch held, and before the content check,
    because a document the curator was never invited to touch is not a document whose diff is
    worth reading."""
    _pitfalls_path_rule(xy, path, systems=systems)
    _pitfalls_offer_rule(path, reducer_offered=reducer_offered)
    _pitfalls_content_rule(repo_root, xy, path)


def _verify_pitfalls_state(
    repo_root: Path, baseline_stray: list[str], *,
    systems: frozenset[str], reducer_offered: bool,
) -> list[str]:
    """`reducer_offered` is REQUIRED rather than defaulted, and that is the point: a default
    would have to be one of "every tick may write the reducer surface" (the hole this closes)
    or "no tick may" (which breaks the lane), and both are wrong for a caller that forgot to
    pass it. Every call site names the tick it is verifying."""
    return _verify_corpus_scope(
        repo_root, baseline_stray, actor="pitfalls curator",
        rule=partial(
            _pitfalls_rule, repo_root,
            systems=systems, reducer_offered=reducer_offered,
        ),
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
    *, reducer_offered: bool, changed: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """The tick's three-way partition, ASYMMETRIC by row class (#870 M8 / FK-7).

    THREE lists, because the partition is three-way: the ids curated, the ids dropped, and the
    ids HELD. The held half was returned by set arithmetic at the caller
    (`set(batch_ids) - committed - dropped`) while this function had already computed it —
    two derivations of one partition, which is the shape this round spent its review ending
    everywhere else in the lane.

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

    F3 — WHICH SEAM CARRIES THE CRITERION — IS RESOLVED AS THE `reducer_emitted: bool` OF THE
    THREE F3 NAMED, and it is passed in rather than re-derived from the handoff list here. The
    round's review is why: the same "was a reducer handoff emitted" question is now also the
    commit gate's (`_pitfalls_offer_rule`), and two readers deriving one fact from one list
    twice is the shape that already cost this lane three disagreeing spellings of "is this the
    reducer's row". One derivation, at the tick's own scope, handed to both. `changed` is the
    second conjunct and rides beside it under either reading; this function is still the single
    place that answers "was this row curated".
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
    # `- curated` because a duplicate `pitfall_id` on disk could put one id on both sides, and
    # a row that WAS curated is not also held: rotating it twice is the double-count the
    # caller's own set arithmetic was written to avoid.
    return committed_ids, dropped_ids, sorted(held_ids - curated)


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


#: The graveyard reason a held reducer row finally retires under. Its own class, beside
#: `_deadletter_reason`'s three and `drains._retire_pitfalls_batch`' `batch-error:`, because it
#: is the one retirement that follows no fault at all: the tick worked, the offer was made, and
#: the curator declined it — which is a legitimate outcome the ceiling exists to bound rather
#: than an error to diagnose.
HELD_CEILING_REASON = "reducer-offered-never-taught"

#: The queue-row field counting how many ticks OFFERED this row its surface and had the
#: curator decline. Distinct from `attempts`, which is the lane's FAULT counter and is bumped
#: for the whole batch by `drains._retire_pitfalls_batch` on any tick that raised: a decline is
#: not a fault, and one counter serving both retires a row on its first decline whenever
#: unrelated infra faults happened to spend its budget first.
OFFERS_DECLINED_KEY = "offers_declined"


def _retire_exhausted_holds(paths, held_ids: list[str]) -> int:
    """Bump every held row once, and retire the ones that have now been offered too often.

    FK-7 makes a no-edit reducer tick a first-class outcome — `lead_pitfalls.md`'s "skip that
    failure; never invent one" — and leaves the rows in the queue. What it did not give them is
    an EXIT. A row the curator can never turn into a concrete fix (PO-R2's own frequent shape,
    an undiagnosable reduce) satisfied the arrival gate on its own occurrences, was offered,
    was declined, and came back byte-identical on the next tick: the wake gate stayed open, the
    curator agent was re-spawned every drain pass, and nothing ever progressed. Measured over
    consecutive ticks before this: the queue unchanged, `attempts` still unset, one LLM spawn
    per pass, forever. Every OTHER exit from this queue is bounded — `consumed_committed` on a
    taught row, `consumed_unattributable` plus the graveyard on an undeclared name, the
    `batch-error:` ceiling on a faulting batch — and the hold was the one that was not.

    So the hold KEEPS its meaning and gains a ceiling: the row survives being declined, and
    survives being declined again, and leaves on the same `author_max_attempts()` the rest of
    the lane retires on, with a durable record naming what happened to it. `drain.retire` is
    the shared primitive that does exactly this, so the bump, the graveyard entry and the
    `consumed_retired` ledger row are the channel's own — not a fourth hand-rolled rotation.

    COUNTED ON ITS OWN COUNTER, and that is what makes the ceiling mean what it says. The bump
    happens only on a tick that actually made the offer — the caller reaches here past the
    arrival gate and the spawn — but `drain.retire`'s default `attempts` is the LANE'S FAULT
    counter, which `drains._retire_pitfalls_batch` bumps for every row in the batch on any tick
    that raised. Sharing it made each ceiling arrive early in the other's traffic: two
    infra-faulting ticks spent a freshly-queued row's whole offer budget, so its FIRST decline
    retired it terminally with its lesson never taught — verbatim the loss FK-7's hold exists
    to prevent, reintroduced by the bound meant to complete it. `OFFERS_DECLINED_KEY` therefore
    counts declines and nothing else, and the two ceilings are independent: a row may fault its
    way out, or be declined its way out, and neither spends the other's budget.
    """
    if not held_ids:
        return 0
    outcome = _author_drain.retire(
        channel=paths.pitfalls,
        batch_ids=held_ids,
        reason=HELD_CEILING_REASON,
        max_attempts=_loop_config.author_max_attempts(),
        counter_key=OFFERS_DECLINED_KEY,
    )
    if outcome.retired:
        _log(
            f"pitfalls: retired {len(outcome.retired)} held reducer row(s) at the offer "
            f"ceiling ({_loop_config.author_max_attempts()} tick(s) offered and declined): "
            f"{list(outcome.retired)}"
        )
    return len(outcome.retired)


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
    # ONE derivation of "was the reducer surface opened on this tick", at the tick's own scope,
    # spent by three readers: the commit gate (`_pitfalls_offer_rule`, which refuses the
    # literal on a tick that never offered it), FK-7's partition, and the hold's ceiling below.
    reducer_offered = any(h.get("surface") == "reducer" for h in handoffs)
    # The `surface` FILTER runs first and is what makes the subscript safe: the reducer entry
    # OMITS `system` (FK-9), so `kept` is built from the SYSTEM half alone and a reducer
    # handoff contributes no name to it.
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
        _, dropped_ids, _ = _split_batch_by_membership(
            rows, batch_ids, kept, reducer_offered=reducer_offered, changed=[],
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

    changed = _verify_pitfalls_state(
        repo_root, baseline_stray, systems=systems, reducer_offered=reducer_offered,
    )
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
    committed_ids, dropped_ids, held_ids = _split_batch_by_membership(
        rows, batch_ids, kept, reducer_offered=reducer_offered, changed=changed,
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
    # Every count off the same DISTINCT id sets: `batch_ids` is read from the queue file and
    # a repeated `pitfall_id` there would otherwise make the counts a difference between a row
    # count and two id counts, i.e. report rows held that are not.
    rotated = set(committed_ids) | set(dropped_ids)
    retired = _retire_exhausted_holds(paths, held_ids)
    # The retired rows LEFT on this tick, so they are not also "held for a later tick" — the
    # two numbers partition the held set rather than overlapping it.
    _log(
        f"pitfalls curation done; commit={(sha or 'none')[:12]}, "
        f"taught {len(changed)} surface(s): {changed}, "
        f"rotated {len(rotated) + retired} row(s) out of the queue "
        f"({len(set(dropped_ids))} unattributable, "
        f"{len(held_ids) - retired} held for a later tick"
        + (f", {retired} retired at the hold ceiling" if retired else "")
        + ")"
    )
    return 0
