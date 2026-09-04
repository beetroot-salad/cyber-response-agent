"""#996 — `record`, MAIN's only document verb.

`record(text)`: append MAIN's prose verbatim (through the ordinary write gate, D11's verb name
"record"); hand the clerk the grammar+catalog, the document so far, the pending queue, this
prose and the previous call's GAPS; land the clerk's returned rows through the same gate;
retry a STRUCTURAL refusal (the clerk can fix it alone) and STOP on a JUDGMENT-only one (D7 —
only MAIN can settle it, in prose, on the next `record`); repair a warn-accepted block inside
the same call (D2); return MAIN a receipt.

Repair rounds and round-loop rounds draw from ONE shared budget of six clerk calls per
`record` call (not two independent pools) — `_round_budget` below is the single counter both
halves decrement.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from pydantic_ai.exceptions import ModelRetry

from defender._io import read_text_utf8

from ..clerk import CLERK_ROUND_BUDGET, ClerkMalformedReply
from ._deps import AgentDeps
from ._document import (
    _investigation_path,
    _tool_append_block,
    _tool_fix_row,
    committed_document_refusal,
    flagged_diagnostics,
    flagged_write_refusal,
    repairable_diagnostics,
)

#: id-owning cells — a row's own id column, the families the receipt names.
_ID_RE = re.compile(r"^(?:[vehl]-\d+|ac\d+|ip\d+)")
#: A block header line — `:R attr_updates [...]`, `:V prologue.vertices [...]`, etc.
_BLOCK_HEADER_RE = re.compile(r"^:[A-Za-z]\s+([\w.]+)")
#: `:R attr_updates`'s own first column is `resolved_by` — a REFERENCE to the lead that
#: resolved it, never a newly-declared id — so `_extract_ids` must not read it as one, or a
#: row citing `l-001` as its resolver gets reported as having committed `l-001` itself.
_REFERENCE_ONLY_BLOCK = "attr_updates"
_GAPS_MARK = "GAPS:"
_PHASE_RE = re.compile(r"^##\s+(\S.*)$", re.MULTILINE)
#: The runtime loop's own closed phase vocabulary (`SKILL.md`: ORIENT -> PLAN -> GATHER ->
#: ANALYZE -> REPORT). `_current_phase` matches a `## ` line's FIRST token against this set —
#: not every `## ` line in the document is a phase transition. The harness seeds a
#: `## lead-0 (l-000) — harness-authored, declared before the investigation begins` heading
#: before MAIN's first turn (#964); a bare `## ` scan reads "lead-0" as the phase in force and
#: S6 drops a `:T conclude` block that has done nothing wrong.
_PHASE_NAMES = frozenset({"ORIENT", "PLAN", "GATHER", "ANALYZE", "REPORT"})
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_GAP_MAX_CHARS = 400
_REFUSAL_TRUNC = 600

OUTCOME_COMMITTED = "record: committed rows for "
OUTCOME_COMMITTED_ANON = "record: committed rows (no id-carrying row)"
OUTCOME_NOTHING = "record: nothing to commit"
OUTCOME_PENDING = "record: rows pending (provider fault: "
OUTCOME_HELD = "record: rows held — the close price is owed:"
OUTCOME_GIVEUP = "record: rows could not be committed after "


def _extract_ids(rows_text: str) -> list[str]:
    """Every DECLARED id in `rows_text` — never a REFERENCE. Block-aware: `:R attr_updates`'s
    leading cell is `resolved_by`, an existing lead's id cited as this row's resolver, not a
    new one this block commits."""
    ids: set[str] = set()
    in_reference_block = False
    for line in rows_text.splitlines():
        stripped = line.strip()
        header = _BLOCK_HEADER_RE.match(stripped)
        if header:
            in_reference_block = header.group(1) == _REFERENCE_ONLY_BLOCK
            continue
        if in_reference_block:
            continue
        m = _ID_RE.match(stripped)
        if m:
            ids.add(m.group(0))
    return sorted(ids)


def _current_phase(document: str) -> str:
    """The phase in force — the document's own LAST recognized-phase `## ` heading — never the
    calling prose's own header (HD-3): read once at the START of `record`, before this call's
    own prose has landed, so a phase word the model's OWN just-appended prose happens to carry
    never counts as the document moving there.

    Only a `## ` line whose first token is in `_PHASE_NAMES` counts — a `## ` heading that
    isn't one of the loop's five names (the harness's lead-0 declaration, say) is not a phase
    transition and must not be read as one."""
    for line in reversed(_PHASE_RE.findall(document)):
        stripped = line.strip()
        if not stripped:
            continue
        token = stripped.split()[0].upper()
        if token in _PHASE_NAMES:
            return token
    return ""


def _screen_conclude_fences(text: str, phase: str) -> str:
    """S6, applied to text BEFORE it reaches the write gate: excise any fenced ```invlang
    block whose body carries a `:T conclude` while the phase in force is not `## REPORT` —
    security-relevant because the close gate reads the PARSED companion regardless of who
    wrote the bytes, so a conclude fence MAIN quotes into its own prose would otherwise never
    meet this guard at all."""
    if phase == "REPORT" or not phase or ":T conclude" not in text:
        return text
    from defender.skills.invlang.parser import scan_fences

    scan = scan_fences(text)
    drop = [span for span, body in zip(scan.spans, scan.bodies, strict=True)
            if ":T conclude" in body]
    if not drop:
        return text
    out: list[str] = []
    cursor = 0
    for start, end in drop:
        out.append(text[cursor:start])
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def _sanitize_gap(text: str) -> str:
    cleaned = _CONTROL_RE.sub("", text)
    if len(cleaned) > _GAP_MAX_CHARS:
        cleaned = cleaned[:_GAP_MAX_CHARS] + "…"
    return cleaned


def _split_clerk_reply(raw: str) -> tuple[str, list[str]]:
    """The clerk's fenced rows, VERBATIM (the clerk's own reply already carries real
    ```invlang fences — nothing here re-wraps them), and the `GAPS:` bullets."""
    idx = raw.find(_GAPS_MARK)
    if idx == -1:
        return raw.strip(), []
    rows_text = raw[:idx].strip()
    tail = raw[idx + len(_GAPS_MARK):]
    first_line, _, rest = tail.partition("\n")
    gaps: list[str] = []
    inline = first_line.strip()
    if inline and inline.lower() != "none":
        gaps.append(inline)
    for line in rest.splitlines():
        line = line.strip()
        # ONE bullet marker stripped, never a run of them: `lstrip("-* ")` would also eat a
        # gap whose own text starts with `-`/`*` (AR-14's own fixture, "*** unbalanced
        # [markup"), silently mangling the verbatim bullet O2 requires.
        if line.startswith(("-", "*")) and (len(line) == 1 or line[1] == " "):
            item = line[1:].strip()
            if item and item.lower() != "none":
                gaps.append(item)
    return rows_text, gaps


def _parse_repair_reply(raw: str) -> list[tuple[str, str]]:
    """`fix_row(old, new)` pairs, one per line, each a real Python string literal pair — the
    exact wire `_clerk_996.repair_reply` writes. Lines that do not parse are skipped rather
    than raised on: best effort over a reply that answered some rows and not others."""
    pairs: list[tuple[str, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        m = re.match(r"fix_row\((.*)\)\s*$", line)
        if not m:
            continue
        try:
            args = ast.literal_eval(f"({m.group(1)})")
        except (ValueError, SyntaxError):
            continue
        if isinstance(args, tuple) and len(args) == 2:
            pairs.append((str(args[0]), str(args[1])))
    return pairs


def _is_malformed_repair_reply(raw: str) -> bool:
    """A NON-EMPTY repair reply carrying no `fix_row(` call at all — what a model that lost the
    format answers in prose. An EMPTY reply is the clerk legitimately DECLINING the repair,
    never malformed."""
    return bool(raw) and raw.strip() != "" and "fix_row(" not in raw


def _grammar_and_catalog(defender_dir: Path) -> str:
    from .. import orient as orient_mod

    grammar = orient_mod._invlang_grammar(defender_dir) or ""
    catalog = orient_mod._catalog()
    return (grammar + "\n\n## invlang catalog (closed slots)\n\n" + catalog).strip()


def _render_pending(pending: list[tuple[str, str | None, tuple[str, ...]]]) -> str:
    if not pending:
        return ""
    parts = []
    for prose, block, owed in pending:
        lines = [f"- prose: {prose}"]
        if block:
            lines.append(
                "  a held block from a previous call — it MAY ALREADY BE COMPILED in the "
                f"document above; check before re-emitting:\n{block}"
            )
        if owed:
            lines.append("  owed:\n" + "\n".join(f"    - {o}" for o in owed))
        parts.append("\n".join(lines))
    return "\n\n".join(parts)


def _round_prompt(  # noqa: PLR0913 — the round loop's own full slot set, named once
    instructions: str, grammar_catalog: str, document: str, pending: list, prose: str,
    last_gaps: list[str], refusal: str | None,
) -> str:
    parts = [
        instructions,
        grammar_catalog,
        "## investigation.md so far\n\n" + (document.strip() or "(empty)"),
        # THE ONE SLOT LABEL THE TURN'S GRAMMAR IS PINNED ON (`_clerk_996.PENDING_LABEL`):
        # a bare `pending:` line, empty when nothing is pending, bounded below by another
        # bare label so the empty rendering is observable rather than swallowed to the end
        # of the turn.
        "pending:\n" + _render_pending(pending) + "\nend_pending:",
    ]
    if last_gaps:
        parts.append(
            "## your previous call's GAPS — answer these if this prose does\n\n"
            + "\n".join(f"- {g}" for g in last_gaps)
        )
    parts.append("## prose just recorded — compile this into rows\n\n" + prose)
    if refusal:
        parts.append(
            "## the validator refused your last attempt — read this and fix it\n\n" + refusal
        )
    parts.append(
        "Return ONLY: one or more fenced ```invlang blocks recording what the prose "
        "asserts, then a line `GAPS:` followed by a bulleted list of what could not be "
        "grounded in a row — or `GAPS: none`."
    )
    return "\n\n".join(parts)


def _repair_prompt(instructions: str, grammar_catalog: str, diags: tuple, prose: str) -> str:
    from defender._artifact_schema import render_diagnostic

    flagged_text = "\n".join(render_diagnostic(d) for d in diags)
    parts = [
        instructions,
        grammar_catalog,
        "## flagged rows — repair or delete each one with fix_row(old_row, new_row)\n\n"
        + flagged_text,
        "## the prose that was being recorded when this window opened\n\n" + prose,
        "Return ONLY: one `fix_row(old_row, new_row)` call per line, one per flagged row "
        "you can address — or nothing at all if you cannot repair any of them.",
    ]
    return "\n\n".join(parts)


class _Budget:
    """The ONE shared pool of six clerk calls a `record` call spends, repair rounds and
    round-loop rounds alike (§7's settled reading, over an author's own hedge)."""

    def __init__(self) -> None:
        self.left = CLERK_ROUND_BUDGET
        self.repair_rounds = 0
        self.rounds = 0

    def spend_repair(self) -> None:
        self.left -= 1
        self.repair_rounds += 1

    def spend_round(self) -> None:
        self.left -= 1
        self.rounds += 1


async def _repair_loop(
    deps: AgentDeps, caller: Any, budget: _Budget, prose: str, grammar_catalog: str,
) -> tuple[bool, str | None]:
    """Runs repair rounds while the window is open and the shared budget/ceiling allow another
    call. Returns `(closed, fix_row_refusal_or_None)`. Raises whatever `caller.call` raises
    (a transport fault) or `ClerkMalformedReply` — both are provider-fault shapes the caller
    handles identically."""
    while flagged_diagnostics(deps) and budget.left > 0 and caller.allowed():
        diags = flagged_diagnostics(deps)
        prompt = _repair_prompt(caller.instructions, grammar_catalog, diags, prose)
        budget.spend_repair()
        raw = await caller.call(prompt)
        if _is_malformed_repair_reply(raw):
            raise ClerkMalformedReply(raw)
        pairs = _parse_repair_reply(raw)
        if not pairs:
            continue
        try:
            for old, new in pairs:
                _tool_fix_row(deps, old, new)
        except ModelRetry as e:
            return False, str(e)
    return (not flagged_diagnostics(deps)), None


def _append_trace(run_dir: Path, row: dict) -> str | None:
    """Best-effort append to `wire_logs/clerk_trace.jsonl` — its own failure never fails a
    `record`, and is named in the receipt rather than swallowed (O5)."""
    import json

    from defender._io import write_guarded
    from defender._run_paths import RunPaths

    path = RunPaths(Path(run_dir)).wire_log.parent / "clerk_trace.jsonl"
    try:
        write_guarded(path, json.dumps(row) + "\n", mode="append")
        return None
    except OSError as e:
        note = f"clerk_trace.jsonl append failed ({e!r})"
        print(f"[tools/_clerk] {note}")
        return note


def _flagged_section(deps: AgentDeps) -> str:
    flagged = flagged_diagnostics(deps)
    if not flagged:
        return ""
    text = flagged_write_refusal("record", flagged)
    # Only the diagnostic list carries into section (3) — most of `flagged_write_refusal`'s
    # own text belongs to a REFUSAL (it names `fix_row`, a verb MAIN's roster does not hold),
    # and this is a receipt telling MAIN what is still open, not a refusal of this call.
    diag_lines = "\n".join(
        ln for ln in text.splitlines() if ln.strip().startswith("- ") or ln.strip().startswith("row:")
    )
    return "FLAGGED: `record` is blocked while investigation.md carries a flagged row:\n\n" + diag_lines


async def _tool_record(  # noqa: C901, PLR0912, PLR0915 — one state machine (design v2 flow 1:
    # repair round, prose append, the D7 round loop, S6's guard, the pending queue, the
    # receipt) whose steps share too much live state (the shared clerk-call budget, the
    # document snapshot, the trace row being built) to split without threading a dozen
    # parameters between fragments that only ever run once, in this order, for this call
    deps: AgentDeps, text: str, caller: Any,
) -> str:
    run_dir = deps.run_dir
    inv_path = _investigation_path(deps)
    defender_dir = deps.defender_dir
    grammar_catalog = _grammar_and_catalog(defender_dir)

    # Read BEFORE this call's own append attempt (HD-3): the phase in force is the document's
    # own LAST `## ` heading as it stood when this call began, never MAIN's just-supplied
    # prose — the same value S6's guard is keyed on below, so the trace records the phase the
    # guard actually used rather than re-deriving a different one after the fact.
    document_before = read_text_utf8(inv_path) if inv_path.is_file() else ""
    phase_at_call = _current_phase(document_before)
    budget = _Budget()

    caller.record_n += 1
    trace: dict = {
        "n": caller.record_n, "phase_header": phase_at_call,
        "repair_rounds": 0, "rounds": 0, "refusals": [], "stopped_on_judgment": False,
        "held": False, "gaps": [], "prose_chars": len(text), "rows_chars": 0,
        "committed": False, "pending": 0, "ids": [],
    }

    def finish(sections: list[str], *, committed: bool, held: bool, stopped: bool) -> str:
        trace["committed"] = committed
        trace["held"] = held
        trace["stopped_on_judgment"] = stopped
        trace["pending"] = len(caller.pending)
        note = _append_trace(run_dir, trace)
        if note:
            sections.append(f"(note: {note})")
        return "\n\n".join(s for s in sections if s)

    async def pend(detail: str) -> str:
        dropped = caller.push_pending((text, None, ()))
        # The prose's own lead rides along so consecutive pending receipts are not
        # byte-identical — each names what it pended, which is also the honest content MAIN
        # needs to tell one held call from the next.
        sections = [f"{OUTCOME_PENDING}{detail}) — prose: {text[:80]!r}"]
        if dropped is not None:
            # HD-4: the cap's eviction is NAMED, not silent — a dropped entry is prose that
            # was never compiled and never will be (O2's own failing condition).
            from ..clerk import PENDING_CAP

            sections.append(
                f"record: dropped the oldest pending entry to stay under the cap of "
                f"{PENDING_CAP}: {dropped[:200]!r}"
            )
        return finish(sections, committed=False, held=False, stopped=False)

    # ---------------------------------------------------------------------------------
    # step 0: repair round, only if the window is already open when this call begins
    # ---------------------------------------------------------------------------------
    if flagged_diagnostics(deps):
        try:
            closed, fix_refusal = await _repair_loop(
                deps, caller, budget, text, grammar_catalog)
        except ClerkMalformedReply:
            return await pend("the clerk's reply could not be parsed as a repair answer")
        except Exception as e:  # noqa: BLE001 — any non-parsed-response, non-ModelRetry fault
            return await pend(f"{type(e).__name__}: {e}")
        trace["repair_rounds"] = budget.repair_rounds
        if not closed:
            flagged = flagged_diagnostics(deps)
            note = (
                f"the repair call was refused — {fix_refusal}" if fix_refusal is not None
                else f"{len(flagged)} row(s) still flagged after {budget.repair_rounds} round(s)"
            )
            sections = [f"record: {note}", _flagged_section(deps)]
            return finish(sections, committed=False, held=False, stopped=False)

    # ---------------------------------------------------------------------------------
    # step 1: MAIN's own prose lands first, through the ordinary gate, verb name "record"
    # ---------------------------------------------------------------------------------
    # S6 screens the PROPOSED DOCUMENT, not just the clerk's output (a security finding, not
    # an ambiguity): a `:T conclude` fence MAIN smuggles into its OWN prose meets the same
    # phase guard a clerk-emitted one does, before it ever reaches disk.
    screened_text = _screen_conclude_fences(text, phase_at_call)
    # Captured BEFORE this call's own append attempt: is the document ALREADY unrepairable,
    # independent of what MAIN is about to send? That is the one condition under which a
    # refusal on MAIN's own bytes gets enriched below — a defect this specific append
    # introduces reaches MAIN unchanged (flow 1.1).
    pre_existing_defect = committed_document_refusal(deps)
    try:
        prose_receipt = _tool_append_block(deps, screened_text, verb="record")
    except ModelRetry as e:
        # Cluster L: a trace row per CALL, early exits included, round fields zero — a refusal
        # on MAIN's own bytes never reaches the round loop, but it is still one `record` call,
        # and skipping the row here would make the trace undercount the run's `record` calls
        # (O2's prompt-level half loses its denominator on exactly the calls that never asked
        # the clerk anything).
        trace["pending"] = len(caller.pending)
        _append_trace(run_dir, trace)
        # A refusal reaches MAIN unchanged UNLESS nothing can ever repair it: the document
        # already carried a committed error outside the repair verb's `:R attr_updates`-only
        # scope before this call even began — append-only puts it permanently out of reach,
        # and the model would otherwise loop on a repeating refusal until the framework
        # force-closes. Told, not fixed: the forced close is named as the escape MAIN has.
        if pre_existing_defect is not None and not repairable_diagnostics(deps):
            raise ModelRetry(
                f"{e}\n\nThis document cannot be repaired further (append-only, and nothing "
                "here is in the repair verb's scope) — record what you can and let the run "
                "reach its forced close if you cannot otherwise resolve this."
            ) from e
        raise
    document = read_text_utf8(inv_path) if inv_path.is_file() else ""

    # ---------------------------------------------------------------------------------
    # step 2/3: the round loop
    # ---------------------------------------------------------------------------------
    committed = False
    held = False
    stopped_on_judgment = False
    s6_dropped = False
    gave_up = False
    last_block = ""
    last_refusal = ""
    owed_lines: tuple[str, ...] = ()
    ids: list[str] = []
    rows_text = ""
    gaps: list[str] = []
    post_accept_repair_note: str | None = None

    while budget.left > 0:
        if not caller.allowed():
            # O10: past the run's derived clerk ceiling, `record` degrades to no clerk call
            # at all rather than refusing — MAIN's prose is already on disk from step 1.
            committed = True
            break
        prompt = _round_prompt(
            caller.instructions, grammar_catalog, document, caller.pending, text,
            caller.last_gaps, trace["refusals"][-1] if trace["refusals"] else None,
        )
        budget.spend_round()
        try:
            raw = await caller.call(prompt)
        except Exception as e:  # noqa: BLE001 — any non-parsed-response fault pends
            return await pend(f"{type(e).__name__}: {e}")
        rows_text, gaps = _split_clerk_reply(raw)
        caller.last_gaps = list(gaps)
        trace["gaps"] = list(gaps)
        last_block = rows_text
        if not rows_text:
            committed = True
            break
        if ":T conclude" in rows_text and phase_at_call and phase_at_call != "REPORT":
            s6_dropped = True
            caller.push_pending((text, rows_text, ()))
            break
        try:
            _tool_append_block(deps, rows_text, verb="record")
            committed = True
            # Design flow 3: "Clean accept -> done; `pending` cleared." The clerk had the
            # WHOLE backlog in its prompt this round (`_round_prompt` renders `caller.pending`
            # verbatim) and every chance to fold each entry's resolution into the rows it just
            # committed — an accept that lands is the backlog getting a fresh look, not a
            # promise every entry was actually resolved. Without this, a single early pend
            # locks the run out of ever closing again: `close_investigation` refuses while
            # `pending` is non-empty, and nothing else ever empties it.
            caller.pending.clear()
            flagged_before = flagged_diagnostics(deps)
            if flagged_before:
                closed2, fix_refusal2 = await _repair_loop(
                    deps, caller, budget, text, grammar_catalog)
                if closed2:
                    # D9 section (0): a repair round that ran and closed the window is
                    # reported the same as any other repair round — silence here would make
                    # a warn-accepted block's post-accept repair the ONE repair episode the
                    # receipt never names.
                    post_accept_repair_note = (
                        f"record: repaired {len(flagged_before)} flagged row(s)"
                    )
                else:
                    if fix_refusal2:
                        trace["refusals"].append(fix_refusal2[:_REFUSAL_TRUNC])
                    post_accept_repair_note = (
                        f"record: {len(flagged_diagnostics(deps))} row(s) still flagged "
                        f"after {budget.repair_rounds} round(s)"
                    )
            break
        except ModelRetry as e:
            refusal_text = str(e)
            trace["refusals"].append(refusal_text[:_REFUSAL_TRUNC])
            last_refusal = refusal_text
            sep = "\n" if document and not document.endswith("\n") else ""
            proposed = document + sep + rows_text
            from defender.skills.invlang.validate import (
                judgment_diagnostics,
                structural_diagnostics,
            )

            structural = structural_diagnostics(proposed, document)
            judgment = judgment_diagnostics(proposed, document)
            if structural:
                continue  # retryable within budget
            if judgment:
                stopped_on_judgment = True
                held = True
                owed_lines = tuple(d.message for d in judgment)
                caller.push_pending((text, rows_text, owed_lines))
                break
            # AR-7: a refusal carrying NO diagnostic in either partition (the byte cap, sitting
            # outside the diagnostic machinery entirely) — surfaced and held, not retried.
            held = True
            caller.push_pending((text, rows_text, ()))
            break
    else:
        gave_up = False  # loop condition exhausted the budget with no break — see below

    if not (committed or s6_dropped or held):
        gave_up = True

    trace["rounds"] = budget.rounds
    trace["repair_rounds"] = budget.repair_rounds
    trace["rows_chars"] = len(rows_text)

    sections = [prose_receipt]
    if post_accept_repair_note is not None:
        sections.append(post_accept_repair_note)
    if gave_up:
        sections.append(
            f"{OUTCOME_GIVEUP}{CLERK_ROUND_BUDGET} clerk rounds — {last_refusal}\n\n"
            f"{last_block}"
        )
    elif s6_dropped:
        sections.append(OUTCOME_NOTHING)
        sections.append(
            "Note: a `:T conclude` block was dropped — it lands only under the `## REPORT` "
            "phase header. State the report again once the phase is REPORT."
        )
    elif held:
        ids_held = _extract_ids(rows_text)
        trace["ids"] = ids_held
        if stopped_on_judgment:
            sections.append(OUTCOME_HELD + "\n" + "\n".join(owed_lines))
        else:
            sections.append(
                f"record: rows refused — {last_refusal}"
            )
    else:
        ids = _extract_ids(rows_text) if rows_text.strip() else []
        trace["ids"] = ids
        if ids:
            sections.append(OUTCOME_COMMITTED + ", ".join(ids))
        elif rows_text.strip():
            sections.append(OUTCOME_COMMITTED_ANON)
        else:
            sections.append(OUTCOME_NOTHING)

    flagged_now = _flagged_section(deps)
    if flagged_now:
        sections.append(flagged_now)

    if gaps:
        sections.append(
            "GAPS:\n" + "\n".join(f"- {_sanitize_gap(g)}" for g in gaps)
        )

    return finish(sections, committed=committed and not held, held=held, stopped=stopped_on_judgment)
