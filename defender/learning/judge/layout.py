"""The judge's prompt layout (design M3) under the payload cap (A9), its host text outside every
untrusted frame (A10)."""

from __future__ import annotations

from typing import Any, NamedTuple, TypeVar

from defender.records._episode_paths import WORLD_LEAVES
from defender._untrusted import message_salt, wrap
from defender.learning._prompt import host_heading, stage_user_message
from defender.learning.branch.ledger import ORACLE, normalized_source
from defender.learning.judge._errors import JudgeRefused
from defender.learning.judge.render import (
    UNTRUSTED_TAG,
    JudgeContext,
    RunText,
    RunView,
    _json,
    _render_leads,
    _render_lessons,
    aligned_lead_rows,
    fact_surfaces,
    run_view,
)
from defender.learning.judge.runs import RunSet

#: M3's section titles: host text, outside every untrusted frame (A10), each once per prompt.
TITLE_HEADER = "COMPUTED HEADER"
TITLE_CONTRAST = "CONTRAST TABLE"
TITLE_SURFACES = "FACT SURFACES"
TITLE_ALIGNED = "ALIGNED LEAD VIEW"
TITLE_REFERENCES = "REFERENCE RUNS"
TITLE_FOCUS = "JUDGED WORLD VIEWS"
TITLE_NOISE = "NOISE CONTEXT"

#: The label every text-matched (not established) row and hit carries, in host text (M2).
HEURISTIC = "heuristic: text-matched, not established"

#: The knob the cap is read from, named by every refusal it causes.
CAP_KNOB = "JUDGE_PAYLOAD_CAP"

#: The host line a block cut under the cap ends with (A9: a cut is stated, never silent).
CUT_NOTICE = "\n[truncated at the payload cap]\n"

Part = str | RunText
Block = tuple[str | None, list[Part]]
#: One prompt section: its host title and its blocks.
Section = tuple[str, list[Block]]

K = TypeVar("K")


# --------------------------------------------------------------------------------------
# Rendering and measuring (one spelling of each, so what is measured is what is sent).
# --------------------------------------------------------------------------------------


def _part_cost(part: Part) -> int:
    return len(part) if isinstance(part, str) else len(part.text)


def _block_cost(block: Block) -> int:
    return sum(map(_part_cost, block[1]))


def _section_cost(section: Section) -> int:
    return sum(map(_block_cost, section[1]))


def render_sections(sections: list[Section], salt: str) -> list[str]:
    """Each section's host title, then each block's host label and its parts, every `RunText`
    inside one untrusted frame on `salt`, in prompt order. A title or label outside the host
    grammar raises (`_prompt.host_heading`)."""
    out: list[str] = []
    for title, blocks in sections:
        out.append(f"\n## {host_heading(title)}\n")
        for label, parts in blocks:
            if label is not None:
                out.append(f"\n### {host_heading(label)}\n")
            out.append("".join(p if isinstance(p, str) else wrap(p.text, UNTRUSTED_TAG, salt)
                               for p in parts))
    return out


def framed_prompt(task: str, sections: list[Section]) -> str:
    """`task` (host text), the reader contract and `sections`, on one salt no text holds.

    Refused (`JudgeRefused`, naming the cause) when a run text cannot be sent as UTF-8 — a lone
    surrogate decoded off an archived JSON escape — rather than failing inside the model call."""
    texts = [task, *(t for t, _b in sections),
             *(label for _t, blocks in sections for label, _p in blocks if label),
             *(p if isinstance(p, str) else p.text
               for _t, blocks in sections for _l, parts in blocks for p in parts)]
    salt = message_salt(*texts)
    prompt = task + stage_user_message(salt, *render_sections(sections, salt))
    try:
        prompt.encode("utf-8")
    except UnicodeEncodeError as bad:
        raise JudgeRefused(f"the prompt carries text that is not valid UTF-8 ({bad.reason} at "
                           f"character {bad.start}): a lone surrogate in an archived run text"
                           ) from bad
    return prompt


# --------------------------------------------------------------------------------------
# Section builders.
# --------------------------------------------------------------------------------------


def _run(value: Any) -> Part:
    """A run- or manifest-derived value framed in place (a string verbatim, anything else as
    canonical JSON); `None` as host text saying so."""
    if value is None:
        return "(none recorded)"
    return RunText(value if isinstance(value, str) else _json(value))


def _each(values: Any) -> list[Part]:
    """Each of `values` framed on its own, comma-separated; `none` when there are none."""
    out: list[Part] = []
    for i, value in enumerate(values or ()):
        out += ([", "] if i else []) + [_run(value)]
    return out or ["none"]


def _word(source: Any) -> Part:
    """A ledger decision word: host text when it is one of the ledger's own words (`SOURCES`),
    else framed (the archive can carry anything)."""
    word = normalized_source(source)
    return word if word is not None else _run(source)


def _pick(mapping: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """The `keys` of an archived mapping, as that record spells them."""
    return {k: mapping.get(k) for k in keys}


def _entry(run: RunView) -> dict[str, Any]:
    """A run's manifest world entry as the header shows it, by the manifest's own names."""
    return {"role": run.role, "story": run.story, "axis": run.axis,
            "disposition_declared": run.declared, "label_basis": run.label_basis}


def _family_block(doc: dict[str, Any]) -> Block:
    discriminator = doc.get("discriminator")
    predicate = discriminator.get("predicate") if isinstance(discriminator, dict) else None
    return (None, ["served systems: ", _run(doc.get("served_systems")),
                   "\ndiscriminator predicate: ", _run(predicate),
                   "\nbase story: ", _run(doc.get("base_story")), "\n"])


def _fact_parts(facts: list[dict[str, Any]]) -> list[Part]:
    if not facts:
        return ["facts: none (this run serves the capture's own answers)\n"]
    parts: list[Part] = []
    for fact in facts:
        parts += ["fact (its id, statement and entities): ",
                  _run(_pick(fact, ("fact_id", "statement", "entities"))), "\n"]
    return parts


def _run_header_block(run: RunView) -> Block:
    return (f"run {run.label}", [
        f"storage world UUID: {run.world_id}\n",
        "its manifest entry (role, story, axis, declared verdict, label basis): ",
        _run(_entry(run)), f"\nreached verdict (its archived {WORLD_LEAVES.report}): ",
        _run(run.reached) if run.reached is not None
        else "none (its report names no disposition)", "\n", *_fact_parts(run.facts)])


def _call_ref(entry: dict[str, Any]) -> list[Part]:
    """A call as a contrast row names it: its number (host), else the ledger row's own fields."""
    if entry.get("call") is not None:
        return [f"call {entry['call']}"]
    return ["a ledger row with no query-table row ",
            _run({k: entry.get(k) for k in ("call_id", "system", "verb", "params") if k in entry})]


def _numbers(values: Any) -> str:
    return ", ".join(str(v) for v in values) if values else "none"


def _contrast_block(run: RunView, *, focus: bool) -> Block:
    """One run's contrast row (M2): host-computed values as host text, every run-derived
    string framed in place. A field this renderer does not know is still shown, framed."""
    row = dict(run.contrast)
    shown = row.pop("shown_its_facts", None)
    parts: list[Part] = [f"shown its facts: {'yes' if shown else 'no'}\n"]
    if focus and not shown:
        parts.append("this world was never shown its facts: no altered answer was served to "
                     "it, so analyze-discipline and decision-discipline are unavailable to it\n")
    first = row.pop("first_altered_call", None)
    parts.append(f"first altered call: {first if first is not None else 'none'}\n")
    parts += ["leads served altered answers: ", *_each(row.pop("altered_leads", None)), "\n"]
    counts = row.pop("call_counts", None) or {}
    parts.append("calls by system and verb:")
    for key, n in counts.items():
        parts += [" ", _run(key), f" x{n};"]
    parts.append(" none\n" if not counts else "\n")
    blocked = row.pop("blocked_calls", None) or []
    parts.append("blocked calls (refused, faulted, or the inherited pre-branch denial):")
    for entry in blocked:
        parts += [" ", *_call_ref(entry), " [", _word(entry.get("source")), "];"]
    parts.append(" none\n" if not blocked else "\n")
    parts.append("calls served an error (an outage, not a gap): "
                 f"{_numbers(row.pop('errored_calls', None))}\n")
    parts.append(f"unserved calls: {_numbers(row.pop('unserved_calls', None))}\n")
    unmapped = row.pop("unmapped_calls", None) or []
    parts.append("ledger rows no query-table row carries:")
    for entry in unmapped:
        parts += [" ", *_call_ref(entry), " [", _word(entry.get("source")), "];"]
    parts.append(" none\n" if not unmapped else "\n")
    parts.append(f"inherited pre-branch calls: {_numbers(row.pop('shared_baseline', None))}\n")
    for key, value in row.items():
        if isinstance(key, str) and host_text_ok(key):
            parts += [f"{key}: ", _run(value), "\n"]
    return (f"run {run.label}", parts)


def host_text_ok(text: str) -> bool:
    """Is `text` of the host grammar (`_prompt.host_heading`)?"""
    try:
        host_heading(text)
    except ValueError:
        return False
    return True


def _surfaces_block(surfaces: list[dict[str, Any]]) -> Block:
    if not surfaces:
        return (None, ["No planted fact is in these runs.\n"])
    parts: list[Part] = [f"Every hit below is {HEURISTIC}.\n"]
    for s in surfaces:
        parts += ["fact ", _run(s["fact_id"]), f" of run {s['world']}: the systems its forged "
                  "rows were served on ", _run(s["systems"]), "; its entities ",
                  _run(s["entities"]), "\n"]
        for run, leads in s["hits"].items():
            parts += [f"  run {run}: leads ", _run(leads), f" ({HEURISTIC})\n"]
    return (None, parts)


def _aligned_block(rows: list[dict[str, Any]]) -> Block:
    if not rows:
        return (None, ["No lead is recorded in these runs.\n"])
    parts: list[Part] = [
        f"Every row below is {HEURISTIC}. A row marked shared baseline holds only judged-world "
        "calls made before its first altered answer: noise, not contrast.\n"]
    for i, row in enumerate(rows, 1):
        how = row.get("matched_by")
        parts.append(f"row {i} ({HEURISTIC}; ")
        if how == "fact surface":
            parts += ["matched through the fact surface of ", _run(row.get("fact_id"))]
        elif how == "system and verb":
            parts += ["matched by system and verb ", _run([row.get("system"), row.get("verb")])]
        else:
            parts.append("unmatched: no other run's lead pairs with it")
        parts.append(")" + (" — shared baseline" if row.get("shared_baseline") else "") + ":")
        by_run: dict[str, list[str]] = {}
        for lead in row.get("leads") or ():
            by_run.setdefault(lead["run"], []).append(lead["lead"])
        for label, leads in by_run.items():
            parts += [f" run {label} leads ", _run(leads), ";"]
        parts.append("\n")
    return (None, parts)


def computed_sections(doc: dict[str, Any], runs: list[RunView], surfaces: list[dict[str, Any]],
                      aligned: list[dict[str, Any]], *, focus: str | None) -> list[Section]:
    """M3's sections 2-4 over `runs`: the family's served systems, predicate and base story,
    then every run's computed header and contrast row, labelled by run (the judged world's,
    `focus`, says so when it was never shown its facts); then the fact surfaces and the aligned
    lead view. Never cut (A9)."""
    return [
        (TITLE_HEADER, [_family_block(doc), *(_run_header_block(run) for run in runs)]),
        (TITLE_CONTRAST, [_contrast_block(run, focus=run.label == focus) for run in runs]),
        (TITLE_SURFACES, [_surfaces_block(surfaces)]),
        (TITLE_ALIGNED, [_aligned_block(aligned)]),
    ]


def _answer_key(entry: dict[str, Any]) -> str:
    return _json([entry.get("system"), entry.get("verb"), entry.get("params")])


def _call_line(entry: dict[str, Any]) -> list[Part]:
    n = entry.get("call")
    head = f"- call {n} [" if n is not None else "- a ledger row with no query-table row ["
    parts: list[Part] = [head, _word(entry.get("source")) if entry.get("source") is not None
                         else "no ledger row", "]"]
    if entry.get("blocked"):
        parts.append(" BLOCKED")
    if entry.get("inherited"):
        parts.append(" inherited from before the branch")
    request = {"lead_id": entry.get("lead"), "system": entry.get("system"),
               "verb": entry.get("verb"), "params": entry.get("params")}
    return [*parts, " ", _run(request)]


def _reference_block(run: RunView, focus_answers: dict[str, Any],
                     calls: list[dict[str, Any]]) -> Block:
    """A reference run's compressed section (M3 section 5, A24): its leads, its report and its
    call list; a call's answer is shown in full only where it differs from the judged world's
    matched call (same system, verb and params) or the judged world made no such call."""
    parts: list[Part] = ["leads:\n"]
    for lead, goal in run.lead_goals.items():
        parts += ["- lead ", _run(lead), ", its goal: ", _run(goal), "\n"]
    if not run.lead_goals:
        parts.append("none recorded\n")
    parts += [f"its {WORLD_LEAVES.report}: ", _run(run.report_text) if run.report_text
              else "(empty)", "\ncalls:\n"]
    for entry in calls:
        parts += _call_line(entry)
        answer = run.answers.get(entry["call"]) if entry.get("call") is not None else None
        if answer is not None:
            key = _answer_key(entry)
            if key not in focus_answers:
                parts += [" — answered (the judged world made no such call): ", _run(answer)]
            elif focus_answers[key] != answer:
                parts += [" — answered differently from the judged world's matched call: ",
                          _run(answer)]
            else:
                parts.append(" — answered as the judged world's matched call was")
        parts.append("\n")
    if not calls:
        parts.append("this run made no call\n")
    return (f"run {run.label}", parts)


def _claim_parts(claim: dict[str, Any]) -> list[Part]:
    """An `oracle` call's claim and verifier verdict, or the words saying either was never
    stored — a call with no stored claim is never presented as verified (N22)."""
    if not isinstance(claim.get("claim"), dict):
        return [" — claim unavailable (none was stored for this call; it is not verified)"]
    if not isinstance(claim.get("verifier_verdict"), dict):
        return [" — claim ", _run(claim["claim"]), "; verifier verdict unavailable (none was "
                "stored; the claim is not verified)"]
    return [" — claim ", _run(claim["claim"]), "; verifier verdict ",
            _run(claim["verifier_verdict"])]


def _focus_calls(run: RunView) -> list[Part]:
    """VIEW 1: every call of the judged world with its decision word, and an altered call's
    claim and verifier verdict — never cut by the cap."""
    parts: list[Part] = []
    for entry in run.calls:
        parts += _call_line(entry)
        claim = run.claims.get(entry["call"]) if entry.get("call") is not None else None
        if claim is not None or entry.get("source") == ORACLE:
            parts += _claim_parts(claim or {})
        parts.append("\n")
    return parts or ["This world's investigator made no call.\n"]


def _focus_answers(run: RunView) -> list[Part]:
    """VIEW 2: the answer each call was served, by call number."""
    parts: list[Part] = []
    for entry in run.calls:
        n = entry.get("call")
        if n is not None and run.answers.get(n) is not None:
            parts += [f"- call {n} answer: ", _run(run.answers[n]), "\n"]
    return parts or ["No answer was served to this world.\n"]


#: Each focus view's host label (section 6), in the order the views are shown.
FOCUS_VIEW_TITLES: dict[str, str] = {
    "manifest": "its facts and declared verdict, as the family recorded them",
    "calls": "VIEW 1: every call its investigator made, with its decision word",
    "answers": "VIEW 2: the answers those calls were served, by call number",
    "leads": "VIEW 3: per-lead chain (goal, params, payload, refused, summary, resolutions)",
    "lessons": "VIEW 4: lessons that reached it (body at its recorded commit)",
    "document": "its own investigation.md",  # lint-run-records: ok — a label naming the record for the model
    "report": "its own report.md",  # lint-run-records: ok — a label naming the record for the model
    "samples": "real example answers per served system (the samples record)",
    "oracle": "its frozen telemetry and identifier collisions (its built layer)",
}


def _focus_views(ctx: JudgeContext) -> dict[str, Block]:
    run, focus = ctx.run_views[0], ctx.focus
    bodies: dict[str, list[Part]] = {
        "manifest": ["its manifest entry: ", _run(_entry(run)), "\n", *_fact_parts(run.facts)],
        "calls": _focus_calls(run),
        "answers": _focus_answers(run),
        "leads": [RunText(_render_leads(focus.leads))],
        "lessons": [RunText(_render_lessons(focus.lessons))],
        "document": [RunText(focus.document_text)],
        "report": [RunText(focus.report_text)],
        "samples": [RunText(focus.samples_text)],
        "oracle": [RunText(focus.oracle_text)],
    }
    return {name: (f"world {ctx.world_label} — {FOCUS_VIEW_TITLES[name]}", parts)
            for name, parts in bodies.items()}


# --------------------------------------------------------------------------------------
# The cap (A9).
# --------------------------------------------------------------------------------------


def _equal_shares(full: dict[K, int], least: int, budget: int) -> dict[K, int]:
    """Split `budget` among blocks of `full` cost, each keeping at least `least` (or its whole
    self, when smaller): what is left above the minimums goes in equal shares, smallest block
    first, a block that needs less than its share handing the rest on. `budget` is at least
    the minimums' sum."""
    if sum(full.values()) <= budget:
        return dict(full)
    floor = {k: min(c, least) for k, c in full.items()}
    spare, left = budget - sum(floor.values()), len(full)
    out: dict[K, int] = {}
    for key in sorted(full, key=lambda k: full[k] - floor[k]):
        extra = min(full[key] - floor[key], spare // left)
        out[key] = floor[key] + extra
        spare -= extra
        left -= 1
    return out


def _cut(block: Block, allowed: int) -> Block:
    """`block` within `allowed` characters of content: its whole self when it fits, else its
    parts in order up to where the allowance runs out (a run text cut inside its frame), at
    least one frame, and the cut notice as the host line after the last frame kept."""
    if _block_cost(block) <= allowed:
        return block
    label, parts = block
    room = allowed - len(CUT_NOTICE)
    kept: list[Part] = []
    for part in parts:
        if isinstance(part, str):
            if len(part) > room:
                break
            kept.append(part)
            room -= len(part)
            continue
        if len(part.text) > room:
            kept.append(RunText(part.text[:max(room, 0)]))
            break
        kept.append(part)
        room -= len(part.text)
    if any(isinstance(p, RunText) for p in kept):
        # Host text past the last frame kept is dropped, so the notice is the host line right
        # after that frame (where a reader looks for the cut).
        while isinstance(kept[-1], str):
            kept.pop()
    else:
        kept.append(RunText(""))
    return (label, [*kept, CUT_NOTICE])


def cap_refusal(cap: int, needed: int, what: str) -> str:
    """Why a call whose uncuttable content needs `needed` characters is refused under `cap`."""
    return (f"{what}: its computed sections, with the notice each cut block keeps, take {needed} "
            f"characters, over the payload cap ({CAP_KNOB}={cap}) — refused rather than sent "
            "without the comparison it claims")


class WorldLayout(NamedTuple):
    """A world call's sections under the cap, and the served systems whose samples section
    the prompt shows whole (the set a `samples.yaml#<system>` pointer may resolve in, g18)."""

    sections: list[Section]
    samples_shown: frozenset[str]


def _give(stages: list[dict[K, Block]], budget: int) -> list[dict[K, Block]]:
    """`stages` of cuttable blocks cut to fit `budget`, the first stage giving first: each stage
    is held to what the stages after it leave at their full size (never below the notice each
    of its blocks keeps), its share split equally among its blocks (`_equal_shares`). `budget` covers
    every block's minimum."""
    least = len(CUT_NOTICE)
    out: list[dict[K, Block]] = []
    for i, stage in enumerate(stages):
        later = sum(_block_cost(b) for after in stages[i + 1:] for b in after.values())
        full = {k: _block_cost(b) for k, b in stage.items()}
        floor = sum(min(c, least) for c in full.values())
        alloc = _equal_shares(full, least, max(budget - later, floor))
        cut = {k: _cut(b, alloc[k]) for k, b in stage.items()}
        budget -= sum(map(_block_cost, cut.values()))
        out.append(cut)
    return out


def world_layout(ctx: JudgeContext, doc: dict[str, Any]) -> WorldLayout:
    """Every section of `ctx`'s world call after the task, in M3's order, under
    `ctx.payload_cap` (A9; see the module docstring). What gives, in order: section 5's blocks,
    section 7, section 6's views (VIEW 1 never), and last a reference run's own header block (its
    manifest entry and facts — the judged world's own computed rows never give). Raises
    `JudgeRefused` naming the cap when the rows that never give and the notice each other block
    would keep alone exceed it."""
    cap = ctx.payload_cap
    computed = computed_sections(doc, ctx.run_views, ctx.fact_surfaces, ctx.aligned_rows,
                                 focus=ctx.world_label)
    (header_title, header_blocks), rest = computed[0], computed[1:]
    # The header's blocks: the family's, the judged world's, then each reference run's.
    ref_headers = {run.label: block for run, block in zip(ctx.run_views[1:], header_blocks[2:],
                                                         strict=True)}
    focus_run = ctx.run_views[0]
    focus_answers = {_answer_key(e): focus_run.answers.get(e["call"])
                     for e in ctx.focus_calls if e.get("call") is not None}
    references = {run.label: _reference_block(run, focus_answers, ctx.reference_calls[run.label])
                  for run in ctx.run_views[1:]}
    views = _focus_views(ctx)
    calls = views.pop("calls")
    noise: dict[str, Block] = {"noise": (None, list(ctx.noise))}
    if cap is not None:
        least = len(CUT_NOTICE)
        fixed_cost = (sum(map(_block_cost, header_blocks[:2])) + sum(map(_section_cost, rest)))
        stages: list[dict[str, Block]] = [references, noise, views, ref_headers]
        needed = fixed_cost + sum(min(_block_cost(b), least)
                                  for stage in stages for b in stage.values())
        if needed > cap:
            raise JudgeRefused(cap_refusal(cap, needed, f"world {ctx.world_label}"))
        references, noise, views, ref_headers = _give(stages, cap - fixed_cost)
    samples_parts = views["samples"][1]
    kept = samples_parts[0].text if samples_parts and isinstance(samples_parts[0], RunText) else ""
    shown = frozenset(system for system, end in ctx.focus.samples_ends.items()
                      if len(kept) >= end)
    ordered = {"manifest": views["manifest"], "calls": calls,
               **{k: v for k, v in views.items() if k != "manifest"}}
    return WorldLayout(sections=[
        (header_title, [*header_blocks[:2], *ref_headers.values()]),
        *rest,
        (TITLE_REFERENCES, list(references.values()) or [(None, ["No reference run.\n"])]),
        (TITLE_FOCUS, list(ordered.values())),
        (TITLE_NOISE, list(noise.values())),
    ], samples_shown=shown)


def family_layout(doc: dict[str, Any], runs: RunSet, noise: list[Any], *,
                  cap: int | None) -> list[Section]:
    """The family call's sections (design M6, A22): every usable run's computed header and
    contrast row, the fact surfaces and the aligned lead view, then the noise context — no
    samples and nothing any world call answered, so the prompt is the same whatever the worlds'
    outcomes. Under `cap` the noise is cut; refused (`JudgeRefused` naming the cap) when the
    computed sections alone exceed it: the family call never loses them."""
    labels = list(runs.usable)
    views = [run_view(doc, runs, label) for label in labels]
    surfaces = fact_surfaces(doc, runs, labels)
    fixed = computed_sections(doc, views, surfaces, aligned_lead_rows(views, surfaces),
                              focus=None)
    block: Block = (None, list(noise))
    if cap is not None:
        fixed_cost = sum(map(_section_cost, fixed))
        needed = fixed_cost + min(_block_cost(block), len(CUT_NOTICE))
        if needed > cap:
            raise JudgeRefused(cap_refusal(cap, needed, "the family call"))
        block = _cut(block, cap - fixed_cost)
    return [*fixed, (TITLE_NOISE, [block])]


__all__ = [
    "CAP_KNOB", "CUT_NOTICE", "FOCUS_VIEW_TITLES", "HEURISTIC", "Section", "TITLE_ALIGNED",
    "TITLE_CONTRAST", "TITLE_FOCUS", "TITLE_HEADER", "TITLE_NOISE", "TITLE_REFERENCES",
    "TITLE_SURFACES", "WorldLayout", "cap_refusal", "computed_sections", "family_layout",
    "framed_prompt", "host_text_ok", "render_sections", "world_layout",
]
