"""#1234 slice 4, prompt_references: what each judge prompt carries once a planted world is
judged against labelled reference runs (the control and every gradable sibling).

The world prompt (M3 as amended by A9, A10 and the drift overlay) runs: task and taxonomy,
computed header, contrast table, fact surfaces and aligned lead view, compressed reference runs,
the judged world's views, and the noise context (pre-flight's record). Every prompt test drives
the real entry point (`S.grade` -> `grade_episode`) and reads what the recording model seam
(`S.RoutedJudge`, the `judge=` seam) was handed. The `JudgeContext` tests call `render` through
`S.render_context` and read what it returns.

HOW A TEST FINDS A SECTION AND A RUN'S BLOCK. A10 puts host-authored section titles and run labels
outside the untrusted frames, so:
  * a section starts at its title in host text (`_sections`). The titles are the implementer's to
    name (F2), so they are COINED and live in `S.COINED["title.<section>"]`. Each title must
    occur exactly once in a prompt's host text.
  * a run's labelled block is the text whose nearest preceding host-text run label is that run's
    (`_blocks`, label tokens by `S.label_re`). A frame belongs to the run whose label heads it —
    the same reading frames_and_cap's `_owner` takes.
The labels are `ctl` (the control), `wb` and `wc`, never `a`/`b`/`c`: host prose spells those as
words ("a reference run"). Every scripted pointer therefore names its run explicitly; `S.inv` and
`S.wf` default to `b`/`a` pointers.

THE `JudgeContext` WALK. The context's field names are the implementer's too (F2). The context
tests make no guess at them: they assert the class is `S.COINED["cls.context"]` and read what the
context holds by walking it (`_nodes`): its strings, its collections (a row list is any list or
mapping in it), and the lead ids each element holds.

THE SALT. Every message frames its sections in a fresh random salt (#875 F-1,
`_untrusted.message_salt`). Two renders of the same archive therefore differ in the salt alone.
"Byte-identical" (s_A9, s_L24, d03k) is compared with the frame tags' salt normalised
(`S.unsalted`); every other byte must match.

THE CAP is A9's and frames_and_cap's to pin. Here it is lifted (`_UNCAPPED`) so no trim decides
what a reference test sees. g18 sets its own cap, because a cut section is one of its cases.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import pytest

from defender.tests.judge_contrast_1234 import _spec1234 as S

#: The words A2/M2 require on the aligned lead view and the fact surfaces (`S.COINED`).
HEURISTIC = S.COINED["label.heuristic"]
BASELINE = S.COINED["label.baseline"]
HEURISTIC_RE = re.compile(re.escape(HEURISTIC), re.IGNORECASE)

CTL, WB, WC = "ctl", "wb", "wc"
LABELS = (CTL, WB, WC)
_UNCAPPED = 10_000_000

#: M3's sections, each found by its COINED host-text title (`S.COINED["title.<section>"]`),
#: outside every untrusted frame (A10).
SECTIONS = ("header", "contrast", "surfaces", "aligned", "references", "focus", "noise")

#: A pre-flight drift entry (the noise context is pre-flight's record alone, drift overlay).
DRIFT_MARK = "MARK-preflight-drift"
#: The episode id of a second, separately graded family in one test (finding ids carry it).
SECOND_EPISODE_ID = "20260728t161845z-fresh-case-n60"


def _title(section: str) -> str:
    return S.COINED[f"title.{section}"]


@pytest.fixture(autouse=True)
def _payload_cap_lifted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(S.CAP_KNOB, str(_UNCAPPED))


# --------------------------------------------------------------------------------------
# Building the family: distinct labels, distinct lead ids, a marker in every text.
# --------------------------------------------------------------------------------------


def _q(text: str) -> dict:
    return S.query_params(text)


def _call(lead: str, system: str = "idp", verb: str = "query", params: dict | None = None,
          **kw: Any) -> S.CallRow:
    return S.CallRow(system=system, verb=verb, params=params, lead=lead, **kw)


def _altered(lead: str, q: str, *, system: str = "idp", fact_id: str = "f-wb",
             forged_id: str = "fg-wb-1", **kw: Any) -> S.CallRow:
    """World wb's altered answer (an `oracle` ledger row with its claim and verifier verdict)."""
    return S.oracle_call(q, system=system, fact_id=fact_id, forged_id=forged_id, lead=lead, **kw)


def _forged(forged_id: str, fact_id: str, system: str, *, label: str = WB) -> dict:
    return {"forged_id": forged_id, "fact_id": fact_id, "system": system,
            "row": {"user": "alice", "event_id": f"e-{forged_id}",
                    "note": S.marker(label, "forged-" + fact_id)}}


def _triad(**over: dict[str, Any]) -> list[S.World]:
    """The default family: control `ctl` (one call, lead l-305), planted `wb` (a passthrough on
    l-201, then an altered answer on l-917: shown its facts) and `wc` (one passthrough on edr,
    lead l-406). Each call's params carry `MARK-<label>-call`. `over` replaces a world's fields;
    a new label adds a planted world."""
    spec: dict[str, dict[str, Any]] = {
        CTL: {"calls": [_call("l-305", params=_q(f"user:alice {S.marker(CTL, 'call')}"))]},
        WB: {"calls": [_call("l-201", params=_q(f"user:alice {S.marker(WB, 'call')}")),
                       _altered("l-917", f"user:alice host:db-1 {S.marker(WB, 'altered')}")]},
        WC: {"role": "C", "forged_system": "edr",
             "calls": [_call("l-406", "edr", params=_q(f"host:db-1 {S.marker(WC, 'call')}"))]},
    }
    for label, fields in over.items():
        spec.setdefault(label, {}).update(fields)
    order = [CTL, WB, WC, *sorted(set(spec) - set(LABELS))]
    return [S.control(label, **spec[label]) if label == CTL else S.planted(label, **spec[label])
            for label in order]


def _family(tmp_path: Path, worlds: list[S.World] | None = None, **kw: Any) -> S.Built:
    return S.family(tmp_path, worlds if worlds is not None else _triad(), **kw)


def _drift() -> dict:
    return {"system": "idp", "verb": "query", "params": _q(f"host:db-9 {DRIFT_MARK}"),
            "status": "drifted"}


def _graded(built: Any, judge: S.RoutedJudge | None = None, **kw: Any) -> S.RoutedJudge:
    seam = judge if judge is not None else S.judge()
    S.grade(built, seam, **kw)
    return seam


def _world_prompts(judge: S.RoutedJudge) -> list[str]:
    return [p for a, p in zip(judge.agent_ids, judge.prompts, strict=True)
            if S.parse_agent_id(a)[0] not in (None, S.FAMILY)]


# --------------------------------------------------------------------------------------
# Reading a prompt: host text, sections, labelled blocks.
# --------------------------------------------------------------------------------------

_FRAME_TAG = re.compile(r"</?run-[0-9a-f]+-[A-Za-z_]+>")


def _host_spans(text: str) -> list[tuple[int, int]]:
    """The spans of `text` outside every closed untrusted frame (`S.untrusted_frames`), the
    complement `S.outside_untrusted_frames` joins, kept as positions."""
    spans, cursor = [], 0
    for start, _open_end, _close_start, end in S.untrusted_frames(text):
        if start < cursor:
            continue
        spans.append((cursor, start))
        cursor = end
    spans.append((cursor, len(text)))
    return spans


def _in_frame(text: str, pos: int) -> bool:
    return any(open_end <= pos < close_start
               for _s, open_end, close_start, _e in S.untrusted_frames(text))


def _host_hits(text: str, pattern: re.Pattern[str], lo: int = 0, hi: int | None = None) -> list[int]:
    end = len(text) if hi is None else hi
    hits: list[int] = []
    for a, b in _host_spans(text):
        a, b = max(a, lo), min(b, end)
        if a < b:
            hits.extend(m.start() for m in pattern.finditer(text, a, b))
    return sorted(hits)


def _host_text(text: str, lo: int = 0, hi: int | None = None) -> str:
    end = len(text) if hi is None else hi
    return "".join(text[max(a, lo):min(b, end)] for a, b in _host_spans(text)
                   if max(a, lo) < min(b, end))


def _sections(prompt: str) -> dict[str, tuple[int, int]]:
    """Each section's span: from its COINED title in host text to the next title (or the end).
    The task-and-taxonomy region is everything before the first title (`_task`)."""
    starts: dict[str, int] = {}
    for section in SECTIONS:
        token = _title(section)
        hits = _host_hits(prompt, re.compile(re.escape(token)))
        assert hits, (f"no host-text title {token!r} opens the {section} section (A10: titles sit "
                      f"outside the untrusted frames; COINED title.{section})")
        assert len(hits) == 1, (f"the {section} section's title {token!r} occurs {len(hits)} times "
                                "in host text; rename it in COINED so it marks its section once")
        starts[section] = hits[0]
    order = sorted(starts, key=starts.__getitem__)
    return {s: (starts[s], starts[order[i + 1]] if i + 1 < len(order) else len(prompt))
            for i, s in enumerate(order)}


def _section(prompt: str, section: str) -> str:
    lo, hi = _sections(prompt)[section]
    return prompt[lo:hi]


def _task(prompt: str) -> str:
    return prompt[:min(lo for lo, _hi in _sections(prompt).values())]


def _blocks(prompt: str, span: tuple[int, int], labels: Iterable[str]) -> dict[str, str]:
    """Within `span`, each label's labelled block: the text from each host-text occurrence of a
    run label to the next occurrence of any of `labels`. A reference block's sub-titles may name
    the judged world it is compared with, so callers reading reference blocks pass the reference
    labels only."""
    wanted = tuple(labels)
    lo, hi = span
    hits = sorted((at, label) for label in wanted for at in _host_hits(prompt, S.label_re(label), lo, hi))
    out = {label: "" for label in wanted}
    for i, (at, label) in enumerate(hits):
        out[label] += prompt[at:hits[i + 1][0] if i + 1 < len(hits) else hi]
    return out


def _reference_blocks(prompt: str, focus: str, labels: Iterable[str] = LABELS) -> dict[str, str]:
    return _blocks(prompt, _sections(prompt)["references"], [x for x in labels if x != focus])


def _derived_lines(text: str) -> list[str]:
    """The section's lines with frame tags dropped, stripped, long enough to be distinctive."""
    return [line.strip() for line in _FRAME_TAG.sub("\n", text).splitlines()
            if len(line.strip()) >= 16 and re.search(r"[A-Za-z]", line)]


def _sentences(text: str) -> list[str]:
    """Sentences of hard-wrapped prose: a single line break inside a paragraph is a space; a blank
    line or a list item starts a new one."""
    joined = re.sub(r"\n(?!\n|\s*(?:[-*]|\d+\.)\s)", " ", text)
    return [s for s in re.split(r"(?<=[.!?])\s+|\n+", joined) if s.strip()]


# --------------------------------------------------------------------------------------
# Reading a `JudgeContext` without guessing its field names (F2).
# --------------------------------------------------------------------------------------

_SCALARS = (str, bytes, int, float, bool, type(None), Path)


def _children(node: Any) -> list[Any]:
    if isinstance(node, Mapping):
        return [*node.keys(), *node.values()]
    if isinstance(node, (list, tuple, set, frozenset)):
        return list(node)
    if dataclasses.is_dataclass(node) and not isinstance(node, type):
        return [getattr(node, f.name) for f in dataclasses.fields(node)]
    if (type(node).__module__.startswith("defender.") and hasattr(node, "__dict__")
            and not callable(node)):
        return list(vars(node).values())
    return []


def _nodes(obj: Any) -> list[tuple[Any, Any]]:
    """Every node reachable from `obj`, each with its parent (cycle-guarded)."""
    seen: set[int] = set()
    out: list[tuple[Any, Any]] = []
    stack: list[tuple[Any, Any]] = [(obj, None)]
    while stack:
        node, parent = stack.pop()
        if not isinstance(node, _SCALARS):
            if id(node) in seen:
                continue
            seen.add(id(node))
            stack.extend((child, node) for child in _children(node))
        out.append((node, parent))
    return out


def _strings(obj: Any) -> list[str]:
    return [n for n, _p in _nodes(obj) if isinstance(n, str)]


def _holds(obj: Any, needle: str) -> bool:
    return any(needle in s for s in _strings(obj))


def _holds_label(obj: Any, label: str) -> bool:
    pattern = S.label_re(label)
    return any(pattern.search(s) for s in _strings(obj))


def _leads_in(obj: Any, leads: Iterable[str]) -> set[str]:
    strings = _strings(obj)
    return {lead for lead in leads if any(lead in s for s in strings)}


def _collections(obj: Any) -> list[list[Any]]:
    """Every list-like in the context as its elements: a sequence's items, a mapping's
    `(key, value)` items (so an element keyed by a fact id still holds that id), a multi-line
    string's lines."""
    out: list[list[Any]] = []
    for node, _parent in _nodes(obj):
        if isinstance(node, Mapping):
            out.append(list(node.items()))
        elif isinstance(node, (list, tuple, set, frozenset)):
            out.append(list(node))
        elif isinstance(node, str) and "\n" in node:
            out.append(node.splitlines())
    return out


def _elements(obj: Any) -> list[Any]:
    return [e for c in _collections(obj) for e in c]


def _marked_regions(obj: Any, word: str) -> list[Any]:
    """What the context marks with `word`: a string saying it (and its parent), the value of a
    truthy key or field naming it when that value is a collection, else the record carrying it."""
    regions: list[Any] = []
    for node, parent in _nodes(obj):
        if isinstance(node, str):
            if word in node.lower():
                regions.append(node)
                if parent is not None:
                    regions.append(parent)
            continue
        if isinstance(node, Mapping):
            items = list(node.items())
        elif dataclasses.is_dataclass(node) and not isinstance(node, type):
            items = [(f.name, getattr(node, f.name)) for f in dataclasses.fields(node)]
        else:
            items = []
        for key, value in items:
            if isinstance(key, str) and word in key.lower() and value:
                regions.append(value if isinstance(value, (Mapping, list, tuple, set, frozenset))
                               else node)
    return regions


def _context(built: Any, label: str = WB) -> Any:
    ctx = S.render_context(built, label, payload_cap=_UNCAPPED)
    assert type(ctx).__name__ == S.COINED["cls.context"], (
        f"render returned {type(ctx).__name__}, not the {S.COINED['cls.context']} the design names")
    return ctx


def _row_check(rows: list[Any], expected: Mapping[str, set[str]], universe: set[str]) -> list[str]:
    """Why `rows` is not the aligned lead view `expected` describes (empty: it is). For each lead,
    every row holding it holds only leads of its expected row, and together they hold all of
    them; a row per pair of runs passes, a row joining unrelated leads does not."""
    problems = []
    for lead, partners in expected.items():
        holding = [_leads_in(row, universe) for row in rows if lead in _leads_in(row, universe)]
        want = {lead, *partners}
        if not holding:
            problems.append(f"no row holds {lead}")
            continue
        stray = set().union(*holding) - want
        if stray:
            problems.append(f"{lead}'s row also holds {sorted(stray)}")
        if set().union(*holding) != want:
            problems.append(f"{lead}'s rows hold {sorted(set().union(*holding))}, not {sorted(want)}")
    return problems


# --------------------------------------------------------------------------------------
# d00f — the seam.
# --------------------------------------------------------------------------------------


def test_1234_render_builds_judge_context_per_focus_world(tmp_path: Path) -> None:
    """render, given the archived episode and one focus world, returns a JudgeContext holding
    header rows and contrast rows for every run, fact surfaces, heuristic-labelled aligned lead
    rows, one reference section per reference run, the focus section, the noise context and the
    questioner inputs, built without any model call."""
    built = _family(tmp_path, drift=[_drift()])
    ctx = _context(built, WB)
    assert isinstance(ctx, S.sym(S.JUDGE_RENDER, S.COINED["cls.context"]))
    # Header rows for every run: each run's manifest story.
    for label in LABELS:
        assert _holds(ctx, S.marker(label, "story")), f"no header row for run {label}"
    # One reference section per reference run, and the focus section.
    for label in (CTL, WC):
        assert _holds(ctx, S.marker(label, "report")), f"no reference section for {label}"
    assert _holds(ctx, S.marker(WB, "investigation")), "no focus section"
    # Every run's calls (the contrast rows count them; the sections list them).
    for label in LABELS:
        assert _holds(ctx, S.marker(label, "call")), f"the context holds none of {label}'s calls"
    # A fact surface: wb's fact with the leads of two runs that touch it (l-917 on idp, the
    # forged system; the control's l-305 names alice). Heuristic-labelled aligned rows.
    assert any(_holds(e, "f-wb") and _holds(e, "l-917") and _holds(e, "l-305")
               for e in _elements(ctx)), "no fact surface lists the leads touching wb's fact"
    assert any(HEURISTIC in s.lower() for s in _strings(ctx)) or _marked_regions(ctx, HEURISTIC)
    # The noise context (pre-flight's record) and the questioner inputs (samples, base story).
    assert _holds(ctx, DRIFT_MARK)
    assert _holds(ctx, S.marker("base", "story"))
    for system in S.SYSTEMS:
        assert _holds(ctx, S.marker(system, "samples"))
    # Built without any model call: render wrote no wire-log record.
    assert S.wire_log_records(built) == []
    # grade_episode drives render: the prompt it sends carries what the context holds.
    judge = _graded(built)
    assert judge.called(WB)
    prompt = judge.prompt_for(WB)
    for needle in (S.marker(CTL, "report"), S.marker(WC, "report"), DRIFT_MARK,
                   S.marker("base", "story")):
        assert needle in prompt, f"{needle} is in the context but not in the prompt sent"


# --------------------------------------------------------------------------------------
# d02a, d02b, d02g — the reference set.
# --------------------------------------------------------------------------------------


def test_1234_world_prompt_carries_control_and_every_gradable_sibling_as_references(
        tmp_path: Path) -> None:
    """In a triad (control a, planted b and c), world b's prompt carries a labelled reference
    section for the control and one for c, each with its leads, report and call list, and a
    marker planted in the control's report.md reaches b's prompt (today it reaches no prompt,
    C1/E-01)."""
    built = _family(tmp_path)
    judge = _graded(built)
    assert judge.called(WB)
    prompt = judge.prompt_for(WB)
    assert S.marker(CTL, "report") in prompt, "the control's report reaches no prompt (C1)"
    blocks = _reference_blocks(prompt, WB)
    for label, lead in ((CTL, "l-305"), (WC, "l-406")):
        block = blocks[label]
        assert S.marker(label, "report") in block, f"{label}'s report is not in its labelled block"
        assert (S.marker(label, "goal-" + lead) in block
                or S.marker(label, "summary-" + lead) in block), f"{label}'s lead {lead} is missing"
        assert S.marker(label, "call") in block, f"{label}'s call list is missing"
    assert S.marker(CTL, "report") not in blocks[WC]
    assert S.marker(WC, "report") not in blocks[CTL]


def test_1234_pair_family_has_the_control_as_its_only_reference(tmp_path: Path) -> None:
    """In a pair family (control and one planted world), the planted world's prompt carries
    exactly one reference section, the control's."""
    built = _family(tmp_path, [w for w in _triad() if w.label in (CTL, WB)])
    judge = _graded(built)
    assert judge.called(WB)
    prompt = judge.prompt_for(WB)
    lo, hi = _sections(prompt)["references"]
    assert _host_hits(prompt, S.label_re(CTL), lo, hi), "the control heads no reference block"
    references = prompt[lo:hi]
    assert references.count(S.marker(CTL, "report")) == 1, (
        "the pair's references carry the control's report other than exactly once")
    block = _reference_blocks(prompt, WB, (CTL, WB))[CTL]
    assert S.marker(CTL, "call") in block
    assert S.marker(CTL, "report") in block


_UNGRADABLE = {
    "o5-failed": ({"world_record": "did not finish"}, "did not finish"),
    "cut-short": ({"run_end": {"truncated_by": "budget", "closed_before_cut": False}}, "budget"),
    "malformed": ({"report": ("---\ndisposition: benign\noutcome: stands\ndisposition: malicious\n"
                              f"---\nWorld wx closed. {S.marker('wx', 'report')}\n")}, "report"),
}


@pytest.mark.parametrize("kind", sorted(_UNGRADABLE))
def test_1234_ungradable_planted_world_is_in_no_reference_set(tmp_path: Path, kind: str) -> None:
    """A planted world that failed O5, was cut short, or is malformed appears in no other
    world's prompt or the family prompt as a reference: a marker in its report reaches no
    prompt, and its own row keeps the named reason it carries today."""
    # rejected: grading on a thinned, flagged or partial run set (X5)
    fields, reason_word = _UNGRADABLE[kind]
    wx = {"role": "D", "calls": [_call("l-777", params=_q(f"user:alice {S.marker('wx', 'call')}"))],
          **fields}
    built = _family(tmp_path, _triad(wx=wx))
    judge = _graded(built)
    for label in (WB, WC, S.FAMILY):
        assert judge.called(label), f"no call was made for {label}"
    assert not judge.called("wx"), "the ungradable world was judged"
    hidden = [S.marker("wx", what) for what in
              ("report", "investigation", "call", "goal-l-777", "summary-l-777")]
    for agent, prompt in zip(judge.agent_ids, judge.prompts, strict=True):
        leaked = [m for m in hidden if m in prompt]
        assert not leaked, f"{agent}'s prompt carries the ungradable world's text: {leaked}"
    # The positive control: a gradable sibling IS a reference, and wx heads no reference block.
    prompt = judge.prompt_for(WB)
    assert S.marker(WC, "report") in _reference_blocks(prompt, WB)[WC]
    lo, hi = _sections(prompt)["references"]
    assert not _host_hits(prompt, S.label_re("wx"), lo, hi), "wx heads a reference block"
    reason = S.row(built, "wx").get(S.COINED["row.ungradable_reason"])
    assert isinstance(reason, str), f"wx's row carries no named reason: {reason!r}"
    assert reason_word in reason, f"wx's row does not keep its named reason ({reason_word!r}): {reason!r}"


# --------------------------------------------------------------------------------------
# d03a, s_A71 — the computed header.
# --------------------------------------------------------------------------------------


def _header_worlds(**over: dict[str, Any]) -> list[S.World]:
    """Each run with its own reached verdict, axis, label basis and entity."""
    worlds = {
        CTL: {"label_basis": "policy-rule"},
        WB: {"facts": [S.fact("f-wb", entities=("ent-wb-917",), label=WB)], "declared": "malicious",
             "reached": "false-positive", "axis": f"axis {S.marker(WB, 'axis')}",
             "label_basis": "judgment"},
        WC: {"facts": [S.fact("f-wc", entities=("ent-wc-406",), label=WC)], "declared": "malicious",
             "reached": "inconclusive", "axis": f"axis {S.marker(WC, 'axis')}",
             "label_basis": "policy-rule"},
    }
    for label, fields in over.items():
        worlds[label].update(fields)
    return _triad(**worlds)


def _has_word(text: str, word: str) -> bool:
    return bool(re.search(rf"(?<![A-Za-z0-9_\-]){re.escape(word)}(?![A-Za-z0-9_\-])", text))


def test_1234_header_names_each_runs_role_facts_and_reached_verdict(tmp_path: Path) -> None:
    """The computed header carries, for every run in a block labelled with that run (the host
    label outside the untrusted frames, the run's manifest and report text framed in place, A10),
    its role, its facts with entities, story, axis, declared verdict and label_basis from the
    manifest, its reached verdict from that run's own archived report.md, the served systems and
    the discriminator predicate."""
    predicate = f"did the analyst look at idp after the branch {S.marker('family', 'predicate')}"
    built = _family(tmp_path, _header_worlds(), predicate=predicate)
    judge = _graded(built)
    assert judge.called(WB)
    prompt = judge.prompt_for(WB)
    span = _sections(prompt)["header"]
    header = prompt[span[0]:span[1]]
    blocks = _blocks(prompt, span, LABELS)
    expect = {
        CTL: {"role": "A", "declared": "benign", "reached": "benign", "basis": "policy-rule"},
        WB: {"role": "B", "declared": "malicious", "reached": "false-positive", "basis": "judgment",
             "fact": S.marker(WB, "fact-f-wb"), "entity": "ent-wb-917", "axis": S.marker(WB, "axis")},
        WC: {"role": "C", "declared": "malicious", "reached": "inconclusive", "basis": "policy-rule",
             "fact": S.marker(WC, "fact-f-wc"), "entity": "ent-wc-406", "axis": S.marker(WC, "axis")},
    }
    for label, want in expect.items():
        block = blocks[label]
        story = S.marker(label, "story")
        assert story in block, f"run {label}'s header block lacks its story"
        at = span[0] + header.index(story)
        assert _in_frame(prompt, at), f"run {label}'s story sits outside an untrusted frame (A10)"
        assert _has_word(block, want["role"]), f"run {label}'s header block lacks its role"
        for key in ("declared", "reached", "basis", "fact", "entity", "axis"):
            if key in want:
                assert want[key] in block, f"run {label}'s header block lacks its {key} {want[key]!r}"
    # Each reached verdict is that run's own (read off its own report.md), never a sibling's.
    for label, foreign in ((WB, "inconclusive"), (CTL, "inconclusive"), (WC, "false-positive"),
                           (CTL, "false-positive")):
        assert foreign not in blocks[label], f"run {label}'s header shows a sibling's verdict {foreign!r}"
    for system in S.SYSTEMS:
        assert system in header, f"the header does not name served system {system}"
    assert S.marker("family", "predicate") in header, "the header lacks the discriminator predicate"


def test_1234_control_reached_a_verdict_other_than_its_declared_one(tmp_path: Path) -> None:
    """A wrong control is information in the header (its reached verdict is shown) and gates
    nothing."""
    built = _family(tmp_path, _triad(**{CTL: {"reached": "false-positive"}}))
    judge = _graded(built)
    for label in (WB, WC):
        assert judge.called(label), f"a wrong control gated the pass ({label} not judged)"
    assert not S.stamp(built), "a wrong control stamped the family not graded"
    for label in (WB, WC):
        assert S.row(built, label).get(S.RULED["row.completed_draws"]) == 1
        prompt = judge.prompt_for(label)
        block = _blocks(prompt, _sections(prompt)["header"], LABELS)[CTL]
        assert "false-positive" in block, f"{label}'s header does not show the control's reached verdict"
        assert "benign" in block, f"{label}'s header does not show the control's declared verdict"


# --------------------------------------------------------------------------------------
# d03f, d03g, d03h, s_A34, s_D21 — fact surfaces and the aligned lead view.
# --------------------------------------------------------------------------------------

_SURFACE_LEADS = {"l-001", "l-201", "l-305", "l-406", "l-556", "l-560", "l-917"}


def test_1234_fact_surface_names_forged_systems_entities_and_touching_leads(tmp_path: Path) -> None:
    """Each fact's surface names the systems its forged rows were served on (oracle store
    forged.jsonl, fact_id to system) and its entities, and for each run the leads that queried one
    of those systems or mention one of those entities in their params."""
    # rejected: a matcher tolerance for degenerate entities (X4)
    # f-wb1's forged row is on siem-x (and served there); f-wb2's is on edr and was never served
    # an oracle answer, so only forged.jsonl can name edr for it.
    wb = S.planted(WB, facts=[S.fact("f-wb1", entities=("ent917",), label=WB),
                              S.fact("f-wb2", entities=("ent918",), label=WB)],
                   forged=[_forged("fg-wb-1", "f-wb1", "siem-x"), _forged("fg-wb-2", "f-wb2", "edr")],
                   calls=[_call("l-201", params=_q("user:alice")),
                          _altered("l-917", "host:h917", system="siem-x", fact_id="f-wb1")])
    ctl = S.control(CTL, calls=[_call("l-305", "siem-x", "lookup", {"entity": "x305"}),
                                _call("l-556", "idp", "lookup", {"entity": "zed556"}),
                                _call("l-560", "edr", "query", _q("host:h560"))])
    wc = S.planted(WC, role="C", facts=[S.fact("f-wc", entities=("entwc",), label=WC)],
                   forged_system="siem-x", calls=[_call("l-406", "idp", "query", _q("user:ent917"))])
    built = _family(tmp_path, [ctl, wb, wc])
    ctx = _context(built, WB)
    expected = {
        "f-wb1": ("f-wb2", "siem-x", "ent917", {"l-917", "l-305", "l-406"}, (WB, CTL, WC)),
        "f-wb2": ("f-wb1", "edr", "ent918", {"l-560"}, (CTL,)),
    }
    for fact_id, (other, system, entity, leads, runs) in expected.items():
        entries = [e for e in _elements(ctx) if _holds(e, fact_id) and not _holds(e, other)]
        matching = [e for e in entries
                    if _holds(e, system) and _holds(e, entity) and _leads_in(e, _SURFACE_LEADS) == leads
                    and all(_holds_label(e, run) for run in runs)]
        assert matching, (
            f"no fact surface for {fact_id} names {system}, {entity} and exactly the touching leads "
            f"{sorted(leads)} with their runs {runs}; entries holding {fact_id} hold "
            f"{[sorted(_leads_in(e, _SURFACE_LEADS)) for e in entries]}")


def _aligned_worlds() -> list[S.World]:
    """wb: l-201 (idp query, before its first altered answer), l-917 (siem-x query, the first
    altered answer; siem-x is the forged system of wb's fact), l-918 (edr lookup).
    ctl: l-211 (idp query), l-305 (siem-x lookup: touches wb's fact surface), l-556 (idp lookup:
    matches nothing). wc: l-221 (idp query), l-408 (edr lookup)."""
    wb = S.planted(WB, facts=[S.fact("f-wb", entities=("ent917",), label=WB)], forged_system="siem-x",
                   calls=[_call("l-201", params=_q("user:alice")),
                          _altered("l-917", "host:h917", system="siem-x"),
                          _call("l-918", "edr", "lookup", {"entity": "h918"})])
    ctl = S.control(CTL, calls=[_call("l-211", params=_q("user:alice")),
                                _call("l-305", "siem-x", "lookup", {"entity": "x305"}),
                                _call("l-556", "idp", "lookup", {"entity": "zed556"})])
    wc = S.planted(WC, role="C", facts=[S.fact("f-wc", entities=("entwc",), label=WC)],
                   forged_system="siem-x",
                   calls=[_call("l-221", params=_q("user:alice")),
                          _call("l-408", "edr", "lookup", {"entity": "h408"})])
    return [ctl, wb, wc]


_ALIGNED_LEADS = {"l-001", "l-201", "l-211", "l-221", "l-305", "l-408", "l-556", "l-917", "l-918"}
_ALIGNED_ROWS = {"l-917": {"l-305"}, "l-918": {"l-408"}, "l-556": set(),
                 "l-201": {"l-211", "l-221"}}


def test_1234_aligned_lead_view_matches_by_surface_then_system_and_verb(tmp_path: Path) -> None:
    """Leads are matched across runs through fact surfaces first and by system and verb second,
    an unmatched lead gets a row of its own, and the region before the judged world's first
    altered answer is marked shared baseline."""
    built = _family(tmp_path, _aligned_worlds())
    ctx = _context(built, WB)
    candidates = [c for c in _collections(ctx)
                  if any(_leads_in(e, _ALIGNED_LEADS) == {"l-917", "l-305"} for e in c)]
    assert candidates, ("no row in the context pairs wb's l-917 with the control's l-305, which "
                        "touch wb's fact surface on different verbs")
    verdicts = {i: _row_check(c, _ALIGNED_ROWS, _ALIGNED_LEADS) for i, c in enumerate(candidates)}
    assert any(not v for v in verdicts.values()), f"no row list is the aligned lead view: {verdicts}"
    regions = _marked_regions(ctx, BASELINE)
    assert any(_holds(r, "l-201") and not _holds(r, "l-917") for r in regions), (
        "nothing marks the region before wb's first altered answer (l-201) shared baseline apart "
        "from the altered call's row (l-917)")
    judge = _graded(built)
    assert judge.called(WB)
    assert BASELINE in _section(judge.prompt_for(WB), "aligned").lower(), (
        "the prompt's aligned lead view does not mark the shared baseline")


def test_1234_every_matched_row_and_surface_hit_is_labelled_heuristic(tmp_path: Path) -> None:
    """Every matched lead row and every fact-surface hit in the prompt is labelled heuristic:
    text-matched, not established."""
    built = _family(tmp_path, _aligned_worlds())
    judge = _graded(built)
    assert judge.called(WB)
    prompt = judge.prompt_for(WB)
    spans = _sections(prompt)
    # Three matched rows (l-917+l-305 by surface; l-918+l-408 and l-201+l-211+l-221 by system and
    # verb) and two hits on wb's fact surface (l-917, l-305): each carries its own label.
    rows = len(_host_hits(prompt, HEURISTIC_RE, *spans["aligned"]))
    hits = len(_host_hits(prompt, HEURISTIC_RE, *spans["surfaces"]))
    assert rows >= 3, f"{rows} heuristic label(s) over the aligned lead view's 3 matched rows"
    assert hits >= 2, f"{hits} heuristic label(s) over the 2 fact-surface hits"


def test_1234_one_lead_id_names_different_leads_in_two_runs(tmp_path: Path) -> None:
    """The aligned lead view never matches leads by lead id alone; a shared id across runs names
    different leads unless fact surface or system/verb matching pairs them; unmatched leads get
    their own rows, all labelled heuristic."""
    # l-001 is wb's lead before its first altered answer (idp lookup), the control's post-branch
    # edr query and wc's edr lookup: one id, three unrelated leads.
    wb = S.planted(WB, facts=[S.fact("f-wb", entities=("ent917",), label=WB)], forged_system="siem-x",
                   calls=[_call("l-001", "idp", "lookup", {"entity": "b001"}),
                          _altered("l-917", "host:h917", system="siem-x")])
    ctl = S.control(CTL, calls=[_call("l-001", "edr", "query", _q("host:a001")),
                                _call("l-305", "siem-x", "lookup", {"entity": "x305"})])
    wc = S.planted(WC, role="C", facts=[S.fact("f-wc", entities=("entwc",), label=WC)],
                   forged_system="siem-x", calls=[_call("l-001", "edr", "lookup", {"entity": "c001"})])
    built = _family(tmp_path, [ctl, wb, wc])
    universe = {"l-001", "l-305", "l-917"}
    ctx = _context(built, WB)
    lists = [c for c in _collections(ctx)
             if any(_leads_in(e, universe) == {"l-917", "l-305"} for e in c)]
    assert lists, "no row pairs wb's l-917 with the control's l-305 (the positive control)"
    shares = {i: [e for e in c if "l-001" in _leads_in(e, universe)] for i, c in enumerate(lists)}
    # Three runs' l-001 leads, each in a row of its own (a row per pair of runs holds more rows).
    good = [i for i, rows in shares.items()
            if len(rows) >= 3 and all(_leads_in(e, universe) == {"l-001"} for e in rows)]
    assert good, ("the three runs' l-001 leads are not three rows of their own: rows holding l-001 "
                  f"per candidate list: {[len(r) for r in shares.values()]}")
    judge = _graded(built)
    assert judge.called(WB)
    prompt = judge.prompt_for(WB)
    labels = len(_host_hits(prompt, HEURISTIC_RE, *_sections(prompt)["aligned"]))
    assert labels >= 4, f"{labels} heuristic label(s) over 4 aligned rows (3 x l-001, l-917+l-305)"


_ENTITY_CASES = {
    "empty": ([""], None),
    "whitespace-only": (["   "], None),
    "over-256-characters": (["e" * 257], None),
    "pattern-metacharacters": (["a.b*c", "[a-"], {"l-917", "l-305", "l-307"}),
    "single-character": (["z"], {"l-917", "l-305"}),
}


@pytest.mark.parametrize("case", sorted(_ENTITY_CASES))
def test_1234_fact_entity_that_matches_every_lead(tmp_path: Path, case: str) -> None:
    """Entities match as literal substrings, never as patterns. Empty and over-256-character
    entities are refused at manifest load (OB21), and so is a whitespace-only entity (X4), so
    none reaches the matcher; single-character entities match literally and the heuristic label
    covers the noise (M2)."""
    entities, touching = _ENTITY_CASES[case]
    # wb's fact is forged on siem-x; l-917 queried siem-x (a system hit). The control's l-305 and
    # l-307 carry an entity literally; l-306 carries what the entity matches only as a pattern
    # ("aXbbbc" for a.b*c) or not at all ("host1" for z).
    hit = "user:a.b*c" if case == "pattern-metacharacters" else "user:zed"
    miss = "aXbbbc" if case == "pattern-metacharacters" else "host1"
    wb = S.planted(WB, facts=[S.fact("f-wb", entities=entities, label=WB)], forged_system="siem-x",
                   calls=[_altered("l-917", "host:h917", system="siem-x")])
    ctl = S.control(CTL, calls=[_call("l-305", params=_q(hit)),
                                _call("l-306", "idp", "lookup", {"entity": miss}),
                                _call("l-307", params=_q("user:[a-"))])
    wc = S.planted(WC, role="C", forged_system="edr",
                   calls=[_call("l-406", "edr", params=_q("host:db-1"))])
    built = _family(tmp_path, [ctl, wb, wc])
    if touching is None:
        family_error = S.sym(S.FAMILY_LOADER, "FamilyError")
        with S.mod("_io").bind(built.ep) as view, pytest.raises(family_error):
            S.sym(S.FAMILY_LOADER, "load_family")(view)
        judge = S.judge()
        S.grade_refused(built, judge)
        assert judge.calls == 0, "a refused manifest still reached the model"
        return
    universe = {"l-001", "l-305", "l-306", "l-307", "l-406", "l-917"}
    ctx = _context(built, WB)
    entries = [e for e in _elements(ctx) if _holds(e, "f-wb") and not _holds(e, "f-wc")]
    surfaces = [_leads_in(e, universe) for e in entries if _holds(e, "siem-x")]
    assert touching in surfaces, (
        f"wb's fact surface does not list exactly the literal hits {sorted(touching)}; its "
        f"entries list {[sorted(s) for s in surfaces]}")


# --------------------------------------------------------------------------------------
# d03i, d03j, d04b — what the judged world and the references show.
# --------------------------------------------------------------------------------------


def test_1234_planted_world_shown_as_designed_built_and_served(tmp_path: Path) -> None:
    """The judged planted world is shown in three layers: designed (its manifest entry), built
    (its forged rows per fact, claims, verifier verdicts, collisions and pre-flight's calibration
    result) and served (its altered calls)."""
    claim = {"added": [{"forged_id": "fg-wb-1", "fact_id": "f-wb"}], "removed": [], "changed": [],
             "counts": [], "entity_refs": [S.marker(WB, "claim")]}
    verdict = {"passed": True, "reason": f"the fact's telemetry is present {S.marker(WB, 'verdict')}"}
    worlds = _triad(**{WB: {"axis": f"axis {S.marker(WB, 'axis')}", "calls": [
        _call("l-201", params=_q("user:alice")),
        _altered("l-917", f"user:alice host:db-1 {S.marker(WB, 'altered')}",
                 ledger_extra={"claim": claim, "verifier_verdict": verdict})]}})
    built = _family(tmp_path, worlds)
    collisions = S.sym("_episode_paths", "COLLISIONS_FILENAME")
    built.oracle_path(WB, collisions).write_text(json.dumps(
        {"forged_id": "fg-wb-1", "column": "event_id", "value": S.marker(WB, "collision"),
         "real_rows": []}) + "\n", encoding="utf-8")
    # Pre-flight's calibration (`registry.calibrate_one`) froze the forged rows and the facts it
    # recorded (`facts.jsonl`) and logged its replay as a `preflight` row of the world's
    # oracle-side ledger (N14). Either record shows its result.
    built.oracle_path(WB, "facts.jsonl").write_text(json.dumps(
        {"entity": "alice", "field": "logon_host", "value": S.marker(WB, "calibration")}) + "\n",
        encoding="utf-8")
    built.oracle_path(WB, "ledger.jsonl").write_text(json.dumps(
        {"actor": "preflight", "system": "idp", "verb": "query",
         "params": _q(f"user:alice host:db-1 {S.marker(WB, 'calibrated-call')}")}) + "\n",
        encoding="utf-8")
    judge = _graded(built)
    assert judge.called(WB)
    prompt = judge.prompt_for(WB)
    layers = {
        "designed": [S.marker(WB, "story"), S.marker(WB, "axis"), S.marker(WB, "fact-f-wb")],
        "built": [S.marker(WB, "forged-f-wb"), S.marker(WB, "claim"), S.marker(WB, "verdict"),
                  S.marker(WB, "collision")],
        "served": [S.marker(WB, "altered")],
    }
    missing = {layer: [m for m in marks if m not in prompt] for layer, marks in layers.items()}
    assert not any(missing.values()), f"layers missing from wb's prompt: {missing}"
    assert (S.marker(WB, "calibration") in prompt
            or S.marker(WB, "calibrated-call") in prompt), "pre-flight's calibration result is not shown"


def test_1234_prompt_carries_the_samples_record_and_base_story(tmp_path: Path) -> None:
    """The world prompt carries the samples record per served system and the manifest's
    base_story."""
    built = _family(tmp_path)
    judge = _graded(built)
    for label in (WB, WC):
        assert judge.called(label)
        prompt = judge.prompt_for(label)
        for system in S.SYSTEMS:
            assert S.marker(system, "samples") in prompt, f"{label}'s prompt lacks {system}'s samples"
        assert S.marker("base", "story") in prompt, f"{label}'s prompt lacks the base story"


def test_1234_reference_run_shows_a_full_answer_only_where_it_differs(tmp_path: Path) -> None:
    """A reference run's section holds its leads, report and call list, and a full answer only
    for a call whose answer differs from the judged world's matched call."""
    same = {"rows": [{"note": "MARK-shared-answer"}]}
    ctl = S.control(CTL, calls=[
        _call("l-305", params=_q("user:alice"), payload=same),
        _call("l-306", "edr", params=_q("host:db-1"), payload={"rows": [{"note": "MARK-ctl-diff-answer"}]})])
    wb = S.planted(WB, calls=[
        _call("l-201", params=_q("user:alice"), payload=same),
        _call("l-202", "edr", params=_q("host:db-1"), payload={"rows": [{"note": "MARK-wb-diff-answer"}]}),
        _altered("l-917", "user:alice host:db-1")])
    built = _family(tmp_path, [ctl, wb])
    judge = _graded(built)
    assert judge.called(WB)
    prompt = judge.prompt_for(WB)
    block = _reference_blocks(prompt, WB, (CTL, WB))[CTL]
    assert S.marker(CTL, "report") in block
    for lead in ("l-305", "l-306"):
        assert (S.marker(CTL, "goal-" + lead) in block
                or S.marker(CTL, "summary-" + lead) in block), f"the control's lead {lead} is missing"
    for params in ("user:alice", "host:db-1"):
        assert params in block, f"the control's call list lacks its {params} call"
    assert "MARK-ctl-diff-answer" in block, "the answer that differs is not shown in full"
    assert "MARK-shared-answer" not in block, "an answer equal to wb's matched call is shown in full"
    assert "MARK-shared-answer" in prompt, "wb's own answer is missing (the channel shows answers)"


# --------------------------------------------------------------------------------------
# d03k, d03l, d04a, d04h — where the prompt lives, its order, its wording.
# --------------------------------------------------------------------------------------


def test_1234_judge_context_is_stored_nowhere_but_the_wire_log(tmp_path: Path) -> None:
    """After a pass, no file under the episode holds the contrast table, fact surfaces or aligned
    lead view except the judge's wire-log records of the prompt, and a second render over the
    unchanged archive produces the same prompt."""
    built = _family(tmp_path)
    archive = S.episode_texts(built, skip=())
    # Pass 1's call for wb fails (#921 P9), so the bare re-run renders wb a second time over the
    # unchanged archive.
    first = _graded(built, S.judge(fail={WB}))
    second = _graded(built)
    assert first.called(WB), "pass 1 made no call for wb"
    assert second.called(WB), "the bare re-run did not render wb again"
    prompt = second.prompt_for(WB)
    derived = [line for section in ("contrast", "surfaces", "aligned")
               for line in _derived_lines(_section(prompt, section))
               if not any(line in text for text in archive.values())]
    assert derived, "the computed sections hold no line of their own to look for"
    after = S.episode_texts(built, skip=())
    for rel, text in after.items():
        if rel.startswith("wire_logs/") or archive.get(rel) == text:
            continue
        stored = [line for line in derived if line in text]
        assert not stored, f"{rel} stores computed context: {stored[:3]}"
    wire = [r for r in S.wire_log_records(built) if r.get("agent_id") == f"judge:{WB}:0"]
    assert wire, "no wire-log record for wb's call"
    assert all(line in wire[-1].get("prompt", "") for line in derived), (
        "the wire log does not hold the computed sections (the positive control)")
    assert S.unsalted(first.prompt_for(WB)) == S.unsalted(prompt), (
        "a second render over the unchanged archive produced a different prompt")


def test_1234_wire_log_holds_the_prompt_with_its_contrast_table(tmp_path: Path) -> None:
    """The judge's wire-log record for world b holds the whole prompt sent, and that prompt
    contains b's contrast table."""
    built = _family(tmp_path)
    judge = _graded(built)
    assert judge.called(WB)
    records = [r for r in S.wire_log_records(built) if r.get("agent_id") == f"judge:{WB}:0"]
    assert len(records) == 1, f"{len(records)} wire-log records for wb's call"
    assert records[0].get("prompt") == judge.prompt_for(WB), "the wire log is not the prompt sent"
    prompt = records[0]["prompt"]
    row = _blocks(prompt, _sections(prompt)["contrast"], LABELS)[WB]
    assert "l-917" in row, "wb's contrast row does not name the lead that received its altered answer"


def test_1234_world_prompt_sections_run_in_order(tmp_path: Path) -> None:
    """The world prompt's sections run in this order: task and taxonomy, computed header,
    contrast table, fact surfaces and aligned lead view, compressed reference runs, the judged
    world's views, noise context (pre-flight record)."""
    built = _family(tmp_path, drift=[_drift()])
    judge = _graded(built)
    assert judge.called(WB)
    prompt = judge.prompt_for(WB)
    spans = _sections(prompt)
    start = {s: lo for s, (lo, _hi) in spans.items()}
    assert start["header"] < start["contrast"] < min(start["surfaces"], start["aligned"])
    assert max(start["surfaces"], start["aligned"]) < start["references"] < start["focus"] < start["noise"]
    task = _task(prompt)
    for word in (*S.INVESTIGATOR_BUCKETS, *S.WORLD_FINDING_BUCKETS):
        assert word in task, f"the task and taxonomy do not name {word!r} before the header"
    content = {
        "header": [S.marker(label, "story") for label in LABELS],
        "contrast": ["l-917"],
        "references": [S.marker(CTL, "report"), S.marker(WC, "report")],
        "focus": [S.marker(WB, "investigation"), S.marker(WB, "call")],
        "noise": [DRIFT_MARK],
    }
    for section, needles in content.items():
        text = _section(prompt, section)
        for needle in needles:
            assert needle in text, f"{needle} is not in the {section} section"
    assert DRIFT_MARK not in prompt[:start["noise"]], "the pre-flight record is not last"


_WITHHELD_RULE = re.compile(S.COINED["re.withheld_rule"], re.IGNORECASE | re.DOTALL)
_REFERENCE_RULE = re.compile(S.COINED["re.reference_rule"], re.IGNORECASE | re.DOTALL)


def _says_other_worlds_withheld(sentence: str) -> bool:
    return bool(_WITHHELD_RULE.match(sentence))


def _says_reference_facts_in_their_section(sentence: str) -> bool:
    return bool(_REFERENCE_RULE.match(sentence))


def test_1234_role_prompt_and_task_no_longer_say_other_worlds_are_withheld(tmp_path: Path) -> None:
    """Neither judge/role.md nor the world task text says every other world's facts are withheld;
    both say a reference run's facts sit only in that run's labelled section."""
    role = (Path(S.mod(S.JUDGE_RUN).__file__).parent / "role.md").read_text(encoding="utf-8")
    _assert_reference_rule("judge/role.md", role)
    built = _family(tmp_path)
    judge = _graded(built)
    assert judge.called(WB)
    _assert_reference_rule("the world task text", _task(judge.prompt_for(WB)))


def _assert_reference_rule(name: str, text: str) -> None:
    claims = [s for s in _sentences(text) if _says_other_worlds_withheld(s)]
    assert not claims, f"{name} still says other worlds' facts are withheld: {claims}"
    assert any(_says_reference_facts_in_their_section(s) for s in _sentences(text)), (
        f"{name} does not say a reference run's facts sit only in its labelled section")


# --------------------------------------------------------------------------------------
# s_A9, s_L24 — references are computed from the archive alone.
# --------------------------------------------------------------------------------------

_REPLY_MARKS = ("MARK-wb-reply-claim", "MARK-wb-reply-world", "MARK-wb-reply-note")


def _marked_reply() -> dict:
    """A reply for wb whose every text carries a marker, with explicit pointers (ctl/wb labels)."""
    return S.world_reply(
        "lead-quality", ["idp"], noise_floor_note=f"one trial {_REPLY_MARKS[2]}",
        investigator=[S.inv("lead-quality", contrast=[S.conduct(WB), S.conduct(CTL)],
                            claim=f"the lead was never revisited {_REPLY_MARKS[0]}")],
        world=[S.wf("mislabelled", systems=["idp"], evidence=[S.plan_ptr(WB)],
                    claim=f"the declared verdict does not follow {_REPLY_MARKS[1]}")])


def test_1234_reference_render_after_the_reference_world_was_judged(tmp_path: Path) -> None:
    """World c's prompt contains nothing of b's judge reply; c's prompt is byte-identical whether
    b was judged before or after c (P-c, P-b: inputs derived from the immutable archive)."""
    built = _family(tmp_path)
    # Pass 1: both calls fail (#921 P9): c is rendered while b has no reply. Pass 2 re-grades both,
    # b first (manifest order), so c is rendered after b's reply is on disk.
    first = _graded(built, S.judge(fail={WB, WC}))
    second = _graded(built, S.judge({WB: _marked_reply()}))
    assert first.called(WC), "pass 1 made no call for c"
    assert second.called(WB), "pass 2 did not judge b"
    assert second.called(WC), "pass 2 did not judge c"
    assert second.agent_ids.index(f"judge:{WB}:0") < second.agent_ids.index(f"judge:{WC}:0")
    draws = S.draw_files(built, WB)
    assert draws, "b has no draw file"
    assert any(m in draws[0].read_text(encoding="utf-8") for m in _REPLY_MARKS), (
        "b's reply is not on disk when c is rendered (the scenario did not happen)")
    prompt = second.prompt_for(WC)
    leaked = [m for m in _REPLY_MARKS if m in prompt]
    assert not leaked, f"c's prompt carries b's judge reply: {leaked}"
    assert S.marker(WB, "report") in _reference_blocks(prompt, WC)[WB], (
        "b is not a reference for c (the positive control)")
    assert S.unsalted(first.prompt_for(WC)) == S.unsalted(prompt), (
        "c's prompt depends on whether b was judged before it")


def test_1234_references_do_not_depend_on_whether_a_sibling_has_been_graded_yet(
        tmp_path: Path) -> None:
    """C is a reference for B in both passes whether or not C has a completed draw; the reference
    set is computed from the archive alone."""
    built = _family(tmp_path)
    # Pass 1: b's call fails; b is rendered before c has any draw. Pass 2 re-grades b alone, with
    # c's draw completed and c's row carried, not re-read.
    first = _graded(built, S.judge(fail={WB}))
    assert S.row(built, WC).get(S.RULED["row.completed_draws"]) == 1
    second = _graded(built)
    assert first.called(WB), "pass 1 made no call for b"
    assert second.called(WB), "pass 2 did not re-judge b"
    assert not second.called(WC), "c was re-judged (the scenario needs its draw carried)"
    for which, judge in (("first", first), ("second", second)):
        prompt = judge.prompt_for(WB)
        assert S.marker(WC, "report") in _reference_blocks(prompt, WB)[WC], (
            f"c is not a reference for b in the {which} pass")
    assert S.unsalted(first.prompt_for(WB)) == S.unsalted(second.prompt_for(WB))


# --------------------------------------------------------------------------------------
# s_A42, s_D17 — an excluded world's facts reach no other world's prompt.
# --------------------------------------------------------------------------------------


def test_1234_failed_world_detail_quoting_its_forged_rows(tmp_path: Path) -> None:
    """A failed world's detail quoting its forged rows reaches no per-world prompt, framed or
    not: the failed world is in no reference set (M1, A3), so its facts have no labelled section
    in another world's prompt (M3). It may reach the family prompt inside an untrusted frame, and
    the page escaped."""
    live = f"<script>alert('{S.marker('wx', 'detail')}')</script>"
    detail = (f"refused: frozen row fg-wx-1 {{'note': '{S.marker('wx', 'detail')}'}} did not verify"
              f" {live}")
    wx = {"role": "D", "world_record": "oracle unservable", "world_record_detail": detail}
    built = _family(tmp_path, _triad(wx=wx))
    judge = _graded(built)
    for label in (WB, WC):
        assert judge.called(label), f"no call was made for {label}"
    assert not judge.called("wx"), "the failed world was judged"
    hidden = [S.marker("wx", "detail"), S.marker("wx", "forged-f-wx"), S.marker("wx", "fact-f-wx")]
    for prompt in _world_prompts(judge):
        leaked = [m for m in hidden if m in prompt]
        assert not leaked, f"a per-world prompt carries the failed world's facts: {leaked}"
    family = judge.prompt_for(S.FAMILY)
    if S.marker("wx", "detail") in family:
        S.assert_wrapped_untrusted(family, S.marker("wx", "detail"), "the failed world's detail")
    # The page shows the recorded prompts; wherever it shows the detail, the markup is escaped.
    # The archive carries the live markup verbatim, so its absence from the page is observable.
    record = S.S24.read_world_record(built.ep, "wx")
    assert any(live in text for text in S.strings_in(record)), (
        "fixture: the failed world's record does not carry the live markup")
    assert live not in S.page(built), "the page renders the failed world's detail as live markup"
    # The positive controls: the judged world's own forged rows reach its own prompt, and a
    # gradable sibling's facts reach it too (the channel the failed world's facts would take).
    assert S.marker(WB, "forged-f-wb") in judge.prompt_for(WB)
    assert S.marker(WC, "fact-f-wc") in judge.prompt_for(WB), "a gradable sibling's facts are withheld"


@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_1234_reference_file_links_to_an_ungradable_worlds_oracle_store(
        tmp_path: Path, link: str) -> None:
    """A link in a reference archive to another world's oracle store is refused as a link; the
    excluded world's facts appear in no other prompt."""
    wx = {"role": "D", "world_record": "oracle unservable"}
    built = _family(tmp_path, _triad(wx=wx))
    target = built.oracle_path("wx")
    report = built.world_dir(WC) / "report.md"
    if link == "symlink":
        S.plant_symlink(report, os.path.relpath(target, report.parent))
    else:
        S.plant_hardlink(report, target)
    judge = _graded(built)
    assert judge.called(WB), "the pass did not judge b"
    hidden = [S.marker("wx", "forged-f-wx"), S.marker("wx", "fact-f-wx")]
    for prompt in _world_prompts(judge):
        leaked = [m for m in hidden if m in prompt]
        assert not leaked, f"the excluded world's facts reached a world prompt: {leaked}"
    assert S.marker("wx", "forged-f-wx") in built.oracle_path("wx").read_text(encoding="utf-8"), (
        "fixture: the excluded world's store does not carry the marker the prompts are read for")
    assert S.marker("wx", "forged-f-wx") not in judge.prompt_for(S.FAMILY)
    # Refused as a link: wc's report did not read, so wc is malformed, named by the file.
    assert not judge.called(WC), "the linked reference run was judged as if its report read"
    reason = S.row(built, WC).get(S.COINED["row.ungradable_reason"])
    assert isinstance(reason, str), f"wc's row names no reason: {reason!r}"
    assert "report.md" in reason, f"wc's row does not name report.md: {reason!r}"
    # The positive control: the control's archive still reaches b's prompt as a reference.
    assert S.marker(CTL, "report") in _reference_blocks(judge.prompt_for(WB), WB)[CTL]


# --------------------------------------------------------------------------------------
# d11b — drift is information.
# --------------------------------------------------------------------------------------


def test_1234_drift_is_shown_as_noise_and_never_refuses_grading(tmp_path: Path) -> None:
    """An accepted family whose pre-flight record lists drifted calls is graded, and the drift
    entries appear in each world prompt's noise context (the pre-flight record)."""
    # rejected: drift as a pre-grading refusal (N-d, N16 stands)
    built = _family(tmp_path, drift=[_drift()])
    judge = _graded(built)
    for label in (WB, WC):
        assert judge.called(label), f"drift refused grading ({label} not judged)"
    assert not S.stamp(built)
    for label in (WB, WC):
        assert S.row(built, label).get(S.RULED["row.completed_draws"]) == 1
        assert DRIFT_MARK in _section(judge.prompt_for(label), "noise"), (
            f"{label}'s noise context does not list the drifted call")


# --------------------------------------------------------------------------------------
# g03 — the judge call's payload.
# --------------------------------------------------------------------------------------

_SLOT = re.compile(r"\{[A-Za-z_][A-Za-z0-9_.]*\}")
_ABSENT = re.compile(S.COINED["re.layer_absent"], re.IGNORECASE)


def _new_absence_lines(absent: str, present: str, keywords: tuple[str, ...]) -> list[str]:
    """Lines only the layer-absent prompt has that name the layer and say it is absent."""
    had = set(S.unsalted(present).splitlines())
    return [line for line in S.unsalted(absent).splitlines()
            if line not in had and _ABSENT.search(line)
            and any(k in line.lower() for k in keywords)]


def test_1234_judge_call_sends_role_as_system_and_the_built_prompt_as_user_with_no_unbound_slot(
        tmp_path: Path) -> None:
    """The fake judge records the messages of a world call and of the family call: the system turn
    is judge/role.md and the user turn is the built prompt, and the two share no source (the
    template is never passed both as the raw system prompt and, rendered, as the user turn); no
    `{...}` slot token survives in either turn, including for a world whose lessons record or
    samples are absent (the prompt says the layer is absent instead). A planted world with no
    oracle store is not an absent layer but a failed read (AM15 read literally, principle 2;
    R6 (b), human 2026-10-12): it is malformed, named by the store, and never asked; only the
    control may lack a store."""
    role_path = Path(S.mod(S.JUDGE_RUN).__file__).parent / "role.md"
    role_text = role_path.read_text(encoding="utf-8")
    assert not _SLOT.search(role_text), "an unbound slot survives in the system turn"
    role_lines = [line.strip() for line in role_text.splitlines() if len(line.strip()) >= 25]
    # wc has no lessons record, wd no oracle store, and the family no samples record.
    sparse = {WC: {"lessons": False}, "wd": {"role": "D", "oracle": False}}
    # One episode id under two roots, so the two prompts differ only where a layer does (and
    # where the malformed wd's reference block is gone).
    present = _graded(_family(tmp_path, _triad(wd={"role": "D"}), root=tmp_path / "present"))
    absent_built = _family(tmp_path, _triad(**sparse), samples=None, root=tmp_path / "absent")
    absent = _graded(absent_built)
    assert present.called("wd"), "control: wd with its oracle store was not asked"
    for label in (WB, WC, S.FAMILY):
        assert absent.called(label), f"no call was made for {label}"
    assert not absent.called("wd"), "a planted world with no oracle store was asked"
    row = S.row(absent_built, "wd")
    assert row.get(S.EXISTING["row.ungradable"]) is True, f"wd is not ungradable: {row}"
    assert row.get(S.COINED["row.malformed"]) is True, f"wd is not marked malformed: {row}"
    reason = str(row.get(S.COINED["row.ungradable_reason"]) or "")
    assert "forged.jsonl" in reason, f"wd's reason does not name its oracle store: {reason!r}"
    for agent, prompt, system in zip(absent.agent_ids, absent.prompts, absent.system_prompts(),
                                     strict=True):
        assert system is not None, f"{agent}'s call carried no system turn"
        assert Path(system).resolve() == role_path.resolve(), (
            f"{agent}'s system turn is {system!r}, not judge/role.md")
        shared = [line for line in role_lines if line in prompt]
        assert not shared, f"{agent}'s user turn repeats the role prompt: {shared[:2]}"
        slots = _SLOT.findall(S.outside_untrusted_frames(prompt))
        assert not slots, f"{agent}'s user turn carries unbound slot(s) {slots}"
    layers = ((WC, (S.COINED["layer.lessons"],)), (WB, (S.COINED["layer.samples"],)))
    for label, keywords in layers:
        said = _new_absence_lines(absent.prompt_for(label), present.prompt_for(label), keywords)
        assert said, f"{label}'s prompt does not say its {keywords[0]} layer is absent"


# --------------------------------------------------------------------------------------
# g18 — the samples section render shows and the resolver accepts are one set.
# --------------------------------------------------------------------------------------

#: Each system's samples, by the marker its section's LAST answer carries: idp has a small
#: section, siem-x a large one (what a cap cuts), edr none at all.
_SAMPLES_END = {"idp": S.marker("idp", "samples"), "siem-x": "MARK-siem-x-samples-end",
                "edr": "MARK-edr-samples-never"}
_SAMPLES_ORDER = ("idp", "siem-x", "edr")


def _samples_record() -> dict:
    pad = [json.dumps({"rows": [{"i": i, "pad": "x" * 2000}]}) for i in range(30)]
    return {
        "idp": {"verbs": {"query": [json.dumps({"rows": [], "note": _SAMPLES_END["idp"]})]}},
        "siem-x": {"verbs": {"query": [json.dumps({"rows": [], "note": "MARK-siem-x-samples-start"}),
                                       *pad, json.dumps({"rows": [], "note": _SAMPLES_END["siem-x"]})]}},
    }


def _samples_reply() -> dict:
    """wb files, per system, a world finding citing only its samples section (index 2i) and a
    design finding citing the plan and the samples section (index 2i+1)."""
    world = []
    for system in _SAMPLES_ORDER:
        world.append(S.wf("mislabelled", systems=[system], evidence=[S.samples_ptr(system)]))
        world.append(S.wf("mislabelled", systems=[system],
                          evidence=[S.plan_ptr(WB), S.samples_ptr(system)]))
    return S.world_reply(S.NO_BUCKET, [], world=world)


def _samples_pass(tmp_path: Path, episode_id: str) -> tuple[S.Built, str]:
    built = _family(tmp_path, samples=_samples_record(), episode_id=episode_id)
    judge = _graded(built, S.judge({WB: _samples_reply()}))
    assert judge.called(WB), "wb was not judged (refused at the cap?)"
    return built, judge.prompt_for(WB)


def _samples_coherence(built: S.Built, prompt: str) -> tuple[set[str], list[str]]:
    shown = {s for s in _SAMPLES_ORDER if _SAMPLES_END[s] in prompt}
    queued = {r.get("finding_id") for r in S.questioner_queue()}
    problems = []
    for i, system in enumerate(_SAMPLES_ORDER):
        context_id, design_id = built.finding_id(WB, 0, 2 * i), built.finding_id(WB, 0, 2 * i + 1)
        context_lane = S.lane_of(built, context_id)
        if system in shown:
            if context_lane != S.LANES["user_record"]:
                problems.append(f"{system} is shown but its context cite took lane {context_lane}")
            if design_id not in queued:
                problems.append(f"{system} is shown but its design cite was not queued")
        else:
            if context_lane != S.LANES["dropped_unresolved"]:
                problems.append(f"{system} is not shown but its context cite took lane {context_lane}")
            if design_id in queued or S.lane_of(built, design_id) == S.LANES["questioner"]:
                problems.append(f"{system} is not shown but its design cite reached the questioner")
    return shown, problems


def test_1234_a_samples_pointer_resolves_exactly_when_the_prompt_shows_that_section(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A `samples.yaml#` pointer is a context pointer (and a design cite is dropped under O16)
    exactly when the prompt shows that served system's section of real answers: the section
    render shows and the fragment the resolver accepts are the same set, for a system with
    samples, a system without, and a section the cap cut. The control is a pointer at a shown
    section."""
    built, prompt = _samples_pass(tmp_path / "uncapped", S.EPISODE_ID)
    shown, problems = _samples_coherence(built, prompt)
    assert shown == {"idp", "siem-x"}, f"uncapped, the prompt shows {sorted(shown)}"
    assert not problems, problems
    # Capped so the charged sections must lose at least half of siem-x's section.
    monkeypatch.setenv(S.CAP_KNOB, str(len(prompt) - 30_000))
    built_cut, prompt_cut = _samples_pass(tmp_path / "capped", SECOND_EPISODE_ID)
    shown_cut, problems_cut = _samples_coherence(built_cut, prompt_cut)
    assert shown_cut < shown, f"the cap cut no samples section (shown: {sorted(shown_cut)})"
    assert not problems_cut, problems_cut
