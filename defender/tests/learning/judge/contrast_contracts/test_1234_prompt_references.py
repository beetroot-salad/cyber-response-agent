"""#1234 judge contrast: judge prompt construction: references, contrast tables, facts."""

from __future__ import annotations

import dataclasses
import json
import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import pytest

from defender.tests.learning.judge.contrast_contracts import _spec1234 as S


@pytest.fixture(autouse=True)
def _payload_cap_lifted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(S.CAP_KNOB, str(_UNCAPPED))


#: The words A2/M2 require on the aligned lead view and the fact surfaces (`S.COINED`).
HEURISTIC = S.COINED["label.heuristic"]
BASELINE = S.COINED["label.baseline"]

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


def _host_hits(text: str, pattern: re.Pattern[str], lo: int = 0, hi: int | None = None) -> list[int]:
    end = len(text) if hi is None else hi
    hits: list[int] = []
    for a, b in _host_spans(text):
        a, b = max(a, lo), min(b, end)
        if a < b:
            hits.extend(m.start() for m in pattern.finditer(text, a, b))
    return sorted(hits)


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


def test_1234_render_builds_judge_context_per_focus_world(tmp_path: Path) -> None:
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


def test_1234_world_prompt_carries_control_and_every_gradable_sibling_as_references(
        tmp_path: Path) -> None:
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


_UNGRADABLE = {
    "o5-failed": ({"world_record": "did not finish"}, "did not finish"),
    "cut-short": ({"run_end": {"truncated_by": "budget", "closed_before_cut": False}}, "budget"),
    "malformed": ({"report": ("---\ndisposition: benign\noutcome: stands\ndisposition: malicious\n"
                              f"---\nWorld wx closed. {S.marker('wx', 'report')}\n")}, "report"),
}


@pytest.mark.parametrize("kind", sorted(_UNGRADABLE))
def test_1234_ungradable_planted_world_is_in_no_reference_set(tmp_path: Path, kind: str) -> None:
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


_SURFACE_LEADS = {"l-001", "l-201", "l-305", "l-406", "l-556", "l-560", "l-917"}


def test_1234_fact_surface_names_forged_systems_entities_and_touching_leads(tmp_path: Path) -> None:
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


def test_1234_planted_world_shown_as_designed_built_and_served(tmp_path: Path) -> None:
    claim = {"added": [{"forged_id": "fg-wb-1", "fact_id": "f-wb"}], "removed": [], "changed": [],
             "counts": [], "entity_refs": [S.marker(WB, "claim")]}
    verdict = {"passed": True, "reason": f"the fact's telemetry is present {S.marker(WB, 'verdict')}"}
    worlds = _triad(**{WB: {"axis": f"axis {S.marker(WB, 'axis')}", "calls": [
        _call("l-201", params=_q("user:alice")),
        _altered("l-917", f"user:alice host:db-1 {S.marker(WB, 'altered')}",
                 ledger_extra={"claim": claim, "verifier_verdict": verdict})]}})
    built = _family(tmp_path, worlds)
    collisions = S.sym("episodes._episode_paths", "COLLISIONS_FILENAME")
    built.oracle_path(WB, collisions).write_text(json.dumps(
        {"forged_id": "fg-wb-1", "column": "event_id", "value": S.marker(WB, "collision"),
         "real_rows": []}) + "\n", encoding="utf-8")
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


def test_1234_failed_world_detail_quoting_its_forged_rows(tmp_path: Path) -> None:
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
