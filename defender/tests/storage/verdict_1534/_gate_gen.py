"""G2 generator: seeded documents on both sides of every entry bound, with canonical windows known by construction (no tests).

Each document is `_close_b.baseline_document(disposition, baseline rows, ceiling=receipt rows)`. Sizes are aimed at the
bounds through the product's own line renderers (`closing.ceiling_line`/`baseline_line`), so a fraction of the documents
sits just inside and just outside each aggregate; which side the gate puts a document on is never predicted here."""
from __future__ import annotations

import random
from typing import Any, NamedTuple

from defender.tests.storage.verdict_1534 import _close_b as B
from defender.tests.support.shared.contracts import _tacit983 as scene

#: Instant spellings the walker parses, each with its canonical form (ISO-8601 UTC, `Z`, microseconds when non-zero):
#: start instants (2026-04-04) and end instants (2026-05-04), all before the alerted event.
STARTS = (
    ("2026-04-04T00:00:00Z", "2026-04-04T00:00:00Z"),
    ("2026-04-04", "2026-04-04T00:00:00Z"),
    ("20260404T000000Z", "2026-04-04T00:00:00Z"),
    ("2026-04-04T00:00Z", "2026-04-04T00:00:00Z"),
    ("2026-04-04T00:00:00", "2026-04-04T00:00:00Z"),
    ("2026-04-04T02:00:00+02:00", "2026-04-04T00:00:00Z"),
    ("2026-04-04T00:00:00.5Z", "2026-04-04T00:00:00.500000Z"),
    ("2026-04-03T23:00:00.000001-01:00", "2026-04-04T00:00:00.000001Z"),
    ("2026-04-04T00:00:00.250+00:00", "2026-04-04T00:00:00.250000Z"),
)
ENDS = (
    ("2026-05-04T00:00:00Z", "2026-05-04T00:00:00Z"),
    ("2026-05-04", "2026-05-04T00:00:00Z"),
    ("20260504T000000Z", "2026-05-04T00:00:00Z"),
    ("2026-05-04T00:00Z", "2026-05-04T00:00:00Z"),
    ("2026-05-04T05:30:00+05:30", "2026-05-04T00:00:00Z"),
    ("2026-05-04T00:00:00.000001Z", "2026-05-04T00:00:00.000001Z"),
)
#: Spellings shorter than their canonical form: a gate that measured the window as written would undercount them.
SHORT_STARTS = tuple(s for s in STARTS if len(s[0]) < len(s[1]))
SHORT_ENDS = tuple(e for e in ENDS if len(e[0]) < len(e[1]))
CANONICAL = dict(STARTS + ENDS)


def canonical_window(written: str) -> tuple[str, str]:
    """The canonical `(start, end)` of a window this generator wrote."""
    start, _sep, end = written.partition("/")
    return CANONICAL[start.strip()], CANONICAL[end.strip()]


class Plan(NamedTuple):
    name: str
    disposition: str
    text: str
    features: frozenset[str]


def _text(rng: random.Random, n: int) -> str:
    """`n` treated characters: plain words, or host-shaped tokens that grow when defanged."""
    return B.expanding(n) if n >= 24 and rng.random() < 0.4 else B.plain(n)


def _short_text(rng: random.Random) -> str:
    return rng.choice(("", "x", "came back empty", "see https://evil.example/x", "host db-1.corp.example", "10.0.0.5"))


def _cap(rng: random.Random, i: int, *, over: bool = False) -> str:
    """A `nothing-to-try` capability: dotted but not host-shaped, host-shaped (defanged in the record), undotted, or
    host-shaped and long: 63 or 64 characters once treated, or (`over`) 65 or 66, past `CAP_BOUND`."""
    kind = rng.randrange(4)
    if kind == 0:
        return f"fake-system-{i:03d}.fake-verb"
    if kind == 1:
        return f"gap{i:03d}.example"
    if kind == 2:
        return f"sandbox-{i:03d}"
    return f"g{i:03d}" + "a" * (rng.randint(51, 52) if over else rng.randint(49, 50)) + ".example"


def _receipt(cap: str, note: str) -> str:
    return f"state=nothing-to-try cap={cap} note={note}"


def _ceiling_rows(rng: random.Random, mode: str, disposition: str) -> tuple[list[str], set[str]]:
    from defender._vocab import PROCESS_GAP_DISPOSITION
    from defender.records import closing as C
    from defender.tests.support.runtime.engine import _spec923 as S

    features: set[str] = set()
    if mode == "few":
        rows = [_receipt(_cap(rng, i, over=rng.random() < 0.3), _short_text(rng)) for i in range(rng.randint(1, 3))]
        if disposition != PROCESS_GAP_DISPOSITION and rng.random() < 0.5:
            rows.append(S.PAYING_ROW)
        if rng.random() < 0.4:
            rows.append(rng.choice((S.SOURCE_ONLY_ROW, rows[0])))  # a row the walker refuses, or a repeat
            features.add("walker-refused-row")
        return rows, features
    if mode == "count":
        count = C.CEILING_COUNT_CAP + rng.choice((-1, 0, 1))
        return [_receipt(_cap(rng, i), f"n{i}") for i in range(count)], {f"ceiling-count-{count - C.CEILING_COUNT_CAP:+d}"}
    if mode == "aggregate":
        extra = rng.choice((-1, 0, 0, 1, 3))
        caps = [_cap(rng, i) for i in range(rng.randint(6, 8))]
        probes = [C.ceiling_line(C.CeilingEntry(state="nothing-to-try", ref=None, cap=c, note="x")) for c in caps]
        sizes = B.fill_sizes(probes, C.CEILING_LINES_BOUND, extra)
        return [_receipt(c, _text(rng, s)) for c, s in zip(caps, sizes, strict=True)], {f"ceiling-aggregate-{extra:+d}"}
    assert mode == "mixed"
    # Leading rows that fill most of the aggregate, one that overflows it, then short rows that would still fit.
    sizes = [rng.randint(300, 400) for _ in range(4)] + [rng.choice((400, 900))] + [rng.randint(1, 20) for _ in range(3)]
    return [_receipt(_cap(rng, i), _text(rng, s)) for i, s in enumerate(sizes)], {"ceiling-mixed"}


def _baseline_row(rng: random.Random, i: int, *, result: str, short: bool, grounding: str | None = None) -> str:
    from defender.records import closing as C

    start = rng.choice(SHORT_STARTS if short else STARTS)[0]
    end = rng.choice(SHORT_ENDS if short else ENDS)[0]
    return scene.consultation_row(
        anchor_id=rng.choice((f"tk-{i:03d}", f"tk-{i:03d}.corp.example", "")),
        grounding=grounding if grounding is not None else rng.choice(("", *C.GROUNDING_KINDS)),
        result=result, reasoning=rng.choice(("", "r", "no adverse outcome fell inside the window")),
        window=f"{start}/{end}")


def _baseline_rows(rng: random.Random, mode: str) -> tuple[list[str], set[str]]:
    from defender.records import closing as C

    if mode == "few":
        rows = [_baseline_row(rng, i, result=_short_text(rng), short=False) for i in range(rng.randint(0, 3))]
        if rows and rng.random() < 0.3:
            rows.append(scene.consultation_row(anchor_id="tk-late", window=scene.WINDOW_STARTING_AT_ALERT))
            return rows, {"walker-refused-baseline"}
        return rows, set()
    if mode == "aggregate":
        extra = rng.choice((-1, 0, 0, 1, 3))
        count = rng.randint(6, 8)
        rows = [_baseline_row(rng, i, result="x", short=True) for i in range(count)]
        probes = [_probe_line(row) for row in rows]
        sizes = B.fill_sizes(probes, C.BASELINE_LINES_BOUND, extra)
        assert max(sizes) <= C.RESULT_BOUND, "generator control: each result fits its own bound"
        return [row.replace('|"x"|', f'|"{_text(rng, s)}"|', 1) for row, s in zip(rows, sizes, strict=True)], {
            f"baseline-aggregate-{extra:+d}"}
    assert mode == "mixed"
    sizes = [rng.randint(300, 400) for _ in range(4)] + [rng.choice((400, 900))] + [rng.randint(1, 20) for _ in range(3)]
    return [_baseline_row(rng, i, result=_text(rng, s), short=False) for i, s in enumerate(sizes)], {"baseline-mixed"}


def _probe_line(row: str) -> str:
    """The line the record renders for a generated baseline row whose result is `x` (canonical window, treated cells)."""
    from defender.records import closing as C

    lead, kind, grounding, anchor, _result, window, reasoning = row.split("|")
    start, end = canonical_window(window)
    # Rendered with a vocabulary member, then the row's own grounding put back: sizing never depends on whether the
    # record accepts the row's grounding (which is what the tests ask).
    stand_in = C.GROUNDING_KINDS[0]
    line = C.baseline_line(C.BaselineEntry(lead=lead, anchor_kind=kind, grounding_kind=stand_in, anchor_id=anchor,
                                           window_start=start, window_end=end, result="x", reasoning=reasoning.strip('"')))
    return line.replace(f"({stand_in},", f"({grounding},", 1)


#: Column-mode pairs: `mixed` (always over a bound, for the forced close) beside a `few` column only, so the gate
#: refuses a mixed document for that column alone.
MODE_PAIRS = (("few", "few"), ("few", "aggregate"), ("count", "few"), ("count", "aggregate"), ("aggregate", "few"),
              ("aggregate", "aggregate"), ("mixed", "few"), ("few", "mixed"))


def plans(count: int = 96, seed: int = 15347) -> list[Plan]:
    """`count` documents cycling every pair of column modes, with seeded sizes, spellings and dispositions."""
    rng = random.Random(seed)
    dispositions = B.model_dispositions()
    out = []
    for i in range(count):
        ceiling_mode, baseline_mode = MODE_PAIRS[i % len(MODE_PAIRS)]
        disposition = dispositions[i % len(dispositions)] if i % 3 else rng.choice(dispositions)
        ceiling, f1 = _ceiling_rows(rng, ceiling_mode, disposition)
        baselines, f2 = _baseline_rows(rng, baseline_mode)
        text = B.baseline_document(disposition, baselines, ceiling=tuple(ceiling))
        out.append(Plan(f"g2-{i:02d}-{disposition}-{ceiling_mode}-{baseline_mode}", disposition, text,
                        frozenset(f1 | f2)))
    return out


def receipts(text: str) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """The product walkers' accepted ceiling receipts and baselines for `text`, in document order."""
    from defender.investigation.review.projector import parse_investigation
    from defender.skills.invlang.validate import conclude_ceiling_test_rows, conclude_runtime_evidence_rows

    companion = parse_investigation(text)
    return conclude_ceiling_test_rows(companion), conclude_runtime_evidence_rows(companion)


def uncut_ceiling(receipts_: tuple[Any, ...]) -> list[tuple]:
    """What a gated close stores per accepted receipt: each model-text field treated, never cut."""
    from defender.records import closing as C

    return [(r.state, r.ref, None if r.cap is None else C.treat(r.cap, None), C.treat(r.note, None)) for r in receipts_]


def uncut_baselines(receipts_: tuple[Any, ...]) -> list[tuple]:
    from defender.records import closing as C

    def t(x: str) -> str:
        return C.treat(x, None)

    return [(t(r.resolved_by_lead), r.anchor_kind, r.grounding_kind, t(r.anchor_id), *canonical_window(r.window),
             t(r.result), t(r.reasoning)) for r in receipts_]


def stored_ceiling(record: Any) -> list[tuple]:
    return [(e.state, e.ref, e.cap, e.note) for e in record.ceiling_test]


def stored_baselines(record: Any) -> list[tuple]:
    return [(e.lead, e.anchor_kind, e.grounding_kind, e.anchor_id, e.window_start, e.window_end, e.result, e.reasoning)
            for e in record.runtime_evidence]


def buildable_ceiling(receipts_: tuple[Any, ...]) -> list[Any]:
    """The accepted receipts the record's own entry type builds (treated to its field bounds), in order."""
    from defender.records import closing as C

    built = []
    for r in receipts_:
        try:
            built.append(C.CeilingEntry(state=r.state, ref=r.ref, cap=r.cap, note=r.note))
        except ValueError:
            continue
    return built


def buildable_baselines(receipts_: tuple[Any, ...]) -> list[Any]:
    from defender.records import closing as C

    built = []
    for r in receipts_:
        start, end = canonical_window(r.window)
        try:
            built.append(C.BaselineEntry(lead=r.resolved_by_lead, anchor_kind=r.anchor_kind, grounding_kind=r.grounding_kind,
                                         anchor_id=r.anchor_id, window_start=start, window_end=end, result=r.result,
                                         reasoning=r.reasoning))
        except ValueError:
            continue
    return built


def ceiling_fits(entries: list[Any]) -> bool:
    """Within the ceiling column's count cap and its aggregate of rendered lines, separators counted."""
    from defender.records import closing as C

    return (len(entries) <= C.CEILING_COUNT_CAP
            and len("\n".join(C.ceiling_line(e) for e in entries)) <= C.CEILING_LINES_BOUND)


def baselines_fit(entries: list[Any]) -> bool:
    from defender.records import closing as C

    return len("\n".join(C.baseline_line(e) for e in entries)) <= C.BASELINE_LINES_BOUND


def longest_fitting_prefix(entries: list[Any], fits: Any) -> int:
    """The length of the longest leading run of `entries` that fits."""
    n = 0
    while n < len(entries) and fits(entries[:n + 1]):
        n += 1
    return n


def skip_would_differ(entries: list[Any], fits: Any) -> bool:
    """Whether some later entry would still fit after the first that does not: a cut that skipped instead of
    stopping would keep it."""
    n = longest_fitting_prefix(entries, fits)
    return any(fits([*entries[:n], e]) for e in entries[n + 1:])
