"""#1534 G2: the write gates and the record builder measure the same thing (design "Bounds", M3/OD16), the ceiling `cap`
treated and bounded (owner decision b), and an empty baseline grounding kept (owner decision a).

Documents come from `_gate_gen` (seeded, on both sides of every entry bound). The oracle is the product's own walker
output (`conclude_*_rows`), `closing.treat`, the entry types and the bound constants; windows are canonical by
construction. Neither the gate's decision nor the builder's loop is re-implemented."""
from __future__ import annotations

import functools

import pytest

from defender.tests.storage.verdict_1534 import _close_b as B
from defender.tests.storage.verdict_1534 import _gate_gen as G
from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.runtime.engine import _spec992 as S9
from defender.tests.support.sandbox._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)
from defender.tests.support.shared.contracts import _tacit983 as scene

CHUNKS = 8


@functools.cache
def _plans() -> list[G.Plan]:
    return G.plans()


def _chunk(i: int) -> list[G.Plan]:
    """A contiguous slice: each holds every column-mode pair (`_gate_gen.MODE_PAIRS` cycles)."""
    size = -(-len(_plans()) // CHUNKS)
    return _plans()[i * size:(i + 1) * size]


def _gate(text: str) -> list[str]:
    from defender.skills.invlang.validate import validate_companion

    return validate_companion(text, None)


def test_g2_the_generated_documents_fall_on_both_sides_of_the_gate_and_carry_every_feature():
    """Controls for the two properties below: accepted and refused documents, each window spelling, grounding value,
    empty optional cell and dotted cap in an accepted one, and forced-close inputs a skipping cut would treat apart."""
    from defender.records import closing as C

    accepted = [p for p in _plans() if not _gate(p.text)]
    assert 20 <= len(accepted) <= len(_plans()) - 20, len(accepted)
    seen: set[str] = set()
    for plan in accepted:
        seen |= plan.features
        ceiling, baselines = G.receipts(plan.text)
        for r in baselines:
            seen |= {f"window:{half}" for half in r.window.split("/")}
            seen.add(f"grounding:{r.grounding_kind}")
            seen |= {f"empty:{cell}" for cell in ("anchor_id", "reasoning") if getattr(r, cell) == ""}
        seen |= {"cap-defanged" for r in ceiling if r.cap is not None and C.treat(r.cap, None) != r.cap}
    wanted = {f"window:{w}" for w, _c in G.STARTS + G.ENDS} | {f"grounding:{g}" for g in ("", *C.GROUNDING_KINDS)}
    wanted |= {"empty:anchor_id", "empty:reasoning", "cap-defanged", "baseline-aggregate-+0", "ceiling-aggregate-+0",
               "ceiling-count-+0", "walker-refused-row"}
    assert wanted <= seen, sorted(wanted - seen)
    differ = [(G.skip_would_differ(G.buildable_ceiling(c), G.ceiling_fits),
               G.skip_would_differ(G.buildable_baselines(b), G.baselines_fit))
              for c, b in (G.receipts(p.text) for p in _plans())]
    assert any(c for c, _b in differ), "no ceiling input tells a stopping cut from a skipping one"
    assert any(b for _c, b in differ), "no baseline input tells a stopping cut from a skipping one"


@pytest.mark.parametrize("chunk", range(CHUNKS))
def test_g2_a_document_the_gate_accepts_closes_with_every_walker_accepted_entry_treated_and_uncut(tmp_path, chunk):
    """For each accepted document the model close commits, and the record holds exactly the walkers' accepted receipts and
    baselines in order, each field treated and none cut, windows canonical. (G2a, M3/OD16, V-FIELDS)"""
    closed = 0
    for plan in _chunk(chunk):
        if _gate(plan.text):
            continue
        ceiling, baselines = G.receipts(plan.text)
        record = B.close_run(tmp_path / plan.name, plan.disposition, plan.text).record
        assert G.stored_ceiling(record) == G.uncut_ceiling(ceiling), ("ceiling", plan.name)
        assert G.stored_baselines(record) == G.uncut_baselines(baselines), ("baselines", plan.name)
        closed += 1
    assert closed >= 1, "fixture control: the chunk holds an accepted document"


@pytest.mark.parametrize("chunk", range(CHUNKS))
def test_g2_the_forced_close_commits_the_longest_leading_run_of_buildable_accepted_entries(tmp_path, chunk):
    """Over every generated document, gated or not: the host's forced close commits, never raises, and each column is
    the longest leading run of the accepted entries the record builds that fits its caps. (G2b, V-TEXT)"""
    for plan in _chunk(chunk):
        ceiling, baselines = G.receipts(plan.text)
        record = B.forced_close(tmp_path / plan.name, plan.text).record
        for stored, built, fits in ((record.ceiling_test, G.buildable_ceiling(ceiling), G.ceiling_fits),
                                    (record.runtime_evidence, G.buildable_baselines(baselines), G.baselines_fit)):
            n = G.longest_fitting_prefix(built, fits)
            assert list(stored) == built[:n], (plan.name, "stored", len(stored), "prefix", n, "built", len(built))


def _beyond_utc() -> str:
    """A benign document whose first baseline's window starts at year 1 ahead of UTC (it has no UTC form), then a plain one."""
    rows = [scene.consultation_row(anchor_id="tk-edge", window="0001-01-01T00:00:00+05:00/2026-05-04T00:00:00Z"),
            scene.consultation_row(anchor_id="tk-plain")]
    return B.baseline_document("benign", rows)


def test_g2_a_window_beyond_the_utc_range_does_not_crash_the_write_gate():
    """The gate answers with a list (accepting or refusing the row is not pinned). (G2, design "Bounds")"""
    assert isinstance(_gate(_beyond_utc()), list)


def test_g2_a_window_beyond_the_utc_range_does_not_fail_the_forced_close(tmp_path):
    """The host's forced close commits, the plain baseline kept (the edge row's fate is not pinned). (G2, design "Bounds":
    the build never fails)"""
    record = B.forced_close(tmp_path, _beyond_utc()).record
    assert "tk-plain" in [e.anchor_id for e in record.runtime_evidence]


# --- owner decision (b): a ceiling receipt's `cap` is model text, treated, bounded by CAP_BOUND -------------------------

def _cap_of(treated_length: int) -> str:
    """An identifier-shaped, host-shaped cap (`<system>.example`) whose treated form (`[.]`) has `treated_length`
    characters: two more than it has raw."""
    return "g" + "a" * (treated_length - 11) + ".example"


@pytest.mark.parametrize("disposition", B.model_dispositions())
def test_cap_a_host_shaped_cap_is_stored_defanged_and_its_rendered_line_carries_no_raw_host(tmp_path, disposition):
    """`cap=gap.example` pays, and the record and its ceiling line hold `gap[.]example`; a dotted cap that is not
    host-shaped is kept as written. (decision b, V-TEXT)"""
    from defender.records import closing as C

    rows = ("state=nothing-to-try cap=gap.example note=no such source",
            "state=nothing-to-try cap=fake-system-000.fake-verb note=nor this one")
    text = B.with_ceiling(disposition, rows)
    assert _gate(text) == [], "fixture control: the gate accepts both receipts"

    entries = B.close_run(tmp_path, disposition, text).record.ceiling_test

    assert [e.cap for e in entries] == ["gap[.]example", "fake-system-000.fake-verb"]
    line = C.ceiling_line(entries[0])
    assert "gap[.]example" in line
    assert "gap.example" not in line


@pytest.mark.parametrize("disposition", B.model_dispositions())
def test_cap_the_gate_measures_the_treated_cap_against_its_bound(tmp_path, disposition):
    """A cap of `CAP_BOUND` characters once treated closes and is stored whole; one of `CAP_BOUND - 1` raw characters that
    defangs to `CAP_BOUND + 1` is refused at both gates naming `cap` and the bound, and nothing is committed. (decision b)"""
    from defender.records import closing as C

    at, over = _cap_of(C.CAP_BOUND), _cap_of(C.CAP_BOUND + 1)
    assert len(over) < C.CAP_BOUND < len(C.treat(over, None)), "fixture control: raw within, treated over"
    at_text = B.with_ceiling(disposition, (f"state=nothing-to-try cap={at} note=n",))
    over_text = B.with_ceiling(disposition, (f"state=nothing-to-try cap={over} note=n",))

    assert _gate(at_text) == []
    (entry,) = B.close_run(tmp_path / "at", disposition, at_text).record.ceiling_test
    assert entry.cap == C.treat(at, None)
    assert len(entry.cap) == C.CAP_BOUND

    assert any(B.refusal_names(e, ("cap",), C.CAP_BOUND) for e in _gate(over_text)), _gate(over_text)
    with B.opened(tmp_path / "over", over_text) as (deps, run_dir, store):
        message = S9.refusal(deps, disposition, S9.recording(S9.holds()))
        assert B.refusal_names(message, ("cap",), C.CAP_BOUND), message
        assert V.scalar_rows(store.path, run_dir.name) == []


def test_cap_the_forced_close_cuts_an_over_bound_cap_and_keeps_the_receipt(tmp_path):
    """Ungated, a treated cap past the bound is cut to it and the receipt stays. (decision b, V-TEXT)"""
    from defender.records import closing as C

    cap = _cap_of(C.CAP_BOUND + 8)
    (entry,) = B.forced_close(tmp_path, B.forced_doc(ceiling=(f"state=nothing-to-try cap={cap} note=n",))).record.ceiling_test

    assert len(entry.cap) <= C.CAP_BOUND
    assert entry.cap == C.treat(cap, C.CAP_BOUND)


# --- owner decision (a): an empty grounding is accepted by the gate, the walker and the record alike -------------------

#: Empty and every `GROUNDING_KINDS` member (a literal, so collection never needs the record module; checked below).
GROUNDINGS = ("", "org-authority", "telemetry-baseline")


@pytest.mark.parametrize("disposition", ["benign", "inconclusive"])
@pytest.mark.parametrize("grounding", GROUNDINGS, ids=lambda g: g or "empty")
def test_grounding_every_acceptable_grounding_is_kept_by_the_model_close_and_the_forced_close(tmp_path, grounding,
                                                                                               disposition):
    """Empty or a vocabulary member: the gate accepts the baseline and both closes store it with that grounding. (decision a)"""
    from defender.records import closing as C

    assert ("", *C.GROUNDING_KINDS) == GROUNDINGS, "fixture control: the literal is the whole accepted set"
    text = B.baseline_document(disposition, [scene.consultation_row(grounding=grounding)])
    assert _gate(text) == []

    for record in (B.close_run(tmp_path / "model", disposition, text).record, B.forced_close(tmp_path / "forced", text).record):
        assert [(e.anchor_id, e.grounding_kind) for e in record.runtime_evidence] == [("tk-baseline-30d", grounding)]


def test_grounding_a_value_outside_the_vocabulary_is_refused_at_the_gate_and_dropped_by_the_forced_close(tmp_path):
    """The negative beside the one above: `bogus` is refused naming the grounding; ungated, that row alone is dropped."""
    rows = [scene.consultation_row(anchor_id="tk-bogus", grounding="bogus"), scene.consultation_row(anchor_id="tk-ok")]
    text = B.baseline_document("benign", rows)

    assert any("grounding" in e and "bogus" in e for e in _gate(text)), _gate(text)
    record = B.forced_close(tmp_path, text).record
    assert [e.anchor_id for e in record.runtime_evidence] == ["tk-ok"]
