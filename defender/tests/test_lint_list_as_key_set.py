"""Tests for the lint_list_as_key_set gate (#956).

The gate's whole value is the line it draws between two loops that look identical:

    for x in seq: table[x] += n     # a FIX-UP over a table already keyed by seq — the bug
    for x in seq: tally[x] += 1     # a COUNT whose keys seq discovers — the correct idiom

A rule that cannot tell them apart is unarmable: measured over the tree, the plain
"augmented assign into a dict keyed on the loop variable" rule fires six times and every
one of the six is correct code. So the first block below pins the separation itself, and
the second pins the reach the module docstring claims — because a gate that quietly stops
finding things reads exactly like a clean tree.

The gate is driven through its DI seams:
  - main(argv=None, *, scope=None, baseline_path=None) -> exit code
  - _scan(root) -> list[Finding]
"""
from __future__ import annotations

import json
from pathlib import Path

from defender.tests._by_path import load_lint_gate

_GATE = load_lint_gate("lint_list_as_key_set")

#: The defect as it actually shipped (`scripts/visualize/visualize_run.py`, #956), reduced
#: to the two lines that carry it: a table keyed by `phase_order`, then patched by walking
#: `phase_order`. A name appearing twice bills its gather cost twice.
_THE_BUG = """
def render(events, phase_order, tags):
    attribution = phase_attribution(events, phase_order, tags)
    for ph in phase_order:
        attribution[ph]["cost"] += gather_by_phase.get(ph, 0.0)
    return attribution
"""


def _scan(tmp_path: Path, src: str, rel: str = "m.py") -> list[str]:
    tree = tmp_path / "tree"
    tree.mkdir(exist_ok=True)
    path = tree / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(src, encoding="utf-8")
    return [f.fingerprint for f in _GATE._scan(tree)]


def _flags(tmp_path: Path, src: str) -> bool:
    return bool(_scan(tmp_path, src))


# what it catches


def test_the_shipped_defect_is_caught(tmp_path):
    assert _scan(tmp_path, _THE_BUG) == ["m.py:render:phase_order->attribution"]


def test_the_read_modify_write_twin_is_caught(tmp_path):
    """#956's worse half: the second visit reads the value the first one wrote, so the
    adjustment compounds instead of merely repeating."""
    assert _flags(tmp_path, """
def render(events, phase_order, tags):
    wall_times = phase_wall_times(events, tags, phase_order)
    for ph in phase_order:
        d = wall_times.get(ph) or {}
        d["duration_sec"] = d.get("duration_sec", 0.0) - moved
        wall_times[ph] = d
""")


def test_a_table_unpacked_from_a_call_still_counts(tmp_path):
    """`by_phase, total = f(..., order, ...)` keys `by_phase` from `order` exactly as a
    single-target assignment does; reading only single targets would miss it."""
    assert _flags(tmp_path, """
def render(events, order):
    by_phase, total = cost_by_phase(events, order)
    for ph in order:
        by_phase[ph] += 1
""")


def test_the_sequence_passed_by_keyword_still_counts(tmp_path):
    """The table is keyed by the sequence whether or not the call spells the argument."""
    assert _flags(tmp_path, """
def render(events, order):
    table = build(events, phases=order)
    for ph in order:
        table[ph] = 0
""")


def test_a_nested_write_names_the_table_not_the_slice(tmp_path):
    """`t[ph]["cost"] = v` is a write to `t`'s `ph` bucket. Reporting the inner subscript
    would fingerprint the defect under a name that is not a table."""
    assert _scan(tmp_path, """
def render(events, order):
    t = build(events, order)
    for ph in order:
        t[ph]["cost"] = 1
""") == ["m.py:render:order->t"]


# what it must NOT catch (the idiom)


def test_the_counting_idiom_is_not_flagged(tmp_path):
    """`Counter()`/`{}` DISCOVERS its keys from the iteration, so a repeat is the point.
    This is the shape of all six sites the plain rule fires on in this tree — the reason
    the plain rule is not the gate."""
    assert not _flags(tmp_path, """
def build_idf(token_sets):
    df = Counter()
    for ts in token_sets:
        for tok in ts:
            df[tok] += 1
    return df
""")


def test_a_table_built_from_a_different_sequence_is_not_flagged(tmp_path):
    """The two halves must meet. A table keyed by something else is not a fix-up pass over
    the sequence being walked, and repeats in that sequence cost it nothing."""
    assert not _flags(tmp_path, """
def render(events, order, other):
    table = build(events, other)
    for ph in order:
        table[ph] = 0
""")


def test_a_deduped_walk_is_not_flagged(tmp_path):
    """The cure must scan clean, or the gate argues against its own fix."""
    assert not _flags(tmp_path, """
def render(events, order):
    table = build(events, order)
    for ph in dict.fromkeys(order):
        table[ph] = 0
""")


def test_a_sequence_rebound_from_a_unique_source_is_not_flagged(tmp_path):
    """`keys = list(dict.fromkeys(order))` is the same cure spelled over two lines. The
    detector looks THROUGH `list`/`sorted` to what produced the elements rather than
    trusting the outer call's name."""
    assert not _flags(tmp_path, """
def render(events, order):
    table = build(events, order)
    keys = list(dict.fromkeys(order))
    for ph in keys:
        table[ph] = 0
""")


def test_reading_a_table_is_not_patching_it(tmp_path):
    """A loop that only READS `table[ph]` visits one bucket twice harmlessly. Firing here
    would bury the write sites this gate exists for."""
    assert not _flags(tmp_path, """
def render(events, order):
    table = build(events, order)
    out = []
    for ph in order:
        out.append(table[ph])
    return out
""")


def test_the_suppression_marker_is_honoured(tmp_path):
    assert not _flags(tmp_path, """
def render(events, order):
    table = build(events, order)
    for ph in order:  # lint-keyset: ok — order is a set already, upstream
        table[ph] = 0
""")


# scope + the ratchet


def test_a_function_is_scanned_once_not_twice(tmp_path):
    """Module scope must stop at every `def`. Walking through them reports each finding a
    second time under `<module>`, which doubles the baseline and makes the count a lie."""
    fps = _scan(tmp_path, _THE_BUG)
    assert len(fps) == len(set(fps)) == 1, fps


def test_a_closure_patching_its_enclosing_table_is_caught(tmp_path):
    """The table's origin is only visible from the OUTER scope, so a function scope has to
    descend into its closures even though module scope must not."""
    assert _flags(tmp_path, """
def render(events, order):
    table = build(events, order)
    def fix():
        for ph in order:
            table[ph] = 0
    return fix
""")


def test_the_gate_fails_on_a_new_finding_and_passes_once_baselined(tmp_path):
    """The ratchet itself: a new site exits 1; the same site named in the baseline exits 0."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "m.py").write_text(_THE_BUG, encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"//": "test", "entries": {}}) + "\n", encoding="utf-8")

    assert _GATE.main([], scope=tree, baseline_path=baseline) == 1

    baseline.write_text(
        json.dumps({
            "//": "test",
            "entries": {"m.py:render:phase_order->attribution": "test fixture"},
        }) + "\n",
        encoding="utf-8",
    )
    assert _GATE.main([], scope=tree, baseline_path=baseline) == 0


def test_an_unreadable_file_in_scope_exits_two_not_clean(tmp_path):
    """A file the gate could not parse never entered the corpus, so a defect could sit in
    it while the gate prints zero findings. Exit 2 — could-not-run is not clean."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "broken.py").write_text("def f(:\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"//": "test", "entries": {}}) + "\n", encoding="utf-8")
    assert _GATE.main([], scope=tree, baseline_path=baseline) == 2


def test_the_shipped_baseline_is_empty(tmp_path):
    """An entry here is a regression someone chose. Pinned so adding one is a visible act
    rather than a side effect of `--update-baseline`."""
    entries = json.loads(_GATE.BASELINE_PATH.read_text(encoding="utf-8"))["entries"]
    assert entries == {}, f"the gate shipped with accepted debt: {entries}"
