"""#836 M4 — `fix_row(old_row, new_row)`, the repair verb.

`fix_row` is the FIRST verb that rewrites a line INSIDE an already-open fence: `append_block`
only ever adds after the last fence close, so the parser has never had to validate a mid-fence
splice. Everything M4 states as a guard is on `old_row`; what `new_row` may be was fork F-C,
and §7 resolved it (H3) with a shape guard.

The human decisions this module applies, from `.spec-flow/frontiers/70-resolutions.md`:

  H3  `new_row` must be a SINGLE row of the SAME block with that block's cell count — no
      newline, no fence delimiter, no `:V`/`:E` declaration
  H4  the repair applies to EVERY flagged occurrence; it refuses if any match lies outside
      the currently-flagged set; and matching compares against the STRIPPED row text the
      renderer emits, not the raw on-disk line
  H6  the write verbs execute sequentially within one model response
  A3  deletion may empty its block — a header-only `:R attr_updates` block validates clean
  A8  SEC2's discharge is CONDITIONAL on an in-process flag and the suite must say so

H3 is FORCED, not preferred: claim `x1` ("`fix_row` cannot reach a committed `:V`/`:E`
record") is REFUTED. `_check_append_only` compares `:V`/`:E` CORES only and never inspects
`:R` rows (rt10), so a fresh-id `:V` is accepted outright (rt9), a colliding-id one is
swallowed by the parser's first-declaration-wins fold before append-only sees it (rt8), and
one carrying the document's own fence delimiter makes the injected row VANISH with no warning
at all (rt11). Without the guard, O3/SEC1 ships as a negative universal with no enforcer.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests._invlang_warn_836 import (
    CLEAN_BLOCK,
    PROLOGUE,
    REPAIRED_ROW,
    REPAIRED_ROW_ATTRS,
    SECOND_WARN_ROW,
    WARN_DOC,
    WARN_ROW,
    attr_block,
    flagged_rows,
    main_deps,
    offered_tool_defs,
    offered_tool_names,
    run_one_response,
    seed_investigation,
)

#: The `:R attr_updates` block header every fixture below declares — four columns.
_HEADER = ":R attr_updates [resolved_by|target|key|value]"

#: EXECUTED at c0dca747 — two warn-family diagnostics for ONE row text, because the row is
#: written twice. This is F-D's collision, and H4 is what keeps O5 literally true under it.
_DUPLICATE_WARN_DOC = PROLOGUE + attr_block(WARN_ROW, WARN_ROW)


def _fix(deps, old_row, new_row):
    from defender.runtime.tools import _tool_fix_row

    return _tool_fix_row(deps, old_row, new_row)


def _inv(run):
    return (run / "investigation.md").read_text(encoding="utf-8")


def _pay_inconclusive_price(run) -> None:
    """#923: `inconclusive` now carries its own entry price (a `ceiling_test` row naming a
    source or capability), unrelated to anything this module tests — the repair window. Call
    only once the flagged-row window is already clear (both call sites here do), so appending
    this never masks what the test is actually driving."""
    path = run / "investigation.md"
    path.write_bytes(
        path.read_bytes()
        + b'\n```invlang\n:T conclude\nceiling_test  "process telemetry not retrieved"\n```\n'
    )


def _registered_tools():
    """MAIN's registered `Tool` objects, by name — the framework's own view of the roster,
    which is where the per-tool scheduling opt-in H6 sets actually lives."""
    import os

    from pydantic_ai.models import override_allow_model_requests
    from pydantic_ai.models.function import FunctionModel

    from defender.agents import MAIN_DEF
    from defender.hooks.budget_enforcer import DEFAULT_LIMITS
    from defender.runtime import driver, observe
    from defender.runtime.providers import BuiltModel
    from defender.runtime.tools import AgentDeps
    from defender.tests.e2e._replay_harness import ReplayFn

    logger = observe.RequestLogger(Path(os.devnull))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            MAIN_DEF, deps_type=AgentDeps, instructions="probe", logger=logger,
            agent_id="probe",
            make_model=lambda name, effort: BuiltModel(FunctionModel(ReplayFn([])), None),
            limits=DEFAULT_LIMITS,
        )
    return dict(agent._function_toolset.tools)


# the seam

def test_fix_row_takes_old_row_and_new_row_only(tmp_path):
    """M4's signature: two string arguments, no path and no free-form anchor.

    Asserted on the ToolDefinition the MODEL is shown, not on the Python signature alone: the
    schema is what the model fills in, and a path parameter that existed only there would
    still widen the write surface N4 keeps closed. `append_block` set the precedent — the run
    has one transcript and the verb is bound to it."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    defs = {t.name: t for t in offered_tool_defs(deps)}
    assert "fix_row" in defs, "the verb was never offered — nothing to inspect"
    schema = defs["fix_row"].parameters_json_schema

    assert set(schema.get("properties", {})) == {"old_row", "new_row"}
    assert set(schema.get("required", [])) == {"old_row", "new_row"}


def test_new_verb_leaves_same_write_bookkeeping_as_siblings(tmp_path):
    """The repair leaves the SAME bookkeeping its siblings do — the authored-path set, the
    guarded parents, and a byte-count return — as a direct consequence of M4's stated parity
    with `decide_write`.

    Compared against `append_block`'s own bookkeeping in the same run rather than against a
    remembered list, so the parity is asserted rather than restated."""
    from defender.runtime.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    inv = run / "investigation.md"

    _tool_append_block(deps, WARN_DOC)
    after_append = set(deps.authored_paths)
    assert inv.resolve() in after_append

    result = _fix(deps, WARN_ROW, REPAIRED_ROW)

    assert set(deps.authored_paths) == after_append
    assert str(len(_inv(run).encode("utf-8"))) in result, "no byte count in the return"


# the repair itself

def test_fix_row_repairs_a_flagged_row(tmp_path):
    """THE positive control for every negative in this module: a flagged row named exactly,
    replaced by a legal one, closes the window and leaves the rest of the document untouched.

    The whole workflow M4 exists for — the model copies the row out of the warning it was
    handed and passes it back as `old_row`."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    _fix(deps, WARN_ROW, REPAIRED_ROW)

    assert _inv(run) == PROLOGUE + attr_block(REPAIRED_ROW)
    assert flagged_rows(_inv(run)) == ()


def test_fix_row_repair_changes_only_key_keeps_value_verbatim(tmp_path):
    """A key-only repair preserves the VALUE cell byte for byte.

    The value is never separately examined, so a repair that carried an alert-derived value
    through unchanged is indistinguishable from any other — which is the point: the model
    is fixing a schema mistake, not re-authoring evidence."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    _fix(deps, WARN_ROW, REPAIRED_ROW_ATTRS)

    assert REPAIRED_ROW_ATTRS in _inv(run)
    assert _inv(run).count("svc.config-mgmt") == 1
    assert flagged_rows(_inv(run)) == ()


def test_fix_row_matches_a_whole_line_not_a_substring(tmp_path):
    """`old_row` matches a WHOLE line — never a substring of one, and never a span across
    lines.

    A substring match would let a repair rewrite the tail of a longer row, which is exactly
    the general edit capability SEC3 forbids. H4 changed the multiplicity ("exactly once"
    became "every flagged occurrence"); it did not relax the whole-line rule, and this is
    what records the difference."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry):
        _fix(deps, "v-001|owner|svc.config-mgmt", REPAIRED_ROW)

    assert _inv(run) == WARN_DOC
    # ...and the whole line does match, so the refusal above is about the SHAPE of the match.
    _fix(deps, WARN_ROW, REPAIRED_ROW)
    assert flagged_rows(_inv(run)) == ()


def test_fix_row_applies_to_every_flagged_occurrence(tmp_path):
    """H4: when a flagged row's text is not unique, the repair applies to EVERY flagged
    occurrence.

    F-D's collision, and the case the model is most likely to produce: two byte-identical bad
    rows in one block. Refusing as ambiguous would cost O5 outright — the window would be
    open and unclosable, and with M5 so would the run. Applying to every match cannot reach
    an unflagged line, because the flagged set is `:R attr_updates`-only (claims r2/g10).

    Both arms are asserted: the repair closes the window (no occurrence left behind) AND the
    document holds two repaired rows rather than one repaired and one dropped."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, _DUPLICATE_WARN_DOC)
    assert flagged_rows(_inv(run)) == (WARN_ROW, WARN_ROW)

    _fix(deps, WARN_ROW, REPAIRED_ROW)

    assert flagged_rows(_inv(run)) == ()
    assert _inv(run).count(REPAIRED_ROW) == 2
    assert WARN_ROW not in _inv(run)


def test_fix_row_when_one_flagged_row_is_a_prefix_of_another(tmp_path):
    """Two flagged rows where one's text is a PREFIX of the other: each is repairable on its
    own, and repairing the shorter leaves the longer untouched and still flagged.

    The multiplicity has to be counted on WHOLE LINES for this to hold. A substring count
    sees the shorter row inside the longer one, concludes a match lies outside the flagged
    set, and refuses both — a false refusal (both matches are flagged) that left the window
    unclearable and, under the M5 gate, the run unclosable. Cheap, and the exact shape a
    value cell like `svc` / `svc2` produces."""
    short_row = "l-001|v-001|owner|svc"
    long_row = "l-001|v-001|owner|svc2"

    deps, run = main_deps(tmp_path)
    seed_investigation(run, PROLOGUE + attr_block(short_row, long_row))
    assert flagged_rows(_inv(run)) == (short_row, long_row)

    _fix(deps, short_row, "l-001|v-001|class|svc")

    assert flagged_rows(_inv(run)) == (long_row,), "the prefix repair took the longer row too"
    assert long_row in _inv(run)

    # ...and the longer one is then repairable in its turn, so the window still closes.
    _fix(deps, long_row, "")
    assert flagged_rows(_inv(run)) == ()


def test_fix_row_refuses_a_match_outside_the_flagged_set(tmp_path):
    """H4's rider, and the half that keeps the multiplicity safe: if the row also stands as a
    WHOLE LINE the window did not flag, the repair refuses outright.

    The reachable case is the model pasting the row on a line of its own in narrative prose,
    outside any fence. That line is unflagged and byte-identical, so applying to every match
    without this guard would rewrite it too — a general edit capability arriving through the
    back door of a convenience.

    WHOLE-LINE is the correct multiplicity, and this test previously asserted SUBSTRING —
    a row merely EMBEDDED in a prose sentence. That was never a hazard: the repair only ever
    rewrites lines where `line.strip() == old_row`, so an embedded copy is already out of
    reach. Refusing on it cost O5 instead, in a way the model reaches by ordinary means — a
    `:T conclude` summary quoting its own flagged row made both the repair and the deletion
    escape refuse, and with the M5 gate the run could not close. It also fired when one
    flagged row's text was a PREFIX of another (`…|owner|svc` inside `…|owner|svc2`), where
    the refusal's own claim was false: both matches were flagged.

    So the embedded copy is asserted here too, as the complementary condition — it does NOT
    refuse, and the flagged row alone is repaired.

    Paired control: with the whole-line copy removed, the same call succeeds."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    pasted = PROLOGUE + f"\nI wrote this row and it was refused:\n{WARN_ROW}\n" + attr_block(
        WARN_ROW
    )
    seed_investigation(run, pasted)
    assert flagged_rows(_inv(run)) == (WARN_ROW,), "the pasted copy became flagged too"

    with pytest.raises(ModelRetry) as exc:
        _fix(deps, WARN_ROW, REPAIRED_ROW)

    assert _inv(run) == pasted, "a refused repair left residue"
    assert "flagged" in str(exc.value).lower()

    # ...and the EMBEDDED copy is not a match at all: the repair lands, the prose is untouched.
    deps_embedded, run_embedded = main_deps(tmp_path / "embedded")
    embedded = PROLOGUE + f"\nI wrote {WARN_ROW} and it was refused.\n" + attr_block(WARN_ROW)
    seed_investigation(run_embedded, embedded)
    _fix(deps_embedded, WARN_ROW, REPAIRED_ROW)
    assert flagged_rows(_inv(run_embedded)) == ()
    assert f"I wrote {WARN_ROW} and it was refused." in _inv(run_embedded), (
        "the repair rewrote a line it only appeared inside"
    )

    deps2, run2 = main_deps(tmp_path / "control")
    seed_investigation(run2, PROLOGUE + attr_block(WARN_ROW))
    _fix(deps2, WARN_ROW, REPAIRED_ROW)
    assert flagged_rows(_inv(run2)) == ()


def test_fix_row_matches_the_rendered_stripped_row_text(tmp_path):
    """H4's normalisation rider, forced by claim pr1b (REFUTED byte-equality).

    `_tokenize_fence` (parser.py:90) does `stripped = raw.strip()` per source line and
    appends `stripped` to the block's rows, so `Locus.row_text` — the text the warning
    prints and the model copies — is NOT the on-disk line whenever that line carries leading
    or trailing whitespace. A raw-line comparison would make every such row permanently
    unmatchable, and with M5 the run permanently unclosable.

    The repair therefore matches against the STRIPPED row text, and rewrites the whole
    on-disk line it came from — trailing whitespace included."""
    on_disk_line = "  " + WARN_ROW + "   "
    doc = PROLOGUE + attr_block(on_disk_line)
    deps, run = main_deps(tmp_path)
    seed_investigation(run, doc)
    assert flagged_rows(doc) == (WARN_ROW,), "the fixture stopped exercising pr1b"

    _fix(deps, WARN_ROW, REPAIRED_ROW)

    assert flagged_rows(_inv(run)) == ()
    assert on_disk_line not in _inv(run), "the padded on-disk line survived the repair"
    assert REPAIRED_ROW in _inv(run)


def test_fix_row_repair_attempted_on_document_grown_since_window_opened(tmp_path):
    """The match runs against the CURRENT document. M3's derivation has no notion of when a
    row became flagged, only whether it currently is — so a repair issued after the document
    grew still lands."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC + "\nlater prose the model added\n")

    _fix(deps, WARN_ROW, REPAIRED_ROW)

    assert flagged_rows(_inv(run)) == ()
    assert "later prose the model added" in _inv(run)


def test_fix_row_new_row_trades_one_warn_defect_for_another(tmp_path):
    """A repair that introduces a DIFFERENT warn-family defect LANDS, and the window trades
    one flagged row for another.

    M2 makes the chain warn-permissive generically, not `append_block`-specifically, so the
    write is not refused. What bounds a repair loop is the BUDGET, not a refusal — which is
    why `fix_row` is metered rather than exempt (R1's accepted trade-off)."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)
    still_bad = "l-001|v-001|dept|svc.config-mgmt"

    _fix(deps, WARN_ROW, still_bad)

    assert flagged_rows(_inv(run)) == (still_bad,)
    assert still_bad in _inv(run)


def test_fix_row_new_row_syntactically_legal_but_unrelated(tmp_path):
    """Nothing checks a repair's SEMANTIC relationship to the defect it claims to fix.

    A deliberate, acknowledged gap, mirroring N5's exclusion of citation relevance: a repair
    that swaps the whole row for an unrelated but legal refinement of the same block lands
    exactly like a faithful one. Pinned so that nobody later reads its absence as an
    oversight and invents a relatedness check the design declined."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)
    unrelated = "l-001|v-002|class|user/known-corp"

    _fix(deps, WARN_ROW, unrelated)

    assert unrelated in _inv(run)
    assert flagged_rows(_inv(run)) == ()


# H3 — the `new_row` shape guard

@pytest.mark.parametrize(("label", "new_row"), [
    ("embedded newline", "l-001|v-001|class|a\nl-001|v-002|class|b"),
    ("fence delimiter", "l-001|v-001|class|a```invlang"),
    ("vertex declaration", "v-999|compute|bastion/internal/known-corp|evil.corp|kind=physical"),
    ("block header", _HEADER),
    ("too many cells", "l-001|v-001|class|a|b"),
    ("too few cells", "l-001|v-001|class"),
])
def test_fix_row_new_row_is_a_single_row_of_the_same_block(tmp_path, label, new_row):
    """H3's guard, one predicate: `new_row` is a SINGLE line, carries no fence delimiter, and
    parses as a row of the SAME block with that block's cell count.

    Each negative is a construction the probes executed against the code as it stands, and
    every one of them lands CLEAN today:

      * embedded newline — `_tokenize_fence` line-splits before any `Diagnostic` exists, so a
        well-formed second row with a legal key is SILENTLY ACCEPTED (65-probe-r6-frame.md)
      * fence delimiter — the regex treats the injected ``` as the block's CLOSING delimiter
        and the injected row VANISHES from the parsed document, zero warnings (rt11)
      * vertex declaration — append-only never inspects `:R` rows, so a fresh-id `:V` is
        accepted outright with both vertices genuinely present (rt9), and a colliding-id one
        is dropped by the parser's first-declaration-wins fold before append-only can see a
        collision (rt8)
      * too FEW cells — `_row_cells` PADS with `''`: no RowError, zero diagnostics at any
        severity, no denial (pr3, REFUTED as a uniform answer)

    Only the too-MANY-cells case is caught by anything today, and by the parser rather than
    by a guard. This is what makes SEC3 true by construction rather than by four separate
    reachability arguments — and what makes `no_verb_mutates_committed_record` dischargeable
    at all."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry):
        _fix(deps, WARN_ROW, new_row)

    assert _inv(run) == WARN_DOC, f"{label} left residue on disk"


def test_fix_row_new_row_shape_guard_admits_an_ordinary_repair(tmp_path):
    """H3's positive control, on the same address under the complementary condition: an
    ordinary key repair — one line, no delimiter, four cells against a four-column header —
    passes the guard and lands.

    Without it the guard could refuse everything and every negative above would still be
    green."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    _fix(deps, WARN_ROW, REPAIRED_ROW)

    assert REPAIRED_ROW in _inv(run)
    assert flagged_rows(_inv(run)) == ()


def test_no_verb_mutates_or_removes_a_committed_v_or_e_record(tmp_path):
    """O3 / SEC1, bound across EVERY write verb main can reach.

    Claim `x1`'s discharge argument is GONE — `_check_append_only` never inspects `:R` rows
    — so this negative rests entirely on H3's `new_row` guard plus append-only's own
    comparison of `:V`/`:E` cores. Both are driven here: `fix_row` cannot smuggle a record
    into a flagged row's position, and a committed vertex core cannot be mutated in place.

    The append-only half is driven directly through `diagnose`/`_check_append_only`, exactly
    as claim b3 executed it — "mutate v-002's ident in the :V declaration, run
    _check_append_only" — an IN-PLACE edit of the row already on disk, one declaration,
    rewritten, never a second one appended after it. `_tool_append_block` cannot construct
    this case at all: it only ever composes `on_disk + text`, so a "mutated" declaration
    submitted through it necessarily arrives as a SECOND `:V prologue.vertices` block, and
    `_check_append_only`'s `_by_id_first` keeps the FIRST declaration per id — the untouched
    original — so the comparison never sees the duplicate. That gap is real, pre-existing,
    and out of this suite's scope (tracked as FU-3 in the spec graph's handoff block); this
    test does not attempt to discharge it through the verb.

    The positive control is the last block: the SANCTIONED route to the same intent — a `:R`
    refinement — succeeds, so the negative is not green merely because every write fails."""
    from pydantic_ai.exceptions import ModelRetry

    def _diagnose(text, current=None):
        from defender.skills.invlang.validate import diagnose

        return diagnose(text, current)

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)
    committed = _inv(run)

    # fix_row cannot insert a record where a flagged :R row was (rt8/rt9/rt11)
    for smuggled in (
        "v-999|compute|bastion/internal/known-corp|evil.corp|kind=physical",
        "e-999|attempted_auth|v-001|v-002|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed",
    ):
        with pytest.raises(ModelRetry):
            _fix(deps, WARN_ROW, smuggled)
    assert _inv(run) == committed

    # a committed vertex core cannot be mutated in place (claim b3, executed exactly this way)
    mutated = committed.replace(
        "v-002|identity|user/known-corp|jsmith|",
        "v-002|identity|user/known-corp|attacker|",
    )
    reasons = _diagnose(mutated, committed)
    violations = [d for d in reasons if "append-only violation" in d.message]
    assert any("v-002" in d.message for d in violations), reasons
    # Severity is asserted per FAMILY, not over the whole diagnosis. The baseline here is
    # `WARN_DOC`, which carries `WARN_ROW` by construction — so a correct implementation
    # returns that row's WARNING alongside the append-only error, and a blanket
    # `all(severity == "error")` contradicted `test_only_attr_update_key_family_warns` on the
    # same fixture. What O3/SEC1 needs is that the in-place mutation is an ERROR; the second
    # assertion pins that the warn row is the only other thing here, so this is narrower in
    # wording and stricter in effect than the census it replaces.
    assert all(d.severity == "error" for d in violations)
    assert [d.severity for d in reasons if d not in violations] == ["warning"]

    # ...and the sanctioned route to the same intent still works.
    _fix(deps, WARN_ROW, REPAIRED_ROW)
    assert flagged_rows(_inv(run)) == ()


# `old_row`'s own domain

def test_fix_row_old_row_names_text_never_flagged(tmp_path):
    """N2: a row the window never flagged is refused as a SCOPE violation, not merely as a
    match failure.

    SEC1's discharge depends on `old_row` being scoped to the flagged set (claims r2/g10):
    the flagged set is `:R attr_updates`-only, so scoping is what puts every committed `:V`
    and `:E` record out of the verb's reach. A verb that refused only when the text was
    absent would happily rewrite a committed vertex row that IS present."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)
    committed_vertex_row = "v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical"
    assert committed_vertex_row in _inv(run), "the fixture's target line is not on disk"

    with pytest.raises(ModelRetry):
        _fix(deps, committed_vertex_row, "v-001|compute|bastion/internal/known-corp|evil|x")

    assert _inv(run) == WARN_DOC


def test_fix_row_old_row_is_empty(tmp_path):
    """The empty string is `old_row`'s distinguished falsy member and is NOT valid: it is not
    one of the currently-flagged rows, so it fails the same scoping guard as any other
    never-flagged text.

    `new_row`'s empty string is the opposite — the deletion escape — and the asymmetry is
    deliberate, which is why both are pinned."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry):
        _fix(deps, "", REPAIRED_ROW)

    assert _inv(run) == WARN_DOC


def test_fix_row_old_row_spans_more_than_one_line(tmp_path):
    """A multi-line `old_row` finds no match: no single on-disk line can equal a string
    containing a newline, so "matched as a whole line" is what refuses it."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, PROLOGUE + attr_block(WARN_ROW, SECOND_WARN_ROW))
    before = _inv(run)

    with pytest.raises(ModelRetry):
        _fix(deps, f"{WARN_ROW}\n{SECOND_WARN_ROW}", REPAIRED_ROW)

    assert _inv(run) == before


def test_fix_row_old_row_is_a_suggested_alternative(tmp_path):
    """A `use:` alternative is what the row COULD become, not what it IS.

    The model has both strings in front of it in the same rendered warning, so passing the
    correction back as `old_row` is the mistake the message's own shape invites. The match
    requires the literal on-disk flagged line."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry):
        _fix(deps, REPAIRED_ROW, REPAIRED_ROW_ATTRS)

    assert _inv(run) == WARN_DOC


def test_fix_row_old_row_matches_no_line(tmp_path):
    """A row that appears nowhere in the document is refused, nothing is written, and the
    refusal carries the unchanged-notice invariant so the model does not anchor its next
    edit to a repair that never happened."""
    from pydantic_ai.exceptions import ModelRetry

    from defender._artifact_schema import UNCHANGED_NOTICE

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry) as exc:
        _fix(deps, "l-001|v-777|owner|nothing-like-this", REPAIRED_ROW)

    assert UNCHANGED_NOTICE in str(exc.value)
    assert _inv(run) == WARN_DOC


def test_fix_row_old_row_and_new_row_swapped(tmp_path):
    """A swapped call is refused by the ORDINARY `old_row` guard — no special detection is
    needed, and none may be invented.

    Every stated guard is on `old_row`, so a swap simply puts unflagged text in the guarded
    slot. Pinned because a bespoke "did you mean to swap these?" branch would be a second
    place for the scoping rule to live — and a bespoke swap-detector would pass a plain
    `pytest.raises(ModelRetry)` identically to the ordinary guard, so the refusal MESSAGE is
    compared byte-for-byte against a plain never-flagged-text refusal (the technique
    `test_fix_row_repeated_identical_call` uses) rather than only checking that some
    `ModelRetry` was raised."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry) as swap_exc:
        _fix(deps, REPAIRED_ROW, WARN_ROW)
    with pytest.raises(ModelRetry) as plain_exc:
        _fix(deps, "l-001|v-777|owner|swap-guard-control", REPAIRED_ROW)

    assert _inv(run) == WARN_DOC
    assert str(swap_exc.value) == str(plain_exc.value), (
        "a swapped call and a plain never-flagged old_row must refuse IDENTICALLY — any "
        "difference would mean a bespoke swap-detector exists"
    )


def test_fix_row_repeated_identical_call(tmp_path):
    """The second identical call is refused on the same scoping rule as never-flagged text,
    and is deliberately INDISTINGUISHABLE from it — idempotent-safe by construction, not by
    special-casing.

    A "you already did this" branch would need to remember the repair, which is exactly the
    stored state M3 exists to avoid."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)
    _fix(deps, WARN_ROW, REPAIRED_ROW)
    after_first = _inv(run)

    with pytest.raises(ModelRetry) as repeat_exc:
        _fix(deps, WARN_ROW, REPAIRED_ROW)
    with pytest.raises(ModelRetry) as never_exc:
        _fix(deps, "l-001|v-777|owner|never-seen", REPAIRED_ROW)

    assert _inv(run) == after_first
    assert str(repeat_exc.value) == str(never_exc.value)


# `new_row`'s falsy member — O5's escape

def test_fix_row_with_empty_new_row_deletes_the_line(tmp_path):
    """The empty string is `new_row`'s distinguished falsy member and it is VALID: it deletes
    the line, and it is O5's always-available escape.

    `falsy_valid: true` on this domain is the whole reason the member is distinguished — an
    `if not new_row: refuse` coercion would swallow exactly the case O5 depends on."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, PROLOGUE + attr_block(WARN_ROW, SECOND_WARN_ROW))

    _fix(deps, WARN_ROW, "")

    assert WARN_ROW not in _inv(run)
    assert SECOND_WARN_ROW in _inv(run)
    assert flagged_rows(_inv(run)) == (SECOND_WARN_ROW,)


def test_fix_row_deletion_empties_its_block(tmp_path):
    """A3, settled by probe PR-8: deleting the only row of a `:R attr_updates` block leaves a
    HEADER-ONLY block, and that validates completely clean — zero diagnostics with or without
    a baseline, fence count unchanged 2 -> 2, `_check_append_only` returns `[]` because its
    loop compares `:V`/`:E` core tuples only.

    O5's deletion escape is therefore UNCONDITIONAL for this family, and the model never has
    to clean up after itself by removing a block append-only forbids removing."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    _fix(deps, WARN_ROW, "")

    text = _inv(run)
    assert _HEADER in text, "the block header was removed — append-only forbids that"
    assert WARN_ROW not in text
    assert flagged_rows(text) == ()
    assert text.count("```invlang") == WARN_DOC.count("```invlang")


def test_the_repair_window_is_closable_while_the_run_is_still_taking_turns(tmp_path):
    """O5, RE-SCOPED by H1: the window can always be closed **while the run is still taking
    turns**.

    Not unconditional, and the spec must not claim it is. R1 gives `fix_row` tail tier, so
    `should_refuse` never blocks it (claim bd1) and the deletion escape always validates
    clean (pr8) — but past `tail_exhausted` the UNCONDITIONAL hard kill in
    `driver._budget_short_circuit` ends the run at the `fix_row` call itself (bd2/bd6), and
    `UsageLimitExceeded` ends it with no exemption for anything, not even the close (bd4).
    Those boundaries are `test_repair_verb_under_budget_pressure`'s.

    Driven over the shape that would otherwise break it: a flagged row whose text is NOT
    unique. Deleting both identical bad rows closes the window, so O5 stays literally true
    (H4's own reasoning), and the close then commits."""
    from defender.runtime import challenge_gate
    from defender.runtime.close_tool import close_investigation
    from defender.tests import _review_bundle

    deps, run = main_deps(tmp_path)
    seed_investigation(run, _DUPLICATE_WARN_DOC)

    _fix(deps, WARN_ROW, "")

    assert flagged_rows(_inv(run)) == ()
    _pay_inconclusive_price(run)
    close_investigation(
        deps, "inconclusive",
        stages=_review_bundle.bundle(composer=_review_bundle.composer_reply("holds")),
        bounds=challenge_gate.default_bounds(),
    )
    assert (run / "report.md").is_file()


# the gate the repair itself faces

def test_fix_row_result_goes_through_decide_write(tmp_path):
    """The RESULTING full document faces the same `decide_write` -> `validate_investigation`
    chain every other write on this artifact faces.

    Driven with a `new_row` that passes H3's shape guard — one line, four cells, no
    delimiter — but produces an ERROR-severity document (a refinement resolved by a lead the
    document never declared). The repair is refused and nothing is written, which is what
    stops `fix_row` from being a hole in the validator rather than a verb behind it."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry) as exc:
        _fix(deps, WARN_ROW, "l-404|v-001|class|svc.config-mgmt")

    assert "undeclared lead" in str(exc.value)
    assert _inv(run) == WARN_DOC


def test_fix_row_new_row_pushes_document_past_size_bound(tmp_path):
    """The repair faces the SAME 64 KiB bound every write faces (`INVESTIGATION_FILE_MAX`,
    claim p8) — a `new_row` that pushes the document over it is refused.

    The deletion escape survives the bound by construction, because it only ever shrinks the
    document; that is asserted here too, since an over-bound run that could not delete would
    be unclosable under M5."""
    from pydantic_ai.exceptions import ModelRetry

    from defender._artifact_schema import INVESTIGATION_FILE_MAX

    deps, run = main_deps(tmp_path)
    padding = "\nfiller prose line that is not invlang at all\n" * 400
    doc = PROLOGUE + attr_block(WARN_ROW) + padding
    head_room = INVESTIGATION_FILE_MAX - len(doc.encode("utf-8"))
    assert head_room > 0, "the fixture is already over the bound"
    seed_investigation(run, doc)

    with pytest.raises(ModelRetry) as exc:
        _fix(deps, WARN_ROW, "l-001|v-001|class|" + "x" * (head_room + len(WARN_ROW) + 10))

    assert str(INVESTIGATION_FILE_MAX) in str(exc.value)
    assert _inv(run) == doc

    # ...and the escape that only ever shrinks is still available.
    _fix(deps, WARN_ROW, "")
    assert flagged_rows(_inv(run)) == ()


def test_append_block_size_bound_unchanged_by_fix_row(tmp_path):
    """R7's known-noise-mode reader: `append_block`'s own size-bound refusal is unaffected by
    `fix_row` becoming a second reader of the same constant.

    `INVESTIGATION_FILE_MAX` itself did not move (still 65536, code-provenance, claim p8) and
    `append_block`'s edge to it is unmoved — so this is a cheap regression, dismissed on the
    boundary's own evidence at THIS reader's edge rather than by a blanket waiver."""
    from pydantic_ai.exceptions import ModelRetry

    from defender._artifact_schema import INVESTIGATION_FILE_MAX
    from defender.runtime.tools import _tool_append_block

    assert INVESTIGATION_FILE_MAX == 65536

    deps, run = main_deps(tmp_path)
    _tool_append_block(deps, PROLOGUE)
    before = _inv(run)

    with pytest.raises(ModelRetry) as exc:
        _tool_append_block(deps, "x" * INVESTIGATION_FILE_MAX)

    assert str(INVESTIGATION_FILE_MAX) in str(exc.value)
    assert "already committed" in str(exc.value)
    assert _inv(run) == before


# SEC2 / SEC3 — who may call it, and when

def test_fix_row_is_offered_only_while_the_window_is_open(tmp_path):
    """`prepare=` hides the verb when nothing is flagged — the ergonomics half of M4.

    Claim b6/p7 is what makes hiding work at all, re-probed live at the version this project
    ACTUALLY runs: `pydantic-ai-slim` is floored at `>=1.107` and pinned at 1.107.0, and
    `prepare=` returning `None` hides the tool there. The doc's "pydantic-ai 2.19" reading
    came from a stray system interpreter and is corrected in the ledger — a reader must not
    go looking for a 2.x API.

    Both conditions are driven against the same run dir, so the offer is observed CHANGING
    rather than merely being present once."""
    deps, run = main_deps(tmp_path)
    inv = seed_investigation(run, PROLOGUE + attr_block(REPAIRED_ROW))

    assert "fix_row" not in offered_tool_names(deps)
    assert "append_block" in offered_tool_names(deps), "nothing was offered at all"

    inv.write_text(WARN_DOC, encoding="utf-8")
    assert "fix_row" in offered_tool_names(deps)


def test_fix_row_called_with_the_window_closed_is_refused_by_the_body(tmp_path):
    """SEC3: `prepare=` is ergonomics, the BODY is the guard.

    A model that saw the definition on an earlier turn can still emit the call — the offer is
    computed per request, the transcript is not rewritten — so the body re-derives the window
    at call time and refuses. Without this, hiding the tool would be the whole security story
    and a stale tool call would be an unguarded write.

    Positive control: the same call against an OPEN window succeeds, on the same address."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, PROLOGUE + attr_block(REPAIRED_ROW))
    before = _inv(run)

    with pytest.raises(ModelRetry):
        _fix(deps, WARN_ROW, REPAIRED_ROW_ATTRS)
    assert _inv(run) == before

    deps2, run2 = main_deps(tmp_path / "open")
    seed_investigation(run2, WARN_DOC)
    _fix(deps2, WARN_ROW, REPAIRED_ROW)
    assert flagged_rows(_inv(run2)) == ()


def test_fix_row_refused_once_the_close_committed(tmp_path):
    """SEC2 / RS15: no write on `investigation.md` after the close commits a recorded
    disposition — `fix_row` joins the three verbs that already refuse there (claim p10).

    THE DISCHARGE IS CONDITIONAL, AND THIS TEST SAYS SO (A8). PR-10 executed the divergence:
    `ReviewState.of(deps)` reads only an in-process dict, no disk path exists, and a fresh
    `AgentDeps` for the same run dir defaults to `closed=False` even with `report.md` already
    on disk (claims bd7/bd8). What is asserted here is the CONDITION — given the in-process
    flag this run set by closing, the repair is refused — not an unconditional guarantee. The
    scope is honest only because no resume feature exists (bd9): `run_investigation` builds
    deps exactly once and no entrypoint re-enters a prior run dir. The day one does, this
    demand is green and the property is false; that is recorded in `handoff.deviations` and
    filed as FU-2.

    Positive control: the same call BEFORE the close lands."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import challenge_gate
    from defender.runtime.close_tool import close_investigation
    from defender.tests import _review_bundle

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    _fix(deps, WARN_ROW, REPAIRED_ROW)          # pre-close: the repair lands
    assert flagged_rows(_inv(run)) == ()
    _pay_inconclusive_price(run)

    close_investigation(
        deps, "inconclusive",
        stages=_review_bundle.bundle(composer=_review_bundle.composer_reply("holds")),
        bounds=challenge_gate.default_bounds(),
    )
    assert challenge_gate.ReviewState.of(deps).closed is True, "the condition never held"
    committed = _inv(run)

    with pytest.raises(ModelRetry) as exc:
        _fix(deps, REPAIRED_ROW, REPAIRED_ROW_ATTRS)

    assert "closed" in str(exc.value).lower()
    assert _inv(run) == committed


# H6 — two write calls in one model response

def test_write_verbs_execute_sequentially_within_one_response(tmp_path):
    """H6: the write verbs execute SEQUENTIALLY within one model response.

    Probe PR-5 executed the default at the pinned floor and REFUTED the sequential reading
    (rt1): two `ToolCallPart`s in one `ModelResponse` run concurrently — async bodies
    interleave on the event loop, sync bodies run in the AnyIO worker thread pool — and in
    every trial BOTH reads happened before EITHER write. Against the real `write_guarded`
    primitive that is a genuine LOST UPDATE (rt2): identical pre-image in both reads, exactly
    ONE of the two intended changes on disk, and both calls reporting success to the model.

    `Agent.tool(..., sequential=True)` exists in the pinned floor and is unused (rt3). H6
    turns it on — knowingly changing behaviour on the pre-existing `append_block` path, which
    is why this arm drives two APPENDS: the fix is beyond #836's stated scope and was
    accepted with that cost stated.

    THE FLAG IS ASSERTED AS WELL AS THE ORDER, and that is not belt-and-braces. Both write
    verbs register as `async def` wrappers around fully synchronous bodies, so on the event
    loop they already run to completion without an await point — which makes the two-append
    ordering below UNFALSIFIABLE from a test process and would leave this demand pinned by an
    assertion that is green either way. The scheduling opt-in is the mechanism H6 chose, its
    production default is `False`, and `read_file` is the control showing the flag was set
    per-verb rather than globally."""
    deps, run = main_deps(tmp_path)
    tools = _registered_tools()

    assert tools["append_block"].sequential is True
    assert tools["fix_row"].sequential is True
    assert tools["read_file"].sequential is False, "the flag was set globally, not per-verb"

    seed_investigation(run, PROLOGUE)
    first = "\nfirst appended block\n"
    second = "\nsecond appended block\n"

    run_one_response(deps, [
        ("append_block", {"text": first}),
        ("append_block", {"text": second}),
    ])

    text = _inv(run)
    assert first.strip() in text
    assert second.strip() in text
    assert text.index(first.strip()) < text.index(second.strip())


def test_a_repair_and_an_append_in_one_response_both_persist(tmp_path):
    """H6's own worked case: a `fix_row` and an `append_block` emitted in ONE model response
    both persist.

    Under the concurrent default (rt1/rt2) one of the two writes is silently dropped — no
    exception, no torn bytes, both calls reporting success — so `fix_row(old, "")` paired with
    an `append_block` could discard the repair while telling the model it landed. The window
    would look closed and would not be.

    Both halves are asserted on disk, and the window is asserted CLOSED, because "the repair
    survived" and "the window is shut" are the two things a lost update takes apart."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    run_one_response(deps, [
        ("fix_row", {"old_row": WARN_ROW, "new_row": REPAIRED_ROW}),
        ("append_block", {"text": CLEAN_BLOCK}),
    ])

    text = _inv(run)
    assert REPAIRED_ROW in text, "the repair was lost"
    assert WARN_ROW not in text
    assert text.count(_HEADER) == 2, "the appended block was lost"
    assert flagged_rows(text) == ()
