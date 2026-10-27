from __future__ import annotations

import pytest

from defender.tests.support.invlang.validation._invlang_warn_836 import (
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
    offered_tool_names,
    registered_tools,
    run_one_response,
    seed_investigation,
)

#: The `:R attr_updates` block header every fixture below declares — four columns.
_HEADER = ":R attr_updates [resolved_by|target|key|value]"

#: Two warn-family diagnostics for ONE row text, because the row is written twice.
_DUPLICATE_WARN_DOC = PROLOGUE + attr_block(WARN_ROW, WARN_ROW)


def _fix(deps, old_row, new_row):
    from defender.investigation.tools import _tool_fix_row

    return _tool_fix_row(deps, old_row, new_row)


def _inv(run):
    return (run / "investigation.md").read_text(encoding="utf-8")


def _pay_inconclusive_price(run) -> None:
    """Pay `inconclusive`'s entry price (#923), which is unrelated to the repair window; call
    only once the window is already clear, so it never masks what the test drives."""
    path = run / "investigation.md"
    path.write_bytes(
        path.read_bytes()
        + b'\n```invlang\n:T conclude\nceiling_test  state=nothing-to-try cap=telemetry.collect note=process telemetry not retrieved\n```\n'
    )


# the repair itself

def test_fix_row_repairs_a_flagged_row(tmp_path):
    """THE positive control for every negative in this module, the shape guard's included: a
    flagged row named exactly and replaced by a legal one closes the window, the rest untouched."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    _fix(deps, WARN_ROW, REPAIRED_ROW)

    assert _inv(run) == PROLOGUE + attr_block(REPAIRED_ROW)
    assert flagged_rows(_inv(run)) == ()


def test_fix_row_matches_a_whole_line_not_a_substring(tmp_path):
    """`old_row` matches a WHOLE line — never a substring of one, and never a span across lines."""
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
    deps, run = main_deps(tmp_path)
    seed_investigation(run, _DUPLICATE_WARN_DOC)
    assert flagged_rows(_inv(run)) == (WARN_ROW, WARN_ROW)

    _fix(deps, WARN_ROW, REPAIRED_ROW)

    assert flagged_rows(_inv(run)) == ()
    assert _inv(run).count(REPAIRED_ROW) == 2
    assert WARN_ROW not in _inv(run)


def test_fix_row_when_one_flagged_row_is_a_prefix_of_another(tmp_path):
    """Repairing the shorter of two flagged rows, one a PREFIX of the other, leaves the longer
    flagged: the multiplicity counts WHOLE LINES, not substrings."""
    short_row = "l-001|v-001|owner|svc"
    long_row = "l-001|v-001|owner|svc2"

    deps, run = main_deps(tmp_path)
    seed_investigation(run, PROLOGUE + attr_block(short_row, long_row))
    assert flagged_rows(_inv(run)) == (short_row, long_row)

    _fix(deps, short_row, "l-001|v-001|class|file-server/internal/known-corp")

    assert flagged_rows(_inv(run)) == (long_row,), "the prefix repair took the longer row too"
    assert long_row in _inv(run)

    # ...and the longer one is then repairable in its turn, so the window still closes.
    _fix(deps, long_row, "")
    assert flagged_rows(_inv(run)) == ()


def test_fix_row_refuses_a_match_outside_the_flagged_set(tmp_path):
    """If the row also stands as a WHOLE LINE the window did not flag (pasted into prose), the
    repair refuses; a copy merely embedded in a sentence is out of reach and does not."""
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


# the `new_row` shape guard

@pytest.mark.parametrize(("label", "new_row"), [
    ("embedded newline", "l-001|v-001|class|a\nl-001|v-002|class|b"),
    ("fence delimiter", "l-001|v-001|class|a```invlang"),
    ("vertex declaration", "v-999|compute|bastion/internal/known-corp|evil.corp|kind=physical"),
    ("block header", _HEADER),
    ("too many cells", "l-001|v-001|class|a|b"),
    ("too few cells", "l-001|v-001|class"),
])
def test_fix_row_new_row_is_a_single_row_of_the_same_block(tmp_path, label, new_row):
    """One predicate: `new_row` is a SINGLE line, carries no fence delimiter, and parses as a
    row of the SAME block with that block's cell count."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry):
        _fix(deps, WARN_ROW, new_row)

    assert _inv(run) == WARN_DOC, f"{label} left residue on disk"


def test_no_verb_mutates_or_removes_a_committed_v_or_e_record(tmp_path):
    """Bound across EVERY write verb MAIN can reach."""
    from pydantic_ai.exceptions import ModelRetry

    def _diagnose(text, current=None):
        from defender.skills.invlang.validate import diagnose

        return diagnose(text, current)

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)
    committed = _inv(run)

    # fix_row cannot insert a record where a flagged :R row was
    for smuggled in (
        "v-999|compute|bastion/internal/known-corp|evil.corp|kind=physical",
        "e-999|attempted_auth|v-001|v-002|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed",
    ):
        with pytest.raises(ModelRetry):
            _fix(deps, WARN_ROW, smuggled)
    assert _inv(run) == committed

    # a committed vertex core cannot be mutated in place
    mutated = committed.replace(
        "v-002|identity|user/known-corp|jsmith|",
        "v-002|identity|user/known-corp|attacker|",
    )
    reasons = _diagnose(mutated, committed)
    violations = [d for d in reasons if "append-only violation" in d.message]
    assert any("v-002" in d.message for d in violations), reasons
    assert all(d.severity == "error" for d in violations)
    assert [d.severity for d in reasons if d not in violations] == ["warning"]

    # ...and the sanctioned route to the same intent still works.
    _fix(deps, WARN_ROW, REPAIRED_ROW)
    assert flagged_rows(_inv(run)) == ()


# `old_row`'s own domain

def test_fix_row_old_row_names_text_never_flagged(tmp_path):
    """A row the window never flagged is refused as a SCOPE violation, not as a match failure."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)
    committed_vertex_row = "v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical"
    assert committed_vertex_row in _inv(run), "the fixture's target line is not on disk"

    with pytest.raises(ModelRetry):
        _fix(deps, committed_vertex_row, "v-001|compute|bastion/internal/known-corp|evil|x")

    assert _inv(run) == WARN_DOC


def test_fix_row_old_row_is_empty(tmp_path):
    """An empty `old_row` is NOT valid: it is not a flagged row. (An empty `new_row` is the
    deletion escape; the asymmetry is deliberate.)"""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry):
        _fix(deps, "", REPAIRED_ROW)

    assert _inv(run) == WARN_DOC


def test_fix_row_old_row_matches_no_line(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    from defender.records._artifact_schema import UNCHANGED_NOTICE

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry) as exc:
        _fix(deps, "l-001|v-777|owner|nothing-like-this", REPAIRED_ROW)

    assert UNCHANGED_NOTICE in str(exc.value)
    assert _inv(run) == WARN_DOC


# `new_row`'s falsy member — the deletion escape

def test_fix_row_with_empty_new_row_deletes_the_line(tmp_path):
    """An empty `new_row` is VALID: it deletes the line, the always-available escape."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, PROLOGUE + attr_block(WARN_ROW, SECOND_WARN_ROW))

    _fix(deps, WARN_ROW, "")

    assert WARN_ROW not in _inv(run)
    assert SECOND_WARN_ROW in _inv(run)
    assert flagged_rows(_inv(run)) == (SECOND_WARN_ROW,)


def test_the_repair_window_is_closable_while_the_run_is_still_taking_turns(tmp_path):
    """Driven over a flagged row whose text is NOT unique: deleting both copies closes the
    window, and the close commits. Past the budget's tail the run ends instead
    (`test_repair_verb_under_budget_pressure`)."""
    from defender.investigation import challenge_gate
    from defender.investigation.close_tool import close_investigation
    from defender.tests.support.runtime.permissions import _review_bundle

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
    """The RESULTING full document faces the same `decide_write` -> `validate_investigation` chain every other write on this artifact faces."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry) as exc:
        _fix(deps, WARN_ROW, "l-404|v-001|class|svc.config-mgmt")

    assert "undeclared lead" in str(exc.value)
    assert _inv(run) == WARN_DOC


def test_fix_row_new_row_pushes_document_past_size_bound(tmp_path):
    """The repair faces the SAME size bound every write faces (`INVESTIGATION_FILE_MAX`)."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.records._artifact_schema import INVESTIGATION_FILE_MAX

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


# who may call it, and when

def test_fix_row_is_offered_only_while_the_window_is_open(tmp_path):
    """`prepare=` hides the verb when nothing is flagged."""
    deps, run = main_deps(tmp_path)
    inv = seed_investigation(run, PROLOGUE + attr_block(REPAIRED_ROW))

    assert "fix_row" not in offered_tool_names(deps)
    assert "append_block" in offered_tool_names(deps), "nothing was offered at all"

    inv.write_text(WARN_DOC, encoding="utf-8")
    assert "fix_row" in offered_tool_names(deps)


def test_fix_row_called_with_the_window_closed_is_refused_by_the_body(tmp_path):
    """`prepare=` is ergonomics; the BODY is the guard."""
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
    """No write on investigation.md after the close commits: `fix_row` refuses there like the
    other write verbs."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.investigation import challenge_gate
    from defender.investigation.close_tool import close_investigation
    from defender.tests.support.runtime.permissions import _review_bundle

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


# two write calls in one model response

def test_write_verbs_execute_sequentially_within_one_response(tmp_path):
    from defender.agents import MAIN_DEF

    deps, run = main_deps(tmp_path)
    # MAIN's registered `Tool` objects: where the per-tool `sequential` flag lives.
    tools = registered_tools(MAIN_DEF)

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
    """Run concurrently, one of the two writes is silently lost; both must persist and the
    window must close."""
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
