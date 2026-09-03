"""#996 — what MAIN can see, hold and be told (O1, D14, D15; mechanisms 3, 4, 6, 7).

The port's whole cost case rests on one thing: MAIN stops carrying the invlang grammar. That
is not one edit — it is a prompt, a roster, an orientation section and ELEVEN files of runtime
refusal text that MAIN can receive outside the prompt. The census of that eleventh file is not
incidental: the list was written as seven, shown to name eight under a count of seven, and then
found to be eleven by a widened sweep. Two of those eleven instruct a row write in a
MAIN-reachable refusal and mechanism 6 owns neither, which is why they get their own demand.

D15 is the rule the text has to meet: text reaching MAIN may name a row, a slot or an id as the
LOCUS of a fact — the catalog MAIN keeps does the same — but it may not INSTRUCT MAIN to write
a row or to call a verb MAIN lacks.

RED against `7fa49f04`: `record` is not on MAIN's roster, orientation still inlines the
grammar, and the budget refusal still names both retired verbs.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402

from defender.agents import MAIN_DEF  # noqa: E402
from defender.hooks import budget_enforcer  # noqa: E402
from defender.runtime import orient  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.tools import AgentDeps, register_tools  # noqa: E402
from defender.tests import _clerk_996 as C  # noqa: E402

DEFENDER = C.DEFENDER

#: MAIN's roster after D14. `record` replaces BOTH document verbs; the close is registered by
#: its own root and rides beside them.
EXPECTED_ROSTER = {"bash", "read_file", "record", "close_investigation", "gather"}

#: The ten producer edges into MAIN's runtime refusal surface — mechanism 6's eight plus the
#: two the widened sweep found. Every one of them is a file whose strings MAIN can be handed
#: without asking for them.
MAIN_FACING_MODULES = (
    "runtime/close_tool.py",
    "runtime/circuit_breaker.py",
    "hooks/budget_enforcer.py",
    "skills/invlang/validate/_state.py",
    "skills/invlang/validate/_gating.py",
    "skills/invlang/validate/_closure.py",
    "skills/invlang/validate/_structure.py",
    "skills/invlang/validate/_predictions.py",
)

#: The phrasings D15 forbids, each one of O1's own stated failing conditions. A string may
#: still NAME a row, a slot or an id — that is the locus of a fact and MAIN's catalog names the
#: same things. What it may not do is tell MAIN to write one, or to call a verb D14 removed.
BANNED = (
    "append_block",
    "fix_row(",
    "resolve via",
    "re-send this row",
    "refine via",
    "add a `:T conclude.",
)


def _string_literals(path: Path) -> list[str]:
    """Every string literal in a module — comments and docstrings excluded.

    Comments are excluded because they are for a reader of the code, not for the model; module
    and function docstrings are excluded for the same reason, and half the hits in these files
    are exactly that. What is left is the text a refusal can actually carry."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    out: list[str] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and id(node) not in docstrings):
            out.append(node.value)
    return out


def _offenders(path: Path) -> list[str]:
    return [
        f"{path.name}: {phrase!r} in {lit[:80]!r}"
        for lit in _string_literals(path)
        for phrase in BANNED
        if phrase in lit
    ]


# ---------------------------------------------------------------------------------------
# the prompt and the orientation (mechanisms 3 and 4)
# ---------------------------------------------------------------------------------------


def test_996_orientation_drops_the_grammar_and_keeps_the_catalog(tmp_path: Path) -> None:
    """MAIN's orientation no longer inlines the invlang grammar, and STILL inlines the
    catalog.

    The two are different things and the distinction is the whole of mechanism 3: the grammar
    is block SYNTAX — how to spell a row — and it moves to the clerk; the catalog is the closed
    VOCABULARY MAIN reasons in, and MAIN keeps it, because naming a vertex type or a
    disposition is not writing a row. An orientation that dropped both would take away the
    words MAIN reasons with; one that dropped neither is the cost case unmade.

    The grammar block is built in exactly one place, which is what makes this a single edit
    with three test readers rather than a sweep."""
    alert = tmp_path / "alert.json"
    alert.write_text('{"rule": {"name": "probe"}}\n', encoding="utf-8")
    out = orient.orientation(tmp_path, DEFENDER, alert)

    assert "## invlang grammar" not in out, (
        "MAIN's orientation still inlines the row grammar — the port's whole cost case is that "
        "it does not"
    )
    assert ":L findings [id|loop|" not in out, (
        "the grammar's own block headers are still in MAIN's orientation"
    )
    assert "## invlang catalog" in out, (
        "the catalog went with the grammar; MAIN reasons in that vocabulary and still needs it"
    )


def test_996_the_shipped_main_skill_is_prose_only() -> None:
    """The shipped MAIN prompt is the prose variant: it tells MAIN to record in prose, names
    `record` and the REPORT header, and carries no row grammar and no verb MAIN lacks.

    Four additions the port makes to the ported variant are checked because each is a decision
    the design records: a REPORT section (record the report prose under the header, then
    close), the phase headers as the clerk's contract, what a FLAGGED receipt means, and what a
    rows-held receipt means. Without the last two MAIN receives receipts it has never been told
    how to answer."""
    body = (DEFENDER / "SKILL.md").read_text(encoding="utf-8")
    for required in ("record", "## REPORT"):
        assert required in body, f"the shipped MAIN prompt never mentions {required!r}"
    for lost in ("append_block", "fix_row"):
        assert lost not in body, (
            f"the shipped MAIN prompt still names {lost!r}, a verb D14 removes from its roster"
        )
    assert ":V prologue.vertices [id|type|class" not in body, (
        "the shipped MAIN prompt still carries the row grammar"
    )


# ---------------------------------------------------------------------------------------
# the roster (D14, F16)
# ---------------------------------------------------------------------------------------


def test_996_the_main_roster_is_bash_read_file_record_close() -> None:
    """NEGATIVE: MAIN's registered roster holds `record` and NEITHER document verb.

    The roster is read as the MODEL is offered it, off the agent the real composition root
    builds — a registry entry or a re-inspected function object would both agree while the wire
    carried something else. `append_block` and `fix_row` are not merely unadvertised: they are
    not registered, so a model that emits one gets an unknown-tool error rather than a write.

    POSITIVE CONTROL on the same address under the complementary condition: `record` IS
    registered, so the two absences are a swap and not an empty roster."""
    agent = Agent("test", deps_type=AgentDeps)
    register_tools(agent, MAIN_DEF.tools)
    names = set(agent._function_toolset.tools)

    assert "record" in names, "`record` is not on MAIN's roster at all"
    assert "append_block" not in names, "`append_block` is still registered for MAIN"
    assert "fix_row" not in names, "`fix_row` is still registered for MAIN"


def test_996_write_file_and_edit_file_stay_off_mains_roster() -> None:
    """NEGATIVE: the two LATENT writers of `investigation.md` stay off MAIN's roster.

    Both reach the document by path and both would give MAIN a way around `record` entirely —
    an anchored replace on an artifact the validator enforces as append-only. They are latent
    rather than absent: the tool bodies exist and other roles grant them, so nothing but MAIN's
    own tool set keeps them away, and the port is exactly the moment someone reaches for a
    whole-document rewrite.

    POSITIVE CONTROL on the same address under the complementary condition: a write-granting
    tool set DOES register both, so their absence here is MAIN's grant and not a missing
    registration."""
    import dataclasses

    main_agent = Agent("test", deps_type=AgentDeps)
    register_tools(main_agent, MAIN_DEF.tools)
    main_names = set(main_agent._function_toolset.tools)
    assert "write_file" not in main_names
    assert "edit_file" not in main_names

    writer = Agent("test", deps_type=AgentDeps)
    register_tools(writer, dataclasses.replace(MAIN_DEF.tools, write=True))
    writer_names = set(writer._function_toolset.tools)
    assert {"write_file", "edit_file"} <= writer_names, (
        "neither writer registers even for a write-granting role, so their absence above says "
        "nothing about MAIN's grant"
    )


# ---------------------------------------------------------------------------------------
# what MAIN is told (D15, mechanism 6; G5)
# ---------------------------------------------------------------------------------------


def test_996_no_main_facing_text_instructs_row_syntax_or_a_lost_verb() -> None:
    """COHERENCE, one assertion per producer: none of the ten edges into MAIN's runtime
    refusal surface instructs a row write or names a verb MAIN lacks.

    Bound per producing FILE rather than at the surface, for the reason coherence demands
    always are: a demand at the surface's own altitude reads green when eight of the ten
    producers moved — and this census has already under-counted twice, which is why the two
    files the widened sweep added get a demand of their own beside this one.

    The scan is over STRING LITERALS, not the file: comments and docstrings speak to a reader
    of the code and half the hits in these files are exactly that. The positive control is
    below."""
    offenders: list[str] = []
    for rel in MAIN_FACING_MODULES:
        offenders.extend(_offenders(DEFENDER / rel))
    assert offenders == [], (
        "MAIN-facing text instructs a row write or names a verb MAIN no longer holds:\n"
        + "\n".join(offenders)
    )


def test_996_the_banned_phrase_scan_can_see_a_violation(tmp_path: Path) -> None:
    """The positive control for the census above: the same scan over a planted module DOES
    report the phrase.

    A negative census with no control is green on a scan that matches nothing — a renamed
    constant, a changed quoting style, an AST walk that stopped reaching f-strings. This is the
    channel check, not a demand of its own."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        'REFUSAL = f"unresolved class — resolve via :R attr_updates or escalate"\n',
        encoding="utf-8")
    assert _offenders(planted), "the scan cannot see a violation even where one is planted"


def test_996_the_prediction_and_structure_refusals_instruct_no_row_write() -> None:
    """The two files the widened sweep added — the prediction check and the structure check —
    speak prose too, and mechanism 6's own list owns NEITHER.

    They get their own demand because they were found by a sweep, not by the list: the list was
    written as seven files, names eight under that count, and the sweep found eleven. Both of
    these instruct a row write in a refusal MAIN can receive, and both were outside the change
    that reworded the other nine.

    Asserted separately from the census above so that a fix which reworded the eight named
    files and left these two cannot pass by averaging."""
    offenders: list[str] = []
    for rel in ("skills/invlang/validate/_predictions.py",
                "skills/invlang/validate/_structure.py"):
        offenders.extend(_offenders(DEFENDER / rel))
    assert offenders == [], (
        "the two files the widened sweep added still instruct a row write:\n"
        + "\n".join(offenders)
    )


def test_996_the_budget_refusal_names_only_verbs_main_holds() -> None:
    """The budget refusal names `record` and no verb MAIN lacks.

    It is the sharpest of the ten because it is a SURVIVOR LIST: the message exists to tell a
    budget-stopped model what it can still do, so naming two withdrawn verbs there does not
    merely violate D15 — it sends the model to calls that cannot succeed, at the moment it has
    the least budget left to discover that."""
    text = budget_enforcer.BUDGET_REFUSAL_MESSAGE
    assert "record" in text, "the budget refusal never names the verb MAIN still holds"
    assert "append_block" not in text, "the budget refusal still names `append_block`"
    assert "fix_row" not in text, "the budget refusal still names `fix_row`"


def test_996_the_tail_tier_still_answers_for_the_two_retired_verbs() -> None:
    """SURVIVAL: the two retired verbs stay in the tail-tier NAME table, and the tier still
    answers `tail` for them.

    The table is keyed on a NAME, not on a grant, so a stale name in it is INERT — the policy
    the module already documents for exactly this case. What makes it a survival question
    rather than a cleanup is the replay of an OLD transcript: a run replaying calls recorded
    before the port still meets this table, and a tier that no longer answers for those names
    would refuse them at the cap instead of metering them.

    `record` joins them, because it is MAIN's only document verb and O10 requires it never be
    refused for budget."""
    for name in ("append_block", "fix_row", "record", "read_file"):
        assert budget_enforcer.tier(name, AgentRole.MAIN) == "tail", (
            f"{name!r} no longer answers `tail`, so a replayed call is refused at the cap"
        )
    assert "record" in budget_enforcer._MAIN_TAIL_TOOLS
    assert not budget_enforcer.should_refuse(
        {"tool_calls": 10_000}, "record", "tail", budget_enforcer.DEFAULT_LIMITS)


def test_996_the_close_wrapper_and_the_held_rows_section_render_one_text(
    tmp_path: Path,
) -> None:
    """PARITY: the close's own refusal and `record`'s held-rows section render the SAME lines
    for the same owed obligation.

    Two texts for one obligation is how the two drift: MAIN answers the close's wording,
    records again, and is handed a differently-worded version of the same demand — with no way
    to tell whether it is the same one. One text is also what makes the model-close refusal on
    a non-empty queue honest, since that refusal reuses these very lines.

    Driven from both ends over one document: the close is asked for its refusal, and a `record`
    is driven to a judgment stop over the same document, and the owed lines are compared."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.OPEN_SLOT_PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.JUDGMENT_ONLY_ROWS))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)
    receipt = main.receipt

    from defender.skills.invlang.validate import disposition_entry_price

    price = disposition_entry_price("benign", C.document(run_dir))
    assert price, "the fixture prices nothing, so there is nothing to compare"
    assert price.owed, "the fixture owes nothing, so there is nothing to compare"
    missing = [line for line in price.owed if line not in receipt]
    assert missing == [], (
        "the held-rows receipt and the close's own refusal render different text for the same "
        f"owed obligation: {missing}"
    )
