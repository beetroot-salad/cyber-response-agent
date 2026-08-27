"""#935 — the two retrieval lanes score on ONE scale, and the class match is normalised to the
vertex type rather than guessed from the cell.

Three defects, filed as one because fixing any alone makes another worse and all three want
the same missing thing: a per-type class-tuple arity, documented in `skills/invlang/SKILL.md`
§Classification grammar and readable by nothing.

  1. EVERY node selector scored 2. `type` and `slot` are both mandatory and most shipped
     selectors omit the optional `class`, so the node lane was one flat value and `match_loaded`
     handed the top-3 to its `name` tiebreak. Two lessons keyed on a bare `slot: ident` — a cell
     every vertex carries — cut the one naming the exact `attrs.loginuid` the run held, because
     `c` sorts before `f`. That is the lesson #919 exists to make reachable.
  2. The EDGE lane was structurally starved. `anchor_kind` is its only mandatory field, so every
     shipped `frontier_edges` selector floored at 1 against a node floor of 2, and `_best_match`
     pools both lanes into one `max` — so any node match outranked any edge match. On the append
     where the first authorization contract opens, `_frontier_recall` emitted NO BLOCK AT ALL.
  3. `_class_pins` was NON-MONOTONIC across arity. For a three-slot selector, cases `??`,
     `??/??` and `ip-only/??/??` all matched, but `ip-only/??` MISSED — recording more about
     slot 0 of a two-slot tuple LOST a selector the vaguer document matched one write earlier.

What ships: `vocab.CLASS_GRAMMAR` / `vocab.class_arity` (the table SKILL.md states in prose),
the weights under THE SCALE in `scripts/lessons/lessons_frontier.py`, and `_spread_over_items`
— which is the half a reweight alone cannot do, because two selectors at their lanes' floors
are genuinely equally specific and no honest weight orders them.

WHY THIS FILE EXISTS SEPARATELY from `test_frontier_recall_919.py`. That suite ran its
inversion test at `top_k=9` and asserted only scores, so it stayed green across all three
defects while the EMITTED ordering was wrong. Every test here observes what the model is
actually handed — the list at the real cut, or the rendered block — against the real corpus and
the repo's own committed runs, not against documents written to suit the mechanism.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[1]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

from defender.scripts.lessons import lessons_frontier as LF  # noqa: E402
from defender.skills.invlang import vocab  # noqa: E402
from defender.skills.invlang.frontier import frontier_at, frontier_from_text  # noqa: E402
from defender.skills.invlang.validate import diagnose  # noqa: E402
from defender.tests._lessons_corpus import _write_lesson  # noqa: E402

CORPUS = DEFENDER / "lessons"
SKILL_MD = DEFENDER / "skills" / "invlang" / "SKILL.md"

#: The issue's reproduction of defect 1, verbatim. A `compute` vertex whose identifier is open
#: and an `identity` vertex holding `loginuid=-1` — the shape #919 was filed about, in two rows.
#: EXECUTED against the real `diagnose` and clean (asserted below), so an empty frontier here
#: would be a bug rather than the honest answer.
TWO_VERTEX_DOC = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/??/??|??|knowledge=partial
v-002|identity|user/known-corp|jsmith|uid=1000;loginuid=-1
```
"""

#: The lesson the whole lane exists to reach, and the one every defect cut.
LOGINUID_LESSON = "falco-loginuid-tty-non-interactive-not-docker-exec"

#: The two runs the issue replayed, at paths git actually tracks.
#:
#: `turnN-A` is COPIED into `_golden_invlang/` rather than read from `learning/runs/turnN-A/`,
#: which is where the run itself lives and which `.gitignore:91` excludes — runs are kept out
#: of the repo on purpose (`defender/CLAUDE.md`). Reading it there made every assertion about
#: it a skip on any machine but the one that produced it, so the fence-by-fence evidence for
#: #935's defect 2 could never run in CI. It is the document #919 was filed about and the one
#: this lane is judged on; committing the ~11KB is what makes the claim checkable by anyone.
REPLAYED_RUNS = (
    ("golden-sshpivot-ab3", DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3" / "investigation.md"),
    ("turnN-A", DEFENDER / "tests" / "_golden_invlang" / "turnN-A.investigation.md"),
)


#: One open authorization contract alongside THREE open node cells on three different vertices
#: — the shape that separates the fix from the fix the issue rejects. Three distinct node items
#: means `_spread_over_items` cannot rescue the edge lesson: each node lesson takes a first-pass
#: slot of its own, so the edge lane has to win on SCORE or not at all. EXECUTED against the
#: real `diagnose` and clean (asserted below).
CONTRACT_AND_THREE_CELLS_DOC = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical
v-002|identity|user/known-corp|jsmith|
v-003|process|??|nc[pid=4242]|image=/usr/bin/nc
v-004|file|??|/etc/passwd|
v-005|session|??|sess-9|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-002|v-001|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed

:L findings [id|loop|name|target|tests|system|window]
l-001|1|cmdb-lookup|v-001||cmdb|n/a

:H hypothesize.hypotheses \
[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?stolen-credential-reuse|v-001|runs_on|process|unclassified-process||null|active

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"jsmith permitted to authenticate at this time"|escalate|escalate
```
"""


def _names(hits) -> list[str]:
    return [h.name for h in hits]


def _match(text: str, *, top_k: int = LF.DEFAULT_TOP_K) -> list:
    return LF.match_lessons(frontier_from_text(text), CORPUS, top_k=top_k)


def _prefixes(text: str) -> list:
    """The frontier after each of `text`'s first `n` fences, for every `n` in `0..total`.

    ONE list, walked once. Fence by fence because that is when the recall FIRES:
    `_frontier_recall` derives the block over the pre- and post-append document and injects only
    when the two differ, so a defect that shows up as "the same three lessons as last time" is
    invisible to any test that scores the terminal document once. Every caller below wants both
    `n` and `n - 1`, and `frontier_at` re-scans and re-parses the whole document per call."""
    total = frontier_at(text, sys.maxsize).total
    return [frontier_at(text, n).frontier for n in range(total + 1)]


# --------------------------------------------------------------------------- #
# the missing table
# --------------------------------------------------------------------------- #

def test_the_arity_table_says_what_the_skill_documents():
    """CLAIM: `vocab.CLASS_GRAMMAR` is the SKILL's §Classification grammar table, readable.

    THE ROOT CAUSE, closed from both ends. All three defects deferred to "class arity is a
    documented function of the vertex type" and there was nothing to defer TO — the grammar
    lived only in prose a human reads. A table transcribed by hand is the same failure one
    refactor later, so this parses the prose and holds the code against it: the arity, and the
    ENUM NAME filling each position, both have to agree.
    """
    # SCOPED to the section, not to the whole file. The row pattern is generic enough to hit
    # any table anywhere in SKILL.md whose first column happens to be a vertex type, and the
    # dict below is last-wins — so an unrelated table added later would silently redefine what
    # this test holds the code against, or fail it somewhere the grammar is not even discussed.
    body = SKILL_MD.read_text(encoding="utf-8")
    section = re.search(r"^## Classification grammar$(.*?)^#", body, re.M | re.S)
    assert section, "SKILL.md no longer has a §Classification grammar section"
    rows = re.findall(r"^\|\s*`?([a-z -]+)`?\s*\|\s*`?([^|`]+)`?\s*\|", section.group(1), re.M)
    documented = {
        t.strip(): g.strip() for t, g in rows if t.strip() in vocab.TYPES or t.strip() == "all others"
    }
    assert "all others" in documented, (
        f"SKILL.md §Classification grammar did not parse — got {sorted(documented)}"
    )

    for vertex_type, grammar in documented.items():
        if vertex_type == "all others":
            continue
        # `<role>/<zone>/<provenance>` is a tuple; "single token" / "image basename" is not.
        placeholders = re.findall(r"<([a-z-]+)>", grammar)
        expected = len(placeholders) or vocab.DEFAULT_CLASS_ARITY
        assert vocab.class_arity(vertex_type) == expected, (
            f"SKILL.md gives `{vertex_type}` as `{grammar}` ({expected} slots) and "
            f"`vocab.class_arity` answers {vocab.class_arity(vertex_type)}"
        )
        # ...and each position names the enum that fills it, so the table cannot drift into a
        # bare count that no longer describes the grammar it claims to.
        assert vocab.CLASS_GRAMMAR.get(vertex_type, ()) == tuple(
            f"{vertex_type}.{p}" for p in placeholders
        ), f"`{vertex_type}`'s positions disagree with SKILL.md's `{grammar}`"

    assert set(vocab.CLASS_GRAMMAR) == {
        t for t, g in documented.items() if "<" in g
    }, "a multi-slot type in SKILL.md is missing from CLASS_GRAMMAR, or vice versa"


def test_every_grammar_position_is_a_slot_enum_can_answer():
    """CLAIM: the table's positions are `SLOTS` keys, so `enum {slot}` answers for each.

    Spelling the positions as enum names rather than as an integer is what makes the assert
    above possible AND what an author is sent to look up when a slot is wrong. A position
    naming a key `SLOTS` does not carry is a lookup that dead-ends."""
    for vertex_type, slots in vocab.CLASS_GRAMMAR.items():
        for slot in slots:
            assert vocab.get_enum(slot), f"{vertex_type}'s position {slot!r} enumerates nothing"


# --------------------------------------------------------------------------- #
# defect 3 — the class match is monotonic in what the document records
# --------------------------------------------------------------------------- #

def test_recording_more_about_a_class_slot_never_loses_a_selector():
    """CLAIM: refining a class cell only ever ADDS matches — never removes one.

    The filed table, which is the whole defect in four rows. Against
    `sel='ip-only/internet/novel'`, cases `??`, `??/??` and `ip-only/??/??` all matched and
    `ip-only/??` MISSED, because arity was guessed from the cell: a cell concrete enough to be
    taken at its length was taken at the WRONG length. `_check_vocab_vertices` validates `type`
    and never class arity, so `class=ip-only/??` on a `compute` vertex is diagnostic-clean —
    there is no other line of defence.

    Asserted as monotonicity rather than as four numbers because that is the property: a
    document is refined one write at a time, and a retrieval that goes DARK on a refinement is
    worse than one that never fired."""
    sel = "ip-only/internet/novel"
    refinements = ("??", "??/??", "??/??/??", "ip-only/??", "ip-only/??/??", "ip-only/internet/??")
    pins = {case: LF._class_pins(sel, case, "compute") for case in refinements}

    assert None not in pins.values(), (
        f"refining a compute class cell lost the selector: {pins}"
    )
    assert pins["ip-only/??"] == pins["ip-only/??/??"], (
        "a two-slot spelling of a three-slot type scored differently from the padded one — "
        "the cell is still being taken at its own length"
    )
    # ...and the inversion still costs what it always cost: a pattern that matched NOWHERE by
    # equality pins nothing, so the wholly-open cases stay at 0 rather than riding the padding.
    assert pins["??"] == pins["??/??"] == pins["??/??/??"] == 0
    assert pins["ip-only/??"] == 3

    # The normalisation is per TYPE, not a blanket pad: `identity` is two slots, so the same
    # arity that admits a triple on a `compute` cell must refuse one here.
    assert LF._class_pins("user/known-corp", "user/??", "identity") == 2
    assert LF._class_pins(sel, "user/??", "identity") is None, (
        "a three-slot selector matched a two-slot type — arity is not being read from the type"
    )

    # ...and the property holds ONE ARITY OVER, where the first fix left a second copy of the
    # same defect. A selector naming more slots than its type has is mis-authored, and a
    # "wholly-open cases say nothing about their own arity" clause widened the bound to the
    # SELECTOR — so `class: bash/child` on a one-slot `process` matched `class=??` and then
    # returned `None` the moment the run settled the basename to `bash`. Refusing it at every
    # stage of the refinement is what the surrounding comment already claimed; refusing it at
    # only some of them is the retrieval going dark on the write that says more.
    over_long = [
        LF._class_pins("bash/child", case, "process")
        for case in ("??", "{bash, sh}", "bash")
    ]
    assert over_long == [None, None, None], (
        f"a mis-authored over-long selector matched while the cell was open and stopped "
        f"matching once it settled: {over_long}"
    )


def test_a_settled_slot_still_refuses_a_selector_that_disagrees_with_it():
    """CLAIM: normalising arity WIDENS the case, it does not wildcard it.

    The cheap wrong fix for defect 3 is to pad the case with `??` unconditionally and let
    everything through. Slot 0 is settled to `ip-only` in both cells below, so a selector
    naming `bastion` must still miss — at either spelling of the same cell."""
    for case in ("ip-only/??", "ip-only/??/??"):
        assert LF._class_pins("bastion/internal/novel", case, "compute") is None, (
            f"a concrete slot 0 stopped refusing a selector that disagrees with it ({case})"
        )


def test_a_cell_declaring_more_slots_than_its_type_is_widened_not_truncated():
    """CLAIM: an over-long class cell keeps every slot it declared.

    Truncating to the grammar's arity would silently drop what the author DID say and let a
    selector match through the hole — a mis-authored document reading as a more permissive one.
    `process` is a single token, so this cell is wrong; the selector still has to agree with it."""
    assert LF._class_pins("bash/child", "bash/child", "process") == 2
    assert LF._class_pins("bash/other", "bash/child", "process") is None, (
        "a slot past the type's arity stopped constraining — the cell was truncated"
    )


# --------------------------------------------------------------------------- #
# defect 1 — the node lane can tell a named attribute from a universal cell
# --------------------------------------------------------------------------- #

def test_the_filed_reproduction_reaches_the_loginuid_lesson_at_the_real_cut():
    """CLAIM: the issue's own two-row document, against the REAL corpus, at the REAL `top_k`.

    Filed as rank 4 of 4 with everything tied at 2 and the alphabet deciding: two lessons whose
    selector is a bare `slot: ident` — a cell every vertex carries — beat the one naming the
    exact `attrs.loginuid` the document holds, because `c` sorts before `f`.

    At `top_k=3`, which is what the model is handed. The suite's existing inversion test ran at
    `top_k=9` and asserted only scores, which is precisely why it stayed green through this."""
    assert diagnose(TWO_VERTEX_DOC, None) == [], "the reproduction is no longer a clean document"

    hits = _match(TWO_VERTEX_DOC)
    top = _names(hits)
    assert LOGINUID_LESSON in top, (
        f"#919's motivating lesson is still cut from its own reproduction; got {top}"
    )

    # ...and it is IN because it outscores the two bare-`ident` lessons that cut it, not
    # because it happens to sort ahead of them. Asserted as a score relation rather than as
    # `top[0] == ...`, and the difference is whether this test survives its own corpus:
    # `defender/lessons/` is machine-authored and the curator commits to it one batch at a
    # time (`defender/CLAUDE.md`), so a NEW lesson keyed on the same `attrs.loginuid` cell
    # ties at the same score on the same item — `_spread_over_items` cannot separate two
    # lessons about one cell, so the `name` tiebreak decides between them. Pinning the
    # position would then red CI in a file nobody edited, and would be pinning the one thing
    # this lane genuinely cannot promise.
    by_name = {h.name: h.score for h in _match(TWO_VERTEX_DOC, top_k=99)}
    cut_it = ["container-id-anchor-before-uid-lookup", "container-identity-gap-not-terminal"]
    for loser in cut_it:
        assert by_name[loser] < by_name[LOGINUID_LESSON], (
            f"{loser} keys on a bare `slot: ident` and still scores at or above the lesson "
            f"naming the exact attribute the document holds"
        )


def test_a_named_attribute_outscores_a_cell_every_vertex_carries():
    """CLAIM: `attrs.<name>` and `class`/`ident` are not the same amount of specificity.

    The mechanism behind defect 1. `class` and `ident` exist on every vertex, so matching one
    narrows the frontier to "a vertex of this type"; `attrs.loginuid` narrows it to the
    vertices that HOLD that attribute, which is a claim about the document. Scoring them alike
    is what made the whole node lane a constant 2.

    Read off the selectors rather than off a corpus, so a reweight that fixed the shipped
    ranking by accident — a name change, a lucky tie — cannot pass this."""
    universal = LF._NodeSelector(type="identity", class_pattern="*", slot="ident")
    named = LF._NodeSelector(type="identity", class_pattern="*", slot="attrs.loginuid")

    assert named.fixed_specificity > universal.fixed_specificity, (
        "a selector naming an attribute scored no better than one naming a universal cell"
    )
    assert LF._NodeSelector(type="identity", class_pattern="*", slot="class").fixed_specificity == (
        universal.fixed_specificity
    ), "`class` and `ident` are both universal cells and must weigh the same"


# --------------------------------------------------------------------------- #
# defect 2 — the edge lane can be heard
# --------------------------------------------------------------------------- #

def test_the_edge_lane_is_not_floored_below_the_node_lane():
    """CLAIM: an edge selector carrying only its mandatory field is not outranked by every
    node match.

    `anchor_kind` is the only mandatory field on an edge selector, so a count of declared
    fields floored the lane at 1 against a node floor of 2 — and `_best_match` pools both into
    one `max`. The lane could not win a slot from any node match at all, and `held` only
    accumulates, so once three node selectors matched it never recovered within a run."""
    floor_edge = LF._EdgeSelector(rel="", auth_kind="", anchor_kind="iam-policy")
    floor_node = LF._NodeSelector(type="compute", class_pattern="*", slot="class")

    assert floor_edge.specificity >= floor_node.fixed_specificity, (
        "the loosest edge selector still scores below the loosest node selector"
    )
    # ...and the optional fields still buy precision on top, so the lane has range rather than
    # a single raised floor.
    assert LF._EdgeSelector(
        rel="attempted_auth", auth_kind="siem-event", anchor_kind="iam-policy"
    ).specificity > floor_edge.specificity


def test_the_edge_lane_wins_a_slot_on_score_rather_than_on_its_name(tmp_path):
    """CLAIM: an edge lesson at its lane's FLOOR is retrieved against three bare node matches,
    and it does not depend on how the lesson is named.

    THE TEST FOR THE FIX THE ISSUE REJECTS. Raising the edge floor to 2 makes it TIE with a
    bare node selector, and `match_loaded`'s `name` tiebreak then evicts whichever sorts later
    — which is defect 1 wearing the other lane's clothes, and it passes any test whose edge
    lesson happens to sort early. So the edge lesson here is named `zzz` and the three node
    lessons `aaa`/`bbb`/`ccc`, which is the worst case for it.

    Three DIFFERENT open cells on purpose: `_spread_over_items` gives each node lesson a
    first-pass slot of its own, so it cannot rescue the edge lesson from a tie. The lane has to
    carry its own weight — matching one of the run's ~2 open contracts under a named anchor is
    a stronger claim about this document than matching one of its ~25 node cells by type plus a
    universal cell, and `ANCHOR_KIND_WEIGHT` is where that is written down."""
    assert diagnose(CONTRACT_AND_THREE_CELLS_DOC, None) == [], "the fixture is not clean"

    corpus = tmp_path / "lessons"
    corpus.mkdir()
    _write_lesson(corpus, "zzz-anchor-only", edges=("anchor_kind: iam-policy",))
    for name, vertex_type in (
        ("aaa-any-process", "process"), ("bbb-any-file", "file"), ("ccc-any-session", "session")
    ):
        _write_lesson(corpus, name, nodes=(f"type: {vertex_type}, slot: class",))

    hits = LF.match_lessons(frontier_from_text(CONTRACT_AND_THREE_CELLS_DOC), corpus)
    assert "zzz-anchor-only" in _names(hits), (
        "the lesson speaking to the run's one open authorization question lost every slot to "
        f"three bare node matches that sort earlier; got {_names(hits)}"
    )
    assert _names(hits)[0] == "zzz-anchor-only", (
        "the edge lesson survived on the alphabet rather than on its score"
    )


@pytest.mark.parametrize(("label", "path"), REPLAYED_RUNS)
def test_the_block_moves_on_the_append_that_opens_an_authorization_question(label, path):
    """CLAIM: replayed fence by fence, the append where `contracts` goes 0 -> 2 changes what
    the model is handed.

    The filed defect, on the repo's own runs. Both authz lessons matched at 1, three node
    matches at 2 saturated `top_k`, the emitted list was UNCHANGED from the block before —
    and because `_frontier_recall` diffs the rendered block, the append that opened "what can
    this anchor conclude" emitted nothing at all. A test that scores the terminal document
    cannot see this: by then the list has moved for other reasons.

    Asserted on the RENDERED block, which is the thing the diff actually compares."""
    assert path.is_file(), f"{label}'s document is tracked and must be present ({path})"
    text = path.read_text(encoding="utf-8")
    # ONE walk of the prefixes. `frontier_at` re-scans the fences and re-parses the rebuilt
    # prefix on every call, so asking for `n` and `n - 1` inside the comprehension paid for the
    # whole document twice per fence.
    prefixes = _prefixes(text)

    opened = [
        n for n in range(1, len(prefixes))
        if prefixes[n].contracts and not prefixes[n - 1].contracts
    ]
    assert opened, f"{label} never opens an authorization contract — the fixture moved"

    for n in opened:
        before = LF.render(LF.match_lessons(prefixes[n - 1], CORPUS))
        after = LF.render(LF.match_lessons(prefixes[n], CORPUS))
        assert after != before, (
            f"{label} fence {n} opened a contract and the block did not move — "
            f"`_frontier_recall` would inject nothing:\n{after}"
        )
        assert any("anchor=" in line for line in after.splitlines()), (
            f"{label} fence {n}: the block moved but no lesson speaks to the contract:\n{after}"
        )


# --------------------------------------------------------------------------- #
# the selection — what a reweight alone cannot do
# --------------------------------------------------------------------------- #

def test_two_lessons_about_one_open_thing_do_not_take_the_whole_block(tmp_path):
    """CLAIM: the head covers as many DISTINCT frontier items as the matches allow, before it
    spends a second slot on any one of them.

    Not "never repeats" — a document with two open things and a `top_k` of three must repeat,
    and the third slot rightly goes to the runner-up on the better item. The property is that
    no item takes a second slot while another item is still unrepresented.

    The interlock the issue names: reweighting alone just changes WHICH lesson the alphabet
    evicts. Two selectors at their lanes' floors are genuinely equally specific and no honest
    weight orders them — so on `turnN-A` the two lessons keyed on `iam-policy` both matched the
    same contract `ac2`, took two of three slots between them, and cut the `attrs.loginuid`
    lesson a second time.

    Three lessons about one cell is strictly less of the frontier covered than three about
    three, and the runner-up is not lost — it sits behind the leader on every OTHER item."""
    corpus = tmp_path / "lessons"
    corpus.mkdir()
    same = ("type: identity, slot: attrs.loginuid",)
    _write_lesson(corpus, "aaa-crowd-one", observed=same)
    _write_lesson(corpus, "bbb-crowd-two", observed=same)
    _write_lesson(corpus, "ccc-crowd-three", observed=same)
    _write_lesson(corpus, "zzz-other-item", observed=("type: identity, slot: ident",))

    everything = LF.match_lessons(frontier_from_text(TWO_VERTEX_DOC), corpus, top_k=9)
    hits = LF.match_lessons(frontier_from_text(TWO_VERTEX_DOC), corpus)
    available = {h.matched for h in everything}
    assert len({h.matched for h in hits}) == min(LF.DEFAULT_TOP_K, len(available)), (
        f"the block left an open thing unrepresented while doubling up on another: "
        f"{[h.matched for h in hits]} out of {sorted(available)}"
    )
    assert "zzz-other-item" in _names(hits), (
        "a lesson about a second open thing lost every slot to three about the first, and "
        "only the alphabet decided which three"
    )
    # ...and the crowd is ordered among itself, not dropped: the runner-up follows once every
    # item has had its turn.
    assert _names(everything) == [
        "aaa-crowd-one", "zzz-other-item", "bbb-crowd-two", "ccc-crowd-three",
    ]


def test_the_order_is_total_and_stable_across_calls():
    """CLAIM: two calls on one frontier give the same list, in the same order.

    Not cosmetic and not covered by the existing stability test, which predates the spread:
    `_frontier_recall` decides whether to inject by comparing two RENDERED blocks, so any
    non-determinism in the re-grouping re-injects the same lessons on every frontier-moving
    write — the churn the second gate exists to prevent, with nothing red to notice it by."""
    first = _match(TWO_VERTEX_DOC, top_k=9)
    second = _match(TWO_VERTEX_DOC, top_k=9)
    assert _names(first) == _names(second)
    assert [h.score for h in first] == [h.score for h in second]
    # ...and `top_k` is a CUT on that one order rather than a second ranking.
    assert _names(_match(TWO_VERTEX_DOC, top_k=2)) == _names(first)[:2]


# --------------------------------------------------------------------------- #
# the whole thing, against the real corpus and the real runs
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("label", "path"), REPLAYED_RUNS)
def test_no_replayed_block_leaves_an_open_thing_unrepresented(label, path):
    """CLAIM: across every fence of both committed runs, the block covers as many distinct
    frontier items as its matches allow.

    The end-to-end reading of the spread, and the one that catches a regression in either
    half: a weight change that re-crowds one item, or a selection change that stops spreading.
    Every prefix of both runs, against the real 16-file corpus.

    The bound is `min(top_k, distinct items matched)`, not `top_k` — an early fence may simply
    not have three different open things to speak to, and filling the third slot with the
    runner-up on a covered item is the right answer there."""
    assert path.is_file(), f"{label}'s document is tracked and must be present ({path})"
    text = path.read_text(encoding="utf-8")
    for n, frontier in enumerate(_prefixes(text)):
        # ONE corpus walk per fence, and the two values derived from it separately. `top_k` is
        # a CUT on one order rather than a second ranking — `test_the_order_is_total_and_stable
        # _across_calls` pins that — so the emitted block is the head of this list, and asking
        # `match_lessons` a second time re-opened and re-YAML-parsed all 16 lesson files per
        # fence of both runs for an answer already in hand.
        ranked = LF.match_lessons(frontier, CORPUS, top_k=99)
        emitted = [h.matched for h in ranked[:LF.DEFAULT_TOP_K]]
        available = {h.matched for h in ranked}
        assert len(set(emitted)) == min(LF.DEFAULT_TOP_K, len(available)), (
            f"{label} fence {n} doubled up while an open thing went unmentioned: "
            f"{emitted} out of {sorted(available)}"
        )


def test_the_loginuid_lesson_survives_every_fence_of_its_own_run():
    """CLAIM: once `turnN-A` holds `loginuid=-1`, the lesson about it stays in the block.

    `test_the_shipped_corpus_reaches_the_motivating_investigation` asserts this on the terminal
    document only, and the terminal document is the easiest one: this asserts it from the fence
    that settles the value onward, which is where defect 2's fix could quietly evict it — the
    contracts on this run are never discharged, so the edge lane holds a slot for the rest of
    the run."""
    # BY LABEL, not by index: reordering `REPLAYED_RUNS` would otherwise point this silently
    # at the other run, and `assert holds` below would fail naming the wrong cause.
    path = dict(REPLAYED_RUNS)["turnN-A"]
    assert path.is_file(), f"turnN-A's document is tracked and must be present ({path})"

    prefixes = _prefixes(path.read_text(encoding="utf-8"))
    holds = [
        n for n, frontier in enumerate(prefixes)
        if any(h.slot == "attrs.loginuid" for h in frontier.held)
    ]
    assert holds, "turnN-A no longer settles `attrs.loginuid` — the fixture moved"

    for n in holds:
        assert LOGINUID_LESSON in _names(
            LF.match_lessons(prefixes[n], CORPUS)
        ), f"the loginuid lesson fell out of the block at fence {n}, where the run holds the value"


# --------------------------------------------------------------------------- #
# the gate the spread sits in front of
# --------------------------------------------------------------------------- #

#: One `compute` vertex with an open class triple and an open ident, and the ordinary append
#: that declares a second. The pair is the churn shape the gate below exists for — see the test.
_ONE_COMPUTE = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/??/??|??|knowledge=partial
```
"""
_SECOND_COMPUTE = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-004|compute|??/??/??|host-4.corp|knowledge=partial
```
"""


def test_a_coverage_reshuffle_does_not_re_staple_the_same_lessons(tmp_path):
    """CLAIM: `_frontier_recall` stays quiet when the lesson set and its scores are unchanged
    and only the COVERAGE order moved.

    `_spread_over_items` makes the emitted order a property of which frontier items the block
    covers, not of score alone — so an append can permute the three without changing which
    three or what they scored. The gate compared an ORDERED `(path, score)` list, which was a
    pure function of the pairs only while the ranking was `(-score, name)`; it now compares
    that as a sorted multiset, because re-stapling ~1.5KB of precedent the model already holds
    is the churn this second gate exists to prevent.

    The append below is ordinary: `v-001` is the only compute vertex, so the loose
    `{type: compute, slot: class}` lesson shares its cell with the `ip-only` one and sits in
    the second pass. Declaring `v-004` gives it a cell of its own, it moves into the first
    pass, and all three permute — same three lessons, same three scores.

    Driven through `_tool_append_block`, which is where the gate runs on the authoring path."""
    pytest.importorskip("pydantic_ai")  # as the two sibling suites do at module scope
    from defender.runtime.tools import _tool_append_block
    from defender.tests._lessons_corpus import _main_deps

    deps, _run, dfn = _main_deps(tmp_path)
    corpus = dfn / "lessons"
    corpus.mkdir()
    _write_lesson(corpus, "aaa-any-compute-class", nodes=("type: compute, slot: class",))
    _write_lesson(corpus, "bbb-ip-only", nodes=("type: compute, class: ip-only, slot: class",))
    _write_lesson(corpus, "ccc-any-compute-ident", nodes=("type: compute, slot: ident",))

    # The fixture only tests the gate if the append really is the churn shape: same lessons at
    # the same scores, different order. Asserted rather than assumed — a weight or placement
    # change that stopped permuting would make the assertion below vacuous.
    ranked = [
        [(h.name, h.score) for h in LF.match_lessons(frontier_from_text(doc), corpus)]
        for doc in (_ONE_COMPUTE, _ONE_COMPUTE + _SECOND_COMPUTE)
    ]
    assert sorted(ranked[0]) == sorted(ranked[1]), "the fixture no longer holds scores equal"
    assert ranked[0] != ranked[1], (
        "the fixture no longer permutes the block — it cannot test the gate"
    )

    _tool_append_block(deps, _ONE_COMPUTE)
    second = _tool_append_block(deps, _SECOND_COMPUTE)
    assert "Lessons matched against your record" not in second, (
        f"the same three lessons at the same three scores were re-stapled:\n{second}"
    )
    # ...and the gate is not simply mute: an append reaching a lesson it has not shown emits.
    _write_lesson(corpus, "ddd-loginuid", nodes=("type: identity, slot: attrs.loginuid",))
    third = _tool_append_block(deps, """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-007|identity|user/known-corp|jsmith|loginuid=??
```
""")
    assert "ddd-loginuid" in third, (
        "the gate stayed quiet on an append that reached a lesson it had not shown"
    )


def test_a_lesson_tied_across_two_cells_is_placed_on_the_one_nothing_else_covers(tmp_path):
    """CLAIM: a lesson that reaches its best score on several items is recorded against the
    item the block is not already covering — not against whichever the walk saw first.

    `_best_match` used to answer with `max`, which returns the FIRST maximal element, so a
    lesson tied across two cells was attributed by the order the vertices happen to be declared
    in. That was harmless while the answer was only rendered; the spread places a lesson BY its
    item, which made block membership depend on declaration order. The tie is not an edge case:
    replayed over both committed runs it holds on nearly every fence, including for the
    `attrs.loginuid` lesson this lane exists to retrieve.

    Below, the loose class lesson ties across both compute vertices. Placing it on the one the
    `ip-only` lesson is not already occupying is what lets the block name two cells instead of
    one — and it is a function of the frontier's content, so reversing the declaration order
    cannot change it."""
    corpus = tmp_path / "lessons"
    corpus.mkdir()
    _write_lesson(corpus, "aaa-any-compute-class", nodes=("type: compute, slot: class",))
    _write_lesson(corpus, "bbb-ip-only", nodes=("type: compute, class: ip-only, slot: class",))

    rows = (
        "v-001|compute|ip-only/??/??|host-1.corp|knowledge=partial",
        "v-004|compute|??/??/??|host-4.corp|knowledge=partial",
    )

    def block(order):
        doc = "```invlang\n:V prologue.vertices [id|type|class|ident|attrs?]\n"
        doc += "\n".join(order) + "\n```\n"
        return {h.name: h.matched for h in LF.match_lessons(frontier_from_text(doc), corpus)}

    placed = block(rows)
    assert placed["bbb-ip-only"].startswith("v-001"), "the `ip-only` lesson left its own cell"
    assert placed["aaa-any-compute-class"].startswith("v-004"), (
        "the loose lesson doubled up on the cell the specific one already covers, leaving the "
        "other open class unmentioned"
    )
    assert block(tuple(reversed(rows))) == placed, (
        "reversing the order the vertices are DECLARED in changed where the lessons landed — "
        "placement is reading the walk order rather than the frontier's content"
    )


def test_the_open_marker_in_a_selector_says_exactly_what_a_wildcard_says(tmp_path):
    """CLAIM: a class-pattern slot the author spelled `??` behaves identically to `*` — it
    never pins, never anchors, and never refuses.

    Two defects meet here, and the second is why "never refuses" is in the claim.

    It used to ANCHOR. `??` compares equal to an open case slot, so `??/internet/novel`
    against `??/??/??` anchored on slot 0 and collected slots 1 and 2 as pins — a full pinned
    triple for a selector agreeing with the document about nothing, where the honest
    `*/internet/novel` scores zero. That is the inversion this scoring exists to refuse,
    wearing the open marker. Harmless while every node selector scored 2; the new weights made
    it block-saturating.

    Refusing was the OTHER half, and it made the marker non-monotonic. A first fix credited
    nothing but still refused against a SETTLED case slot, so `??/internet/novel` matched
    `??/??/??` and returned `None` once a refinement settled slot 0 — the retrieval going dark
    on the write that made the document more specific, which is exactly what
    `test_recording_more_about_a_class_slot_never_loses_a_selector` forbids. A slot that says
    nothing cannot also constrain.

    Asserted as EQUIVALENCE to `*` over a refinement sequence rather than as three numbers,
    because that is the property: whatever the wildcard does, the marker does."""
    refinements = ("??/??/??", "bastion/??/??", "bastion/internet/??", "bastion/internet/novel")
    wildcard = [LF._class_pins("*/internet/novel", c, "compute") for c in refinements]

    assert [
        LF._class_pins("??/internet/novel", c, "compute") for c in refinements
    ] == wildcard, (
        "`??` does not say what `*` says — it is either crediting a pin it did not earn or "
        "refusing a match it cannot refuse"
    )
    # ...and the sequence it agrees with is itself monotonic, so the equivalence above is not
    # two functions being wrong together.
    assert None not in wildcard, f"the wildcard baseline stopped matching: {wildcard}"
    assert wildcard == sorted(wildcard), (
        f"the wildcard baseline is not monotonic: {wildcard}"
    )

    # ...and NARROWING the credit did not widen the MATCH: a concrete selector slot still
    # refuses a case slot settled to something else, which is the clause all of this sits on.
    assert LF._class_pins("bastion/internet", "ip-only/??/??", "compute") is None, (
        "a concrete slot stopped refusing a case slot that disagrees with it"
    )


def test_a_candidate_set_in_a_selector_is_a_disjunction_and_not_a_wildcard(tmp_path):
    """CLAIM: `{a, b}` written by a LESSON AUTHOR scopes the lesson to `a` or `b` — it earns
    no pin, but it refuses a cell settled outside it.

    The two unresolved spellings part company here, and reading them as one thing was wrong.
    In a DOCUMENT both mean "not settled" and the candidate set is the richer of the two, which
    is why `is_open_slot` answers for both and why neither may anchor. In a SELECTOR the author
    is stating a scope: `??` says nothing, and `{internal, dmz}` says "internal or dmz". Making
    both behave like `*` let a lesson about internal-or-dmz hosts match — and score a pin
    against — a `bastion` vertex.

    The refusal is not the non-monotonicity the sibling test forbids. Losing a selector the
    document CONTRADICTS is correct and already pinned by
    `test_a_settled_slot_still_refuses_a_selector_that_disagrees_with_it`; losing one the
    document merely REFINED is the bug. Inside the set the path stays monotonic, and it is
    strictly better than the pre-#935 code, which compared the whole `{...}` string to the cell
    and so refused even a member."""
    sel = "{internal, dmz}/internet"
    inside = [
        LF._class_pins(sel, c, "compute")
        for c in ("??/??/??", "{internal, dmz}/??/??", "internal/??/??", "dmz/internet/??")
    ]
    assert None not in inside, (
        f"refining a cell toward a value the selector NAMES lost the selector: {inside}"
    )
    assert inside == sorted(inside), f"the in-set refinement path is not monotonic: {inside}"

    assert LF._class_pins(sel, "bastion/internet/novel", "compute") is None, (
        "a lesson scoped to internal-or-dmz matched a bastion vertex — the candidate set is "
        "being read as a wildcard rather than as the disjunction the author wrote"
    )
    # ...and it still earns nothing where it matches: it names no single value, so there is
    # no equality for it to anchor on, exactly as the open marker has none.
    assert LF._class_pins(sel, "{internal, dmz}/??/??", "compute") == 0, (
        "a candidate set anchored on a cell carrying the same set and collected the rest"
    )
