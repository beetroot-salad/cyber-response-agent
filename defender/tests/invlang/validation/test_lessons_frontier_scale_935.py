"""Frontier lesson retrieval: node and edge lanes score on one scale, class match is arity-aware, ordering is what the model is handed."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[3]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

from defender.runtime.lessons_engine import lessons_frontier as LF  # noqa: E402
from defender.skills.invlang.frontier import frontier_from_text  # noqa: E402
from defender.skills.invlang.parser import scan_fences  # noqa: E402
from defender.skills.invlang.validate import diagnose  # noqa: E402
from defender.tests.support.learning.retrieval._lessons_corpus import _write_lesson  # noqa: E402

from defender.tests.support.shared._pre_p4_shipped import LESSONS as SHIPPED_LESSONS  # noqa: E402

#: The corpus these cases rank against: the lessons this repo shipped before #1108 P4 moved
#: lessons to each tenant (O1, O-U5), byte for byte — the retrieval engine is the subject, and
#: its motivating lesson and the run reproductions below are pinned against that real corpus.
CORPUS = SHIPPED_LESSONS

TWO_VERTEX_DOC = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/??/??|??|knowledge=partial
v-002|identity|user/known-corp|jsmith|uid=1000;loginuid=-1
```
"""

#: The lesson the whole lane exists to reach, and the one every defect cut.
LOGINUID_LESSON = "falco-loginuid-tty-non-interactive-not-docker-exec"

REPLAYED_RUNS = (
    ("golden-sshpivot-ab3", DEFENDER / "tests" / "fixtures" / "e2e" / "golden-sshpivot-ab3" / "investigation.md"),
    ("turnN-A", DEFENDER / "tests" / "fixtures" / "invlang" / "turnN-A.investigation.md"),
)


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
    """Build each append-stage document to exercise lesson retrieval over its evolution."""
    frontiers = [frontier_from_text("")]
    document = ""
    for body in scan_fences(text).bodies:
        document += f"```invlang\n{body}\n```\n\n"
        frontiers.append(frontier_from_text(document))
    return frontiers


# the missing table


# defect 3 — the class match is monotonic in what the document records

def test_recording_more_about_a_class_slot_never_loses_a_selector():
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

    over_long = [
        LF._class_pins("bash/child", case, "process")
        for case in ("??", "{bash, sh}", "bash")
    ]
    assert over_long == [None, None, None], (
        f"a mis-authored over-long selector matched while the cell was open and stopped "
        f"matching once it settled: {over_long}"
    )


def test_a_settled_slot_still_refuses_a_selector_that_disagrees_with_it():
    for case in ("ip-only/??", "ip-only/??/??"):
        assert LF._class_pins("bastion/internal/novel", case, "compute") is None, (
            f"a concrete slot 0 stopped refusing a selector that disagrees with it ({case})"
        )


def test_a_cell_declaring_more_slots_than_its_type_is_widened_not_truncated():
    assert LF._class_pins("bash/child", "bash/child", "process") == 2
    assert LF._class_pins("bash/other", "bash/child", "process") is None, (
        "a slot past the type's arity stopped constraining — the cell was truncated"
    )


# defect 1 — the node lane can tell a named attribute from a universal cell

def test_the_filed_reproduction_reaches_the_loginuid_lesson_at_the_real_cut():
    assert diagnose(TWO_VERTEX_DOC, None) == [], "the reproduction is no longer a clean document"

    hits = _match(TWO_VERTEX_DOC)
    top = _names(hits)
    assert LOGINUID_LESSON in top, (
        f"#919's motivating lesson is still cut from its own reproduction; got {top}"
    )

    by_name = {h.name: h.score for h in _match(TWO_VERTEX_DOC, top_k=99)}
    cut_it = ["container-id-anchor-before-uid-lookup", "container-identity-gap-not-terminal"]
    for loser in cut_it:
        assert by_name[loser] < by_name[LOGINUID_LESSON], (
            f"{loser} keys on a bare `slot: ident` and still scores at or above the lesson "
            f"naming the exact attribute the document holds"
        )


def test_a_named_attribute_outscores_a_cell_every_vertex_carries():
    universal = LF._NodeSelector(type="identity", class_pattern="*", slot="ident")
    named = LF._NodeSelector(type="identity", class_pattern="*", slot="attrs.loginuid")

    assert named.fixed_specificity > universal.fixed_specificity, (
        "a selector naming an attribute scored no better than one naming a universal cell"
    )
    assert LF._NodeSelector(type="identity", class_pattern="*", slot="class").fixed_specificity == (
        universal.fixed_specificity
    ), "`class` and `ident` are both universal cells and must weigh the same"


# defect 2 — the edge lane can be heard

def test_the_edge_lane_is_not_floored_below_the_node_lane():
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
    assert path.is_file(), f"{label}'s document is tracked and must be present ({path})"
    text = path.read_text(encoding="utf-8")
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


# the selection — what a reweight alone cannot do

def test_two_lessons_about_one_open_thing_do_not_take_the_whole_block(tmp_path):
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


# the whole thing, against the real corpus and the real runs

@pytest.mark.parametrize(("label", "path"), REPLAYED_RUNS)
def test_no_replayed_block_leaves_an_open_thing_unrepresented(label, path):
    assert path.is_file(), f"{label}'s document is tracked and must be present ({path})"
    text = path.read_text(encoding="utf-8")
    for n, frontier in enumerate(_prefixes(text)):
        ranked = LF.match_lessons(frontier, CORPUS, top_k=99)
        emitted = [h.matched for h in ranked[:LF.DEFAULT_TOP_K]]
        available = {h.matched for h in ranked}
        assert len(set(emitted)) == min(LF.DEFAULT_TOP_K, len(available)), (
            f"{label} fence {n} doubled up while an open thing went unmentioned: "
            f"{emitted} out of {sorted(available)}"
        )


def test_the_loginuid_lesson_survives_every_fence_of_its_own_run():
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


# the gate the spread sits in front of

#: One `compute` vertex with an open class triple and an open ident, and the ordinary append
#: that declares a second. The pair is the churn shape the gate below exists for — see the test.


def test_a_lesson_tied_across_two_cells_is_placed_on_the_one_nothing_else_covers(tmp_path):
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
