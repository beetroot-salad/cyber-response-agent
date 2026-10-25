"""Lesson recall keyed on the document's frontier: open slots and contracts, selector matching and scoring, append_block/fix_row wiring, fail-open behavior."""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[3]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

pytest.importorskip("pydantic_ai")

from defender.records._artifact_schema import validate_investigation  # noqa: E402
from defender.skills.invlang.parser import parse_dense_companion  # noqa: E402
from defender.skills.invlang.validate import diagnose  # noqa: E402
from defender.tests.support.invlang.validation._invlang_warn_836 import (  # noqa: E402
    CONCLUDE_BENIGN,
    PROLOGUE,
    attr_block,
)


OPEN_CLASS_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-006|process|??|nc[pid=4242]|image=/usr/bin/nc
```
"""

#: The `:R attr_updates` row that CLOSES `v-006`'s class. The `:V` row above is immutable, so
#: the frontier's "post-attr_updates" clause is the only thing that can drop the slot.
CLOSE_CLASS_ROW = "l-001|v-006|class|nc"

OPEN_LOGINUID_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-004|process|nc|nc[pid=4242]|loginuid=??;image=/usr/bin/nc
```
"""

#: A `process` vertex with NOTHING open — the base the `fix_row` case opens a slot on from
#: inside the repair window.
CLOSED_PROCESS_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-006|process|nc|nc[pid=4242]|image=/usr/bin/nc
```
"""

OPEN_IDENT_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-005|identity|user/known-corp|??|
```
"""

OPEN_TRIPLE_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-003|compute|ip-only/??/??|10.42.7.183|knowledge=partial
```
"""

CANDIDATE_SET_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-007|compute|ip-only/{internal, dmz}/known-corp|10.42.7.9|knowledge=partial
```
"""

AUTHZ_DECL_BLOCK = """
```invlang
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-002|v-001|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?stolen-credential-reuse|v-001|runs_on|process|unclassified-process||null|active

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"jsmith permitted to authenticate to the bastion at this time"|escalate|escalate
```
"""

SECOND_CONTRACT_BLOCK = """
```invlang
:H l-001.new_hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-002|?unapproved-source|v-001|runs_on|process|unclassified-process||null|active

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac2|e-001|approved-source-list|"source host is on the approved list"|escalate|escalate
```
"""

#: Refutes `h-001`, so its contract stops being outstanding — the weight move the benign
#: authz gate reads when it walks LIVE hypotheses only.
REFUTE_H001_BLOCK = """
```invlang
:H h-001.preds [id|subject|claim]
p1|proposed_parent|"the authenticating source is undocumented"

:H h-001.refuts [id|refutes|claim]
r1|p1|"CMDB documents the source as an approved admin host"

:T resolutions
h-001  null → --    [l-001 r1 severe ⟂ e-001 :: the source is documented and approved]
```
"""

#: A contract on an UNOBSERVED edge — `edge_ref` is the parser's `proposed` sentinel, so there
#: is no `:E` row to read a `rel` or an `auth_kind` off.
PROPOSED_CONTRACT_BLOCK = """
```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-002|?undocumented-source-host|v-001|runs_on|process|unclassified-process||null|active

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac2|proposed|approved-source-list|"the source host is a documented admin workstation"|escalate|escalate
```
"""

HALF_WRITTEN_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-007|compute|??/??
"""

TRUNCATED_ROW_DOC = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-007|compute|??/??
```
"""

#: Ordinary prose. `append_block` takes it, and it moves no slot and no contract — the
#: negative half of case 6.
PROSE_BLOCK = "+ dispatching the cmdb lookup; nothing to record yet\n"

#: The alert signature of the case these documents belong to. It is never passed to
#: `match_lessons` — there is nowhere to pass it — and that is the point of case 2.
CASE_SIGNATURE = "v2-falco-suspicious-network-tool"


def authz_row(verdict: str) -> str:
    """One `:R authz` block resolving `ac1` with `verdict`, in the header order SKILL.md
    declares. `resolved_by` is `l-001`, the lead `PROLOGUE` already declares, so the row files
    onto a real lead rather than adding an undeclared-lead fault to the fixture."""
    return (
        "\n```invlang\n"
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        f"l-001|e-001|ac1|{verdict}|iam-policy|"
        '"documented in CMDB as an approved admin source"\n'
        "```\n"
    )


#: Every fixture document, by the name the failure message should name.
_FIXTURE_DOCS = {
    "open class": PROLOGUE + OPEN_CLASS_BLOCK,
    "closed class": PROLOGUE + OPEN_CLASS_BLOCK + attr_block(CLOSE_CLASS_ROW),
    "open loginuid": PROLOGUE + OPEN_LOGINUID_BLOCK,
    "open ident": PROLOGUE + OPEN_IDENT_BLOCK,
    "open triple": PROLOGUE + OPEN_TRIPLE_BLOCK,
    "candidate set": PROLOGUE + CANDIDATE_SET_BLOCK,
    "authz declared": PROLOGUE + AUTHZ_DECL_BLOCK,
    "authz authorized": PROLOGUE + AUTHZ_DECL_BLOCK + authz_row("authorized"),
    "authz unauthorized": PROLOGUE + AUTHZ_DECL_BLOCK + authz_row("unauthorized"),
    "proposed contract": PROLOGUE + PROPOSED_CONTRACT_BLOCK,
    "half written": PROLOGUE + HALF_WRITTEN_BLOCK,
}


# the frontier, read through the functions this spec mints

def _frontier(text: str):
    """`frontier_from_text(text)` — imported INSIDE the body, never at module scope, so this
    file still COLLECTS on a tree where `skills/invlang/frontier.py` does not exist. Red is
    the expected state of a spec; an uncollectable file is not."""
    from defender.skills.invlang.frontier import frontier_from_text

    return frontier_from_text(text)


def _slot_tuples(text: str) -> list[tuple[str, ...]]:
    return [
        (s.vertex_id, s.type, s.class_tuple, s.slot, s.value) for s in _frontier(text).slots
    ]


def _contract_tuples(text: str) -> list[tuple]:
    return [
        (c.contract_id, c.hypothesis_id, c.anchor_kind, c.edge_ref, c.rel, c.auth_kind)
        for c in _frontier(text).contracts
    ]


def _lessons_frontier():
    """The retrieval script as a module."""
    from defender.runtime.lessons_engine import lessons_frontier

    return lessons_frontier


# corpora

# `_write_lesson` and `_main_deps` live in `_lessons_corpus` so a second suite can use them
# without importing this COLLECTED module (which would load it twice in one session).
from defender.tests.support.learning.retrieval._lessons_corpus import _write_lesson  # noqa: E402
from defender.tests.support.learning.retrieval._lessons_corpus import _run_copy_main_deps  # noqa: E402


def _corpus(parent: Path, name: str = "lessons") -> Path:
    """A corpus directory. `name` is a parameter for exactly one test — the relocation seam
    refuses a directory whose LEAF NAME is not `lessons`, and that refusal needs a
    correctly-populated corpus under the wrong name to be about the name."""
    d = parent / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _names(hits) -> list[str]:
    return [h.name for h in hits]


def _exit_code(main, argv: list[str]) -> int:
    """`main`'s exit code, whether it RETURNS one or raises `SystemExit`."""
    try:
        return int(main(argv))
    except SystemExit as e:
        return int(e.code or 0)


# the fixtures themselves


# case 1 — an open slot is in the frontier until a refinement closes it

def test_an_open_class_slot_matches_until_a_refinement_closes_it(tmp_path):
    from defender.skills.invlang.frontier import derive_frontier

    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "process-class-open", nodes=("type: process, slot: class",))
    open_doc = _FIXTURE_DOCS["open class"]
    closed_doc = _FIXTURE_DOCS["closed class"]
    match_lessons = _lessons_frontier().match_lessons

    assert _slot_tuples(open_doc) == [("v-006", "process", "??", "class", "??")]
    assert _names(match_lessons(_frontier(open_doc), corpus)) == ["process-class-open"]

    assert _frontier(closed_doc).slots == (), (
        "a `:R attr_updates` row closed the slot and it is still on the OPEN half"
    )
    assert any(h.vertex_id == "v-006" and h.slot == "class"
               for h in _frontier(closed_doc).held), "the closed slot went nowhere"
    assert match_lessons(_frontier(closed_doc), corpus) == []

    # ...and `frontier_from_text` is parse-then-derive and nothing else, so a caller holding a
    # companion it already parsed gets the identical answer.
    body, _warnings = parse_dense_companion(open_doc)
    assert derive_frontier(body) == _frontier(open_doc)


# case 2 — the motivating miss, retrieved without the alert signature

def test_the_loginuid_lesson_is_retrieved_though_its_signature_does_not_match(tmp_path):
    """CLAIM: retrieval is signature-BLIND — the frontier is the whole key."""
    corpus = _corpus(tmp_path)
    wanted = _write_lesson(
        corpus, "loginuid-open-is-not-docker-exec",
        nodes=("type: process, slot: attrs.loginuid",),
        signature="v2-cross-tier-ssh-pivot",
    )
    _write_lesson(corpus, "signature-twin", signature=CASE_SIGNATURE)
    match_lessons = _lessons_frontier().match_lessons

    hits = match_lessons(_frontier(_FIXTURE_DOCS["open loginuid"]), corpus)

    assert _names(hits) == ["loginuid-open-is-not-docker-exec"]
    hit = hits[0]
    assert hit.path == wanted
    # The `description` reaches the model through the rendered frontmatter, which is the only
    # surface that carries it — `Hit` no longer keeps a second, unrendered copy.
    assert "loginuid-open-is-not-docker-exec description" in _lessons_frontier().render(hits)
    assert hit.frontmatter["source_signature"] == ["v2-cross-tier-ssh-pivot"], (
        "the retrieved lesson's signature is not the disjoint one the fixture wrote"
    )
    assert CASE_SIGNATURE not in hit.frontmatter["source_signature"]
    assert "attrs.loginuid" in hit.matched, (
        f"`matched` must name the frontier item that matched; got {hit.matched!r}"
    )
    # the API itself has nowhere to put a signature
    assert set(inspect.signature(match_lessons).parameters) == {"frontier", "corpus", "top_k"}

    # ...and the class cell comes back verbatim, so a `class:` selector has something to match
    # even when the OPEN slot is an attribute.
    assert _slot_tuples(_FIXTURE_DOCS["open loginuid"]) == [
        ("v-004", "process", "nc", "attrs.loginuid", "??")
    ]


# case 3 — `ident` is in the frontier and still not in the benign gate

def test_an_unresolved_ident_is_in_the_frontier_but_not_in_the_benign_gate(tmp_path):
    """CLAIM: `identifier` is an `OpenSlot` (`slot="ident"`), and `_check_benign_open_slots` is
    UNCHANGED by that."""
    from defender.skills.invlang.validate import _check_benign_open_slots

    doc = _FIXTURE_DOCS["open ident"]
    body, _warnings = parse_dense_companion(doc)

    assert _slot_tuples(doc) == [("v-005", "identity", "user/known-corp", "ident", "??")]

    assert _check_benign_open_slots(body) == [], (
        "the frontier work leaked into the benign disposition gate"
    )
    assert validate_investigation(doc + CONCLUDE_BENIGN, None) is None, (
        "an unresolved ident newly blocks a benign close — #836 N3 says it must not"
    )
    # ...and the control that the gate still WORKS: an open class on the same document blocks.
    blocked = PROLOGUE + OPEN_CLASS_BLOCK + CONCLUDE_BENIGN
    assert "benign blocked" in (validate_investigation(blocked, None) or "")


# case 4 — contracts

def test_a_contract_is_open_until_a_row_authorizes_it(tmp_path):
    declared = _FIXTURE_DOCS["authz declared"]

    assert _contract_tuples(declared) == [
        ("ac1", "h-001", "iam-policy", "e-001", "attempted_auth", "siem-event")
    ]

    assert _contract_tuples(_FIXTURE_DOCS["authz authorized"]) == [], (
        "an `authorized` :R authz row did not discharge the contract"
    )
    assert _contract_tuples(_FIXTURE_DOCS["authz unauthorized"]) == [
        ("ac1", "h-001", "iam-policy", "e-001", "attempted_auth", "siem-event")
    ], "a non-`authorized` verdict must leave the contract on the frontier"

    # the vertices are untouched by any of this — the contract half of the frontier is not
    # the slot half wearing a different name.
    assert _frontier(declared).slots == ()


def test_an_unobserved_contract_carries_no_edge_facts(tmp_path):
    """CLAIM: `edge_ref` is `proposed` when the contract attaches to no observed edge, and then
    `rel` and `auth_kind` are None rather than invented."""
    assert _contract_tuples(_FIXTURE_DOCS["proposed contract"]) == [
        ("ac2", "h-002", "approved-source-list", "proposed", None, None)
    ]


def test_an_edge_selector_matches_only_when_every_field_it_declares_is_equal(tmp_path):
    """CLAIM: an edge selector is a conjunction over the fields it DECLARES — an omitted field
    constrains nothing, a declared one must be equal."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "edge-both", edges=("rel: attempted_auth, anchor_kind: iam-policy",))
    _write_lesson(corpus, "edge-kind-only", edges=("anchor_kind: iam-policy",))
    _write_lesson(corpus, "edge-wrong-rel", edges=("rel: assumed_role, anchor_kind: iam-policy",))
    _write_lesson(corpus, "edge-wrong-kind", edges=("anchor_kind: change-mgmt",))
    match_lessons = _lessons_frontier().match_lessons

    hits = match_lessons(_frontier(_FIXTURE_DOCS["authz declared"]), corpus, top_k=10)

    assert _names(hits) == ["edge-both", "edge-kind-only"]
    assert [h.score for h in hits] == [4, 3]


# case 5 — ranking

def _ranking_corpus(tmp_path: Path) -> Path:
    """Five node selectors against `OPEN_TRIPLE_BLOCK` (`class=ip-only/??/??`)."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "zeta-ip-only-internet",
                  nodes=("type: compute, class: ip-only/internet, slot: class",))
    _write_lesson(corpus, "delta-ip-only", nodes=("type: compute, class: ip-only, slot: class",))
    for name in ("alpha-any-compute", "beta-any-compute", "gamma-any-compute"):
        _write_lesson(corpus, name, nodes=("type: compute, slot: class",))
    _write_lesson(corpus, "omega-bastion", nodes=("type: compute, class: bastion, slot: class",))
    _write_lesson(corpus, "sigma-ident", nodes=("type: compute, slot: ident",))
    return corpus


def test_specificity_outranks_generality_and_top_k_bounds_the_list(tmp_path):
    """CLAIM: score is the count of BOUND components — type, each non-`*` class slot, and the slot
    name — highest first, and `top_k` (default 3) is the cut."""
    corpus = _ranking_corpus(tmp_path)
    match_lessons = _lessons_frontier().match_lessons
    frontier = _frontier(_FIXTURE_DOCS["open triple"])

    everything = match_lessons(frontier, corpus, top_k=10)
    assert _names(everything) == [
        "zeta-ip-only-internet", "delta-ip-only",
        "alpha-any-compute", "beta-any-compute", "gamma-any-compute",
    ]
    assert [h.score for h in everything] == [4, 3, 2, 2, 2]

    top = match_lessons(frontier, corpus)
    assert _names(top) == ["zeta-ip-only-internet", "delta-ip-only", "alpha-any-compute"], (
        "the default top_k is 3, taken off the ranked head"
    )
    assert _names(match_lessons(frontier, corpus, top_k=1)) == ["zeta-ip-only-internet"]

    # the render carries the ranking the caller was handed, in that order
    rendered = _lessons_frontier().render(top)
    assert [rendered.index(name) for name in _names(top)] == sorted(
        rendered.index(name) for name in _names(top)
    ), f"render reordered the hits:\n{rendered}"


# case 6 — the recall rides on the append that moved it

def test_append_block_carries_the_lessons_only_when_the_append_moved_the_recall(tmp_path):
    """CLAIM: `_tool_append_block` derives the recall over the pre- and post-append document and
    appends the rendered section ONLY when the two differ.

    #1108 P4 (O2, O-TEXT): the recalled lesson is the RUN COPY's, shown by its model-view path
    `/agent/lessons/<name>.md`; a lesson left in the checkout's `lessons/` (a decoy matching the
    same open slot) is never recalled."""
    from defender.runtime.tools import _tool_append_block

    deps, run, agent, dfn = _run_copy_main_deps(tmp_path)
    corpus = _corpus(agent)
    _write_lesson(corpus, "process-class-open", nodes=("type: process, slot: class",))
    _write_lesson(_corpus(dfn), "checkout-decoy-class-open", nodes=("type: process, slot: class",))

    first = _tool_append_block(deps, PROLOGUE)
    assert "appended" in first
    assert "process-class-open" not in first, "a document with no open slot recalled a lesson"

    second = _tool_append_block(deps, OPEN_CLASS_BLOCK)
    assert second.startswith("appended "), "the byte-count lead is still the first thing said"
    assert "process-class-open" in second, (
        "the append that opened `class=??` did not carry the lesson it unlocked"
    )
    assert "/agent/lessons/process-class-open.md" in second, (
        "the pushed lesson is not named by the run copy's model-view path (O-TEXT)"
    )
    assert "checkout-decoy-class-open" not in second, (
        "the recall read the checkout's lessons corpus, not the run copy's (O2)"
    )

    third = _tool_append_block(deps, PROSE_BLOCK)
    assert "appended" in third
    assert "process-class-open" not in third, (
        "the section re-fired on an append that left the frontier exactly as it was"
    )

    assert (run / "investigation.md").read_text(encoding="utf-8") == (
        PROLOGUE + OPEN_CLASS_BLOCK + PROSE_BLOCK
    ), "the recall changed what landed on disk"


# case 7 — a half-written block is inert, not fatal

def test_a_malformed_block_yields_an_empty_frontier_rather_than_raising(tmp_path):
    """CLAIM: `frontier_from_text` never raises — a document it cannot read has an empty frontier."""
    for label, doc, intact in (
        ("unterminated fence", PROLOGUE + HALF_WRITTEN_BLOCK, PROLOGUE),
        ("short row", TRUNCATED_ROW_DOC, ""),
        ("not invlang at all", "```yaml\nfoo: ??\n```\n", ""),
        ("empty", "", ""),
    ):
        frontier = _frontier(doc)
        baseline = _frontier(intact)
        assert frontier.slots == baseline.slots, f"{label} invented an open slot"
        assert frontier.contracts == baseline.contracts, f"{label} invented a contract"
        assert frontier.held == baseline.held, f"{label} invented a held fact"
        assert frontier.slots == (), f"{label} put something on the open half"


def test_an_append_landing_a_half_written_block_still_leads_with_its_byte_count(tmp_path):
    """CLAIM: the recall never turns a write that LANDED into a failed tool call."""
    from defender.runtime.tools import _tool_append_block

    deps, run, agent, _dfn = _run_copy_main_deps(tmp_path)
    _write_lesson(_corpus(agent), "process-class-open", nodes=("type: process, slot: class",))
    _tool_append_block(deps, PROLOGUE)

    result = _tool_append_block(deps, HALF_WRITTEN_BLOCK)

    assert result.startswith("appended "), result
    assert f"appended {len(HALF_WRITTEN_BLOCK.encode('utf-8'))} bytes" in result
    assert (run / "investigation.md").read_text(encoding="utf-8").endswith(HALF_WRITTEN_BLOCK)


# case 8 — `--corpus` is a relocation seam, not a corpus selector

def test_the_relocated_corpus_must_still_be_named_lessons(tmp_path, capsys):
    """CLAIM: `--corpus` accepts a RELOCATED `lessons` directory and refuses anything else, exiting
    2."""
    main = _lessons_frontier().main
    investigation = tmp_path / "investigation.md"
    investigation.write_text(_FIXTURE_DOCS["open class"], encoding="utf-8")

    right = _corpus(tmp_path / "relocated", "lessons")
    _write_lesson(right, "process-class-open", nodes=("type: process, slot: class",))
    wrong = _corpus(tmp_path / "relocated", "lessons-environment")
    _write_lesson(wrong, "process-class-open", nodes=("type: process, slot: class",))

    argv = ["lessons_frontier.py", "--investigation", str(investigation), "--corpus"]
    assert _exit_code(main, [*argv, str(right)]) == 0
    assert "process-class-open" in capsys.readouterr().out

    assert _exit_code(main, [*argv, str(wrong)]) == 2, (
        "a corpus whose leaf name is not `lessons` was accepted"
    )
    assert "process-class-open" not in capsys.readouterr().out


def test_an_open_case_slot_matches_a_concrete_selector_and_a_settled_one_does_not(tmp_path):
    corpus = _corpus(tmp_path)
    # Slot 0 concrete (`ip-only`), slots 1 and 2 open.
    _write_lesson(corpus, "hits-through-the-open-slot",
                  nodes=("type: compute, class: ip-only/internal, slot: class",))
    # Same vertex, same slot — but slot 0 disagrees, and slot 0 is SETTLED.
    _write_lesson(corpus, "misses-on-the-settled-slot",
                  nodes=("type: compute, class: bastion, slot: class",))
    match_lessons = _lessons_frontier().match_lessons

    hits = _names(match_lessons(_frontier(_FIXTURE_DOCS["open triple"]), corpus))
    assert hits == ["hits-through-the-open-slot"], (
        "`ip-only/internal` can only reach `ip-only/??/??` through the open slot 1, and "
        "`bastion` must still be refused by the concrete slot 0"
    )

    # ...and against a wholly open cell, a fully concrete selector matches too — the same
    # clause, with nothing else in the tuple that could carry the match.
    _write_lesson(corpus, "concrete-against-a-bare-marker",
                  nodes=("type: process, class: nc, slot: class",))
    bare = _names(match_lessons(_frontier(_FIXTURE_DOCS["open class"]), corpus))
    assert bare == ["concrete-against-a-bare-marker"]


def test_ties_break_by_lesson_name_rather_than_by_filename(tmp_path):
    """CLAIM: equal scores order by the lesson's `name`."""
    corpus = _corpus(tmp_path)
    sel = ("type: compute, slot: class",)
    _write_lesson(corpus, "aaa-first", nodes=sel, filename="99-last.md")
    _write_lesson(corpus, "mmm-middle", nodes=sel, filename="50-middle.md")
    _write_lesson(corpus, "zzz-last", nodes=sel, filename="01-first.md")
    match_lessons = _lessons_frontier().match_lessons

    order = _names(match_lessons(_frontier(_FIXTURE_DOCS["open triple"]), corpus, top_k=3))
    assert order == ["aaa-first", "mmm-middle", "zzz-last"], (
        "equal scores are ordering by filename, not by the lesson name"
    )
    assert order == _names(
        match_lessons(_frontier(_FIXTURE_DOCS["open triple"]), corpus, top_k=3)
    ), "two identical calls disagreed — the order is not total"


def test_a_lesson_scores_its_best_selector_not_the_sum_of_them(tmp_path):
    """CLAIM: a lesson's score is its most specific MATCHING selector, not an accumulation."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "two-loose", nodes=(
        "type: compute, slot: class", "type: compute, slot: ident",
    ))
    _write_lesson(corpus, "one-exact", nodes=("type: compute, class: ip-only, slot: class",))

    hits = _lessons_frontier().match_lessons(_frontier(_FIXTURE_DOCS["open triple"]), corpus)
    assert _names(hits)[0] == "one-exact", (
        "a lesson with two loose selectors outranked one naming the class — scores are "
        "being summed instead of maximised"
    )
    assert hits[0].score > hits[1].score


def test_an_edge_selector_can_key_on_the_observational_authority(tmp_path):
    """CLAIM: `auth_kind` constrains an edge selector like the other two fields."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "right-authority",
                  edges=("auth_kind: siem-event, anchor_kind: iam-policy",))
    _write_lesson(corpus, "wrong-authority",
                  edges=("auth_kind: authoritative-source, anchor_kind: iam-policy",))

    hits = _lessons_frontier().match_lessons(
        _frontier(_FIXTURE_DOCS["authz declared"]), corpus)
    assert _names(hits) == ["right-authority"], (
        "an edge selector matched a contract whose observational authority differs"
    )
    assert hits[0].score == 4, (
        "both declared fields should count toward specificity — `ANCHOR_KIND_WEIGHT` plus "
        "`AUTH_KIND_WEIGHT`"
    )


def test_matched_names_the_frontier_item_rather_than_the_selector(tmp_path):
    """CLAIM: `Hit.matched` identifies WHICH open thing hit — the vertex and its value."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "loginuid", nodes=("type: process, slot: attrs.loginuid",))

    hit = _lessons_frontier().match_lessons(
        _frontier(_FIXTURE_DOCS["open loginuid"]), corpus)[0]
    assert "v-004" in hit.matched, "matched does not name the vertex that hit"
    assert "??" in hit.matched, "matched does not carry the unresolved value"


def test_the_recall_is_omitted_when_the_corpus_is_missing_or_malformed(tmp_path):
    """CLAIM: the recall never turns a landed write into a failed tool call."""
    from defender.runtime.tools import _tool_append_block

    deps, _run, agent, dfn = _run_copy_main_deps(tmp_path)
    opening = PROLOGUE + OPEN_LOGINUID_BLOCK

    # No corpus at all (in the run copy, nor in the checkout).
    assert not (agent / "lessons").exists()
    assert not (dfn / "lessons").exists()
    assert _tool_append_block(deps, opening).startswith("appended "), (
        "a missing lessons corpus turned a landed write into something other than an accept"
    )

    # A corpus whose lesson declares garbage where a selector sequence belongs.
    corpus = _corpus(agent)
    _write_lesson(corpus, "malformed", raw_nodes="not-a-list")
    out = _tool_append_block(deps, PROLOGUE + OPEN_CLASS_BLOCK)
    assert out.startswith("appended "), (
        "a malformed selector raised out of the recall instead of failing open"
    )


def test_render_of_nothing_is_empty_and_the_cli_honours_top_k(tmp_path):
    """CLAIM: the two surfaces the contract pins but nothing exercised."""
    lf = _lessons_frontier()
    assert lf.render([]) == "", "render([]) is not empty — the injection gate keys on this"

    corpus = _corpus(tmp_path)
    sel = ("type: compute, slot: class",)
    _write_lesson(corpus, "alpha", nodes=sel)
    _write_lesson(corpus, "beta", nodes=sel)
    doc = tmp_path / "investigation.md"
    doc.write_text(_FIXTURE_DOCS["open triple"], encoding="utf-8")

    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = _exit_code(lf.main, ["prog", "--investigation", str(doc),
                                  "--corpus", str(corpus), "--top-k", "1"])
    out = buf.getvalue()
    assert rc == 0
    assert "alpha" in out, "the higher-ranked lesson is missing from the output"
    assert "beta" not in out, "--top-k did not reach the retrieval"


def test_the_tool_pushes_only_the_lessons_that_matched(tmp_path):
    """CLAIM: `_tool_append_block` is wired to `match_lessons`, not to a directory listing."""
    from defender.runtime.tools import _tool_append_block

    deps, _run, agent, _dfn = _run_copy_main_deps(tmp_path)
    corpus = _corpus(agent)
    _write_lesson(corpus, "matches-the-open-loginuid",
                  nodes=("type: process, slot: attrs.loginuid",))
    _write_lesson(corpus, "decoy-matches-nothing",
                  nodes=("type: storage, slot: attrs.bucket",))

    _tool_append_block(deps, PROLOGUE)
    out = _tool_append_block(deps, OPEN_LOGINUID_BLOCK)

    assert "matches-the-open-loginuid" in out
    assert "decoy-matches-nothing" not in out, (
        "the tool emitted a lesson the frontier never matched — it is listing the corpus "
        "rather than retrieving from it"
    )


def test_the_cli_retrieves_against_the_investigation_it_is_handed(tmp_path):
    """CLAIM: `main` derives the frontier from `--investigation`."""
    lf = _lessons_frontier()
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "aaa-decoy-matches-nothing",
                  nodes=("type: storage, slot: attrs.bucket",))
    _write_lesson(corpus, "zzz-matches-the-open-triple",
                  nodes=("type: compute, slot: class",))
    doc = tmp_path / "investigation.md"
    doc.write_text(_FIXTURE_DOCS["open triple"], encoding="utf-8")

    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = _exit_code(lf.main, ["prog", "--investigation", str(doc),
                                  "--corpus", str(corpus)])
    out = buf.getvalue()
    assert rc == 0
    assert "zzz-matches-the-open-triple" in out
    assert "aaa-decoy-matches-nothing" not in out, (
        "the CLI printed a lesson the investigation's frontier never matched"
    )
    # ...and the block carries the lesson's own account of itself, not just a path.
    assert "description" in out, "render dropped the frontmatter it is supposed to carry"


def test_a_row_discharges_only_the_contract_it_names(tmp_path):
    """CLAIM: discharge joins on `fulfills_contract`."""
    doc = (
        PROLOGUE + AUTHZ_DECL_BLOCK + SECOND_CONTRACT_BLOCK + authz_row("authorized")
    )
    open_ids = [c.contract_id for c in _frontier(doc).contracts]
    assert open_ids == ["ac2"], (
        "an `authorized` row naming ac1 discharged a contract it does not name"
    )


def test_a_refinement_closes_an_ident_or_an_attribute_too(tmp_path):
    """CLAIM: the `:R attr_updates` fold honours all three legal keys."""
    closed_attr = (
        PROLOGUE + OPEN_LOGINUID_BLOCK + attr_block("l-001|v-004|attrs.loginuid|1000")
    )
    closed_ident = PROLOGUE + OPEN_IDENT_BLOCK + attr_block("l-001|v-005|ident|svc.monitoring")

    assert _frontier(closed_attr).slots == (), "an `attrs.` refinement did not close the slot"
    assert _frontier(closed_ident).slots == (), "an `ident` refinement did not close the slot"
    assert any(h.slot == "attrs.loginuid" and h.value == "1000"
               for h in _frontier(closed_attr).held), "the resolved value is not held"
    assert any(h.slot == "ident" and h.value == "svc.monitoring"
               for h in _frontier(closed_ident).held), "the resolved identifier is not held"


def test_a_contract_on_a_refuted_hypothesis_is_not_on_the_frontier(tmp_path):
    """CLAIM: only LIVE hypotheses carry outstanding contracts."""
    refuted = PROLOGUE + AUTHZ_DECL_BLOCK + REFUTE_H001_BLOCK
    assert _frontier(PROLOGUE + AUTHZ_DECL_BLOCK).contracts, "positive control"
    assert _frontier(refuted).contracts == (), (
        "a contract on a refuted hypothesis is still being reported as open"
    )


# review follow-ups (#930): the two ways the shipped mechanism missed its own case

def test_a_class_slot_matched_only_through_the_inversion_pins_nothing(tmp_path):
    """CLAIM: specificity scores the MATCH, not the selector — a class component that landed on an
    open case slot discriminated nothing and earns nothing."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "aaa-wholly-open-class",
                  nodes=("type: process, class: nginx, slot: class",))
    _write_lesson(corpus, "zzz-names-the-open-attribute",
                  nodes=("type: process, slot: attrs.loginuid",))
    match_lessons = _lessons_frontier().match_lessons

    open_class = PROLOGUE + """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-008|process|??|nc[pid=4242]|loginuid=??
```
"""
    hits = {h.name: h.score for h in match_lessons(_frontier(open_class), corpus, top_k=9)}
    assert hits["aaa-wholly-open-class"] == 2, (
        "`nginx` matched a `??` — it pinned nothing and must not outscore the attribute"
    )
    assert hits["zzz-names-the-open-attribute"] == 3, (
        "naming an `attrs.<name>` slot is a claim about what the document HOLDS, where "
        "`class` and `ident` are cells every vertex carries — `ATTR_SLOT_WEIGHT` (#935)"
    )
    assert hits["aaa-wholly-open-class"] < hits["zzz-names-the-open-attribute"], (
        "a class literal the document never mentions outranked the exact open slot"
    )

    assert _names(match_lessons(_frontier(open_class), corpus, top_k=1)) == [
        "zzz-names-the-open-attribute"
    ], "the exact open slot must lead the block, not lose a coin-flip to `aaa`"


def test_the_frontier_and_the_benign_gate_agree_on_a_shared_contract_id(tmp_path):
    """CLAIM: `_open_contracts` calls `validate.outstanding_authz_contracts` rather than restating
    "discharged", so the two cannot disagree."""
    from defender.skills.invlang.validate import _check_benign_authz

    shared = (
        PROLOGUE
        + AUTHZ_DECL_BLOCK  # h-001 declares ac1, anchor iam-policy
        + """
```invlang
:H l-001.new_hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-002|?unapproved-source|v-001|runs_on|process|unclassified-process||null|active

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|approved-source-list|"source host is on the approved list"|escalate|escalate
```
"""
        + REFUTE_H001_BLOCK  # ...and h-001 is refuted, which makes the shared id legal
        + authz_row("authorized")  # an `iam-policy` row for `ac1`
    )
    assert diagnose(shared, None) == [], "the fixture must be a document the gate accepts"
    body, _w = parse_dense_companion(shared)

    assert _check_benign_authz(body), "positive control: the gate is blocked on h-002's ac1"
    assert [c.contract_id for c in _frontier(shared).contracts] == ["ac1"], (
        "the frontier discharged a contract the disposition gate is still blocking on"
    )


def test_fix_row_carries_the_recall_because_it_moves_the_frontier_too(tmp_path):
    """CLAIM: the repair verb pushes lessons on the same terms `append_block` does."""
    from defender.runtime.tools import _tool_append_block, _tool_fix_row

    deps, run, agent, _dfn = _run_copy_main_deps(tmp_path)
    corpus = _corpus(agent)
    _write_lesson(corpus, "tty-open", nodes=("type: process, slot: attrs.tty",))

    near_miss = "l-001|v-006|clas|nc"
    landed = _tool_append_block(
        deps, PROLOGUE + CLOSED_PROCESS_BLOCK + attr_block(near_miss)
    )
    assert "FLAGGED" in landed, "the fixture row must open the repair window"
    assert "tty-open" not in landed, "nothing was open yet"

    repaired = _tool_fix_row(deps, near_miss, "l-001|v-006|attrs.tty|??")

    assert "tty-open" in repaired, (
        "the repair opened `attrs.tty=??` and the repair verb said nothing about it"
    )
    assert repaired.startswith("repaired "), "the repair's own lead is still the first thing said"


def test_the_block_hands_main_a_path_its_own_gate_will_read(tmp_path):
    from defender.runtime.tools import _tool_append_block, _tool_read_file
    from defender.tests.support.runtime.state._1255_view import MODEL_AGENT

    deps, run, agent, _dfn = _run_copy_main_deps(tmp_path)
    corpus = _corpus(agent)
    _write_lesson(corpus, "readable-from-the-block", nodes=("type: process, slot: class",))
    lf = _lessons_frontier()

    hits = lf.match_lessons(_frontier(_FIXTURE_DOCS["open class"]), corpus)
    _tool_append_block(deps, PROLOGUE)
    rendered = _tool_append_block(deps, OPEN_CLASS_BLOCK)

    assert hits, "positive control: the fixture should match the lesson"
    assert "readable-from-the-block" in rendered, (
        f"positive control: the write pushed the lesson:\n{rendered}")
    assert f"matched {hits[0].matched}" in rendered, (
        f"the block dropped its account of WHY the lesson was pushed:\n{rendered}"
    )
    # The first hit row (#1206 frames the hits, so it follows the frame's opening line; the write
    # return's own text comes before the block, so the row is found by its `matched` account).
    first = next(ln for ln in rendered.splitlines()
                 if ln.startswith("- ") and " — matched " in ln)
    quoted = first.removeprefix("- ").split(" — matched ")[0]
    # #1108 P4 (O2, O-TEXT): the lesson lives in the run copy, the model's `/agent` tree.
    assert quoted == f"{MODEL_AGENT}/lessons/readable-from-the-block.md", (
        f"the block quotes {quoted!r}, not the lesson's model path under {MODEL_AGENT}")
    body = _tool_read_file(deps, quoted)  # ModelRetry here IS the failure
    assert "lesson body" in body, f"the path the block quoted ({quoted!r}) did not read back"


def test_a_pushed_lesson_is_recorded_the_way_a_read_one_is(tmp_path):
    """CLAIM: the recall lane writes `lessons_loaded.jsonl`, like `_gated_read` does — #1108 P4
    O5: for a lesson pushed from the RUN COPY's `lessons/` too."""
    import json

    from defender.runtime.tools import _tool_append_block

    deps, run, agent, _dfn = _run_copy_main_deps(tmp_path)
    corpus = _corpus(agent)
    _write_lesson(corpus, "recorded-on-push", nodes=("type: process, slot: class",))

    _tool_append_block(deps, PROLOGUE)
    pushed = _tool_append_block(deps, OPEN_CLASS_BLOCK)

    assert "recorded-on-push" in pushed, "positive control: the lesson was pushed"
    rows = [
        json.loads(line)
        for line in (run / "lessons_loaded.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [r["lesson_name"] for r in rows] == ["recorded-on-push"], (
        f"the push left no trace row: {rows}"
    )


#: A `process` whose class and attributes are all SETTLED. Nothing here is open, so the whole
#: document is invisible to `frontier_nodes` and visible only to `observed_nodes`.
SETTLED_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-008|identity|user/anonymous|root|uid=0;loginuid=-1
```
"""


def test_a_settled_value_is_a_held_fact_and_not_an_open_slot(tmp_path):
    """CLAIM: the two node halves are complements — a cell is open XOR held, never both."""
    doc = PROLOGUE + SETTLED_BLOCK
    f = _frontier(doc)
    assert f.slots == (), "a fully settled vertex put something on the OPEN half"
    held = {(h.vertex_id, h.slot, h.value) for h in f.held}
    assert ("v-008", "attrs.loginuid", "-1") in held
    assert ("v-008", "ident", "root") in held
    assert ("v-008", "class", "user/anonymous") in held
    assert not f.is_empty(), "a document with held facts and no open slot reported empty"

    for label, fixture in (
        ("class", _FIXTURE_DOCS["open class"]),
        ("attrs", _FIXTURE_DOCS["open loginuid"]),
        ("ident", _FIXTURE_DOCS["open ident"]),
    ):
        of = _frontier(fixture)
        assert of.slots, f"{label}: positive control — nothing was open"
        open_cells = {(s.vertex_id, s.slot) for s in of.slots}
        held_cells = {(h.vertex_id, h.slot) for h in of.held}
        assert not (open_cells & held_cells), (
            f"{label}: a cell is on BOTH halves {open_cells & held_cells} — an open slot "
            "counted as a held fact would make every lesson match every document"
        )


def test_observed_nodes_retrieves_on_a_value_the_document_settled(tmp_path):
    """CLAIM: `observed_nodes` fires on a concrete value, and `frontier_nodes` does not."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "licenses-a-known-loginuid",
                  observed=("type: identity, slot: attrs.loginuid",))
    _write_lesson(corpus, "closes-an-open-loginuid",
                  nodes=("type: identity, slot: attrs.loginuid",))
    doc = PROLOGUE + SETTLED_BLOCK

    hits = _names(_lessons_frontier().match_lessons(_frontier(doc), corpus))
    assert hits == ["licenses-a-known-loginuid"], (
        "the settled value reached the wrong lane — `observed_nodes` must match a concrete "
        "cell and `frontier_nodes` must not"
    )
