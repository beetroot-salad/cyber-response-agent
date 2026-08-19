"""#919 — lesson recall is keyed on the FRONTIER, and re-fires whenever the document moves.

The measured failure: retrieval fires once, at PLAN time, keyed on the alert signature — before
`investigation.md` exists. So the run that opened `attrs.loginuid=??` on a `process` vertex in
loop 2 never saw the lesson about non-interactive loginuid, because that lesson's
`source_signature` names a different rule and the one retrieval that ever ran had already
happened. A retrieval keyed on what the alert SAYS cannot answer a question the investigation
only raised later.

What ships:

  * `skills/invlang/frontier.py` — `derive_frontier(body)` / `frontier_from_text(text)`, the
    document's still-unresolved surface: `OpenSlot` per open `class` / `ident` / `attrs.<name>`
    (post-`:R attr_updates`, so a refinement that closed a slot removes it), and `OpenContract`
    per `:H h-NNN.authz` contract no `:R authz` row has authorized.
  * `scripts/lessons/lessons_frontier.py` — `match_lessons` over the two new OPTIONAL lesson
    frontmatter keys (`frontier_nodes`, `frontier_edges`), ranked by SPECIFICITY, `top_k` 3.
  * `_tool_append_block` derives the recall over the pre- and post-append document and appends
    a rendered lessons section only when the two differ.

The load-bearing inversion is in the class match: a selector slot matches when it is `*`, when
it EQUALS the case slot, or when the CASE slot is unresolved. An open slot is a HIT, not a
miss — the ordinary `_class_match` reading (`lessons_env_retrieve.py`) is exactly backwards for
a retrieval whose whole subject is what is not known yet.

Deliberately out of scope: the PLAN-time signature retrieval is not removed here (the two
coexist; this file asserts only that the frontier lane is signature-blind), no lesson in the
checked-in corpus is re-authored, and nothing about WHERE the model is told to put the
rendered section — only that the string comes back on the append that moved the frontier.

The benign-disposition gate is the thing this must not disturb, and #836 already pinned the
difference: `ident` is excluded there and INCLUDED here. That asymmetry is asserted in one
test, from both sides, so the frontier work cannot leak into the gate.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[1]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

pytest.importorskip("pydantic_ai")

from defender._artifact_schema import validate_investigation  # noqa: E402
from defender.skills.invlang.parser import parse_dense_companion  # noqa: E402
from defender.skills.invlang.validate import diagnose  # noqa: E402
from defender.tests._invlang_warn_836 import (  # noqa: E402
    CONCLUDE_BENIGN,
    PROLOGUE,
    attr_block,
)

# --------------------------------------------------------------------------- #
# documents
#
# Every fixture below was EXECUTED against the real `diagnose` while this file was written and
# carries ZERO diagnostics — `test_the_fixture_documents_carry_no_invlang_fault` re-asserts it
# on every run. That is not decoration: an empty frontier is the expected answer for a
# malformed document (case 7), so a fixture that quietly failed to parse would let a
# do-nothing implementation pass half this file.
#
# `PROLOGUE` (two vertices, one lead, nothing open) is the base every document extends, so
# each fixture carries exactly the ONE open thing under test and no other — the fixture-hygiene
# rule `_invlang_warn_836` states.
# --------------------------------------------------------------------------- #

#: A `process` vertex whose CLASS cell is the bare open marker. `process` class is a single
#: token (SKILL.md §Classification grammar), so `??` is the whole cell — which makes the
#: `OpenSlot.value` unambiguous where a `compute` triple would leave "the unresolved value"
#: readable two ways.
OPEN_CLASS_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-006|process|??|nc[pid=4242]|image=/usr/bin/nc
```
"""

#: The `:R attr_updates` row that CLOSES `v-006`'s class. The `:V` row above is immutable, so
#: the frontier's "post-attr_updates" clause is the only thing that can drop the slot.
CLOSE_CLASS_ROW = "l-001|v-006|class|nc"

#: The motivating miss, verbatim in shape: a `process` vertex whose class is settled and whose
#: `attrs.loginuid` is not. Two attributes, one open and one concrete, so a match on this
#: vertex has to be a match on the SLOT rather than on the vertex.
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

#: An `identity` vertex whose IDENT cell is open and whose class and attributes are not. The
#: whole of case 3 rests on this document reading as open to the frontier and as CLEAN to
#: `_check_benign_open_slots`.
OPEN_IDENT_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-005|identity|user/known-corp|??|
```
"""

#: A `compute` vertex with a PARTIALLY open class triple: slot 0 concrete, slots 1 and 2 open.
#: The ranking fixture, and the one that can tell the inversion from "everything matches" — a
#: selector naming `bastion` must still miss on slot 0.
OPEN_TRIPLE_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-003|compute|ip-only/??/??|10.42.7.183|knowledge=partial
```
"""

#: The `{a, b}` half of the three-state progression `??` -> `{a, b}` -> concrete. Slot 0 is
#: concrete, slot 1 is an ENUMERATED CANDIDATE SET. `is_unresolved` reads both markers, and
#: without a fixture carrying this one an implementation that only ever tests `== "??"` is
#: indistinguishable from a correct one.
CANDIDATE_SET_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-007|compute|ip-only/{internal, dmz}/known-corp|10.42.7.9|knowledge=partial
```
"""

#: One observed edge, one live hypothesis, and one authz contract attached to that edge. The
#: hypothesis is LIVE (`weight null`, no refuting `:T resolutions`) so the frontier and the
#: benign gate are looking at the same contract rather than at two different questions.
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

#: A SECOND live hypothesis carrying its own contract `ac2` on the same edge. Without a
#: second contract, "any authorized row clears everything" and a real join on
#: `fulfills_contract` are the same observable.
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

#: A model that stopped mid-block: the fence never closes. EXECUTED — the tokenizer sees no
#: block at all, so it draws zero diagnostics and the write gate ACCEPTS it, which is what
#: makes it the shape case 7's tool half needs. It carries a literal `??` so a regex-shaped
#: implementation that never parses would produce a slot here.
HALF_WRITTEN_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-007|compute|??/??
"""

#: The other half-written shape: the fence CLOSES but the row is three cells against a header
#: requiring four, so the parser drops the row. EXECUTED — this one is an error-severity parse
#: diagnostic and the write gate refuses it, so it exercises the derivation only.
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


# --------------------------------------------------------------------------- #
# the frontier, read through the functions this spec mints
# --------------------------------------------------------------------------- #

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
    """The retrieval script as a module. Imported rather than path-loaded: it is a real
    module under `defender.scripts.lessons`, the way `lessons_env_retrieve` is, and nothing
    here rebinds a module constant (the `--corpus` seam is what a fixture corpus goes
    through)."""
    from defender.scripts.lessons import lessons_frontier

    return lessons_frontier


# --------------------------------------------------------------------------- #
# corpora
# --------------------------------------------------------------------------- #

def _write_lesson(
    corpus: Path,
    name: str,
    *,
    nodes: tuple[str, ...] = (),
    edges: tuple[str, ...] = (),
    observed: tuple[str, ...] = (),
    signature: str = "v2-cross-tier-ssh-pivot",
    filename: str | None = None,
    raw_nodes: str | None = None,
) -> Path:
    """One lesson file. `nodes` / `edges` are YAML FLOW mappings written exactly as the
    design spells them (`type: process, slot: attrs.loginuid`), so the fixture and the doc
    cannot drift on spelling."""
    lines = [
        f"name: {name}",
        f"description: {name} description",
        f"source_signature: [{signature}]",
    ]
    if observed:
        lines.append("observed_nodes:")
        lines += [f"  - {{{sel}}}" for sel in observed]
    if raw_nodes is not None:
        lines.append(f"frontier_nodes: {raw_nodes}")
    elif nodes:
        lines.append("frontier_nodes:")
        lines += [f"  - {{{sel}}}" for sel in nodes]
    if edges:
        lines.append("frontier_edges:")
        lines += [f"  - {{{sel}}}" for sel in edges]
    path = corpus / (filename or f"{name}.md")
    path.write_text("---\n" + "\n".join(lines) + "\n---\n\nlesson body\n", encoding="utf-8")
    return path


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
    """`main`'s exit code, whether it RETURNS one or raises `SystemExit`.

    `_lessons_common.resolve_corpus` refuses through `ap.error`, which raises
    `SystemExit(2)`; the pinned signature here is `main(argv) -> int`. Both spellings are the
    same observable, so this test asserts the observable rather than the spelling."""
    try:
        return int(main(argv))
    except SystemExit as e:
        return int(e.code or 0)


def _main_deps(tmp_path: Path):
    """MAIN deps through the real `bind` seam — real compiled policy, real gate.

    `test_append_only_write_lane_810.py::_main_deps` verbatim, plus the defender tree in the
    return: the corpus `_tool_append_block` recalls against is `deps`-resolved
    (`defender_dir/lessons`, MAIN's own `corpus_dirs` entry), so a hermetic test needs the
    tmp tree the `bind` call was given."""
    from defender.agents import MAIN_DEF
    from defender.runtime.agent_definition import bind

    run = tmp_path / "run"
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    return bind(MAIN_DEF, run, defender_dir=dfn), run, dfn


# --------------------------------------------------------------------------- #
# the fixtures themselves
# --------------------------------------------------------------------------- #

def test_the_fixture_documents_carry_no_invlang_fault():
    """Guards every document below. An empty frontier is the CORRECT answer for a malformed
    document, so a fixture that silently stopped parsing — a header typo, a cell miscount —
    would make the negative halves of cases 1, 4, 6 and 7 pass against an implementation that
    derives nothing at all. Each document is asserted diagnostic-clean here, once, so the
    other tests can read their emptiness as a claim about the frontier."""
    for label, doc in _FIXTURE_DOCS.items():
        assert diagnose(doc, None) == [], f"{label} fixture is not clean"

    # ...and the two deliberately-broken ones are broken in the way case 7 needs: the
    # unterminated fence is INVISIBLE to the parser (accepted), the short row is a parse error.
    assert diagnose(PROLOGUE + HALF_WRITTEN_BLOCK, None) == []
    assert [d.severity for d in diagnose(TRUNCATED_ROW_DOC, None)] == ["error"]


# --------------------------------------------------------------------------- #
# case 1 — an open slot is in the frontier until a refinement closes it
# --------------------------------------------------------------------------- #

def test_an_open_class_slot_matches_until_a_refinement_closes_it(tmp_path):
    """CLAIM: the frontier is the document's state AFTER `:R attr_updates`, so the same
    vertex retrieves a lesson while its class is `??` and retrieves nothing once a refinement
    row settles it.

    The negative half is what makes this discriminating. `:V` rows are immutable and
    append-only, so the `??` is still on disk after the refinement lands — an implementation
    that read the DECLARED rows (or grepped the text) would keep matching forever and re-fire
    the same lesson on every subsequent append, which is the failure mode a frontier keyed on
    raw text has instead of the one keyed on the alert."""
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
    # ...and it moved to the held half rather than vanishing, which is what makes the
    # complement claim in `test_a_settled_value_is_a_held_fact_and_not_an_open_slot` real
    # from this direction too.
    assert any(h.vertex_id == "v-006" and h.slot == "class"
               for h in _frontier(closed_doc).held), "the closed slot went nowhere"
    assert match_lessons(_frontier(closed_doc), corpus) == []

    # ...and `frontier_from_text` is parse-then-derive and nothing else, so a caller holding a
    # companion it already parsed gets the identical answer.
    body, _warnings = parse_dense_companion(open_doc)
    assert derive_frontier(body) == _frontier(open_doc)


# --------------------------------------------------------------------------- #
# case 2 — the motivating miss, retrieved without the alert signature
# --------------------------------------------------------------------------- #

def test_the_loginuid_lesson_is_retrieved_though_its_signature_does_not_match(tmp_path):
    """CLAIM: retrieval is signature-BLIND — the frontier is the whole key.

    The regression this issue was filed on. The lesson that would have caught the case names
    `v2-cross-tier-ssh-pivot` in `source_signature` and the case fired on
    `v2-falco-suspicious-network-tool`, so every signature-keyed retrieval misses it by
    construction; what the two share is an open `attrs.loginuid` on a `process` vertex.

    Asserted twice over, because a passing retrieval alone would not prove blindness: the
    lesson whose signature DOES match the case is in the same corpus and must NOT come back
    (it declares no frontier selector, so it has nothing to match), and `match_lessons` is
    pinned to have no parameter a signature could be threaded through."""
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


# --------------------------------------------------------------------------- #
# case 3 — `ident` is in the frontier and still not in the benign gate
# --------------------------------------------------------------------------- #

def test_an_unresolved_ident_is_in_the_frontier_but_not_in_the_benign_gate(tmp_path):
    """CLAIM: `identifier` is an `OpenSlot` (`slot="ident"`), and `_check_benign_open_slots` is
    UNCHANGED by that.

    The two are deliberately different questions and #836 already decided the second one: it
    routes `ident` into a distinct top-level `identifier` slot precisely so an `ident=??` does
    NOT block a benign close (its N3). Retrieval asks the opposite question — an identifier
    nobody has pinned down is exactly when a lesson about identifying that kind of entity is
    worth reading.

    The failure mode this guards is a shared helper: an implementation that reaches for
    "every unresolved slot" by widening `_check_benign_open_slots`, or by folding `identifier`
    into `attributes` so both readers see it, passes the frontier half and silently starts
    refusing benign closes on a slot that never gated one. So the gate is asserted from both
    sides — the raw check returns nothing, and a real `:T conclude` claiming `benign` still
    validates."""
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


# --------------------------------------------------------------------------- #
# case 4 — contracts
# --------------------------------------------------------------------------- #

def test_a_contract_is_open_until_a_row_authorizes_it(tmp_path):
    """CLAIM: a contract leaves the frontier on `verdict == "authorized"` and on nothing else.
    A declared contract with no fulfilling row is open; a row carrying any OTHER verdict
    leaves it open.

    The middle case is the one an implementer would otherwise have to guess, so it is pinned
    explicitly: `unauthorized` is a resolved-and-FAILING contract, and the reading this ships
    is that it stays on the frontier — the question the lesson corpus can still help with is
    live until the answer is `authorized`. (`_check_benign_authz` reads the same join the same
    way: anything that is not `authorized` blocks.)"""
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
    `rel` and `auth_kind` are None rather than invented.

    `_hyp_sub_authz_row` defaults an empty `edge_ref` cell to the `proposed` sentinel, so this
    is the common shape at PLAN time — the contract exists before the edge does. An
    implementation that looked the sentinel up in the `:E` table would either raise or fill
    the two fields from whatever the lookup returned, and an edge selector naming `rel` would
    then match a contract that has no relation at all."""
    assert _contract_tuples(_FIXTURE_DOCS["proposed contract"]) == [
        ("ac2", "h-002", "approved-source-list", "proposed", None, None)
    ]


def test_an_edge_selector_matches_only_when_every_field_it_declares_is_equal(tmp_path):
    """CLAIM: an edge selector is a conjunction over the fields it DECLARES — an omitted field
    constrains nothing, a declared one must be equal.

    Both halves matter. Without the first, the two-field lesson below could only be written by
    a corpus author who knows every field of the contract; without the second, `rel:
    assumed_role` would match an `attempted_auth` contract and the selector would be
    decoration."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "edge-both", edges=("rel: attempted_auth, anchor_kind: iam-policy",))
    _write_lesson(corpus, "edge-kind-only", edges=("anchor_kind: iam-policy",))
    _write_lesson(corpus, "edge-wrong-rel", edges=("rel: assumed_role, anchor_kind: iam-policy",))
    _write_lesson(corpus, "edge-wrong-kind", edges=("anchor_kind: change-mgmt",))
    match_lessons = _lessons_frontier().match_lessons

    hits = match_lessons(_frontier(_FIXTURE_DOCS["authz declared"]), corpus, top_k=10)

    assert _names(hits) == ["edge-both", "edge-kind-only"]
    # ...and specificity is the count of DECLARED fields, so the two-field selector ranks first
    assert [h.score for h in hits] == [2, 1]


# --------------------------------------------------------------------------- #
# case 5 — ranking
# --------------------------------------------------------------------------- #

def _ranking_corpus(tmp_path: Path) -> Path:
    """Five node selectors against `OPEN_TRIPLE_BLOCK` (`class=ip-only/??/??`).

    The names fight the scores on purpose: `zeta` and `delta` are the two most specific and
    the two LAST alphabetically, so a list that comes back alphabetically is visibly wrong.
    `omega-bastion` is the control on the inversion — the case's slot 0 is CONCRETE
    (`ip-only`), so a selector naming a different concrete value must miss even though slots 1
    and 2 of the same cell are wide open."""
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
    """CLAIM: score is the count of BOUND components — type, each non-`*` class slot, and the
    slot name — highest first, and `top_k` (default 3) is the cut.

    `zeta` binds four components against `delta`'s three and the bare `type+slot` selectors'
    two, and it earns its top slot through the INVERSION: its second class slot (`internet`)
    matches an open `??`. That is the clause this issue turns around, so the lesson that
    names the most about a mostly-unknown entity is the one the model reads first.

    The two non-matching selectors are in the same corpus so `top_k` is a cut on the MATCHES,
    never on the corpus: an implementation that padded to `top_k` from what is left would
    return `omega-bastion` here."""
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


def test_ties_break_by_name_and_the_order_is_stable_across_calls(tmp_path):
    """CLAIM: equal scores order by lesson `name` ascending, and two calls give the same list.

    Not cosmetic. The rendered section goes into `append_block`'s return, and case 6 decides
    whether to show it by COMPARING two recalls — so an unstable order (a dict, a `glob` on a
    filesystem that does not sort) would make an unchanged frontier look changed, and the
    model would be handed the same three lessons again on every append."""
    corpus = _ranking_corpus(tmp_path)
    match_lessons = _lessons_frontier().match_lessons
    frontier = _frontier(_FIXTURE_DOCS["open triple"])

    first = match_lessons(frontier, corpus, top_k=10)
    second = match_lessons(frontier, corpus, top_k=10)

    tied = [h.name for h in first if h.score == 2]
    assert tied == sorted(tied) == [
        "alpha-any-compute", "beta-any-compute", "gamma-any-compute",
    ]
    assert _names(first) == _names(second)
    assert [h.score for h in first] == [h.score for h in second]


# --------------------------------------------------------------------------- #
# case 6 — the recall rides on the append that moved it
# --------------------------------------------------------------------------- #

def test_append_block_carries_the_lessons_only_when_the_append_moved_the_recall(tmp_path):
    """CLAIM: `_tool_append_block` derives the recall over the pre- and post-append document
    and appends the rendered section ONLY when the two differ.

    Re-timing is the whole issue: the retrieval fires when the document changes, not once
    before it exists. But firing on EVERY append is the failure that would get the section
    ignored — three appends in a loop, the same three lessons three times, and the model
    learns to skip the block. So the comparison is the mechanism, and both halves are
    asserted on one deps object across three real appends:

      1. the prologue opens nothing        → no section
      2. the block that opens `class=??`   → the section, naming the lesson
      3. prose that moves no slot          → no section again

    Step 3 is a NON-empty frontier that did not CHANGE, which is the case a "is the frontier
    non-empty" implementation gets wrong while passing steps 1 and 2."""
    from defender.runtime.tools import _tool_append_block

    deps, run, dfn = _main_deps(tmp_path)
    corpus = _corpus(dfn)
    _write_lesson(corpus, "process-class-open", nodes=("type: process, slot: class",))

    first = _tool_append_block(deps, PROLOGUE)
    assert "appended" in first
    assert "process-class-open" not in first, "a document with no open slot recalled a lesson"

    second = _tool_append_block(deps, OPEN_CLASS_BLOCK)
    assert second.startswith("appended "), "the byte-count lead is still the first thing said"
    assert "process-class-open" in second, (
        "the append that opened `class=??` did not carry the lesson it unlocked"
    )

    third = _tool_append_block(deps, PROSE_BLOCK)
    assert "appended" in third
    assert "process-class-open" not in third, (
        "the section re-fired on an append that left the frontier exactly as it was"
    )

    assert (run / "investigation.md").read_text(encoding="utf-8") == (
        PROLOGUE + OPEN_CLASS_BLOCK + PROSE_BLOCK
    ), "the recall changed what landed on disk"


# --------------------------------------------------------------------------- #
# case 7 — a half-written block is inert, not fatal
# --------------------------------------------------------------------------- #

def test_a_malformed_block_yields_an_empty_frontier_rather_than_raising(tmp_path):
    """CLAIM: `frontier_from_text` never raises — a document it cannot read has an empty
    frontier.

    A model streams `investigation.md` a block at a time and `append_block` is called on
    partial documents by construction, so "malformed" is a normal input here rather than an
    edge case. Both shapes carry a literal `??` in text the parser DISCARDS, so an
    implementation that scanned the raw document instead of the companion would report an
    open slot on a vertex that does not exist — worse than reporting nothing, because the
    recall would then be keyed on a row the author never committed."""
    # Each shape is paired with the SAME document minus the malformed block, so the claim is
    # "the broken block contributed nothing" rather than "the document was empty" — the two
    # differ now that a settled `:V` cell is a held fact and `PROLOGUE` carries several.
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
    """CLAIM: the recall never turns a write that LANDED into a failed tool call.

    The same fail-open discipline `_warn_over` (tools.py:878) already holds, and for the same
    reason: both derive AFTER the bytes are on disk, so an exception raised here surfaces to
    the model as a refusal for a write that succeeded — and under append-only a model that
    believes its block was refused re-sends it, doubling the block."""
    from defender.runtime.tools import _tool_append_block

    deps, run, dfn = _main_deps(tmp_path)
    _write_lesson(_corpus(dfn), "process-class-open", nodes=("type: process, slot: class",))
    _tool_append_block(deps, PROLOGUE)

    result = _tool_append_block(deps, HALF_WRITTEN_BLOCK)

    assert result.startswith("appended "), result
    assert f"appended {len(HALF_WRITTEN_BLOCK.encode('utf-8'))} bytes" in result
    assert (run / "investigation.md").read_text(encoding="utf-8").endswith(HALF_WRITTEN_BLOCK)


# --------------------------------------------------------------------------- #
# case 8 — `--corpus` is a relocation seam, not a corpus selector
# --------------------------------------------------------------------------- #

def test_the_relocated_corpus_must_still_be_named_lessons(tmp_path, capsys):
    """CLAIM: `--corpus` accepts a RELOCATED `lessons` directory and refuses anything else,
    exiting 2.

    `_lessons_common.resolve_corpus` states the argument in full and this mirrors it: its
    other caller IS reachable as a pinned, argv-blind grant, so containment is the resolver's
    whole job — the rule is the resolved LEAF NAME, because a legitimate relocation (a
    worktree copy, a test fixture) changes the root and never the corpus name. NOTE the rule
    is weaker here than for the sibling: this script's own default corpus IS `defender/lessons`,
    so the leaf-name test cannot keep an actor out of it. Do not grant-list this script.

    The two directories below hold the SAME lesson, so the refusal is demonstrably about the
    name rather than about an empty directory."""
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


# --------------------------------------------------------------------------- #
# hardening (#919 review) — the holes a mutation sweep found in the cases above
#
# Every test below was written because a WRONG implementation survived the suite as it
# first stood. Each names the mutation it kills.
# --------------------------------------------------------------------------- #

def test_an_open_case_slot_matches_a_concrete_selector_and_a_settled_one_does_not(tmp_path):
    """CLAIM: the inversion — an UNRESOLVED case slot satisfies any selector slot — and it is
    an inversion rather than "everything matches", because a slot that is settled to a
    different value still misses.

    THE central claim of #919, and the suite did not hold it. Every node selector in the
    cases above omits `class`, so it matches through the ordinary `*` wildcard and never
    through the inversion: deleting the open-case-slot clause from `class_match` left twelve
    of thirteen tests green. The environment corpus's matcher wildcards on the SELECTOR side
    only, and it is the retrieval this one has to differ from — so a lesson naming a concrete
    class against an open cell is the discriminating shape.
    """
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


def test_a_candidate_set_is_open_exactly_as_the_bare_marker_is(tmp_path):
    """CLAIM: `{a, b}` is an open slot. SKILL.md documents `??` -> `{a, b}` -> concrete as
    three states of one thing, where the candidate set is an UPGRADE from `??` and not a
    resolution of it.

    No fixture carried the brace form, so `is_unresolved` reduced to `value == "??"` passed
    the whole suite — on both the derivation side and the matching side."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "candidate-set-is-open",
                  nodes=("type: compute, class: ip-only/dmz, slot: class",))
    doc = _FIXTURE_DOCS["candidate set"]

    assert _slot_tuples(doc) == [
        ("v-007", "compute", "ip-only/{internal, dmz}/known-corp", "class",
         "ip-only/{internal, dmz}/known-corp")
    ], "an enumerated candidate set is not being read as an open slot"
    assert _names(_lessons_frontier().match_lessons(_frontier(doc), corpus)) == [
        "candidate-set-is-open"
    ]


def test_a_node_selectors_type_must_equal_the_open_slots_type(tmp_path):
    """CLAIM: `type` is a constraint, not decoration.

    Deleting the type comparison from `_node_match_score` passed all thirteen: no corpus in the
    suite held a selector whose type disagreed with the vertex it would otherwise hit."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "right-type", nodes=("type: process, slot: attrs.loginuid",))
    _write_lesson(corpus, "wrong-type", nodes=("type: identity, slot: attrs.loginuid",))

    hits = _names(_lessons_frontier().match_lessons(
        _frontier(_FIXTURE_DOCS["open loginuid"]), corpus))
    assert hits == ["right-type"], "a selector matched a slot on a vertex of another type"


def test_ties_break_by_lesson_name_rather_than_by_filename(tmp_path):
    """CLAIM: equal scores order by the lesson's `name`.

    The original tie test could not see this. `iter_lesson_paths` sorts by PATH and the
    fixture wrote each lesson to `{name}.md`, so corpus order was already name order and a
    sort with no tiebreak passed. Here the filenames are deliberately the reverse of the
    names, so only a real tiebreak produces the expected order — and an unstable sort is a
    live defect, because the recall diff that gates injection compares two rendered lists."""
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
    """CLAIM: a lesson's score is its most specific MATCHING selector, not an accumulation.

    Every fixture lesson declared exactly one selector, so summing passed the suite — while
    the whole point of the rule is that a lesson carrying several loose selectors must not
    outrank one that names the exact slot in play."""
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
    """CLAIM: `auth_kind` constrains an edge selector like the other two fields.

    Deleting its clause from `_edge_matches` passed the suite — `auth_kind` appeared only in
    the expected value of a contract tuple, never as something a lesson selected on. It is
    the field that separates a verdict resting on a SIEM event from one resting on an
    authoritative source, which is exactly what a lesson about anchor strength speaks to."""
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
    assert hits[0].score == 2, "both declared fields should count toward specificity"


def test_matched_names_the_frontier_item_rather_than_the_selector(tmp_path):
    """CLAIM: `Hit.matched` identifies WHICH open thing hit — the vertex and its value.

    The original assertion was `"attrs.loginuid" in hit.matched`, which a hardcoded constant
    and an echo of the selector both satisfy. `matched` is the model's only account of why a
    lesson was pushed at it, so an echo of the query makes the block unauditable."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "loginuid", nodes=("type: process, slot: attrs.loginuid",))

    hit = _lessons_frontier().match_lessons(
        _frontier(_FIXTURE_DOCS["open loginuid"]), corpus)[0]
    assert "v-004" in hit.matched, "matched does not name the vertex that hit"
    assert "??" in hit.matched, "matched does not carry the unresolved value"


def test_the_recall_is_omitted_when_the_corpus_is_missing_or_malformed(tmp_path):
    """CLAIM: the recall never turns a landed write into a failed tool call.

    The original fail-open test asserted only the byte-count lead on a document that reaches
    no corpus at all, so it passed with the recall unwired, with the guard deleted, and with
    the `except` re-raising. These two inputs actually reach the failure paths: a defender
    tree with no `lessons/` directory, and a lesson whose selector list is a scalar where a
    sequence belongs."""
    from defender.runtime.tools import _tool_append_block

    deps, _run, dfn = _main_deps(tmp_path)
    opening = PROLOGUE + OPEN_LOGINUID_BLOCK

    # No corpus at all.
    assert not (dfn / "lessons").exists()
    assert _tool_append_block(deps, opening).startswith("appended "), (
        "a missing lessons corpus turned a landed write into something other than an accept"
    )

    # A corpus whose lesson declares garbage where a selector sequence belongs.
    corpus = _corpus(dfn)
    _write_lesson(corpus, "malformed", raw_nodes="not-a-list")
    out = _tool_append_block(deps, PROLOGUE + OPEN_CLASS_BLOCK)
    assert out.startswith("appended "), (
        "a malformed selector raised out of the recall instead of failing open"
    )


def test_render_of_nothing_is_empty_and_the_cli_honours_top_k(tmp_path):
    """CLAIM: the two surfaces the contract pins but nothing exercised.

    `render([])` must be empty rather than a loud-empty banner — `_frontier_recall` gates on
    its falsiness, so a header here would make every append emit a block. And `--top-k` must
    reach `match_lessons`, not just the keyword argument the other tests call directly."""
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


# --------------------------------------------------------------------------- #
# hardening, round 2 — what an adversarial implementer got away with
#
# A throwaway implementation passed the suite above while (a) never calling
# `match_lessons` from the tool at all, (b) never opening `--investigation`, (c) discharging
# every contract off any one authorized row, and (d) folding only `class` refinements. Each
# test below is the decoy that makes one of those impossible.
# --------------------------------------------------------------------------- #

def test_the_tool_pushes_only_the_lessons_that_matched(tmp_path):
    """CLAIM: `_tool_append_block` is wired to `match_lessons`, not to a directory listing.

    Nothing above proved this. Every integration corpus held only lessons that were supposed
    to match, so an implementation that globbed the corpus and pasted every filename passed —
    which in a real run would staple the whole lesson corpus to every tool return. The decoy
    is the entire point: it matches nothing, and it must not appear."""
    from defender.runtime.tools import _tool_append_block

    deps, _run, dfn = _main_deps(tmp_path)
    corpus = _corpus(dfn)
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
    """CLAIM: `main` derives the frontier from `--investigation`.

    Case 8 asserted an exit code and the top-k test asserted a cut, both of which an
    implementation that never opens the file can satisfy by printing the corpus in order.
    The decoy forces the read."""
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
    """CLAIM: discharge joins on `fulfills_contract`.

    The original fixture carried one contract and one row, so "any authorized row clears
    everything" was indistinguishable from a real join — and that shortcut would silently
    close every outstanding authorization question the moment one of them was answered."""
    doc = (
        PROLOGUE + AUTHZ_DECL_BLOCK + SECOND_CONTRACT_BLOCK + authz_row("authorized")
    )
    open_ids = [c.contract_id for c in _frontier(doc).contracts]
    assert open_ids == ["ac2"], (
        "an `authorized` row naming ac1 discharged a contract it does not name"
    )


def test_a_refinement_closes_an_ident_or_an_attribute_too(tmp_path):
    """CLAIM: the `:R attr_updates` fold honours all three legal keys.

    Case 1 shipped only a `class` refinement, so an implementation that dropped `ident` and
    `attrs.<name>` rows passed — leaving a resolved attribute open forever and re-pushing
    the same lesson on every subsequent append, which is precisely the churn the diff-gated
    injection exists to prevent."""
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


def test_a_document_with_only_an_open_contract_is_not_empty(tmp_path):
    """CLAIM: `is_empty()` reads both axes.

    An `is_empty` that consulted only `slots` passed everything above, because no test ever
    called it on a contract-bearing document — and `_frontier_recall` gates the whole
    injection on the emptiness of the render, so an edge-only frontier would never fire."""
    declared = _FIXTURE_DOCS["authz declared"]
    frontier = _frontier(declared)
    assert frontier.slots == ()
    assert frontier.contracts, "the fixture should carry one contract"
    assert not frontier.is_empty(), (
        "a frontier carrying an open contract and no open slot reported itself empty"
    )


def test_a_contract_on_a_refuted_hypothesis_is_not_on_the_frontier(tmp_path):
    """CLAIM: only LIVE hypotheses carry outstanding contracts.

    `_check_benign_authz` walks live hypotheses only, so a contract whose hypothesis has been
    refuted blocks nothing and owes nothing. Reading it as open would push lessons about a
    question the investigation abandoned, and would disagree with the disposition gate about
    what is outstanding."""
    refuted = PROLOGUE + AUTHZ_DECL_BLOCK + REFUTE_H001_BLOCK
    assert _frontier(PROLOGUE + AUTHZ_DECL_BLOCK).contracts, "positive control"
    assert _frontier(refuted).contracts == (), (
        "a contract on a refuted hypothesis is still being reported as open"
    )


# --------------------------------------------------------------------------- #
# review follow-ups (#930): the two ways the shipped mechanism missed its own case
# --------------------------------------------------------------------------- #

def test_a_class_slot_matched_only_through_the_inversion_pins_nothing(tmp_path):
    """CLAIM: specificity scores the MATCH, not the selector — a class component that landed
    on an open case slot discriminated nothing and earns nothing.

    This is the case #919 exists for, and the shipped scoring lost it. A vertex declared
    `class=??` is matched by `{class: bastion}` and by `{class: client-cert}` alike, purely
    through the inversion; crediting those literals scored them 3 against the 2 of a selector
    naming the exact open ATTRIBUTE. With `top_k=3` the motivating loginuid lesson fell off a
    list saturated by lessons the document says nothing about — and because `_frontier_recall`
    diffs the RENDERED block, the append that opened `attrs.loginuid=??` then emitted nothing
    at all.

    `test_specificity_outranks_generality_and_top_k_bounds_the_list` is the other half and
    still holds: once ONE class slot matches by equality the pattern is anchored to this cell
    and the rest is real precision (`ip-only/internet` over `ip-only` on `ip-only/??/??`)."""
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
    assert hits["zzz-names-the-open-attribute"] == 2
    assert hits["aaa-wholly-open-class"] <= hits["zzz-names-the-open-attribute"], (
        "a class literal the document never mentions outranked the exact open slot"
    )


def test_the_frontier_and_the_benign_gate_agree_on_a_shared_contract_id(tmp_path):
    """CLAIM: `_open_contracts` calls `validate.outstanding_authz_contracts` rather than
    restating "discharged", so the two cannot disagree.

    A bare-id discharge set gets this wrong on the one document shape where it matters. Two
    declarers may share `ac1` once one of them is REFUTED (`_check_authz_contract_ids` exempts
    exactly that, because `:H` rows are immutable and refuting is the only repair left), and
    `_check_benign_authz` then scopes the row to the contract whose ANCHOR KIND it carries. So
    an `iam-policy` row does not answer an `approved-source-list` question wearing the same
    number — and the frontier must not report settled what the close is still blocked on."""
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
    """CLAIM: the repair verb pushes lessons on the same terms `append_block` does.

    `fix_row`'s window is `:R attr_updates`-only, and those rows are precisely what CLOSES an
    open slot — so a repair can close one and `fix_row(row, "")` REOPENS one. Wiring the recall
    to `append_block` alone did not merely leave that move unannounced, it made it
    unannounceable: the next append reads the repair as part of its own `before`, the two
    frontiers match, and the block is suppressed for the rest of the run.

    Here the flagged row carries a near-miss KEY, which warns and refines nothing; repairing it
    to a legal `attrs.tty|??` is the append-only way to open a slot from inside the window."""
    from defender.runtime.tools import _tool_append_block, _tool_fix_row

    deps, run, dfn = _main_deps(tmp_path)
    corpus = _corpus(dfn)
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
    """CLAIM: the rendered path is ABSOLUTE, and the `matched` line is part of the block.

    Both were unpinned, which is why the repo-relative spelling shipped green. MAIN's
    `cwd_anchor` is the RUN DIR, so `_resolve_operand` rebases `defender/lessons/<name>.md`
    onto the run dir and `decide_read` refuses it — `test_grant_gate_575.py::test_a11` pins
    that spelling as DENY, on the grounds that "nothing hands MAIN that spelling any more".
    A block that hands it one costs a refused tool call per lesson and degrades the whole
    push to description-only, which is the one thing SKILL.md says not to decide on.

    Asserted through the REAL gate rather than against a string shape, because the property
    is "MAIN can read this", not "this starts with a slash". The `matched` half rides along:
    `HIDDEN_KEYS` strips the selectors, so it is the model's only account of why a lesson was
    pushed, and every other assertion in this file is satisfied by the `name:` key inside the
    frontmatter dump."""
    from defender.runtime.tools import _tool_read_file

    deps, run, dfn = _main_deps(tmp_path)
    corpus = _corpus(dfn)
    _write_lesson(corpus, "readable-from-the-block", nodes=("type: process, slot: class",))
    lf = _lessons_frontier()

    hits = lf.match_lessons(_frontier(_FIXTURE_DOCS["open class"]), corpus)
    rendered = lf.render(hits)

    assert hits, "positive control: the fixture should match the lesson"
    assert f"matched {hits[0].matched}" in rendered, (
        f"the block dropped its account of WHY the lesson was pushed:\n{rendered}"
    )
    quoted = rendered.splitlines()[1].removeprefix("- ").split(" — matched ")[0]
    body = _tool_read_file(deps, quoted)  # ModelRetry here IS the failure
    assert "lesson body" in body, f"the path the block quoted ({quoted!r}) did not read back"


def test_a_pushed_lesson_is_recorded_the_way_a_read_one_is(tmp_path):
    """CLAIM: the recall lane writes `lessons_loaded.jsonl`, like `_gated_read` does.

    That file is the only "was this lesson in context" signal the loop has, and
    `learning/ops/trace_lesson.py` is the stated post-merge human control that reads it. A
    push that left no row makes a merged lesson look inert to whoever is judging its impact
    — the block already carries the description and the dimensions, which is what SKILL.md
    tells the model to decide on."""
    import json

    from defender.runtime.tools import _tool_append_block

    deps, run, dfn = _main_deps(tmp_path)
    corpus = _corpus(dfn)
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


# --------------------------------------------------------------------------- #
# the in-hand axis — `observed_nodes`
#
# Keying only on OPEN slots made #919's own motivating lesson unreachable: the alert carries
# `loginuid=-1` concretely, so the slot it keyed on never opened. These pin the second half.
# --------------------------------------------------------------------------- #

#: A `process` whose class and attributes are all SETTLED. Nothing here is open, so the whole
#: document is invisible to `frontier_nodes` and visible only to `observed_nodes`.
SETTLED_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-008|identity|user/anonymous|root|uid=0;loginuid=-1
```
"""


def test_a_settled_value_is_a_held_fact_and_not_an_open_slot(tmp_path):
    """CLAIM: the two node halves are complements — a cell is open XOR held, never both.

    Without this the `observed_nodes` lane could be implemented as "every cell", which would
    make `frontier_nodes`' negative half (case 1) unenforceable from the other side."""
    doc = PROLOGUE + SETTLED_BLOCK
    f = _frontier(doc)
    assert f.slots == (), "a fully settled vertex put something on the OPEN half"
    held = {(h.vertex_id, h.slot, h.value) for h in f.held}
    assert ("v-008", "attrs.loginuid", "-1") in held
    assert ("v-008", "ident", "root") in held
    assert ("v-008", "class", "user/anonymous") in held
    assert not f.is_empty(), "a document with held facts and no open slot reported empty"

    # ...and the mirror, over ALL THREE slot kinds rather than just `class`: an unresolved
    # cell must be absent from the held half. Checking one kind let a mutation that
    # double-counted ATTRIBUTES pass, which is the kind the motivating lesson keys on.
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
    """CLAIM: `observed_nodes` fires on a concrete value, and `frontier_nodes` does not.

    The regression for #919's real motivating shape. A lesson about what `loginuid=-1`
    licenses must reach a document that RECORDED `loginuid=-1` — which is the only shape the
    alert ever produces."""
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


def test_the_two_node_lanes_share_one_ranking_scale(tmp_path):
    """CLAIM: neither lane is systematically preferred; specificity alone orders them.

    A tilt toward either half would bury one kind of advice behind the other regardless of
    how precisely it speaks to the document."""
    corpus = _corpus(tmp_path)
    _write_lesson(corpus, "aaa-held-loose", observed=("type: identity, slot: attrs.loginuid",))
    _write_lesson(corpus, "zzz-open-loose", nodes=("type: process, slot: class",))
    doc = PROLOGUE + SETTLED_BLOCK + OPEN_CLASS_BLOCK
    hits = _lessons_frontier().match_lessons(_frontier(doc), corpus)

    assert {h.name for h in hits} == {"aaa-held-loose", "zzz-open-loose"}
    assert hits[0].score == hits[1].score, (
        "an open-slot match and a held-fact match of equal specificity scored differently"
    )


def test_the_shipped_corpus_reaches_the_motivating_investigation(tmp_path):
    """CLAIM: against the repo's own committed investigation, the lesson #919 exists for is
    retrieved.

    Every other test in this file drives a fixture. This one drives the artefact the issue
    was filed about — `learning/runs/turnN-A/investigation.md`, the Falco authorized_keys
    case whose report asserted an attack chain that did not happen — against the REAL 16-file
    corpus. It is the only test here that can tell "the mechanism works" from "the mechanism
    works on documents written to suit it"."""
    real = Path(__file__).resolve().parents[1] / "learning" / "runs" / "turnN-A" / "investigation.md"
    if not real.is_file():
        pytest.skip(f"the motivating investigation is not in this tree ({real})")
    corpus = Path(__file__).resolve().parents[1] / "lessons"

    hits = _names(_lessons_frontier().match_lessons(
        _frontier(real.read_text(encoding="utf-8")), corpus))
    assert "falco-loginuid-tty-non-interactive-not-docker-exec" in hits, (
        f"#919's motivating lesson is still not retrieved on its own case; got {hits}"
    )
