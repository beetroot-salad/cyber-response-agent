"""A resolution's `h-*` and `p*`/`ap*`/`r*` references resolve, and a strong move
carries one.

`:H h-NNN.preds` / `.attr_preds` / `.refuts` are the sole sites that declare a
prediction or a refutation shape. The parser never joined a resolution's
citations back to them — `matched_prediction_ids` is the head tokens that start
with `p` — so `h-001 … [l-001 p9 severe ⟂ e-002]` parsed clean and validated
clean, and the semantic reviewer downstream would have been the first thing in
the pipeline to notice p9 does not exist.

The row's own `h-*` was the same hole one level up, deferred until `:H` blocks
accumulated (#817/#818): an id no `:H` row declares moved a phantom hypothesis
to `++` with nothing in the pipeline objecting.

The strong-move rule is the other half of the provenance tuple
(`_check_strong_move_provenance`): one half makes a `++`/`--` cite the
observation, this one makes it name the pre-committed claim that observation
settled (#798).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from defender.skills.invlang.validate import validate_companion

from defender.tests._invlang_corpus import corpus_docs, corpus_id

_LEAD_HEADER = ":L findings [id|loop|name|target|tests|system|window]"
_HYP_HEADER = (
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]"
)
_STRONG_EDGE = (
    ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    "e-002|executed|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|\n"
)

_MARKERS = (
    "cites prediction",
    "cites refutation",
    "cites no prediction or refutation",
    "moves undeclared hypothesis",
)


def _doc(body: str) -> str:
    return "```invlang\n" + body + "\n```"


def _errors(text: str) -> list[str]:
    return [e for e in validate_companion(text) if any(m in e for m in _MARKERS)]


def _two_hypotheses() -> str:
    """h-001 declares p1/p2 + ap1 + r1; h-002 declares only its own p1."""
    return (
        _STRONG_EDGE + "\n"
        + _HYP_HEADER + "\n"
        "h-001|?adversary-shell|v-001|executed|process|unclassified-process||null|active\n"
        "h-002|?packaged-daemon|v-001|executed|process|unclassified-process||null|active\n"
        "\n"
        ":H h-001.preds [id|subject|claim]\n"
        'p1|proposed_parent|"parent is an interactive shell"\n'
        'p2|proposed_parent|"no packaging metadata for the binary"\n'
        "\n"
        ":H h-001.attr_preds [id|target|attribute|claim]\n"
        'ap1|attached_vertex|signing|"unsigned"\n'
        "\n"
        ":H h-001.refuts [id|refutes|claim]\n"
        'r1|p1,p2|"parent is a distro-packaged systemd unit"\n'
        "\n"
        ":H h-002.preds [id|subject|claim]\n"
        'p1|proposed_parent|"parent is a packaged systemd unit"\n'
        "\n"
        + _LEAD_HEADER + "\n"
        "l-001|1|process-ancestry|v-001|h-001,h-002|elastic|±10m\n"
    )




def _resolution_doc(row: str, extra: str = "") -> str:
    """The two-hypothesis fixture, optional extra blocks, then one `:T resolutions` row.
    Every case below varies only the row (and, where the case is about a block, `extra`)."""
    return _doc(_two_hypotheses() + "\n" + extra + ":T resolutions\n" + row)


# --- rows the rule must REJECT ---------------------------------------------
# Each case is one defective resolution row, and each asserts the same two things: the row
# produces EXACTLY ONE error (a second error means the check double-reports a single defect),
# and that error names the offending token — an error the author cannot act on is the failure
# mode this rule was added to avoid.
@pytest.mark.parametrize(("case", "row", "extra", "fragments"), [
    # A prediction id no hypothesis declares. The error must name the declaring BLOCK, or the
    # author has to guess where `p9` was supposed to have come from.
    ("prediction-id-no-hypothesis-declares",
     "h-001  null → +    [l-001 p9 weak ⟂ e-002 :: parent looks interactive]", "",
     ["'p9'", "h-001.preds"]),

    # h-002 declares a p1 and h-001 does not. Citing h-001's for h-002 is the cross-citation
    # the id namespace makes so easy: both spell it `p1`, and before this check the head token
    # resolved against nothing at all. The error must show what IS declared.
    ("siblings-prediction-id-even-though-it-exists",
     "h-002  null → +    [l-001 p2 weak ⟂ e-002 :: no packaging metadata]", "",
     ["'p2'", "declare: p1"]),

    # The refutation half of the same rule, resolved against `.refuts`.
    ("undeclared-refutation-id",
     "h-001  null → -    [l-001 r7 weak ⟂ e-002 :: parent is packaged]", "",
     ["'r7'", "h-001.refuts"]),

    # h-404 has no `:H` row anywhere. Nothing else catches it — the projector opens no bucket
    # for an unknown `h-*`, so before this the row moved a phantom to `++` in silence and
    # `_walkers.final_weights` reported it live. Enforcing it had to wait for `:H` blocks to
    # accumulate (#817): while a second `:H hypothesize.hypotheses` REPLACED the list, every
    # loop-1 hypothesis vanished from a legitimately-forked document and this fired on it.
    ("resolution-against-an-undeclared-hypothesis",
     "h-404  null → +    [l-001 p1,p2 weak ⟂ e-002 :: unrelated]", "",
     ["'h-404'", "h-001, h-002"]),

    # The same phantom citing TWO predictions: still one defect, so still one error. The
    # citation half stands down rather than piling three errors on one row.
    ("undeclared-hypothesis-reported-once-per-row-not-per-id",
     "h-404  null → ++   [l-001 p1,p2 severe ⟂ e-002 :: phantom]", "",
     ["'h-404'"]),

    # The deference to a parse warning is keyed to the DECLARING block, not to "the document
    # parsed without a single warning". An unknown block drops no `:H` row, so h-404 is still
    # phantom for exactly the reason the error gives — gating on `not warnings` hid it behind
    # any unrelated parse defect, and would have hid it behind every warning added since.
    ("a-warning-that-drops-no-hypothesis-does-not-stand-the-rule-down",
     "h-404  null → ++   [l-001 p1 severe ⟂ e-002 :: phantom]",
     ":Z bogus.block [a|b]\nx|y\n\n",
     ["'h-404'"]),

    # The strongest moves owe an id. `++` citing nothing is the write this rule denies...
    ("strong-move-citing-nothing",
     "h-001  null → ++   [l-001 severe ⟂ e-002 :: everything lines up]", "",
     ["'++'"]),
    # ... and `--` is the same claim in the refuting direction.
    ("refutation-to-double-minus-citing-nothing",
     "h-001  null → --   [l-001 severe ⟂ e-002 :: it just is not this]", "",
     ["'--'"]),

    # An `ap*` the head names but `.attr_preds` never declared used to be dropped before any
    # check could see it (the other side of the `startswith("p")` fix).
    ("undeclared-attribute-prediction-in-the-head",
     "h-001  null → ++   [l-001 ap9 severe ⟂ e-002 :: the binary is unsigned]", "",
     ["'ap9'"]),

    # The shape this check found in the shipped corpus. Severity is positional-last in the
    # head, so a row that leaves it out has its prediction ids read AS the severity: three
    # predictions written down, none of them bound to the `++` (`golden-v2sshd`, fixed in
    # #798). The error must point at the slot that ate them.
    ("omitting-severity-reads-as-a-strong-move-citing-nothing",
     "h-001  null → ++   [l-001 p1,p2 ⟂ e-002 :: interactive parent, no packaging]", "",
     ["<severity>"]),
], ids=lambda v: v if isinstance(v, str) and len(v) < 60 and "⟂" not in v else "")
def test_a_defective_resolution_row_is_rejected_once_and_names_the_token(
    case, row, extra, fragments
):
    """A resolution row may only move on predictions its own hypothesis declared. Each defect
    here yields exactly ONE error naming the token at fault — the id, the move, or the slot
    that swallowed it."""
    errors = _errors(_resolution_doc(row, extra))
    assert len(errors) == 1
    for fragment in fragments:
        assert fragment in errors[0], f"the error must name {fragment}"


# --- rows the rule must ACCEPT ---------------------------------------------
# The controls. Each of these is a legitimate shape the rule cost nothing, and several are
# shapes an earlier draft of it wrongly denied.
@pytest.mark.parametrize(("case", "row", "extra"), [
    # Both hypotheses resolving on ids they declared — the plain accepted shape.
    ("declared-predictions-and-refutations",
     "h-001  null → ++   [l-001 p1,p2 severe ⟂ e-002 :: interactive parent, no packaging]\n"
     "h-002  null → -    [l-001 p1 weak ⟂ e-002 :: some packaging metadata after all]", ""),

    # The `⟺` annotation form is the one that cites `ap*`, so `.attr_preds` declares matched
    # ids too — a check reading only `.preds` would reject every attribute-graded resolution.
    ("attribute-prediction-via-the-annotation",
     "h-001  null → +    [l-001 severe ⟂ e-002 :: unsigned binary ⟺ ap1]", ""),

    # The spelling the error message itself asks for. `matched_prediction_ids` fell out of a
    # bare `startswith("p")`, so `ap1` in the head parsed as citing NOTHING — and this rule
    # then blocked the write of a row that had named its attribute prediction, telling the
    # author to name the `ap*` they had just named.
    ("attribute-prediction-cited-in-the-head",
     "h-001  null → ++   [l-001 ap1 severe ⟂ e-002 :: the binary is unsigned]", ""),

    # `+`/`-` is the honest register for evidence that shifts belief without settling a named
    # prediction; only the strongest moves owe an id.
    ("weak-move-may-cite-nothing",
     "h-001  null → +    [l-001 weak ⟂ e-002 :: suggestive, nothing settled]", ""),

    # A strong move needs only ONE of the two lists — a refutation id alone satisfies it.
    ("strong-move-needs-only-one-of-the-two-lists",
     "h-001  null → --   [l-001 r1 severe ⟂ e-002 :: parent is a packaged unit]", ""),

    # The legitimate fork this rule must not cost: `:H l-NNN.new_hypotheses` declares h-010
    # inside the lead that found it, and a resolution against it is as well-grounded as one
    # against a loop-1 hypothesis.
    ("hypothesis-the-lead-declares-mid-run",
     "h-010  null → ++   [l-001 p1 severe ⟂ e-002 :: the fork holds]",
     ":H l-001.new_hypotheses "
     "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
     "h-010|?mid-run-fork|v-001|executed|process|unclassified-process||null|active\n"
     "\n"
     ":H h-010.preds [id|subject|claim]\n"
     'p1|proposed_parent|"the fork predicts this"\n'
     "\n"),

    # The other documented spelling. Both must be live before this rule can be, since between
    # them they are the only way to declare a hypothesis after loop 1 — append-only forbids
    # rewriting the first block.
    ("second-hypothesize-block-declares-a-fork",
     "h-003  null → +    [l-001 weak ⟂ e-002 :: suggestive]",
     _HYP_HEADER + "\n"
     "h-003|?late-fork|v-001|executed|process|unclassified-process||null|active\n"
     "\n"),

    # The head is not id-only — `[l-001 p1 + l-003 p1,p2 moderate ⟂ …]` is a shipped shape. A
    # `startswith` test read any word beginning `p`, `ap` or `r` as a cited id, which cost
    # nothing while the ids resolved against nothing; once this rule joined them to the
    # declaring block, these words became denied writes. Only an id-SHAPED token is a citation.
    ("head-prose-partial-is-not-a-citation",
     "h-001  null → ++   [l-001 p1 partial severe ⟂ e-002 :: interactive parent]", ""),
    ("head-prose-approved-is-not-a-citation",
     "h-001  null → ++   [l-001 p1 approved severe ⟂ e-002 :: interactive parent]", ""),
    ("head-prose-refuted-is-not-a-citation",
     "h-001  null → ++   [l-001 p1 refuted severe ⟂ e-002 :: interactive parent]", ""),
], ids=lambda v: v if isinstance(v, str) and len(v) < 60 and "⟂" not in v else "")
def test_a_well_grounded_resolution_row_is_accepted(case, row, extra):
    """The rule costs the corpus no legitimate document: ids that resolve against the block
    that declared them — including one declared mid-run — pass, and so does prose that merely
    looks like an id."""
    assert _errors(_resolution_doc(row, extra)) == []


def test_a_dropped_hypothesis_block_defers_to_its_own_parse_warning():
    """The `:H` header is off-schema, so the parser rejects the whole block and
    h-001 never exists — every resolution against it then looks phantom. The
    parse warning already names the cause; reporting the rows too would bury one
    fixable defect under errors pointing away from it.

    `examples/example-b-parallel-iam-cmdb.md` is the shipped instance: seven
    parse warnings, and four resolutions against the hypotheses they dropped."""
    doc = _doc(
        _STRONG_EDGE + "\n"
        ":H hypothesize.hypotheses [id|name|attached_to|rel]\n"
        "h-001|?adversary-shell|v-001|executed\n"
        "\n"
        + _LEAD_HEADER + "\n"
        "l-001|1|process-ancestry|v-001|h-001|elastic|±10m\n"
        "\n"
        ":T resolutions\n"
        "h-001  null → +    [l-001 weak ⟂ e-002 :: suggestive]"
    )
    assert _errors(doc) == []
    assert [e for e in validate_companion(doc) if "whole block rejected" in e]


def test_a_misspelled_new_hypotheses_block_names_itself():
    """`:H l-NNN.new_hypotheses` is now a documented authoring surface, so the
    singular typo is reachable. The projector drops an unhandled `:H` lead
    sub-block, and with no warning the resolution row took the blame for a
    hypothesis the author did declare — an error pointing at a correct row."""
    doc = _doc(
        _two_hypotheses() + "\n"
        ":H l-001.new_hypothesis "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        "h-010|?mid-run-fork|v-001|executed|process|unclassified-process||null|active\n"
        "\n"
        ":T resolutions\n"
        "h-010  null → +    [l-001 weak ⟂ e-002 :: the fork holds]"
    )
    assert [e for e in validate_companion(doc) if "new_hypothesis`" in e], (
        "the parse warning must name the misspelled block"
    )




@pytest.mark.parametrize("path", corpus_docs(), ids=corpus_id)
def test_the_shipped_corpus_carries_no_prediction_reference_defect(path: Path):
    """Neither rule may cost the corpus a document. (`examples/` carries
    unrelated errors that predate this — the filter is to these two rules, so
    this stays a check on them, not a freeze of the whole validator's
    verdict.)"""
    assert _errors(path.read_text(encoding="utf-8")) == []
