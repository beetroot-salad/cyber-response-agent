"""A resolution's `p*`/`ap*`/`r*` citations resolve, and a strong move carries one.

`:H h-NNN.preds` / `.attr_preds` / `.refuts` are the sole sites that declare a
prediction or a refutation shape. The parser never joined a resolution's
citations back to them — `matched_prediction_ids` is the head tokens that start
with `p` — so `h-001 … [l-001 p9 severe ⟂ e-002]` parsed clean and validated
clean, and the semantic reviewer downstream would have been the first thing in
the pipeline to notice p9 does not exist.

The second rule is the other half of the strong-move provenance tuple
(`_check_strong_move_provenance`): one half makes a `++`/`--` cite the
observation, this one makes it name the pre-committed claim that observation
settled (#798).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from defender.skills.invlang.validate import validate_companion

_DEFENDER = Path(__file__).resolve().parents[1]

_LEAD_HEADER = ":L findings [id|loop|name|target|tests|system|window]"
_HYP_HEADER = (
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]"
)
_STRONG_EDGE = (
    ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    "e-002|executed|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|\n"
)

_MARKERS = ("cites prediction", "cites refutation", "cites no prediction or refutation")


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
        'ap1|v-001|signing|"unsigned"\n'
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




def test_a_prediction_id_no_hypothesis_declares_is_rejected():
    errors = _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → +    [l-001 p9 mild ⟂ e-002 :: parent looks interactive]"
    ))
    assert len(errors) == 1
    assert "'p9'" in errors[0]
    assert "h-001.preds" in errors[0], "the error must name the declaring block"


def test_a_siblings_prediction_id_is_rejected_even_though_it_exists():
    """h-002 declares a p1 and h-001 does not. Citing it for h-001 is the
    cross-citation the id namespace makes so easy: both spell it `p1`, and
    before this check the head token resolved against nothing at all."""
    errors = _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-002  null → +    [l-001 p2 mild ⟂ e-002 :: no packaging metadata]"
    ))
    assert len(errors) == 1
    assert "'p2'" in errors[0]
    assert "declare: p1" in errors[0], "the error must show what IS declared"


def test_an_undeclared_refutation_id_is_rejected():
    errors = _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → -    [l-001 r7 mild ⟂ e-002 :: parent is packaged]"
    ))
    assert len(errors) == 1
    assert "'r7'" in errors[0]
    assert "h-001.refuts" in errors[0]


def test_declared_predictions_and_refutations_are_accepted():
    assert _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → ++   [l-001 p1,p2 severe ⟂ e-002 :: interactive parent, no packaging]\n"
        "h-002  null → -    [l-001 p1 mild ⟂ e-002 :: some packaging metadata after all]"
    )) == []


def test_an_attribute_prediction_id_resolves_against_attr_preds():
    """The `⟺` annotation form is the one that cites `ap*`, so `.attr_preds`
    declares matched-prediction ids too — a check reading only `.preds` would
    reject every attribute-graded resolution."""
    assert _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → +    [l-001 severe ⟂ e-002 :: unsigned binary ⟺ ap1]"
    )) == []


def test_a_resolution_against_an_undeclared_hypothesis_is_left_to_the_parser():
    """h-404 has no `:H` row, so there is no id set to resolve against. The
    parse layer owns that failure; repeating it once per citation would bury
    it under three copies of the same news."""
    assert _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-404  null → +    [l-001 p1,p2 mild ⟂ e-002 :: unrelated]"
    )) == []




def test_a_strong_move_citing_nothing_is_rejected():
    errors = _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → ++   [l-001 severe ⟂ e-002 :: everything lines up]"
    ))
    assert len(errors) == 1
    assert "'++'" in errors[0]


def test_a_refutation_to_double_minus_citing_nothing_is_rejected():
    errors = _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → --   [l-001 severe ⟂ e-002 :: it just is not this]"
    ))
    assert len(errors) == 1
    assert "'--'" in errors[0]


def test_a_weak_move_may_cite_nothing():
    """`+`/`-` is the honest register for evidence that shifts belief without
    settling a named prediction; only the strongest moves owe an id."""
    assert _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → +    [l-001 mild ⟂ e-002 :: suggestive, nothing settled]"
    )) == []


def test_a_strong_move_needs_only_one_of_the_two_lists():
    assert _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → --   [l-001 r1 severe ⟂ e-002 :: parent is a packaged unit]"
    )) == []


def test_an_attribute_prediction_cited_in_the_HEAD_satisfies_the_rule():
    """The spelling the error message itself asks for. `matched_prediction_ids`
    fell out of a bare `startswith("p")`, so `ap1` in the head parsed as citing
    NOTHING — and this rule then blocked the write of a row that had named its
    attribute prediction, telling the author to name the `ap*` they had just
    named. `⟺ ap1` in the annotation was the only spelling that worked."""
    assert _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → ++   [l-001 ap1 severe ⟂ e-002 :: the binary is unsigned]"
    )) == []


def test_an_undeclared_attribute_prediction_in_the_head_is_still_rejected():
    """The other side of the same fix: an `ap*` the head names but `.attr_preds`
    never declared used to be dropped before any check could see it."""
    errors = _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → ++   [l-001 ap9 severe ⟂ e-002 :: the binary is unsigned]"
    ))
    assert len(errors) == 1
    assert "'ap9'" in errors[0]


def test_omitting_severity_is_caught_as_a_strong_move_citing_nothing():
    """The shape this check found in the shipped corpus. Severity is
    positional-last in the head, so a row that leaves it out has its
    prediction ids read as the severity: three predictions written down, none
    of them bound to the `++` (`golden-v2sshd`, fixed in #798)."""
    errors = _errors(_doc(
        _two_hypotheses() + "\n"
        ":T resolutions\n"
        "h-001  null → ++   [l-001 p1,p2 ⟂ e-002 :: interactive parent, no packaging]"
    ))
    assert len(errors) == 1
    assert "<severity>" in errors[0], "the error must point at the slot that ate them"




def _corpus_docs() -> list[Path]:
    """Every SHIPPED document with an ```invlang fence: the two `fixtures-e2e/`
    golden runs and the `examples/` the SKILL points at.

    `learning/runs/` is deliberately absent. It is gitignored machine-local run
    output (`.gitignore` line 79; `git ls-files` lists nothing under it), so
    globbing it makes the parametrization a function of what happens to sit on
    the developer's disk — empty on CI, where the guard is supposed to run, and
    on a laptop able to go red over a run nobody is shipping."""
    candidates = [
        *sorted((_DEFENDER / "examples").glob("*.md")),
        *sorted((_DEFENDER / "fixtures-e2e").glob("*/investigation.md")),
    ]
    docs = [p for p in candidates if "```invlang" in p.read_text(encoding="utf-8")]
    # An empty parametrize list is a silently-green suite; if the corpus moves,
    # this must be a loud collection error, not a check that stopped running.
    assert docs, "no ```invlang corpus documents found — did the tree move?"
    return docs


@pytest.mark.parametrize(
    "path", _corpus_docs(), ids=lambda p: str(p.relative_to(_DEFENDER))
)
def test_the_shipped_corpus_carries_no_prediction_reference_defect(path: Path):
    """Neither rule may cost the corpus a document. (`examples/` carries
    unrelated errors that predate this — the filter is to these two rules, so
    this stays a check on them, not a freeze of the whole validator's
    verdict.)"""
    assert _errors(path.read_text(encoding="utf-8")) == []
