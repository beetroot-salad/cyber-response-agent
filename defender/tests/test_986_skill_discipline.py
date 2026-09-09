"""#986 M1 + M2 — the two prose mechanisms are PRESENT in the surfaces the agent reads.

ADDED BY THE ADVERSARY PASS. Without this file an implementer can build #986's oracle, green
every other test, close the PR, and have changed nothing about what the agent does — M1 and M2
are the two mechanisms that actually cause the behaviour O1 measures, and the red team shipped
neither while the gate stayed as green as the honest tree.

WHAT THESE TESTS CAN AND CANNOT DO, stated plainly because the line matters:

  * They CANNOT check that the model obeys the rule. Whether a run writes the sibling contract
    is a live-trial question, and the design puts it in `experiments/` at N >= 12 for exactly
    that reason. Pinning it in CI would be pinning a model.
  * They CAN check the rule is still there to be read. That is not a formality: the failure
    mode is a later edit that reflows the paragraph and drops the clause, after which the
    experiment's baseline no longer means what its write-up says it means.

This is the repo's own idiom, not an invention — `test_gather_template_discovery.py`'s d15/d16
read `skills/gather/SKILL.md` and assert on substrings for the same reason, and d16's docstring
records the exact failure it exists to catch: "this test passed on #611's branch only because
the SKILL still taught the dead flag".

ANCHORS ARE CHOSEN TO SURVIVE REWORDING. Each assertion below names the load-bearing NOUN of
the rule rather than a sentence, so the prose stays editable and only DELETING the rule goes
red. A test that pinned whole sentences would be red on every copy-edit, which is how a
prose guard earns its way into being deleted.

PATHS ARE RESOLVED FROM `__file__`, deliberately. `test_tacit_authz_hardening_991.py` reads
`Path("defender/skills/invlang/SKILL.md")` relative to the working directory while CI runs
pytest from `defender/`; run alone it raises `FileNotFoundError` on `main` today and passes in
the full suite only because some earlier test leaves the process somewhere convenient. A guard
that holds by luck is not a guard.
"""
from __future__ import annotations

from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[1]

MAIN_SKILL = DEFENDER / "SKILL.md"
INVLANG_SKILL = DEFENDER / "skills" / "invlang" / "SKILL.md"


def _text(path: Path) -> str:
    """The file lowercased with every run of whitespace collapsed to one space.

    WITHOUT the collapse these anchors are hostage to line wrapping: `undischarged contract`
    is one phrase to a reader and two lines to `in`, so re-wrapping the paragraph — which
    changes nothing about the rule — turns the guard red and teaches the next editor that the
    guard is noise. A prose guard that cries wolf on a reflow does not survive to catch the
    deletion it exists for."""
    return " ".join(path.read_text(encoding="utf-8").lower().split())


def test_the_main_skill_says_a_discharge_covers_only_the_subject_the_claim_names():
    """CLAIM (M1 -> O1, O2): the coarse-to-fine contract rule is in the surface MAIN reads.

    The defect #986 was filed on: all nine runs discharged every authz contract against the
    alert-envelope host, and nothing in the skill said that a discharge against the coarser
    subject fails to cover the finer one. The only loop-back rule fires on an UNANSWERED
    contract (C11), never on a wrongly-subjected one, so a run that resolved the container had
    no rule telling it anything was still owed."""
    text = _text(MAIN_SKILL)
    assert "the subject its claim names" in text, (
        "the rule that a contract answers about the subject its claim names is gone from "
        "SKILL.md — with it goes the only thing that makes a moved subject owe anything"
    )
    assert "changes what the subject is" in text, (
        "the rule no longer names its own trigger. The trigger is a lead CHANGING THE "
        "SUBJECT — sharpening, replacing or splitting it — not the container case that "
        "prompted it; an anchor on the example would survive the rule being narrowed back "
        "to that one shape, which is the regression worth catching"
    )


def test_the_main_skill_says_the_lead_that_moved_the_subject_declares_a_new_contract():
    """CLAIM (M1 -> O1): the rule names the ACTION owed, not just the gap.

    Naming the gap without naming the repair is what the tried-and-rejected frontier
    intervention did (#994): it reported what was open and changed what the run RECORDED, not
    what it ASKED next. The re-ask only happens because a fresh undischarged contract blocks
    the close, so the instruction to DECLARE one is the load-bearing half."""
    text = _text(MAIN_SKILL)
    assert "declare a new `authz?` contract" in text, (
        "the ACTION the rule owes — declaring a fresh contract naming the subject as it is "
        "now understood — is gone. Naming the gap without naming the repair is what the "
        "tried-and-rejected frontier intervention did: it changed what runs RECORDED and "
        "not what they ASKED next"
    )
    assert "it is undischarged" in text, (
        "the rule no longer says why the new contract does anything — being undischarged is "
        "what makes the existing machinery force the re-ask, and without that clause the "
        "rule is an observation rather than an instruction"
    )


def test_the_invlang_skill_puts_a_resolved_name_in_ident_and_not_in_an_attribute():
    """CLAIM (M2 -> O3): the name-as-attribute habit is refused where the keys are documented.

    Three of nine runs parked the resolved container name in an `attrs.*` cell — twice on the
    HOST rather than on the container — while the container's own `ident` still held the raw
    id. The `attr_updates` key guidance lists `ident` as legal and never said it was the right
    one for a name, so the habit was not contradicted anywhere."""
    text = _text(INVLANG_SKILL)
    assert "neither is where its identifier goes" in text, (
        "the rule that an `attrs.*` cell — on the entity or on its host — is not where a "
        "resolved NAME goes is gone from invlang/SKILL.md. Two anchors were tried and "
        "REJECTED for being unable to fail: `key=ident`, which the attr_updates key guidance "
        "has spelled since long before #986, and `sharpen the vertex`, which §Open questions "
        "already contains inside `sharpen the vertex's identifier` — invisible to a raw "
        "substring test only because the base file happens to wrap that phrase across two "
        "lines. An anchor that predates the rule cannot go red when the rule is deleted"
    )
    assert "attrs.container_name" in text, (
        "the worked counter-example is gone — the guidance names a legal key without saying "
        "which cell a resolved NAME belongs in, which is the state #986 was filed against"
    )
    assert "is not a name" in text, (
        "the CONVERSE half is gone: an opaque token is not a name, so it belongs in an "
        "attribute with `ident` left open. That is the half that actually keeps the open "
        "question visible — a run that closes `ident` over a raw id looks resolved to every "
        "mechanism built to surface an unresolved identity, which is why the lesson lane was "
        "dark on the runs this issue was filed from"
    )
