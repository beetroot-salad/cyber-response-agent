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

import sys
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[1]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

MAIN_SKILL = DEFENDER / "SKILL.md"
INVLANG_SKILL = DEFENDER / "skills" / "invlang" / "SKILL.md"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").lower()


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
        "SKILL.md — with it goes the only thing that makes a resolved container owe anything"
    )
    assert "finer" in text, (
        "the coarse-to-fine resolution the rule is about is no longer described"
    )


def test_the_main_skill_says_the_resolving_lead_declares_a_contract_naming_the_finer_entity():
    """CLAIM (M1 -> O1): the rule names the ACTION owed, not just the gap.

    Naming the gap without naming the repair is what the tried-and-rejected frontier
    intervention did (#994): it reported what was open and changed what the run RECORDED, not
    what it ASKED next. The re-ask only happens because a fresh undischarged contract blocks
    the close, so the instruction to DECLARE one is the load-bearing half."""
    text = _text(MAIN_SKILL)
    assert "undischarged contract" in text, (
        "the mechanism that turns the new contract into a re-ask — an undischarged contract "
        "blocking a confident close — is no longer stated where the rule is"
    )
    assert "privilege edge" in text, (
        "the rule no longer tells the resolving lead to write the privilege edge to the "
        "finer entity, which is O2's half of the record repair"
    )


def test_the_invlang_skill_puts_a_resolved_name_in_ident_and_not_in_an_attribute():
    """CLAIM (M2 -> O3): the name-as-attribute habit is refused where the keys are documented.

    Three of nine runs parked the resolved container name in an `attrs.*` cell — twice on the
    HOST rather than on the container — while the container's own `ident` still held the raw
    id. The `attr_updates` key guidance lists `ident` as legal and never said it was the right
    one for a name, so the habit was not contradicted anywhere."""
    text = _text(INVLANG_SKILL)
    assert "key=ident" in text, "the ident refinement key is no longer documented at all"
    assert "attrs.container_name" in text, (
        "the worked counter-example is gone — the guidance names a legal key without saying "
        "which cell a resolved NAME belongs in, which is the state #986 was filed against"
    )
