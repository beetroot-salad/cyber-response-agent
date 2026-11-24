"""#1592 S3-24: the amendments to `defender/CLAUDE.md` a test can read: the "Upgrade from before #1592" section and its
eight steps, the restore step, the lab wiring, the #1414 notes without a freshness bound, and the reworded F9 sentence."""
from __future__ import annotations

import re
from pathlib import Path

NOTES = Path(__file__).resolve().parents[3] / "CLAUDE.md"
TEXT = NOTES.read_text("utf-8")

#: The design's eight steps, each as a phrase its line must carry, in order.
STEPS = (
    r"pending|finish",                       # 1. let every pending action and host request finish
    r"organisation|organization",            # 2. per tenant: the organisation `t-<T>`, transfer, rename
    r"sessions setup|forgejo-sessions|sessions database",  # 3. the sessions setup script and the two logins
    r"migrat",                               # 4. migrate (0027)
    r"start the lifecycle|start the management service|start .{0,20}lifecycle",  # 5. start
    r"rotate",                               # 6. rotate each tenant
    r"resync-people",                        # 7. resync-people
    r"hand-made|delete .{0,40}accounts",     # 8. delete the hand-made accounts
)


def _section() -> str:
    found = re.search(r"^## Upgrade from before #1592\b.*?(?=^## |\Z)", TEXT, re.S | re.M)
    assert found, "the notes have no `## Upgrade from before #1592` section"
    return found.group(0)


def test_1592_the_upgrade_section_has_the_eight_steps_in_order():
    """S3-24: each of the design's steps is in the section, in the design's order."""
    section = _section()
    at = 0
    for step in STEPS:
        found = re.search(step, section[at:], re.I)
        assert found, f"step {step!r} is missing or out of order"
        at += found.end()


def test_1592_the_upgrade_section_names_the_wiring_the_migration_demands_and_the_repository_move():
    """S3-24: the section names `t-<T>/knowledge` and the `0027` migration's refusals."""
    section = _section()
    assert re.search(r"t-<[^>]+>/knowledge", section), section
    assert "0027" in section or "migration" in section.lower()


def test_1592_the_restore_procedure_runs_resync_people():
    """S3-24 / F6(c): outside the upgrade section too, the notes tell the operator to run `python -m defender.lifecycle
    resync-people` after a restore."""
    outside = TEXT.replace(_section(), "")
    assert re.search(r"python -m defender\.lifecycle resync-people", outside), "no restore step runs resync-people"


def test_1592_the_lab_procedure_wires_the_knowledge_repository_under_the_tenants_organisation():
    """S3-24: the lab wiring step names `t-<T>/knowledge`, not `tenants/<T>`."""
    outside = TEXT.replace(_section(), "")
    assert re.search(r"t-<[^>]+>/knowledge", outside), "the lab procedure does not name the new wiring"
    assert not re.search(r"wiring[^\n]{0,80}tenants/<", outside), "the lab procedure still names `tenants/<T>`"


def test_1592_the_1414_notes_no_longer_carry_the_record_or_its_freshness_bound():
    """S3-24 / OD-6: no `merge_eligibility`, `LEARNING_FEEDBACK_ELIGIBILITY_MAX_AGE` or record-freshness wording remains."""
    for gone in ("merge_eligibility", "LEARNING_FEEDBACK_ELIGIBILITY_MAX_AGE", "eligibility_max_age", "MergeEligibility"):
        assert gone not in TEXT, gone
    assert not re.search(r"eligibility record", TEXT, re.I)


def test_1592_the_removed_1471_paragraph_no_longer_says_revert_lesson_stays():
    """S3-24 / F9: the "Removed (#1471)" paragraph is reworded: `revert_lesson.py` is not kept."""
    assert "revert_lesson.py` stays" not in TEXT
    assert "revert_lesson.py stays" not in TEXT
