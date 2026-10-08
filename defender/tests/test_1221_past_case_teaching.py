"""#1221 O4 — both model hops are taught what a tagged comment is.

The design (issue #1221, D2/M4): nothing mechanical checks that a served agent comment is cited
as a past case (N1); the teaching is the control, and it spans two hops.

  * gather reads ticket replies. Its system prompt (`skills/gather/SKILL.md`, loaded whole by
    `runtime.driver._gather_instructions`) must say that a comment opening with the agent tag
    is a model-made verdict from the named run, and that it is reported as such with the run
    id — never as a person's finding.
  * MAIN writes invlang and never sees raw replies. Its grammar (`skills/invlang/SKILL.md`,
    inlined into MAIN's orientation by `runtime.orient`) must say that such a precedent is
    cited `grounding past-case`, `cites_past_case <run id>`.

Both quote the tag's prefix verbatim (`case_ticket.AGENT_TAG_PREFIX`, the one definition), so
the words the model is taught are the words it will read in a reply. Neither teaching may live
only in the lab's ticket adapter doc (`skills/ticket/SKILL.md`), which #1172 moves out.

Asserted on the text the product's own prompt builders hand the model, not on the files.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from defender._paths import PATHS
from defender.runtime import case_ticket, orient
from defender.runtime.driver import _gather_instructions
from defender.tests._spec767 import require

DEFENDER = PATHS.defender_dir


def _prefix() -> str:
    return require(case_ticket, "AGENT_TAG_PREFIX",
                   "#1221 M1: the agent tag's fixed prefix, which the teaching quotes")


def _paragraphs_naming(text: str, needle: str) -> list[str]:
    """The blank-line-separated blocks of `text` that contain `needle`."""
    return [p for p in re.split(r"\n\s*\n", text) if needle in p]


def _main_orientation(tmp_path: Path) -> str:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"rule": {"id": "5710"}}), encoding="utf-8")
    return orient.orientation(run_dir, DEFENDER, alert, systems=())


def test_1221_gather_is_taught_that_a_tagged_comment_is_a_past_case():
    """Gather's system prompt quotes the agent tag's prefix verbatim, and the passage that does
    tells it to report the run id the tag names."""
    prompt = _gather_instructions(DEFENDER)
    prefix = _prefix()
    assert prefix in prompt, (
        f"gather's system prompt never quotes the agent tag {prefix!r}: gather reads the "
        "replies, so nothing tells it a tagged comment is model-made"
    )
    taught = _paragraphs_naming(prompt, prefix)
    assert any(re.search(r"run[\s_-]*id", p, re.I) for p in taught), (
        "the passage quoting the tag never says to report the run id it names"
    )


def test_1221_main_is_taught_to_cite_a_tagged_precedent_as_past_case(tmp_path):
    """MAIN's orientation — the invlang grammar it writes from — quotes the agent tag's prefix
    verbatim, in a passage that names both cells the citation is written with:
    `grounding past-case` and `cites_past_case`."""
    text = _main_orientation(tmp_path)
    assert "## invlang grammar" in text, "the control failed: the grammar was not inlined"
    prefix = _prefix()
    taught = _paragraphs_naming(text, prefix)
    assert taught, (
        f"MAIN's invlang grammar never quotes the agent tag {prefix!r}, so a precedent gather "
        "marked model-made has no taught citation"
    )
    assert any("past-case" in p and "cites_past_case" in p for p in taught), (
        "the passage quoting the tag does not teach `grounding past-case` with "
        "`cites_past_case`"
    )

