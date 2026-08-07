"""#796 — reading what the lenses and the composer return, and the role prompts they run under."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from defender.runtime.review import role_prompt
from defender.runtime.review.projector import parse_investigation
from defender.runtime.review.reply import (
    ASK_PROSE_MAX,
    GAP,
    HOLDS,
    Unreadable,
    citable_refs,
    read_composer_reply,
    read_lens_reading,
)
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)

DEFENDER = Path(__file__).resolve().parents[1]
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3" / "investigation.md"
ROLES = ("support", "composer")


@pytest.fixture(scope="module")
def refs():
    return citable_refs(parse_investigation(GOLDEN.read_text(encoding="utf-8")))


def _reply(review="the close holds", ask=None, finding=None):
    if finding is None:
        finding = HOLDS if ask is None else GAP
    return json.dumps({"finding": finding, "review": review, "ask": ask})


# ---------------------------------------------------------------------------------------
# Role prompts
# ---------------------------------------------------------------------------------------


def test_every_role_has_a_prompt_asset():
    for name in ROLES:
        assert role_prompt(name).strip(), f"{name} has an empty role prompt"


def test_an_unknown_role_raises_rather_than_running_promptless():
    with pytest.raises(FileNotFoundError):
        role_prompt("challenger")


def test_no_role_prompt_names_an_issue_number():
    """The retired stages shared one system instruction and it opened by naming an issue
    number, which names nothing to a model — it was the only role description they had."""
    for name in ROLES:
        found = re.findall(r"#\d{3,}", role_prompt(name))
        assert not found, f"{name}.md names {found}"


def _flat(name: str) -> str:
    """The prompt with its line wrapping collapsed — these assertions are about what a role
    is told, and where the asset happens to wrap is not part of that."""
    return " ".join(role_prompt(name).split())


def test_each_lens_prompt_states_what_it_cannot_see():
    """The blindness is the mechanism. A lens that does not know it is blind asks for the
    missing half instead of reaching a reading without it."""
    assert "do not see" in _flat("support")


def test_the_composer_is_told_it_cannot_argue_the_opposite_disposition():
    assert "opposite disposition" in _flat("composer")


# ---------------------------------------------------------------------------------------
# Lens readings — the fail-open guard
# ---------------------------------------------------------------------------------------


def test_a_lens_reading_survives_intact():
    assert read_lens_reading("  l-003 separates h-001 from h-002.  ") == (
        "l-003 separates h-001 from h-002."
    )


@pytest.mark.parametrize("empty", [None, "", "   ", "\n\t "])
def test_an_empty_lens_reading_is_refused(empty):
    """The fail-open read the retired gate shipped: everything that was not the expected word
    was taken as the permissive value, so an empty reply let a confident close through on a
    reading nothing had made. A composer handed silence weighs it as agreement."""
    with pytest.raises(Unreadable):
        read_lens_reading(empty)


# ---------------------------------------------------------------------------------------
# The composer's reply
# ---------------------------------------------------------------------------------------


def test_a_review_with_no_ask_is_readable(refs):
    got = read_composer_reply(_reply(), refs=refs)
    assert got.ask is None
    assert got.review == "the close holds"


def test_an_absent_ask_reads_the_same_as_a_null_one(refs):
    """Readable-and-empty keeps its own arm. "Nothing measurable would settle this" is a
    finding the host routes on, not a reply that failed to arrive."""
    assert read_composer_reply(json.dumps({"finding": HOLDS, "review": "holds"}), refs=refs).ask is None


def test_an_ask_naming_a_real_reference_is_readable(refs):
    target = sorted(refs)[0]
    got = read_composer_reply(
        _reply(ask={"target": target, "prose": "script provenance"}), refs=refs,
    )
    assert got.ask is not None
    assert got.ask.target == target
    assert got.ask.prose == "script provenance"


def test_an_ask_naming_an_invented_reference_is_refused(refs):
    """The invented-identifier guard. Unbounded, a hallucinated id is handed back to the
    investigator as work to go do — the forced turn's economy inverted, with the gate
    charging the investigation for a hallucination."""
    with pytest.raises(Unreadable, match="never recorded"):
        read_composer_reply(
            _reply(ask={"target": "v-hallucinated", "prose": "provenance"}), refs=refs,
        )


def test_the_ask_prose_is_bounded(refs):
    """Model-authored text on the channel that returns to the live session."""
    target = sorted(refs)[0]
    got = read_composer_reply(
        _reply(ask={"target": target, "prose": "x" * (ASK_PROSE_MAX * 3)}), refs=refs,
    )
    assert got.ask is not None
    assert len(got.ask.prose) == ASK_PROSE_MAX


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "not json at all",
        "[]",
        '"a string"',
        json.dumps({"finding": HOLDS, "ask": None}),
        json.dumps({"finding": HOLDS, "review": "", "ask": None}),
        json.dumps({"finding": HOLDS, "review": "   ", "ask": None}),
        json.dumps({"finding": GAP, "review": "r", "ask": "not an object"}),
        json.dumps({"finding": GAP, "review": "r", "ask": {"prose": "no target"}}),
        json.dumps({"finding": GAP, "review": "r", "ask": {"target": "v-001"}}),
        json.dumps({"finding": GAP, "review": "r", "ask": {"target": "v-001", "prose": "  "}}),
        json.dumps({"finding": "maybe", "review": "r", "ask": None}),
    ],
)
def test_every_unusable_composer_reply_is_refused(bad, refs):
    with pytest.raises(Unreadable):
        read_composer_reply(bad, refs=refs)


def test_a_whole_reply_wrapped_in_a_code_fence_is_still_read(refs):
    """The contract asks for one JSON object and nothing else, and a model that packages that
    object in a ```json fence has met it in content and missed it in packaging. Refusing the
    fence fails a confident close CLOSED on formatting, on every close, for as long as the
    model has the habit — and unwrapping it changes nothing that is then validated."""
    for fenced in (
        f"```json\n{_reply()}\n```",
        f"```\n{_reply()}\n```",
        f"  ```json\n{_reply()}\n```  ",
    ):
        assert read_composer_reply(fenced, refs=refs).holds


def test_a_fence_around_prose_is_still_unreadable(refs):
    """The unwrap is anchored at BOTH ends of the whole reply. A fence that merely appears
    inside a reply of prose means the composer answered outside its contract, and that is the
    fail-closed arm rather than something to dig an object out of."""
    with pytest.raises(Unreadable):
        read_composer_reply(f"Here is my answer:\n```json\n{_reply()}\n```\nHope that helps.",
                            refs=refs)


def test_a_finding_of_holds_carrying_an_ask_is_refused(refs):
    """A composer that says the close holds AND asks for a measurement has contradicted
    itself, and either half could be the one it meant. Dropping the ask and committing would
    be the gate choosing for it."""
    target = sorted(refs)[0]
    with pytest.raises(Unreadable, match="holds"):
        read_composer_reply(
            _reply(finding=HOLDS, ask={"target": target, "prose": "provenance"}), refs=refs,
        )


def test_the_finding_decides_the_route_and_not_the_presence_of_an_ask(refs):
    """`holds` and a gap nothing can settle both carry no ask and route to opposite outcomes,
    which is the whole reason the finding is a field rather than something the host derives."""
    holds = read_composer_reply(_reply(finding=HOLDS), refs=refs)
    gap = read_composer_reply(_reply(finding=GAP, review="a live sibling remains"), refs=refs)
    assert holds.ask is None
    assert gap.ask is None
    assert holds.holds
    assert not gap.holds


# ---------------------------------------------------------------------------------------
# The citable set
# ---------------------------------------------------------------------------------------


def test_the_citable_set_spans_every_kind_a_review_may_name(refs):
    """An ask may name an entity or a hypothesis, not only a lead — which is exactly why the
    retired guard, keyed on executed leads alone, does not generalise."""
    for prefix in ("v-", "e-", "h-", "l-"):
        assert any(r.startswith(prefix) for r in refs), f"no {prefix}* id is citable"
