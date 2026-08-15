"""#750 — the disposition vocabulary reaches the model STRUCTURALLY, and the host still gates.

Today the four members reach the model only as prose: a hand-maintained literal in the close
tool's docstring, which *is* the tool schema's `description`. #806 adding `false-positive` was a
manual multi-site sync, and `lint_borrowed_vocabulary` names bare literals as its own blind spot.
The change under test derives the tool argument's schema from `defender._vocab` — the vocabulary's
one owner — and deletes the prose copy.

The two halves have to be pinned TOGETHER, because each one is dangerous without the other:

  * the schema must ADVERTISE the vocabulary (O1) — asserted against `DISPOSITION_VALUES` itself,
    never against a list of members re-typed here, so a fifth member that lands without the schema
    following fails this file;
  * the schema must NOT BECOME THE GATE (NU2). `json_schema_extra` is a hint pydantic does not
    validate against, and the design depends on that: if the framework ever rejected the argument
    first, the membership test in `_close_investigation_async` (named, never cited by line
    number — a line number rots on the next edit above it) would become unreachable from the
    tool lane, the SYNC host entry (which never passes through tool-argument validation at all)
    would be left ungated, and #722's exact retry text — the one that renders an invisible
    character visibly — would be replaced by a framework message that echoes the value raw.

Hermetic: the model is a `FunctionModel` replaying scripted turns (`tests/e2e/_replay_harness`),
and the close's four review stages are the shared no-provider bundle. Both enter through the
entry point's own injection seams (`register_close_tool(stages=…, bounds=…)`,
`close_investigation(stages=…, bounds=…)`) — no `monkeypatch.setattr`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.exceptions import ModelRetry  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender._vocab import DISPOSITION_VALUES  # noqa: E402
from defender.agents import MAIN_DEF  # noqa: E402
from defender.runtime import challenge_gate  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.close_tool import (  # noqa: E402
    STANDS,
    close_investigation,
    register_close_tool,
)
from defender.runtime.tools import AgentDeps  # noqa: E402
from defender.tests._review_bundle import bundle, composer_reply  # noqa: E402
from defender.tests.e2e._replay_harness import ToolRoster, Turn  # noqa: E402

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures-e2e" / "golden-v2sshd"

#: The #722 case: a zero-width space inside an otherwise valid member. It renders as `benign`
#: to every human reader and to every terminal, and it is not one.
#: Spelled with the escape rather than the character itself, so an editor, a diff or a copy
#: through a terminal cannot silently strip the thing under test.
LACED = "beni\u200bgn"

#: What a value outside the vocabulary looks like when it is nearly inside it. Case, trailing
#: whitespace, the invisible character, a superstring, and nothing at all — each one is a
#: distinct way a model reading attacker-influenced alert data lands off the enum.
NEAR_MISSES = ("Benign", "benign ", LACED, "totally-benign", "")


def _deps(tmp_path: Path):
    """MAIN's deps through the REAL `bind` seam — the real compiled policy, the real gate."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "alert.json").write_bytes((GOLDEN / "alert.json").read_bytes())
    (run_dir / "investigation.md").write_bytes((GOLDEN / "investigation.md").read_bytes())
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    return bind(MAIN_DEF, run_dir, defender_dir=dfn), run_dir


def _stages():
    """The close's four review stages, answering without a provider."""
    return bundle(composer=composer_reply(finding="holds"))


def _drive_tool(tmp_path: Path, disposition: str | None = None):
    """Register the REAL close tool on an agent and run it against a scripted model.

    With `disposition` given, the model's first turn calls the tool with that value and its
    second turn is text (so a `ModelRetry` has somewhere to land and the run terminates).
    With no `disposition`, the model never calls the tool — enough to observe the roster.

    Returns `(script, run_dir)`; `script.tool_defs` is the advertised roster and `script.seen`
    is every string the model was handed, which is where retry feedback shows up.
    """
    deps, run_dir = _deps(tmp_path)
    turns = [Turn(text="reading the alert")]
    if disposition is not None:
        turns = [
            Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
            Turn(text="acknowledged; stopping"),
        ]
    script = ToolRoster(turns)
    agent = Agent(FunctionModel(script), deps_type=AgentDeps)
    register_close_tool(agent, stages=_stages(), bounds=challenge_gate.default_bounds())
    with override_allow_model_requests(False):
        agent.run_sync("close this investigation", deps=deps)
    assert script.tool_defs is not None, "the model was never called"
    return script, run_dir


def _close_tool_def(script: ToolRoster):
    """The one tool `register_close_tool` put in front of the model."""
    defs = script.tool_defs or []
    names = [t.name for t in defs]
    assert names == ["close_investigation"], (
        f"the close tool is not the registered roster: {names}"
    )
    return defs[0]


def _disposition_property(tool_def) -> dict:
    """The `disposition` argument's own schema, following a `$ref` if the annotation made one.

    A `StrEnum` annotation would advertise the vocabulary through `$defs`; the `Annotated`
    alias inlines it. Both are "the model was told the members", so the indirection is resolved
    here rather than being what the assertion accidentally turns on.
    """
    schema = tool_def.parameters_json_schema
    prop = schema.get("properties", {}).get("disposition")
    assert prop is not None, (
        f"the tool advertises no `disposition` argument at all: {schema}"
    )
    ref = prop.get("$ref")
    if ref:
        prop = schema.get("$defs", {}).get(ref.rsplit("/", 1)[-1], {})
    return prop


# ═══════════════════════════════════════════════════════════════════════════
# O1 — the vocabulary is stated to the model structurally, derived from its owner.
# ═══════════════════════════════════════════════════════════════════════════


def test_the_registered_tool_advertises_the_owners_vocabulary(tmp_path):
    """O1. The schema the MODEL is offered carries `DISPOSITION_VALUES`, in the owner's order.

    Compared against `_vocab` itself rather than against a literal list re-typed here: a test
    that spelled the four members would be a fifth copy of the very thing this issue exists to
    delete, and it would keep passing on the day a fifth member lands and the schema does not
    follow. With the comparison pointed at the owner, that day fails here.

    Positive control: the owner is non-empty, so an emptied vocabulary cannot make an empty
    `enum` (or an absent one read as `[]`) satisfy this.
    """
    script, _run_dir = _drive_tool(tmp_path)
    prop = _disposition_property(_close_tool_def(script))

    assert DISPOSITION_VALUES, "the vocabulary owner is empty; the comparison below is vacuous"
    assert prop.get("enum") == list(DISPOSITION_VALUES), (
        "the model is not told the disposition vocabulary structurally — the schema's enum is "
        f"{prop.get('enum')!r}, the owner's members are {list(DISPOSITION_VALUES)!r}. The "
        f"whole advertised argument schema is {prop!r}"
    )


def test_the_tool_description_no_longer_copies_the_member_list(tmp_path):
    """D3 (serving O1). The prose copy of the vocabulary is gone from the tool's description.

    Asserted as "not all of the members appear as literals" rather than as an exact string:
    `false-positive` legitimately survives in the sentence about the `detection_notes` +
    `entity_check` rows it requires, and pinning the exact replacement wording would make this
    a diff test. What must not survive is the ENUMERATION — the hand-maintained list that #806
    had to sync by hand.

    Positive control: the description is still a real description. A tool whose docstring was
    deleted outright would satisfy the absence above while telling the model nothing.
    """
    script, _run_dir = _drive_tool(tmp_path)
    description = _close_tool_def(script).description or ""

    assert "disposition" in description, (
        f"the close tool's description no longer describes the close: {description!r}"
    )
    assert len(description) > 100, (
        f"the close tool's description was emptied rather than trimmed: {description!r}"
    )
    copied = [member for member in DISPOSITION_VALUES if member in description]
    assert len(copied) <= 1, (
        "the tool description still enumerates the vocabulary "
        f"({copied!r}) — the schema's enum is where the members now live, and a second copy "
        "is the hand-synced surface this change removes. ONE member may survive as prose "
        "about its own entry price; two or more is a list, whatever it is punctuated as"
    )


# ═══════════════════════════════════════════════════════════════════════════
# NU2 — the hint must not become the gate.
# ═══════════════════════════════════════════════════════════════════════════


def test_the_schema_hint_is_not_the_gate(tmp_path):
    """NU2. With the enum advertised, an out-of-enum value STILL reaches the tool body.

    This pins a framework behavior the design leans on: pydantic does not validate against
    `json_schema_extra`, so the advertised enum is a hint to the model and the membership test
    in `_close_investigation_async` remains the sole rejecter. If a future pydantic (or a future
    annotation — a `Literal`, a `StrEnum`) rejected the argument first, three things break
    silently at once: the host check becomes unreachable from the tool lane, the SYNC entry that
    never sees tool-argument validation is left as the only ungated lane, and the retry text
    stops being ours.

    The discriminator is WHOSE refusal came back. The host's message is written by
    `_close_investigation_async` and nothing else in the stack produces it, so its presence is
    the evidence the body ran; a framework rejection would instead hand the model a validation
    error it never wrote.

    The first assertion is the premise, not decoration: without the advertised enum this test
    would pass vacuously, pinning nothing about a hint that is not there.
    """
    script, run_dir = _drive_tool(tmp_path, disposition="Benign")
    prop = _disposition_property(_close_tool_def(script))
    assert prop.get("enum") == list(DISPOSITION_VALUES), (
        "no enum is advertised, so this test cannot say whether the hint stayed a hint"
    )

    seen = "\n".join(script.seen)
    assert "a typed enum, not free text" in seen, (
        "the host's own refusal never reached the model — the argument was rejected before the "
        "tool body ran, which leaves the membership test in `_close_investigation_async` "
        f"unreachable from this lane. Saw: {seen!r}"
    )
    assert "Input should be" not in seen, (
        "a pydantic validation error came back instead of the host's refusal — the schema "
        f"hint became the gate. Saw: {seen!r}"
    )
    assert not (run_dir / "report.md").exists(), "an out-of-enum close committed a report"


# ═══════════════════════════════════════════════════════════════════════════
# O2 — no value outside the vocabulary commits, by EITHER entry path.
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("disposition", NEAR_MISSES)
def test_the_sync_host_entry_refuses_every_near_miss(tmp_path, disposition):
    """O2, the lane with no tool-argument validation anywhere in front of it.

    `close_investigation()` is reached directly by hosts and tests; nothing about the model's
    tool schema is between a caller and this function, which is exactly why the refusal has to
    live in the body. Each near miss is a distinct way off the enum — case, trailing space, an
    invisible character, a superstring, nothing at all.
    """
    deps, run_dir = _deps(tmp_path)

    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, disposition, stages=_stages())

    assert "disposition must be exactly one of" in str(excinfo.value)
    assert not (run_dir / "report.md").exists(), (
        f"{disposition!r} committed a disposition through the sync host entry"
    )


@pytest.mark.parametrize("disposition", [["benign"], {"disposition": "benign"}, 1, None])
def test_the_sync_host_entry_denies_a_non_string_rather_than_crashing(tmp_path, disposition):
    """O2's unhashable arm, and the one near miss the string list above cannot express.

    `DISPOSITION_ENUM` is a frozenset, so a bare `value in DISPOSITION_ENUM` raises `TypeError`
    on an unhashable value instead of denying — the crash `_vocab.normalized_disposition`
    documents and `_artifact_schema` guards with an `isinstance` test one layer later. The tool
    lane cannot deliver one (pydantic validates the argument as `str`), so this lane is the only
    place the guard can be observed, and it is the lane with nothing in front of it.
    """
    deps, run_dir = _deps(tmp_path)

    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, disposition, stages=_stages())

    assert "disposition must be exactly one of" in str(excinfo.value)
    assert not (run_dir / "report.md").exists()


def test_a_member_of_the_vocabulary_still_closes(tmp_path):
    """O2's positive control, and it belongs to the same lane.

    Every refusal above would hold just as well if the close were simply broken in this
    fixture. `inconclusive` bypasses the review gate, so this arm asserts the sync entry can
    still commit — which is what makes the refusals evidence about the vocabulary.
    """
    deps, run_dir = _deps(tmp_path)

    result = close_investigation(deps, "inconclusive", stages=_stages())

    assert result.outcome == STANDS
    assert (run_dir / "report.md").exists(), "a valid disposition did not commit"


def test_the_tool_lane_refuses_a_value_outside_the_vocabulary(tmp_path):
    """O2, the model-facing lane, driven end to end through the registered tool.

    The refusal has to come back as retry FEEDBACK — a value the model can act on — rather
    than as an exception out of the run, and nothing may reach `report.md` on the way.
    """
    script, run_dir = _drive_tool(tmp_path, disposition="totally-benign")

    seen = "\n".join(script.seen)
    assert "disposition must be exactly one of" in seen, (
        f"the model was never told why its close was refused. Saw: {seen!r}"
    )
    assert not (run_dir / "report.md").exists(), (
        "an out-of-vocabulary disposition committed a report through the tool lane"
    )


def test_a_member_of_the_vocabulary_commits_through_the_tool_lane(tmp_path):
    """O2's positive control on the MODEL-FACING lane, and it has to be on this lane.

    The sync entry's control says the CLOSE works; it says nothing about the registration.
    Every "nothing reached report.md" above would hold just as well if the registered tool
    could not commit at all — `stages`/`bounds` threaded wrong through the closure, or a
    close whose write never happens — and each of those passes the refusals while breaking
    the only lane a real run uses. `inconclusive` bypasses the review gate, so this arm
    needs no live stage to say the lane can still write.
    """
    script, run_dir = _drive_tool(tmp_path, disposition="inconclusive")

    seen = "\n".join(script.seen)
    assert "disposition must be exactly one of" not in seen, (
        f"a member of the vocabulary was refused on the tool lane. Saw: {seen!r}"
    )
    report = run_dir / "report.md"
    assert report.exists(), "a valid disposition did not commit through the tool lane"
    assert "disposition: inconclusive" in report.read_text(encoding="utf-8"), (
        f"the committed report does not carry the disposition: {report.read_text()!r}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# O3 — the refusal distinguishes an invisible character from a valid value.
# ═══════════════════════════════════════════════════════════════════════════


def test_the_refusal_escapes_an_invisible_character_rather_than_echoing_it(tmp_path):
    """O3 (#722). `beni<U+200B>gn` comes back repr-escaped, on both lanes.

    This is the reason the write gates stay exact instead of normalizing: the author is still
    on the other end of the call, and retry text that echoed the value RAW would read as
    "disposition must be exactly one of [...] (got 'benign')" — a message that tells the model
    its correct-looking answer was wrong for no visible reason, which is a loop it cannot exit.
    `!r` renders the character as `\\u200b`; the assertions below are that both halves hold —
    the escaped form present, the raw one absent.
    """
    deps, run_dir = _deps(tmp_path)

    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, LACED, stages=_stages())
    message = str(excinfo.value)

    assert repr(LACED) == "'beni\\u200bgn'", (
        "python's repr no longer escapes U+200B, so the assertions below are about the wrong "
        "thing — the retry text needs another way to make the character visible"
    )
    assert "'beni\\u200bgn'" in message, (
        f"the refusal does not show the invisible character: {message!r}"
    )
    assert LACED not in message, (
        "the refusal echoes the laced value raw, so the model reads its own rejected answer "
        f"as identical to a valid one: {message!r}"
    )
    assert not (run_dir / "report.md").exists()

    # The same text, on the lane the model actually reads it from.
    script, tool_run_dir = _drive_tool(tmp_path / "tool", disposition=LACED)
    seen = "\n".join(script.seen)
    assert "'beni\\u200bgn'" in seen, (
        f"the model was handed a refusal that hides the character it must fix: {seen!r}"
    )
    # BOTH halves on this lane too, not just the escaped one: an escaped copy alongside a raw
    # echo still hands the model a rejected answer that reads identical to a valid one, and
    # this is the lane the model actually reads. `ToolCallPart` carries no `content`, so the
    # model's own laced argument is not what this would be seeing.
    assert LACED not in seen, (
        "the model was handed the laced value raw, so its rejected answer reads as identical "
        f"to a valid one: {seen!r}"
    )
    assert not (tool_run_dir / "report.md").exists()
