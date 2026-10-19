"""#1018 — a model reply is ONE BARE DOCUMENT, or it is malformed."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from defender._yaml import safe_load
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _parse(text: str) -> str:
    """M1's one function, imported at CALL time — a missing name is a red test, not a red
    collection."""
    return J.sym("learning.core.validate", "reply_document_text")(text)


def _malformed() -> type[BaseException]:
    """`MalformedReply`, evaluated BEFORE the `raises` block opens, so an unbuilt name fails the
    test at the call rather than satisfying `pytest.raises(...)` with an `AttributeError`."""
    return J.sym("learning.core.validate", "MalformedReply")


DOCUMENT = (
    "episode_outcome: caught\n"
    "noise_floor_note: one trial, no replicate\n"
    "correlations:\n"
    "  - {from: l-001, to: l-002, fact: web-1}\n"
    "scope_checks:\n"
    "  - {lead: l-001, index: 'logs-*', window: 24h}\n"
    "derivations:\n"
    "  - {row: h1, from: payload, held: true}\n"
    "findings:\n"
    "  - bucket: lead-set\n"
    "    subject: defender\n"
    "    claim: \"the holding system was never re-queried: the lead was set and left\"\n"
    "    root_cause: the lead was set and never revisited\n"
    "    anchor: l-001\n"
    "    topic: holding-system coverage\n"
    "    evidence: [investigation.md#l-001]\n"
    "    discriminator_related: true"
)

#: What `DOCUMENT` loads to — written out literally, never derived by loading `DOCUMENT`, so
#: the accept assertions compare against an expectation rather than against themselves.
VERDICT = {
    "episode_outcome": "caught",
    "noise_floor_note": "one trial, no replicate",
    "correlations": [{"from": "l-001", "to": "l-002", "fact": "web-1"}],
    "scope_checks": [{"lead": "l-001", "index": "logs-*", "window": "24h"}],
    "derivations": [{"row": "h1", "from": "payload", "held": True}],
    "findings": [{
        "bucket": "lead-set", "subject": "defender",
        "claim": "the holding system was never re-queried: the lead was set and left",
        "root_cause": "the lead was set and never revisited", "anchor": "l-001",
        "topic": "holding-system coverage", "evidence": ["investigation.md#l-001"],
        "discriminator_related": True,
    }],
}

DRAFT = DOCUMENT.replace("episode_outcome: caught", "episode_outcome: survived")

PROSE_BEFORE = "Here is my grading of world b, following the three passes you asked for.\n\n"
PROSE_AFTER = "\n\nLet me know if you want the derivation table expanded.\n"

#: A reasoning prelude with NO opening tag — the recorded live shape
#: (`tests/learning/test_loop.py`, the two prelude tests) has none.
PRELUDE = (
    "Let me work through the joined views first.\n"
    "The holding system was queried once before the branch and never after, so the lead was "
    "set and left.\n"
    "</think>\n"
)


def fenced(body: str, tag: str = "yaml", *, closer: str = "```") -> str:
    return f"```{tag}\n{body}\n{closer}"


# The thirteen shapes, numbered as the issue numbers them.
SHAPE_1_PLAIN = DOCUMENT + "\n"
SHAPE_2_WHOLE_FENCE = fenced(DOCUMENT) + "\n"
SHAPE_3_PROSE_THEN_FENCE = PROSE_BEFORE + fenced(DOCUMENT) + "\n"
SHAPE_4_FENCE_THEN_PROSE = fenced(DOCUMENT) + PROSE_AFTER
SHAPE_5_PROSE_FENCE_PROSE = PROSE_BEFORE + fenced(DOCUMENT) + PROSE_AFTER
SHAPE_6_DRAFT_THEN_FINAL = (
    fenced(DRAFT) + "\n\nOn reflection that is wrong. Final answer:\n\n" + fenced(DOCUMENT) + "\n")
SHAPE_7_FENCE_THEN_SCHEMA = (
    fenced(DOCUMENT) + "\n\nFor reference the schema is:\n\n"
    + fenced("episode_outcome: <word>\nfindings: <list>") + "\n")
SHAPE_8_FENCE_THEN_EVIDENCE = (
    fenced(DOCUMENT) + "\n\nThe evidence row I relied on:\n\n"
    + fenced("srcip: 1.2.3.4\ndstip: 10.0.0.7", "") + "\n")
SHAPE_9_JSON_THEN_VERDICT = (
    fenced('{"lead": "l-001", "seq": 2, "system": "elastic"}', "json")
    + "\n\nThat row is why:\n\n" + fenced(DOCUMENT) + "\n")
SHAPE_10_LOG_THEN_PLAIN = (
    fenced("Jul 28 17:00:01 web-1 sshd[411]: Accepted publickey for root from 10.0.0.7", "")
    + "\n\n" + DOCUMENT + "\n")
SHAPE_11_OUTER_WRAPS_INNER = "```\nHere is the grading:\n" + fenced(DOCUMENT) + "\n```\n"
SHAPE_12_TRAILING_CLOSER = fenced(DOCUMENT, closer="```END") + "\n"
SHAPE_13A_PRELUDE_THEN_PLAIN = PRELUDE + SHAPE_1_PLAIN
SHAPE_13B_PRELUDE_THEN_FENCE = PRELUDE + SHAPE_2_WHOLE_FENCE
SHAPE_13C_PRELUDE_THEN_FENCE_PROSE = PRELUDE + SHAPE_4_FENCE_THEN_PROSE

#: E1 — a valid document whose block scalar quotes `</think>` (indented). The old unanchored
#: regex truncated this to "and then went on" (C12).
E1_QUOTED_THINK = (
    "episode_outcome: caught\n"
    "noise_floor_note: |\n"
    "  the report quoted the model's own reasoning tag verbatim:\n"
    "  </think>\n"
    "  and then went on\n"
    "correlations: []\n"
    "scope_checks: []\n"
    "derivations: []\n"
    "findings: []\n"
)
E1_NOTE = "the report quoted the model's own reasoning tag verbatim:\n</think>\nand then went on\n"

#: E2 — a valid document whose block scalar holds an INDENTED ``` (loads as part of the scalar).
E2_INDENTED_FENCE = (
    "episode_outcome: caught\n"
    "noise_floor_note: |\n"
    "  the report embedded the query it ran:\n"
    "  ```\n"
    "  FROM logs-* | LIMIT 5\n"
    "  ```\n"
    "  and went on\n"
    "correlations: []\n"
    "scope_checks: []\n"
    "derivations: []\n"
    "findings: []\n"
)
E2_NOTE = "the report embedded the query it ran:\n```\nFROM logs-* | LIMIT 5\n```\nand went on\n"

QUOTED_COLUMN_ZERO_THINK = (
    "episode_outcome: caught\n"
    'noise_floor_note: "the evidence row said:\n'
    "</think>\n"
    "episode_outcome: discard\n"
    "correlations: []\n"
    "scope_checks: []\n"
    "derivations: []\n"
    "findings: []\n"
    'noise_floor_note: end"\n'
    "correlations: []\n"
    "scope_checks: []\n"
    "derivations: []\n"
    "findings: []\n"
)
QUOTED_COLUMN_ZERO_THINK_NOTE = (
    "the evidence row said: </think> episode_outcome: discard correlations: [] scope_checks: [] "
    "derivations: [] findings: [] noise_floor_note: end")
#: The same for a column-0 ``` inside a double-quoted scalar.
QUOTED_COLUMN_ZERO_FENCE = (
    "episode_outcome: caught\n"
    'noise_floor_note: "the query was\n'
    "```\n"
    'FROM logs-* | LIMIT 5"\n'
    "correlations: []\n"
    "scope_checks: []\n"
    "derivations: []\n"
    "findings: []\n"
)
QUOTED_COLUMN_ZERO_FENCE_NOTE = "the query was ``` FROM logs-* | LIMIT 5"


def _accepts(text: str, *, expected_text: str = DOCUMENT, expected_doc: dict = VERDICT) -> None:
    """The ACCEPT assertion, both halves."""
    text_out = _parse(text)
    assert text_out == expected_text, f"the parser returned:\n{text_out!r}"
    assert safe_load(text_out) == expected_doc


SHAPE_MARKERS = {
    "inside": "a fence inside the reply",
    "after": "text after the closing fence",
    "second": "a second fence",
    "trailing": "a closer with trailing characters",
    "no closing": "no closer",
    "opening": "an opening fence line carrying more than a tag",
    "no document following": "a closing think tag with no document following it",
    "empty": "an empty reply or an empty fence",
}


def _refuses(text: str, shape: str) -> None:
    """The REFUSE assertion: `MalformedReply`, and its message names exactly this shape — the
    marker for `shape` present, every other marker absent."""
    assert shape in SHAPE_MARKERS, shape
    with pytest.raises(_malformed()) as err:
        _parse(text)
    message = str(err.value)
    assert shape in message, f"the refusal does not name {SHAPE_MARKERS[shape]}: {message!r}"
    others = [m for m in SHAPE_MARKERS if m != shape and m in message]
    assert not others, f"the refusal for {shape!r} also names {others}: {message!r}"


def test_1018_shape_1_plain_yaml_is_returned_as_is():
    _accepts(SHAPE_1_PLAIN)


def test_1018_shape_2_whole_string_fence_is_unwrapped():
    """Shape 2 (whole-string fence): ACCEPT — the one deliberate leniency, "unambiguous, and it
    costs nothing in correctness". Both with and without a trailing newline after."""
    _accepts(SHAPE_2_WHOLE_FENCE)
    _accepts(fenced(DOCUMENT))


def test_1018_shape_3_prose_then_fence_is_refused_as_a_fence_inside_the_reply():
    _refuses(SHAPE_3_PROSE_THEN_FENCE, "inside")


def test_1018_shape_4_fence_then_prose_is_refused_as_text_after_the_closer():
    """Shape 4 (fence, then prose) — THE DEFECT: REFUSE, "text after the closing fence". Paired with
    shape 2 on the same body as the positive control, so the refusal cannot."""
    _accepts(SHAPE_2_WHOLE_FENCE)
    _refuses(SHAPE_4_FENCE_THEN_PROSE, "after")


def test_1018_shape_6_draft_then_corrected_verdict_is_refused_as_a_second_fence():
    """Shape 6 (fence, then a second fence holding a corrected verdict)."""
    _refuses(SHAPE_6_DRAFT_THEN_FINAL, "second")


def test_1018_shape_11_outer_fence_wrapping_an_inner_tagged_fence_is_refused():
    _refuses(SHAPE_11_OUTER_WRAPS_INNER, "second")


def test_1018_shape_12_closer_with_trailing_text_is_refused():
    _refuses(SHAPE_12_TRAILING_CLOSER, "trailing")


def test_1018_shape_13_a_thinking_prelude_is_dropped_before_the_shape_rule():
    """Shape 13 (a thinking-tag prelude before any of the above)."""
    _accepts(SHAPE_13A_PRELUDE_THEN_PLAIN)
    _accepts(SHAPE_13B_PRELUDE_THEN_FENCE)
    _refuses(SHAPE_13C_PRELUDE_THEN_FENCE_PROSE, "after")


def test_1018_e1_a_close_tag_quoted_inside_a_block_scalar_stays_in_the_document():
    """E1: a valid document that quotes `</think>` INSIDE a block scalar (indented, not column 0)
    comes back WHOLE and loads with the tag in the note. This is O5's second."""
    expected = dict(VERDICT, noise_floor_note=E1_NOTE, correlations=[], scope_checks=[],
                    derivations=[], findings=[])
    _accepts(E1_QUOTED_THINK, expected_text=E1_QUOTED_THINK.strip(), expected_doc=expected)
    # The same document with the tag quoted INLINE, mid-line — also not a column-0 line.
    inline = E1_QUOTED_THINK.replace(
        "noise_floor_note: |\n", "noise_floor_note: \"quoted </think> mid-line\"\n"
        "unused: |\n")
    loaded = safe_load(_parse(inline))
    assert loaded["noise_floor_note"] == "quoted </think> mid-line"
    assert loaded["unused"] == E1_NOTE


def test_1018_e2_an_indented_fence_inside_a_block_scalar_survives_and_loads():
    expected = dict(VERDICT, noise_floor_note=E2_NOTE, correlations=[], scope_checks=[],
                    derivations=[], findings=[])
    _accepts(E2_INDENTED_FENCE, expected_text=E2_INDENTED_FENCE.strip(), expected_doc=expected)
    _accepts(fenced(E2_INDENTED_FENCE.strip()), expected_text=E2_INDENTED_FENCE.strip(),
             expected_doc=expected)


def test_1018_a_column_zero_close_tag_quoted_in_a_double_quoted_scalar_cannot_flip_the_verdict():
    """The security-adjacent point driven from the attacker's side, through the one shape that DOES
    load with a column-0 tag."""
    expected = dict(VERDICT, noise_floor_note=QUOTED_COLUMN_ZERO_THINK_NOTE, correlations=[],
                    scope_checks=[], derivations=[], findings=[])
    _accepts(QUOTED_COLUMN_ZERO_THINK, expected_text=QUOTED_COLUMN_ZERO_THINK.strip(),
             expected_doc=expected)
    _accepts(fenced(QUOTED_COLUMN_ZERO_THINK.strip()),
             expected_text=QUOTED_COLUMN_ZERO_THINK.strip(), expected_doc=expected)
    # With a REAL prelude in front, the cut lands on the real tag and the quoted one is still
    # document: the remainder loads, so no fence or tag rule ever sees it.
    _accepts(PRELUDE + QUOTED_COLUMN_ZERO_THINK, expected_text=QUOTED_COLUMN_ZERO_THINK.strip(),
             expected_doc=expected)


def test_1018_an_indented_quoted_close_tag_cannot_end_a_prelude_on_an_unloadable_reply():
    """The prelude rule only runs on a bare reply that does NOT load ."""
    unloadable = E1_QUOTED_THINK.replace(
        "episode_outcome: caught\n", "episode_outcome: caught\nnote: one trial: no replicate\n")
    with pytest.raises(yaml.YAMLError):
        safe_load(unloadable)
    assert _parse(unloadable) == unloadable.strip()


def test_1018_a_close_tag_with_nothing_after_it_is_named_not_called_empty():
    _refuses(DOCUMENT + "\n</think>\n", "no document following")


@pytest.mark.parametrize("opener", ["``` yaml", "```yaml # the verdict", "````yaml", "```yaml:"])
def test_1018_an_opening_fence_carrying_more_than_a_tag_is_refused_and_named(opener):
    """A fenced reply whose OPENER line carries more than a tag is refused naming the opener ."""
    _refuses(f"{opener}\n{DOCUMENT}\n```\n", "opening")


@pytest.mark.parametrize("tag", ["json", "YAML", "yml", "x-yaml", "text+yaml", ""])
def test_1018_e3_any_fence_tag_on_one_fenced_document_is_still_one_document(tag):
    _accepts(fenced(DOCUMENT, tag) + "\n")


def test_1018_e3_trailing_spaces_on_the_opener_and_closer_lines_are_tolerated():
    _accepts("```yaml   \n" + DOCUMENT + "\n```   \n")


def test_1018_e4_crlf_line_endings_are_normalised_before_the_shape_rule():
    crlf = (fenced(DOCUMENT) + "\n").replace("\n", "\r\n")
    _accepts(crlf)
    assert "\r" not in _parse(crlf)


def test_1018_e5_a_leading_bom_is_dropped():
    _accepts("\ufeff" + SHAPE_2_WHOLE_FENCE)
    _accepts("\ufeff" + SHAPE_1_PLAIN)


@pytest.mark.parametrize("text", [
    "",
    "   ",
    "\n\n  \n",
    "\ufeff\n",
    "```yaml\n```",
    "```yaml\n\n```\n",
    "```\n   \n```",
])
def test_empty_plain_or_fenced_reply_is_refused_and_named(text):
    _refuses(text, "empty")


def test_1018_a_fence_with_no_closer_is_refused():
    """A reply that opens a fence and never closes it (a truncated completion) is refused,
    naming the missing closer. Failing: the opener line is dropped and the rest returned."""
    _refuses("```yaml\n" + DOCUMENT + "\n", "no closing")


@pytest.mark.parametrize("lead", ["\n\n", "  ", " \t\n"])
def test_1018_whitespace_before_the_opener_is_stripped_before_the_fence_rule(lead):
    """M1 step 3 runs BEFORE step 4: surrounding whitespace is stripped, and only then is "does it
    start with a fence" decided. A parser that reads the first character before."""
    _accepts(lead + SHAPE_2_WHOLE_FENCE)


def test_1018_the_prelude_ends_at_the_first_column_zero_close_tag_not_the_last():
    """M1 step 2 drops everything through the FIRST column-0 closing think tag."""
    text = PRELUDE + DRAFT + "\n</think>\n" + DOCUMENT + "\n"
    out = _parse(text)
    assert out == (DRAFT + "\n</think>\n" + DOCUMENT), f"the parser returned:\n{out!r}"
    with pytest.raises(yaml.YAMLError):
        safe_load(out)


@pytest.mark.parametrize("tag", ["</think>", "</thinking>", "</system_thinking>"])
def test_1018_e8_every_closing_think_spelling_is_a_prelude_boundary(tag):
    """E8: `</think>`, `</thinking>` and `</system_thinking>` on their own column-0 line each end a
    prelude — including the recorded no-opening-tag shape, with the prelude."""
    _accepts(PRELUDE.replace("</think>", tag) + SHAPE_1_PLAIN)
    recorded = "outcome: caught\n(reasoning trace…)\n" + tag + "\noutcome: survived\nconfidence: high\n"
    _accepts(recorded, expected_text="outcome: survived\nconfidence: high",
             expected_doc={"outcome": "survived", "confidence": "high"})


def test_1018_e8_an_explicit_opening_tag_and_a_fenced_draft_inside_the_prelude_are_dropped():
    """The prelude rule is "drop everything through the FIRST such line" and runs BEFORE the fence
    rules ."""
    reasoning = ("<think>\nA first draft:\n" + fenced(DRAFT)
                 + "\nNo — the lead was set and left, so caught.\n</think>\n")
    _accepts(reasoning + SHAPE_2_WHOLE_FENCE)


def test_1018_a_dangling_closer_after_a_plain_document_is_refused():
    """M4 / "no dangling-closer trim": a plain document followed by a lone column-0 ``` is "a
    fence inside the reply". Failing: the closer is trimmed and the document recovered."""
    _refuses(DOCUMENT + "\n```\n", "inside")


def _episode(tmp_path, **kw):
    kw.setdefault("ledgers", {"b": [J.staged_row("b")], "c": []})
    return J.accepted_episode(tmp_path, **kw)


def _grade(tmp_path, ep, judge, **kw):
    """The real pass. Returns the grade so the caller can assert the pass RETURNED — O2's
    "never the pass"."""
    return J.grade_at(
        ep, judge=judge, state=_state1135.env_state(), **kw)


def _wire_row(ep: Path, label: str, draw: int) -> dict:
    """The judge's own wire-log row for one draw — `_write_wire_log`'s file, read back."""
    path = Path(ep) / "wire_logs" / f"judge_{label}_{draw}_framed_trace.jsonl"
    assert path.is_file(), f"no wire log at {path}"
    return json.loads(path.read_text(encoding="utf-8").splitlines()[0])


def _bare_verdict() -> str:
    return J.as_reply_text(J.reply_doc())


def _fence_then_prose(body: str) -> str:
    return fenced(body.rstrip("\n")) + PROSE_AFTER


ASKS_PER_DRAW = 3


def test_1018_judge_fence_then_prose_reply_costs_one_draw_and_the_reply_is_on_disk(tmp_path):
    """M2 at the judge, shape 4: a fence-then-prose reply carrying an otherwise VALID verdict is one
    malformed draw — `completed_draws` 0, `malformed_replies` 1, no."""
    ep = _episode(tmp_path)
    shape_4 = _fence_then_prose(_bare_verdict())
    judge = J.scripted_judge(replies=[shape_4] * ASKS_PER_DRAW, default=_bare_verdict())
    grade = _grade(tmp_path, ep, judge, draws=1)

    rows = J.world_rows(J.judge_record(ep))
    assert rows["b"]["completed_draws"] == 0, "a fence-then-prose reply completed a draw"
    assert rows["b"]["malformed_replies"] == ASKS_PER_DRAW
    assert not (ep / "worlds" / "b" / "judge" / "0.yaml").exists(), (
        "a draw file was written off a reply that was not one bare document")
    assert grade.episode_dir == ep, "the pass did not return normally"
    assert _wire_row(ep, "b", 0)["reply"] == shape_4, (
        "the refused reply's own bytes are not on the wire log")
    # Positive control on the same pass: world c's bare reply completed its draw.
    assert rows["c"]["completed_draws"] == 1
    assert (ep / "worlds" / "c" / "judge" / "0.yaml").is_file()


def test_1018_judge_a_bare_second_draw_completes_beside_a_malformed_first(tmp_path):
    ep = _episode(tmp_path)
    judge = J.scripted_judge(
        replies=[_fence_then_prose(_bare_verdict())] * ASKS_PER_DRAW + [_bare_verdict()],
        default=_bare_verdict())
    _grade(tmp_path, ep, judge, draws=2)

    rows = J.world_rows(J.judge_record(ep))
    assert rows["b"]["completed_draws"] == 1
    assert rows["b"]["malformed_replies"] == ASKS_PER_DRAW
    assert not (ep / "worlds" / "b" / "judge" / "0.yaml").exists()
    # #1234: the reply carries no `episode_outcome` (retired, A17); the completed draw's own
    # answer is its world bucket.
    assert J.draw_doc(ep, "b", 1)["bucket"] == "lead-set"


def test_1018_validate_reply_wraps_the_parser_refusal_in_judge_refused(tmp_path):
    """M2 at the unit: `validate_reply` on shape 4 raises `JudgeRefused` — the class NAMED, not
    `J.refusals()`, whose tuple includes `ValueError` and would be satisfied by a."""
    run_mod = J.mod("learning.judge.run")
    JudgeRefused = J.sym("learning.judge", "JudgeRefused")
    assert run_mod.validate_reply(_bare_verdict()).bucket == "lead-set"
    with pytest.raises(JudgeRefused):
        run_mod.validate_reply(_fence_then_prose(_bare_verdict()))
    family_bare = _family_verdict()
    # #1234 M6: a family reply carries family-scope world findings only, no bucket.
    family_parsed = run_mod.validate_reply(family_bare, scope="family")
    assert family_parsed.bucket is None
    assert family_parsed.world_findings == []
    with pytest.raises(JudgeRefused):
        run_mod.validate_reply(_fence_then_prose(family_bare), scope="family")


def _family_verdict() -> str:
    """A verdict valid at FAMILY scope: no findings (#1234 M6 retired the family's
    `verdict_word`), so nothing names a world or the defender."""
    return J.as_reply_text(J.family_reply())


def test_1018_judge_family_scope_fence_then_prose_costs_one_family_draw_not_the_family_call(
        tmp_path):
    """O2 at the family lane: a fence-then-prose reply on `judge:family:0` (draws=2) is ONE
    malformed family ASK — the family row's `malformed_replies` 1 and no."""
    ep = _episode(tmp_path)
    # Call order is world b's draws, world c's draws, then the family's: 2 + 2 + 2.
    judge = J.FakeJudge(replies=[_bare_verdict()] * 4 + [_fence_then_prose(_family_verdict())],
                        default=_family_verdict())
    _grade(tmp_path, ep, judge, draws=2)

    family = J.judge_record(ep)["family"]
    assert family.get("draws_failed_reason") is None, family["draws_failed_reason"]
    assert family["malformed_replies"] == 1
    family_calls = [a for a in judge.agent_ids if a.startswith(J.FAMILY_AGENT_PREFIX)]
    assert family_calls == ["judge:family:0", "judge:family:0:1", "judge:family:1"], (
        judge.agent_ids)
    assert family["completed_draws"] == 2, "the bare family draws did not count"
    assert family["draws"] == [{"draw": 0}, {"draw": 1}]
    assert _wire_row(ep, "family", 0)["reply"] == _fence_then_prose(_family_verdict())


def _questioner():
    return T.mod("learning.branch.questioner")


def _branch_error() -> type[BaseException]:
    """`BranchError` NAMED — `T.refusals()` includes `ValueError`, which a bare `MalformedReply`
    would satisfy."""
    return T.sym("runtime.branch", "BranchError")


def _fenced_doc(doc: dict) -> str:
    """The questioner fixture's own fenced shape (`test_947`): closer last, no trailing newline."""
    return f"```yaml\n{yaml.safe_dump(doc, sort_keys=False)}```"


def _author(tmp_path, agent):
    return _questioner().author_family(
        source_run_dir=tmp_path, episode_dir=T.episode(tmp_path),
        invoke=agent, leads=[], alert={}, frontier="")


def test_1018_questioner_call_1_fence_then_prose_aborts_naming_call_1_before_any_seat_is_paid(
        tmp_path):
    """M2 at the questioner, shape 4 on call 1."""
    agent = T.FakeAgent(_fenced_doc(T.family_doc()) + PROSE_AFTER,
                        _fenced_doc(T.world_doc("b")), _fenced_doc(T.world_doc("c")))
    with pytest.raises(_branch_error()) as err:
        _author(tmp_path, agent)
    assert "call 1" in str(err.value)
    assert agent.calls == 1, "seat calls were paid against a family that was refused"


def test_1018_questioner_seat_call_fence_then_prose_aborts_naming_the_seat(tmp_path):
    """Shape 4 on a SEAT call (call 2)."""
    agent = T.FakeAgent(_fenced_doc(T.family_doc()),
                        _fenced_doc(T.world_doc("b")) + PROSE_AFTER,
                        _fenced_doc(T.world_doc("c")))
    with pytest.raises(_branch_error()) as err:
        _author(tmp_path, agent)
    assert "seat B" in str(err.value)
    assert agent.calls == 2


SHAPE_PHRASE = "not inside a code fence, with nothing before or after it"
#: Words that would turn the sentence into permission for a shape the parser refuses. None
#: may appear in the sentence that carries the phrase.
PERMISSIVE_WORDS = ("wrap", "you may", "commentary", "treated as", "before and after")
#: M3's label on the two questioner examples, which still SHOW the document inside a fence.
ILLUSTRATION_LABEL = "illustration, not part of the reply"


def _says_bare(text: str) -> bool:
    """The site states the accepted shape: the whole phrase, whitespace-normalised so a wrapped
    markdown line counts, in a sentence that permits nothing the parser refuses."""
    flat = " ".join(text.split())
    at = flat.find(SHAPE_PHRASE)
    if at < 0:
        return False
    start = max(flat.rfind(". ", 0, at), flat.rfind(": ", 0, at), 0)
    end = flat.find(". ", at)
    sentence = flat[start:end if end > 0 else None].lower()
    return not any(word in sentence for word in PERMISSIVE_WORDS)
