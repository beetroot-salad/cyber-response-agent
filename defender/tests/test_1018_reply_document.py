"""#1018 — a model reply is ONE BARE DOCUMENT, or it is malformed.

What is pinned, by obligation (verbatim ids from the design doc, "Design: a model reply is one
bare document, or it is malformed"):

O1  a document is taken from a reply only when the reply is EXACTLY one document — never one
    block of several, never the prose between blocks, never a draft the model then corrected.
O2  a reply that is not one document is refused with a TYPED error naming the shape, and the
    refusal costs the consumer's own unit — one judge draw, one questioner episode — never the
    pass.
O3  every refusal is diagnosable from disk: the judge's wire-log row carries the reply verbatim.
O4  every sentence that tells the model the reply shape states the shape the parser accepts.
O5  a legitimate one-document reply is never refused: a reasoning prelude is removed before the
    shape rule, and nothing the rule does can reach inside a loadable document.

M1 is the parser: `learning.core.validate.reply_document_text(text) -> str`, raising
`MalformedReply` (a `ValueError`). It replaces `strip_yaml_fence`, `strip_yaml_preamble` and
`normalize_judge_yaml`, which are DELETED (M5). M2 is each consumer wrapping `MalformedReply`
in its own refusal class — `JudgeRefused` at `judge/run.py::validate_reply`, `BranchError` at
`questioner::_reply_document`. M3 is the seven prompt sites.

THE CODE DOES NOT EXIST YET: `reply_document_text` and `MalformedReply` are the surface the
design specifies, so every parser test here is RED by construction until it is built. Every
import goes through `J.mod()` / `J.sym()` PER TEST (the `_judge_921` idiom) so the missing
target is one failure per test rather than one collection error hiding the rest.

The corpus is the issue's own: shapes 1-13 from "The corpus of shapes any fix must be measured
against", the edge cases E1-E8 from the design's answers table, and the three lenient rules the
old parser carried (XML envelope, trailing close tag, dangling closer — `test_loop.py`) that M4
retires. Each test's docstring cites its shape number and states the design's answer for it.

WHY THE JUDGE END-TO-END TESTS ARE PARTLY GREEN AT BASE (C2/C3): the current parser already
REFUSES shape 4 and turns shapes 6/7/8 into a one-key mapping the schema then refuses — so at
the judge, "no verdict is recorded" holds today by accident of two wrong answers cancelling.
Those tests are the regression guard against the three attempts the issue records, each of
which took a block (first, last, tagged) and RECORDED it. The prose-then-fence judge test and
both questioner shape-6 tests are RED at base.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from defender._yaml import safe_load
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _parse(text: str) -> str:
    """M1's one function, imported at CALL time — a missing name is a red test, not a red
    collection."""
    return J.sym("learning.core.validate", "reply_document_text")(text)


def _malformed() -> type[BaseException]:
    """`MalformedReply`, evaluated BEFORE the `raises` block opens, so an unbuilt name fails the
    test at the call rather than satisfying `pytest.raises(...)` with an `AttributeError`."""
    return J.sym("learning.core.validate", "MalformedReply")


# ---------------------------------------------------------------------------------------
# The corpus. One verdict, spelled once; every shape is that verdict dressed differently.
# ---------------------------------------------------------------------------------------

#: The verdict every shape carries — the issue's own "`episode_outcome: caught` is the correct
#: answer throughout". Realistic keys, a quoted colon and a flow sequence with a `#` in a
#: scalar, so a parser that merely locates SOME mapping cannot pass on a stand-in.
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

#: The abandoned draft of shape 6: the same verdict with the OTHER outcome word. If a parser
#: takes the first block, THIS is what gets recorded — the silent wrong verdict the issue is
#: about.
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

#: A valid document whose DOUBLE-QUOTED scalar puts `</think>` and a verdict-shaped tail at
#: column 0 — a shape YAML loads (a quoted scalar's continuation lines carry no indentation
#: rule). A parser that cuts a prelude at any column-0 tag before asking whether the reply
#: already loads records the quoted tail's `discard` in place of the real `caught`, silently.
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
    """The ACCEPT assertion, both halves: the bare text comes back EXACTLY, and it LOADS to the
    expected mapping. The second half is what stops a stand-in — a parser returning the wrong
    slice that happens to equal `DOCUMENT` cannot exist, but one returning something that
    merely `safe_load`s can."""
    text_out = _parse(text)
    assert text_out == expected_text, f"the parser returned:\n{text_out!r}"
    assert safe_load(text_out) == expected_doc


# THE SHAPE VOCABULARY, ONE MARKER PER REFUSAL. O2/M1 say the message NAMES the shape, and a
# message that names every shape at once ("fence inside / text after / second fence / …")
# would satisfy any single-substring check — so a refusal is pinned as carrying its own
# marker and NONE of the others. Each marker is a word the design's own answer table uses.
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


# ---------------------------------------------------------------------------------------
# M1 / O1 — the thirteen shapes, each with the design's stated answer
# ---------------------------------------------------------------------------------------


def test_1018_shape_1_plain_yaml_is_returned_as_is():
    """Shape 1 (plain YAML, no fence): ACCEPT. The text comes back stripped and unchanged and
    loads to the verdict. Failing: the parser rewrites or refuses a reply that was already
    bare."""
    _accepts(SHAPE_1_PLAIN)


def test_1018_shape_2_whole_string_fence_is_unwrapped():
    """Shape 2 (whole-string fence): ACCEPT — the one deliberate leniency, "unambiguous, and it
    costs nothing in correctness". Both with and without a trailing newline after the closer
    (the questioner's own fixture is `"```yaml\\n<dump>```"`, closer last, no newline).
    Failing: a fenced-only reply is refused, or the backticks reach the loader."""
    _accepts(SHAPE_2_WHOLE_FENCE)
    _accepts(fenced(DOCUMENT))


def test_1018_shape_3_prose_then_fence_is_refused_as_a_fence_inside_the_reply():
    """Shape 3 (prose, then fence): REFUSE, "a fence inside the reply". This was the C12 shape
    #921's lenient parser recovered; the design's explicit non-obligation ("no leniency for
    prose before or after the document") retires it. Failing: the fenced block is recovered."""
    _refuses(SHAPE_3_PROSE_THEN_FENCE, "inside")


def test_1018_shape_4_fence_then_prose_is_refused_as_text_after_the_closer():
    """Shape 4 (fence, then prose) — THE DEFECT: REFUSE, "text after the closing fence". Paired
    with shape 2 on the same body as the positive control, so the refusal cannot pass on a
    parser that refuses every fence. Failing: the reply is accepted (attempt 1 returned the
    block) or the backticks reach the loader with an unnamed error."""
    _accepts(SHAPE_2_WHOLE_FENCE)
    _refuses(SHAPE_4_FENCE_THEN_PROSE, "after")


def test_1018_shape_5_prose_fence_prose_is_refused():
    """Shape 5 (prose, fence, prose): REFUSE, "a fence inside the reply" — the reply does not
    start with a fence, so the unfenced rule applies and finds a column-0 fence line.
    Failing: the block is recovered (the old unanchored search's arming case)."""
    _refuses(SHAPE_5_PROSE_FENCE_PROSE, "inside")


def test_1018_shape_6_draft_then_corrected_verdict_is_refused_as_a_second_fence():
    """Shape 6 (fence, then a second fence holding a corrected verdict): REFUSE, "a second
    fence". The ONLY silent shape in the corpus (C3): both blocks are complete, valid verdicts,
    so a parser taking the first records the abandoned `survived`, one taking the last records
    `caught` with no error either way. Neither is taken. Failing: any text comes back."""
    _refuses(SHAPE_6_DRAFT_THEN_FINAL, "second")


def test_1018_shape_7_fence_then_schema_example_is_refused_as_a_second_fence():
    """Shape 7 (fence, then a fence holding a schema example): REFUSE, "a second fence". Attempt
    2 returned `{'episode_outcome': '<word>', 'findings': '<list>'}` for this one. Failing: the
    verdict OR the schema comes back."""
    _refuses(SHAPE_7_FENCE_THEN_SCHEMA, "second")


def test_1018_shape_8_fence_then_evidence_fence_is_refused_as_a_second_fence():
    """Shape 8 (fence, then a fence holding raw evidence): REFUSE, "a second fence". Attempt 2
    returned `{'srcip': '1.2.3.4'}` for this one; the current code returns the prose line
    between the blocks as a one-key mapping (C2). Failing: any text comes back."""
    _refuses(SHAPE_8_FENCE_THEN_EVIDENCE, "second")


def test_1018_shape_9_json_tagged_fence_before_the_verdict_fence_is_refused():
    """Shape 9 (a `json`-tagged fence before the verdict fence): REFUSE, "a second fence". No
    tag preference — the design settles "prefer the `yaml`-tagged block" (attempt 3) as NOT
    the policy. Failing: the tagged verdict is picked out from beside the JSON block."""
    _refuses(SHAPE_9_JSON_THEN_VERDICT, "second")


def test_1018_shape_10_untagged_log_fence_then_plain_verdict_is_refused():
    """Shape 10 (an untagged fenced log excerpt, then a plain-YAML verdict): REFUSE, "text after
    the closing fence" — the reply starts with a fence, so the whole-string rule applies and the
    plain verdict is text after its closer. Attempt 1 returned the log excerpt. Failing: the
    plain verdict is recovered from after the block."""
    _refuses(SHAPE_10_LOG_THEN_PLAIN, "after")


def test_1018_shape_11_outer_fence_wrapping_an_inner_tagged_fence_is_refused():
    """Shape 11 (an outer ``` wrapping an inner ```yaml fence): REFUSE, "a second fence".
    Attempt 3 returned `{'Here is the grading': None}` for this one, SILENTLY. Failing: any
    text comes back."""
    _refuses(SHAPE_11_OUTER_WRAPS_INNER, "second")


def test_1018_shape_12_closer_with_trailing_text_is_refused():
    """Shape 12 (a closing marker with trailing text on its line, ```END): REFUSE — a closer
    with trailing characters is no closer, and "no repair of a mangled closer" is an explicit
    non-obligation. Failing: ```END is accepted as a closer."""
    _refuses(SHAPE_12_TRAILING_CLOSER, "trailing")


def test_1018_shape_13_a_thinking_prelude_is_dropped_before_the_shape_rule():
    """Shape 13 (a thinking-tag prelude before any of the above): the prelude is removed FIRST,
    then the shape rule runs on what is left — so 13→1 and 13→2 ACCEPT and 13→4 REFUSES with
    shape 4's own reason. Failing: a prelude followed by one bare document is refused (O5), or
    a prelude launders a fence-then-prose reply into an accept."""
    _accepts(SHAPE_13A_PRELUDE_THEN_PLAIN)
    _accepts(SHAPE_13B_PRELUDE_THEN_FENCE)
    _refuses(SHAPE_13C_PRELUDE_THEN_FENCE_PROSE, "after")


# ---------------------------------------------------------------------------------------
# M1 / O5 — the edge cases E1-E8, and the prelude's anchoring
# ---------------------------------------------------------------------------------------


def test_1018_e1_a_close_tag_quoted_inside_a_block_scalar_stays_in_the_document():
    """E1: a valid document that quotes `</think>` INSIDE a block scalar (indented, not column
    0) comes back WHOLE and loads with the tag in the note. This is O5's second sub-case and
    the design's one security-adjacent point: untrusted text quoted inside the reply must not
    be able to move the parse boundary, which is why a reply that already loads as one mapping
    is returned before any prelude rule runs (C12: the old regex truncated this to "and then
    went on"). Failing: the note loses its first lines, or the reply is refused."""
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


def test_1018_e1_an_indented_close_tag_cannot_move_the_boundary_even_after_a_real_prelude():
    """O5's anchoring, driven from the attacker's side: a reply with a real column-0 prelude
    AND a later `  </think>` quoted inside the document. The FIRST column-0 tag line is the
    boundary; the indented one is document. Failing: the parse boundary moves to the quoted
    tag and the verdict's head is lost."""
    expected = dict(VERDICT, noise_floor_note=E1_NOTE, correlations=[], scope_checks=[],
                    derivations=[], findings=[])
    _accepts(PRELUDE + E1_QUOTED_THINK, expected_text=E1_QUOTED_THINK.strip(),
             expected_doc=expected)


def test_1018_e2_an_indented_fence_inside_a_block_scalar_survives_and_loads():
    """E2: an INDENTED ``` inside a block scalar is not a fence line (C13: column-0 anchoring)
    — the document comes back whole, bare or fenced, and the fence lines load as part of the
    scalar. Failing: the reply is refused as "a fence inside the reply", or the scalar is cut."""
    expected = dict(VERDICT, noise_floor_note=E2_NOTE, correlations=[], scope_checks=[],
                    derivations=[], findings=[])
    _accepts(E2_INDENTED_FENCE, expected_text=E2_INDENTED_FENCE.strip(), expected_doc=expected)
    _accepts(fenced(E2_INDENTED_FENCE.strip()), expected_text=E2_INDENTED_FENCE.strip(),
             expected_doc=expected)


def test_1018_a_column_zero_close_tag_quoted_in_a_double_quoted_scalar_cannot_flip_the_verdict():
    """The security-adjacent point driven from the attacker's side, through the one shape that
    DOES load with a column-0 tag: a double-quoted scalar. The reply is one valid document with
    `caught`; the quoted tail spells a complete `discard` verdict. It comes back WHOLE and loads
    to `caught`. Failing: the parse boundary moves to the quoted tag and `discard` is what the
    consumer loads — the silent wrong verdict the issue is about, with no refusal."""
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


def test_1018_a_column_zero_fence_quoted_in_a_double_quoted_scalar_is_still_one_document():
    """A column-0 ``` CAN sit inside a loadable document (a double-quoted scalar), so "a fence
    line at column 0" is not on its own proof of a second block: bare, the reply loads and
    comes back whole; fenced, the body loads and comes back whole. Failing: a legitimate
    one-document reply is refused as "a fence inside the reply" or "a second fence"."""
    expected = dict(VERDICT, noise_floor_note=QUOTED_COLUMN_ZERO_FENCE_NOTE, correlations=[],
                    scope_checks=[], derivations=[], findings=[])
    _accepts(QUOTED_COLUMN_ZERO_FENCE, expected_text=QUOTED_COLUMN_ZERO_FENCE.strip(),
             expected_doc=expected)
    _accepts(fenced(QUOTED_COLUMN_ZERO_FENCE.strip()),
             expected_text=QUOTED_COLUMN_ZERO_FENCE.strip(), expected_doc=expected)


def test_1018_an_indented_quoted_close_tag_cannot_end_a_prelude_on_an_unloadable_reply():
    """The prelude rule only runs on a bare reply that does NOT load — and there, the column-0
    anchor is the whole defence: a `</think>` quoted inside an INDENTED block scalar must not
    become the boundary. The reply is E1's document made unloadable by an unquoted colon (C12's
    live shape); the honest answer is to return it whole for the loader to refuse. Failing:
    the text before the quoted tag is discarded and the tail is accepted as a verdict off a
    reply that was never one document."""
    unloadable = E1_QUOTED_THINK.replace(
        "episode_outcome: caught\n", "episode_outcome: caught\nnote: one trial: no replicate\n")
    with pytest.raises(yaml.YAMLError):
        safe_load(unloadable)
    assert _parse(unloadable) == unloadable.strip()


def test_1018_a_close_tag_with_nothing_after_it_is_named_not_called_empty():
    """A complete document followed by a stray closing think tag on the last line: the cut
    would leave nothing, and the refusal says so rather than calling a multi-KB reply "empty".
    Failing: `empty reply` for a reply the wire log shows in full."""
    _refuses(DOCUMENT + "\n</think>\n", "no document following")


def test_1018_a_close_tag_ending_a_reasoning_line_is_still_a_prelude_boundary():
    """A prelude whose closing tag ends the last line of reasoning (`…so caught.</think>`) rather
    than sitting on a line of its own is the other live prelude spelling; it is dropped the
    same way, before a bare or a fenced document. Failing: the prelude reaches the loader and
    a one-document reply is refused as invalid YAML."""
    inline = PRELUDE.replace("set and left.\n</think>\n", "set and left.</think>\n")
    assert inline.count("</think>") == 1
    assert "\n</think>" not in inline
    _accepts(inline + SHAPE_1_PLAIN)
    _accepts(inline + SHAPE_2_WHOLE_FENCE)
    _refuses(inline + SHAPE_4_FENCE_THEN_PROSE, "after")


@pytest.mark.parametrize("opener", ["``` yaml", "```yaml # the verdict", "````yaml", "```yaml:"])
def test_1018_an_opening_fence_carrying_more_than_a_tag_is_refused_and_named(opener):
    """A fenced reply whose OPENER line carries more than a tag is refused naming the opener —
    not "empty fence", which is what a shape diagnosis that only inspects the closer says
    about a fence holding the whole verdict. Failing: the refusal names a shape the reply does
    not have."""
    _refuses(f"{opener}\n{DOCUMENT}\n```\n", "opening")


@pytest.mark.parametrize("tag", ["json", "YAML", "yml", "x-yaml", "text+yaml", ""])
def test_1018_e3_any_fence_tag_on_one_fenced_document_is_still_one_document(tag):
    """E3: the tag on a single fenced document is any `[A-Za-z0-9_+-]*` — `json`, upper-case
    `YAML`, a `-`/`+` tag, none — because YAML subsumes JSON and a tag is not a second
    document. Failing: an unfamiliar tag refuses a reply that holds exactly one document."""
    _accepts(fenced(DOCUMENT, tag) + "\n")


def test_1018_e3_trailing_spaces_on_the_opener_and_closer_lines_are_tolerated():
    """The whole-string fence is ```<tag>?<spaces>\\n<body>\\n```<spaces> — spaces after the tag
    and after the closer are not "text after the closer" (a closer followed by NON-space is,
    shape 12). Failing: a trailing space on either fence line refuses the reply."""
    _accepts("```yaml   \n" + DOCUMENT + "\n```   \n")


def test_1018_e4_crlf_line_endings_are_normalised_before_the_shape_rule():
    """E4: `\\r\\n` is normalised to `\\n` first, so a CRLF fenced reply is one whole-string
    fence and the returned text carries no `\\r`. Failing: the closer is not recognised
    (`\\r` before it), or `\\r` survives into the document."""
    crlf = (fenced(DOCUMENT) + "\n").replace("\n", "\r\n")
    _accepts(crlf)
    assert "\r" not in _parse(crlf)


def test_1018_e5_a_leading_bom_is_dropped():
    """E5: a leading U+FEFF is dropped before the shape rule, so a BOM-prefixed fence is still a
    reply that STARTS with a fence. Failing: the fence is not seen as leading and the reply is
    refused or the backticks reach the loader."""
    _accepts("\ufeff" + SHAPE_2_WHOLE_FENCE)
    _accepts("\ufeff" + SHAPE_1_PLAIN)


@pytest.mark.parametrize("text", ["", "   ", "\n\n  \n", "\ufeff\n"])
def test_1018_e6_an_empty_or_whitespace_only_reply_is_refused_and_named(text):
    """E6: an empty completion is refused with a NAMED reason, never returned as "" for the
    loader to turn into `None` and the consumer into "not a mapping". Failing: no
    `MalformedReply`."""
    _refuses(text, "empty")


@pytest.mark.parametrize("text", ["```yaml\n```", "```yaml\n\n```\n", "```\n   \n```"])
def test_1018_e7_an_empty_fence_is_refused_and_named(text):
    """E7: a fence with a blank body is refused and named. Failing: an empty string comes back
    and the loader's `None` is what the consumer sees."""
    _refuses(text, "empty")


def test_1018_a_fence_with_no_closer_is_refused():
    """A reply that opens a fence and never closes it (a truncated completion) is refused,
    naming the missing closer. Failing: the opener line is dropped and the rest returned."""
    _refuses("```yaml\n" + DOCUMENT + "\n", "no closing")


@pytest.mark.parametrize("lead", ["\n\n", "  ", " \t\n"])
def test_1018_whitespace_before_the_opener_is_stripped_before_the_fence_rule(lead):
    """M1 step 3 runs BEFORE step 4: surrounding whitespace is stripped, and only then is "does
    it start with a fence" decided. A parser that reads the first character before stripping
    sees a reply that "does not start with a fence" yet holds a column-0 fence line, and
    refuses one legitimate document (O5). Failing: a blank line or spaces before the opener
    turns shape 2 into a refusal."""
    _accepts(lead + SHAPE_2_WHOLE_FENCE)


def test_1018_the_prelude_ends_at_the_first_column_zero_close_tag_not_the_last():
    """M1 step 2 drops everything through the FIRST column-0 closing think tag. A parser that
    cuts at the LAST one turns "prelude, draft document, close tag, corrected document" into
    an accept of the corrected document — a two-document reply yielding a verdict (O1). The
    honest cut leaves the second tag inside the returned text, where the loader refuses it
    (C12), so the consumer refuses the reply. Failing: `caught` loads from the tail."""
    text = PRELUDE + DRAFT + "\n</think>\n" + DOCUMENT + "\n"
    out = _parse(text)
    assert out == (DRAFT + "\n</think>\n" + DOCUMENT), f"the parser returned:\n{out!r}"
    with pytest.raises(yaml.YAMLError):
        safe_load(out)


@pytest.mark.parametrize("tag", ["</think>", "</thinking>", "</system_thinking>"])
def test_1018_e8_every_closing_think_spelling_is_a_prelude_boundary(tag):
    """E8: `</think>`, `</thinking>` and `</system_thinking>` on their own column-0 line each end
    a prelude — including the recorded no-opening-tag shape, with the prelude itself looking
    like a document (`test_loop.py`'s "outcome: caught ... </thinking> ... outcome: survived").
    Failing: one spelling is not recognised and the prelude reaches the loader."""
    _accepts(PRELUDE.replace("</think>", tag) + SHAPE_1_PLAIN)
    recorded = "outcome: caught\n(reasoning trace…)\n" + tag + "\noutcome: survived\nconfidence: high\n"
    _accepts(recorded, expected_text="outcome: survived\nconfidence: high",
             expected_doc={"outcome": "survived", "confidence": "high"})


def test_1018_e8_a_column_zero_close_tag_with_trailing_spaces_still_ends_the_prelude():
    """The prelude line is "a line ending in a closing think tag, trailing spaces allowed".
    Failing: `</think>   ` is not recognised and the whole prelude reaches the loader."""
    _accepts(PRELUDE.replace("</think>\n", "</think>   \n") + SHAPE_2_WHOLE_FENCE)


def test_1018_e8_an_explicit_opening_tag_and_a_fenced_draft_inside_the_prelude_are_dropped():
    """The prelude rule is "drop everything through the FIRST such line" and runs BEFORE the
    fence rules — so an opening `<think>` and even a fenced draft inside the reasoning are
    gone before any fence is counted. Failing: the draft's fence is counted as a second fence,
    or the opening tag reaches the loader."""
    reasoning = ("<think>\nA first draft:\n" + fenced(DRAFT)
                 + "\nNo — the lead was set and left, so caught.\n</think>\n")
    _accepts(reasoning + SHAPE_2_WHOLE_FENCE)


# ---------------------------------------------------------------------------------------
# M4 — the three lenient rules the old parser carried are gone
# ---------------------------------------------------------------------------------------


def test_1018_the_xml_envelope_and_trailing_close_tag_shapes_are_no_longer_unwrapped():
    """M4 / the "no XML envelope unwrapping" non-obligation: `<content>…</content>` around a
    document, and a bare `</content>` after one, are NOT fence lines and NOT think tags, so the
    parser returns them UNCHANGED (M1 step 5) — and the consumer's own loader is what refuses
    them. Failing: the envelope is stripped and the document inside it recovered."""
    envelope = "<content>\n" + DOCUMENT + "\n</content>\n"
    trailing = DOCUMENT + "\n</content>\n"
    for text in (envelope, trailing):
        assert _parse(text) == text.strip()
        with pytest.raises(yaml.YAMLError):
            safe_load(_parse(text))


def test_1018_a_dangling_closer_after_a_plain_document_is_refused():
    """M4 / "no dangling-closer trim": a plain document followed by a lone column-0 ``` is "a
    fence inside the reply". Failing: the closer is trimmed and the document recovered."""
    _refuses(DOCUMENT + "\n```\n", "inside")


def test_1018_malformed_reply_is_a_value_error():
    """`MalformedReply` is a `ValueError` subclass — the class `grade_episode`'s conversion set
    names, so one that leaked past a consumer's own wrap would still arrive as `JudgeRefused`
    rather than a bare traceback. Failing: a `MalformedReply` is not caught by `except
    ValueError`."""
    with pytest.raises(ValueError, match="after") as err:
        _parse(SHAPE_4_FENCE_THEN_PROSE)
    assert "second" not in str(err.value)
    assert "inside" not in str(err.value)


def test_1018_the_three_old_parser_names_are_gone_from_validate_and_from_loop():
    """M5: `strip_yaml_fence`, `strip_yaml_preamble` and `normalize_judge_yaml` are DELETED
    from `learning.core.validate` and no longer re-exported by `learning.loop`, which
    re-exports the new pair instead. A surviving old name is a bypass for the lenient parse.
    Failing: any of the three still imports."""
    validate = J.mod("learning.core.validate")
    loop = J.mod("learning.loop")
    for old in ("strip_yaml_fence", "strip_yaml_preamble", "normalize_judge_yaml"):
        with pytest.raises(AttributeError):
            getattr(validate, old)
        assert old not in loop.__all__
    assert {"reply_document_text", "MalformedReply"} <= set(loop.__all__)
    assert loop.reply_document_text is validate.reply_document_text


# ---------------------------------------------------------------------------------------
# M2 / O2 / O3 at the judge — through the real `grade_episode`, `judge=` injected
# ---------------------------------------------------------------------------------------


def _episode(tmp_path, **kw):
    kw.setdefault("ledgers", {"b": [J.staged_row("b")], "c": []})
    return J.accepted_episode(tmp_path, **kw)


def _grade(tmp_path, ep, judge, **kw):
    """The real pass. Returns the grade so the caller can assert the pass RETURNED — O2's
    "never the pass"."""
    return J.mod("learning.judge").grade_episode(
        ep, judge=judge, runs_base=tmp_path / "defender-runs", **kw)


def _wire_row(ep: Path, label: str, draw: int) -> dict:
    """The judge's own wire-log row for one draw — `_write_wire_log`'s file, read back."""
    path = Path(ep) / "wire_logs" / f"judge_{label}_{draw}_framed_trace.jsonl"
    assert path.is_file(), f"no wire log at {path}"
    return json.loads(path.read_text(encoding="utf-8").splitlines()[0])


def _bare_verdict() -> str:
    return J.as_reply_text(J.reply_doc())


def _fence_then_prose(body: str) -> str:
    return fenced(body.rstrip("\n")) + PROSE_AFTER


def test_1018_judge_fence_then_prose_reply_costs_one_draw_and_the_reply_is_on_disk(tmp_path):
    """M2 at the judge, shape 4: a fence-then-prose reply carrying an otherwise VALID verdict is
    one malformed draw — `completed_draws` 0, `malformed_replies` 1, no `worlds/b/judge/0.yaml`
    — and the pass RETURNS (`JudgeRefused` is contained by the draw loop; a `MalformedReply`
    leaking past `validate_reply` would take the whole pass down via `grade_episode`'s
    conversion set). O3: the wire-log row for that draw exists and carries the reply text
    VERBATIM, so the refusal is diagnosable from disk.

    Failing: the draw completes (the block was recovered), a class escapes `grade_episode`, or
    the reply text is nowhere on disk."""
    ep = _episode(tmp_path)
    shape_4 = _fence_then_prose(_bare_verdict())
    judge = J.FakeJudge(replies=[shape_4], default=_bare_verdict())
    grade = _grade(tmp_path, ep, judge, draws=1)

    rows = J.world_rows(J.judge_record(ep))
    assert rows["b"]["completed_draws"] == 0, "a fence-then-prose reply completed a draw"
    assert rows["b"]["malformed_replies"] == 1
    assert not (ep / "worlds" / "b" / "judge" / "0.yaml").exists(), (
        "a draw file was written off a reply that was not one bare document")
    assert grade.episode_dir == ep, "the pass did not return normally"
    assert _wire_row(ep, "b", 0)["reply"] == shape_4, (
        "the refused reply's own bytes are not on the wire log")
    # Positive control on the same pass: world c's bare reply completed its draw.
    assert rows["c"]["completed_draws"] == 1
    assert (ep / "worlds" / "c" / "judge" / "0.yaml").is_file()


def test_1018_judge_a_bare_second_draw_completes_beside_a_malformed_first(tmp_path):
    """The positive control at draw granularity: draws=2, draw 0 fence-then-prose and draw 1
    the same verdict bare. `completed_draws` is 1, `1.yaml` exists and `0.yaml` does not.
    Failing: the malformed draw poisons the world (0 completed) or is silently completed (2)."""
    ep = _episode(tmp_path)
    judge = J.FakeJudge(replies=[_fence_then_prose(_bare_verdict()), _bare_verdict()],
                        default=_bare_verdict())
    _grade(tmp_path, ep, judge, draws=2)

    rows = J.world_rows(J.judge_record(ep))
    assert rows["b"]["completed_draws"] == 1
    assert rows["b"]["malformed_replies"] == 1
    assert not (ep / "worlds" / "b" / "judge" / "0.yaml").exists()
    assert J.draw_doc(ep, "b", 1)["episode_outcome"] == "gradable"


def test_1018_judge_draft_then_corrected_verdict_records_neither(tmp_path):
    """Shape 6 at the judge — the silent-wrong-verdict case: a complete, SCHEMA-VALID draft
    (`discard`, the judge's own vocabulary) followed by "Final answer:" and a corrected
    `gradable` verdict with a finding. A parser taking the first block records `discard` (every
    finding thrown away, no error); one taking the last records `gradable`. NEITHER is
    recorded: no draw file, `completed_draws` 0, nothing enqueued, and the pass returns.

    Failing: a draw file exists with either outcome, or a row was enqueued."""
    ep = _episode(tmp_path)
    draft = J.as_reply_text(J.reply_doc(episode_outcome="discard", findings=[]))
    final = _bare_verdict()
    shape_6 = (fenced(draft.rstrip("\n")) + "\n\nOn reflection that is wrong. Final answer:\n\n"
               + fenced(final.rstrip("\n")) + "\n")
    judge = J.FakeJudge(replies=[shape_6], default=final)
    _grade(tmp_path, ep, judge, draws=1)

    record = J.judge_record(ep)
    rows = J.world_rows(record)
    assert not J.draw_files(ep, "b"), "a verdict was recorded off a two-document reply"
    assert rows["b"]["completed_draws"] == 0
    assert rows["b"]["malformed_replies"] == 1
    assert _wire_row(ep, "b", 0)["reply"] == shape_6
    # World c (bare) is the control that the enqueue path was live for this pass.
    assert rows["c"]["completed_draws"] == 1


def test_1018_judge_prose_then_fence_reply_is_no_longer_recovered(tmp_path):
    """Shape 3 at the judge: the C12 shape #921's lenient parser recovered is now one malformed
    draw. RED AT BASE — the current parser completes this draw. Failing: `completed_draws`
    is 1."""
    ep = _episode(tmp_path)
    shape_3 = PROSE_BEFORE + fenced(_bare_verdict().rstrip("\n")) + "\n"
    judge = J.FakeJudge(replies=[shape_3], default=_bare_verdict())
    _grade(tmp_path, ep, judge, draws=1)

    rows = J.world_rows(J.judge_record(ep))
    assert rows["b"]["completed_draws"] == 0, "prose-then-fence was recovered leniently"
    assert rows["b"]["malformed_replies"] == 1
    assert _wire_row(ep, "b", 0)["reply"] == shape_3


def test_1018_validate_reply_wraps_the_parser_refusal_in_judge_refused(tmp_path):
    """M2 at the unit: `validate_reply` on shape 4 raises `JudgeRefused` — the class NAMED, not
    `J.refusals()`, whose tuple includes `ValueError` and would be satisfied by a bare
    `MalformedReply` leaking through. Positive control: the same verdict bare validates.
    Failing: a `MalformedReply` (or anything else) escapes `validate_reply`."""
    run_mod = J.mod("learning.judge.run")
    JudgeRefused = J.sym("learning.judge", "JudgeRefused")
    assert run_mod.validate_reply(_bare_verdict()).episode_outcome == "gradable"
    with pytest.raises(JudgeRefused):
        run_mod.validate_reply(_fence_then_prose(_bare_verdict()))
    # BOTH SCOPES. `scope="family"` is the same seam's second caller (#1007 M5), and a wrap
    # discharged for the default scope alone lets a `MalformedReply` cross the family lane
    # bare — where `grade_episode`'s family arm swallows it as `family_failed_reason` and
    # makes no further family draw.
    family_bare = _family_verdict()
    assert run_mod.validate_reply(family_bare, scope="family").episode_outcome == "gradable"
    with pytest.raises(JudgeRefused):
        run_mod.validate_reply(_fence_then_prose(family_bare), scope="family")


def _family_verdict() -> str:
    """A verdict valid at FAMILY scope: no findings, so nothing names a world or the defender."""
    return J.as_reply_text(J.reply_doc(findings=[]))


def test_1018_judge_family_scope_fence_then_prose_costs_one_family_draw_not_the_family_call(
        tmp_path):
    """O2 at the family lane: a fence-then-prose reply on `judge:family:0` (draws=2) is ONE
    malformed family draw — `family_malformed_replies` 1, `family_failed_reason` None — and the
    second family draw is still made and completes, so `family_outcome` resolves. A refusal
    that escapes `validate_reply` at this scope is caught by the family arm's `except
    Exception` as a FAILED CALL: draw 1 never made, `family_malformed_replies` 0, and the
    family outcome lost to one bad reply. Failing: `family_failed_reason` names
    `MalformedReply`, or `judge:family:1` was never called."""
    ep = _episode(tmp_path)
    # Call order is world b's draws, world c's draws, then the family's: 2 + 2 + 2.
    judge = J.FakeJudge(replies=[_bare_verdict()] * 4 + [_fence_then_prose(_family_verdict())],
                        default=_family_verdict())
    _grade(tmp_path, ep, judge, draws=2)

    record = J.judge_record(ep)
    assert record["family_failed_reason"] is None, record["family_failed_reason"]
    assert record["family_malformed_replies"] == 1
    assert judge.agent_ids[-2:] == ["judge:family:0", "judge:family:1"], judge.agent_ids
    assert record["family_outcome"] == "gradable", "the bare second family draw did not count"
    assert _wire_row(ep, "family", 0)["reply"] == _fence_then_prose(_family_verdict())


# ---------------------------------------------------------------------------------------
# M2 / O2 at the questioner — through the real `author_family`, `invoke=` injected
# ---------------------------------------------------------------------------------------


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
    """M2 at the questioner, shape 4 on call 1: `BranchError` whose message names call 1, and
    `agent.calls == 1` — the two seat calls are NOT paid against a refused family. The
    refusal costs the episode (its own unit), as the design's cost table says it must.
    Failing: another class escapes, the message names no call, or the seats are called."""
    agent = T.FakeAgent(_fenced_doc(T.family_doc()) + PROSE_AFTER,
                        _fenced_doc(T.world_doc("b")), _fenced_doc(T.world_doc("c")))
    with pytest.raises(_branch_error()) as err:
        _author(tmp_path, agent)
    assert "call 1" in str(err.value)
    assert agent.calls == 1, "seat calls were paid against a family that was refused"


def test_1018_questioner_call_1_draft_then_corrected_family_aborts_with_no_seat_paid(tmp_path):
    """Shape 6 on call 1: a complete draft family document, "Final answer:", a corrected one.
    RED AT BASE: the current parser returns the prose line between the blocks as a one-key
    mapping, `_reply_document` accepts any mapping, and both seat calls are paid before
    `parse_family` refuses at the launcher (C4). Now: `BranchError` naming call 1 and
    `agent.calls == 1`. Failing: `author_family` returns, or three calls are made."""
    draft = T.family_doc(base_story="a draft story the model then withdrew")
    agent = T.FakeAgent(
        _fenced_doc(draft) + "\n\nOn reflection the discriminator above is wrong. Final "
        "answer:\n\n" + _fenced_doc(T.family_doc()),
        _fenced_doc(T.world_doc("b")), _fenced_doc(T.world_doc("c")))
    with pytest.raises(_branch_error()) as err:
        _author(tmp_path, agent)
    assert "call 1" in str(err.value)
    assert agent.calls == 1


def test_1018_questioner_seat_call_fence_then_prose_aborts_naming_the_seat(tmp_path):
    """Shape 4 on a SEAT call (call 2): `BranchError` naming seat B, with `agent.calls == 2` —
    call 1's bare fenced family (the positive control, `test_947`'s own shape) composed, and
    the refused seat is where the episode stops. Failing: the seat's overlay is recovered and a
    third call made, or the message names the wrong call."""
    agent = T.FakeAgent(_fenced_doc(T.family_doc()),
                        _fenced_doc(T.world_doc("b")) + PROSE_AFTER,
                        _fenced_doc(T.world_doc("c")))
    with pytest.raises(_branch_error()) as err:
        _author(tmp_path, agent)
    assert "seat B" in str(err.value)
    assert agent.calls == 2


def test_1018_questioner_one_bare_fenced_document_per_call_still_composes(tmp_path):
    """The positive control beside the three refusals above, on THIS module's own helpers: one
    whole-string-fenced document per call (closer last, no trailing newline) composes the
    family. Failing: the refusals above pass on a parser that refuses every fence."""
    agent = T.FakeAgent(_fenced_doc(T.family_doc()), _fenced_doc(T.world_doc("b")),
                        _fenced_doc(T.world_doc("c")))
    composed = _author(tmp_path, agent)
    assert agent.calls == 3
    assert composed["base_story"] == "the captured story"
    assert [w["world_id"] for w in composed["worlds"]] == ["a", "b", "c"]


# ---------------------------------------------------------------------------------------
# M3 / O4 — every sentence that tells the model the reply shape says the shape
# ---------------------------------------------------------------------------------------

#: The one phrase every shape-telling site carries, so the implementation has one string to
#: write and this census one string to look for.
#: THE WHOLE SENTENCE, not a substring: the shape the parser accepts, in the words every site
#: must use. A substring pin ("not inside a code fence") was greened by a sentence that PERMITS
#: the opposite — "anything not inside a code fence is commentary, so wrap the mapping in one"
#: — which is the #700 attack-deck shape (prose describing content, pinned by presence alone).
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


def test_1018_every_shape_telling_prompt_site_says_the_document_is_bare(tmp_path):
    """M3 (C7): the eight sites that tell the model its reply shape each say the document is
    bare — `not inside a code fence`. The judge's world and family prompts are taken off the
    prompts the REAL pass hands the seam (three calls: b, c, family); the two deny reasons off
    the registered definitions (the questioner's is the last shape-telling sentence a draw that
    reached for a tool reads before it answers); the four role/task files off disk. A census, so no positive control:
    the assertion is that the set of sites missing the phrase is empty, named.
    Failing: any site still permits a shape the parser refuses."""
    ep = _episode(tmp_path)
    judge = J.FakeJudge(default=_bare_verdict())
    _grade(tmp_path, ep, judge, draws=1)
    assert judge.calls == 3, "the census did not see all three judge prompts"
    by_call = dict(zip(judge.agent_ids, judge.prompts, strict=True))
    world_prompts = [p for a, p in by_call.items() if not a.startswith("judge:family")]
    family_prompts = [p for a, p in by_call.items() if a.startswith("judge:family")]
    assert len(world_prompts) == 2, sorted(by_call)
    assert len(family_prompts) == 1, sorted(by_call)
    prompt_files = T.DEFENDER / "learning"
    # One site is ONE template, so the two rendered world prompts are one entry — and it
    # holds only if BOTH renderings carry the phrase.
    said: dict[str, bool] = {
        "run.py world prompt": all(_says_bare(p) for p in world_prompts),
        "run.py family prompt": _says_bare(family_prompts[0]),
        "run.py deny reason": _says_bare(J.sym("learning.judge.run", "JUDGE_DEF").deny_reason),
        "questioner deny reason": _says_bare(
            J.sym("learning.branch.questioner", "QUESTIONER_DEF").deny_reason),
    }
    for rel in ("judge/role.md", "branch/questioner/role.md", "branch/questioner/world.md",
                "branch/questioner/family.md"):
        said[rel] = _says_bare((prompt_files / rel).read_text(encoding="utf-8"))
    assert len(said) == 8
    missing = sorted(name for name, present in said.items() if not present)
    assert missing == [], f"sites that do not say the reply is bare: {missing}"
    # The two questioner examples stay, LABELLED: each file shows the document inside a fence,
    # and the sentence that shows it must say the fence is illustration.
    for rel in ("branch/questioner/world.md", "branch/questioner/family.md"):
        text = " ".join((prompt_files / rel).read_text(encoding="utf-8").split())
        assert ILLUSTRATION_LABEL in text, f"{rel} shows a fenced example without labelling it"
        assert text.find(SHAPE_PHRASE) < text.find(ILLUSTRATION_LABEL) < text.find("```yaml"), (
            f"{rel}: the label is not between the shape sentence and the example it labels")
