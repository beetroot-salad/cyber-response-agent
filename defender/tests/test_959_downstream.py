r"""#959 - everything downstream of the decision: the box, the operand set, the audit row, the
sibling read lane, the refusal message and the operator's view.

A word-boundary change does not stop at `BashDecision`. The same parse-derived operand set is
walked again after the decision in four further places, the pipelines cross into the box
unmediated, an audit row records the raw text beside an argv derived from the parse, and the one
tool that prints a decision for a human serialises only half of it. O3's neutrality obligation
stops at the decision object (F2/FK8); these are bound under O1 instead, at the derivation they
all read.

The box is entered through the `box=` injection seam every deps object already carries - a fake
that records what it is handed and returns a canned `BoxResult`, never a monkeypatched module
attribute.
"""
from __future__ import annotations

import copy
import dataclasses
import io
import json
import re
from contextlib import redirect_stdout
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.agents import GATHER_DEF  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.box_codec import BoxResult  # noqa: E402
from defender.runtime.permission import files as pfiles  # noqa: E402
from defender.runtime.tools import _tool_bash  # noqa: E402
from defender.scripts import policy_cli  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.tests import _baseline_959 as base  # noqa: E402

CR = base.CR
NBSP = base.NBSP
REPORT = base.REPORT
DEFENDER = Path(__file__).resolve().parents[1]


class Box:
    """The execution seam, faked at the value the run is handed.

    It injects nothing and decides nothing - it RECORDS what crossed (a deep copy taken at the
    moment of receipt, so a later mutation of the live object is visible as a difference) and
    returns the result it was constructed with."""

    def __init__(self, result: BoxResult):
        self.result = result
        self.calls: list[dict] = []

    def run_parsed(self, pipelines, *, command, cwd, timeout):
        self.calls.append({
            "pipelines": pipelines,
            "snapshot": copy.deepcopy(pipelines),
            "command": command,
            "cwd": cwd,
            "timeout": timeout,
        })
        return self.result


def _bash(cmd: str, policy=None):
    return permission.decide_bash(
        cmd, policy=policy or base.MAIN, run_dir=base.RUN, defender_dir=base.DFN,
    )


def _argv_of(decision):
    if decision.pipelines is None:
        return None
    return [[list(st.argv) for st in pl.stages] for pl in decision.pipelines]


def _gather_scene(tmp_path: Path, result: BoxResult, *, lead_id: str = "l-1"):
    """A real gather deps over a real run dir, with the box seam handed a fake."""
    run = tmp_path / "run"
    dfn = tmp_path / "tree" / "defender"
    (run / "gather_raw" / lead_id).mkdir(parents=True)
    dfn.mkdir(parents=True)
    payload = run / "gather_raw" / lead_id / "0.json"
    payload.write_text("{}", encoding="utf-8")
    box = Box(result)
    deps = dataclasses.replace(
        bind(GATHER_DEF, run, defender_dir=dfn, box=box), lead_id=lead_id,
    )
    return deps, box, payload


# O3 - the neutrality negative, at the decision object.
def test_no_verdict_moves_outside_the_enumerated_set():
    """Every command shape this suite and the two differentials already exercise reaches the
    same decision after the refactor as before it - the same allow, the same reason IDENTITY,
    the same argv and the same stderr routing - except the enumerated shapes this spec changes
    on purpose. A `cd`-containing command is the standing control: it already denies at the gate
    because no grant names `cd`, and none of the six mechanisms touches grant matching.

    Rejected: the design body's non-obligation "not a change to what is accepted or refused" as
    the whole test - the enumerated set accepts explicitly that some of the fixes change
    verdicts. The instrument that certifies the universal is the frozen baseline replay
    (`test_a_frozen_baseline_replay_certifies_every_unenumerated_shape`); this is the same claim
    stated at the decision object, over the shapes recorded as neutral."""
    moved = []
    for case in base.frozen()["cases"]:
        if case["member"]:
            continue
        got = base.decision_record(case["command"], case["policy"])
        if got != case["baseline"]:
            moved.append((case["id"], case["baseline"], got))
    assert not moved, (
        f"{len(moved)} unenumerated shapes changed their decision; first three: {moved[:3]}"
    )
    # The standing control: `cd` is absent from the enumerated set because nothing in this
    # change can move it - no grant names it, and grant matching is untouched.
    for cmd in ("cd /run", f"cat {REPORT} && cd /run", "bash -c 'cd /run'", "timeout 5 cd /run"):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} moved"
        assert d.reason == base.MAIN.deny_reason, f"{cmd!r} moved"


# FK8 - the operand set the four post-decision consumers read.
def test_the_operand_set_the_four_post_decision_consumers_read_is_the_one_the_gate_authorised(
    tmp_path,
):
    """The operand set is walked once from the authorised decision and threaded, and every
    consumer downstream of the decision sees THAT set: whether an authored read is refused,
    whether the returned bytes are framed as untrusted, which output ceiling applies, and how
    the overflow hint is worded. A word-boundary change can move all four while allow, reason
    and pipelines are literally unchanged, which is why O3's neutrality stopping at the decision
    object is only safe if this derivation is bound under O1."""
    deps, _box, payload = _gather_scene(tmp_path, BoxResult(0, b"x" * 20000, b""))

    opened = _tool_bash(deps, f"cat {payload}")
    assert "untrusted" in opened, "the payload operand did not reach the frame decision"
    assert str(payload) in opened, "the overflow hint names a file the operand set did not carry"
    assert len(opened) < 12000, (
        "the capture ceiling the payload operand chose was not applied - the ceiling is a "
        "property of the DATA the command opened, read off the same operand set"
    )

    # ...and a command that opens nothing takes the other branch of all four: no frame, the
    # authored ceiling, and the hint that has no path to name.
    deps2 = dataclasses.replace(deps, box=Box(BoxResult(0, b"y" * 20000, b"")))
    opened_nothing = _tool_bash(deps2, "echo hi")
    assert "untrusted" not in opened_nothing
    assert len(opened_nothing) > 12000, "the capture ceiling was applied to a command with no operand"

    # The half this change moves: an operand the TEXT does not name must never reach any of
    # them. Today the gate trims the trailing blank and all four consumers are handed a file
    # the model did not write.
    deps3 = dataclasses.replace(deps, box=Box(BoxResult(0, b"z", b"")))
    with pytest.raises(ModelRetry) as refusal:
        _tool_bash(deps3, f"cat {payload}" + NBSP)
    assert "untrusted" not in str(refusal.value)


def test_the_audit_rows_system_attribution_derives_from_the_authorised_operand_set(tmp_path):
    """The queries-table row the shim-failure path writes derives its `system=` attribution from
    the same authorised operand set, re-derived from the same decision with no cache, so the row
    and the execution cannot disagree about which files the command opened."""
    deps, _box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"boom"))
    run = deps.run_dir
    record_query.append_query_row(
        run, lead_id="l-1", system="elastic", verb="query", query_id="elastic.q", params={},
        raw_command="seed", payload_text="{}", exit_code=0, payload_status="ok",
        payload_digest="d",
    )
    _tool_bash(deps, f"cat {payload} | defender-sql 'SELECT 1'")
    rows = [json.loads(line) for line in (run / "executed_queries.jsonl").read_text().splitlines()]
    shim = [r for r in rows if r["query_id"] == record_query.BASH_SHIM_QUERY_ID]
    assert len(shim) == 1, "the shim-failure row never reached the queries table"
    assert shim[0]["system"] == "elastic", (
        "the row's attribution is not the system of the payload the AUTHORISED operand set "
        "named - a row that disagrees with the execution about which file was opened sends the "
        "curator at the wrong system"
    )
    assert shim[0]["system"] == record_query.system_for_payload_operands(run, [payload])

    # ...and a reduce that opened no run payload attributes to nothing rather than guessing.
    deps2 = dataclasses.replace(deps, box=Box(BoxResult(1, b"", b"boom")))
    _tool_bash(deps2, "echo hi | defender-sql 'SELECT 1'")
    rows2 = [json.loads(line) for line in (run / "executed_queries.jsonl").read_text().splitlines()]
    assert rows2[-1]["system"] == ""


def test_the_audit_rows_raw_command_is_unmoved_for_every_shape_outside_the_enumerated_set(
    tmp_path,
):
    """The audit row records the RAW command text while its gating and attribution come from the
    PARSE - a documented, accepted divergence this change does not close. What this change must
    not do is widen it: for every shape outside the enumerated set the recorded row is unmoved,
    and for the `\\r` class the two agree more closely after the change than before, because the
    argv stops naming a command the text does not.

    The bound is evidentiary and it is NOT closed (probe pj1): `recorded_command =
    command[:SHIM_COMMAND_MAX_CHARS]` with the constant at 2000, and the field's own docstring
    names it as the one field of a shim row an attacker-influenced turn chooses freely. So a
    command padded past 2000 characters can push a divergent character out of the recorded
    evidence and leave the audit row showing a plausible, non-divergent command while a
    different one ran. The boundary is re-probed here rather than cited."""
    deps, _box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"boom"))
    run = deps.run_dir

    short = f"cat {payload} | defender-sql 'SELECT 1'"
    _tool_bash(deps, short)
    rows = [json.loads(line) for line in (run / "executed_queries.jsonl").read_text().splitlines()]
    assert rows[-1]["raw_command"] == short, "a realistic command is recorded verbatim"

    cap = record_query.SHIM_COMMAND_MAX_CHARS
    prefix = f"cat {payload} | defender-sql "
    for marker_at, survives in ((cap - 1, True), (cap, False)):
        pad = marker_at - len(prefix)
        assert pad > 0, "the tmp path is too long to place the marker"
        cmd = prefix + ("x" * pad) + "Z" + ("x" * 8)
        assert cmd[marker_at] == "Z"
        deps_n = dataclasses.replace(deps, box=Box(BoxResult(1, b"", b"boom")))
        _tool_bash(deps_n, cmd)
        rows = [
            json.loads(line)
            for line in (run / "executed_queries.jsonl").read_text().splitlines()
        ]
        recorded = rows[-1]["raw_command"]
        assert ("Z" in recorded) is survives, (
            f"a character at index {marker_at} of the command was recorded={('Z' in recorded)}; "
            f"the truncation boundary at {cap} is off by one, and it is what bounds how much of "
            "the audit row's evidentiary value survives an attacker-padded command"
        )


# The sibling surfaces: the read-tool lane.
#: Paths and the answer both lanes must give for them, under MAIN. Every row is a constraint
#: the read lane enforces - confine (the grant's scope fullmatch), the denylist, and resolve.
_PARITY = (
    ("/run/report.md", True),
    ("/dfn/lessons/a.md", True),
    ("/etc/hosts", False),                       # outside every root: confine
    ("/run/.env", False),                        # denylist
    ("/run/gather_raw/l-1/0.json", False),       # not in MAIN's shapes
    ("/run/wire_logs/llm_requests.jsonl", False),
    ("/run/../etc/passwd", False),               # resolve, then confine
)


def test_every_constraint_the_read_tool_lane_enforces_the_bash_lane_enforces_too():
    """Every constraint the read-tool lane enforces on a resolved operand path - confine (the
    grant's scope fullmatch), denylist, and resolve - the bash lane enforces too, over the
    operand set THE PARSE PRODUCED. The two vias reach the same resource and only one of them
    derives its operand set by splitting text, so a divergence introduced on the bash side has
    no mirror on the read-tool side to contradict it."""
    for path, allowed in _PARITY:
        read = pfiles.decide_read(
            Path(path), run_dir=base.RUN, defender_dir=base.DFN, policy=base.MAIN,
        )
        cat = _bash(f"cat {path}")
        assert read.allow is allowed, f"{path}: the read lane moved"
        assert cat.allow is allowed, (
            f"{path}: the bash lane and the read lane disagree - the read tool says "
            f"{allowed} and `cat` says {cat.allow}, over the same resolved path"
        )
    # ...and the operand set the bash lane checks is the one the PARSE produced: a word
    # boundary that moves changes which path is checked, with no mirror on the read side.
    assert not _bash(f"cat {REPORT}" + CR + "x").allow
    assert not _bash(f"cat {REPORT}" + NBSP).allow


def test_the_read_tool_lane_reaches_the_same_decisions_it_reached_before():
    """The read-tool lane is unmoved: it never parses command text, so every path it admits and
    refuses before the change it admits and refuses after - driven and observed at that reader,
    not asserted at the boundary."""
    for path, allowed in _PARITY:
        d = pfiles.decide_read(
            Path(path), run_dir=base.RUN, defender_dir=base.DFN, policy=base.MAIN,
        )
        assert d.allow is allowed, f"{path}: the read-tool lane's own verdict moved"
    # The lane that DOES see gather_raw still does, so the table above is not green because
    # everything is refused.
    assert pfiles.decide_read(
        Path("/run/gather_raw/l-1/0.json"), run_dir=base.RUN, defender_dir=base.DFN,
        policy=base.GATHER,
    ).allow
    # A divergent blank in a path is not a bash question at all here: the read tool takes a
    # Path, so its answer cannot move with a word boundary.
    assert not pfiles.decide_read(
        Path(REPORT + NBSP), run_dir=base.RUN, defender_dir=base.DFN, policy=base.MAIN,
    ).allow


def test_every_assertion_site_of_the_lexing_reason_agrees_with_the_reason_after_the_change():
    """Every reader of the refusal message moves with it. The drift guard that pins the cause
    list is updated in the same change - #971 strikes cause (5) whole, because there is no
    wrapper step left for it to describe - and the other assertion sites across
    `test_permission.py` and `test_read_confine.py` still agree with what the parser actually
    refuses. A reason that has drifted from the parser is a sentence about nothing."""
    reason = permission.UNTOKENIZABLE_REASON
    # Each cause the reason still documents has a live command that earns it.
    for cmd, phrase in (
        (f"cat {REPORT} | grep 'unterminated", "unbalanced quote"),
        (f"cat {REPORT} \\", "continues nothing"),
        (f"cat {REPORT}\n| wc -l", "line boundary"),
        (f"cat {REPORT} | ; wc -l", "BOTH sides"),
    ):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} no longer earns the lexing reason"
        assert d.reason == reason, f"{cmd!r} no longer earns the lexing reason"
        assert phrase in reason, f"the reason stopped naming {phrase!r}"
    # ...and the clause F4 strikes has no live command left, in the reason OR in the readers
    # that assert on it. #971 settles it the other way from F4 - the parser has no opinion about
    # a `timeout` prefix at all now, quoted or not - but the obligation is the same one: the
    # reason must not name a shape it does not decide, and no reader may pin the struck clause.
    # ...and neither wrapper word is named any more, because neither is parsed any differently
    # from `ls`. A refusal message that describes a step the parser does not take sends the
    # model to fix a problem it does not have.
    assert "timeout" not in reason
    for cmd in ("bash -c 'x' extra", "bash", "sh -lc 'ls'", f"bash -c 'cat {REPORT}'"):
        assert _bash(cmd).reason == base.MAIN.deny_reason, (
            f"{cmd!r} still earns the lexing reason - `bash`/`sh` is an ungranted PROGRAM now, "
            "and the capability message is the one that says which programs the lane has"
        )
    assert _bash(f"timeout '5' cat {REPORT}").reason == base.MAIN.deny_reason, (
        "a quoted `timeout` prefix earns the CAPABILITY reason - it is an ungranted word, and "
        "sending the model to fix its quoting explains nothing about the program it named"
    )
    # ...and no reader still PINS the struck clause. Read over the code only: this scan used to
    # look at the whole file, which made it fire on the comment that RECORDS the removal - prose
    # explaining that a shape is no longer a lexing refusal is the opposite of asserting that it
    # is, and contorting the comment around a substring check would have been the wrong repair.
    for name in ("test_permission.py", "test_read_confine.py"):
        source = (DEFENDER / "tests" / name).read_text(encoding="utf-8")
        code = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        assert "quoted `timeout` prefix" not in code, (
            f"{name} still asserts that a quoted `timeout` prefix is a lexing refusal, and the "
            "parser has no opinion about one - the clause is struck TOGETHER WITH the test "
            "pinning it"
        )


# The object that crosses into the box.
def test_the_object_the_gate_authorised_is_the_object_the_box_runs(tmp_path):
    r"""The pipelines the gate authorised are the pipelines the box runs: they cross the process
    boundary unmediated, with no re-derivation from text anywhere on the path, and every argv
    entry that crosses is the resolved value the parse produced - a CR-bearing operand included,
    unmodified and unre-encoded. That is what makes every argv-divergence demand here an
    EXECUTION-change demand and not merely an authorisation one."""
    deps, box, payload = _gather_scene(tmp_path, BoxResult(0, b"ok", b""))
    cmd = f"cat {payload}"
    _tool_bash(deps, cmd)
    assert len(box.calls) == 1
    sent = box.calls[0]
    authorised = permission.decide_bash(
        cmd, policy=deps.policy, run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        cwd_anchor=deps.cwd_anchor,
    )
    assert [[list(st.argv) for st in pl.stages] for pl in sent["pipelines"]] == \
        _argv_of(authorised), "the box ran something other than what the gate authorised"
    assert sent["command"] == cmd

    # ...and an argv entry carrying the character the scanner no longer splits on crosses as
    # the one operand the text names.
    deps2 = dataclasses.replace(deps, box=Box(BoxResult(0, b"ok", b"")))
    _tool_bash(deps2, "echo a" + CR + "b")
    crossed = deps2.box.calls[0]["pipelines"]
    assert [list(st.argv) for pl in crossed for st in pl.stages] == [["echo", "a" + CR + "b"]], (
        "the operand the gate authorised is not the operand that crossed the wire - a carriage "
        "return is part of the word it touches, and nothing re-encodes an argv entry here"
    )


def test_nothing_mutates_the_authorised_pipelines_between_authorisation_and_execution(tmp_path):
    """Nothing mutates the authorised pipeline objects between the authorisation and the
    execution: the operand walk, the audit path and the executor all read the same object graph
    and none of them writes to it. Only the token record is frozen by this change; the object
    graph above it has no declared immutability on either side, so the property that makes the
    check meaningful is asserted rather than assumed."""
    deps, box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"boom"))
    _tool_bash(deps, f"cat {payload} | defender-sql 'SELECT 1'")
    sent = box.calls[0]
    live = [[list(st.argv) for st in pl.stages] for pl in sent["pipelines"]]
    at_receipt = [[list(st.argv) for st in pl.stages] for pl in sent["snapshot"]]
    assert live == at_receipt, (
        "the authorised pipelines were mutated after they crossed into the box - the audit "
        "path and the operand walk read this object graph and must not write to it"
    )
    # ...and the decision the gate would reach for the same text is still that object: the gate
    # is a pure function of its inputs, so two identical calls produce identical decisions.
    again = permission.decide_bash(
        f"cat {payload} | defender-sql 'SELECT 1'", policy=deps.policy, run_dir=deps.run_dir,
        defender_dir=deps.defender_dir, cwd_anchor=deps.cwd_anchor,
    )
    assert live == _argv_of(again)


# What the model is told, and what the operator can see.
def _names_codepoint(reason: str, char: str) -> bool:
    """Does `reason` name `char` the only way a reason can name a character nobody can see -
    by its codepoint? `U+00A0`, any case, leading zeros optional."""
    return re.search(rf"U\+0*{ord(char):04x}\b", reason, re.IGNORECASE) is not None


def test_a_command_refused_only_for_an_invisible_character_is_told_so():
    r"""A command refused only because a character the model cannot see is now part of a word is
    told WHICH character: the reason names it by codepoint - the only way a reason can name a
    character that renders as nothing - rather than handing back a generic capability deny for a
    command that looks on screen exactly like one that works.

    The class, not one member of it (RC2). FK6 was resolved for "a character the model cannot
    see"; the demand it minted was bound for the line ending alone, while the invisible class is
    the enumerated set's centre of gravity - 107 corpus cases are member 1 (a no-break space or
    one of 25 siblings at one end of a command that was quietly allowed before and is refused
    now) and 209 more are member 8, where an invisible character moved which arm refuses an
    already-refused command; 316 of the 362 enumerated cases turn on a character nobody can see. Of the 118 corpus cases that delegate their reason
    to this test, 103 carry no carriage return at all. A model that pastes a path with a no-break
    space in it - the ordinary result of copying out of rendered documentation - has no other way
    to discover the character.

    The alphabet is swept from the frozen corpus's own codepoint tuple rather than sampled, and
    swept at every POSITION the class occupies, which is the second half of the same lesson
    (RC6): the trailing end, where the blank corrupts an operand; the leading end, where it
    corrupts `argv[0]` and the program name is what the model got wrong; and immediately after a
    separator, where the refusal that used to name the problem is the thing being lost. Sweeping
    one position of three is how member 8 came to state a 26-character family as a rule about
    one character.

    TWO PREDICATES, not one (RC9). A command refused ONLY for the invisible character is the
    first; the second is a command that was ALREADY refused, whose REASON CLASS moved because of
    one - every lexing arm whose refusal is decided by the text of the last token loses its
    specific message when a blank is appended there. The model is worse off in that case than in
    the first: it had a message naming the problem and now has one that does not, for a command
    that renders identically to the one it sent.

    Two boundaries, both asserted below. A command already refused for the same operand BEFORE
    this change - a quoted `\r`, say - keeps the reason it has today, because moving that one
    would be a verdict change outside the enumerated set. And an ordinary capability refusal
    with nothing invisible in it keeps the plain reason, or this obligation has smeared over
    every deny in the lane."""
    for blank in base.DIVERGENT_BLANKS:
        for position, cmd in (
            ("trailing, in an operand", f"cat {REPORT}" + blank),
            ("leading, in the program name", blank + f"cat {REPORT}"),
            ("after a separator", f"cat {REPORT} |" + blank),
        ):
            d = _bash(cmd)
            assert not d.allow, (
                f"U+{ord(blank):04X} {position} still authorises a command the text does not "
                "name - the refusal this reason explains has not happened yet"
            )
            assert d.reason != base.MAIN.deny_reason, (
                f"a command refused only for U+{ord(blank):04X} ({position}) was refused with "
                "the generic capability deny; the model cannot see the character and has no way "
                "to find it"
            )
            assert _names_codepoint(d.reason, blank), (
                f"the refusal of {cmd!r} never names U+{ord(blank):04X}. It cannot be shown, so "
                "the codepoint is the only thing that can be said about it"
            )
    # The carriage return, in each of the three places this change newly refuses it for: inside
    # an operand, at a word edge, and - member 8 - as a word of its own after a connector, where
    # it also costs the model the one message that used to name the problem.
    for cmd in (f"cat {REPORT}" + CR + "x", f"cat {REPORT}" + CR + "\nwc -l",
                f"cat {REPORT} |" + CR, f"cat {REPORT} &&" + CR):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} is still authorised as a command the text does not name"
        assert _names_codepoint(d.reason, CR), (
            f"{cmd!r}: the refusal never names U+000D. A CRLF paste is by far the likeliest "
            "carriage return a model sends, and after this change every one of them carrying a "
            "path operand under a `cat`-shaped grant is refused"
        )
    # The second predicate, at BOTH ends: the shapes whose refusal an invisible character moves
    # off the lexing path. Swept from the corpus's own derived tables, so this follows the code
    # and the recorded positions rather than a list of shapes.
    for arm, shape, moves_trailing, moves_leading in base.LEXING_ARMS:
        for label, build, moves in (
            ("trailing", lambda b, sh=shape: sh + b, moves_trailing),
            ("leading", lambda b, sh=shape: b + sh, moves_leading),
        ):
            for blank in base.DIVERGENT_BLANKS:
                d = _bash(build(blank))
                if not moves:
                    # The control: where the character did not move the refusal, the specific
                    # message stays, which is what scopes this obligation to what actually moved.
                    assert d.reason == permission.UNTOKENIZABLE_REASON, (
                        f"{arm} ({label} U+{ord(blank):04X}): a refusal this spec records as "
                        "unmoved left its own arm"
                    )
                    continue
                assert not d.allow, f"{arm} ({label} U+{ord(blank):04X}) became an allow"
                assert _names_codepoint(d.reason, blank), (
                    f"{arm} ({label} U+{ord(blank):04X}): this command was refused with a message "
                    "naming its problem before the change and is refused with one that names "
                    "nothing after it. The character is what moved the refusal off that arm, so "
                    "the reason has to say which character"
                )
    # ...and the wrapper shapes, which are the case #971 INVERTS. They used to be refused for
    # the lexing reason and to lose it when a leading blank took the wrapper word with it, so
    # the character had to be named. There is no wrapper word to take any more: each one is an
    # ungranted program with the blank and without it, so the character is not what refuses
    # them, and naming it would send the model hunting for a stray codepoint in a command whose
    # real problem is the program it names.
    for name, shape in base.WRAPPER_LATER_TOKEN_SHAPES:
        for blank in base.DIVERGENT_BLANKS:
            d = _bash(blank + shape)
            assert not d.allow, f"leading U+{ord(blank):04X} + {name} became an allow"
            assert not _names_codepoint(d.reason, blank), (
                f"leading U+{ord(blank):04X} + {name}: a codepoint is named for a command that "
                f"is refused with it and without it ({shape!r} is refused on its own)"
            )
            assert _bash(shape).reason == d.reason, (
                f"{name}: the blank changed the message after all, so it IS part of the answer "
                "and the obligation to name it is back"
            )

    # The controls. An ordinary capability refusal keeps the plain reason...
    assert _bash("ls -la").reason == base.MAIN.deny_reason
    assert not _names_codepoint(_bash("ls -la").reason, CR)
    # ...and a command already refused for the same operand before this change does not move.
    assert _bash(f"cat '{REPORT}" + CR + "'").reason == base.MAIN.deny_reason


def test_the_serialised_verdict_an_operator_reads_carries_the_argv_half(capsys):
    """The one tool that prints a decision for a human reports the WHOLE verdict: the operator
    path reaches the same gate over the same command text, and what it serialises carries the
    pipelines as well as allow, grant and reason - otherwise the surface a human audits is blind
    to exactly the half F2 resolved a verdict to include.

    It is also the natural vehicle for auditing the neutrality claim afterwards: a human who
    cannot see the argv cannot see the class of change where allow does not move."""
    cmd = f"cat {REPORT} | wc -c"
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = policy_cli.main(
            ["explain", "main", cmd, "--json", "--run-dir", "/run", "--defender-dir", "/dfn"],
        )
    assert rc == 0
    out = json.loads(buf.getvalue())
    assert out["allow"] is True
    assert out["grant"] == ["cat", "wc"]
    assert "pipelines" in out, (
        "`policy_cli explain --json` serialises allow/grant/reason and never the pipelines, so "
        "the one surface a human audits cannot see the argv the gate authorised"
    )
    assert out["pipelines"] == [[["cat", REPORT], ["wc", "-c"]]], (
        "the serialised pipelines are not the argv the gate authorised"
    )
    # The refused side carries the same shape rather than dropping the field.
    buf = io.StringIO()
    with redirect_stdout(buf):
        policy_cli.main(
            ["explain", "main", "ls -la", "--json", "--run-dir", "/run", "--defender-dir", "/dfn"],
        )
    refused = json.loads(buf.getvalue())
    assert refused["allow"] is False
    assert "pipelines" in refused
