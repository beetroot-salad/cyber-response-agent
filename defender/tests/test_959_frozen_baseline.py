"""#959 - the frozen-baseline replay, and the guards that keep it honest.

The corpus, the recorder and the recording live beside this file (`_baseline_959.py`,
`_baseline_959_frozen.json`); its module docstring carries why the recording had to be taken
before the implementation existed. This file is the replay and its controls.

Read the failure of the replay this way: a case whose `member` is empty must reach the SAME
decision it reached at the base commit; a case that names a member must reach the NEW decision
this spec demands. Before the implementation lands, the second half is red - that is the
expected state of a spec, and the first half being green is the whole point of having recorded
it while the recording was still possible.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # the compiled policies the corpus is recorded against

from defender.runtime import bash_exec  # noqa: E402
from defender.runtime.permission import bash as pbash  # noqa: E402
from defender.tests import _baseline_959 as base  # noqa: E402

FROZEN = base.frozen()
CASES = FROZEN["cases"]
TESTS_DIR = Path(__file__).resolve().parent

#: Every file this spec adds. Read back as bytes by the literal-blank guard below - the suite
#: has to survive the defect it is about.
SUITE_FILES = (
    "_baseline_959.py",
    "test_959_frozen_baseline.py",
    "test_959_scanner.py",
    "test_959_wrapper_fold.py",
    "test_955_bash_fd_prefix.py",
    "test_959_downstream.py",
)


def matches(got: dict, want: dict) -> bool:
    """Does `got` satisfy the `want` record?

    Allow and pipelines are always exact. The reason slot is exact too, except in the two forms
    the corpus documents: `"*"` where another demand of this spec owns that reason's identity
    (FK6's invisible-character obligation), and `"!<id>"` where what is demanded IS that the
    reason is no longer the one it names."""
    if got["allow"] != want["allow"] or got["pipelines"] != want["pipelines"]:
        return False
    reason = want["reason"]
    if reason == base.OWNED_ELSEWHERE:
        return True
    if reason.startswith("!"):
        return got["reason"] != reason[1:]
    return got["reason"] == reason


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_a_frozen_baseline_replay_certifies_every_unenumerated_shape(case):
    """A corpus of command texts was run through the gate AT THE BASE COMMIT and its whole
    decision recorded - allow, reason identity, and the pipelines - then replayed after the
    change: every shape outside the enumerated set reaches an identical decision, and every
    shape inside it reaches the enumerated one. The corpus carries the three classes the
    existing corpora do not: wrapper words, `\\r`, and the divergent blanks.

    This is the only instrument that can discharge O3's neutrality obligation as the universal
    it is written as. "No existing test changed its mind" is what the two differentials
    certify, over corpora containing no wrapper word, no carriage return and no blank but a
    space (claims c9, x12) - which is how three of the five live divergences in this change
    survived every previous review round.
    """
    got = base.decision_record(case["command"], case["policy"])
    if not case["member"]:
        assert got == case["baseline"], (
            f"{case['id']}: {case['command']!r} is not in the enumerated verdict-change set, "
            f"and its decision moved.\n  recorded at the base commit: {case['baseline']}\n"
            f"  now: {got}\n"
            "Either the refactor changed a verdict nobody enumerated, or the set is short a "
            "member and D2's list has to say so BEFORE the code is written."
        )
    else:
        assert matches(got, case["after"]), (
            f"{case['id']}: {case['command']!r} is member {case['member']} of the enumerated "
            f"set and must reach the decision this spec demands.\n  demanded: {case['after']}\n"
            f"  now: {got}\n  (recorded at the base commit: {case['baseline']})"
        )


def test_the_recorded_baseline_predates_the_change_it_certifies():
    """The replay's own control, and the one way it can be silently disarmed.

    A baseline re-recorded after the implementation lands would report every case as neutral
    and certify nothing at all - the failure mode FK7's rejected reading ("the suite's own
    opinion afterwards") has by construction. So every enumerated case's RECORDED decision must
    differ from the decision this spec demands: that inequality can only hold for a recording
    taken before the change, and it is checked here rather than trusted."""
    enumerated = [c for c in CASES if c["member"]]
    assert len(enumerated) >= 100, "the enumerated half of the corpus vanished"
    unmoved = [c["id"] for c in enumerated if matches(c["baseline"], c["after"])]
    assert not unmoved, (
        "these enumerated shapes were recorded already holding the verdict the change is "
        f"supposed to give them, so the recording postdates the change: {unmoved[:10]}"
    )
    # ...and the neutral half must not be uniformly one answer, or "identical decision" is a
    # sentence about a corpus that asks nothing.
    neutral = [c for c in CASES if not c["member"]]
    answers = {(c["baseline"]["allow"], c["baseline"]["reason"]) for c in neutral}
    assert len(answers) >= 4, f"the neutral corpus answers uniformly: {answers}"


def test_the_frozen_corpus_carries_the_three_classes_the_existing_corpora_do_not():
    """The instrument's own coverage, measured rather than asserted - against the two corpora
    that were supposed to certify neutrality and cannot.

    Claims c9 and x12 established that neither differential's corpus contains a wrapper word, a
    carriage return, or a blank other than a space; both are re-read here from their own source
    so the finding cannot go stale silently, and the frozen corpus is required to carry all
    three."""
    commands = [c["command"] for c in CASES]
    wrapper = [c for c in commands if re.search(r"(?:^|\s|')(?:bash|sh|timeout)\b", c)]
    carriage = [c for c in commands if base.CR in c]
    divergent = [c for c in commands if any(b in c for b in base.DIVERGENT_BLANKS if b != base.CR)]
    assert len(wrapper) >= 20, f"the corpus has {len(wrapper)} wrapper-word shapes"
    assert len(carriage) >= 8, f"the corpus has {len(carriage)} carriage-return shapes"
    assert len(divergent) >= 50, f"the corpus has {len(divergent)} divergent-blank shapes"

    for name in ("test_955_bash_fd_prefix.py", "test_bash_differential_897.py"):
        source = (TESTS_DIR / name).read_text(encoding="utf-8")
        candidates = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        assert not any(b in candidates for b in base.DIVERGENT_BLANKS), (
            f"{name} now carries a divergent blank - if it grew this coverage, this claim "
            "(x12) is stale and the corpus split between the two instruments should be revisited"
        )


def test_the_corpus_module_and_the_recording_have_not_drifted_apart():
    """The recording is the frozen artifact; the module is what built it. A case added to the
    module after the fact would be replayed against nothing, and a case edited in the module
    would be replayed as a different command than the one recorded - both silent. They are
    required to be the same list, and the recorder is a one-shot that may not be re-run."""
    assert base.corpus_rows() == [
        {k: v for k, v in c.items() if k != "baseline"} for c in CASES
    ], (
        "the corpus module and `_baseline_959_frozen.json` disagree. The recording may NOT be "
        "regenerated to close this: it can only be taken at the base commit, before the "
        "implementation exists."
    )
    assert FROZEN["base"] == "6a2ea874"


def _lexing_raise_fragments() -> dict[str, str]:
    """Every `raise UntokenizableCommand(...)` in the tree, keyed `file:line`, valued by the
    longest constant fragment of the message it raises — derived from the code by AST walk, not
    from a list anybody maintains."""
    import ast

    root = TESTS_DIR.parent
    found: dict[str, str] = {}
    for rel in ("runtime/bash_exec.py", "runtime/permission/bash.py"):
        tree = ast.parse((root / rel).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                continue
            func = node.exc.func
            if (getattr(func, "id", None) or getattr(func, "attr", None)) != "UntokenizableCommand":
                continue
            parts: list[str] = []
            for arg in node.exc.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    parts.append(arg.value)
                elif isinstance(arg, ast.JoinedStr):
                    parts += [v.value for v in arg.values
                              if isinstance(v, ast.Constant) and isinstance(v.value, str)]
            if parts:
                found[f"{rel}:{node.lineno}"] = max(parts, key=len).strip()
    return found


def _message_for(command: str) -> str:
    """The lexing refusal `command` earns, as the parser's own words. Tries the one entry point
    first: after the fold `parse` owns the wrapper too, and the gate's private pre-parse step
    should no longer be reachable."""
    try:
        bash_exec.parse(command)
    except bash_exec.UntokenizableCommand as exc:
        return str(exc)
    except bash_exec.BashExecError:
        return ""
    gate_parse = getattr(pbash, "_parse", None)
    if gate_parse is None:
        return ""
    try:
        gate_parse(command)
    except bash_exec.UntokenizableCommand as exc:
        return str(exc)
    except bash_exec.BashExecError:
        return ""
    return ""


def test_every_lexing_refusal_arm_the_code_has_is_swept():
    """The arm axis, stated as a rule over the code rather than as a list of shapes.

    A trailing divergent blank does not only turn allowed commands into refused ones (member 1);
    where a command was ALREADY refused, and its refusal was decided by the text of the last
    token, the blank moves it off the lexing arm onto the generic capability path — the command
    still fails, correctly, but the message that told the model what to fix is gone, and reason
    identity is part of a verdict (F2). That is member 8.

    Member 8 was written five times as a list: one character at one arm, the alphabet at one arm,
    the alphabet at four separators, the arms at one END, and the arms of one REASON CLASS. Each
    widening closed what had been demonstrated and left the next axis open. So this test does not
    check shapes at all; it checks that the sweep covers sets the code defines.

    THE AXIS IS THE REASON CLASS, NOT THE STATEMENT FORM (RC12). What member 8 is about is which
    message a refusal carries, and there are four: `reason_classes()` names them and the recorder
    already resolved every decision against that same tuple. Deriving the arms from `raise`
    statements missed one by construction — `ADAPTER_RETIRED_REASON` is RETURNED, not raised, so a
    walk over raise sites cannot reach it however carefully it is written, and 78 shapes moved off
    the message that tells the model to use the `query` tool instead while the derivation reported
    itself complete. So: every class in `reason_classes()` must have at least one arm, each arm
    must be swept across the whole 26-character alphabet AT BOTH ENDS, and the raise-site walk
    survives as the mechanism for the one class whose arms are raises.

    The non-moving arms and the non-moving end of each arm are swept too and recorded NEUTRAL; a
    sweep run only over the part of a set that moves cannot say the rest does not.

    THE FOUR AXES ARE NOW CLOSED, NOT WIDENED: character (a computed set checked against the
    frozen tuple), arm (derived here from the code), position (two, because `str.strip()` reaches
    two ends and nothing else — the interior belongs to member 2, where only the carriage return
    moves), and reason class (the four messages the gate can answer with, enumerated in one place
    that the recorder and this test both read). A fifth axis would have to be a fifth thing a
    refusal can vary in; the transition control below is what says the recorded space is
    exhausted rather than merely wide."""
    fragments = _lexing_raise_fragments()
    assert len(fragments) >= 5, f"the lexing arms vanished from the code: {fragments}"

    live = {arm: _message_for(shape) for arm, shape, _trail, _lead in base.LEXING_ARMS}
    unreached = {
        site: fragment for site, fragment in fragments.items()
        if not any(fragment in message for message in live.values())
    }
    assert not unreached, (
        f"these lexing refusal arms are in the code and no corpus arm reaches them: {unreached}.\n"
        f"The corpus sweeps {len(base.LEXING_ARMS)} arms × {len(base.DIVERGENT_BLANKS)} "
        "characters; a NEW arm is a new class of command whose refusal a trailing invisible "
        "character may or may not move, and that is an enumerated-set question — it needs a "
        "decision and a corpus row recorded at the base commit, not a re-recording afterwards."
    )
    # ...and every arm the corpus sweeps still reaches a lexing refusal, so a base shape cannot
    # rot into something that exercises nothing.
    dead = [arm for arm, message in live.items() if not message]
    assert not dead, f"these corpus arms no longer reach any lexing refusal at all: {dead}"

    # The position axis is derived, not a constant of one: every arm must be swept at BOTH ends
    # over the whole alphabet, which is 2 x 26 rows per arm and per wrapper shape.
    ids = {c["id"] for c in CASES}

    def swept(kind: str, name: str, position: str) -> int:
        """How many of the 26 characters this (shape, position) pair is recorded for, whichever
        side of the move it landed on."""
        return sum(
            any(f"{tag}-{position}{kind}-{name}-u{ord(blank):04x}" in ids
                for tag in ("m8", "neutral"))
            for blank in base.DIVERGENT_BLANKS
        )

    missing_position = [
        (kind, name, position or "trailing", swept(kind, name, position))
        for kind, names in (
            ("arm", [a for a, _s, _t, _l in base.LEXING_ARMS]),
            ("wrapper", [n for n, _s in base.WRAPPER_LATER_TOKEN_SHAPES]),
            *[(f"reason-{cls}", [a for c, a, _s, _t, _l in base.RETURNED_REASON_ARMS if c == cls])
              for cls in dict.fromkeys(c for c, *_ in base.RETURNED_REASON_ARMS)],
        )
        for name in names
        for position in ("", "lead-")
        if swept(kind, name, position) != len(base.DIVERGENT_BLANKS)
    ]
    assert not missing_position, (
        f"these shape/position pairs are not swept over the whole alphabet: {missing_position}. "
        "An invisible character glues to the token it TOUCHES, so a shape swept at one end says "
        "nothing about the other - and the two ends give opposite answers for the wrapper arm."
    )

    # ...and every reason class the gate can answer with has an arm at all. This is the check
    # that a raise-site walk cannot make: `ADAPTER_RETIRED_REASON` is returned, so it was outside
    # the derivation by construction until the axis was stated over the classes instead.
    covered = {"untokenizable"} | {cls for cls, *_ in base.RETURNED_REASON_ARMS}
    unarmed = [cls for cls, _text in base.reason_classes(base.MAIN) if cls not in covered]
    assert not unarmed, (
        f"these reason classes have no arm in the corpus: {unarmed}. Every message a refusal can "
        "carry is a message an invisible character can move it off, whether the code RAISES it or "
        "RETURNS it - and a derivation that keys on the statement form misses the returned ones "
        "silently, which is how the adapter class stayed out of member 8 for four verify loops."
    )


#: Every reason transition the recorded corpus contains, as (recorded reason -> demanded reason),
#: with `unchanged` for a row this change must not move. Seven enumerated families and five
#: neutral ones, and the list is what makes "the space is exhausted" checkable rather than
#: asserted: a transition outside it is a class of verdict change nobody enumerated.
_RECORDED_TRANSITIONS = {
    # enumerated: the demanded verdict differs from the recorded one
    ("adapter-retired", "!adapter-retired"),   # member 8, adapter class, leading end (RC12)
    ("untokenizable", "!untokenizable"),       # member 8, lexing class, both ends
    ("untokenizable", "none"),                 # member 4: the quoted `timeout` prefix is accepted
    ("none", "*"),                             # members 1/2: refused, reason owned by FK6's demand
    ("none", "none"),                          # members 1/2: allowed, with a different argv
    ("none", "policy-deny"),                   # member 7: the timeout gap
    ("none", "untokenizable"),                 # members 3/5: the wrapper narrowings
    # neutral: the recorded decision must not move at all
    ("adapter-retired", "unchanged"),
    ("embedded-nul", "unchanged"),
    ("none", "unchanged"),
    ("policy-deny", "unchanged"),
    ("untokenizable", "unchanged"),
}


def test_every_recorded_transition_belongs_to_an_enumerated_class():
    """The closure control: the corpus's own reason transitions are a CLOSED set, and it is the
    thing that lets a reader see the space is exhausted instead of taking anyone's word for it.

    Five verify loops each found member 8 stated over one point of an axis - one character, one
    arm, one end, one reason class - and each fix closed exactly what had been demonstrated. What
    stops a sixth is not a wider sweep but a statement about the whole space: every row in the
    corpus moves (or does not move) from one of the four reason classes to another, and the set of
    transitions that actually occur is small, listed above, and each one names the member it
    belongs to. A row whose transition is not in that set is a class of verdict change nobody has
    enumerated - which is precisely what the adapter class was before RC12.

    Two halves. Every RECORDED baseline resolves to a known reason class, so the four-class
    enumeration is complete over the corpus rather than complete-as-far-as-anyone-looked; and
    every transition the corpus demands is one of the listed families."""
    unknown_baselines = [
        c["id"] for c in CASES if c["baseline"]["reason"] == "unrecognised-reason"
    ]
    assert not unknown_baselines, (
        f"these rows recorded a reason the corpus cannot name: {unknown_baselines[:5]}. "
        "`reason_classes()` is meant to be the whole set the gate can answer with."
    )
    seen = {
        (c["baseline"]["reason"], c["after"]["reason"] if c["after"] else "unchanged")
        for c in CASES
    }
    unenumerated = sorted(seen - _RECORDED_TRANSITIONS)
    assert not unenumerated, (
        f"these reason transitions are recorded and belong to no enumerated class: "
        f"{unenumerated}. Each one is a way a refusal's MESSAGE moves that the written "
        "verdict-change set does not describe, and reason identity is part of a verdict (F2)."
    )
    # ...and the listed set is not padded: every family in it is actually exercised.
    unused = sorted(_RECORDED_TRANSITIONS - seen)
    assert not unused, f"these transitions are listed but no corpus row exercises them: {unused}"


def test_no_source_file_of_this_suite_carries_a_literal_divergent_blank():
    """The defect this change is about, applied to the suite's own bytes.

    `40-premise-file.py` and every answer file of this spec's own record contain ZERO literal
    U+00A0, VT, FF, CR or U+2028 (claim a3): four worked examples were written with a literal
    U+00A0 that the record normalised into an ordinary space, and one docstring visibly
    self-corrects mid-sentence as its author watches the character vanish. A test written from
    those descriptions passes while exercising an ordinary space. Every divergent blank in this
    suite is therefore built from its CODEPOINT, and this reads the files back to prove it -
    the same probe claim a3 ran over the frontier files, pointed at the suite instead."""
    for name in SUITE_FILES:
        text = (TESTS_DIR / name).read_text(encoding="utf-8")
        literals = sorted({hex(ord(c)) for c in text if c.strip() == "" and c not in " \t\n"})
        assert not literals, (
            f"{name} carries literal divergent blank(s) {literals} in its source. A character "
            "typed into a docstring or a fixture is one an editor, a paste or a frontier file "
            "can normalise into a space, and the test then passes while exercising a space."
        )
    # The control the assertion above needs: the corpus really does exercise those characters,
    # so "no literals" is not green because nothing is being tested.
    assert base.NBSP not in (TESTS_DIR / "_baseline_959.py").read_text(encoding="utf-8")
    assert any(base.NBSP in c["command"] for c in CASES)
    assert [ord(base.NBSP), ord(base.CR), ord(base.VT), ord(base.FF), ord(base.LSEP)] == [
        0x00A0, 0x000D, 0x000B, 0x000C, 0x2028,
    ]
