r"""#959 - the FROZEN BASELINE corpus: the gate's whole decision, recorded before the change.

This module is the corpus and the recorder; `_baseline_959_frozen.json` beside it is the
RECORDING, taken at the spec's base commit while the four places that decide where a bash word
ends still all disagree. `test_959_frozen_baseline.py` replays it.

WHY IT EXISTS, AND WHY IT HAD TO BE BUILT BEFORE THE IMPLEMENTATION (FK7, human-resolved).
O3 says every verdict this refactor changes is in one written, enumerated set and everything
else is verdict-neutral. The two instruments that were supposed to certify that - the #897
reject-direction differential and the #955 accept-direction one - carry NO wrapper word, NO
carriage return and NO blank other than an ordinary space in their corpora (claims c9, x12).
"Verdict-neutral" therefore meant "no test that already existed changed its mind", over a
corpus with zero coverage of the three classes this change touches, which is how three of the
five live divergences found in this flow survived every prior review round. The only instrument
that can discharge the obligation is a recording of the CURRENT gate's whole decision over a
corpus that does carry those three classes - and the window in which it can be taken closes the
moment the parser changes. The recording is committed with the spec and is NEVER regenerated
afterwards: a re-record after the implementation lands certifies nothing at all, and
`test_the_recorded_baseline_predates_the_change_it_certifies` is the guard that says so.

WHAT A VERDICT IS (F2, resolved): the whole `BashDecision` - whether it allows, WHICH REASON it
names, and the PIPELINES it hands the box. A record here is all three. Reason IDENTITY, not the
reason's text: F4 strikes a clause out of `UNTOKENIZABLE_REASON` on purpose, so the recorder
resolves a reason against the live constants and stores the symbolic name.

NO DIVERGENT BLANK IN THIS FILE IS A LITERAL CHARACTER (45-dispositions RF-J2, claim a3). This
spec's own premise record contains ZERO literal U+00A0, VT, FF, CR or U+2028: four worked
examples were written with a literal U+00A0 that the record then normalised into an ordinary
space, and one docstring visibly self-corrects mid-sentence as its author watches the character
vanish. A corpus written that way exercises a space while claiming to exercise a no-break
space - the issue's own defect class, inside the paperwork about it. So every blank here is
built from its CODEPOINT (`chr(0x00A0)`), which is one step stronger than an escape: there is
no character in the source for an editor, a copy-paste or a frontier file to normalise, and
`test_no_source_file_of_this_suite_carries_a_literal_divergent_blank` reads these files' own
bytes back to prove it.

THE CORPUS IS STATIC ON PURPOSE. Nothing here is derived from `_WORD_SEPARATORS` or from any
other constant the change edits: a corpus that moved with the code would replay a different
question than the one that was recorded. The DERIVED form of the alphabet is checked against
this frozen tuple in `test_959_scanner.py`, which is where a drift between the two belongs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.agents import GATHER_DEF, MAIN_DEF
from defender.runtime import permission
from defender.runtime.agent_definition import compile_policy_for
from defender.runtime.permission import bash as _bash

FROZEN = Path(__file__).with_name("_baseline_959_frozen.json")

#: The synthetic run roots every recorded decision is taken against - the same pair
#: `test_permission.py` uses, so a recorded verdict is comparable with the rest of the suite.
#: `decide_bash` resolves an operand but never stats it, so they need not exist.
RUN = Path("/run")
DFN = Path("/dfn")

MAIN = compile_policy_for(MAIN_DEF, run_dir=RUN, defender_dir=DFN)
GATHER = compile_policy_for(GATHER_DEF, run_dir=RUN, defender_dir=DFN)
POLICIES = {"main": MAIN, "gather": GATHER}

#: The 26 characters `str.strip()` removes that bash does not treat as a blank at all, written
#: as CODEPOINTS and FROZEN here (claim a1, computed: `str.strip()`'s 29 minus space, tab and
#: newline - newline excluded because `parse` splits physical lines on it before `_scan` ever
#: runs). U+000D is the 26th, and it is in this alphabet only because M6 takes it out of
#: `_WORD_SEPARATORS`; the closed set that said 25 had counted against the very constant this
#: change edits.
DIVERGENT_BLANK_CODEPOINTS = (
    0x000B, 0x000C, 0x000D, 0x001C, 0x001D, 0x001E, 0x001F, 0x0085,
    0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
    0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F,
    0x205F, 0x3000,
)
DIVERGENT_BLANKS = tuple(chr(cp) for cp in DIVERGENT_BLANK_CODEPOINTS)

NBSP = chr(0x00A0)
VT = chr(0x000B)
FF = chr(0x000C)
CR = chr(0x000D)
LSEP = chr(0x2028)
NUL = chr(0x0000)

#: The three bash blanks plus the empty command, which stay the allowed no-op (`""` is the
#: falsy member, and `if not cmd` is the swallow shape).
BASH_BLANKS = ("", "   ", "\t", "\n")


def reason_classes(policy) -> tuple[tuple[str, str], ...]:
    """Every message a refusal can carry, paired with the id this corpus stores it under.

    THE SET, IN ONE PLACE, because the derivation that needed it was one function away from it
    (RC12). Member 8 is about which of these messages a refusal earns, and an axis derived from
    HOW a message is produced misses one: three of the four are RAISED and `ADAPTER_RETIRED_REASON`
    is RETURNED, so a walk over `raise UntokenizableCommand` sites cannot reach it by construction.
    `test_every_lexing_refusal_arm_the_code_has_is_swept` reads this tuple and requires every class
    in it to have arms swept at both ends, whatever statement form produces it."""
    return (
        ("untokenizable", permission.UNTOKENIZABLE_REASON),
        ("embedded-nul", _bash.EMBEDDED_NUL_REASON),
        ("adapter-retired", _bash.ADAPTER_RETIRED_REASON),
        ("policy-deny", policy.deny_reason),
    )


@dataclass(frozen=True)
class Case:
    """One corpus entry.

    `member` is `""` for a shape this change must leave alone, or the enumerated verdict-change
    member(s) it belongs to (`"1"`, `"2"`, `"1+4"` for a composition of two). `after` is the
    decision an enumerated shape must reach AFTER the change - present iff `member` is set, and
    asserted by the replay, so the recorded old verdict can never be mistaken for the contract.
    """

    cid: str
    command: str
    member: str = ""
    after: dict[str, Any] | None = None
    policy: str = "main"


#: The reason slot of an `after` record, when ANOTHER demand of this spec owns that reason's
#: identity. FK6 (auto-resolved) obliges a command refused ONLY for a character the model cannot
#: see to be told which character and where, rather than handed a generic deny - so for exactly
#: those shapes the reason a refusal earns is
#: `test_a_command_refused_only_for_an_invisible_character_is_told_so`'s to pin - the WHOLE
#: invisible class, not the line ending alone (RC2, human-resolved at the verify loop: 78 of the
#: 91 cases delegating their reason here carry no carriage return at all) - and pinning a second
#: answer here would put two conflicting contracts in one spec. The allow half and the
#: argv half stay exact; nothing is unasserted, the assertion just lives at the demand that owns
#: it.
OWNED_ELSEWHERE = "*"


def _deny(reason: str = "policy-deny") -> dict[str, Any]:
    """A refusal. `reason` is a reason id, `"*"` where another demand owns it, or `"!<id>"`
    where what this spec demands is that the reason is no longer that one."""
    return {"allow": False, "reason": reason, "pipelines": None}


def _allow(*stages: tuple[list[str], str]) -> dict[str, Any]:
    """An allow whose pipelines are ONE pipeline of `stages` - all the shapes below need."""
    return {
        "allow": True,
        "reason": "none",
        "pipelines": [[[list(argv), stderr] for argv, stderr in stages]],
    }


REPORT = "/run/report.md"


#: The wrapper shapes whose LAST token is not the wrapper word, swept with a trailing divergent
#: blank. RESOLVED AT §7 (RF-E8, human, third verify loop): these KEEP THE SPECIFIC LEXING REASON.
#: A faithful folded matcher recognises the wrapper by its FIRST token, so the shape is still
#: recognisably a wrapper and cause (5) still names it — a stray word after the `-c` string is a
#: stray word whether or not it ends in a character nobody can see. Rejected: falling back to the
#: capability deny (182 more shapes into member 8, and the model loses the message that says what
#: is actually wrong — the same message-loss the last three findings were about), and leaving it
#: unrecorded, where whichever way the implementer happened to build it would silently become the
#: answer.
#:
#: THE DECISION IS ABOUT THE TRAILING END ONLY, and the leading end inverts it — an OBSERVATION,
#: not a second decision (RC11). `<blank>bash -c '<cmd>' extra` has `<blank>bash` as its first
#: token, which no matcher recognises as `bash` on any implementation this spec permits (matching
#: is on resolved values and exact, per three settled phase-C premises), so the shape falls
#: through to the capability path whether the fold is there or not. RF-E8's unanswerable-by-probe
#: status does not reach that end: the uncertainty it named was about a matcher that still SEES
#: `bash` first, and here nothing does. Those rows are member 8, executed 26/26.
#:
#: SO THE TRAILING ROWS ARE NEUTRAL BY DECISION, NOT BY OBSERVATION. That distinction is the whole point
#: of recording them: an M4+M6+M2 simulation reports these shapes MOVING, but the simulation
#: parses without the fold, which is exactly the code the answer depends on. A later reader must
#: not read these rows as a measurement — they are a contract, and
#: `test_every_wrapper_shape_the_lexing_reason_names_is_still_refused_for_that_reason` states it
#: as an obligation on the implementation rather than leaving it to be inferred from a row.
WRAPPER_LATER_TOKEN_SHAPES = (
    ("sh-lc",              "sh -lc 'ls'"),
    ("stray-word-after-c", "bash -c 'cat " + REPORT + "' extra"),
    ("flag-between",       "bash -x -c 'echo hi'"),
    ("glued-c",            "bash -c'echo hi'"),
    ("bash-script",        "bash " + REPORT),
    ("second-wrapper",     "bash -c 'echo a' bash -c 'echo b'"),
    ("c-then-second-line", "bash -c 'ls'\ncat /etc/hosts"),
)

#: THE ARMS OF THE REASON CLASSES THAT ARE RETURNED RATHER THAN RAISED (RC12). `LEXING_ARMS`
#: above is the `UNTOKENIZABLE_REASON` class, and it is AST-derivable because every one of its
#: arms is a `raise`. The other three classes are `return`s, so no derivation built on raise sites
#: can reach them — which is exactly how the adapter class stayed outside member 8 while a leading
#: blank moved 78 of its shapes off it. The axis was never "places that raise"; it is "places that
#: decide which message a refusal carries", and `reason_classes()` is the set.
#:
#: `adapter-retired` moves at the LEADING end only, 26/26 executed, and the mechanism is the
#: wrapper arm's exactly: `is_adapter_stage` reads `argv[0]`, a leading blank makes that
#: `<blank>defender-elastic`, `startswith("defender-")` is then false and `ADAPTER_RE` does not
#: match, so the stage is not an adapter and the decision falls through to the policy reason. A
#: trailing blank lands on the last operand and leaves `argv[0]` intact — 0/26, the same asymmetry
#: the wrapper arm has, for the same reason. Determined rather than chosen: no permitted matcher
#: reads `<blank>defender-elastic` as an adapter, so the unwritten fold cannot change it.
#:
#: WHAT THE ADAPTER MESSAGE COSTS WHEN IT IS LOST is sharper than the lexing case: it is not a
#: diagnosis but a REDIRECTION — it names the `query` tool the model should have used and gives
#: the call shape. A model that pastes an adapter command with a no-break space in front of it
#: gets "not permitted for this agent" and has no way to discover either the character or the
#: route it was supposed to take.
#:
#: `embedded-nul` and `policy-deny` are swept as NON-MOVERS at both ends, 26/26 each: the NUL arm
#: fires over the whole raw string before anything else is asked, and the policy reason is the
#: fall-through itself, so there is nothing below it to fall to.
RETURNED_REASON_ARMS = (
    # reason class        arm id                 base command                                trail  lead
    ("adapter-retired", "elastic-standalone", "defender-elastic query foo",                 False, True),
    ("adapter-retired", "elastic-sql-pipe",
     "defender-elastic query x | defender-sql 'SELECT 1'",                                  False, True),
    ("adapter-retired", "adapter-script",
     "python3 scripts/adapters/elastic_adapter.py --q x",                                   False, True),
    ("embedded-nul",    "nul-in-an-operand",   "cat " + REPORT + NUL,                       False, False),
    ("policy-deny",     "ungranted-program",   "ls -la",                                    False, False),
    ("policy-deny",     "outside-every-scope", "cat /etc/hosts",                            False, False),
)

#: The separators a divergent blank can sit immediately after, and what that costs. `|`, `&&`
#: and `||` are DANGLING connectors: today the blank is a separator, the connector is the line's
#: last token, and the per-line completeness check refuses with the LEXING reason - the one
#: message that names the problem and tells the model to rewrite on one line. After the change
#: the blank is a word of its own, the connector is no longer last, that check is out of reach,
#: and the refusal falls through elsewhere: deny -> deny, with the reason moving. `;` is NOT a
#: dangling connector, so nothing looked at it before and the command was ALLOWED: allow -> deny,
#: which is member 1's direction at member 8's position, hence the composed tag.
SEPARATORS = (("pipe", "|", "8"), ("and", "&&", "8"), ("or", "||", "8"), ("semicolon", ";", "1+8"))

#: THE LEXING ARMS - every check in the tree that answers a refusal with the LEXING reason rather
#: than the generic capability one, each with a base shape that reaches it and what a trailing
#: divergent blank does to it. DERIVED FROM THE CODE, not from a list of shapes someone noticed:
#: `test_every_lexing_refusal_arm_the_code_has_is_swept` AST-walks every `raise
#: UntokenizableCommand` in `bash_exec.py` and `permission/bash.py` and requires each one to be
#: reached by an arm below, so a new arm cannot be added without a decision about this axis.
#:
#: THE PREDICATE, which is why this is a family and not a list: a refusal moves iff it is decided
#: by the text of the LAST token. Append a blank there and that token stops matching the pattern
#: the arm recognises, so the command falls through to the capability path - still refused, and
#: correctly, but with the message that told the model what to fix replaced by one that does not.
#: Where the failing construct is somewhere else in the command (an unclosed quote, a connector at
#: a line boundary, a `|` whose right side is empty three tokens back), nothing moves. Both halves
#: are swept: the movers are member 8, the non-movers are recorded as NEUTRAL, which is what says
#: the sweep was run against the whole arm set rather than against the part of it that moves.
#:
#: `moves=True` rows carry member 8; `moves=False` rows carry no member and must reach the same
#: decision after the change as before it. Every value here was executed under the M4+M6+M2
#: simulation over all 26 characters before it was written down - 26/26 either way, never mixed.
LEXING_ARMS = (
    # id                        base command                            trail   lead
    # bash_exec.py:281 `_scan` returned nothing - and the two causes that reach it part company.
    ("quote-never-closes",      "cat " + REPORT + " | grep 'unterminated", False, False),
    ("newline-inside-a-quote",  "cat " + REPORT + " | grep 'a\nb'",       False, False),
    ("trailing-backslash",      "cat " + REPORT + " \\",                   True, False),
    # bash_exec.py:206 a `|` that banked a stage with nothing complete to its right.
    ("pipe-into-a-bare-redirect", "cat " + REPORT + " | 2> /dev/null",     True, False),
    ("pipe-then-semicolon",     "cat " + REPORT + " | ; wc -l",            False, False),
    # bash_exec.py:237 a connector with no command to its left.
    ("connector-opens-a-line",  "| wc -l",                                 False, True),
    # bash_exec.py:290 a connector closing a line. The single-separator spelling of this arm is
    # already swept above (`cat P |{blank}`); what is added here is the ACROSS-LINES spelling,
    # where the blank lands on a later line and the refusal does not move.
    ("connector-across-lines",  "cat " + REPORT + " |\nwc -l",            False, False),
    # bash_exec.py:304 an `&&`/`||` whose right side never arrived within its own line.
    ("pending-connector",       "cat " + REPORT + " && ;",                 True, False),
    # permission/bash.py:107 a wrapper that does not fold to a single command string. This arm
    # is the one that moves at BOTH ends, and for different reasons: at either end the blank lands
    # on the wrapper word itself, which no matcher recognises once it is glued. The shapes whose
    # LATER token carries the blank are the RF-E8 table below, and they part company with this arm
    # at the trailing end only.
    ("bare-bash",               "bash",                                    True, True),
    ("bare-sh",                 "sh",                                      True, True),
    ("unclosed-quote-inside-c", "bash -c 'cat " + REPORT,                  False, False),
)


def _blank_sweep() -> list[Case]:
    """Every member of the closed alphabet at every position it occupies: both ends of an
    allowed pipeline, the whole command, the operand of a program that opens nothing, and
    immediately after each of the four separators the grammar has.

    Swept, never sampled, and swept over the ALPHABET rather than over a character. Member 1 was
    written as 25 characters because it was measured against the very constant this change
    edits; member 8 was written as a carriage-return rule because a carriage return was what the
    finding that produced it was about, and it is a 26-character family (RC6). Both are the same
    error, two members apart, and this loop is what makes the difference between them a template
    rather than a hand-written example.
    """
    cases: list[Case] = []
    for blank in DIVERGENT_BLANKS:
        tag = f"u{ord(blank):04x}"
        cases += [
            Case(f"m1-lead-cat-{tag}", blank + "cat " + REPORT, "1", _deny(OWNED_ELSEWHERE)),
            Case(f"m1-trail-cat-{tag}", "cat " + REPORT + blank, "1", _deny(OWNED_ELSEWHERE)),
            Case(f"m1-whole-{tag}", blank, "1", _deny(OWNED_ELSEWHERE)),
            # The half a check reading only allow/deny cannot see: for an `OPENS_NOTHING`
            # program whose grant shape ends in a bare VALUE, the blank belongs to the operand
            # and the command stays ALLOWED - with a different argv crossing into the box.
            Case(
                f"m1-trail-echo-{tag}", "echo hi" + blank, "1",
                _allow((["echo", "hi" + blank], "capture")),
            ),
        ]
        for name, shape in WRAPPER_LATER_TOKEN_SHAPES:
            # Trailing: neutral BY DECISION (RF-E8) - the wrapper is recognised by its first
            # token, so an invisible character on a LATER token may not move the reason class.
            cases.append(
                Case(f"neutral-wrapper-{name}-{tag}", shape + blank, "", None)
            )
            # Leading: the blank lands ON the wrapper word, which no matcher recognises. Member 8
            # by OBSERVATION (26/26 executed), and the boundary of the decision above.
            cases.append(
                Case(f"m8-lead-wrapper-{name}-{tag}", blank + shape, "8",
                     _deny("!untokenizable"))
            )
        for cls, arm, base, moves_trailing, moves_leading in RETURNED_REASON_ARMS:
            # The same rule, over the reason classes a `return` produces rather than a `raise`.
            for position, cmd, moves in (
                ("", base + blank, moves_trailing),
                ("lead-", blank + base, moves_leading),
            ):
                cases.append(
                    Case(f"{'m8' if moves else 'neutral'}-{position}reason-{cls}-{arm}-{tag}",
                         cmd, "8" if moves else "",
                         _deny("!adapter-retired") if moves else None)
                )
        for arm, base, moves_trailing, moves_leading in LEXING_ARMS:
            # The refusal is already a refusal; what an invisible character can move is WHICH ARM
            # answers it, and F2 makes the reason identity part of the verdict. Swept at both
            # ends, because the blank glues to the token it touches and the arms differ in which
            # token their decision turns on.
            for position, cmd, moves in (
                ("", base + blank, moves_trailing),
                ("lead-", blank + base, moves_leading),
            ):
                cases.append(
                    Case(f"{'m8' if moves else 'neutral'}-{position}arm-{arm}-{tag}", cmd,
                         "8" if moves else "", _deny("!untokenizable") if moves else None)
                )
        for name, sep, member in SEPARATORS:
            # `|`/`&&`/`||`: the LEXING reason answers today and may not answer after, which is
            # the whole of member 8 - what it becomes is the invisible-character demand's to
            # pin. `;`: allowed today, refused after, so the allow flip carries the change and
            # the reason is again owned by that demand.
            after = _deny("!untokenizable") if member == "8" else _deny(OWNED_ELSEWHERE)
            cases.append(
                # The id carries the member verbatim, `+` included: `m18-…` for the composed
                # tag would read as "member 18" to the one reader this corpus exists for, the
                # human auditing the written set against the rows.
                Case(f"m{member}-after-{name}-{tag}",
                     "cat " + REPORT + " " + sep + blank, member, after)
            )
    return cases


#: The corpus. Hand-authored shapes first, then the swept alphabet.
CORPUS: tuple[Case, ...] = tuple([
    # ---------------------------------------------------------------- neutral: the plain lane
    Case("plain-cat", "cat " + REPORT),
    Case("plain-pipe", "cat " + REPORT + " | wc -c"),
    Case("plain-three-stage", "cat " + REPORT + " | grep alpha | wc -l"),
    Case("plain-echo", "echo hi"),
    Case("plain-true", "true"),
    Case("plain-shim", "defender-invlang enum types"),
    Case("plain-lessons", "defender-lessons --tags"),
    Case("plain-connectors", "cat " + REPORT + " && wc -l"),
    Case("plain-semicolon", "cat " + REPORT + " ; echo done"),
    Case("plain-stderr-devnull", "cat " + REPORT + " 2>/dev/null"),
    Case("plain-stderr-stdout", "cat " + REPORT + " 2>&1"),
    Case("plain-quoted-operator", "echo ';' foo"),
    Case("plain-escaped-semicolon", "echo \\; foo"),
    Case("plain-glued-quotes", "echo 'a'\"b\"c"),
    Case("plain-dollar-not-expanded", 'echo "$HOME"'),
    Case("plain-escaped-space", "echo a\\ b"),
    Case("plain-fd-glued", "cat " + REPORT + " 2>/dev/null | wc -c"),
    # ------------------------------------------------------------ neutral: refusals of today
    Case("deny-ungranted-program", "ls -la"),
    Case("deny-outside-scope", "cat /etc/hosts"),
    Case("deny-write-redirect", "cat " + REPORT + " > /tmp/out"),
    Case("deny-background", "cat " + REPORT + " & rm -rf /"),
    Case("deny-substitution", "cat $(cat injected)"),
    Case("deny-process-substitution", "cat <(id)"),
    Case("deny-fd-on-a-value", "head -c 2 >/dev/null"),
    Case("deny-adapter", "defender-elastic query foo"),
    Case("deny-adapter-pipe", "defender-elastic query x | defender-sql 'SELECT 1'"),
    Case("deny-embedded-nul", "cat " + REPORT + NUL),
    Case("untok-unbalanced-quote", "cat " + REPORT + " | grep 'unterminated"),
    Case("untok-newline-in-quote", "cat " + REPORT + " | grep 'a\nb'"),
    Case("untok-trailing-backslash", "cat " + REPORT + " \\\n | wc -l"),
    Case("untok-connector-closes-line", "cat " + REPORT + " |\nwc -l"),
    Case("untok-connector-opens-line", "cat " + REPORT + "\n| wc -l"),
    Case("untok-pipe-then-semicolon", "cat " + REPORT + " | ; wc -l"),
    Case("untok-pipe-then-pipe", "cat " + REPORT + " | | wc -l"),
    Case("untok-connector-then-semicolon", "cat " + REPORT + " && ;"),
    Case("untok-pipe-into-redirect", "cat " + REPORT + " | 2> /dev/null"),
    # ------------------------------------------------- neutral: the bash blanks, still no-ops
    Case("blank-empty", ""),
    Case("blank-spaces", "   "),
    Case("blank-tab", "\t"),
    Case("blank-newline", "\n"),
    Case("blank-trailing-newline", "cat " + REPORT + "\n"),
    # ------------------------------- neutral: a divergent blank that is NOT at either end
    Case("neutral-interior-blank-echo", "echo a" + NBSP + "b"),
    Case("neutral-interior-blank-operand", "cat " + REPORT + NBSP + "| wc -c"),
    Case("neutral-blank-glued-to-timeout", "timeout" + NBSP + "5 cat " + REPORT),
    Case("neutral-blank-glued-to-bash", "bash" + NBSP + "-c 'ls'"),
    Case("neutral-blank-inside-c-argument", "bash -c '" + NBSP + "cat " + REPORT + "'"),
    Case("neutral-blank-is-the-whole-c-argument", "bash -c '" + NBSP + "'"),
    Case("neutral-quoted-blank", "echo 'a" + NBSP + "b'"),
    # --------------------------------------------- neutral: carriage returns that do not move
    Case("neutral-quoted-cr-operand", "cat '" + REPORT + CR + "'"),
    Case("neutral-quoted-cr-echo", "echo 'a" + CR + "b'"),
    Case("neutral-cr-before-fd-marker", "cat " + REPORT + " 2" + CR + ">/dev/null"),
    # ------------------------------------------------------- neutral: the wrapper words today
    Case("wrap-bash-c", "bash -c 'cat " + REPORT + "'"),
    Case("wrap-bash-c-pipeline", "bash -c 'cat " + REPORT + " | wc -l'"),
    Case("wrap-sh-c", "sh -c 'echo hi'"),
    Case("wrap-quoted-bash", '"bash" -c "echo hi"'),
    Case("wrap-concatenated-bash", "'ba''sh' -c 'echo hi'"),
    Case("wrap-glued-c", "bash -c'echo hi'"),
    Case("wrap-flag-between", "bash -x -c 'echo hi'"),
    Case("wrap-uppercase", "BASH -c 'echo hi'"),
    Case("wrap-bare-bash", "bash"),
    Case("wrap-bare-sh", "sh"),
    Case("wrap-bash-script", "bash " + REPORT),
    Case("wrap-sh-lc", "sh -lc 'ls'"),
    Case("wrap-stray-word-after-c", "bash -c 'cat " + REPORT + "' extra"),
    Case("wrap-second-wrapper", "bash -c 'echo a' bash -c 'echo b'"),
    Case("wrap-unclosed-inside-c", "bash -c 'cat " + REPORT),
    Case("wrap-empty-c", "bash -c ''"),
    Case("wrap-c-then-second-line", "bash -c 'ls'\ncat /etc/hosts"),
    # (`wrap-timeout`, `wrap-timeout-fractional`, `wrap-timeout-then-line` and
    #  `wrap-timeout-then-bash-c` were here too, recorded as allows. #971 moves them into
    #  member 9 below; the `timeout` rows that stay are the ones that were denials already,
    #  which do not move - only the code that refuses them does.)
    Case("wrap-timeout-suffix-duration", "timeout 5s cat " + REPORT),
    Case("wrap-timeout-signal-flag", "timeout -s KILL 5 cat " + REPORT),
    Case("wrap-bare-timeout", "timeout"),
    Case("wrap-timeout-double-dash", "timeout --"),
    Case("wrap-timeout-twice", "timeout 5 timeout 3 cat " + REPORT),
    Case("wrap-timeout-inside-c", "bash -c 'timeout 5 cat " + REPORT + "'"),
    Case("wrap-nested-bash-c", "bash -c 'bash -c \"echo hi\"'"),
    # ------------------------------------------------------------------ neutral: gather's lane
    Case("gather-payload-pipe", "cat /run/gather_raw/l-1/0.json | grep hits", policy="gather"),
    Case("gather-adapter-denied", "defender-elastic query foo", policy="gather"),
    Case("gather-untok-wrapper", "bash -c 'cat " + REPORT + "' extra", policy="gather"),
    # ============================================== the enumerated set - members 1 through 7
    # 1: leading/trailing divergent blanks - the deleted trim (M4). The sweep below carries the
    #    whole 26-character alphabet at both ends; these are the composed spellings.
    Case("m1-stacked-real-and-divergent", " " + NBSP + "cat " + REPORT, "1",
         _deny(OWNED_ELSEWHERE)),
    Case("m1-lead-vt-pipeline", VT + "cat " + REPORT + " | wc -c", "1",
         _deny(OWNED_ELSEWHERE)),
    Case("m1-trail-ls-pipeline", "cat " + REPORT + " | wc -c" + LSEP, "1",
         _deny(OWNED_ELSEWHERE)),
    # 2: `\r` inside or at the edge of a word (M6, and M2 with it). BOTH directions.
    Case("m2-cr-inside-operand", "cat " + REPORT + CR + "x", "2", _deny(OWNED_ELSEWHERE)),
    Case("m2-cr-at-word-edge", "cat " + REPORT + CR, "2", _deny(OWNED_ELSEWHERE)),
    Case("m2-cr-inside-program-word", "cat" + CR + REPORT, "2", _deny(OWNED_ELSEWHERE)),
    Case("m2-cr-before-connector", "cat " + REPORT + CR + "| wc -c", "2", _deny(OWNED_ELSEWHERE)),
    Case("m2-cr-as-its-own-word", "cat " + REPORT + " " + CR + "| wc -c", "2", _deny(OWNED_ELSEWHERE)),
    Case("m2-crlf-physical-lines", "cat " + REPORT + CR + "\nwc -l", "2", _deny(OWNED_ELSEWHERE)),
    Case("m2-cr-opens-nothing", "echo a" + CR + "b", "2",
         _allow((["echo", "a" + CR + "b"], "capture"))),
    Case("m2-cr-in-program-of-opens-nothing", "echo" + CR + "a", "2", _deny(OWNED_ELSEWHERE)),
    Case("m2-cr-gather-lane", "cat " + REPORT + CR + "x", "2",
         _deny(OWNED_ELSEWHERE), "gather"),
    # RC1's named sibling: inside member 2's written description, absent from the corpus until
    # phase F read the other half of the neighbourhood. ALLOWED today as `['cat', P]` with
    # stderr on /dev/null, while real bash runs `cat P<CR>2` with STDOUT redirected - an operand
    # changed AND both streams re-routed. Its mirror (`cat P 2<CR>>/dev/null`) was already here,
    # tagged neutral; this direction was not.
    Case("m2-cr-before-the-fd-marker-itself", "cat " + REPORT + CR + "2>/dev/null", "2",
         _deny(OWNED_ELSEWHERE)),
    # (The `\r`-after-a-`;` spelling moved into the sweep at the second verify loop, tagged
    # `1+8`: the `\r` is not inside a word there, it becomes a STAGE OF ITS OWN - member 8's
    # mechanism at member 1's position and in member 1's direction. Filing it under member 2
    # sent a reader auditing the set to a sentence that does not describe it.)
    # 3: an outer operator after a `bash -c` argument (M3) - the fix's own headline case.
    Case("m3-outer-operator", "bash -c 'echo a '2>/dev/null", "3", _deny("untokenizable")),
    Case("m3-outer-operator-cat", "bash -c 'cat " + REPORT + " '2>/dev/null", "3",
         _deny("untokenizable")),
    # 4 WAS "a quoted `timeout` wrapper word is skipped like any other prefix" - the one
    # deny->allow member. #971 RETIRES IT into member 9: there is no prefix arm left for a
    # quoted spelling to reach, and both shapes are refused on the capability reason with the
    # rest of the class. The number is left standing rather than reused, so a reader tracing a
    # member id through this spec's history lands where they expect.
    Case("m4-quoted-duration", "timeout '5' cat " + REPORT, "9", _deny()),
    Case("m4-quoted-wrapper-word", '"timeout" 5 cat ' + REPORT, "9", _deny()),
    # ...composed with member 1. It WAS the union of two accepted changes; the blank is not
    # part of the answer any more, because `timeout` is ungranted with it and without it. What
    # survives is the demand that always mattered here: not the lexing reason. (That the blank
    # must now NOT be named either is
    # `test_a_blank_glued_to_an_ungranted_word_is_not_blamed_for_the_refusal`'s to pin - the
    # `!untokenizable` slot cannot say it.)
    Case("m4-quoted-with-leading-blank", NBSP + "timeout '5' cat " + REPORT, "1+4",
         _deny("!untokenizable")),
    Case("m4-quoted-with-trailing-blank", "timeout '5' cat " + REPORT + NBSP, "1+4",
         _deny("!untokenizable")),
    # 5: a newline inside a `bash -c` argument (M3 + F5).
    Case("m5-newline-in-c", "bash -c 'cat " + REPORT + "\nwc -l'", "5", _deny(OWNED_ELSEWHERE)),
    Case("m5-newline-in-c-with-cr", "bash -c 'cat " + REPORT + "\nwc -l" + CR + "'", "5",
         _deny(OWNED_ELSEWHERE)),
    # 6 is the slot the assembler reserved for FK1 while it was pending at the human seam;
    # FK1 landed as member 7, so the set numbers to seven and holds six distinct shapes.
    # 7: a `timeout` prefix with no duration-shaped token (FK1, MINIMAL arm only). Member 9
    # subsumes the rule - NO prefix is recognised now - and these two keep the verdict they
    # were enumerated for, reached by the wider rule instead of the minimal one.
    Case("m7-timeout-no-duration", "timeout cat " + REPORT, "7", _deny()),
    Case("m7-timeout-no-duration-echo", "timeout echo hi", "7", _deny()),
    # 9 (#971): A `timeout` PREFIX IS NOT A WRAPPER AT ALL. Every row here was an ALLOW under
    # the fold, reached by DELETING the prefix from the text before the decision - which is what
    # made every mis-read a widening rather than a refusal: `timeout\n5 cat P` (the prefix
    # straddling a line boundary) and `timeout --foreground cat P` (a prefix carrying no
    # duration at all) both folded to `cat P` and authorised a command real `timeout` never
    # runs. Two live deny->allow holes in one arm, found by review rather than by the corpus,
    # which carried neither spelling.
    #
    # And the fold honoured nothing it appeared to. The stripped prefix was DISCARDED, not
    # executed - there is no `timeout` binary in the box - so the bound the model asked for was
    # dropped in silence and the command ran under the runtime's own 120s deadline. Granting the
    # word instead was rejected for a sharper reason: `timeout` turns the rest of the argv into
    # a new program, the one shape a per-stage grant ladder must never be loose about.
    #
    # So it is an ordinary ungranted word, and the lane's capability reason - which names the
    # programs the lane does have - answers on the same turn. Pass-through cannot widen; a fold
    # can. That asymmetry is the whole of the argument, and it is why this is a deletion rather
    # than a third repair of the same arm.
    Case("wrap-timeout", "timeout 5 cat " + REPORT, "9", _deny()),
    Case("wrap-timeout-fractional", "timeout 0.5 cat " + REPORT, "9", _deny()),
    Case("wrap-timeout-then-line", "timeout 5\ncat " + REPORT, "9", _deny()),
    Case("wrap-timeout-then-bash-c", "timeout 5 bash -c 'echo hi'", "9", _deny()),
    # 8 (RC1, human-resolved at the verify loop; widened to the whole alphabet at the second
    # loop, RC6): A DIVERGENT BLANK IMMEDIATELY AFTER A SEPARATOR - 26 characters x 4
    # separators, all 104 of which move, with the carriage return as the worked example rather
    # than the subject. The shape a CRLF paste makes. Today the `\r` is a separator, the connector is the line's last
    # token, and the line-completeness check refuses with the LEXING reason, which names the
    # problem and tells the model to rewrite on one line. After M4+M6+M2 the `\r` is a word of
    # its own, the connector is no longer last, that check never fires, and the refusal falls
    # through to the generic policy path. The command still fails - correctly, and more
    # faithfully to bash - but for a reason that explains nothing, on a command that renders
    # identically to one that works. What it becomes is
    # `test_a_command_refused_only_for_an_invisible_character_is_told_so`'s to pin (RC2); what
    # the replay pins here is that the lexing reason no longer answers it.
    # REJECTED at §7: special-casing the connector check to look past a trailing `\r` - bash
    # genuinely ends the pipeline there, and it would put a second private opinion about `\r`
    # back inside the change whose thesis is that there should be exactly one.
    # The three single-separator spellings are rendered by the sweep below, over the whole
    # alphabet rather than for the carriage return alone (RC6). What stays here is the spelling
    # the sweep cannot render: the connector's own line ends and the command continues on the
    # next one, which is what a CRLF paste of a two-line pipeline actually looks like.
    Case("m8-cr-after-pipe-then-line", "cat " + REPORT + " |" + CR + "\nwc -l", "8",
         _deny("!untokenizable")),
] + _blank_sweep())


def decision_record(command: str, policy_name: str = "main") -> dict[str, Any]:
    """The WHOLE decision `decide_bash` reaches for `command`, as a comparable record.

    Reason IDENTITY rather than reason text: F4 strikes a clause out of cause (5) on purpose,
    so a text comparison would report that deliberate edit as a verdict change on every shape
    the lexing reason answers.
    """
    policy = POLICIES[policy_name]
    d = permission.decide_bash(command, policy=policy, run_dir=RUN, defender_dir=DFN)
    known = reason_classes(policy)
    if not d.reason:
        reason = "none"
    else:
        reason = next((name for name, text in known if d.reason == text), "unrecognised-reason")
    return {
        "allow": d.allow,
        "reason": reason,
        "pipelines": None if d.pipelines is None else [
            [[list(st.argv), st.stderr] for st in pl.stages] for pl in d.pipelines
        ],
    }


def corpus_rows() -> list[dict[str, Any]]:
    """The corpus as plain data - what the frozen file carries, minus the recording."""
    return [
        {"id": c.cid, "command": c.command, "policy": c.policy,
         "member": c.member, "after": c.after}
        for c in CORPUS
    ]


def record(base: str) -> dict[str, Any]:
    """Take the recording. Run ONCE, at the base commit, before any implementation exists."""
    return {
        "base": base,
        "note": (
            "Recorded by defender/tests/_baseline_959.py at the spec's base commit, before the "
            "one-scanner change existed. NEVER REGENERATE: a baseline re-recorded after the "
            "implementation lands certifies nothing, and the replay's own guard "
            "(test_the_recorded_baseline_predates_the_change_it_certifies) fails if it is."
        ),
        "cases": [
            {**row, "baseline": decision_record(row["command"], row["policy"])}
            for row in corpus_rows()
        ],
    }


def frozen() -> dict[str, Any]:
    return json.loads(FROZEN.read_text(encoding="utf-8"))


if __name__ == "__main__":  # pragma: no cover - the one-shot recorder
    import sys

    FROZEN.write_text(
        json.dumps(record(sys.argv[1]), indent=1, ensure_ascii=True) + "\n", encoding="utf-8",
    )
    print(f"recorded {len(CORPUS)} cases at {sys.argv[1]} -> {FROZEN}")
