"""#959 - constants shared by the bash-scanner tests: policies, the divergent-blank alphabet, and the lexing-refusal arms.

Every divergent blank is built from its CODEPOINT, never a literal character, so no editor or copy-paste can normalise it into a plain space.
"""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

from defender.agents import MAIN_DEF
from defender.runtime.agent_definition import compile_policy_for

RUN = Path("/run")
DFN = Path("/dfn")

MAIN = compile_policy_for(MAIN_DEF, run_dir=RUN, defender_dir=DFN)


@functools.cache
def _gather_policy() -> Any:
    """Gather's policy, compiled on first use from the committed playground tenant's grant.

    #1106 M4: `GATHER_DEF` carries no table grant (a grant fixed per process), so gather is
    compiled from a RUN's grant — and lazily, so importing this module reads no settings file.
    `GATHER` and `POLICIES` below stay attribute-spelled (`base.GATHER`) through the module
    `__getattr__`."""
    from defender.tests import _tenants1106

    return compile_policy_for(_tenants1106.fixture_gather_def(), run_dir=RUN, defender_dir=DFN)


def __getattr__(name: str) -> Any:
    if name == "GATHER":
        return _gather_policy()
    if name == "POLICIES":
        return {"main": MAIN, "gather": _gather_policy()}
    raise AttributeError(name)

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

BASH_BLANKS = ("", "   ", "\t", "\n")


REPORT = "/run/report.md"

WRAPPER_LATER_TOKEN_SHAPES = (
    ("sh-lc",              "sh -lc 'ls'"),
    ("stray-word-after-c", "bash -c 'cat " + REPORT + "' extra"),
    ("flag-between",       "bash -x -c 'echo hi'"),
    ("glued-c",            "bash -c'echo hi'"),
    ("bash-script",        "bash " + REPORT),
    ("second-wrapper",     "bash -c 'echo a' bash -c 'echo b'"),
    ("c-then-second-line", "bash -c 'ls'\ncat /etc/hosts"),
)

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
    # An unclosed quote that happens to have a `bash -c` in front of it. It reaches the same arm
    # as `quote-never-closes` above and always did - the wrapper step never got a say about a
    # quote that never closes - so it survives #971 unchanged. That is what makes it worth
    # keeping: the control that says the two arms above went and this one did not.
    ("unclosed-quote-inside-c", "bash -c 'cat " + REPORT,                  False, False),
)
