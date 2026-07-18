"""The containment model: `Grant` — one shape, one scope, one program table (#575).

A command is allowed iff it matches a grant's **shape** (program + flags + arity, NO
paths) AND every operand `PROGRAMS[grant.program]` says it opens **resolves** into that
grant's **scope** (an anchored regex over the RESOLVED path). Shape and scope are separate
and neither is interpolated into the other. That split is the whole point:

  - the old lane baked the run's roots INTO the argv regex, so containment was TEXTUAL —
    it could not see through a symlink, and it re-derived the same path grammar in three
    places (a bash regex, a read filter, a write filter) which then drifted (#545);
  - `resolve()`-then-match is a true path set: `..` collapses, a symlink out of the root
    collapses to where it points, and the same shape objects gate the read tool and the
    bash lane, so the two surfaces cannot disagree.

**What a program opens is a fact about the PROGRAM**, so it lives in one global table
(`PROGRAMS`) keyed by name, never on a grant — two agents cannot represent a disagreement
about what `cat` does. `cat` is the sole opener; every other granted program is
`OPENS_NOTHING`.

`OPENS_NOTHING` is a CLAIM, not a check: the gate skips the scope check for such a program
entirely, so its SHAPE regex is the sole containment and must earn the claim by admitting
no file-opening or arg-consuming flag (`grep -f F`, `wc --files0-from=F`, `jq --rawfile`,
`grep -r`, which walks the CWD with no operand at all). Hence every flag class here is a
POSITIVE boolean allowlist built from `gnu_flags` (read that module for why a catch-all
minus the known-bad fails OPEN — #579), and every long option is enumerated per program.
`tests/test_grant_gate_575.py` (b7/b8) enforces both properties structurally, so the
convention cannot be silently dropped by a future grammar author.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS
from defender.runtime import gnu_flags

# ── The program table ────────────────────────────────────────────────────────

Extractor = Callable[[list[str]], "list[str] | None"]


def _opens_nothing(argv: list[str]) -> list[str] | None:
    """The `OPENS_NOTHING` sentinel's body — never called (the gate tests for it by
    IDENTITY and skips the scope check), but a real callable so the table's value type is
    uniform and a caller that does invoke it gets the safe answer."""
    return []


#: The claim "this program opens no file the gate must check". Compared by IDENTITY.
OPENS_NOTHING: Extractor = _opens_nothing

# `cat`'s complete short-option set (coreutils). EVERY one is boolean — `cat` has no
# arg-taking flag at all. That is the whole reason `cat` is the ONE file-opening program:
# "which files does this argv open?" is answerable without reimplementing an option parser
# (jq's `-f`/`-L`/`--slurpfile`/`--rawfile` + short-bundle arg consumption needed ~60 lines
# and three fail-closed branches to answer the same question). `gnu_flags.CAT_BOOL` is the
# SOLE encoding of that option set — this extractor and the `cat` shape below both compile
# it, so they cannot drift apart.
_CAT_BOOL_BUNDLE = re.compile(gnu_flags.bundle(gnu_flags.CAT_BOOL))


def cat_input_files(argv: list[str]) -> list[str] | None:
    """Every file path a `cat` invocation will OPEN. `cat` has no arg-taking flag, so every
    non-flag token is an input operand. Returns `[]` for an inert stdin-only `cat` in a
    downstream pipe stage (nothing to gate), or `None` to FAIL CLOSED on any `-`-prefixed
    token that is not a known boolean bundle: the shape admits only those, so anything else
    means shape and extractor disagree — the bug class this gate exists to prevent.

    A bare `-` is stdin (not an operand). `--` ends options, so every LATER token is an
    operand even one starting with `-` — `cat -- /etc/passwd` opens `/etc/passwd` and is
    scope-checked like any other operand (reading this backwards ships a fail-open)."""
    files: list[str] = []
    opts_done = False
    for t in argv[1:]:
        if opts_done or t == "-" or not t.startswith("-"):
            if t != "-":
                files.append(t)
        elif t == "--":
            opts_done = True
        elif not _CAT_BOOL_BUNDLE.fullmatch(t):
            return None
    return files


# The `defender-*` shims' long options — a POSITIVE allowlist per shim, because a shim grant
# is `OPENS_NOTHING` and its shape is therefore its only containment. Enumerated from each
# CLI's argparse; a `--flag` the CLI doesn't define is denied rather than passed through, so
# a new flag is a deliberate grant change (that is the #579 discipline, applied to the shims).
#
# `defender-record-query` left with its shim (#611): the wrapper it fronted is gone, and a shim
# must leave `NON_ADAPTER_SHIMS` and this table TOGETHER — one left in `NON_ADAPTER_SHIMS` but
# dropped from here gets a free-text-only shape from `_shim_shape`, which silently WIDENS what it
# may be handed rather than removing it.
_SHIM_FLAGS: dict[str, tuple[str, ...]] = {
    "defender-lessons": ("--tags", "--show"),
    "defender-invlang": (
        "--attached-to-type", "--class", "--contains", "--disposition", "--final-weight",
        "--frontier", "--hyp", "--json", "--max-hypotheses-per-lead", "--min-support",
        "--parent-class", "--parent-type", "--quiet", "--rel", "--signature", "--top-k",
    ),
    "defender-sql": (),
}

#: Every program any agent may be granted → what its argv opens. `cat` is the sole opener.
PROGRAMS: dict[str, Extractor] = {
    "cat": cat_input_files,
    # The stdin-only viewers: no file slot at all (their file-operand form was removed —
    # `cat X | grep …` is the substitute), so they open nothing by CONSTRUCTION, not by claim.
    "grep": OPENS_NOTHING,
    "head": OPENS_NOTHING,
    "tail": OPENS_NOTHING,
    "wc": OPENS_NOTHING,
    "jq": OPENS_NOTHING,
    # The argument-inert viewers.
    "echo": OPENS_NOTHING,
    "true": OPENS_NOTHING,
    # The pinned in-repo shims + scripts. These DO open files — their own corpus, their own
    # run dir — but they resolve those paths THEMSELVES, from their own trusted code; the gate
    # pins the program token and, per #565, cannot constrain the operands a program then acts
    # on anyway. `OPENS_NOTHING` here means "opens no path this gate is the right place to
    # check", and the pinned-script/pinned-CLI grants that name them carry `pins_path=True`.
    **{shim: OPENS_NOTHING for shim in NON_ADAPTER_SHIMS},
    "python3": OPENS_NOTHING,
    "rm": OPENS_NOTHING,
}


# ── Path shapes: the scope half ──────────────────────────────────────────────

# One path segment of a RESOLVED path. Tight on purpose (`[^\x00]*` would admit spaces and
# newlines, so a gate-approved path would not be a safe token downstream — see #565); a
# resolved path carries no `..` and no `//`, so a per-segment class needs no traversal guard.
SEG = r"[\w.@=+-]+"
#: A tree of such segments — the loosest tail any shape uses (an agent's own run dir / corpus).
TREE = rf"{SEG}(?:/{SEG})*"


class PathShapes(tuple[re.Pattern[str], ...]):
    """The resolved-path shapes an agent may open — a distinct TYPE, not a bare tuple.

    The read surface IS the `cat` grant's scope OBJECT (identity, not equality — that is what
    makes read↔bash parity structural), and a bare tuple makes that contract **untestable**:
    `tuple(t) is t` for an exact tuple, so a would-be forgery — a policy whose read scope was
    copied rather than shared — silently yields the SAME object, and an identity check that can
    never fail proves nothing. A distinct type keeps `tuple(shapes)` a real copy, so the
    invariant is falsifiable, which is the only kind worth asserting."""

    __slots__ = ()


def under(root: Path, tail: str) -> re.Pattern[str]:
    """A path shape: `tail` UNDER `root`, `fullmatch`ed against the **RESOLVED** path.

    `root` is `re.escape`d and closed with a `/` boundary, so a sibling sharing the prefix
    (`{root}-evil/x`) cannot match — the anchor is a path boundary, not a string prefix. The
    caller passes an ALREADY-RESOLVED root: the operand is resolved before matching, so a
    scope compiled from an unresolved root (a symlinked `$DEFENDER_RUNS_BASE`, `/tmp` →
    `/private/tmp`) would never match and EVERY in-root read would silently deny.

    The shape carries NO negative lookahead: the secret/ground-truth denylist is applied at
    `resolve()` time (`files._denylisted`), not compiled in — so an empty denylist axis can
    subtract nothing, and cannot brick the lane by flipping a lookahead to match everywhere."""
    return re.compile(re.escape(str(root)) + "/" + tail)


# ── The grant ────────────────────────────────────────────────────────────────

class Route(enum.Enum):
    """What the gate does with a command a grant claims.

    One member since #611. The two adapter routes (`CAPTURE_ADAPTER`, `CAPTURE_ADAPTER_SQL`) went
    with the capability they WERE: a data source is reached through the `query` tool, so no grant
    on any lane may carry an adapter route, and there is nothing left for the bash gate to route.
    The enum survives as the field's type — a single-valued enum still says "this is a routing
    decision", and the next route (an MCP capture, say) lands here rather than as a bare bool."""

    PLAIN = "plain"


@dataclass(frozen=True)
class Grant:
    """One thing an agent may run: a SHAPE (program + flags + arity, no paths) and a SCOPE
    (anchored regexes over the resolved path of everything the program opens).

      - `program` — a FIELD, not a regex capture: `compile_policy` fails LOUD when a grant
        names a program absent from `PROGRAMS` (an untabled program would otherwise be
        silently UNGATED — today's `_OPERAND_GATED_PROGRAMS.get(...) is None → True`
        pass-through), and `defender-policy show` prints per-program lines.
      - `pattern` — the argv shape, `fullmatch`ed against the tokenized stage.
      - `scope` — the path shapes every extracted operand must resolve into. Empty for an
        `OPENS_NOTHING` program (nothing to check).
      - `route` — what the gate does with a claimed command (`PLAIN` — see `Route`).
      - `pins_path` — the R1 exemption: this grant's operand IS the program (the actor's
        pinned `python3 <script>`, the lead author's/curator's `rm <path>`, the judge's
        ticket CLI), so its path legitimately lives in the PATTERN and `resolve()` is the
        wrong operand model for it (`rm` unlinks the LINK, not the target; a pinned script's
        own argv is ungated anyway — #565). The invariant is therefore "no UNMARKED grant's
        pattern embeds a path", which is checkable and true. Load-bearing beyond the audit:
        the judge's `--require-closed` is a MANDATORY flag and its entire security property
        (it is what stops the benign judge grading against the live answer key), and a
        boolean-flag allowlist makes every flag OPTIONAL — so that pattern is kept VERBATIM,
        lookahead included, rather than mechanically migrated into a flag grammar."""

    program: str
    pattern: re.Pattern[str]
    scope: PathShapes = PathShapes()
    route: Route = Route.PLAIN
    pins_path: bool = field(default=False)


# ── The shared program shapes ────────────────────────────────────────────────
#
# One shape per program, compiled from the `gnu_flags` arity facts. Every flag class is a
# POSITIVE boolean allowlist and every positional slot is closed with `(?!-)`, so a rejected
# flag can never be re-absorbed as free text (#579) and no `--long` option is admitted
# anywhere it is not enumerated.

# A free-text token: a grep PATTERN, a jq filter, a shim argument. A leading `-` is
# FORBIDDEN — without that, a rejected file-opening flag (`grep -f`, `-e`, `-r`) slides into
# this slot and the program runs it as a flag, with no operand the gate ever saw.
VALUE = r"(?!-)[^ ]+"

_CAT_FLAG = gnu_flags.bundle(gnu_flags.CAT_BOOL)
_WC_FLAG = gnu_flags.bundle(gnu_flags.WC_BOOL)
# grep: the boolean flags + `-l`/`-L` (which report WHICH files matched — they open nothing).
# NOT `-f`/`-e` (file/pattern takers) and NOT `-r`/`-R` (which walk the CWD with no operand).
_GREP_FLAG = gnu_flags.bundle(gnu_flags.GREP_BOOL + gnu_flags.GREP_LIST)
# tail/head: booleans + `-n`/`-c` (whose NUM is a bare digit run) + a fused count (`-5`).
# `-f`/`-F` (follow) are excluded: a follow never returns, wedging the stage.
_NUM_FLAG = gnu_flags.bundle(gnu_flags.TAIL_HEAD_BOOL + gnu_flags.DIGITS)
# jq is not a coreutil, so its set stays local: the safe boolean short flags (NO `-f`/`-L`,
# which open a filter file / a module dir) plus the file-FREE `--arg`/`--argjson` binders,
# whose VALUE is an inert string/JSON literal even when it looks like a path.
_JQ_FLAG = r"-[rjcnesRaSCM]+"
_JQ_KV_FLAG = rf"(?:--arg|--argjson) {VALUE} {VALUE}"


def _shim_shape(name: str) -> re.Pattern[str]:
    """A pinned `defender-*` shim (or an inert `echo`/`true`): the program token plus its
    ENUMERATED long flags and free-text arguments. The flag allowlist is what earns the
    shim's `OPENS_NOTHING` claim — a `--flag` its CLI does not define is denied here rather
    than passed through to a program the gate cannot see into."""
    flags = _SHIM_FLAGS.get(name, ())
    alts = [rf"{re.escape(f)}(?:={VALUE})?" for f in flags] + [VALUE]
    return re.compile(rf"^{re.escape(name)}(?: (?:{'|'.join(alts)}))*$")


def program_shape(name: str) -> re.Pattern[str]:
    """The one shape for `name` — every agent that grants a program grants the SAME shape, so
    two lanes can never drift into disagreeing about what `grep` may do (they did: #579 had to
    be fixed twice, and the second copy was missed).

    The five stdin-only viewers have NO file slot: their operands were removed, which is what
    makes `cat` the sole opener and their `OPENS_NOTHING` a structural fact rather than a
    claim. `cat X | grep -n s` is the substitute for every file-operand viewer form."""
    if name == "cat":
        # PROG (flag)* FILE* — operands are OPTIONAL: a `cat -` / `cat` reading stdin in a
        # downstream pipe stage names no file and must still match. Operands are UNANCHORED
        # here (no path in the shape) and gated by the grant's SCOPE at resolve() time.
        # `--` is admitted because it is not a denial: it ends options, so what follows is an
        # OPERAND — `cat -- /etc/passwd` reaches the extractor and denies on SCOPE, which is
        # the honest place for it (rejecting `--` at the shape would hide that).
        return re.compile(rf"^cat(?: (?:{_CAT_FLAG}|--|-|{VALUE}))*$")
    if name == "grep":
        return re.compile(rf"^grep(?: {_GREP_FLAG})*(?: {VALUE})$")
    if name in ("head", "tail"):
        return re.compile(rf"^{name}(?: (?:{_NUM_FLAG}|[0-9]+))*$")
    if name == "wc":
        return re.compile(rf"^wc(?: {_WC_FLAG})*$")
    if name == "jq":
        return re.compile(rf"^jq(?: (?:{_JQ_FLAG}|{_JQ_KV_FLAG}))*(?: {VALUE})$")
    if name == "true":
        return re.compile(r"^true$")
    return _shim_shape(name)


#: The stdin-only viewers, in a canonical order so a compiled lane is deterministic.
#:
#: `jq` was dropped (#540). It predated #611 and was never the sanctioned reduce: the
#: aggregation path is `query(...)` then `cat <payload> | defender-sql '<SQL>'`, and
#: `skills/gather/SKILL.md` actively counter-teaches jq ("do not `jq` over payloads").
#: Nothing in SKILL.md, the handbook or any lesson corpus taught it. Keeping it would have
#: meant baking a program nobody uses into the box's rootfs — granting a capability the
#: boundary then has to carry. The repertoire test reads this tuple, so the grant and the
#: image cannot drift apart in either direction.
STDIN_VIEWERS = ("wc", "tail", "head", "grep")


__all__ = [
    "PathShapes",
    "OPENS_NOTHING",
    "PROGRAMS",
    "SEG",
    "STDIN_VIEWERS",
    "TREE",
    "VALUE",
    "Grant",
    "Route",
    "cat_input_files",
    "program_shape",
    "under",
]
