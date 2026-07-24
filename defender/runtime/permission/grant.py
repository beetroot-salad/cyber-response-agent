
from __future__ import annotations

import enum
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS
from defender.runtime import gnu_flags


Extractor = Callable[[list[str]], "list[str] | None"]


def _opens_nothing(argv: list[str]) -> list[str] | None:
    return []


OPENS_NOTHING: Extractor = _opens_nothing

_CAT_BOOL_BUNDLE = re.compile(gnu_flags.bundle(gnu_flags.CAT_BOOL))


def rm_target_files(argv: list[str]) -> list[str] | None:
    """The operand(s) a claimed `rm` grant names — the grant's own `pattern` already restricts
    the shape to a single bare path (no flags), so this is a plain tail slice, resolved+scoped
    like any other opener (#691 MD-3): a symlink INSIDE the corpus pointing OUTSIDE it must be
    caught by resolving the operand, not merely by the pattern matching the pre-resolution text."""
    return argv[1:]


def cat_input_files(argv: list[str]) -> list[str] | None:
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


_SHIM_FLAGS: dict[str, tuple[str, ...]] = {
    "defender-lessons": ("--tags", "--show"),
    "defender-invlang": (
        "--attached-to-type", "--class", "--contains", "--disposition", "--final-weight",
        "--frontier", "--hyp", "--json", "--max-hypotheses-per-lead", "--min-support",
        "--parent-class", "--parent-type", "--quiet", "--rel", "--signature", "--top-k",
    ),
    "defender-sql": (),
}

PROGRAMS: dict[str, Extractor] = {
    "cat": cat_input_files,
    "grep": OPENS_NOTHING,
    "head": OPENS_NOTHING,
    "tail": OPENS_NOTHING,
    "wc": OPENS_NOTHING,
    "echo": OPENS_NOTHING,
    "true": OPENS_NOTHING,
    **{shim: OPENS_NOTHING for shim in NON_ADAPTER_SHIMS},
    "python3": OPENS_NOTHING,
    "rm": OPENS_NOTHING,
}



SEG = r"[\w.@=+-]+"
TREE = rf"{SEG}(?:/{SEG})*"


class PathShapes(tuple[re.Pattern[str], ...]):

    __slots__ = ()


def under(root: Path, tail: str) -> re.Pattern[str]:
    return re.compile(re.escape(str(root)) + "/" + tail)



class Route(enum.Enum):

    PLAIN = "plain"


@dataclass(frozen=True)
class Grant:

    program: str
    pattern: re.Pattern[str]
    scope: PathShapes = PathShapes()
    route: Route = Route.PLAIN
    pins_path: bool = field(default=False)
    resolve_operand: bool = field(default=False)



VALUE = r"(?!-)[^ ]+"

_CAT_FLAG = gnu_flags.bundle(gnu_flags.CAT_BOOL)
_WC_FLAG = gnu_flags.bundle(gnu_flags.WC_BOOL)
_GREP_FLAG = gnu_flags.bundle(gnu_flags.GREP_BOOL + gnu_flags.GREP_LIST)
_NUM_FLAG = gnu_flags.bundle(gnu_flags.TAIL_HEAD_BOOL + gnu_flags.DIGITS)


def _shim_shape(name: str) -> re.Pattern[str]:
    flags = _SHIM_FLAGS.get(name, ())
    alts = [rf"{re.escape(f)}(?:={VALUE})?" for f in flags] + [VALUE]
    return re.compile(rf"^{re.escape(name)}(?: (?:{'|'.join(alts)}))*$")


def program_shape(name: str) -> re.Pattern[str]:
    if name == "cat":
        return re.compile(rf"^cat(?: (?:{_CAT_FLAG}|--|-|{VALUE}))*$")
    if name == "grep":
        return re.compile(rf"^grep(?: {_GREP_FLAG})*(?: {VALUE})$")
    if name in ("head", "tail"):
        return re.compile(rf"^{name}(?: (?:{_NUM_FLAG}|[0-9]+))*$")
    if name == "wc":
        return re.compile(rf"^wc(?: {_WC_FLAG})*$")
    if name == "true":
        return re.compile(r"^true$")
    return _shim_shape(name)


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
