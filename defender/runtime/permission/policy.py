
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .grant import PROGRAMS, Grant, PathShapes
from ..verb_grant import DENY_ALL, VerbGrant

_DEFAULT_DENY_REASON = (
    "Blocked: this command is not permitted for this agent (read-only viewers and "
    "the agent's declared capabilities only)."
)


@dataclass(frozen=True)
class AgentPolicy:

    bash_allow: tuple[Grant, ...] = ()
    read_allow: PathShapes = PathShapes()
    read_roots: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = ()
    write_allow: tuple[re.Pattern[str], ...] = ()
    deny_reason: str = _DEFAULT_DENY_REASON
    budget_enforced: bool = False
    verb_allow: VerbGrant = DENY_ALL

    @property
    def write_roots(self) -> tuple[re.Pattern[str], ...]:
        """The write scope this policy compiled, under the name that reads as a question.

        The same value as `write_allow` and deliberately so: `read_roots` and `write_roots` are
        how a policy AUDIT asks "may this role read anywhere / write anywhere at all", and the
        two halves of that question should not be spelled with two different vocabularies. The
        write side is compiled to PATTERNS rather than roots — a write scope is a set of named
        artifacts under a root, not the root — so this is the honest thing to hand back, and the
        answer that matters at a deny-all role is the emptiness rather than the members.
        """
        return self.write_allow

    def __post_init__(self) -> None:
        untabled = sorted({g.program for g in self.bash_allow if g.program not in PROGRAMS})
        if untabled:
            raise ValueError(
                f"bash grant names untabled program(s) {untabled}: every granted program must "
                "declare what it opens in permission.grant.PROGRAMS (an untabled program is an "
                "ungated one). Add it there — with a real extractor, or OPENS_NOTHING earned by "
                "a shape admitting no file-opening flag."
            )
