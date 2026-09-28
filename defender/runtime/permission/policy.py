
from __future__ import annotations

import re
from defender._model import model
from pathlib import Path

from .grant import PROGRAMS, Compiled, Grant, PathShapes
from ..verb_grant import DENY_ALL, VerbGrant

_DEFAULT_DENY_REASON = (
    "Blocked: this command is not permitted for this agent (read-only viewers and "
    "the agent's declared capabilities only)."
)


@model(frozen=True)
class AgentPolicy:

    bash_allow: tuple[Grant, ...] = ()
    read_allow: PathShapes = PathShapes()
    read_roots: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = ()
    write_allow: tuple[Compiled, ...] = ()
    deny_reason: str = _DEFAULT_DENY_REASON
    budget_enforced: bool = False
    verb_allow: VerbGrant = DENY_ALL

    @property
    def write_roots(self) -> tuple[re.Pattern[str], ...]:
        """`write_allow` under the name a policy audit pairs with `read_roots`. These are
        patterns, not roots; what an audit usually needs is whether it is empty.
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
