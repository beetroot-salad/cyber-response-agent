"""What a run may call and whether it is up: the verb registry, grants, and the system-skill scaffold rules."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.systems._scaffold_rules import (
        Finding as Finding,
        ScaffoldRuleError as ScaffoldRuleError,
        VerbResolver as VerbResolver,
        check_system_skill as check_system_skill,
        check_template as check_template,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("Finding", "ScaffoldRuleError", "VerbResolver", "check_system_skill", "check_template",), "_scaffold_rules"),
}

__getattr__ = lazy_door(globals(), _HOMES)
