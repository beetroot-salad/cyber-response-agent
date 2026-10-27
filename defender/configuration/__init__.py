"""Environment parsing and model price configuration."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.configuration._env import (
        FatalConfigError as FatalConfigError,
        env_bool as env_bool,
        env_choice as env_choice,
        env_int as env_int,
        env_str as env_str,
    )
    from defender.configuration._pricing import (
        PRICING as PRICING,
        UnknownModel as UnknownModel,
        billed_usage as billed_usage,
        model_key as model_key,
        usage_cost as usage_cost,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("FatalConfigError", "env_bool", "env_choice", "env_int", "env_str",), "_env"),
    **dict.fromkeys(("PRICING", "UnknownModel", "billed_usage", "model_key", "usage_cost",), "_pricing"),
}

__getattr__ = lazy_door(globals(), _HOMES)
