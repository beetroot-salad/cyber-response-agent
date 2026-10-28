"""Lead authoring, rendering and curation for the learning loop."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.learning.leads._errors import (
        LeadAuthorError as LeadAuthorError,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("LeadAuthorError",), "_errors"),
}

__getattr__ = lazy_door(globals(), _HOMES)
