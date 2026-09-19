
from __future__ import annotations

from defender._model import model


@model(frozen=True)
class Decision:
    allow: bool
    reason: str = ""
