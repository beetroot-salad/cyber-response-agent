"""The `Decision` value object returned by the gate's pure decision functions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""
