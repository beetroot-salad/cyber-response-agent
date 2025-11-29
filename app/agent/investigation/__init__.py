"""Investigation agent module."""

from .runner import (
    InvestigationConfig,
    InvestigationResult,
    InvestigationRunner,
    investigate,
)

__all__ = [
    "InvestigationConfig",
    "InvestigationResult",
    "InvestigationRunner",
    "investigate",
]
