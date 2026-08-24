"""Instrumented speculative decomposition with Pydantic AI."""

from .adaptive import AdaptiveHarness
from .adaptive_models import (
    AdaptiveFinalArtifact,
    AdaptiveResult,
    KnowledgePost,
    ParticipantTurn,
    ResponseEffect,
)
from .intake import IntakeExecution, compile_intake
from .models import HarnessResult, HarnessSpec, ModelPolicy, SourceEnvelope
from .orchestrator import SeamHarness
from .recursive import RecursiveHarness
from .recursive_models import RecursivePolicy, RecursiveResult

__all__ = [
    "AdaptiveFinalArtifact",
    "AdaptiveHarness",
    "AdaptiveResult",
    "HarnessResult",
    "HarnessSpec",
    "IntakeExecution",
    "KnowledgePost",
    "ModelPolicy",
    "ParticipantTurn",
    "RecursiveHarness",
    "RecursivePolicy",
    "RecursiveResult",
    "ResponseEffect",
    "SeamHarness",
    "SourceEnvelope",
    "compile_intake",
]

__version__ = "0.4.0"
