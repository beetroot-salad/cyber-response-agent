"""The job store (#1342): alerts, the investigations of them and their learning jobs (#1344), on PostgreSQL.

Loads SQLAlchemy and nothing of the runtime, so the API can load it. The tables are created by
`defender.migrations`; the worker that runs claimed investigations is `defender.worker`."""

from __future__ import annotations

from .errors import Conflict, NotFound, UnknownReference, UnstorableText
from .models import Claim, InvestigationRecord, LearningClaim, LearningJobRecord, LearningProgress, StoredAlert
from .store import JobStore, is_outage, is_refusal

__all__ = ["Claim", "Conflict", "InvestigationRecord", "JobStore", "LearningClaim", "LearningJobRecord",
           "LearningProgress", "NotFound", "StoredAlert", "UnknownReference", "UnstorableText", "is_outage",
           "is_refusal"]
