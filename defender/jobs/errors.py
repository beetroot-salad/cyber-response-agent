"""What the job store refuses. The API's ports re-export these classes as their own refusals
(`defender.api.ports`), so a store's raise is the API's answer with nothing mapped between."""

from __future__ import annotations


class NotFound(Exception):
    """The addressed investigation does not exist for this tenant."""


class Conflict(Exception):
    """The record exists but its state refuses the request."""


class UnknownReference(Exception):
    """A request names an alert, or a tenant, that does not exist."""


class UnstorableText(ValueError):
    """A text argument holds what PostgreSQL text cannot (a NUL or a lone surrogate). Names the
    field, never the value. The API's own models refuse such text first (#1379 O1), so from the
    API this is unreachable; any other caller that reaches it has a bug."""


class OffboardNotSettled(RuntimeError):
    """An offboard kept finding live jobs of the tenant after every one it ended (new rows inserted behind its
    passes). The whole transaction is rolled back: the tenant is unchanged and the request can be repeated."""
