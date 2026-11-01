"""What the job store refuses. The API's ports re-export these classes as their own refusals
(`defender.api.ports`), so a store's raise is the API's answer with nothing mapped between."""

from __future__ import annotations


class NotFound(Exception):
    """The addressed investigation does not exist for this tenant."""


class Conflict(Exception):
    """The record exists but its state refuses the request."""


class UnknownReference(Exception):
    """A request names an alert, or a tenant, that does not exist."""
