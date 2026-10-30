"""What the job store refuses. The API's ports have errors of the same names; this package sits
below the API and cannot import them, so the adapter (#1083) maps one onto the other."""

from __future__ import annotations


class NotFound(Exception):
    """The addressed investigation does not exist for this tenant."""


class Conflict(Exception):
    """The record exists but its state refuses the request."""


class UnknownReference(Exception):
    """A request names an alert, or a tenant, that does not exist."""
