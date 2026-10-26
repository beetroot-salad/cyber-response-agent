"""What the identity service refuses, as exceptions the API maps to problems."""

from __future__ import annotations


class DataRuleViolation(ValueError):
    """A write the repository's own data rules refuse (a duplicate email, a second live
    membership, a status without its timestamps, a reference to a record that is not there)."""


class BootstrapRefused(Exception):
    """The bootstrap file cannot be applied safely; the message names the email or tenant id."""


class SignInRefused(Exception):
    """The sign-in port could not verify a login: a bad code, or an ID token that fails a check."""


class SignInUnavailable(Exception):
    """The sign-in port could not be reached or answered with a failure; the caller may retry."""


class IdentityError(Exception):
    """Base of the refusals a request can meet."""


class NotAuthenticated(IdentityError):
    """No session, an unknown one, or one past its limits: a 401."""


class Forbidden(IdentityError):
    """The caller is known but may not do this: a 403."""


class NotFound(IdentityError):
    """No such record for this caller. The same answer for a record that is not there and one
    the caller may not see, so nothing can be discovered by probing (P-D)."""


class Conflict(IdentityError):
    """The record's state refuses the request: a 409."""


class CallbackRefused(IdentityError):
    """A sign-in callback that opens no session. `reason` names its problem type:
    `prelogin-missing` (a missing and a replayed pre-login cookie are one reason, since the
    server keeps no record of used states), `login-attempt-invalid`, `unknown-account` or
    `otp-required`."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
