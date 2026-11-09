"""People, memberships and sign-in (#1306): the users, their tenants, invitations and sessions.

Imports nothing from `api`, `runtime` or `learning`. It loads SQLAlchemy (the models are its
tables), so it needs the `database` extra installed, even for the in-memory repository. The sign-in
provider's adapter and the PostgreSQL repository are separate modules, so importing this package
loads neither a web client nor a database driver."""

from __future__ import annotations

from .bootstrap import Bootstrap
from .errors import (
    BootstrapRefused,
    CallbackRefused,
    Conflict,
    DataRuleViolation,
    Forbidden,
    IdentityError,
    Invalid,
    NotAuthenticated,
    NotFound,
    SignInRefused,
    SignInUnavailable,
)
from .memory import InMemoryIdentityRepository
from .models import Membership, ProgramCredential, Session, User
from .ports import (
    ExpiryWarning, IdentityRepository, MailPort, ProgramsPort, SignInPort, VerifiedProgramToken, VerifiedSignIn,
)
from .service import (
    Authenticated,
    IdentityService,
    InvitationView,
    LoginStart,
    MemberView,
    MeView,
    OpenInvitation,
)

__all__ = [
    "Authenticated", "Bootstrap", "BootstrapRefused", "CallbackRefused", "Conflict",
    "DataRuleViolation", "ExpiryWarning", "Forbidden", "IdentityError", "IdentityRepository", "IdentityService",
    "InMemoryIdentityRepository", "Invalid", "InvitationView", "LoginStart", "MailPort", "MemberView",
    "Membership", "MeView", "NotAuthenticated", "NotFound", "OpenInvitation", "ProgramCredential", "ProgramsPort", "Session",
    "SignInPort", "SignInRefused", "SignInUnavailable", "User", "VerifiedProgramToken", "VerifiedSignIn",
]
