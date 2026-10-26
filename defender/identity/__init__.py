"""People, memberships and sign-in (#1306): the users, their tenants, invitations and sessions.

Imports nothing from `api`, `runtime` or `learning`. The sign-in provider's adapter and the
PostgreSQL repository are separate modules, so importing this package loads neither a web
client nor a database driver."""

from __future__ import annotations

from .bootstrap import Bootstrap, register_tenant
from .errors import (
    BootstrapRefused,
    CallbackRefused,
    Conflict,
    DataRuleViolation,
    Forbidden,
    IdentityError,
    NotAuthenticated,
    NotFound,
    SignInRefused,
    SignInUnavailable,
)
from .memory import InMemoryIdentityRepository
from .ports import IdentityRepository, MailPort, SignInPort, VerifiedSignIn
from .rows import Membership, Session, User
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
    "DataRuleViolation", "Forbidden", "IdentityError", "IdentityRepository", "IdentityService",
    "InMemoryIdentityRepository", "InvitationView", "LoginStart", "MailPort", "MemberView",
    "Membership", "MeView", "NotAuthenticated", "NotFound", "OpenInvitation", "Session",
    "SignInPort", "SignInRefused", "SignInUnavailable", "User", "VerifiedSignIn",
    "register_tenant",
]
