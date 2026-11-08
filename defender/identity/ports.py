"""What the identity service needs from outside: the stored records, the sign-in provider and
mail. Structural, so the in-memory and PostgreSQL repositories and the test fakes all fit."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Collection
from typing import Protocol

from defender._model import model
from defender.records.formats import CredentialId, MembershipId, TenantId, UserId

from .models import CredentialKind, Membership, MembershipStatus, ProgramCredential, Session, User


@model(frozen=True)
class VerifiedSignIn:
    """What a verified login says: the provider's account id, the display name, and the
    authentication methods used (`amr`). The provider's tokens never leave the adapter."""

    account_id: str
    name: str
    amr: tuple[str, ...]


@model(frozen=True)
class VerifiedProgramToken:
    """What a verified programs-realm access token says: the OAuth client it was issued to (`azp`), its
    service-account user id (`sub`) and when it expires. The token itself never leaves the adapter."""

    client_id: str
    subject: str
    expires_at: _dt.datetime


@model(frozen=True)
class ExpiryWarning:
    """A claimed expiry-warning send: which credential, and which threshold (how long before expiry)."""

    credential_id: CredentialId
    threshold: _dt.timedelta


class IdentityRepository(Protocol):
    """Users, memberships and sessions, with the rules the data must hold on its own:

    - emails are unique and stored lower-cased;
    - at most one `invited`-or-`active` membership per (user, tenant);
    - a membership refers to a stored tenant and an existing user;
    - every status change is conditional on the expected status and reports whether it applied;
    - `active` carries `accepted_at`, `ended` carries `ended_at` and `ended_by`;
    - a session is found by the hash of its value, and the value itself is never kept;
    - a person has an email and the `admin` role; a program has neither an email, an account nor the
      administrator flag, is always `active`, holds only the `automation` role, is never invited, and
      owns credentials (at most two usable or still-pending at once, only while its membership is active),
      and only a program owns one: that is a rule of the data itself (a foreign key to the user's kind), not
      something to check again when a credential is used;
    - a program's display name and a credential's name hold only what PostgreSQL text can (no NUL, no lone
      surrogate);
    - every write that changes a program's membership or credentials is serialised on the program's user row.

    Time is an explicit aware-UTC argument; the repository holds no clock. Every method is a
    coroutine. A returned model is a detached copy with every field set: changing it changes
    nothing stored. A refused write raises `DataRuleViolation`."""

    async def close(self) -> None:
        """Release what the repository holds (its connection pool)."""
        ...

    # --- tenants: rows of the tenant repository (`tenancy`), which alone writes them (#1214)
    async def tenant_exists(self, tenant_id: TenantId) -> bool:
        """Present and `active`: a tenant being created or offboarded does not exist here."""
        ...
    async def active_tenants(self, tenant_ids: Collection[TenantId]) -> set[TenantId]:
        """The ids among `tenant_ids` that `tenant_exists`, in one read."""
        ...
    async def tenant_has_active_members(self, tenant_id: TenantId) -> bool: ...

    # --- users
    async def ensure_user(self, email: str, *, now: _dt.datetime) -> User:  # people only
        """The user with this email, or a new `invited` one. Concurrent calls converge."""
        ...
    async def user(self, user_id: UserId) -> User | None: ...
    async def user_by_email(self, email: str) -> User | None: ...
    async def user_by_signin_account(self, account_id: str) -> User | None: ...
    async def platform_admins(self) -> list[User]: ...
    async def record_signin_account(self, user_id: UserId, account_id: str) -> bool:
        """Once per user, and unique across users; `False` when refused."""
        ...
    async def activate_user(self, user_id: UserId, *, display_name: str, now: _dt.datetime) -> bool:
        """`invited` -> `active`, conditional."""
        ...
    async def set_display_name(self, user_id: UserId, display_name: str, *, now: _dt.datetime) -> None: ...
    async def set_platform_admin(self, user_id: UserId, flag: bool) -> None: ...

    # --- memberships
    async def ensure_invitation(
        self, user_id: UserId, tenant_id: TenantId, *, invited_by: UserId | None, now: _dt.datetime,
        expires_at: _dt.datetime | None = None,
    ) -> Membership | None:
        """The user's `invited` row for the tenant, or a new one; `None` when the user is
        already an active member. Finished rows are never reopened."""
        ...
    async def accept_invitation(self, membership_id: MembershipId, *, now: _dt.datetime) -> bool:
        """`invited` -> `active` while unexpired (`expires_at` unset or after `now`) and while its
        tenant is `active`, checked in the same statement."""
        ...
    async def end_membership(self, membership_id: MembershipId, *, ended_by: UserId | None, now: _dt.datetime) -> bool: ...
    async def revoke_invitation(self, membership_id: MembershipId) -> bool: ...
    async def membership(self, membership_id: MembershipId) -> Membership | None: ...
    async def memberships_of_user(self, user_id: UserId) -> list[Membership]: ...
    async def memberships_of_tenant(self, tenant_id: TenantId) -> list[Membership]: ...
    async def people_of_tenant(
        self, tenant_id: TenantId, status: MembershipStatus,
    ) -> list[tuple[Membership, User]]:
        """The tenant's rows in `status`, each with its user, in one read."""
        ...
    async def active_membership(self, user_id: UserId, tenant_id: TenantId) -> Membership | None: ...

    # --- programs and their credentials (#1307)
    async def add_program(
        self, tenant_id: TenantId, *, display_name: str, created_by: UserId, now: _dt.datetime,
    ) -> User:
        """A program of the tenant: an active user of kind program with one active `automation` membership."""
        ...
    async def programs_of_tenant(self, tenant_id: TenantId) -> list[User]:
        """The tenant's programs with an active membership."""
        ...
    async def remove_program(self, program_id: UserId, *, removed_by: UserId | None, now: _dt.datetime) -> bool:
        """One write: end the program's active membership and revoke every credential still `pending` or
        `live`. `False` when it has no active membership."""
        ...
    async def add_credential(
        self, program_id: UserId, *, kind: CredentialKind, name: str, created_by: UserId,
        expires_at: _dt.datetime, now: _dt.datetime, key_hash: str | None = None,
        credential_id: CredentialId | None = None,
    ) -> ProgramCredential:
        """A key (`live`, with its hash) or an OAuth client (`pending`, deadline `now` + 10 minutes, no hash).
        Refused for a user that is no program, a program without an active membership, a key without its hash,
        or when the program already has two credentials that are usable or pending within their deadline.
        The id is minted unless given (a key's value holds its id, so the caller mints it first)."""
        ...
    async def go_live(self, credential_id: CredentialId, *, service_account_id: str, now: _dt.datetime) -> bool:
        """`pending` -> `live`, only before the deadline and while the program's membership is active."""
        ...
    async def revoke_credential(self, credential_id: CredentialId, *, revoked_by: UserId | None, now: _dt.datetime) -> bool:
        """`pending` or `live` -> `revoked`, once."""
        ...
    async def credential_by_id(self, credential_id: CredentialId) -> ProgramCredential | None: ...
    async def credential_by_hash(self, key_hash: str) -> ProgramCredential | None: ...
    async def credentials_of_program(self, program_id: UserId) -> list[ProgramCredential]: ...
    async def touch_credential(self, credential_id: CredentialId, *, now: _dt.datetime) -> bool:
        """Move `last_used_at` to `now` only when unset or more than five minutes old."""
        ...
    async def revoke_stale_pending(self, *, now: _dt.datetime) -> list[CredentialId]:
        """Revoke (by the system) every `pending` credential at or past its deadline; their ids."""
        ...
    async def oauth_credentials_to_keep(self, *, now: _dt.datetime) -> set[CredentialId]:
        """The OAuth credentials whose realm client must exist: `live` and unexpired, or `pending`
        within the deadline."""
        ...
    async def claim_expiry_warning(self, *, now: _dt.datetime, hold_until: _dt.datetime) -> ExpiryWarning | None:
        """A usable credential's due warning (14 or 3 days before expiry; a threshold already passed when the
        credential was created never is). Of several due, the tightest is returned and the looser ones are
        settled unsent. Moves the send's next try to `hold_until`."""
        ...
    async def settle_expiry_warning(self, credential_id: CredentialId, threshold: _dt.timedelta, *, sent_at: _dt.datetime) -> bool:
        """Once per (credential, threshold)."""
        ...
    async def defer_expiry_warning(self, credential_id: CredentialId, threshold: _dt.timedelta, *, until: _dt.datetime) -> None: ...

    # --- sends: a send is pending while requested_seq > sent_seq, and due while its next try
    # is unset or not after `now`
    async def request_set_password(self, user_id: UserId, *, now: _dt.datetime) -> int: ...
    async def request_notification(self, membership_id: MembershipId, *, now: _dt.datetime) -> int: ...
    async def claim_set_password(
        self, *, now: _dt.datetime, hold_until: _dt.datetime, skip: Collection[UserId] = (),
    ) -> User | None:
        """An `invited` user with a due set-password send that is not in `skip`, or `None`.
        Moves its next try to `hold_until` before returning, so any other claimant skips it
        until then; nothing stays locked after the call."""
        ...
    async def claim_notification(
        self, *, now: _dt.datetime, hold_until: _dt.datetime, skip: Collection[MembershipId] = (),
    ) -> Membership | None:
        """As `claim_set_password`, for an `invited` row with a due notification."""
        ...
    async def defer_set_password(self, user_id: UserId, *, until: _dt.datetime) -> None:
        """After a failed send: one more attempt, and the next try at `until`."""
        ...
    async def defer_notification(self, membership_id: MembershipId, *, until: _dt.datetime) -> None: ...
    async def settle_set_password(
        self, user_id: UserId, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        """Move `sent_seq` to `read_seq`, only while `sent_seq < read_seq <= requested_seq`.
        `sent_at=None` means the send was dropped. `expires_at` goes on the user's `invited`
        rows. When it applies it clears the attempts and the next try."""
        ...
    async def settle_notification(
        self, membership_id: MembershipId, read_seq: int, *, sent_at: _dt.datetime | None = None,
        expires_at: _dt.datetime | None = None,
    ) -> bool:
        """As `settle_set_password`; `expires_at` goes on that one row."""
        ...

    # --- sessions
    async def add_session(
        self, value: str, user_id: UserId, *, now: _dt.datetime, expires_at: _dt.datetime,
        used_otp: bool = False,
    ) -> Session: ...
    async def session_by_value(self, value: str) -> Session | None: ...
    async def delete_session(self, value: str) -> bool: ...
    async def touch_session(self, value: str, *, now: _dt.datetime) -> bool:
        """Move `last_seen_at` to `now` only when it is more than five minutes old."""
        ...
    async def purge_expired_sessions(self, *, now: _dt.datetime, idle_since: _dt.datetime) -> int:
        """Delete every session sign-in refuses already: `expires_at <= now`, or last seen before
        `idle_since`; how many."""
        ...


class SignInPort(Protocol):
    """The sign-in provider. Failures: `SignInRefused` for a login that does not
    verify, `SignInUnavailable` for anything else that went wrong."""

    async def close(self) -> None: ...

    async def create_account(self, *, username: str, email: str, required_actions: frozenset[str]) -> str:
        """Create the account, or find the one with this username. Required actions are
        `set_password` and `set_up_otp`. Returns the provider's account id."""
        ...
    async def send_set_password_email(self, account_id: str, *, lifespan: _dt.timedelta) -> None: ...
    async def has_otp(self, account_id: str) -> bool: ...
    async def require_otp_setup(self, account_id: str) -> None: ...
    async def begin_signin(self, *, state: str, nonce: str, code_challenge: str) -> str:
        """The URL to send the person to."""
        ...
    async def finish_signin(self, *, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn: ...


class ProgramsPort(Protocol):
    """The programs realm (the identity provider's realm for programs): OAuth clients for program credentials and the
    verification of their tokens. Failures: `SignInRefused` for a token that does not verify,
    `SignInUnavailable` for anything else that went wrong."""

    async def close(self) -> None: ...

    async def create_client(self, credential_id: CredentialId) -> tuple[str, str]:
        """Create the confidential client (service account only) whose client id and internal id are the
        credential's id; its service-account user id and secret, read back."""
        ...
    async def delete_client(self, client_id: str) -> None:
        """Delete the client; one that is already gone is fine."""
        ...
    async def client_ids(self) -> set[str]:
        """The program clients now in the realm (client ids that are UUIDs); the adapter's own clients and
        the realm's built-in ones are never listed."""
        ...
    async def verify_token(self, token: str) -> VerifiedProgramToken: ...


class MailPort(Protocol):
    async def notify_invitation(self, to: str, tenant_id: TenantId, invitation_id: MembershipId) -> None: ...
    async def notify_credential_expiry(
        self, to: str, tenant_id: TenantId, program_id: UserId, credential_id: CredentialId,
        expires_at: _dt.datetime,
    ) -> None: ...
