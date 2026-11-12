"""Every identity rule: invitations, sign-in, sessions, memberships, administrators, the
bootstrap and the sender. The only code that sends. Routes translate; repositories store."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as _dt
import hashlib
import logging
import secrets
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from defender._model import model
from defender.records.formats import CredentialId, IdRefused, MembershipId, ProgramId, TenantId, UserId

from . import audit
from .bootstrap import Bootstrap
from .errors import (
    BootstrapRefused,
    CallbackRefused,
    Conflict,
    CredentialCapReached,
    DataRuleViolation,
    Forbidden,
    Invalid,
    NotAuthenticated,
    NotFound,
    SignInRefused,
    TenantNotActive,
)
from . import roles
from .memory import secret_hash
from .ports import ExpiryWarning, IdentityRepository, MailPort, ProgramsPort, SignInPort
from .models import CredentialKind, Membership, Program, ProgramCredential, Role, Session, User, postgres_text
from .roles import Permission

_logger = logging.getLogger(__name__)

#: How long an invitation, and a set-password link, stays open after the send.
INVITATION_LIFETIME = _dt.timedelta(days=7)
#: A session ends this long after sign-in however busy it is, or this long after last use.
SESSION_LIFETIME = _dt.timedelta(days=7)
SESSION_IDLE_LIMIT = _dt.timedelta(hours=12)
#: How often the background loop removes expired sessions (#1349).
PURGE_INTERVAL = _dt.timedelta(hours=1)
#: A purge still running after this is cut off and logged, so it never holds up sends or shutdown.
PURGE_DEADLINE = _dt.timedelta(seconds=60)
#: A failed send is retried after 30 s, doubling, but never later than this.
_RETRY_FIRST = _dt.timedelta(seconds=30)
_RETRY_LAST = _dt.timedelta(hours=1)
#: How long a claimed send is skipped by every other sender: well past a send's port calls, so
#: two API processes do not send it twice, and short enough that a crashed one's send comes back.
_SEND_HOLD = _dt.timedelta(minutes=5)
#: One email's claim, sends and record together: past it the email is deferred like a failed send.
SEND_DEADLINE = _dt.timedelta(seconds=30)
_PRELOGIN_PARTS = 3
#: A program's key starts with this, so a secret scanner can recognise it and the API routes it without parsing a JWT.
KEY_PREFIX = "dfk_"
#: A credential's lifetime: at least a week (so the 3-day warning always fires), at most a year; 90 days unless asked.
MIN_CREDENTIAL_LIFETIME = _dt.timedelta(days=7)
DEFAULT_CREDENTIAL_LIFETIME = _dt.timedelta(days=90)
MAX_CREDENTIAL_LIFETIME = _dt.timedelta(days=365)
#: A failed expiry warning is tried again after this.
_WARNING_RETRY = _dt.timedelta(minutes=15)


@model(frozen=True)
class PersonCaller:
    """A request's caller who signed in (P-F): the user and the session it came in on. `administrator` is
    computed per request: the user is flagged now and this session's sign-in used a one-time code."""

    user: User
    session: Session
    administrator: bool

    @property
    def actor_id(self) -> UserId:
        return self.user.id


@model(frozen=True)
class ProgramCaller:
    """A request's caller who came in on a program credential (P-F): the program, read with the credential when it was
    admitted (its tenant then `active`, so no read again), and the credential. A program is never an administrator."""

    program: Program
    credential: ProgramCredential

    @property
    def actor_id(self) -> ProgramId:
        return self.program.id


#: A request's caller, one of two types, never one type with optional fields (#1454 D1).
Authenticated = PersonCaller | ProgramCaller


@model(frozen=True)
class LoginStart:
    url: str
    prelogin: str


@model(frozen=True)
class InvitationView:
    """What an invitation listing shows: nothing the inviter did not type, but its own date."""

    id: MembershipId
    email: str
    status: Literal["invited"]
    created_at: _dt.datetime


@model(frozen=True)
class MemberView:
    user_id: UserId
    email: str
    display_name: str


@model(frozen=True)
class OpenInvitation:
    id: MembershipId
    tenant_id: TenantId


@model(frozen=True)
class MeView:
    """A person's own view."""

    user: User
    tenants: tuple[TenantId, ...]
    administrator: bool
    invitations: tuple[OpenInvitation, ...]


def _audit_removal(program_id: ProgramId, revoked: list[CredentialId], *, actor: str, tenant_id: TenantId) -> None:
    """A program's removal, by an admin or by its tenant's offboarding, as one record: each credential the removal
    revoked, then the program (O8; #1450 review: both ways out read alike)."""
    for credential_id in revoked:
        audit.emit("program_credential.revoke", actor=actor, tenant_id=tenant_id, target=credential_id)
    audit.emit("program.remove", actor=actor, tenant_id=tenant_id, target=program_id)


def _pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


class IdentityService:
    def __init__(  # noqa: PLR0913 — the four ports and the clock are required; the rest tune a test
        self, repo: IdentityRepository, *, signin: SignInPort, mail: MailPort,
        clock: Callable[[], _dt.datetime], bootstrap: Bootstrap, programs: ProgramsPort,
        send_interval: _dt.timedelta = _dt.timedelta(seconds=30),
        send_deadline: _dt.timedelta = SEND_DEADLINE,
        session_idle_limit: _dt.timedelta = SESSION_IDLE_LIMIT,
    ) -> None:
        self._repo = repo
        self._signin = signin
        self._mail = mail
        self._clock = clock
        self._bootstrap = bootstrap
        self._programs = programs
        self.send_interval = send_interval
        self.send_deadline = send_deadline
        self._session_idle_limit = session_idle_limit
        self.purge_deadline = PURGE_DEADLINE
        self._listed = frozenset(bootstrap.administrators)

    def now(self) -> _dt.datetime:
        """The service's clock, so the API stamps tenant requests with the one the people use."""
        return self._clock()

    async def close(self) -> None:
        """Close the repository and the sign-in and programs ports; the service is not used afterwards."""
        try:
            await self._repo.close()
        finally:
            try:
                await self._signin.close()
            finally:
                await self._programs.close()

    # --- start: the bootstrap file ---------------------------------------------------------
    async def start(self) -> None:
        """Make the administrators in the bootstrap file reachable: each is flagged, and any listed
        person still `invited` gets a fresh set-password email once the last is over 7 days old.
        Raises `BootstrapRefused` before writing anything if the file cannot be applied."""
        now = self._clock()
        admins = tuple(dict.fromkeys(self._bootstrap.administrators))
        await self._refuse_unsafe_file(admins)
        await self._flag_administrators(admins, now)
        for email in admins:
            pending = await self._repo.user_by_email(email)
            if pending is not None and pending.status == "invited" and (
                    pending.set_password_sent_at is None
                    or now - pending.set_password_sent_at > INVITATION_LIFETIME):
                await self._repo.request_set_password(pending.id, now=now)
        await self._unflag_removed_administrators(admins)

    async def _unflag_removed_administrators(self, admins: tuple[str, ...]) -> None:
        for stale in await self._repo.platform_admins():
            if stale.email not in admins:
                await self._repo.set_platform_admin(stale.id, False)
                audit.emit("admin.flag.clear", actor=audit.SYSTEM, tenant_id=None, target=stale.id)

    async def _flag_administrators(self, admins: tuple[str, ...], now: _dt.datetime) -> None:
        for email in admins:
            user = await self._repo.ensure_user(email, now=now)
            if not user.is_platform_admin:
                await self._repo.set_platform_admin(user.id, True)
                audit.emit("admin.flag.set", actor=audit.SYSTEM, tenant_id=None, target=user.id)

    async def _refuse_unsafe_file(self, admins: tuple[str, ...]) -> None:
        for email in admins:
            known = await self._repo.user_by_email(email)
            if known is not None and not known.is_platform_admin and any(
                    m.status in ("invited", "active") for m in await self._repo.memberships_of_user(known.id)):
                raise BootstrapRefused(
                    f"{email} would become an administrator but holds a membership or invitation")

    # --- the background loop: the sender and the session purge -------------------------------
    async def run_background(self, stop: asyncio.Event) -> None:
        """Pass now and then every `send_interval` until `stop` is set: a sender pass, then, when one is due
        (on the first pass, then once per `PURGE_INTERVAL` on the clock), the purge of the sessions sign-in
        refuses (expired, or idle past the limit) and the reconciliation of the programs realm. A stop never
        interrupts an email: the sender ends before claiming the next one, or during its wait. A failing
        pass, purge or reconciliation, or one cut off at `purge_deadline`, is logged, and ends neither the
        loop nor the others."""
        next_purge: _dt.datetime | None = None
        while not stop.is_set():
            try:
                await self.send_pending(stop)
            except Exception:
                _logger.exception("a sender pass failed; the next pass tries again")
            now = self._clock()
            if not stop.is_set() and (next_purge is None or now >= next_purge):
                next_purge = now + PURGE_INTERVAL
                try:
                    async with asyncio.timeout(self.purge_deadline.total_seconds()):
                        purged = await self._repo.purge_expired_sessions(
                            now=now, idle_since=now - self._session_idle_limit)
                    _logger.info("purged %d sessions sign-in refuses (expired or idle)", purged)
                except Exception:
                    _logger.exception("a session purge failed; the next is due at %s", next_purge.isoformat())
                try:
                    async with asyncio.timeout(self.purge_deadline.total_seconds()):
                        await self.reconcile_program_clients()
                except Exception:
                    _logger.exception(
                        "the programs realm reconciliation failed; the next is due at %s", next_purge.isoformat())
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), self.send_interval.total_seconds())

    async def send_pending(self, stop: asyncio.Event | None = None) -> None:
        """One pass of the sender, the only code that sends: whole, or until `stop` is set. A failure
        of one send leaves that send pending and does not stop the others; a repository failure
        propagates."""
        await self._send_each(stop, self._repo.claim_set_password, self._send_set_password,
                              self._defer_set_password, "set-password send for user")
        await self._send_each(stop, self._repo.claim_notification, self._send_notification,
                              self._defer_notification, "notification for invitation")
        await self._send_expiry_warnings(stop)

    async def _send_each(self, stop: asyncio.Event | None, claim: Callable[..., Awaitable[Any]],
                         send: Callable[[Any], Awaitable[None]], defer: Callable[[Any], Awaitable[None]],
                         what: str) -> None:
        """Claim and send one email at a time until none is due or `stop` is set. Each email's claim,
        sends and record share one `send_deadline`; a send that fails or outlives it is deferred."""
        tried: set[str] = set()
        while stop is None or not stop.is_set():
            now = self._clock()
            row = None
            try:
                async with asyncio.timeout(self.send_deadline.total_seconds()):
                    row = await claim(now=now, hold_until=now + _SEND_HOLD, skip=tried)
                    if row is None:
                        return
                    tried.add(row.id)
                    await send(row)
            except Exception:
                if row is None:
                    raise
                _logger.exception("%s %s failed; it stays pending", what, row.id)
                await defer(row)

    async def _send_expiry_warnings(self, stop: asyncio.Event | None) -> None:
        """Claim and send one credential-expiry warning at a time until none is due or `stop` is set; one
        send is one (credential, threshold), to every active admin of the program's tenant at that moment.
        A send that fails or outlives `send_deadline` is deferred, and its retry mails only the admins it has not
        reached yet; delivery to each is at least once."""
        while stop is None or not stop.is_set():
            now = self._clock()
            claimed: ExpiryWarning | None = None
            try:
                async with asyncio.timeout(self.send_deadline.total_seconds()):
                    claimed = await self._repo.claim_expiry_warning(now=now, hold_until=now + _SEND_HOLD)
                    if claimed is None:
                        return
                    await self._send_expiry_warning(claimed)
            except Exception:
                if claimed is None:
                    raise
                _logger.exception("expiry warning for credential %s failed; it stays pending", claimed.credential_id)
                await self._repo.defer_expiry_warning(
                    claimed.credential_id, claimed.threshold, until=self._clock() + _WARNING_RETRY)

    async def _send_expiry_warning(self, claimed: ExpiryWarning) -> None:
        now = self._clock()
        credential, threshold = claimed.credential_id, claimed.threshold
        admitted = await self._repo.admit_by_credential(credential, now=now)
        if admitted is None:  # revoked, expired or out of standing since it was claimed: nothing to say
            await self._repo.settle_expiry_warning(credential, threshold)
            return
        row, program = admitted
        tenant_id = program.tenant_id
        reached = await self._repo.warning_deliveries(credential, threshold)
        failure: Exception | None = None
        # A tenant with no active person left is told nothing and the warning is settled: the program itself
        # sees the expiry on every response (D9), and a person who joins later is not owed a passed warning.
        for _, admin in await self._repo.people_of_tenant(tenant_id, "active"):
            if admin.id in reached:
                continue
            # One admin's send and its record are one step: either failing leaves the others tried, and the
            # warning as a whole fails and is retried for whoever has no record (a record that failed after its
            # mail went out means that admin is mailed again: at least once, never skipped).
            try:
                await self._mail.notify_credential_expiry(
                    admin.email, tenant_id, program.id, row.id, row.expires_at)
                await self._repo.record_warning_delivery(credential, threshold, admin.id, sent_at=self._clock())
            except Exception as e:
                failure = failure or e
        if failure is not None:
            raise failure
        await self._repo.settle_expiry_warning(credential, threshold)

    async def _defer_set_password(self, user: User) -> None:
        await self._repo.defer_set_password(user.id, until=self._retry_at(user.set_password_attempts))

    async def _defer_notification(self, row: Membership) -> None:
        await self._repo.defer_notification(row.id, until=self._retry_at(row.notify_attempts))

    async def _still_wanted(self, user: User) -> bool:
        if user.status != "invited":
            return False
        return user.email in self._listed or any(
            m.status == "invited" for m in await self._repo.memberships_of_user(user.id))

    async def _send_set_password(self, user: User) -> None:
        account = user.signin_account_id
        if account is None:
            required = {"set_password"} | ({"set_up_otp"} if user.is_platform_admin else set())
            account = await self._signin.create_account(
                username=user.id, email=user.email, required_actions=frozenset(required))
            await self._repo.record_signin_account(user.id, account)
        fresh = await self._repo.user(user.id)
        if fresh is None or not await self._still_wanted(fresh):
            await self._repo.settle_set_password(user.id, user.set_password_requested_seq)
            return
        await self._signin.send_set_password_email(fresh.signin_account_id or account, lifespan=INVITATION_LIFETIME)
        sent = self._clock()
        await self._repo.settle_set_password(
            user.id, user.set_password_requested_seq, sent_at=sent, expires_at=sent + INVITATION_LIFETIME)

    def _retry_at(self, failed_before: int) -> _dt.datetime:
        return self._clock() + min(_RETRY_FIRST * 2 ** failed_before, _RETRY_LAST)

    async def _send_notification(self, row: Membership) -> None:
        fresh = await self._repo.membership(row.id)
        user = None if fresh is None else await self._repo.user(fresh.user_id)
        if fresh is None or fresh.status != "invited" or user is None or user.is_platform_admin:
            await self._repo.settle_notification(row.id, row.notify_requested_seq)
            return
        await self._mail.notify_invitation(user.email, fresh.tenant_id, fresh.id)
        sent = self._clock()
        await self._repo.settle_notification(
            row.id, row.notify_requested_seq, sent_at=sent, expires_at=sent + INVITATION_LIFETIME)

    # --- sign-in -----------------------------------------------------------------------------
    async def begin_signin(self) -> LoginStart:
        """The URL to send the person to, and the pre-login cookie value that carries the state,
        nonce and PKCE verifier back (unsigned: all three are single-use and the provider checks them)."""
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(_PRELOGIN_PARTS))
        url = await self._signin.begin_signin(state=state, nonce=nonce, code_challenge=_pkce_challenge(verifier))
        return LoginStart(url=url, prelogin=f"{state}.{nonce}.{verifier}")

    async def complete_signin(self, *, code: str, state: str, prelogin: str | None) -> str:
        """The new session's value, or `CallbackRefused`."""
        parts = (prelogin or "").split(".")
        if len(parts) != _PRELOGIN_PARTS or not all(parts):
            raise CallbackRefused("prelogin-missing", "there is no sign-in in progress; start again")
        expected_state, nonce, verifier = parts
        if not secrets.compare_digest(state.encode(), expected_state.encode()):
            raise CallbackRefused("login-attempt-invalid", "the sign-in does not match the one started")
        try:
            verified = await self._signin.finish_signin(code=code, code_verifier=verifier, nonce=nonce)
        except SignInRefused as e:
            raise CallbackRefused("login-attempt-invalid", "the sign-in could not be verified") from e
        user = await self._repo.user_by_signin_account(verified.account_id)
        if user is None:
            raise CallbackRefused("unknown-account", "this account is not known here")
        used_otp = "otp" in verified.amr
        if user.is_platform_admin and not used_otp:
            if not await self._signin.has_otp(verified.account_id):
                await self._signin.require_otp_setup(verified.account_id)
            raise CallbackRefused(
                "otp-required", "administrators sign in with a one-time code; sign in again")
        now = self._clock()
        if await self._repo.activate_user(user.id, display_name=verified.name, now=now):
            if not user.is_platform_admin:
                await self._accept_open_invitations(user, now)
        else:
            await self._repo.set_display_name(user.id, verified.name, now=now)
        value = secrets.token_urlsafe(32)
        await self._repo.add_session(value, user.id, now=now, expires_at=now + SESSION_LIFETIME, used_otp=used_otp)
        return value

    async def _accept_open_invitations(self, user: User, now: _dt.datetime) -> None:
        for row in await self._repo.memberships_of_user(user.id):
            if row.status == "invited" and await self._repo.accept_invitation(row.id, now=now):
                audit.emit("invitation.accept", actor=user.id, tenant_id=row.tenant_id, target=row.id)

    # --- sessions ----------------------------------------------------------------------------
    async def authenticate(self, value: str | None) -> PersonCaller:
        """The caller behind a session cookie value, or `NotAuthenticated`. Everything is read
        from the repository on every call: nothing a sign-in token claimed is trusted again."""
        if not value:
            raise NotAuthenticated("sign in")
        session = await self._repo.session_by_value(value)
        now = self._clock()
        if session is None or now >= session.expires_at or now - session.last_seen_at > self._session_idle_limit:
            raise NotAuthenticated("sign in")
        user = await self._repo.user(session.user_id)
        if user is None or user.status != "active":  # a session names a users row: only people (P-F, P-J)
            raise NotAuthenticated("sign in")
        await self._repo.touch_session(value, now=now)
        return PersonCaller(user=user, session=session, administrator=user.is_platform_admin and session.used_otp)

    async def authenticate_bearer(self, value: str) -> ProgramCaller:
        """The program behind a bearer value (P-F: bearers identify only programs): a key, by the hash of
        its value, or an access token of the programs realm, by the client and service account it names.
        One repository read admits it: the credential usable, its program active and its tenant `active` (O-C, O-D),
        so every refusal is a 401, one answer (#1450 review). `NotAuthenticated` for anything that does not hold;
        `SignInUnavailable` when a token cannot be checked because the programs realm cannot be reached."""
        now = self._clock()
        if value.startswith(KEY_PREFIX):
            admitted = await self._repo.admit_by_key(secret_hash(value), now=now)
        else:
            try:
                token = await self._programs.verify_token(value)
            except SignInRefused as e:
                raise NotAuthenticated("sign in") from e
            try:
                client = CredentialId(token.client_id)
            except IdRefused as e:
                raise NotAuthenticated("sign in") from e
            admitted = await self._repo.admit_by_client(client, service_account_id=token.subject, now=now)
        if admitted is None:
            raise NotAuthenticated("sign in")
        credential, program = admitted
        await self._repo.touch_credential(credential.id, now=now)
        return ProgramCaller(program=program, credential=credential)

    async def logout(self, auth: PersonCaller, value: str) -> None:
        await self._repo.delete_session(value)

    # --- the caller's own view ---------------------------------------------------------------
    async def member_of(self, auth: Authenticated, tenant_id: TenantId) -> Role:
        """The caller's role in the tenant, else `NotFound` (the same answer for a tenant that does not exist or is
        not active and a non-member): offboarding ends access with its request (#1214). A malformed id never gets
        here: the API refuses it (#1382). A person's role is that of their active membership while the tenant is
        `active`; a program's is `automation` when the tenant is its own (its program and tenant were settled when
        it was let in). The one producer of a role (D1)."""
        if isinstance(auth, ProgramCaller):
            if auth.program.tenant_id != tenant_id:
                raise NotFound("no such tenant")
            return "automation"
        membership = await self._repo.active_membership(auth.user.id, tenant_id)
        if membership is None or not await self._repo.tenant_exists(tenant_id):
            raise NotFound("no such tenant")
        return membership.role

    @staticmethod
    def require(role: Role, permission: Permission) -> None:
        """`Forbidden` unless the role grants `permission` (D4: routes name permissions)."""
        if not roles.grants(role, permission):
            raise Forbidden("this caller may not do that")

    @staticmethod
    def require_administrator(auth: PersonCaller) -> None:
        if not auth.administrator:
            raise Forbidden("platform administrators only")

    async def me(self, auth: Authenticated) -> MeView | ProgramCaller:
        """A person's view; a program's is the caller itself: its program (one tenant, `active` when it was let in) and
        the credential it used."""
        if isinstance(auth, ProgramCaller):
            return auth
        now = self._clock()
        rows = await self._repo.memberships_of_user(auth.user.id)
        active = await self._repo.active_tenants({m.tenant_id for m in rows}) if rows else set()
        open_rows = [OpenInvitation(id=m.id, tenant_id=m.tenant_id)
                     for m in (() if auth.user.is_platform_admin else rows)
                     if m.status == "invited" and (m.expires_at is None or m.expires_at > now) and m.tenant_id in active]
        tenants = [m.tenant_id for m in rows if m.status == "active" and m.tenant_id in active]
        return MeView(
            user=auth.user, tenants=tuple(tenants), administrator=auth.administrator, invitations=tuple(open_rows))

    # --- tenant people -----------------------------------------------------------------------
    async def members(self, tenant_id: TenantId) -> list[MemberView]:
        views = [MemberView(user_id=user.id, email=user.email, display_name=user.display_name)
                 for _, user in await self._repo.people_of_tenant(tenant_id, "active")]
        return sorted(views, key=lambda v: v.email)

    async def invitations(self, tenant_id: TenantId) -> list[InvitationView]:
        views = [InvitationView(id=row.id, email=user.email, status="invited", created_at=row.created_at)
                 for row, user in await self._repo.people_of_tenant(tenant_id, "invited")]
        return sorted(views, key=lambda v: (v.created_at, v.id))

    async def _invite(self, inviter: UserId, tenant_id: TenantId, email: str) -> InvitationView:
        """Flow 1, the request part: only rows are written. Nothing is sent, and nothing in the
        answer depends on who the email belongs to (P-E)."""
        now = self._clock()
        user = await self._repo.ensure_user(email, now=now)
        expires_at = now + INVITATION_LIFETIME if user.is_platform_admin else None
        try:
            row = await self._repo.ensure_invitation(
                user.id, tenant_id, invited_by=inviter, now=now, expires_at=expires_at)
        except TenantNotActive as e:  # left `active` during the request (P-L): as any tenant not active
            raise NotFound("no such tenant") from e
        if row is None:
            raise Conflict("already a member of this tenant")
        if not user.is_platform_admin:
            # An `invited` user is sent a set-password email, an `active` one a notification.
            # Re-read after asking: a sign-in between the read and the request moves the user
            # to the other kind, and an unasked kind would never be sent.
            await self._request_send(user, row, now)
            current = await self._repo.user(user.id)
            if current is not None and current.status != user.status:
                await self._request_send(current, row, now)
        return InvitationView(id=row.id, email=user.email, status="invited", created_at=row.created_at)

    async def _request_send(self, user: User, row: Membership, now: _dt.datetime) -> None:
        if user.status == "invited":
            await self._repo.request_set_password(user.id, now=now)
        else:
            await self._repo.request_notification(row.id, now=now)

    async def invite(self, auth: PersonCaller, tenant_id: TenantId, email: str) -> InvitationView:
        view = await self._invite(auth.user.id, tenant_id, email)
        audit.emit("member.invite", actor=auth.user.id, tenant_id=tenant_id, target=view.id)
        return view

    async def admin_invite(self, auth: PersonCaller, tenant_id: TenantId, email: str) -> InvitationView:
        """An administrator's invitation: only into a tenant with no active members."""
        self.require_administrator(auth)
        if not await self._repo.tenant_exists(tenant_id):
            raise NotFound("no such tenant")
        if await self._repo.tenant_has_active_members(tenant_id):
            raise Conflict("the tenant already has members; they invite")
        view = await self._invite(auth.user.id, tenant_id, email)
        audit.emit("admin.invite", actor=auth.user.id, tenant_id=None, target=tenant_id)
        audit.emit("member.invite", actor=auth.user.id, tenant_id=tenant_id, target=view.id)
        return view

    async def revoke(self, auth: PersonCaller, tenant_id: TenantId, invitation_id: MembershipId) -> None:
        row = await self._repo.membership(invitation_id)
        if row is None or row.tenant_id != tenant_id or not await self._repo.revoke_invitation(invitation_id):
            raise NotFound("no such invitation")
        audit.emit("invitation.revoke", actor=auth.user.id, tenant_id=tenant_id, target=invitation_id)

    async def remove(self, auth: PersonCaller, tenant_id: TenantId, user_id: UserId) -> None:
        row = await self._repo.active_membership(user_id, tenant_id)
        if row is None or not await self._repo.end_membership(row.id, ended_by=auth.user.id, now=self._clock()):
            raise NotFound("no such member")
        audit.emit("member.remove", actor=auth.user.id, tenant_id=tenant_id, target=user_id)

    async def accept(self, auth: PersonCaller, invitation_id: MembershipId) -> TenantId:
        """Accept an invitation addressed to the caller; the tenant it opened."""
        row = await self._repo.membership(invitation_id)
        if (row is None or row.user_id != auth.user.id or auth.user.is_platform_admin
                or not await self._repo.accept_invitation(invitation_id, now=self._clock())):
            raise NotFound("no such invitation")
        audit.emit("invitation.accept", actor=auth.user.id, tenant_id=row.tenant_id, target=row.id)
        return row.tenant_id

    # --- programs and their credentials (#1307) -----------------------------------------------
    async def programs(self, tenant_id: TenantId) -> list[Program]:
        return sorted(await self._repo.programs_of_tenant(tenant_id), key=lambda p: (p.display_name, p.id))

    async def _program_of(self, tenant_id: TenantId, program_id: ProgramId) -> Program:
        """The tenant's active program, else `NotFound`: another tenant's program, a person's id and a
        removed program all answer alike."""
        program = await self._repo.program(program_id)
        if program is None or not program.active or program.tenant_id != tenant_id:
            raise NotFound("no such program")
        return program

    async def create_program(self, auth: PersonCaller, tenant_id: TenantId, display_name: str) -> Program:
        name = display_name.strip()
        if not name:
            raise Invalid("a program needs a name")
        try:
            program = await self._repo.add_program(
                tenant_id, display_name=name, created_by=auth.user.id, now=self._clock())
        except TenantNotActive as e:  # left `active` during the request (P-L): as any tenant not active
            raise NotFound("no such tenant") from e
        audit.emit("program.create", actor=auth.actor_id, tenant_id=tenant_id, target=program.id)
        return program

    async def remove_program(self, auth: PersonCaller, tenant_id: TenantId, program_id: ProgramId) -> None:
        """One write marks the program removed and revokes its credentials; its realm clients wait for
        the reconciliation, the only deleter (D3)."""
        await self._program_of(tenant_id, program_id)
        revoked = await self._repo.remove_program(program_id, removed_by=auth.user.id, now=self._clock())
        if revoked is None:
            raise NotFound("no such program")
        _audit_removal(program_id, revoked, actor=auth.actor_id, tenant_id=tenant_id)

    async def credentials(self, tenant_id: TenantId, program_id: ProgramId) -> list[ProgramCredential]:
        await self._program_of(tenant_id, program_id)
        return sorted(await self._repo.credentials_of_program(program_id), key=lambda c: (c.created_at, c.id))

    async def issue_credential(
        self, auth: PersonCaller, tenant_id: TenantId, program_id: ProgramId, *, kind: CredentialKind, name: str,
        expires_at: _dt.datetime | None,
    ) -> tuple[ProgramCredential, str]:
        """A new credential and its secret, which is returned this once. A key is live at once; an OAuth
        client is recorded `pending`, made in the realm, then made live (a failure in between leaves the row
        for the reconciliation, B1)."""
        await self._program_of(tenant_id, program_id)
        name = name.strip()
        if not name:
            raise Invalid("a credential needs a name")
        try:
            postgres_text(name, "a credential's name")
        except DataRuleViolation as e:
            raise Invalid(str(e)) from e
        now = self._clock()
        if expires_at is None:
            expires_at = now + DEFAULT_CREDENTIAL_LIFETIME
        elif expires_at.tzinfo is None or not MIN_CREDENTIAL_LIFETIME <= expires_at - now <= MAX_CREDENTIAL_LIFETIME:
            raise Invalid("a credential lasts between 7 and 365 days")
        credential_id = CredentialId.mint()
        key = f"{KEY_PREFIX}{credential_id}_{secrets.token_urlsafe(32)}" if kind == "key" else None
        try:
            row = await self._repo.add_credential(
                program_id, kind=kind, name=name, created_by=auth.user.id, expires_at=expires_at, now=now,
                key_hash=None if key is None else secret_hash(key), credential_id=credential_id)
        except CredentialCapReached as e:
            raise Conflict("the program holds two credentials already") from e
        if row is None:  # removed since it was looked up
            raise NotFound("no such program")
        # `program_credential.create` is emitted at the write that made the credential usable (a key's insert,
        # an OAuth credential's `pending -> live`), before anything is read back (A8, W5).
        if key is not None:
            audit.emit("program_credential.create", actor=auth.actor_id, tenant_id=tenant_id, target=row.id)
            return row, key
        went_live = False
        try:
            service_account_id, secret = await self._programs.create_client(row.id)
            went_live = await self._repo.go_live(row.id, service_account_id=service_account_id, now=self._clock())
        finally:
            if not went_live:
                await self._abandon_pending(row.id, tenant_id)
        if not went_live:
            raise Conflict("the program was removed, or the client took too long")
        audit.emit("program_credential.create", actor=auth.actor_id, tenant_id=tenant_id, target=row.id)
        live = await self._repo.credential_by_id(row.id)
        assert live is not None
        return live, secret

    async def _abandon_pending(self, credential_id: CredentialId, tenant_id: TenantId) -> None:
        """An issue that ends without making its OAuth credential live (the realm failed or was too slow, the program
        was removed, the request was cancelled) revokes the `pending` row, freeing its slot at once; only a crash
        leaves it to the deadline (B1). A client the realm made anyway is deleted by the reconciliation, as the row
        no longer keeps it. A revoke that fails too is logged: the deadline still frees the slot, and the issue's own
        failure is the one raised."""
        try:
            if await self._repo.revoke_credential(credential_id, revoked_by=None, now=self._clock()):
                audit.emit("program_credential.revoke", actor=audit.SYSTEM, tenant_id=tenant_id, target=credential_id)
        except Exception:
            _logger.exception("revoking the pending credential %s failed", credential_id)

    async def revoke_credential(
        self, auth: PersonCaller, tenant_id: TenantId, program_id: ProgramId, credential_id: CredentialId,
    ) -> None:
        await self._program_of(tenant_id, program_id)
        row = await self._repo.credential_by_id(credential_id)
        if row is None or row.program_id != program_id:
            raise NotFound("no such credential")
        # Revoking again is a success that changes and audits nothing: the credential is revoked either way.
        if await self._repo.revoke_credential(credential_id, revoked_by=auth.user.id, now=self._clock()):
            audit.emit("program_credential.revoke", actor=auth.actor_id, tenant_id=tenant_id, target=credential_id)

    async def reconcile_program_clients(self) -> None:
        """Make the programs realm hold a client for exactly the OAuth credentials that need one (D3). The
        realm is listed FIRST: a credential created after the listing has a client the listing lacks, so it
        is never deleted; read the other way round, that client would be (D4). A stuck `pending` credential
        is revoked first, by the system. Every deletion is tried; the first failure is raised at the end."""
        existing = await self._programs.client_ids()
        now = self._clock()
        for stale, tenant_id in await self._repo.revoke_stale_pending(now=now):
            audit.emit("program_credential.revoke", actor=audit.SYSTEM, tenant_id=tenant_id, target=stale)
        keep = {str(c) for c in await self._repo.oauth_credentials_to_keep(now=now)}
        doomed = sorted(existing - keep)
        # Every read comes before the first deletion: a failed one fails the pass with nothing deleted (O-F). A client id
        # that is no credential id is no row of ours.
        ours = {}
        for client_id in doomed:
            with contextlib.suppress(IdRefused):
                ours[client_id] = CredentialId(client_id)
        tenants = await self._repo.tenants_of_credentials(list(ours.values()))
        tenant_of = {client_id: tenants.get(credential_id) for client_id, credential_id in ours.items()}
        failure: Exception | None = None
        for client_id in doomed:
            try:
                deleted = await self._programs.delete_client(client_id)
            except Exception as e:  # the others are still deleted; the loop logs this pass as failed
                _logger.exception("deleting the program client %s failed", client_id)
                failure = failure or e
                continue
            # One already gone (another replica's pass deleted it) is not a deletion of ours: nothing to audit.
            if deleted:
                audit.emit("program_client.delete", actor=audit.SYSTEM,
                           tenant_id=tenant_of.get(client_id), target=client_id)
        if failure is not None:
            raise failure

    # --- tenants ending ---------------------------------------------------------------------
    async def _end_program(self, program_id: ProgramId, tenant_id: TenantId, now: _dt.datetime) -> None:
        """A program of an ending tenant: one write removes it and revokes its credentials; its clients are the
        reconciliation's to delete, so the realm is not touched (D3)."""
        revoked = await self._repo.remove_program(program_id, removed_by=None, now=now)
        if revoked is not None:
            _audit_removal(program_id, revoked, actor=audit.SYSTEM, tenant_id=tenant_id)


    async def end_tenant(self, tenant_id: TenantId, *, now: _dt.datetime) -> None:
        """Offboarding's identity step (#1214): first remove every active program (its credentials revoked, #1454),
        then end every active membership of the tenant and revoke every open invitation, each by the system
        (`removed_by`/`ended_by` None) with its usual audit line. A failed program removal raises before any person
        is touched. Idempotent: a row already finished is left as it is."""
        for program in await self._repo.programs_of_tenant(tenant_id):
            await self._end_program(program.id, tenant_id, now)
        for row in await self._repo.memberships_of_tenant(tenant_id):
            if row.status == "active":
                if await self._repo.end_membership(row.id, ended_by=None, now=now):
                    audit.emit("member.remove", actor=audit.SYSTEM, tenant_id=row.tenant_id, target=row.user_id)
            elif row.status == "invited" and await self._repo.revoke_invitation(row.id):
                audit.emit("invitation.revoke", actor=audit.SYSTEM, tenant_id=row.tenant_id, target=row.id)
