"""Every identity rule: invitations, sign-in, sessions, memberships, administrators, the
bootstrap and the sender. The only code that sends. Routes translate; repositories store."""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import logging
import secrets
from collections.abc import Callable
from typing import Literal

from defender._model import model
from defender.records._tenant_id import TenantId, TenantRefused

from . import audit
from .bootstrap import Bootstrap
from .errors import (
    BootstrapRefused,
    CallbackRefused,
    Conflict,
    Forbidden,
    NotAuthenticated,
    NotFound,
    SignInRefused,
)
from .ports import IdentityRepository, MailPort, SignInPort
from .rows import Membership, Session, User

_logger = logging.getLogger(__name__)

#: How long an invitation, and a set-password link, stays open after the send.
INVITATION_LIFETIME = _dt.timedelta(days=7)
#: A session ends this long after sign-in however busy it is, or this long after last use.
SESSION_LIFETIME = _dt.timedelta(days=7)
SESSION_IDLE_LIMIT = _dt.timedelta(hours=12)
#: A failed send is retried after 30 s, doubling, but never later than this.
_RETRY_FIRST = _dt.timedelta(seconds=30)
_RETRY_LAST = _dt.timedelta(hours=1)
#: How long a claimed send is skipped by every other sender: well past a send's port calls, so
#: two API processes do not send it twice, and short enough that a crashed one's send comes back.
_SEND_HOLD = _dt.timedelta(minutes=5)
_PRELOGIN_PARTS = 3


@model(frozen=True)
class Authenticated:
    """A request's caller. `administrator` is computed per request: the user is flagged now
    and this session's sign-in used a one-time code."""

    user: User
    session: Session
    administrator: bool


@model(frozen=True)
class LoginStart:
    url: str
    prelogin: str


@model(frozen=True)
class InvitationView:
    """What an invitation listing shows: nothing the inviter did not type, but its own date."""

    id: str
    email: str
    status: Literal["invited"]
    created_at: _dt.datetime


@model(frozen=True)
class MemberView:
    user_id: str
    email: str
    display_name: str


@model(frozen=True)
class OpenInvitation:
    id: str
    tenant_id: str


@model(frozen=True)
class MeView:
    user: User
    tenants: tuple[str, ...]
    administrator: bool
    invitations: tuple[OpenInvitation, ...]


def _pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


def _accept_tenant(raw: str) -> str:
    """`raw` as a tenant id, or `NotFound`: a malformed id is no tenant."""
    try:
        return str(TenantId(raw))
    except TenantRefused as e:
        raise NotFound("no such tenant") from e


class IdentityService:
    def __init__(
        self, repo: IdentityRepository, *, signin: SignInPort, mail: MailPort,
        clock: Callable[[], _dt.datetime], bootstrap: Bootstrap,
        send_interval: _dt.timedelta = _dt.timedelta(seconds=30),
        session_idle_limit: _dt.timedelta = SESSION_IDLE_LIMIT,
    ) -> None:
        self._repo = repo
        self._signin = signin
        self._mail = mail
        self._clock = clock
        self._bootstrap = bootstrap
        self.send_interval = send_interval
        self._session_idle_limit = session_idle_limit
        self._listed = frozenset(
            {*bootstrap.administrators, *(e for emails in bootstrap.tenants.values() for e in emails)})

    # --- start: the bootstrap file ---------------------------------------------------------
    def start(self) -> None:
        """Make the people and tenants in the bootstrap file reachable. First members are invited
        only into a tenant that never had a membership; any listed person still `invited` gets a
        fresh set-password email once the last is over 7 days old, even if a member revoked their
        invitation (O8). Raises `BootstrapRefused` before writing anything if the file cannot be
        applied."""
        now = self._clock()
        admins = tuple(dict.fromkeys(self._bootstrap.administrators))
        firsts = self._first_members()
        self._refuse_unsafe_file(admins, firsts)
        for tenant in firsts:
            self._repo.register_tenant(TenantId(tenant))
        requested: set[str] = set()

        def ask_set_password(user: User) -> None:
            if user.id not in requested:
                requested.add(user.id)
                self._repo.request_set_password(user.id, now=now)

        self._flag_administrators(admins, now)
        for tenant, emails in firsts.items():
            if not self._repo.tenant_has_ever_had_membership(tenant):
                self._invite_first_members(tenant, emails, now, ask_set_password)
        listed = dict.fromkeys([*admins, *(e for emails in firsts.values() for e in emails)])
        for email in listed:
            pending = self._repo.user_by_email(email)
            if pending is not None and pending.status == "invited" and (
                    pending.set_password_sent_at is None
                    or now - pending.set_password_sent_at > INVITATION_LIFETIME):
                ask_set_password(pending)
        self._unflag_removed_administrators(admins)

    def _unflag_removed_administrators(self, admins: tuple[str, ...]) -> None:
        for stale in self._repo.platform_admins():
            if stale.email not in admins:
                self._repo.set_platform_admin(stale.id, False)
                audit.emit("admin.flag.clear", actor=audit.SYSTEM, tenant_id=None, target=stale.id)

    def _flag_administrators(self, admins: tuple[str, ...], now: _dt.datetime) -> None:
        for email in admins:
            user = self._repo.ensure_user(email, now=now)
            if not user.is_platform_admin:
                self._repo.set_platform_admin(user.id, True)
                audit.emit("admin.flag.set", actor=audit.SYSTEM, tenant_id=None, target=user.id)

    def _first_members(self) -> dict[str, tuple[str, ...]]:
        firsts: dict[str, tuple[str, ...]] = {}
        for raw, emails in self._bootstrap.tenants.items():
            try:
                tenant = str(TenantId(raw))
            except TenantRefused as e:
                raise BootstrapRefused(f"not a tenant id: {raw!r}") from e
            firsts[tenant] = tuple(dict.fromkeys(emails))
        return firsts

    def _refuse_unsafe_file(self, admins: tuple[str, ...], firsts: dict[str, tuple[str, ...]]) -> None:
        both = sorted(set(admins) & {e for emails in firsts.values() for e in emails})
        if both:
            raise BootstrapRefused(f"{both[0]} is listed as an administrator and as a first member")
        for email in admins:
            known = self._repo.user_by_email(email)
            if known is not None and not known.is_platform_admin and any(
                    m.status in ("invited", "active") for m in self._repo.memberships_of_user(known.id)):
                raise BootstrapRefused(
                    f"{email} would become an administrator but holds a membership or invitation")

    def _invite_first_members(
        self, tenant: str, emails: tuple[str, ...], now: _dt.datetime,
        ask_set_password: Callable[[User], None],
    ) -> None:
        for email in emails:
            user = self._repo.ensure_user(email, now=now)
            row = self._repo.ensure_invitation(user.id, tenant, invited_by=audit.SYSTEM, now=now)
            if row is None:
                continue
            if user.status == "invited":
                ask_set_password(user)
            else:
                self._repo.request_notification(row.id, now=now)
            audit.emit("member.invite", actor=audit.SYSTEM, tenant_id=tenant, target=row.id)

    # --- the sender --------------------------------------------------------------------------
    def send_pending(self) -> None:
        """One pass of the sender, the only code that sends. A failure of one send leaves that
        send pending and does not stop the others; a repository failure propagates."""
        self._send_set_passwords()
        self._send_notifications()

    def _send_set_passwords(self) -> None:
        tried: set[str] = set()
        while True:
            now = self._clock()
            user = self._repo.claim_set_password(now=now, hold_until=now + _SEND_HOLD, skip=tried)
            if user is None:
                return
            tried.add(user.id)
            try:
                self._send_set_password(user)
            except Exception:
                _logger.exception("set-password send for user %s failed; it stays pending", user.id)
                self._repo.defer_set_password(user.id, until=self._retry_at(user.set_password_attempts))

    def _still_wanted(self, user: User) -> bool:
        return user.status == "invited" and (
            user.email in self._listed
            or any(m.status == "invited" for m in self._repo.memberships_of_user(user.id)))

    def _send_set_password(self, user: User) -> None:
        account = user.signin_account_id
        if account is None:
            required = {"set_password"} | ({"set_up_otp"} if user.is_platform_admin else set())
            account = self._signin.create_account(
                username=user.id, email=user.email, required_actions=frozenset(required))
            self._repo.record_signin_account(user.id, account)
        fresh = self._repo.user(user.id)
        if fresh is None or not self._still_wanted(fresh):
            self._repo.settle_set_password(user.id, user.set_password_requested_seq)
            return
        self._signin.send_set_password_email(fresh.signin_account_id or account, lifespan=INVITATION_LIFETIME)
        sent = self._clock()
        self._repo.settle_set_password(
            user.id, user.set_password_requested_seq, sent_at=sent, expires_at=sent + INVITATION_LIFETIME)

    def _send_notifications(self) -> None:
        tried: set[str] = set()
        while True:
            now = self._clock()
            row = self._repo.claim_notification(now=now, hold_until=now + _SEND_HOLD, skip=tried)
            if row is None:
                return
            tried.add(row.id)
            try:
                self._send_notification(row)
            except Exception:
                _logger.exception("notification for invitation %s failed; it stays pending", row.id)
                self._repo.defer_notification(row.id, until=self._retry_at(row.notify_attempts))

    def _retry_at(self, failed_before: int) -> _dt.datetime:
        return self._clock() + min(_RETRY_FIRST * 2 ** failed_before, _RETRY_LAST)

    def _send_notification(self, row: Membership) -> None:
        fresh = self._repo.membership(row.id)
        user = None if fresh is None else self._repo.user(fresh.user_id)
        if fresh is None or fresh.status != "invited" or user is None or user.is_platform_admin:
            self._repo.settle_notification(row.id, row.notify_requested_seq)
            return
        self._mail.notify_invitation(user.email, fresh.tenant_id, fresh.id)
        sent = self._clock()
        self._repo.settle_notification(
            row.id, row.notify_requested_seq, sent_at=sent, expires_at=sent + INVITATION_LIFETIME)

    # --- sign-in -----------------------------------------------------------------------------
    def begin_signin(self) -> LoginStart:
        """The URL to send the person to, and the pre-login cookie value that carries the state,
        nonce and PKCE verifier back (unsigned: all three are single-use and the provider checks them)."""
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(_PRELOGIN_PARTS))
        url = self._signin.begin_signin(state=state, nonce=nonce, code_challenge=_pkce_challenge(verifier))
        return LoginStart(url=url, prelogin=f"{state}.{nonce}.{verifier}")

    def complete_signin(self, *, code: str, state: str, prelogin: str | None) -> str:
        """The new session's value, or `CallbackRefused`."""
        parts = (prelogin or "").split(".")
        if len(parts) != _PRELOGIN_PARTS or not all(parts):
            raise CallbackRefused("prelogin-missing", "there is no sign-in in progress; start again")
        expected_state, nonce, verifier = parts
        if not secrets.compare_digest(state.encode(), expected_state.encode()):
            raise CallbackRefused("login-attempt-invalid", "the sign-in does not match the one started")
        try:
            verified = self._signin.finish_signin(code=code, code_verifier=verifier, nonce=nonce)
        except SignInRefused as e:
            raise CallbackRefused("login-attempt-invalid", "the sign-in could not be verified") from e
        user = self._repo.user_by_signin_account(verified.account_id)
        if user is None:
            raise CallbackRefused("unknown-account", "this account is not known here")
        used_otp = "otp" in verified.amr
        if user.is_platform_admin and not used_otp:
            if not self._signin.has_otp(verified.account_id):
                self._signin.require_otp_setup(verified.account_id)
            raise CallbackRefused(
                "otp-required", "administrators sign in with a one-time code; sign in again")
        now = self._clock()
        if self._repo.activate_user(user.id, display_name=verified.name, now=now):
            if not user.is_platform_admin:
                self._accept_open_invitations(user, now)
        else:
            self._repo.set_display_name(user.id, verified.name, now=now)
        value = secrets.token_urlsafe(32)
        self._repo.add_session(value, user.id, now=now, expires_at=now + SESSION_LIFETIME, used_otp=used_otp)
        return value

    def _accept_open_invitations(self, user: User, now: _dt.datetime) -> None:
        for row in self._repo.memberships_of_user(user.id):
            if row.status == "invited" and self._repo.tenant_exists(row.tenant_id) \
                    and self._repo.accept_invitation(row.id, now=now):
                audit.emit("invitation.accept", actor=user.id, tenant_id=row.tenant_id, target=row.id)

    # --- sessions ----------------------------------------------------------------------------
    def authenticate(self, value: str | None) -> Authenticated:
        """The caller behind a session cookie value, or `NotAuthenticated`. Everything is read
        from the repository on every call: nothing a sign-in token claimed is trusted again."""
        if not value:
            raise NotAuthenticated("sign in")
        session = self._repo.session_by_value(value)
        now = self._clock()
        if session is None or now >= session.expires_at or now - session.last_seen_at > self._session_idle_limit:
            raise NotAuthenticated("sign in")
        user = self._repo.user(session.user_id)
        if user is None or user.status != "active":
            raise NotAuthenticated("sign in")
        self._repo.touch_session(value, now=now)
        return Authenticated(user=user, session=session, administrator=user.is_platform_admin and session.used_otp)

    def logout(self, auth: Authenticated, value: str) -> None:
        self._repo.delete_session(value)

    # --- the caller's own view ---------------------------------------------------------------
    def member_of(self, auth: Authenticated, tenant_id: str) -> str:
        """The tenant's id when the caller is an active member, else `NotFound` (the same
        answer for a tenant that does not exist, a malformed id and a non-member)."""
        tenant = _accept_tenant(tenant_id)
        if self._repo.active_membership(auth.user.id, tenant) is None:
            raise NotFound("no such tenant")
        return tenant

    def require_administrator(self, auth: Authenticated) -> None:
        if not auth.administrator:
            raise Forbidden("platform administrators only")

    def me(self, auth: Authenticated) -> MeView:
        now = self._clock()
        rows = self._repo.memberships_of_user(auth.user.id)
        open_rows = () if auth.user.is_platform_admin else tuple(
            OpenInvitation(id=m.id, tenant_id=m.tenant_id) for m in rows
            if m.status == "invited" and (m.expires_at is None or m.expires_at > now)
            and self._repo.tenant_exists(m.tenant_id))
        return MeView(
            user=auth.user, tenants=tuple(m.tenant_id for m in rows if m.status == "active"),
            administrator=auth.administrator, invitations=open_rows)

    # --- tenant people -----------------------------------------------------------------------
    def members(self, tenant_id: str) -> list[MemberView]:
        views = [MemberView(user_id=user.id, email=user.email, display_name=user.display_name)
                 for _, user in self._repo.people_of_tenant(tenant_id, "active")]
        return sorted(views, key=lambda v: v.email)

    def invitations(self, tenant_id: str) -> list[InvitationView]:
        views = [InvitationView(id=row.id, email=user.email, status="invited", created_at=row.created_at)
                 for row, user in self._repo.people_of_tenant(tenant_id, "invited")]
        return sorted(views, key=lambda v: (v.created_at, v.id))

    def _invite(self, inviter: str, tenant_id: str, email: str) -> InvitationView:
        """Flow 1, the request part: only rows are written. Nothing is sent, and nothing in the
        answer depends on who the email belongs to (P-E)."""
        now = self._clock()
        user = self._repo.ensure_user(email, now=now)
        expires_at = now + INVITATION_LIFETIME if user.is_platform_admin else None
        row = self._repo.ensure_invitation(
            user.id, tenant_id, invited_by=inviter, now=now, expires_at=expires_at)
        if row is None:
            raise Conflict("already a member of this tenant")
        if not user.is_platform_admin:
            # An `invited` user is sent a set-password email, an `active` one a notification.
            # Re-read after asking: a sign-in between the read and the request moves the user
            # to the other kind, and an unasked kind would never be sent.
            self._request_send(user, row, now)
            current = self._repo.user(user.id)
            if current is not None and current.status != user.status:
                self._request_send(current, row, now)
        return InvitationView(id=row.id, email=user.email, status="invited", created_at=row.created_at)

    def _request_send(self, user: User, row: Membership, now: _dt.datetime) -> None:
        if user.status == "invited":
            self._repo.request_set_password(user.id, now=now)
        else:
            self._repo.request_notification(row.id, now=now)

    def invite(self, auth: Authenticated, tenant_id: str, email: str) -> InvitationView:
        view = self._invite(auth.user.id, tenant_id, email)
        audit.emit("member.invite", actor=auth.user.id, tenant_id=tenant_id, target=view.id)
        return view

    def admin_invite(self, auth: Authenticated, tenant_id: str, email: str) -> InvitationView:
        """An administrator's invitation: only into a tenant with no active members."""
        self.require_administrator(auth)
        tenant = _accept_tenant(tenant_id)
        if not self._repo.tenant_exists(tenant):
            raise NotFound("no such tenant")
        if self._repo.tenant_has_active_members(tenant):
            raise Conflict("the tenant already has members; they invite")
        view = self._invite(auth.user.id, tenant, email)
        audit.emit("admin.invite", actor=auth.user.id, tenant_id=None, target=tenant)
        audit.emit("member.invite", actor=auth.user.id, tenant_id=tenant, target=view.id)
        return view

    def revoke(self, auth: Authenticated, tenant_id: str, invitation_id: str) -> None:
        row = self._repo.membership(invitation_id)
        if row is None or row.tenant_id != tenant_id or not self._repo.revoke_invitation(invitation_id):
            raise NotFound("no such invitation")
        audit.emit("invitation.revoke", actor=auth.user.id, tenant_id=tenant_id, target=invitation_id)

    def remove(self, auth: Authenticated, tenant_id: str, user_id: str) -> None:
        row = self._repo.active_membership(user_id, tenant_id)
        if row is None or not self._repo.end_membership(row.id, ended_by=auth.user.id, now=self._clock()):
            raise NotFound("no such member")
        audit.emit("member.remove", actor=auth.user.id, tenant_id=tenant_id, target=user_id)

    def accept(self, auth: Authenticated, invitation_id: str) -> str:
        """Accept an invitation addressed to the caller; the tenant it opened."""
        row = self._repo.membership(invitation_id)
        if (row is None or row.user_id != auth.user.id or auth.user.is_platform_admin
                or not self._repo.tenant_exists(row.tenant_id)
                or not self._repo.accept_invitation(invitation_id, now=self._clock())):
            raise NotFound("no such invitation")
        audit.emit("invitation.accept", actor=auth.user.id, tenant_id=row.tenant_id, target=row.id)
        return row.tenant_id

    # --- platform ----------------------------------------------------------------------------
    def all_tenants(self, auth: Authenticated) -> list[str]:
        self.require_administrator(auth)
        tenants = self._repo.tenants()
        audit.emit("admin.tenants.list", actor=auth.user.id, tenant_id=None, target=None)
        return tenants


