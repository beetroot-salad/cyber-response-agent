"""#1307: program credentials, removal, offboarding, expiry warnings, reconciliation (O5, O6, O7, P-G) — sketch."""
from __future__ import annotations

import datetime as _dt
import hashlib

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.identity import Bootstrap, IdentityService  # noqa: E402
from defender.tests.support.api._identity1306 import ANN, T1, items, repo_holds  # noqa: E402
from defender.tests.support.api._programs1307 import (  # noqa: E402
    DAY,
    DEFAULT_LIFETIME,
    EXPIRY_HEADER,
    MAX_LIFETIME,
    Client,
    ProgramsWorld,
    create_program,
    issue,
    issue_oauth,
    parse_time,
    revoke,
    soar,
)

PENDING_DEADLINE = _dt.timedelta(minutes=10)
SECOND = _dt.timedelta(seconds=1)
ORPHAN = "6d3c1f0e-0000-4000-8000-0000000000aa"  # a client whose response was lost before any row


# --- O5 -------------------------------------------------------------------------------------

def test_a_key_is_shown_once_and_only_its_hash_is_kept() -> None:
    """The create response holds the secret; listing and storage never do (O5)."""
    s = soar()
    listed = items(s.ann.get(f"/tenants/{T1}/programs/{s.program_id}/credentials"))
    assert [(c["id"], c["kind"], c["name"]) for c in listed] == [(s.key_id, "key", "primary")]
    assert s.key not in str(listed)
    assert not repo_holds(s.world.raw_repo, s.key)
    [row] = s.world.credentials(s.program_id)
    assert row.key_hash == hashlib.sha256(s.key.encode()).hexdigest()


def test_an_oauth_credential_shows_keycloaks_secret_once_and_stores_none_of_it() -> None:
    """OAuth: client id = credential id; the secret is Keycloak's, returned once, never stored (O5, P-G)."""
    s = soar()
    response = issue(s.ann, T1, s.program_id, kind="oauth_client")
    assert response.status_code == 201, response.text
    credential = response.json()["id"]
    client = s.world.realm.clients[credential]
    assert response.json()["secret"] == client.secret
    assert not repo_holds(s.world.raw_repo, client.secret)
    assert {r.id: r.state for r in s.world.credentials(s.program_id)}[credential] == "live"


def test_expiry_defaults_to_90_days_and_may_not_exceed_365() -> None:
    """Expiry: default 90 days; at most 365 (O5, D6)."""
    s = soar()
    now = s.world.clock()
    [listed] = items(s.ann.get(f"/tenants/{T1}/programs/{s.program_id}/credentials"))
    assert parse_time(listed["expires_at"]) == now + DEFAULT_LIFETIME
    assert issue(s.ann, T1, s.program_id, expires_at=now + MAX_LIFETIME + DAY).status_code == 422
    assert issue(s.ann, T1, s.program_id, expires_at=now + MAX_LIFETIME).status_code == 201


def test_a_program_holds_at_most_two_live_credentials() -> None:
    """Rotation overlaps by two; a third is refused until one is revoked (O5)."""
    s = soar()
    second = issue_oauth(s.ann, T1, s.program_id)
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 409
    assert revoke(s.ann, T1, s.program_id, second).status_code == 204
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 201


def test_revoking_an_oauth_credential_stops_tokens_already_issued() -> None:
    """Revocation is our row: an outstanding token fails on the next request (O5, rotation scenario)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 200
    assert revoke(s.ann, T1, s.program_id, credential).status_code == 204
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 401
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 200  # the other credential lives


def test_an_expired_key_stops_on_the_next_request() -> None:
    """Usable = live and `expires_at > now` (O5)."""
    s = soar()
    s.world.clock.advance(DEFAULT_LIFETIME - DAY)
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 200
    s.world.clock.advance(DAY)
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 401


# --- O6 -------------------------------------------------------------------------------------

def test_removing_a_program_cuts_it_off_and_revokes_every_credential() -> None:
    """Removal ends the membership and revokes all credentials, next request (O6)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    assert s.ann.delete(f"/tenants/{T1}/programs/{s.program_id}").status_code == 204
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 401
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 401
    assert {r.state for r in s.world.credentials(s.program_id)} == {"revoked"}
    assert s.program_id not in {p["id"] for p in items(s.ann.get(f"/tenants/{T1}/programs"))}


def test_offboarding_revokes_program_credentials_without_a_programs_realm() -> None:
    """`end_tenant`, run as the lifecycle runs it (no programs port), revokes rows; the API's purge deletes clients (O6)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    lifecycle = IdentityService(s.world.raw_repo, signin=s.world.signin, mail=s.world.mail,
                                clock=s.world.clock, bootstrap=Bootstrap(administrators=()))
    s.world.call(lifecycle.end_tenant, T1, now=s.world.clock())
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 401
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 401
    assert {r.state for r in s.world.credentials(s.program_id)} == {"revoked"}
    assert credential in s.world.realm.clients
    s.world.call(s.world.service.reconcile_program_clients)
    assert credential not in s.world.realm.clients


# --- O7 -------------------------------------------------------------------------------------

def test_every_active_admin_is_warned_14_days_before_a_credential_expires() -> None:
    """Warnings go to each active admin of the tenant, once per threshold (O7)."""
    s = soar()
    nina = "nina@a.example"
    s.world.member(s.ann, T1, nina)
    s.world.clock.advance(DEFAULT_LIFETIME - 15 * DAY)
    s.world.send_pending()
    assert s.world.mail.warnings == []
    s.world.clock.advance(DAY)
    s.world.send_pending()
    s.world.send_pending()
    warned = sorted((w.to, w.tenant_id, w.program_id, w.credential_id) for w in s.world.mail.warnings)
    assert warned == sorted([(ANN, T1, s.program_id, s.key_id), (nina, T1, s.program_id, s.key_id)])


def test_every_response_to_a_program_carries_its_credential_expiry() -> None:
    """Expiry header on a program's responses, not on a person's (O7, FC-3)."""
    s = soar()
    response = s.program().get(f"/tenants/{T1}/alerts")
    assert parse_time(response.headers[EXPIRY_HEADER]) == s.world.clock() + DEFAULT_LIFETIME
    assert EXPIRY_HEADER not in s.ann.get(f"/tenants/{T1}/alerts").headers


# --- the OAuth pending rule and reconciliation -------------------------------------------------

def test_a_failed_client_creation_answers_503_and_holds_a_slot_only_until_its_deadline() -> None:
    """Keycloak fails mid-create -> 503, row stays pending; the purge revokes it after 10 minutes (B1)."""
    s = soar()
    s.world.realm.lose_create_responses = 1
    assert issue(s.ann, T1, s.program_id, kind="oauth_client").status_code == 503
    [lost] = s.world.realm.created
    assert {r.id: r.state for r in s.world.credentials(s.program_id)}[lost] == "pending"
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 409  # pending holds a slot
    s.world.call(s.world.service.reconcile_program_clients)
    assert lost in s.world.realm.clients  # within its deadline
    s.world.clock.advance(PENDING_DEADLINE + SECOND)
    s.world.call(s.world.service.reconcile_program_clients)
    assert lost not in s.world.realm.clients
    assert {r.id: r.state for r in s.world.credentials(s.program_id)}[lost] == "revoked"
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 201


def test_the_purge_deletes_every_client_without_a_usable_credential_and_keeps_live_ones() -> None:
    """A client exists only while its credential is usable or pending before its deadline (reconciliation)."""
    world = ProgramsWorld(tenants={T1: [ANN]})
    ann = world.sign_in(ANN)
    program_id = str(create_program(ann, T1)["id"])
    live, revoked = issue_oauth(ann, T1, program_id), issue_oauth(ann, T1, program_id)
    assert revoke(ann, T1, program_id, revoked).status_code == 204
    world.realm.clients[ORPHAN] = Client(ORPHAN, "00000000-5a00-4000-8000-0000000000bb", "s")
    world.realm.clients[revoked] = Client(revoked, "00000000-5a00-4000-8000-0000000000cc", "s")  # courtesy delete lost
    world.call(world.service.reconcile_program_clients)
    assert set(world.realm.clients) == {live}
