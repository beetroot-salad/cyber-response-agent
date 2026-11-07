"""#1307: program lifecycle and credentials (O4-O7, D3-D5, D9, D11); audit is in test_programs_1307_audit.py."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as _dt
import hashlib
from typing import Any

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.identity import Bootstrap, IdentityService  # noqa: E402
from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    NEW,
    NINA,
    OPS,
    T1,
    T2,
    InjectedFailure,
    items,
    repo_holds,
    user_id,
)
from defender.tests.support.api._programs1307 import (  # noqa: E402
    DAY,
    DEFAULT_LIFETIME,
    EXPIRY_HEADER,
    MAX_LIFETIME,
    MIN_LIFETIME,
    Client,
    JournalRepository,
    ProgramsWorld,
    Soar,
    RaisingProgramsRealm,
    create_program,
    issue,
    issue_key,
    issue_oauth,
    parse_time,
    revoke,
    soar,
)

PENDING_DEADLINE = _dt.timedelta(minutes=10)
SECOND = _dt.timedelta(seconds=1)
HOUR = _dt.timedelta(hours=1)
ORPHAN = "6d3c1f0e-0000-4000-8000-0000000000aa"  # a client whose response was lost before any row
KINDS = ["key", "oauth_client"]


def _credentials_url(program_id: str, tenant: str = T1) -> str:
    return f"/tenants/{tenant}/programs/{program_id}/credentials"


def _states(world: ProgramsWorld, program_id: str) -> dict[str, str]:
    return {r.id: r.state for r in world.credentials(program_id)}


def _alerts(client: Any) -> int:
    return int(client.get(f"/tenants/{T1}/alerts").status_code)


def _reconcile(world: ProgramsWorld) -> None:
    world.call(world.service.reconcile_program_clients)


# --- O4: a program outlives its creator ---------------------------------------------------------
# Creation shape, the second-membership refusal and audit are pinned in test_programs_1307_roles.py.

def test_a_program_survives_the_person_who_created_it_leaving() -> None:
    """The program belongs to the tenant: its creator leaving changes nothing for it (O4)."""
    s = soar()
    nina = s.world.member(s.ann, T1, NINA)
    assert s.ann.delete(f"/tenants/{T1}/members/{user_id(s.ann)}").status_code == 204
    assert _alerts(s.program()) == 200
    assert s.program_id in {p["id"] for p in items(nina.get(f"/tenants/{T1}/programs"))}
    assert nina.delete(f"/tenants/{T1}/programs/{s.program_id}").status_code == 204  # the tenant's admins manage it


def test_the_last_person_leaving_does_not_stop_a_program_nor_block_platform_rescue() -> None:
    """P-I: a program is not a member in the people sense, so an empty-of-people tenant takes a rescue invitation (O4)."""
    world = ProgramsWorld(administrators=[OPS], tenants={T1: [ANN]})
    ann, ops = world.sign_in(ANN), world.sign_in_admin()
    program_id = str(create_program(ann, T1)["id"])
    _, key = issue_key(ann, T1, program_id)
    assert ops.post(f"/admin/tenants/{T1}/invitations", json={"email": NEW}).status_code == 409  # control: a person remains
    assert ann.delete(f"/tenants/{T1}/members/{user_id(ann)}").status_code == 204
    assert _alerts(world.bearer(key)) == 200
    assert ops.post(f"/admin/tenants/{T1}/invitations", json={"email": NEW}).status_code == 202


@pytest.mark.parametrize("name", ["", "   "])
def test_a_program_needs_a_display_name(name: str) -> None:
    """A blank name is refused and nothing is created (O4)."""
    s = soar()
    assert s.ann.post(f"/tenants/{T1}/programs", json={"display_name": name}).status_code == 422
    assert [p["id"] for p in items(s.ann.get(f"/tenants/{T1}/programs"))] == [s.program_id]


# --- O5: secrets ----------------------------------------------------------------------------------

def test_a_key_is_shown_once_and_only_its_hash_is_kept() -> None:
    """The create response holds the key; listing and storage never do (O5)."""
    s = soar()
    listed = items(s.ann.get(_credentials_url(s.program_id)))
    assert [(c["id"], c["kind"], c["name"]) for c in listed] == [(s.key_id, "key", "primary")]
    assert s.key not in str(listed)
    assert not repo_holds(s.world.raw_repo, s.key)
    [row] = s.world.credentials(s.program_id)
    assert row.key_hash == hashlib.sha256(s.key.encode()).hexdigest()
    assert _alerts(s.program()) == 200  # the shown value is the working one


def test_a_key_is_dfk_prefix_credential_id_and_32_random_bytes() -> None:
    """Value: `dfk_` + credential id + `_` + 32 random bytes, base64url; two keys differ (Keys)."""
    s = soar()
    _, other = issue_key(s.ann, T1, s.program_id, name="second")
    head = f"dfk_{s.key_id}_"
    assert s.key.startswith(head)
    tail = s.key[len(head):]
    assert len(base64.urlsafe_b64decode(tail + "=" * (-len(tail) % 4))) == 32
    assert other.startswith("dfk_")
    assert other != s.key


def test_an_oauth_credential_shows_keycloaks_secret_once_and_stores_none_of_it() -> None:
    """OAuth: client id = credential id; the secret is Keycloak's, returned once, never stored or listed (O5, P-G)."""
    s = soar()
    response = issue(s.ann, T1, s.program_id, kind="oauth_client")
    assert response.status_code == 201, response.text
    credential = response.json()["id"]
    client = s.world.realm.clients[credential]
    assert response.json()["secret"] == client.secret
    assert not repo_holds(s.world.raw_repo, client.secret)
    assert client.secret not in s.ann.get(_credentials_url(s.program_id)).text
    row = {r.id: r for r in s.world.credentials(s.program_id)}[credential]
    assert (row.state, row.kind) == ("live", "oauth_client")


def _use(s: Soar, kind: str, credential: str, secret: str) -> Any:
    """A request authenticated by this very credential: the key itself, or a fresh token for the OAuth client."""
    return s.world.bearer(secret if kind == "key" else s.world.realm.issue(credential))


@pytest.mark.parametrize("kind", KINDS)
def test_listing_shows_the_credentials_facts_and_never_a_secret(kind: str) -> None:
    """Listing: kind, name, creator, created, expiry, last used; no secret or hash, before and after revocation (O5)."""
    s = soar()
    created_at = s.world.clock()
    created = issue(s.ann, T1, s.program_id, kind=kind, name="rotation")
    assert created.status_code == 201, created.text
    credential, secret = created.json()["id"], created.json()["secret"]
    hashes = [r.key_hash for r in s.world.credentials(s.program_id) if r.key_hash]
    listed = {c["id"]: c for c in items(s.ann.get(_credentials_url(s.program_id)))}
    assert listed[credential]["last_used_at"] is None  # control: not yet used
    s.world.clock.advance(_dt.timedelta(minutes=1))
    used_at = s.world.clock()
    assert _alerts(_use(s, kind, credential, secret)) == 200
    for _ in range(2):
        listed = {c["id"]: c for c in items(s.ann.get(_credentials_url(s.program_id)))}
        row = listed[credential]
        assert (row["kind"], row["name"]) == (kind, "rotation")
        assert parse_time(row["created_at"]) == created_at
        assert parse_time(row["expires_at"]) == created_at + DEFAULT_LIFETIME
        assert parse_time(row["last_used_at"]) == used_at
        assert user_id(s.ann) in {str(v) for v in row.values()}  # the creator
        text = str(listed)
        assert secret not in text
        assert s.key not in text
        assert not any(h in text for h in hashes)
        assert not [k for k in row if "secret" in k or "hash" in k]
        assert revoke(s.ann, T1, s.program_id, credential).status_code == 204


@pytest.mark.parametrize("kind", KINDS)
def test_use_is_recorded_as_last_used_at_most_every_five_minutes(kind: str) -> None:
    """`last_used_at` is written on use, and not again within 5 minutes, for a key and for an OAuth credential (Keys, O5)."""
    s = soar()
    credential, secret = s.key_id, s.key
    if kind == "oauth_client":
        created = issue(s.ann, T1, s.program_id, kind=kind, name="oauth")
        credential, secret = created.json()["id"], created.json()["secret"]

    def row() -> Any:
        return {r.id: r for r in s.world.credentials(s.program_id)}[credential]
    assert row().last_used_at is None
    assert _alerts(_use(s, kind, credential, secret)) == 200
    first = row().last_used_at
    assert first == s.world.clock()
    s.world.clock.advance(_dt.timedelta(minutes=4))
    assert _alerts(_use(s, kind, credential, secret)) == 200
    assert row().last_used_at == first
    s.world.clock.advance(_dt.timedelta(minutes=2))
    assert _alerts(_use(s, kind, credential, secret)) == 200
    assert row().last_used_at == s.world.clock()


# --- O5: expiry (D11) -----------------------------------------------------------------------------

@pytest.mark.parametrize("kind", KINDS)
def test_expiry_defaults_to_90_days(kind: str) -> None:
    """No expiry given -> 90 days from now (O5)."""
    s = soar()
    created = issue(s.ann, T1, s.program_id, kind=kind, name="default")
    assert created.status_code == 201, created.text
    assert parse_time(created.json()["expires_at"]) == s.world.clock() + DEFAULT_LIFETIME


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(("offset", "accepted"), [
    (-DAY, False), (_dt.timedelta(0), False),
    (MIN_LIFETIME - SECOND, False), (MIN_LIFETIME, True),
    (MAX_LIFETIME, True), (MAX_LIFETIME + SECOND, False),
])
def test_expiry_outside_7_to_365_days_is_refused_and_creates_nothing(
        kind: str, offset: _dt.timedelta, accepted: bool) -> None:
    """Lifetime bounds are inclusive at 7 and 365 days; outside -> 422, no row, no client (O5, D11)."""
    s = soar()
    when = s.world.clock() + offset
    response = issue(s.ann, T1, s.program_id, kind=kind, name="bounded", expires_at=when)
    if accepted:
        assert response.status_code == 201, response.text
        assert parse_time(response.json()["expires_at"]) == when
        assert len(s.world.credentials(s.program_id)) == 2
    else:
        assert response.status_code == 422, response.text
        assert len(s.world.credentials(s.program_id)) == 1
        assert s.world.realm.created == []


def test_an_unparseable_expiry_is_refused() -> None:
    """Not a timestamp -> 422, nothing created (O5)."""
    s = soar()
    response = s.ann.post(_credentials_url(s.program_id), json={"kind": "key", "name": "x", "expires_at": "someday"})
    assert response.status_code == 422
    assert len(s.world.credentials(s.program_id)) == 1


# --- O5: two slots ----------------------------------------------------------------------------------

def test_a_program_holds_at_most_two_live_credentials_of_any_kind() -> None:
    """A third is refused (409, no client made) until one is revoked (O5)."""
    s = soar()
    second = issue_oauth(s.ann, T1, s.program_id)
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 409
    assert issue(s.ann, T1, s.program_id, kind="oauth_client", name="third").status_code == 409
    assert s.world.realm.created == [second]
    assert revoke(s.ann, T1, s.program_id, second).status_code == 204
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 201


def test_an_expired_credential_frees_its_slot() -> None:
    """Only usable credentials count: after one's expiry a third may be issued (O5)."""
    s = soar()
    short, _ = issue_key(s.ann, T1, s.program_id, name="short", expires_at=s.world.clock() + MIN_LIFETIME)
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 409
    s.world.clock.advance(MIN_LIFETIME + SECOND)
    ann = s.world.sign_in(ANN)  # the earlier session is a week old
    assert issue(ann, T1, s.program_id, name="third").status_code == 201
    assert short in _states(s.world, s.program_id)


def test_a_pending_credential_holds_a_slot_until_its_deadline_even_without_the_purge() -> None:
    """A lost Keycloak response leaves `pending`: it counts for 10 minutes, then not, with no reconciliation run (O5, B1)."""
    s = soar()
    s.world.realm.lose_create_responses = 1
    assert issue(s.ann, T1, s.program_id, kind="oauth_client").status_code == 503
    [lost] = s.world.realm.created
    assert _states(s.world, s.program_id)[lost] == "pending"
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 409
    s.world.clock.advance(PENDING_DEADLINE - SECOND)
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 409
    s.world.clock.advance(2 * SECOND)
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 201
    assert s.world.realm.list_calls == 0  # nothing reconciled


@pytest.mark.parametrize("kind", KINDS)
def test_revoking_a_credential_of_another_program_is_a_404_and_changes_nothing(kind: str) -> None:
    """A credential not of the path's program -> 404 (O2/O5); the credential stays usable."""
    s = soar()
    other = str(create_program(s.ann, T1, "Other")["id"])
    assert revoke(s.ann, T1, other, s.key_id).status_code == 404
    assert _alerts(s.program()) == 200
    assert revoke(s.ann, T1, s.program_id, s.key_id).status_code == 204  # control: the right path works
    assert _alerts(s.program()) == 401


# --- O5: revocation and expiry stop the next request ----------------------------------------------

def test_revoking_an_oauth_credential_stops_tokens_already_issued() -> None:
    """Revocation is our row: an outstanding token fails on the next request, though its client lives (O5, rotation)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 200
    assert revoke(s.ann, T1, s.program_id, credential).status_code == 204
    assert credential in s.world.realm.clients
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 401
    assert _alerts(s.program()) == 200  # the other credential lives


def test_a_token_stays_refused_after_the_reconciliation_deleted_its_client() -> None:
    """A signed token verifies until `exp` whatever happened to its client; only our row refuses it (O5, P-G)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    revoke(s.ann, T1, s.program_id, credential)
    _reconcile(s.world)
    assert credential not in s.world.realm.clients
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 401


def test_an_expired_key_stops_on_the_next_request() -> None:
    """Usable = live and `expires_at > now` (O5)."""
    s = soar()
    s.world.clock.advance(DEFAULT_LIFETIME - DAY)
    assert _alerts(s.program()) == 200
    s.world.clock.advance(DAY)
    assert _alerts(s.program()) == 401


def test_an_expired_oauth_credential_refuses_a_fresh_token_while_its_client_still_exists() -> None:
    """Expiry is computed from our row; the client's later deletion is not what stops it (O5, W4)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id, expires_at=s.world.clock() + MIN_LIFETIME)
    s.world.clock.advance(MIN_LIFETIME - HOUR)
    assert s.world.bearer(s.world.realm.issue(credential)).get(f"/tenants/{T1}/alerts").status_code == 200
    s.world.clock.advance(HOUR + SECOND)
    assert credential in s.world.realm.clients
    assert s.world.bearer(s.world.realm.issue(credential)).get(f"/tenants/{T1}/alerts").status_code == 401
    assert _states(s.world, s.program_id)[credential] == "live"  # never written as a state change


# --- O6 / D3 / D4: removal --------------------------------------------------------------------------

def test_removing_a_program_cuts_it_off_and_revokes_every_credential_but_deletes_no_client() -> None:
    """Removal: next request 401 for key and token; rows revoked; the client waits for reconciliation (O6, D3)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    assert s.ann.delete(f"/tenants/{T1}/programs/{s.program_id}").status_code == 204
    assert _alerts(s.program()) == 401
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 401
    assert set(_states(s.world, s.program_id).values()) == {"revoked"}
    assert s.program_id not in {p["id"] for p in items(s.ann.get(f"/tenants/{T1}/programs"))}
    assert (s.world.realm.deleted, credential in s.world.realm.clients) == ([], True)
    _reconcile(s.world)
    assert s.world.realm.deleted == [credential]


def test_revoking_a_credential_deletes_no_client_but_the_next_reconciliation_does() -> None:
    """D3: revocation never deletes; reconciliation is the only deleter."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    assert revoke(s.ann, T1, s.program_id, credential).status_code == 204
    assert (s.world.realm.deleted, credential in s.world.realm.clients) == ([], True)
    _reconcile(s.world)
    assert credential not in s.world.realm.clients
    assert s.world.realm.deleted == [credential]


def _two_programs_with_credentials(world: ProgramsWorld, ann: Any) -> list[str]:
    programs = [str(create_program(ann, T1, f"P{n}")["id"]) for n in range(2)]
    for program in programs:
        issue_key(ann, T1, program)
        issue_oauth(ann, T1, program)
    return programs


def _consistent(world: ProgramsWorld, program: str) -> tuple[bool, bool]:
    ended = all(m.status != "active" for m in world.call(world.raw_repo.memberships_of_user, program))
    revoked = all(r.state == "revoked" for r in world.credentials(program))
    return ended, revoked


def test_removal_is_one_write_whichever_repository_call_fails_membership_and_credentials_agree() -> None:
    """Failing any one repository call during removal never leaves the membership ended and a credential usable, or the reverse (O6, D4)."""
    def fresh() -> tuple[ProgramsWorld, Any, str]:
        world = ProgramsWorld(tenants={T1: [ANN]}, failing_writes=True)
        ann = world.sign_in(ANN, browser=world.client(raise_errors=False))
        return world, ann, _two_programs_with_credentials(world, ann)[0]

    world, ann, program = fresh()
    mark = len(world.journal)
    assert ann.delete(f"/tenants/{T1}/programs/{program}").status_code == 204
    touched = sorted({name for kind, name in world.journal[mark:] if kind == "repo"})
    assert _consistent(world, program) == (True, True)
    assert touched, "removal touched no repository call"
    for name in touched:
        world, ann, program = fresh()
        world.repo.failing = {name}
        ann.delete(f"/tenants/{T1}/programs/{program}")
        ended, revoked = _consistent(world, program)
        assert ended == revoked, f"{name} failing split the removal: membership ended={ended}, credentials revoked={revoked}"


def _lifecycle(world: ProgramsWorld, repo: Any) -> Any:
    return IdentityService(repo, signin=world.signin, mail=world.mail, clock=world.clock,
                           bootstrap=Bootstrap(administrators=()), programs=RaisingProgramsRealm())


def test_offboarding_a_tenant_is_one_write_per_program_whichever_repository_call_fails() -> None:
    """Failing any one repository call in `end_tenant` leaves each program all-ended or all-usable, never split (O6, D4)."""
    def fresh() -> tuple[ProgramsWorld, list[str]]:
        world = ProgramsWorld(tenants={T1: [ANN]}, failing_writes=True)
        return world, _two_programs_with_credentials(world, world.sign_in(ANN))

    world, programs = fresh()
    journal: list[tuple[str, str]] = []
    world.call(_lifecycle(world, JournalRepository(world.repo, journal)).end_tenant, T1, now=world.clock())
    touched = sorted({name for kind, name in journal if kind == "repo"})
    assert [_consistent(world, p) for p in programs] == [(True, True)] * 2
    for name in touched:
        world, programs = fresh()
        world.repo.failing = {name}
        with contextlib.suppress(InjectedFailure):
            world.call(_lifecycle(world, world.repo).end_tenant, T1, now=world.clock())
        for program in programs:
            ended, revoked = _consistent(world, program)
            assert ended == revoked, f"{name} failing split offboarding of {program}"


def test_offboarding_revokes_program_credentials_without_ever_touching_the_realm() -> None:
    """`end_tenant` as the lifecycle runs it (loud-null programs port) revokes rows; the API's reconciliation deletes the clients (O6, D3, D7)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    s.world.call(s.world.lifecycle_service().end_tenant, T1, now=s.world.clock())  # RaisingProgramsRealm fails on any use
    assert _alerts(s.program()) == 401
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 401
    assert set(_states(s.world, s.program_id).values()) == {"revoked"}
    assert credential in s.world.realm.clients
    assert s.world.realm.deleted == []
    _reconcile(s.world)
    assert credential not in s.world.realm.clients


def test_offboarding_one_tenant_leaves_another_tenants_programs_working() -> None:
    """Control for offboarding: T2's program keeps working after T1 is offboarded (O6)."""
    s = soar()
    bob_program = str(create_program(s.bob, T2, "Bob's")["id"])
    _, bob_key = issue_key(s.bob, T2, bob_program)
    s.world.call(s.world.lifecycle_service().end_tenant, T1, now=s.world.clock())
    assert _alerts(s.program()) == 401
    assert s.world.bearer(bob_key).get(f"/tenants/{T2}/alerts").status_code == 200


# --- OAuth creation: failure, loss, race --------------------------------------------------------------

def test_keycloak_failing_before_creating_the_client_answers_503_and_leaves_a_stale_pending_row() -> None:
    """Keycloak down at create -> 503 with no secret; the row stays `pending` until the reconciliation revokes it after the deadline (B1)."""
    s = soar()
    s.world.realm.fail_creates = 1
    response = issue(s.ann, T1, s.program_id, kind="oauth_client")
    assert response.status_code == 503
    assert "secret" not in response.text
    [attempt] = s.world.realm.created
    assert _states(s.world, s.program_id)[attempt] == "pending"
    _reconcile(s.world)
    assert _states(s.world, s.program_id)[attempt] == "pending"  # within its deadline
    s.world.clock.advance(PENDING_DEADLINE + SECOND)
    _reconcile(s.world)
    assert _states(s.world, s.program_id)[attempt] == "revoked"
    assert issue(s.ann, T1, s.program_id, kind="oauth_client", name="retry").status_code == 201  # control: Keycloak is back


def test_a_lost_response_leaves_a_client_that_is_deleted_after_the_deadline() -> None:
    """The client was made but the answer lost: 503, no usable secret; reconciliation removes it after 10 minutes (B1, D3)."""
    s = soar()
    s.world.realm.lose_create_responses = 1
    response = issue(s.ann, T1, s.program_id, kind="oauth_client")
    assert response.status_code == 503
    [lost] = s.world.realm.created
    assert s.world.realm.clients[lost].secret not in response.text
    assert s.world.bearer(s.world.realm.issue(lost)).get(f"/tenants/{T1}/alerts").status_code == 401  # pending is not usable
    _reconcile(s.world)
    assert lost in s.world.realm.clients
    s.world.clock.advance(PENDING_DEADLINE + SECOND)
    _reconcile(s.world)
    assert lost not in s.world.realm.clients
    assert _states(s.world, s.program_id)[lost] == "revoked"


def test_removal_racing_an_oauth_creation_answers_409_and_returns_no_usable_secret() -> None:
    """The program is removed while Keycloak creates the client: 409, no secret, token refused; reconciliation deletes the client (O5, D4)."""
    s = soar()
    remover = s.world.sign_in(ANN)
    realm, create, removed = s.world.realm, s.world.realm.create_client, []

    async def racing(credential_id: str) -> tuple[str, str]:
        removed.append(await asyncio.wait_for(
            asyncio.to_thread(remover.delete, f"/tenants/{T1}/programs/{s.program_id}"), 10))
        return await create(credential_id)

    realm.create_client = racing  # type: ignore[method-assign]
    response = issue(s.ann, T1, s.program_id, kind="oauth_client")
    assert [r.status_code for r in removed] == [204]
    assert response.status_code == 409, response.text
    [credential] = realm.created
    assert realm.clients[credential].secret not in response.text
    assert _states(s.world, s.program_id)[credential] == "revoked"
    assert s.world.bearer(realm.issue(credential)).get(f"/tenants/{T1}/alerts").status_code == 401
    _reconcile(s.world)
    assert credential not in realm.clients


def test_an_oauth_creation_with_no_race_goes_live_with_the_same_wiring() -> None:
    """Control for the race: the same hook doing nothing yields 201 and a working token (O5)."""
    s = soar()
    seen: list[str] = []
    create = s.world.realm.create_client

    async def passing(credential_id: str) -> tuple[str, str]:
        seen.append(credential_id)
        return await create(credential_id)

    s.world.realm.create_client = passing  # type: ignore[method-assign]
    credential = issue_oauth(s.ann, T1, s.program_id)
    assert seen == [credential]
    assert s.world.bearer(s.world.realm.issue(credential)).get(f"/tenants/{T1}/alerts").status_code == 200


# --- reconciliation (D3, D4) ---------------------------------------------------------------------------

def test_reconciliation_deletes_every_client_without_a_usable_credential_and_keeps_the_rest() -> None:
    """A client exists only while its credential is usable or pending before its deadline (reconciliation, W1)."""
    world = ProgramsWorld(tenants={T1: [ANN]})
    ann = world.sign_in(ANN)
    program_id = str(create_program(ann, T1)["id"])
    live, revoked = issue_oauth(ann, T1, program_id), issue_oauth(ann, T1, program_id)
    assert revoke(ann, T1, program_id, revoked).status_code == 204
    world.realm.clients[ORPHAN] = Client(ORPHAN, "00000000-5a00-4000-8000-0000000000bb", "s")
    assert revoke(ann, T1, program_id, live).status_code == 204
    kept = issue_oauth(ann, T1, program_id)
    world.realm.lose_create_responses = 1  # armed after `kept` exists: the lost response belongs to the pending create
    assert issue(ann, T1, program_id, kind="oauth_client").status_code == 503  # pending, inside its deadline
    [pending] = world.realm.created[-1:]
    _reconcile(world)
    assert set(world.realm.clients) == {kept, pending}
    assert sorted(world.realm.deleted) == sorted([live, revoked, ORPHAN])


def test_reconciliation_deletes_the_client_of_an_expired_oauth_credential() -> None:
    """Expiry is cleaned up by the same rule as revocation (reconciliation, O5)."""
    s = soar()
    short = issue_oauth(s.ann, T1, s.program_id, expires_at=s.world.clock() + MIN_LIFETIME)
    _reconcile(s.world)
    assert short in s.world.realm.clients  # control: usable, kept
    s.world.clock.advance(MIN_LIFETIME + SECOND)
    _reconcile(s.world)
    assert short not in s.world.realm.clients


def test_reconciliation_lists_the_realm_before_it_reads_credentials() -> None:
    """The listing precedes the credential read that decides what to keep (D4)."""
    s = soar()
    issue_oauth(s.ann, T1, s.program_id)
    s.world.realm.clients[ORPHAN] = Client(ORPHAN, "00000000-5a00-4000-8000-0000000000bb", "s")
    mark = len(s.world.journal)
    _reconcile(s.world)
    run = s.world.journal[mark:]
    listing = run.index(("realm", "client_ids"))
    first_delete = run.index(("realm", "delete_client"))
    reads = [i for i, (kind, name) in enumerate(run) if kind == "repo" and "credential" in name]
    assert reads, run  # the keep-set is read through the repository
    assert min(reads) > listing, run  # no credential read precedes the listing
    assert any(listing < i < first_delete for i in reads), run


def test_a_client_created_while_reconciliation_runs_is_not_deleted() -> None:
    """A credential created during the pass has its client kept: the reverse order would delete it (D4)."""
    s = soar()
    other = s.world.sign_in(ANN)
    realm, listing, created = s.world.realm, s.world.realm.client_ids, []

    async def listing_with_a_creation() -> set[str]:
        if not created:
            created.append(await asyncio.wait_for(asyncio.to_thread(issue_oauth, other, T1, s.program_id), 10))
        return await listing()

    realm.client_ids = listing_with_a_creation  # type: ignore[method-assign]
    _reconcile(s.world)
    [credential] = created
    assert credential in realm.clients
    assert realm.deleted == []
    assert s.world.bearer(realm.issue(credential)).get(f"/tenants/{T1}/alerts").status_code == 200


# --- O7 / D5: expiry warnings ---------------------------------------------------------------------------

def _warned(world: ProgramsWorld, credential: str | None = None) -> list[tuple[str, str]]:
    return sorted((w.to, w.credential_id) for w in world.mail.warnings if credential in (None, w.credential_id))


def _until_remaining(world: ProgramsWorld, expires_at: _dt.datetime, remaining: _dt.timedelta) -> None:
    world.clock.advance(expires_at - remaining - world.clock())


def test_every_active_admin_and_only_they_are_warned_14_days_ahead_once() -> None:
    """14 days out: each active admin of the tenant, resolved at send time; not an invitee, a leaver or another tenant's admin (O7)."""
    s = soar()
    nina = NINA
    s.world.member(s.ann, T1, nina)
    leaver = s.world.member(s.ann, T1, "leaver@a.example")
    assert s.world.invite(s.ann, T1, "invitee@a.example").status_code == 202
    s.world.send_pending()
    assert s.ann.delete(f"/tenants/{T1}/members/{user_id(leaver)}").status_code == 204
    expiry = s.world.clock() + DEFAULT_LIFETIME
    _until_remaining(s.world, expiry, 14 * DAY + HOUR)
    s.world.send_pending()
    assert s.world.mail.warnings == []
    s.world.clock.advance(2 * HOUR)
    s.world.send_pending()
    s.world.send_pending()
    assert _warned(s.world) == sorted([(ANN, s.key_id), (nina, s.key_id)])
    assert {(w.tenant_id, w.program_id, w.expires_at) for w in s.world.mail.warnings} == {(T1, s.program_id, expiry)}


def test_warnings_come_at_14_and_3_days_and_the_second_goes_to_whoever_is_admin_then() -> None:
    """Two thresholds, one send each per admin; an admin who joined between them gets only the 3-day one (O7, D5)."""
    s = soar()
    expiry = s.world.clock() + DEFAULT_LIFETIME
    _until_remaining(s.world, expiry, 14 * DAY - HOUR)
    s.world.send_pending()
    assert _warned(s.world) == [(ANN, s.key_id)]
    late = "late@a.example"
    s.world.member(s.world.sign_in(ANN), T1, late)  # a fresh session: the first is two months old
    _until_remaining(s.world, expiry, 3 * DAY + HOUR)
    s.world.send_pending()
    assert _warned(s.world) == [(ANN, s.key_id)]  # not yet
    s.world.clock.advance(2 * HOUR)
    s.world.send_pending()
    s.world.send_pending()
    assert _warned(s.world) == sorted([(ANN, s.key_id)] * 2 + [(late, s.key_id)])


@pytest.mark.parametrize(("lifetime_days", "after_first_window", "after_second_window"),
                         [(20, 1, 2), (10, 0, 1), (7, 0, 1)])
def test_a_threshold_already_passed_at_creation_never_fires(
        lifetime_days: int, after_first_window: int, after_second_window: int) -> None:
    """Created with 10 days left: only the 3-day warning; with 20: both; nothing at creation (O7, D5, D11)."""
    s = soar()
    expiry = s.world.clock() + lifetime_days * DAY
    credential, _ = issue_key(s.ann, T1, s.program_id, name="timed", expires_at=expiry)
    s.world.send_pending()
    assert _warned(s.world, credential) == []
    _until_remaining(s.world, expiry, 14 * DAY - HOUR if lifetime_days > 14 else (lifetime_days - 1) * DAY)
    s.world.send_pending()
    assert len(_warned(s.world, credential)) == after_first_window
    _until_remaining(s.world, expiry, 3 * DAY - HOUR)
    s.world.send_pending()
    s.world.send_pending()
    assert len(_warned(s.world, credential)) == after_second_window


def test_a_sender_that_first_runs_after_both_thresholds_sends_exactly_one_warning_per_admin() -> None:
    """First pass 2 days before expiry: one warning per admin (the 3-day one), none later for the 14-day threshold (W6)."""
    s = soar()
    s.world.member(s.ann, T1, NINA)
    expiry = s.world.clock() + DEFAULT_LIFETIME
    _until_remaining(s.world, expiry, 2 * DAY)
    for _ in range(3):
        s.world.send_pending()
    assert _warned(s.world) == sorted([(ANN, s.key_id), (NINA, s.key_id)])
    s.world.clock.advance(DAY)
    s.world.send_pending()
    assert len(s.world.mail.warnings) == 2  # still: the passed 14-day threshold does not come back


def test_a_revoked_credential_is_not_warned_about() -> None:
    """Only live credentials warn; a sibling still gets its warning (O7)."""
    s = soar()
    second, _ = issue_key(s.ann, T1, s.program_id, name="second")
    assert revoke(s.ann, T1, s.program_id, second).status_code == 204
    _until_remaining(s.world, s.world.clock() + DEFAULT_LIFETIME, 14 * DAY - HOUR)
    s.world.send_pending()
    assert _warned(s.world) == [(ANN, s.key_id)]


def test_a_failed_send_is_retried_so_every_admin_is_warned_at_least_once() -> None:
    """Delivery is at least once: one admin's failed send is retried; once all arrived, no further sends (O7, D5)."""
    s = soar()
    s.world.member(s.ann, T1, NINA)
    mail, refusing = s.world.mail, {NINA}
    notify = mail.notify_credential_expiry

    async def flaky(to: str, *args: Any, **kwargs: Any) -> None:
        if to in refusing:
            raise InjectedFailure("the mail port refused")
        await notify(to, *args, **kwargs)

    mail.notify_credential_expiry = flaky  # type: ignore[method-assign]
    _until_remaining(s.world, s.world.clock() + DEFAULT_LIFETIME, 14 * DAY - HOUR)
    s.world.send_pending()
    assert {to for to, _ in _warned(s.world)} == {ANN}
    refusing.clear()
    for _ in range(48):
        s.world.clock.advance(HOUR)
        s.world.send_pending()
    got = {to for to, _ in _warned(s.world)}
    assert got == {ANN, NINA}
    settled = len(mail.warnings)
    for _ in range(3):
        s.world.send_pending()
    assert len(mail.warnings) == settled


# --- D9: the expiry header -----------------------------------------------------------------------------------

@pytest.mark.parametrize(("method", "path", "body", "status"), [
    ("get", f"/tenants/{T1}/alerts", None, 200),
    ("post", f"/tenants/{T1}/invitations", {"email": "x@y.example"}, 403),
    ("get", f"/tenants/{T2}/alerts", None, 404),
    ("post", f"/tenants/{T1}/investigations", {"alert_id": 5}, 422),
])
@pytest.mark.parametrize("kind", KINDS)
def test_every_response_to_a_verified_program_carries_its_credentials_expiry(
        kind: str, method: str, path: str, body: Any, status: int) -> None:
    """Success and refusals alike carry the used credential's expiry, not the token's (O7, D9)."""
    s = soar()
    when = s.world.clock() + 30 * DAY
    if kind == "key":
        _, value = issue_key(s.ann, T1, s.program_id, name="timed", expires_at=when)
    else:
        credential = issue_oauth(s.ann, T1, s.program_id, expires_at=when)
        value = s.world.realm.issue(credential)
    response = getattr(s.world.bearer(value), method)(path, **({} if body is None else {"json": body}))
    assert response.status_code == status, response.text
    assert parse_time(response.headers[EXPIRY_HEADER]) == when


def test_the_expiry_header_is_absent_for_a_person_and_for_a_refused_credential() -> None:
    """Control: persons and requests refused before verification carry none (O7, D9)."""
    s = soar()
    assert EXPIRY_HEADER not in s.ann.get(f"/tenants/{T1}/alerts").headers
    refused = s.world.bearer(s.key[:-2] + "xx").get(f"/tenants/{T1}/alerts")
    assert refused.status_code == 401
    assert EXPIRY_HEADER not in refused.headers
    assert EXPIRY_HEADER in s.program().get(f"/tenants/{T1}/alerts").headers
