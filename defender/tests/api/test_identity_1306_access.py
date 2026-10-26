"""#1306: who a request is and which tenant it may act in (O1, P-D, O7)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from defender.api.models import AlertSummary  # noqa: E402
from defender.tests.support.api._identity1306 import (  # noqa: E402
    ALERT,
    ANN,
    BOB,
    NEW,
    NO_SUCH_ID,
    SUMMARY,
    T1,
    T2,
    UNKNOWN,
    invitation_id,
    items,
    masked,
    me,
    problem_type,
    tenants_of,
    two_tenants,
    user_id,
)

BAD_TENANT = "not-a-tenant-id"


def test_a_request_without_a_valid_session_cookie_is_401_with_no_bearer_challenge() -> None:
    """No credential, or an unknown cookie value -> 401 without a Bearer challenge (O1, O6)."""
    world, ann, _ = two_tenants()
    assert ann.get("/me").status_code == 200
    for browser in (world.client(), world.client_with_cookie("no-such-session")):
        # Check order: the session before the tenant, so an unknown or malformed tenant is 401 too.
        for path in (f"/tenants/{T1}/alerts", f"/tenants/{UNKNOWN}/alerts", f"/tenants/{BAD_TENANT}/alerts",
                     f"/tenants/{BAD_TENANT}/members", "/me", "/admin/tenants"):
            response = browser.get(path)
            assert response.status_code == 401, path
            assert "bearer" not in response.headers.get("www-authenticate", "").lower()


@pytest.mark.parametrize("other", [T2, UNKNOWN, BAD_TENANT])
def test_a_non_member_an_unknown_and_a_malformed_tenant_get_the_same_404(other: str) -> None:
    """A member reaches their tenant; every other tenant answers alike (O1/P-D)."""
    world, ann, _ = two_tenants()
    assert ann.get(f"/tenants/{T1}/alerts").status_code == 200
    reference = ann.get(f"/tenants/{UNKNOWN}/alerts")
    probed = ann.get(f"/tenants/{other}/alerts")
    assert probed.status_code == reference.status_code == 404
    assert probed.headers["content-type"] == reference.headers["content-type"]
    assert masked(probed, other) == masked(reference, UNKNOWN)


@pytest.mark.parametrize(("method", "path", "body"), [
    ("GET", "members", None),
    ("GET", "invitations", None),
    ("POST", "invitations", {"email": NEW}),
])
def test_every_tenant_route_gives_a_non_member_the_same_404_as_an_unknown_tenant(
        method: str, path: str, body: object) -> None:
    """P-D holds on the people routes as well as the data routes (O1/P-D)."""
    _, ann, _ = two_tenants()
    asked = ann.request(method, f"/tenants/{T2}/{path}", json=body)
    unknown = ann.request(method, f"/tenants/{UNKNOWN}/{path}", json=body)
    assert asked.status_code == unknown.status_code == 404
    assert masked(asked, T2) == masked(unknown, UNKNOWN)
    assert items(ann.get(f"/tenants/{T1}/invitations")) == []  # nothing was written into T1


def test_another_tenants_invitation_or_member_id_is_the_same_404_as_a_missing_one() -> None:
    """An id of another tenant's invitation or member is indistinguishable from none (P-D)."""
    world, ann, bob = two_tenants()
    world.invite(bob, T2, NEW)
    foreign_invitation = invitation_id(bob, T2, NEW)
    bob_id = user_id(bob)
    revoke_foreign = ann.delete(f"/tenants/{T1}/invitations/{foreign_invitation}")
    revoke_missing = ann.delete(f"/tenants/{T1}/invitations/{NO_SUCH_ID}")
    remove_foreign = ann.delete(f"/tenants/{T1}/members/{bob_id}")
    remove_missing = ann.delete(f"/tenants/{T1}/members/{NO_SUCH_ID}")
    assert revoke_foreign.status_code == revoke_missing.status_code == 404
    assert remove_foreign.status_code == remove_missing.status_code == 404
    assert masked(revoke_foreign, foreign_invitation) == masked(revoke_missing, NO_SUCH_ID)
    assert masked(remove_foreign, bob_id) == masked(remove_missing, NO_SUCH_ID)
    # positive control: nothing of T2 was touched, and the owner can still act on both
    assert tenants_of(bob) == {T2}
    assert bob.delete(f"/tenants/{T2}/invitations/{foreign_invitation}").status_code == 204


def test_an_invitation_id_of_someone_else_or_nobody_is_the_same_404_at_accept() -> None:
    """Accepting another person's invitation id looks like accepting none (flow 3, P-D)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, BOB)
    world.send_pending()
    mine = me(bob)["invitations"][0]["id"]
    elsewhere = world.sign_in(ANN)  # ann is not the invitee
    refused = elsewhere.post(f"/invitations/{mine}/accept")
    missing = elsewhere.post(f"/invitations/{NO_SUCH_ID}/accept")
    assert refused.status_code == missing.status_code == 404
    assert masked(refused, mine) == masked(missing, NO_SUCH_ID)
    assert problem_type(refused) == problem_type(missing)
    assert bob.post(f"/invitations/{mine}/accept").status_code == 200


def test_a_member_of_two_tenants_reads_and_writes_only_in_the_paths_tenant() -> None:
    """The path's tenant, not one of the caller's others, is the tenant every data route acts in (P-D, O7)."""
    world, ann, bob = two_tenants()
    other = ALERT.model_copy(update={"alert_id": "al-2", "title": "T2's own"})
    world.store.add_alert(T2, other)
    world.invite(bob, T2, ANN)
    world.send_pending()
    [invitation] = me(ann)["invitations"]
    assert ann.post(f"/invitations/{invitation['id']}/accept").status_code == 200
    assert tenants_of(ann) == {T1, T2}
    for tenant, own, foreign in ((T1, ALERT, other), (T2, other, ALERT)):
        summary = AlertSummary.model_validate(own.model_dump(exclude={"raw"})).model_dump(mode="json")
        assert items(ann.get(f"/tenants/{tenant}/alerts")) == [summary], tenant
        assert ann.get(f"/tenants/{tenant}/alerts/{own.alert_id}").json() == own.model_dump(mode="json")
        assert ann.get(f"/tenants/{tenant}/alerts/{foreign.alert_id}").status_code == 404, tenant
    created = ann.post(f"/tenants/{T2}/investigations", json={"alert_id": "al-2", "client_request_id": "r1"})
    assert created.status_code == 201, created.text
    [event] = world.store.audit_events
    assert (event.tenant_id, event.user_id) == (T2, user_id(ann))
    assert items(ann.get(f"/tenants/{T1}/investigations")) == []
    assert [i["investigation_id"] for i in items(bob.get(f"/tenants/{T2}/investigations"))] == [
        created.json()["investigation_id"]]


def test_the_alerts_routes_answer_unchanged_under_the_tenant_prefix() -> None:
    """Existing routes move under /tenants/{T}/ with unchanged behaviour (O7)."""
    _, ann, _ = two_tenants()
    assert items(ann.get(f"/tenants/{T1}/alerts")) == [SUMMARY.model_dump(mode="json")]
    assert ann.get(f"/tenants/{T1}/alerts/al-1").json() == ALERT.model_dump(mode="json")
    assert ann.get("/alerts").status_code == 404
