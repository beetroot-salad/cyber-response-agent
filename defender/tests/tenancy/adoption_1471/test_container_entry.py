"""#1471 A3, R13-1.3/.4: the adoption container entry `defender.adoption.main(argv, *, environ=, client=)` over a socket stand-in answering
`launch` (with the forge origin and repo, surface §4) and `forge.token`, a real bare remote served at the tenant's recorded wiring, and a
forge double as `client`. Every outcome it writes is the entry's own; the fakes record and inject.

#1618: the entry opens the operation's own private repository against the launch facts' `forge_origin` (K4, K8: no host clone).
Retired with the clone (design "Retired promises": adoption's ref-lock collision and its `repository_busy` writer):
`test_a_ref_lock_held_on_the_clones_main_is_repository_busy_not_delivery_failed`; with one private repository per operation no
other writer can hold a ref lock in it (a stored `repository_busy` stays readable)."""
from __future__ import annotations

import base64
import json
import os
import uuid

import pytest

from defender.tests.support.jobs._socket_standin1170 import SocketStandIn
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._identity import identity as fixture_identity
from defender.tests.tenancy.tenant_1108_delivery._support import git, origin_of

from ._forge import DIGEST, RENDERING, SYSTEM, AdoptionForge, branch_for


#: A remote no forge answers at (G3, repair 5): an origin other than the recorded wiring.
DEAD_ORIGIN = "http://127.0.0.1:9/dead/clone-remote.git"


@pytest.fixture
def forge(repo):
    """The forge double at the tenant's recorded wiring (`wired`): the origin the tenant's remote is served at, which the
    helper's launch facts hand the entry as `forge_origin`."""
    http = AdoptionForge(remote=repo[1])
    http.wired = origin_of(repo)
    assert http.wired, "premise: the tenant's remote is served at an origin"
    http.serve(http.wired)
    return http


def _facts(repo, forge, **over):
    """The helper's launch facts for this job, as the helper hands them (surface §4); `over` changes keys."""
    facts = {
        "kind": "adoption",
        "tenant": str(repo[0].id),
        "job": over.pop("job_id"),
        "tenant_state": "active",
        "system": SYSTEM,
        "digest": DIGEST,
        "rendering": {path: base64.b64encode(data).decode() for path, data in RENDERING.items()},
        "forge_origin": forge.wired,
        "forge_repo": "tenants/blue",
    }
    return {**facts, **over}


def _enter(repo, forge, tmp_path, *, facts=None, silent=False, token=None):
    """Run the entry once against a socket handing `facts` (default: the helper's own); returns the record it wrote, or None."""
    from defender import adoption
    from defender.job_socket import SOCKET_ENV

    job_id = str(uuid.uuid4())
    tenant = str(repo[0].id)
    runs = location_path(repo[0].tenant_root) / "runs"
    runs.mkdir(exist_ok=True)
    own = _facts(repo, forge, job_id=job_id)
    handed = own if facts is None else facts(own)
    minted = fixture_identity(tenant).token()
    answer = token if token is not None else (lambda fields: {"token": minted})
    environ = {**os.environ, "DEFENDER_DATA_ROOT": str(tmp_path / "data")}
    with SocketStandIn(tenant, launch=handed, answers={"forge.token": answer}) as stand_in:
        for gone in set(own) - set(handed):  # the stand-in fills `tenant`/`tenant_state` by default: serve the removal
            stand_in.launch.pop(gone, None)
        environ[SOCKET_ENV] = str(tmp_path / "no-such-socket") if silent else str(stand_in.path)
        adoption.main(["--job", job_id, "--tenant", tenant], environ=environ, client=forge.client)
    path = runs / f"{job_id}.adoption.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def test_with_the_helpers_own_facts_the_entry_opens_the_offer_and_writes_opened(repo, forge, tmp_path):
    """Control: an active tenant, a protected main and the rendering handed over: `{opened, pr_number}` and the pushed adoption branch. (A3, R13-1)"""
    record = _enter(repo, forge, tmp_path)
    [pr] = [r for r in forge.prs if r["head"]["label"] == branch_for(DIGEST)]
    assert record == {"outcome": "opened", "pr_number": pr["number"]}


@pytest.mark.parametrize("fault", ["refused", "crashed"])
def test_a_forge_token_the_helper_cannot_give_ends_delivery_failed_with_a_record_not_a_crash(repo, forge, tmp_path, fault):
    """The helper refusing `forge.token` (its issuer sealed: `forge-fault`), or an answer the container cannot read (no
    `token`: a `KeyError` in the container, a fault of a kind no step names), is `delivery_failed`: the entry writes its
    record whatever the delivery raised, and nothing is opened. (A3: a fixed reason for anything else)"""
    from defender.job_socket import Refused

    def refuse(fields):
        raise Refused("the forge token could not be minted", "forge-fault")

    def unreadable(fields):
        return {"not_a_token": True}

    record = _enter(repo, forge, tmp_path, token=refuse if fault == "refused" else unreadable)
    assert record == {"outcome": "failed", "reason": "delivery_failed"}
    assert forge.creates == []


def test_an_unprotected_main_is_delivery_failed_and_nothing_is_pushed_or_opened(repo, forge, tmp_path):
    """The repository open refuses an unprotected main: `{failed, delivery_failed}`, no branch, no PR. (G-A3, A3)"""
    forge.protection = {**forge.protection, "protected": False}
    assert _enter(repo, forge, tmp_path) == {"outcome": "failed", "reason": "delivery_failed"}
    assert forge.creates == []
    assert git(repo[1], "for-each-ref", "refs/heads/adopt").strip() == ""


def test_the_entry_fetches_pushes_and_opens_only_at_the_facts_forge_origin(repo, forge, tmp_path):
    """The entry opens its repository at the launch facts' `forge_origin`, nowhere else: handed an origin no forge answers
    at, it is `{failed, delivery_failed}` and the forge at the wiring sees no request and gets no branch or PR. Control: the
    helper's own facts (the wiring) open the offer. (G3, A3; #1618 K4: the operation's own repository, no host clone)"""
    record = _enter(repo, forge, tmp_path, facts=lambda facts: {**facts, "forge_origin": DEAD_ORIGIN})
    assert record == {"outcome": "failed", "reason": "delivery_failed"}, record
    at_wiring = [r for r in forge.requests if forge._ours(r)]
    assert forge.requests, "premise: the entry asked a forge (the one its facts named)"
    assert at_wiring == [], f"the entry reached the wiring's forge though its facts named another origin: {at_wiring}"
    assert forge.creates == []
    assert git(repo[1], "for-each-ref", "refs/heads/adopt").strip() == ""
    control = _enter(repo, forge, tmp_path)
    assert control["outcome"] == "opened", control


@pytest.mark.parametrize("change", [
    "silent", "other-kind", "other-tenant", "other-job", "no-rendering",
])
def test_facts_that_are_not_this_requests_are_failed_handover_and_the_control_proceeds(repo, forge, tmp_path, change):
    """A launch that is unanswered, or facts of another kind, tenant or job or without a rendering: `{failed, handover}`; nothing sent. (R13-1.3, R13-1.4)"""
    mutate = {
        "silent": None,
        "other-kind": lambda facts: {**facts, "kind": "readiness"},
        "other-tenant": lambda facts: {**facts, "tenant": str(uuid.UUID(int=1471))},
        "other-job": lambda facts: {**facts, "job": str(uuid.UUID(int=1472))},
        "no-rendering": lambda facts: {k: v for k, v in facts.items() if k != "rendering"},
    }[change]
    assert _enter(repo, forge, tmp_path, facts=mutate, silent=change == "silent") == {"outcome": "failed", "reason": "handover"}
    assert forge.creates == []


def test_facts_saying_the_tenant_is_not_active_are_failed_tenant_not_active_not_handover(repo, forge, tmp_path):
    """`tenant_state` other than `active` in the launch facts: the container's `{failed, tenant_not_active}`; nothing sent. (R13-1.4, surface §5)"""
    record = _enter(repo, forge, tmp_path, facts=lambda facts: {**facts, "tenant_state": "offboarding"})
    assert record == {"outcome": "failed", "reason": "tenant_not_active"}
    assert forge.creates == []


#: The keys of the adoption launch facts (surface §4), as `_facts` hands them.
FACT_KEYS = ("kind", "tenant", "job", "tenant_state", "system", "digest", "rendering", "forge_origin", "forge_repo")
#: The facts' post-step key the adoption entry has no use for (the API base comes from `forge_origin`, surface §4).
UNREAD_KEYS = ("forge_repo",)


def _wrong_typed(value):
    return ["not", "a", "mapping"] if isinstance(value, dict) else ("1471" if not isinstance(value, str) else 1471)


@pytest.mark.parametrize("how", ["removed", "wrong-type"])
@pytest.mark.parametrize("key", FACT_KEYS)
def test_facts_missing_a_key_or_holding_a_value_of_another_type_end_in_a_record_never_a_crash(repo, forge, tmp_path, key, how):
    """Generated over every key of the helper's facts, each removed and each of another type: `{failed, handover}`, the
    container's `tenant_not_active` for `tenant_state`, or the honest `opened` for the key the entry does not read; never
    a crash or an exit with no record. (R13-1.4; repair 5)"""
    # `_facts` is the helper's own key set (`test_adoption_helper_1471`'s launch-facts case pins the helper to it)
    assert set(_facts(repo, forge, job_id="x")) == set(FACT_KEYS), "premise: the keys are the surface's"

    def mutate(facts):
        changed = dict(facts)
        if how == "removed":
            changed.pop(key)
        else:
            changed[key] = _wrong_typed(changed[key])
        return changed

    record = _enter(repo, forge, tmp_path, facts=mutate)
    assert record is not None, "the entry ended with no record"
    if key == "tenant_state":
        assert record in ({"outcome": "failed", "reason": "handover"}, {"outcome": "failed", "reason": "tenant_not_active"})
    elif key in UNREAD_KEYS:
        assert record in ({"outcome": "failed", "reason": "handover"}, {"outcome": "opened", "pr_number": record.get("pr_number")}), record
    else:
        assert record == {"outcome": "failed", "reason": "handover"}, record
        assert forge.creates == []
