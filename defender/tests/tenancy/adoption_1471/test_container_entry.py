"""#1471 A3, R13-1.3/.4: the adoption container entry `defender.adoption.main(argv, *, environ=, client=)` over a socket stand-in answering
`launch` (with the forge origin and repo, surface §4) and `forge.token`, the tenant's clone and a real bare remote, and a forge double as
`client`. Every outcome it writes is the entry's own; the fakes record and inject."""
from __future__ import annotations

import base64
import json
import os
import uuid
from pathlib import Path

import pytest

from defender.tests.support.jobs._socket_standin1170 import SocketStandIn
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._identity import identity as fixture_identity
from defender.tests.tenancy.tenant_1108_delivery._support import configured_origin, git, push_to_remote

from ._forge import DIGEST, RENDERING, SYSTEM, AdoptionForge, branch_for


@pytest.fixture
def forge(repo):
    http = AdoptionForge(remote=repo[1])
    http.serve(configured_origin(repo[0].knowledge))
    return http


def _facts(repo, **over):
    """The helper's launch facts for this job, as the helper hands them (surface §4); `over` changes keys."""
    facts = {
        "kind": "adoption",
        "tenant": str(repo[0].id),
        "job": over.pop("job_id"),
        "tenant_state": "active",
        "system": SYSTEM,
        "digest": DIGEST,
        "rendering": {path: base64.b64encode(data).decode() for path, data in RENDERING.items()},
        "forge_origin": configured_origin(repo[0].knowledge),
        "forge_repo": "tenants/blue",
    }
    return {**facts, **over}


def _enter(repo, forge, tmp_path, *, facts=None, silent=False):
    """Run the entry once against a socket handing `facts` (default: the helper's own); returns the record it wrote, or None."""
    from defender import adoption
    from defender.job_socket import SOCKET_ENV

    job_id = str(uuid.uuid4())
    tenant = str(repo[0].id)
    runs = location_path(repo[0].tenant_root) / "runs"
    runs.mkdir(exist_ok=True)
    handed = _facts(repo, job_id=job_id) if facts is None else facts(_facts(repo, job_id=job_id))
    token = fixture_identity(tenant).token()
    environ = {**os.environ, "DEFENDER_DATA_ROOT": str(tmp_path / "data")}
    with SocketStandIn(tenant, launch=handed, answers={"forge.token": lambda fields: {"token": token}}) as stand_in:
        environ[SOCKET_ENV] = str(tmp_path / "no-such-socket") if silent else str(stand_in.path)
        adoption.main(["--job", job_id, "--tenant", tenant], environ=environ, client=forge.client)
    path = runs / f"{job_id}.adoption.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def test_with_the_helpers_own_facts_the_entry_opens_the_offer_and_writes_opened(repo, forge, tmp_path):
    """Control: an active tenant, a protected main and the rendering handed over: `{opened, pr_number}` and the pushed adoption branch. (A3, R13-1)"""
    record = _enter(repo, forge, tmp_path)
    [pr] = [r for r in forge.prs if r["head"]["label"] == branch_for(DIGEST)]
    assert record == {"outcome": "opened", "pr_number": pr["number"]}


def test_an_unprotected_main_is_delivery_failed_and_nothing_is_pushed_or_opened(repo, forge, tmp_path):
    """The repository open refuses an unprotected main: `{failed, delivery_failed}`, no branch, no PR. (G-A3, A3)"""
    forge.protection = {**forge.protection, "protected": False}
    assert _enter(repo, forge, tmp_path) == {"outcome": "failed", "reason": "delivery_failed"}
    assert forge.creates == []
    assert git(repo[1], "for-each-ref", "refs/heads/adopt").strip() == ""


def test_a_ref_lock_held_on_the_clones_main_is_repository_busy_not_delivery_failed(repo, forge, tmp_path):
    """`refs/remotes/origin/main.lock` planted in the clone while the remote has moved: the fetch's ref update collides, `{failed, repository_busy}`; nothing sent. (A3, surface §7)"""
    def advance(writer):
        (writer / "agent" / "lessons" / "later.md").write_text("landed after the clone fetched\n", encoding="utf-8")
    push_to_remote(repo, tmp_path, advance)
    lock = Path(location_path(repo[0].knowledge)) / ".git" / "refs" / "remotes" / "origin" / "main.lock"
    lock.write_text("", encoding="utf-8")
    assert _enter(repo, forge, tmp_path) == {"outcome": "failed", "reason": "repository_busy"}
    assert forge.creates == []


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
