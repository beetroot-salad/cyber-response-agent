"""#1592 r12 "Feedback" (amends #1414, OD-6): the tick takes in a comment exactly when its author's login is `p-`
followed by the canonical id of a user wanted in T, by the tick's one membership read through the `people=` seam
(in place of `eligibility_max_age`). Every other login, bots' included, is passed over and logged.

Its own fixture: `fb` seeds #1414's eligibility record, which this design removes.
"""
from __future__ import annotations

import logging
from typing import Any

import pytest

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import DSN_ENV, GRACE_ENV, LEASE_ENV, RENEW_ENV
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths, product_repo
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

pytestmark = pytest.mark.postgres

WANTED = fixture_uuid("user:1592-feedback-wanted")
NOT_WANTED = fixture_uuid("user:1592-feedback-not-wanted")


class People:
    """The `people=` seam (FC-13: its shape is not given; here a synchronous `wanted_users(tenant_id)` returning user
    ids, as the identity wrapper the design names would). Records each read."""

    def __init__(self, *users: str) -> None:
        self.users = set(users)
        self.reads: list[str] = []

    def wanted_users(self, tenant_id: Any) -> set[str]:
        self.reads.append(str(tenant_id))
        return set(self.users)


@pytest.fixture
def fbp(tmp_path, data_root, monkeypatch, migrated_database):  # noqa: F811 — the imported fixture
    """#1414's scene (`conftest.fb`) without the eligibility record or its bound."""
    monkeypatch.setenv(DSN_ENV, migrated_database)
    monkeypatch.setenv(LEASE_ENV, "600")
    monkeypatch.setenv(GRACE_ENV, "300")
    monkeypatch.setenv(RENEW_ENV, "600")
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bound = bind_forge(t)
        bot = bound["generations"][0]["bot_login"]
        t.forge.login = bot
        register_tenant(migrated_database, t.tenant_id)
        yield S.Feedback(t=t, paths=drain_paths(t, product_repo(tmp_path)), bot=bot, tmp=tmp_path, dsn=migrated_database)


def test_1592_a_comment_counts_by_its_authors_membership_read_once_per_tick(fbp, caplog):
    """`p-<wanted>` is taken in; `p-<not wanted>`, the wanted id in upper case (not canonical), a plain login and the
    bot are passed over and logged. The tick reads the membership once, for its own tenant."""
    people = People(WANTED)
    number = fbp.opened("case-1592", S.Decider())
    taken = fbp.forge.add_comment(number, user=f"p-{WANTED}", body="expected")
    for login in (f"p-{NOT_WANTED}", f"p-{WANTED.upper()}", "ann", fbp.bot):
        fbp.forge.add_comment(number, user=login, body="approved, add it")
    people.reads.clear()

    decider = S.Decider()
    with caplog.at_level(logging.INFO):
        assert fbp.tick(decider, people=people) == 0

    assert decider.decided == [taken["id"]]
    assert people.reads == [fbp.tid], "the tick did not read the membership exactly once, for its tenant"
    assert any(f"p-{NOT_WANTED}" in r.getMessage() for r in caplog.records), "the passed-over author is not logged"
    assert fbp.requests_to("branch_protections", "/teams", "/orgs/") == [], "the tick read Forgejo's team"
