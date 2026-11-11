"""Fixtures for #1414's feedback tick; its scene and the names it forces live in `_spec1414.py`."""
from __future__ import annotations

import pytest

from defender.tests.learning.feedback_1414._spec1414 import (
    ELIGIBILITY_MAX_AGE_ENV,
    NAMED,
    OUTSIDER,
    OWNER,
    Feedback,
)
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import DSN_ENV, GRACE_ENV, LEASE_ENV, RENEW_ENV
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths, product_repo
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant


@pytest.fixture
def fb(tmp_path, data_root, monkeypatch, migrated_database):  # noqa: F811 — the imported fixture
    """A published tenant with its forge bound; the forge authenticates as the tenant's bot login, and
    the service's eligibility record (D13) holds `ann` and `bea`. The record's staleness bound is set large so a
    multi-tick test never outlives the 60 s default (D15); the staleness test sets or clears it itself. The tenant is
    active in a migrated database found at `DEFENDER_DATABASE_DSN` (A4: every feedback record is a row there; D10: the
    tenant has no `learning` folder). A lease of ten minutes with five of grace and a renewer that never fires, so only a
    case that lapses a lease (`Feedback.lapse`) sees one end."""
    monkeypatch.setenv(DSN_ENV, migrated_database)
    monkeypatch.setenv(LEASE_ENV, "600")
    monkeypatch.setenv(GRACE_ENV, "300")
    monkeypatch.setenv(RENEW_ENV, "600")
    monkeypatch.setenv(ELIGIBILITY_MAX_AGE_ENV, "3600")
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bound = bind_forge(t)
        bot = bound["generations"][0]["bot_login"]
        t.forge.login = bot
        # The forge's own whitelist is a decoy: the tick reads the service's record (D13), never the forge's rule.
        t.forge.protection_rule["merge_whitelist_usernames"] = [OUTSIDER]
        register_tenant(migrated_database, t.tenant_id)
        scene = Feedback(t=t, paths=drain_paths(t, product_repo(tmp_path)), bot=bot, tmp=tmp_path, dsn=migrated_database)
        scene.eligible(OWNER, NAMED)
        yield scene
