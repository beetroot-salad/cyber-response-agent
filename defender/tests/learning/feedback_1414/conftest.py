"""Fixtures for #1414's feedback tick; its scene and the names it forces live in `_spec1414.py`."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.learning.feedback_1414._spec1414 import NAMED, OUTSIDER, OWNER, Feedback
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths, product_repo
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant


@pytest.fixture
def fb(tmp_path, data_root):
    """A published tenant with its forge bound; the forge authenticates as the tenant's bot login, and
    the service's eligibility record (D13) holds `ann` and `bea`."""
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bound = bind_forge(t)
        bot = bound["generations"][0]["bot_login"]
        t.forge.login = bot
        # The forge's own whitelist is a decoy: the tick reads the service's record (D13), never the forge's rule.
        t.forge.protection_rule["merge_whitelist_usernames"] = [OUTSIDER]
        Path(location_path(t.tenant.learning)).mkdir(exist_ok=True)
        scene = Feedback(t=t, paths=drain_paths(t, product_repo(tmp_path)), bot=bot, tmp=tmp_path)
        scene.eligible(OWNER, NAMED)
        yield scene
