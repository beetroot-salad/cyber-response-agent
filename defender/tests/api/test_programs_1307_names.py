"""#1307 A2: a program's display name and a credential's name are refused at the API edge, 422 and nothing stored, when they hold
what PostgreSQL text cannot (NUL, a lone surrogate), as emails and client request ids already are. The repositories refuse the same
names with `DataRuleViolation` (test_1307_repository_contract.py)."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender._text import postgres_can_hold  # noqa: E402
from defender.tests.identity.test_1307_repository_contract import HOLDABLE, UNHOLDABLE  # noqa: E402
from defender.tests.support.api._identity1306 import T1, items  # noqa: E402
from defender.tests.support.api._programs1307 import soar  # noqa: E402


def _post(client, path: str, **body: str):
    """The body as JSON text with ASCII escapes, so a lone surrogate travels as `\\ud800` (the client cannot encode it as UTF-8)."""
    return client.post(path, content=json.dumps(body, ensure_ascii=True).encode(), headers={"content-type": "application/json"})


def test_names_that_postgres_text_cannot_hold_are_422_for_programs_and_credentials_and_store_nothing() -> None:
    """Every unholdable name (NUL, either kind of lone surrogate, at the start, middle or end of a valid name) as a program's
    display name and as a credential's name for both kinds -> 422; the same calls with holdable names are 201 (control)."""
    assert not any(postgres_can_hold(n) for n in UNHOLDABLE)
    s = soar()
    programs, credentials = f"/tenants/{T1}/programs", f"/tenants/{T1}/programs/{s.program_id}/credentials"
    refused = []
    for name in UNHOLDABLE:
        for what, response in (("program", _post(s.ann, programs, display_name=name)),
                               ("key", _post(s.ann, credentials, kind="key", name=name)),
                               ("oauth", _post(s.ann, credentials, kind="oauth_client", name=name))):
            if response.status_code != 422:
                refused.append((what, name, response.status_code))
    assert refused == []
    assert len(items(s.ann.get(programs))) == 1
    assert len(items(s.ann.get(credentials))) == 1
    assert s.world.realm.created == []  # no Keycloak client was made for a refused name
    for name in HOLDABLE:  # control: holdable names go through, so the 422s above are the names'
        assert _post(s.ann, programs, display_name=name).status_code == 201, name
    assert _post(s.ann, credentials, kind="key", name=HOLDABLE[1]).status_code == 201
