"""#1470 O7: the access parser's rule that the secret a scheme sends may not be a field public by name is stated from the
credential schema (the names the schema holds public), not from a table of its own."""
from __future__ import annotations

import pytest

from defender.kit.faults import ConfigFault
from defender.tests.kit.test_credential_schema_1470 import BASIC, OAUTH, faults
from defender.tests.support.tenancy import _systems1366 as R


def _public_names() -> set[str]:
    """The fields the schema lets be short: the public ones of the schemes that have a public field."""
    names = set()
    for auth, fitting in ((BASIC, {"username": "u", "password": "k" * 16}), (OAUTH, {"client_id": "c", "client_secret": "k" * 16})):
        names |= {field for field in fitting if not faults(auth, {**fitting, field: "x"})}
    return names


def _parsed(scheme: str, field: str) -> object:
    from defender.tenancy import parse_access

    extra = {"header": "X-Api-Key"} if scheme == "header" else {}
    return parse_access(R.declaration("https://ticket.example.test", auth={"scheme": scheme, "field": field, **extra}),
                        system="ticket")


def test_1470_o7_the_schemas_public_names_are_username_and_client_id():
    """The premise of the rule below: exactly these two fields are public across the schemes. (O7 schema)"""
    assert _public_names() == {"username", "client_id"}


@pytest.mark.parametrize("scheme", ["bearer", "header"])
def test_1470_o7_a_declaration_whose_secret_field_is_public_by_name_is_refused_naming_it(scheme):
    """For each name the schema holds public, a bearer or header declaration naming it as its secret field is a `ConfigFault`
    naming the field; a name the schema holds secret (`password`, `client_secret`) and an ordinary one parse (control). (O7)"""
    assert _parsed(scheme, "api_key") is not None, "control"
    for ordinary in ("password", "client_secret", "token"):
        assert _parsed(scheme, ordinary) is not None, ordinary
    names = _public_names()
    assert names, "premise: the schema has public names"
    for name in sorted(names):
        with pytest.raises(ConfigFault, match=name):
            _parsed(scheme, name)
