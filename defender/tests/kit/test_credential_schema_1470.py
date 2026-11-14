"""#1470 O7, P6, D-E: `kit.access`'s credential schema decides what a scheme's credential set holds, which fields are secret
and every value rule the proxy refuses at use. FORCED CHOICE: the design names no accessor; `credential_faults(auth, fields)`
(a list of sentences, empty when the set fits) is the one name these tests use."""
from __future__ import annotations

from collections.abc import Mapping

import pytest

from defender.kit.access import Auth

LONG = "k" * 16  # the minimum length of a secret value (#1163 A4)
BEARER = Auth("bearer", field="api_key")
HEADER = Auth("header", field="token", header="X-Api-Key")
BASIC = Auth("basic")
OAUTH = Auth("oauth-client-credentials", token_url="https://idp.example/token", scopes=("read",))
#: scheme -> (auth, {field: secret?}, a set that fits): the design's per-scheme table.
SCHEMES = {
    "bearer": (BEARER, {"api_key": True}, {"api_key": LONG}),
    "header": (HEADER, {"token": True}, {"token": LONG}),
    "basic": (BASIC, {"username": False, "password": True}, {"username": "svc-account", "password": LONG}),
    "oauth": (OAUTH, {"client_id": False, "client_secret": True}, {"client_id": "client-1", "client_secret": LONG}),
}
_AUTH_IDS = list(SCHEMES)


def faults(auth: Auth, fields: Mapping[str, str]) -> list[str]:
    from defender.kit.access import credential_faults

    return list(credential_faults(auth, fields))


def _refused_by_the_proxy(auth: Auth, fields: Mapping[str, str]) -> bool:
    """What the proxy does at use with a set of the right fields: it refuses (`Refused`) or builds the header."""
    from defender.credential_proxy._credentials import CredentialSet, Refused, static_headers

    try:
        static_headers(auth, CredentialSet(kind="static", fields=dict(fields), version=1), "sys")
    except Refused:
        return True
    return False


@pytest.mark.parametrize("name", _AUTH_IDS)
def test_1470_o7_a_set_of_exactly_the_schemes_fields_fits_and_is_the_control_for_every_refusal(name):
    """The fitting set of each scheme has no fault. (O7)"""
    auth, _, fitting = SCHEMES[name]
    assert faults(auth, fitting) == []


@pytest.mark.parametrize("name", _AUTH_IDS)
def test_1470_o7_a_missing_or_extra_field_is_a_fault_naming_it(name):
    """Dropping any field, adding one the scheme does not read, or sending nothing is refused naming each field. (O7)"""
    auth, secret, fitting = SCHEMES[name]
    for dropped in fitting:
        found = faults(auth, {k: v for k, v in fitting.items() if k != dropped})
        assert found, (dropped, found)
        assert any(dropped in f for f in found), (dropped, found)
    extra = faults(auth, {**fitting, "extra_field": LONG})
    assert extra, extra
    assert any("extra_field" in f for f in extra), extra
    nothing = faults(auth, {})
    assert all(any(field in f for f in nothing) for field in secret), nothing


@pytest.mark.parametrize("name", _AUTH_IDS)
def test_1470_o7_exactly_the_secret_fields_need_the_minimum_length_and_the_public_ones_do_not(name):
    """Per field: one character is a fault when the field is secret and fine when public; the minimum length is accepted
    and one less is not. (O7, schema: which fields are secret)"""
    auth, secret, fitting = SCHEMES[name]
    for field, is_secret in secret.items():
        short = faults(auth, {**fitting, field: "x"})
        assert bool(short) is is_secret, (field, short)
        if is_secret:
            assert any(field in f for f in short), short
            assert faults(auth, {**fitting, field: "k" * 15}), field
            assert faults(auth, {**fitting, field: "k" * 16}) == [], field


@pytest.mark.parametrize("name", _AUTH_IDS)
def test_1470_o7_an_empty_value_is_a_fault_in_every_field(name):
    """Every field must be non-empty, secret or not. (O7)"""
    auth, _, fitting = SCHEMES[name]
    for field in fitting:
        assert faults(auth, {**fitting, field: ""}), field


@pytest.mark.parametrize("name", _AUTH_IDS)
def test_1470_o7_every_fault_is_reported_at_once_and_none_shows_a_value(name):
    """A set with a non-printable secret value and a field the scheme does not read lists a fault for each, naming the
    fields; none holds any value. (O7: `faults` lists every fault; credential events name fields, never values)"""
    auth, secret, _ = SCHEMES[name]
    secret_field = next(f for f, is_secret in secret.items() if is_secret)
    found = faults(auth, {secret_field: "sentinel\x07-value-1470", "extra_field": "sentinel-extra-1470"})
    assert any(secret_field in f for f in found), found
    assert any("extra_field" in f for f in found), found
    assert len(found) >= 2, found  # noqa: PLR2004 — each defect has its own fault
    assert not any("sentinel" in f for f in found), found


def _codepoints() -> list[int]:
    """Every control, ASCII and Latin character, then one in every 7th of the rest of the Basic Multilingual Plane and the
    planes above: members by class, not a hand-picked list."""
    return [cp for cp in [*range(0x250), *range(0x250, 0x110000, 7)] if not 0xD800 <= cp <= 0xDFFF]


@pytest.mark.parametrize("name", ["bearer", "header", "basic"])
def test_1470_o7_the_schema_refuses_exactly_what_the_proxy_refuses_at_use_for_any_character_in_any_field(name):
    """For every character in each static field (a value of the minimum length ending in it): the schema finds a fault
    exactly when the proxy's header build refuses the set, so a set accepted at the write is never refused at the first
    call and none the proxy would use is refused. (O7, schema holds every value rule)"""
    auth, _, fitting = SCHEMES[name]
    wrong = []
    for field in fitting:
        for cp in _codepoints():
            value = "k" * 15 + chr(cp)
            fields = {**fitting, field: value}
            if bool(faults(auth, fields)) != _refused_by_the_proxy(auth, fields):
                wrong.append((field, hex(cp)))
    assert not wrong, wrong[:10]


def test_1470_o7_the_rules_by_field_anchor_the_sweep():
    """Anchors for the sweep (it compares two implementations): a control character is refused everywhere; non-ASCII only
    where the value is sent in a header (bearer and header's field), not in a basic password or an OAuth client; `:` only in
    a basic username. (O7, scenarios)"""
    controls = "k" * 15 + "\x00"
    for name, (auth, _, fitting) in SCHEMES.items():
        for field in fitting:
            assert faults(auth, {**fitting, field: controls}), (name, field)
    wide = "k" * 15 + "é"
    assert faults(BEARER, {"api_key": wide})
    assert faults(HEADER, {"token": wide})
    assert faults(BASIC, {"username": "svc", "password": wide}) == []
    assert faults(OAUTH, {"client_id": "client-1", "client_secret": wide}) == []
    assert faults(BASIC, {"username": "svc:acct", "password": LONG})
    assert faults(BASIC, {"username": "svc", "password": "k" * 15 + ":"}) == []
    assert faults(BEARER, {"api_key": "k" * 15 + ":"}) == []
    assert faults(OAUTH, {"client_id": "a:b", "client_secret": LONG}) == []


def test_1470_d_e_the_separate_secrecy_tables_are_gone():
    """`secret_fields` and `PUBLIC_FIELD` (a second statement of which fields are secret) no longer exist beside the
    schema. (D-E: they go)"""
    import defender.kit.access as access

    assert callable(getattr(access, "credential_faults", None)), "premise: the schema's check stands where they were"
    assert [n for n in ("secret_fields", "PUBLIC_FIELD") if hasattr(access, n)] == []


def test_1470_g6_the_schemas_refusal_is_its_own_typed_exception_carrying_the_faults_apart_from_the_stores():
    """`kit.access.CredentialRefused` is an exception type of the credential schema, not one of the store's `RecordRefused`
    family, so the route maps the two by type. (P6, G6)"""
    from defender.kit.access import CredentialRefused
    from defender.system_records import RecordRefused

    assert issubclass(CredentialRefused, Exception)
    assert not issubclass(CredentialRefused, RecordRefused)
