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


#: Base's names outside the field grammar (a field name reaches the audit detail, so one the audit store would refuse never
#: gets in): NUL inside, a lone surrogate, empty, a space, 65 characters, a leading digit.
_BASE_NAMES = ["a\x00b", "\ud800", "", "has space", "x" * 65, "9lead"]
_ALL_FIELDS = {f for _, secret, _ in SCHEMES.values() for f in secret}


def _generated_names() -> list[str]:
    """A seeded sample of names no scheme has: any length 0-80 over controls, ASCII punctuation, Latin and wide characters
    and surrogate halves, so the class is walked, not the hand-picked six."""
    import random

    rng = random.Random(1470)
    alphabet = [chr(c) for c in (*range(0x00, 0x80), *range(0xA0, 0x250), 0x2028, 0x3042, 0x1F600, 0xD800, 0xDFFF)]
    names = ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80))) for _ in range(300)]
    return [n for n in names if n not in _ALL_FIELDS]


@pytest.mark.parametrize("name", _AUTH_IDS)
def test_1470_o7_a_field_name_no_scheme_has_is_a_fault_whatever_it_holds(name):
    """Added to a fitting set of any scheme, each of base's six names outside the grammar and a seeded sample of others is
    an extra field: a non-empty fault list, never an exception. The wording for an unprintable name is not pinned. (O7, F5, G2)"""
    auth, _, fitting = SCHEMES[name]
    missed = [n for n in [*_BASE_NAMES, *_generated_names()] if not faults(auth, {**fitting, n: LONG})]
    assert missed == [], [repr(n) for n in missed[:10]]


@pytest.mark.parametrize(("field", "extra"), [("client_id", "c"), ("key_id", "k"), ("user", "u"), ("account", "a")])
def test_1470_o7_a_bearer_set_with_a_field_of_another_scheme_is_a_fault_naming_it(field, extra):
    """Base's rows: `{api_key: LONG, <field>: <short>}` is refused for each of `client_id`, `key_id`, `user`, `account`
    (another scheme's fields, or none's), the fault naming the field; the bearer set alone fits (control). (O7)"""
    auth, _, fitting = SCHEMES["bearer"]
    assert faults(auth, fitting) == []
    found = faults(auth, {**fitting, field: extra})
    assert found, field
    assert any(field in f for f in found), (field, found)


def test_1470_o7_an_oauth_set_with_a_field_it_does_not_read_is_a_fault_naming_it():
    """Base's row: `{client_id, client_secret: LONG, audience: "x"}` is refused, the fault naming `audience` (a field of no
    scheme is extra even when its value is short). (O7)"""
    auth, _, fitting = SCHEMES["oauth"]
    found = faults(auth, {**fitting, "audience": "x"})
    assert found
    assert any("audience" in f for f in found), found


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


def test_1470_g6_the_schemas_refusal_is_its_own_exception_type_apart_from_the_stores():
    """`kit.access.CredentialRefused` is an exception type of the credential schema, not one of the store's `RecordRefused`
    family, so the route maps the two by type. (P6, G6)"""
    from defender.kit.access import CredentialRefused
    from defender.system_records import RecordRefused

    assert issubclass(CredentialRefused, Exception)
    assert not issubclass(CredentialRefused, RecordRefused)


#: The schemes whose value is sent in a header as it is, so it must be ASCII (the design's schema: bearer, header).
_SENT_IN_A_HEADER = {"bearer", "header"}
#: Characters of each class a value rule tells apart: printable ASCII (`:` and space included), C0/DEL/C1 controls,
#: non-printable characters that are not controls (format, separators, unassigned), printable non-ASCII up to four bytes.
_POOLS = {
    "ascii": [chr(c) for c in range(0x20, 0x7F)],
    "control": [chr(c) for c in (*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0))],
    "unprintable": ["­", "​", " ", " ", " ", "　", "﻿", "\U000e0001", "͸"],
    "wide": ["é", "ж", "あ", "€", "😀", "\U00020000"],
}


def _expected_faulty(scheme: str, field: str, secret: bool, value: str) -> bool:
    """The design's value rules, as stated: empty, not printable, not ASCII where sent in a header, `:` in a basic
    username, or a secret shorter than the minimum counted in characters (code points)."""
    return (value == "" or not value.isprintable() or (scheme in _SENT_IN_A_HEADER and not value.isascii())
            or (scheme == "basic" and field == "username" and ":" in value) or (secret and len(value) < 16))


def _generated_values(rng) -> list[str]:
    """Values of length 0-24 (straddling the minimum), mostly printable ASCII with characters of every other class mixed
    in, plus one per class member at each length about the minimum (so each rule meets a value it alone refuses)."""
    values = []
    for _ in range(600):
        mix = rng.random()
        values.append("".join(rng.choice(_POOLS["ascii"] if rng.random() > mix * 0.3 else _POOLS[rng.choice(
            ["control", "unprintable", "wide"])]) for _ in range(rng.randint(0, 24))))
    for pool in _POOLS.values():
        for char in pool:
            for length in (1, 8, 15, 16, 17):
                values += [char * length, "k" * (length - 1) + char]
    return values


def test_1470_o7_check_credentials_faults_exactly_when_a_value_rule_says_for_any_text_in_any_field_of_any_scheme():
    """A generated sweep over every scheme, every field of its set and unicode text: `check_credentials` refuses exactly
    when the value is empty, not printable, not ASCII where sent in a header, a basic username holding `:`, or a secret
    shorter than the minimum in code points (bytes do not count). (O7, schema: every value rule)"""
    import random

    from defender.kit.access import SCHEMES as DECLARED, CredentialRefused, check_credentials

    assert {auth.scheme for auth, _, _ in SCHEMES.values()} == set(DECLARED), "premise: every scheme the kit declares"
    rng = random.Random(1470)
    values = _generated_values(rng)
    wrong, seen = [], set()
    for name, (auth, secret, fitting) in SCHEMES.items():
        for field, is_secret in secret.items():
            for value in values:
                try:
                    check_credentials(auth, {**fitting, field: value})
                    refused = False
                except CredentialRefused:
                    refused = True
                expected = _expected_faulty(auth.scheme, field, is_secret, value)
                seen.add(expected)
                if not value.isprintable() and not any(c in _POOLS["control"] for c in value):
                    seen.add(("unprintable, no control", name))
                if is_secret and len(value) < 16 <= len(value.encode("utf-8")) and not _expected_faulty(
                        auth.scheme, field, False, value):
                    seen.add(("short in code points only", name))
                if refused != expected:
                    wrong.append((name, field, ascii(value)))
    assert seen >= {True, False}, "premise: the sweep meets both outcomes"
    assert ("unprintable, no control", "oauth") in seen, "premise: an unprintable non-control value in an oauth set"
    assert {("short in code points only", n) for n in ("basic", "oauth")} <= seen, "premise: short in code points only"
    assert wrong == [], wrong[:10]
