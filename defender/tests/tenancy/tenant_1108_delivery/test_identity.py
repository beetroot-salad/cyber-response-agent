"""Vault identity binding, lifetime, refresh and refusal behavior."""

from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid


import pytest

from defender.learning.author.version_control import ForgejoAuthError, ForgejoIdentity
from ._identity import AUDIENCE, ISSUER, NOW, VaultHTTP, token


def test_cached_identity_refreshes_before_an_operation_outlives_it():
    vault = VaultHTTP()
    identity = vault.identity()
    first = identity.token(min_validity=150)
    vault.now += 449
    assert identity.token(min_validity=150) == first
    assert len(vault.calls) == 1
    vault.now += 1
    second = identity.token(min_validity=150)
    assert second != first
    assert len(vault.calls) == 2
    assert vault.calls[0].method == "GET"
    assert first not in repr(identity)
    assert second not in repr(identity)


@pytest.mark.parametrize(
    "claims",
    [
        {"tenant_id": fixture_uuid("tenant:other")},
        {"aud": "other"},
        {"aud": [AUDIENCE, "other"]},
        {"iss": "https://other.test"},
        {"exp": NOW},
        {"exp": NOW + 30},
        {"iat": NOW + 31},
        {"nbf": NOW + 31},
        {"exp": NOW + 601},
        {"exp": None},
        {"exp": True},
        {"iat": "yesterday"},
        {"exp": float("inf")},
        {"iat": NOW - 601},
    ],
)
def test_incorrect_binding_or_lifetime_is_refused(claims):
    vault = VaultHTTP(value=token(**claims))
    with pytest.raises(ForgejoAuthError):
        vault.identity().token()


@pytest.mark.parametrize("value", ["not-a-jwt", "a.b.c", "a.W10.c", "a.eyJhIjoxfQ.c"])
def test_malformed_identity_is_refused(value):
    with pytest.raises(ForgejoAuthError):
        VaultHTTP(value=value).identity().token()


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (403, {"secret": "do-not-log"}),
        (302, {"location": "https://elsewhere.test"}),
        (200, {}),
        (200, {"data": []}),
        (200, {"data": {"token": 1}}),
    ],
)
def test_vault_failure_does_not_expose_response_content(status, body):
    vault = VaultHTTP()
    vault.status, vault.body = status, body
    with pytest.raises(ForgejoAuthError) as error:
        vault.identity().token()
    assert "do-not-log" not in str(error.value)
    assert len(vault.calls) == 1


@pytest.mark.parametrize("budget", [-1, 600, float("inf"), float("nan")])
def test_unbounded_operation_is_refused_before_vault(budget):
    vault = VaultHTTP()
    with pytest.raises(ForgejoAuthError):
        vault.identity().token(min_validity=budget)
    assert vault.calls == []


@pytest.mark.parametrize(
    ("issuer", "role"),
    [
        ("http://vault.test", f"tenant-{fixture_uuid('tenant:blue')}"),
        (ISSUER + "/", f"tenant-{fixture_uuid('tenant:blue')}"),
        (ISSUER, "../other"),
        ("https://user:secret@vault.test", f"tenant-{fixture_uuid('tenant:blue')}"),
    ],
)
def test_identity_configuration_is_explicit_and_https(issuer, role):
    with pytest.raises(ForgejoAuthError):
        ForgejoIdentity(
            tenant_id=fixture_uuid("tenant:blue"),
            issuer=issuer,
            role=role,
            audience=AUDIENCE,
            client=VaultHTTP().client,
        )


def test_vault_request_time_counts_against_remaining_token_lifetime():
    import httpx
    vault = VaultHTTP(value=token(ttl=151))

    def reply(request):
        response = vault.reply(request)
        vault.now += 2
        return response

    with httpx.Client(transport=httpx.MockTransport(reply)) as client:
        identity = ForgejoIdentity(tenant_id=fixture_uuid("tenant:blue"), issuer=ISSUER, role=f"tenant-{fixture_uuid('tenant:blue')}",
                                  audience=AUDIENCE, client=client, clock=lambda: vault.now)
        with pytest.raises(ForgejoAuthError, match="expired"):
            identity.token(min_validity=150)
