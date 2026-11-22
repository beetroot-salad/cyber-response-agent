"""#1546 S0: the evidence-store test machinery behaves as real Garage and OpenBao do (SSE-C, wrapping)."""
from __future__ import annotations

import pytest

from defender.tests.support.evidence._evidence1546 import (  # noqa: F401 — fixtures
    evidence_keys,
    garage,
    new_sse_key,
)
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401


@pytest.mark.garage
def test_sse_c_put_needs_the_key_to_read_and_is_listed_and_isolated(garage):
    """Garage takes a single SSE-C PUT, refuses a keyless or wrong-key read, lists by prefix."""
    key, other = garage.key("a/obj"), new_sse_key()
    sse = new_sse_key()
    garage.put(key, b"secret bytes", sse_key=sse)
    assert garage.get(key, sse_key=sse).content == b"secret bytes"
    assert garage.get(key).status_code == 400
    assert garage.get(key, sse_key=other).status_code in (400, 403)
    assert garage.head(key, sse_key=sse).status_code == 200
    assert garage.head(key, sse_key=sse).headers["content-length"] == str(len(b"secret bytes"))
    assert garage.list(garage.key("a/")) == [key]
    assert garage.list(garage.key("zzz/")) == []  # positive control: the prefix filter filters
    garage.delete(key)
    assert garage.head(key).status_code == 404


@pytest.mark.garage
def test_plant_raw_object_and_tests_do_not_see_each_other(garage):
    """A raw planted object reads back keyless; another test's prefix is separate; teardown clears it."""
    tenant = "00000000-0000-0000-0000-00000000aaaa"
    key = garage.tenant_prefix(tenant) + "investigation/i/c/bundle"
    garage.put(key, b"raw")
    assert garage.get(key).content == b"raw"
    assert garage.list(garage.tenant_prefix(tenant)) == [key]
    assert garage.list(f"s0-{garage.tag}/") == []


@pytest.mark.garage
def test_teardown_removed_the_previous_tests_objects(garage):
    """Objects the previous test planted are gone (the fixture's cleanup)."""
    assert garage.list("t/00000000-0000-0000-0000-00000000aaaa/") == []


@pytest.mark.garage
@pytest.mark.openbao
def test_datakey_wraps_and_unwraps_and_is_per_tenant(garage, evidence_keys):
    """A datakey from `evidence-<T>` opens an SSE-C object; only its own tenant's key unwraps it (A-O5)."""
    t1, t2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
    evidence_keys.make(t1)
    evidence_keys.make(t2)
    dk = evidence_keys.datakey(t1)
    assert len(dk.plaintext) == 32 and dk.wrapped.startswith("vault:v1:")
    key = garage.key("o")
    garage.put(key, b"payload", sse_key=dk.plaintext)
    assert garage.get(key, sse_key=evidence_keys.unwrap(t1, dk.wrapped)).content == b"payload"
    with pytest.raises(AssertionError):  # the other tenant's key cannot unwrap it
        evidence_keys.unwrap(t2, dk.wrapped)
