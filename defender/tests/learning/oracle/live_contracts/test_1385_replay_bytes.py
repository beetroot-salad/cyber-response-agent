"""A recorded call is replayed as the source received it (#1385 O7, H6).

The platform stamps a reply's time itself and no layer rewrites a recording: whatever a recorded
payload holds — keys the adapters once wrote (`captured_at`, `drift`, `as_of`) among them, at any
depth — comes back byte for byte.
"""
from __future__ import annotations

import random
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.learning.oracle.live_contracts import _spec1224 as S  # noqa: E402

SEED = 1385
#: The keys an older adapter or pre-flight stamped into what it recorded or served.
STAMPS = ("captured_at", "drift", "as_of")
POSITIONS = ("top", "under a key", "in a row", "in a row of a nested table", "in a list of lists")


def _value(rng: random.Random) -> Any:
    return rng.choice(["2026-07-28T16:18:45Z", "2026-07-28", 1785252120, None, "", [], {},
                       {"status": "drifted", "calls": [1, 2]}, ["a", {"b": None}], False])


def _placed(rng: random.Random, key: str, position: str) -> dict:
    """A payload holding `key` at `position`, beside ordinary content."""
    stamp = {key: _value(rng)}
    row = {"user": "alice", "event_id": f"e-{rng.randint(100, 999)}", **stamp}
    if position == "top":
        return {"rows": [{"user": "alice", "event_id": "e-100"}], **stamp}
    if position == "under a key":
        return {"rows": [], "meta": {"source": "idp", "inner": {"note": "x", **stamp}}}
    if position == "in a row":
        return {"rows": [{"user": "bob", "event_id": "e-101"}, row]}
    if position == "in a row of a nested table":
        return {"result": {"pages": [{"rows": [row]}]}, "total": 1}
    return {"values": [["e-102", [row, [stamp]]]], "columns": [{"name": "id", "type": "keyword"}]}


def _tree(rng: random.Random, depth: int) -> Any:
    if depth == 0 or rng.random() < 0.25:
        return _value(rng)
    if rng.random() < 0.6:
        keys = rng.sample([*STAMPS, "rows", "host", "meta", "items", "ts"], rng.randint(1, 4))
        return {k: _tree(rng, depth - 1) for k in keys}
    return [_tree(rng, depth - 1) for _ in range(rng.randint(0, 3))]


def test_1385_a_recorded_call_is_replayed_byte_for_byte_whatever_keys_it_holds(tmp_path):
    """In a world without facts every recorded payload — each of `captured_at`, `drift` and
    `as_of` placed at the top, under a key, in a row, in a nested table and among lists, and
    generated trees of such keys — is served and rowed exactly as recorded (O7, H6)."""
    rng = random.Random(SEED)
    payloads: list[Any] = [_placed(rng, key, position)
                           for key in STAMPS for position in POSITIONS]
    payloads += [{"wrapper": _tree(rng, 4), **{k: _value(rng) for k in rng.sample(STAMPS, 2)}}
                 for _ in range(20)]
    asked = [S.query_params(f"user:rec{n}") for n in range(len(payloads))]
    est = S.estate(tmp_path)
    ep = S.episode_v2(tmp_path, base_rows=[S.captured("idp", "query", params, payload)
                                           for params, payload in zip(asked, payloads, strict=True)])
    reg = S.sandboxed_registry(ep, "a", est)
    ctx = est.ctx(tmp_path / "run")

    got = [S.call(reg, "idp", "query", ctx, **params) for params in asked]

    assert est.calls("idp", "query") == [], "a recorded call was read live"
    rows = S.ledger_rows(ep, "a")
    recorded = [S.captured("idp", "query", params, payload)["payload_text"]
                for params, payload in zip(asked, payloads, strict=True)]
    assert [r["payload_text"] for r in rows] == recorded, (
        "a replayed payload's bytes differ from the recording's")
    assert [r["source"] for r in rows] == [S.PASSTHROUGH] * len(payloads), rows
    assert got == payloads, "a replayed payload differs from the recording's"
