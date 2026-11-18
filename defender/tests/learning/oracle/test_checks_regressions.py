"""Regressions for #1224's host checks and rate limiter: a forged row the patch adds must be one
the host staged and must stay in the served answer, and unspaceable limiter rates."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from defender.learning.branch.estate.checks import CheckStore, RealData, check_submission
from defender.learning.branch.estate.limiter import RateLimiter


def _store(staged: dict | None = None) -> CheckStore:
    return CheckStore(frozen={}, staged=staged or {}, facts={}, rerun=lambda *a: {})


def _forged(fid: str, row: dict) -> dict:
    return {fid: {"forged_id": fid, "system": "s", "row": row, "fact_id": "F"}}


WORLD = SimpleNamespace(facts=[SimpleNamespace(fact_id="F")])


def _check(base, patch, store=None) -> list[str]:
    return check_submission(base, {"patch": patch, "entity_refs": [], "proofs": []},
                            world=WORLD, store=store or _store(), real_data=RealData())


def _add(path: str, row: dict, fid: str) -> dict:
    return {"op": "add", "path": path, "value": row, "forged_id": fid, "fact_id": "F"}


# --- an add is one staged forged row ----------------------------------------------------------


def test_an_add_naming_no_staged_forged_row_is_an_unclaimed_row():
    base = {"rows": [{"a": "x", "n": 2}]}
    failures = _check(base, [_add("/rows/-", {"a": "EVIL", "n": 1}, "f1")])
    assert any(f.startswith("check 1") and "'f1' names no forged row" in f
               for f in failures), failures
    assert any(f.startswith("check 1") and "that is no forged row" in f
               for f in failures), failures


def test_control_an_add_of_the_staged_forged_row_passes():
    store = _store(_forged("f1", {"a": "y", "n": 1}))
    base = {"rows": [{"a": "x", "n": 2}]}
    assert _check(base, [_add("/rows/-", {"a": "y", "n": 1}, "f1")], store) == []


def test_an_add_whose_value_is_not_its_forged_row_is_refused():
    store = _store(_forged("f1", {"a": "y", "n": 1}))
    base = {"rows": [{"a": "x", "n": 2}]}
    failures = _check(base, [_add("/rows/-", {"a": "EVIL", "n": 1}, "f1")], store)
    assert any(f.startswith("check 1") and "that is no forged row" in f
               for f in failures), failures
    assert any("forged row 'f1' is not in the served answer" in f for f in failures), failures


# --- an added forged row stays served -------------------------------------------------------


def test_a_forged_row_the_patch_adds_then_removes_is_not_served():
    store = _store(_forged("f1", {"a": 1}))
    patch = [_add("/rows/-", {"a": 1}, "f1"), {"op": "remove", "path": "/rows/0", "fact_id": "F"}]
    failures = _check({"rows": []}, patch, store)
    assert any(f.startswith("check 1") and "forged row 'f1' is not in the served answer" in f
               for f in failures), failures


def test_control_each_forged_row_the_patch_adds_is_served():
    store = _store({**_forged("f1", {"host": "web-1", "count": 1}),
                    **_forged("f2", {"host": "db-1", "count": 1})})
    base = {"counts": [{"host": "web-1", "count": 3}]}
    patch = [{"op": "replace", "path": "/counts/0/count", "value": 4, "fact_id": "F"},
             _add("/counts/-", {"host": "db-1", "count": 1}, "f2"),
             _add("/counts/-", {"host": "web-1", "count": 1}, "f1")]
    assert _check(base, patch, store) == []


# --- Limiter --------------------------------------------------------------------------------


@pytest.mark.parametrize("rate", [5e-324, 1e-310, True])
def test_the_limiter_refuses_a_rate_it_cannot_space_or_a_bool(rate):
    slept: list[float] = []
    with pytest.raises(ValueError, match="rate"):
        RateLimiter(rate, clock=lambda: 0.0, sleep=slept.append)
    assert slept == []
