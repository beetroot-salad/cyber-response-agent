"""Regressions for #1224's host checks and rate limiter, found by the claims adversary.

- D: a `counts` entry with group "*" and base 0 laundered an arbitrary unclaimed added row
  past check 1 — any row carrying a scalar equal to the entry's `served` passed as a bucket.
- C: check 1's coverage of claimed-but-unserved forged rows summed `added` over every count,
  so a count for an unrelated group hid a forged row missing from the answer.
- Limiter: a positive finite rate whose reciprocal overflows (5e-324) made every second
  permit `sleep(inf)`, and `True` was accepted as a rate of 1.
"""
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


def _check(base, served, claim, store=None) -> list[str]:
    return check_submission(base, served, claim, world=WORLD, store=store or _store(),
                            real_data=RealData())


def _count(group, *, base: int, added: int = 0, removed: int = 0) -> dict:
    return {"group": group, "base": base, "added": added, "removed": removed,
            "served": base + added - removed}


# --- D: a "*" count is no bucket ------------------------------------------------------------


def test_a_star_count_does_not_launder_an_unclaimed_added_row():
    base = {"rows": [{"a": "x", "n": 2}]}
    served = {"rows": [{"a": "x", "n": 2}, {"a": "EVIL", "n": 1}]}
    failures = _check(base, served, {"counts": [_count("*", base=0, added=1)]})
    assert any(f.startswith("check 1") and "unclaimed row was added" in f for f in failures), failures


def test_a_bucket_count_claims_only_a_row_carrying_its_group():
    base = {"rows": [{"a": "x", "n": 2}]}
    served = {"rows": [{"a": "x", "n": 2}, {"a": "EVIL", "n": 1}]}
    failures = _check(base, served, {"counts": [_count("db-1", base=0, added=1)]})
    assert any("unclaimed row was added" in f for f in failures), failures


def test_one_bucket_count_claims_one_new_bucket_row():
    base = {"buckets": [{"key": "web-1", "n": 1}]}
    served = {"buckets": [{"key": "web-1", "n": 1}, {"key": "db-1", "n": 1},
                          {"key": "db-1", "n": 1, "x": "dup"}]}
    failures = _check(base, served, {"counts": [_count("db-1", base=0, added=1)]})
    assert sum("unclaimed row was added" in f for f in failures) == 1, failures


def test_control_a_new_bucket_row_carrying_its_group_is_claimed():
    base = {"buckets": [{"key": "web-1", "n": 1}]}
    served = {"buckets": [{"key": "web-1", "n": 1}, {"key": "db-1", "n": 1}]}
    assert _check(base, served, {"counts": [_count("db-1", base=0, added=1)]}) == []


# --- C: coverage is per group ---------------------------------------------------------------


def test_an_unrelated_group_count_does_not_cover_an_unserved_forged_row():
    store = _store(_forged("f1", {"a": 1}))
    claim = {"added": [{"forged_id": "f1", "fact_id": "F"}],
             "counts": [_count("g", base=0, added=5)]}
    failures = _check({"rows": []}, {"rows": []}, claim, store)
    assert any(f.startswith("check 1") and "['f1'] are not in the served answer" in f
               for f in failures), failures


def test_a_group_count_covers_no_more_rows_than_it_adds():
    store = _store({**_forged("f1", {"host": "db-1", "e": 1}),
                    **_forged("f2", {"host": "db-1", "e": 2})})
    claim = {"added": [{"forged_id": "f1", "fact_id": "F"}, {"forged_id": "f2", "fact_id": "F"}],
             "counts": [_count("db-1", base=3, added=1), _count("web-1", base=0, added=1)]}
    failures = _check({"counts": {"db-1": 3}}, {"counts": {"db-1": 4}}, claim, store)
    assert any("are not in the served answer" in f for f in failures), failures


def test_control_each_group_count_covers_the_forged_row_carrying_its_group():
    store = _store({**_forged("f1", {"host": "web-1", "e": 1}),
                    **_forged("f2", {"host": "db-1", "e": 2})})
    claim = {"added": [{"forged_id": "f1", "fact_id": "F"}, {"forged_id": "f2", "fact_id": "F"}],
             "counts": [_count("web-1", base=3, added=1), _count("db-1", base=0, added=1)]}
    base = {"counts": [{"host": "web-1", "count": 3}]}
    served = {"counts": [{"host": "web-1", "count": 4}, {"host": "db-1", "count": 1}]}
    assert _check(base, served, claim, store) == []


# --- Limiter --------------------------------------------------------------------------------


@pytest.mark.parametrize("rate", [5e-324, 1e-310, True])
def test_the_limiter_refuses_a_rate_it_cannot_space_or_a_bool(rate):
    slept: list[float] = []
    with pytest.raises(ValueError, match="rate"):
        RateLimiter(rate, clock=lambda: 0.0, sleep=slept.append)
    assert slept == []
