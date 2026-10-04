"""`--shard I/N` splits a run into parts that together run every test file exactly once."""
from __future__ import annotations

import pytest

from defender.tests import _shard

NODEIDS = [f"tests/test_{name}.py::t{i}" for name, n in
           (("a", 3), ("b", 1), ("c", 2), ("d", 5), ("e", 1)) for i in range(n)]


@pytest.mark.parametrize("count", [1, 2, 3, 5])
def test_the_shards_together_run_every_file_exactly_once(count):
    files = {_shard.file_of(n) for n in NODEIDS}
    parts = [_shard.shard_of_files(NODEIDS, i, count, weights={}) for i in range(1, count + 1)]
    assert sorted(f for part in parts for f in part) == sorted(files)


def test_the_split_is_the_same_whatever_order_the_tests_were_collected_in():
    weights = {"tests/test_d.py": 9.0, "tests/test_a.py": 4.0}
    forward = _shard.shard_of_files(NODEIDS, 1, 2, weights)
    assert forward == _shard.shard_of_files(NODEIDS[::-1], 1, 2, weights)


def test_a_heavy_file_does_not_share_a_shard_with_the_next_heaviest():
    costs = {"x": 10.0, "y": 9.0, "z": 1.0, "w": 1.0}
    plan = _shard.assign(costs, 2)
    assert plan["x"] != plan["y"]
    loads = [sum(c for f, c in costs.items() if plan[f] == s) for s in (0, 1)]
    assert abs(loads[0] - loads[1]) <= 2.0


def test_a_file_the_table_has_not_seen_is_still_placed():
    assert "tests/test_new.py" in set().union(*(
        _shard.shard_of_files(["tests/test_new.py::t"], i, 2, weights={}) for i in (1, 2)))


@pytest.mark.parametrize("spec", ["0/2", "3/2", "x", "1/", "1-2"])
def test_a_malformed_shard_is_refused(spec):
    with pytest.raises(ValueError, match="--shard"):
        _shard.parse_shard(spec)
