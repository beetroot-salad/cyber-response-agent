"""The unit suite's split into CI shards (tests/_shard.py) and the durations that balance it."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from defender.tests import _shard

DEFENDER = Path(__file__).resolve().parents[2]
COSTS = {"tests/a.py": 9.0, "tests/b.py": 5.0, "tests/c.py": 4.0, "tests/d.py": 1.0, "tests/e.py": 1.0}


def test_every_file_lands_in_exactly_one_shard() -> None:
    nodeids = [f"{name}::test_{n}" for name in COSTS for n in range(3)]
    shards = [_shard.shard_of_files(nodeids, i, 3, weights=COSTS) for i in (1, 2, 3)]
    assert set().union(*shards) == set(COSTS)
    assert sum(len(s) for s in shards) == len(COSTS)


def test_the_heaviest_file_goes_first_to_the_lightest_shard() -> None:
    """Greedy by cost: 9 alone, then 5+4+..., so the two shards end 10 and 10."""
    plan = _shard.assign(COSTS, 2)
    loads = [sum(c for f, c in COSTS.items() if plan[f] == i) for i in (0, 1)]
    assert loads == [10.0, 10.0]
    assert plan == _shard.assign(dict(reversed(COSTS.items())), 2)  # order never matters


def test_a_file_missing_from_the_weights_is_costed_by_its_test_count() -> None:
    nodeids = ["tests/new.py::t1", "tests/new.py::t2", "tests/a.py::t"]
    one = _shard.shard_of_files(nodeids, 1, 2, weights={"tests/a.py": 0.01})
    assert one == {"tests/new.py"}  # 2 tests x 0.08 s outweighs a.py's 0.01 s


def test_merge_keeps_the_larger_cost_rounded_and_sorted() -> None:
    table = _shard.merge([{"tests/b.py": 2.04, "tests/a.py": 1.0}, {"tests/b.py": 3.06}])
    assert list(table.items()) == [("tests/a.py", 1.0), ("tests/b.py", 3.1)]


def test_shard_durations_writes_each_files_worker_seconds(tmp_path: Path) -> None:
    """A real run with `--shard-durations` names the file it ran, keyed as the weights are."""
    out = tmp_path / "durations.json"
    here = Path(__file__).relative_to(DEFENDER).as_posix()
    subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:xdist", here,
         "-k", "merge_keeps", "--shard-durations", str(out)],
        cwd=DEFENDER, check=True, capture_output=True, text=True)
    written = json.loads(out.read_text(encoding="utf-8"))
    assert list(written) == [here]
    assert written[here] > 0
