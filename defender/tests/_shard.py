"""Split one pytest run into N shards by whole test files, balanced by what each file cost.

CI runs the suite as parallel jobs, each taking `--shard I/N`. A shard keeps whole files because
the run uses `--dist loadfile` (a file's module-scoped fixtures and per-file tmp repos stay on one
worker), and a file's cost is read from `_shard_weights.json` — seconds of one worker's time per
file, measured from a CI run. A file the table has not seen (new, or under 0.3s) costs
`DEFAULT_SECONDS_PER_TEST` per collected test, so a new file lands somewhere reasonable and the
table can go stale without a shard going missing. The split depends only on the set of collected
files and the table, so every shard — and every xdist worker inside it — computes the same one.
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path

WEIGHTS = Path(__file__).with_name("_shard_weights.json")
#: Seconds of one worker per test for a file the weights table does not name: the suite's average.
DEFAULT_SECONDS_PER_TEST = 0.08


def parse_shard(spec: str) -> tuple[int, int]:
    """`"2/3"` -> (2, 3): shard 2 of 3, counted from 1."""
    try:
        index, count = (int(part) for part in spec.split("/"))
    except ValueError:
        raise ValueError(f"--shard wants I/N (e.g. 1/2), got {spec!r}") from None
    if not 1 <= index <= count:
        raise ValueError(f"--shard {spec!r}: I must be between 1 and N")
    return index, count


def assign(cost_by_file: Mapping[str, float], count: int) -> dict[str, int]:
    """Each file's shard (0-based): heaviest first, each to the lightest shard so far, ties to the
    lowest-numbered shard and the lexically first file, so the answer never depends on order."""
    load = [0.0] * count
    out: dict[str, int] = {}
    for name, cost in sorted(cost_by_file.items(), key=lambda kv: (-kv[1], kv[0])):
        shard = min(range(count), key=lambda i: (load[i], i))
        out[name] = shard
        load[shard] += cost
    return out


def file_of(nodeid: str) -> str:
    return nodeid.split("::", 1)[0]


def shard_of_files(nodeids: Sequence[str], index: int, count: int,
                   weights: Mapping[str, float] | None = None) -> set[str]:
    """The files shard `index` (1-based) of `count` runs, among those `nodeids` come from."""
    table = json.loads(WEIGHTS.read_text(encoding="utf-8")) if weights is None else weights
    tests: dict[str, int] = defaultdict(int)
    for nodeid in nodeids:
        tests[file_of(nodeid)] += 1
    cost = {f: table.get(f, DEFAULT_SECONDS_PER_TEST * n) for f, n in tests.items()}
    return {f for f, shard in assign(cost, count).items() if shard == index - 1}
