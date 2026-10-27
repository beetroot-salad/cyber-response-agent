"""Split one pytest run into N shards by whole test files, balanced by what each file cost.

The costs are worker-seconds per file, measured: `--shard-durations PATH` makes a run write
what each of its files took, CI uploads that file from every shard, and
`python -m defender.tests._shard merge <file>...` rebuilds the weights table from them."""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
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


def merge(measured: Iterable[Mapping[str, float]]) -> dict[str, float]:
    """One weights table from several runs' per-file durations: a file measured twice (it ran in
    two of them) keeps its larger cost. Rounded to a tenth of a second, sorted by file."""
    table: dict[str, float] = {}
    for durations in measured:
        for name, seconds in durations.items():
            table[name] = max(table.get(name, 0.0), seconds)
    return {name: round(table[name], 1) for name in sorted(table)}


def main(argv: Sequence[str]) -> int:
    if len(argv) < 2 or argv[0] != "merge":  # noqa: PLR2004 — `merge` and at least one file
        print("usage: python -m defender.tests._shard merge <durations.json>...", file=sys.stderr)
        return 2
    table = merge(json.loads(Path(name).read_text(encoding="utf-8")) for name in argv[1:])
    WEIGHTS.write_text(json.dumps(table, indent=1) + "\n", encoding="utf-8")
    print(f"{WEIGHTS}: {len(table)} files, {sum(table.values()):.0f} worker-seconds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
