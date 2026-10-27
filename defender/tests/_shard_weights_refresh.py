"""Rewrite `_shard_weights.json` from one CI run's two `test (shard I/2)` job logs (#1333).

    python3 defender/tests/_shard_weights_refresh.py <run id>

The job runs `pytest -v -n auto --dist loadfile`, so each worker runs a file's tests back to
back and logs every result with a timestamp. A test's cost is its result's timestamp minus the
previous result on the same worker (the first one is timed from the session start); a file's
cost is the sum over its tests. Use a run in which both shards finished their pytest step.
`gh run view --log` cuts a long log short, so the logs come from the jobs' log endpoint."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from defender.tests._shard import WEIGHTS

_LINE = re.compile(r"(\S+Z) (.*)$")
_SESSION = re.compile(r"\d+ workers \[\d+ items\]")
_RESULT = re.compile(r"\[(gw\d+)\] \[\s*\d+%\] \w+ (tests/[^:]+)::")


def file_costs(lines: Iterable[str]) -> dict[str, float]:
    """Worker seconds per test file, from one job log's lines."""
    cost: dict[str, float] = defaultdict(float)
    last: dict[str, datetime] = {}
    start: datetime | None = None
    for line in lines:
        m = _LINE.match(line.rstrip("\n").lstrip("﻿"))
        if not m:
            continue
        at = datetime.fromisoformat(m.group(1)[:26])
        if start is None and _SESSION.search(m.group(2)):
            start = at
        result = _RESULT.match(m.group(2))
        if result and start is not None:
            worker, name = result.groups()
            cost[name] += (at - last.get(worker, start)).total_seconds()
            last[worker] = at
    return dict(cost)


def _gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    jobs = json.loads(_gh("run", "view", argv[0], "--json", "jobs"))["jobs"]
    shards = [j["databaseId"] for j in jobs if j["name"].startswith("test (shard ")]
    if len(shards) != 2:
        print(f"run {argv[0]}: expected two test shards, found {len(shards)}", file=sys.stderr)
        return 1
    repo = _gh("repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner").strip()
    table: dict[str, float] = {}
    for job in shards:
        table.update(file_costs(_gh("api", f"repos/{repo}/actions/jobs/{job}/logs").splitlines()))
    rounded = {name: round(cost, 1) for name, cost in sorted(table.items())}
    Path(WEIGHTS).write_text(json.dumps(rounded, indent=1) + "\n", encoding="utf-8")
    print(f"{WEIGHTS}: {len(rounded)} files, {sum(rounded.values()):.0f} worker seconds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
