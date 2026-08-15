"""Re-measure the #872 byte gate under BOTH JSON rulers (fork f3).

`c5`/`c6`/`c7` in the intent+design doc measured the JSON side with `json.dumps`
DEFAULTS — 2-byte separators and `ensure_ascii`. That is not what the model
receives: pydantic-ai serializes a non-`str` tool return with
`tool_return_ta.dump_json(value)` (`ToolReturnPart.model_response_str`), i.e.
pydantic-core's compact raw-UTF-8 dump, which `pydantic_core.to_json` reproduces
byte for byte. The fat ruler inflates the baseline and therefore over-reads every
win; the choice moves the gate's verdict, so it is measured here rather than
argued.

Two arms:

  corpus   — the recorded `gather_raw/` payloads (>=500 B, ES|QL shape excluded),
             the population `c5` set the 15% bar from. Reports, per ruler and per
             bar, how many payloads clear and how many of THOSE did not reach
             TOON's tabular form (a clearing non-tabular payload is the gate
             LEAKING: it is cheaper without being uniform-tabular, which is the
             failure mode the bar exists to exclude).
  fixtures  — the 40 committed fixtures. `owned` is the columnar payload as our
             adapters emit it; `unowned` is the same data re-zipped to dict rows
             by `build_fixtures.toon_input`, standing in for a foreign source.
             The bar has to sit in the gap between them.

The corpus arm needs `/tmp/defender-runs` (ephemeral, one box). The fixtures arm
is self-contained and is the one a test may pin: every fixture embeds its full
payload, and `toon_input` is IMPORTED rather than re-derived, because the
published unowned figures depend on it keeping the full `columns` dicts on the
baseline side.

    python experiments/toon-vs-columnar-kimi/measure_rulers.py
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import statistics
import sys
from collections.abc import Callable
from typing import Any

import toons
from pydantic_core import to_json

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from build_fixtures import toon_input  # noqa: E402 — the sweep's OWN re-zip, imported not reimplemented

#: The header TOON emits once a list of uniform dicts reaches its tabular form.
TABULAR = re.compile(r"\[\d+\]\{[^}]*\}\s*:")

#: The two rulers. `wire` is what the model is actually charged for.
RULERS: dict[str, Callable[[Any], int]] = {
    "json.dumps": lambda v: len(json.dumps(v).encode()),
    "wire/dump_json": lambda v: len(to_json(v)),
}

#: bar -> ratio. 15% is the shipped bar; 10% is the alternative `c5` rejected.
BARS = {"10%": 0.90, "15%": 0.85}


def toon_bytes(value: Any) -> int:
    return len(toons.dumps(value).encode())


def is_tabular(value: Any) -> bool:
    try:
        return bool(TABULAR.search(toons.dumps(value)))
    except Exception:
        return False


def load_corpus(base: pathlib.Path) -> list[tuple[pathlib.Path, Any]]:
    """Recorded payloads >=500 B, ES|QL (`columns`+`values`) excluded — c5's population."""
    out = []
    for path in sorted(base.glob("*/gather_raw/*/*.json")):
        raw = path.read_bytes()
        if len(raw) < 500:
            continue
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        if isinstance(value, dict) and "columns" in value and "values" in value:
            continue
        out.append((path, value))
    return out


def report_corpus(rows: list[tuple[pathlib.Path, Any]]) -> None:
    print(f"corpus: n={len(rows)}")
    # Encoded ONCE per payload. `toons.dumps` is the expensive call here and the loop below
    # asks for it four times (two rulers x two bars) plus once more for `is_tabular`, over a
    # corpus of whole recorded payloads — five encodes of the same bytes to print one table.
    measured = [(p, v, toon_bytes(v), is_tabular(v)) for p, v in rows]
    for ruler, size in RULERS.items():
        for bar, ratio in BARS.items():
            clearing = [(p, tab) for p, v, tb, tab in measured if tb <= ratio * size(v)]
            leaks = [p for p, tab in clearing if not tab]
            print(
                f"  ruler={ruler:15s} bar={bar:4s} clear={len(clearing):3d}/{len(rows)}"
                f"  LEAKS(non-tabular)={len(leaks)}"
                + ("".join(f"\n      {p}" for p in leaks) if leaks else "")
            )


def report_fixtures(name: str, values: list[Any]) -> None:
    for ruler, size in RULERS.items():
        deltas = sorted((toon_bytes(v) - size(v)) / size(v) * 100 for v in values)
        clears = {
            bar: sum(1 for v in values if toon_bytes(v) <= ratio * size(v))
            for bar, ratio in BARS.items()
        }
        print(
            f"  {name:8s} ruler={ruler:15s} best={deltas[0]:+.1f}% median={statistics.median(deltas):+.1f}%"
            f" worst={deltas[-1]:+.1f}%  " + "  ".join(f"clear{b}={c}/{len(values)}" for b, c in clears.items())
        )


def main() -> int:
    # `$DEFENDER_RUNS_BASE` first: the devcontainer is REQUIRED to override the default
    # (`defender/CLAUDE.md` — the bind source the box needs is not `/tmp`), so a hardcoded
    # `/tmp/defender-runs` reports "corpus: SKIPPED" on the one machine this sweep is run on
    # even with a full corpus of recorded payloads sitting under the configured base.
    runs = pathlib.Path(os.environ.get("DEFENDER_RUNS_BASE") or "/tmp/defender-runs")
    if runs.is_dir():
        report_corpus(load_corpus(runs))
    else:
        print(f"corpus: SKIPPED — {runs} absent (ephemeral; the fixtures arm below is self-contained)")

    payloads = [json.loads(p.read_text())["payload"] for p in sorted((HERE / "fixtures").glob("fx-*.json"))]
    print(f"fixtures: n={len(payloads)}")
    report_fixtures("owned", payloads)
    report_fixtures("unowned", [toon_input(v) for v in payloads])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
