#!/usr/bin/env python3
"""Defender entrypoint (PydanticAI engine) — investigate one alert end-to-end.

The Phase-A sibling of run.py: same CLI, same run-dir contract, same post-steps
(materialize → run → cross-check → enqueue-learning → visualize), but the
investigation is driven by the in-process PydanticAI driver
(`runtime/driver.py`) instead of a `claude -p` subprocess. run.py is left
untouched so both engines coexist for A/B.

Usage:
    python3 defender/run_pai.py <alert.json> [--run-id ID] [--no-learn] [--model M]

Requires ANTHROPIC_API_KEY (first-party Anthropic API) — unlike run.py, which
used the Claude Code subscription.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Re-exec into defender/.venv (which has pydantic-ai) if launched elsewhere —
# mirrors run.py. Gated on __main__ so importing this module never execvs.
_DEFENDER_DIR = Path(__file__).resolve().parent
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse  # noqa: E402
import asyncio  # noqa: E402
import json  # noqa: E402

import run as _run  # defender/ is sys.path[0] under __main__ → defender/run.py  # noqa: E402
from runtime import driver  # noqa: E402

DEFENDER_DIR = _DEFENDER_DIR


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("alert", type=Path, help="Path to alert.json fixture")
    p.add_argument("--run-id", default=None, help="Override auto-generated run id")
    p.add_argument("--no-learn", action="store_true", help="Skip enqueuing for learning")
    p.add_argument("--model", default=None, help="model id (overrides $DEFENDER_MODEL)")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    ns = parse_args(argv)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[run_pai] ERROR: ANTHROPIC_API_KEY is not set (the PydanticAI engine "
              "uses the first-party Anthropic API).", file=sys.stderr)
        return 2

    alert = ns.alert.resolve()
    run_dir = _run.materialize_run_dir(alert, ns.run_id)
    salt = json.loads((run_dir / "meta.json").read_text()).get("salt", "")
    model = ns.model or os.environ.get("DEFENDER_MODEL") or driver.DEFAULT_MODEL
    print(f"[run_pai] run_dir={run_dir} model={model}", file=sys.stderr)

    summary = asyncio.run(driver.run_investigation(
        alert_path=run_dir / "alert.json",
        run_dir=run_dir,
        run_id=run_dir.name,
        defender_dir=DEFENDER_DIR,
        salt=salt,
        model_name=model,
    ))
    out = str(summary.get("output") or "")
    print(f"[run_pai] done ({summary.get('requests')} model requests); "
          f"output: {out[:200]}", file=sys.stderr)

    print("[run_pai] artifacts:", file=sys.stderr)
    for entry in sorted(run_dir.iterdir()):
        sys.stderr.write(f"  {entry.name}\n")

    # Loud structural-integrity signal on the two live tables (no-op for a
    # no-gather run — slice 1).
    _run.cross_check_tables(run_dir)

    if ns.no_learn:
        print("[run_pai] --no-learn set; not enqueuing for learning", file=sys.stderr)
    else:
        _run.enqueue_learning(run_dir)
        print("[run_pai] enqueued for off-process learning", file=sys.stderr)

    _run.visualize(run_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
