#!/usr/bin/env python3
"""Defender entrypoint — investigate one alert end-to-end.

The investigation is driven by the in-process PydanticAI driver
(`runtime/driver.py`): materialize the run dir → run → cross-check the two live
tables → enqueue learning → visualize. Run-dir + post-step helpers are shared
via `run_common.py`.

Usage:
    python3 defender/run.py <alert.json> [--run-id ID] [--no-learn] [--model M]

Billing / credentials: the engine calls the first-party Anthropic REST API, so
it needs a real billable API key. Inside a Claude Code session the *ambient*
ANTHROPIC_API_KEY is the subscription credential (it 401s against the REST API),
so we source our own billable key from a `.env` file (`resolve_first_party_key`),
which takes precedence over the ambient value.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_DEFENDER_DIR = Path(__file__).resolve().parent
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse  # noqa: E402
import asyncio  # noqa: E402
import contextlib  # noqa: E402

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import run_common as _run  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime import providers  # noqa: E402

DEFENDER_DIR = _DEFENDER_DIR


from defender._first_party_key import (  # noqa: E402,F401
    _read_env_key,
    resolve_first_party_key,
)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("alert", type=Path, help="Path to alert.json fixture")
    p.add_argument("--run-id", default=None,
                   help="Pin the run id for a named A/B or live run (learning-loop "
                        "commits reference it) instead of the auto timestamp id; a "
                        "collision with an existing run dir is rejected by materialize_run_dir")
    p.add_argument("--no-learn", action="store_true", help="Skip enqueuing for learning")
    p.add_argument("--update-ticket", action="store_true",
                   help="Write/close a case-history ticket for this alert (default off)")
    p.add_argument("--model", default=None,
                   help="model id (overrides $DEFENDER_MODEL); e.g. a claude-* id, "
                        "or 'glm-5.2' / 'fireworks:<id>' for the Fireworks-served GLM")
    return p.parse_args(argv)


def _source_one_provider_key(prov: providers.Provider) -> int:
    var = prov.api_key_var
    key, src = resolve_first_party_key(var=var)
    if key:
        os.environ[var] = key
        note = " (overrides the ambient subscription credential)" if prov.id == "anthropic" else ""
        print(f"[run.py] {var} sourced from {src}{note}", file=sys.stderr)
        return 0
    if os.environ.get(var):
        if prov.id == "anthropic":
            print("[run.py] WARNING: no .env key found; using the ambient "
                  "ANTHROPIC_API_KEY — inside a Claude Code session this is the "
                  "subscription credential and will 401 against the first-party API.",
                  file=sys.stderr)
        else:
            print(f"[run.py] using the ambient {var} for the {prov.id} model",
                  file=sys.stderr)
        return 0
    if prov.id == "anthropic":
        print("[run.py] ERROR: no first-party ANTHROPIC_API_KEY — set it in "
              "<repo>/.env or $DEFENDER_ENV_FILE (the PydanticAI engine bills the "
              "first-party Anthropic API).", file=sys.stderr)
    else:
        print(f"[run.py] ERROR: a {prov.id} model is selected but no {var} — set it "
              f"in <repo>/.env or $DEFENDER_ENV_FILE ({prov.id} bills its "
              "OpenAI-compatible API).", file=sys.stderr)
    return 2


def _source_provider_keys(main_model: str, gather_model: str) -> int:
    try:
        used = {providers.provider_for(main_model), providers.provider_for(gather_model)}
    except ValueError as e:
        print(f"[run.py] ERROR: {e}", file=sys.stderr)
        return 2
    for prov in sorted(used, key=lambda p: p.id):
        rc = _source_one_provider_key(prov)
        if rc:
            return rc
    return 0


def main(argv: list[str]) -> int:
    ns = parse_args(argv)

    model = driver.resolve_main_model(ns.model)
    rc = _source_provider_keys(model, driver.gather_model())
    if rc:
        return rc

    alert = ns.alert.resolve()
    run_dir, salt = _run.materialize_run_dir(alert, ns.run_id)

    ticket_writer = None
    if ns.update_ticket:
        from defender.scripts.case_history import ticket_writer as _tw
        _tw.open_case_ticket(run_dir)
        ticket_writer = _tw

    print(f"[run.py] run_dir={run_dir} model={model}", file=sys.stderr)

    box = box_mod.start_box(run_dir, DEFENDER_DIR)
    investigation_ok = False
    try:
        summary = asyncio.run(driver.run_investigation(
            alert_path=RunPaths(run_dir).alert,
            run_dir=run_dir,
            run_id=run_dir.name,
            defender_dir=DEFENDER_DIR,
            salt=salt,
            model_name=model,
            box=box,
        ))
        investigation_ok = True
    finally:
        if investigation_ok:
            box_mod.stop_box(box)
        else:
            with contextlib.suppress(box_mod.BoxFault):
                box_mod.stop_box(box)

    box_mod.scrub(run_dir)

    out = str(summary.get("output") or "")
    print(f"[run.py] done ({summary.get('requests')} model requests); "
          f"output: {out[:200]}", file=sys.stderr)

    print("[run.py] artifacts:", file=sys.stderr)
    for entry in sorted(run_dir.iterdir()):
        sys.stderr.write(f"  {entry.name}\n")

    _run.cross_check_tables(run_dir)

    if ticket_writer is not None:
        ticket_writer.close_case_ticket(run_dir)

    if ns.no_learn:
        print("[run.py] --no-learn set; not enqueuing for learning", file=sys.stderr)
    elif _run.enqueue_learning(run_dir, alert, truncated_by=summary.get("truncated_by")):
        print("[run.py] enqueued for off-process learning", file=sys.stderr)

    _run.visualize(run_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
