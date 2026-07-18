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

# Re-exec into defender/.venv (which has pydantic-ai) if launched under a
# different interpreter. Gated on __main__ so importing this module never execvs.
_DEFENDER_DIR = Path(__file__).resolve().parent
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse  # noqa: E402
import asyncio  # noqa: E402

# Put the workspace root on sys.path so `defender.*` namespace imports resolve
# whether this file is imported or run directly.
if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import run_common as _run  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime import providers  # noqa: E402

DEFENDER_DIR = _DEFENDER_DIR


# The `.env` metered-key sourcing lives in the neutral `defender._first_party_key`
# module so the learning loop (the judge's metered-key sourcing) can import it too —
# it must NOT import run.py (the heavy runtime graph). Re-exported here for run.py's
# historical surface: tests reach `run.resolve_first_party_key` (and monkeypatch it),
# and `_source_one_provider_key` calls the bare name so the patch takes.
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
    """Source + require one provider's billable API key into `os.environ`. Prefers a
    `.env` key over the ambient value; returns exit code 2 if neither is present."""
    var = prov.api_key_var
    key, src = resolve_first_party_key(var=var)
    if key:
        # The .env key overrides the ambient value a Claude Code session exports —
        # for Anthropic that's the subscription credential, which 401s against the
        # first-party REST API this engine calls.
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
    """Source + require the API key for every provider this run will call. The MAIN
    and gather models each pick a provider from their name (`providers.provider_for`),
    so a mixed run (e.g. GLM main + Sonnet gather) needs *both* keys. Sets the sourced
    keys into `os.environ`; returns a non-zero exit code if a required key is missing
    or a selected model name is unroutable, else 0."""
    try:
        used = {providers.provider_for(main_model), providers.provider_for(gather_model)}
    except ValueError as e:
        # A typo'd `--model` / `$DEFENDER_MODEL` / `$DEFENDER_GATHER_MODEL` fails loud
        # in `provider_for`; surface it as run.py's clean exit-2 (matching the missing-key
        # path below) rather than letting the ValueError escape as a raw traceback.
        print(f"[run.py] ERROR: {e}", file=sys.stderr)
        return 2
    for prov in sorted(used, key=lambda p: p.id):  # deterministic: anthropic before fireworks
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

    # Case-history bridge — create the OPEN ticket now; closed in the post-steps
    # below (engine-agnostic helper, shared with run.py). Opt-in; non-fatal.
    ticket_writer = None
    if ns.update_ticket:
        from defender.scripts.case_history import ticket_writer as _tw
        _tw.open_case_ticket(run_dir)
        ticket_writer = _tw

    print(f"[run.py] run_dir={run_dir} model={model}", file=sys.stderr)

    # The bash lane's execution boundary (#540). Built BEFORE the investigation, so a box that
    # cannot be created refuses the run rather than letting it start unconfined; torn down in a
    # `finally`, so a crashed driver cannot leak a container (one genuinely survives its
    # parent's SIGKILL). Nothing here catches the crash — teardown runs, then the exception
    # keeps propagating, which is what makes the reap-time scrub below unreachable on a run
    # that never finished.
    box = box_mod.start_box(run_dir, DEFENDER_DIR)
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
    finally:
        box_mod.stop_box(box)

    # The reap-time scrub, between the box's death and the FIRST consumer of the tree. The
    # ordering is the whole soundness argument: the box is gone, so there is no live writer and
    # no TOCTOU window; and no consumer below has read the tree yet, so a tainted run reaches
    # none of them. `RunTainted` is deliberately left to propagate — sixteen host consumers read
    # this tree with symlink-unsafe primitives, and the safe answer is to refuse the tree, not
    # to catch the finding and carry on.
    box_mod.scrub(run_dir)

    out = str(summary.get("output") or "")
    print(f"[run.py] done ({summary.get('requests')} model requests); "
          f"output: {out[:200]}", file=sys.stderr)

    print("[run.py] artifacts:", file=sys.stderr)
    for entry in sorted(run_dir.iterdir()):
        sys.stderr.write(f"  {entry.name}\n")

    # Loud structural-integrity signal on the two live tables (no-op for a
    # no-gather run — slice 1).
    _run.cross_check_tables(run_dir)

    # Close the case-history ticket with the disposition (the defender's response).
    if ticket_writer is not None:
        ticket_writer.close_case_ticket(run_dir)

    if ns.no_learn:
        print("[run.py] --no-learn set; not enqueuing for learning", file=sys.stderr)
    else:
        _run.enqueue_learning(run_dir)
        print("[run.py] enqueued for off-process learning", file=sys.stderr)

    _run.visualize(run_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
