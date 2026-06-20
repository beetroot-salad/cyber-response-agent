#!/usr/bin/env python3
"""Defender entrypoint (PydanticAI engine) — investigate one alert end-to-end.

The Phase-A sibling of run.py: same CLI, same run-dir contract, same post-steps
(materialize → run → cross-check → enqueue-learning → visualize), but the
investigation is driven by the in-process PydanticAI driver
(`runtime/driver.py`) instead of a `claude -p` subprocess. run.py is left
untouched so both engines coexist for A/B.

Usage:
    python3 defender/run_pai.py <alert.json> [--run-id ID] [--no-learn] [--model M]

Billing / credentials: the PydanticAI engine calls the first-party Anthropic
REST API, so it needs a real API key — unlike run.py, whose nested `claude -p`
rides the Claude Code subscription. Inside a Claude Code session the *ambient*
ANTHROPIC_API_KEY is the subscription credential (it 401s against the REST API),
so run_pai sources its own billable key from a `.env` file
(`resolve_first_party_key`), which takes precedence over the ambient value. This
is the seam that keeps the two engines on different billing without colliding.
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

# Put the workspace root on sys.path so `defender.*` namespace imports resolve
# whether this file is imported or run directly (mirrors run.py).
if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import run as _run  # noqa: E402
from defender.runtime import driver  # noqa: E402

DEFENDER_DIR = _DEFENDER_DIR


def _read_env_key(env_file: Path, var: str = "ANTHROPIC_API_KEY") -> str | None:
    """Extract a single var from a `.env` file. Deliberately *not* a full dotenv
    load — we only want the API key, not to clobber adapter config (elastic creds,
    docker-context vars) that also live in these files. Returns the value or None."""
    try:
        text = env_file.read_text()
    except OSError:
        return None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        k, sep, v = line.partition("=")
        if sep and k.strip() == var:
            return v.strip().strip('"').strip("'") or None
    return None


def resolve_first_party_key(defender_dir: Path) -> tuple[str | None, Path | None]:
    """The billable first-party API key for the PydanticAI engine, sourced from a
    `.env` file rather than the ambient ANTHROPIC_API_KEY.

    Inside a Claude Code session the ambient key is the *subscription* credential
    (run.py's nested `claude -p` rides it; it 401s against the first-party REST
    API this engine calls), so the `.env` key takes precedence. First existing
    file with an ANTHROPIC_API_KEY wins:

      1. ``$DEFENDER_ENV_FILE``  — explicit override
      2. ``<repo_root>/.env``
      3. ``/workspace/.env``     — canonical host location (repo_root differs under a git worktree)
      4. ``<defender_dir>/../.env``

    Returns ``(key, source_path)`` or ``(None, None)``.
    """
    candidates: list[Path] = []
    explicit = os.environ.get("DEFENDER_ENV_FILE")
    if explicit:
        candidates.append(Path(explicit))
    candidates += [
        _run.REPO_ROOT / ".env",
        Path("/workspace/.env"),
        defender_dir.parent / ".env",
    ]
    seen: set[Path] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        if path.is_file():
            key = _read_env_key(path)
            if key:
                return key, path
    return None, None


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
    p.add_argument("--model", default=None, help="model id (overrides $DEFENDER_MODEL)")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    ns = parse_args(argv)

    # Source the billable first-party key from .env (overrides the ambient
    # subscription credential a Claude Code session exports). See module docstring.
    key, src = resolve_first_party_key(DEFENDER_DIR)
    if key:
        os.environ["ANTHROPIC_API_KEY"] = key
        print(f"[run_pai] first-party API key sourced from {src} "
              "(overrides the ambient subscription credential)", file=sys.stderr)
    elif os.environ.get("ANTHROPIC_API_KEY"):
        print("[run_pai] WARNING: no .env key found; using the ambient "
              "ANTHROPIC_API_KEY — inside a Claude Code session this is the "
              "subscription credential and will 401 against the first-party API.",
              file=sys.stderr)
    else:
        print("[run_pai] ERROR: no first-party ANTHROPIC_API_KEY — set it in "
              "/workspace/.env, <repo>/.env, or $DEFENDER_ENV_FILE (the PydanticAI "
              "engine bills the first-party Anthropic API).", file=sys.stderr)
        return 2

    alert = ns.alert.resolve()
    run_dir = _run.materialize_run_dir(alert, ns.run_id)

    # Case-history bridge — create the OPEN ticket now; closed in the post-steps
    # below (engine-agnostic helper, shared with run.py). Opt-in; non-fatal.
    ticket_writer = None
    if ns.update_ticket:
        from defender.scripts.tools import ticket_writer
        ticket_writer.open_case_ticket(run_dir)

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

    # Close the case-history ticket with the disposition (the defender's response).
    if ticket_writer is not None:
        ticket_writer.close_case_ticket(run_dir)

    if ns.no_learn:
        print("[run_pai] --no-learn set; not enqueuing for learning", file=sys.stderr)
    else:
        _run.enqueue_learning(run_dir)
        print("[run_pai] enqueued for off-process learning", file=sys.stderr)

    _run.visualize(run_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
