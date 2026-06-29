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
import subprocess
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
import json  # noqa: E402

# Put the workspace root on sys.path so `defender.*` namespace imports resolve
# whether this file is imported or run directly.
if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import run_common as _run  # noqa: E402
from defender.runtime import driver  # noqa: E402

DEFENDER_DIR = _DEFENDER_DIR


def _read_env_key(env_file: Path, var: str = "ANTHROPIC_API_KEY") -> str | None:
    """Extract a single var from a `.env` file. Deliberately *not* a full dotenv
    load — we only want the API key, not to clobber adapter config (data-source creds,
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


def _main_repo_root() -> Path:
    """The main worktree's root, where shared config like `.env` lives.

    Under a linked git worktree `_run.REPO_ROOT` is the *worktree* root, not the
    main checkout, so `<repo_root>/.env` misses the canonical file. Git's common
    dir (`.../.git`) is shared by every worktree; its parent is the main root.
    Falls back to `_run.REPO_ROOT` outside a git tree.
    """
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--git-common-dir"],
            cwd=_run.REPO_ROOT, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return _run.REPO_ROOT
    if not out:
        return _run.REPO_ROOT
    common = Path(out)
    if not common.is_absolute():
        common = (_run.REPO_ROOT / common).resolve()
    return common.parent


def resolve_first_party_key(
    *, root: Path | None = None, main_repo_root: Path | None = None
) -> tuple[str | None, Path | None]:
    """The billable first-party API key for the PydanticAI engine, sourced from a
    `.env` file rather than the ambient ANTHROPIC_API_KEY.

    Inside a Claude Code session the ambient key is the *subscription* credential
    (the session's nested `claude -p` rides it; it 401s against the first-party
    REST API this engine calls), so the `.env` key takes precedence. First existing
    file with an ANTHROPIC_API_KEY wins:

      1. ``$DEFENDER_ENV_FILE``        — explicit override
      2. ``<repo_root>/.env``
      3. ``<main_worktree_root>/.env`` — repo_root points at the *worktree* root
                                         under a linked git worktree; shared config
                                         like .env lives in the main checkout

    Returns ``(key, source_path)`` or ``(None, None)``.
    """
    if root is None:
        root = _run.REPO_ROOT
    if main_repo_root is None:
        main_repo_root = _main_repo_root()
    candidates: list[Path] = []
    explicit = os.environ.get("DEFENDER_ENV_FILE")
    if explicit:
        candidates.append(Path(explicit))
    candidates += [
        root / ".env",
        main_repo_root / ".env",
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
    key, src = resolve_first_party_key()
    if key:
        os.environ["ANTHROPIC_API_KEY"] = key
        print(f"[run.py] first-party API key sourced from {src} "
              "(overrides the ambient subscription credential)", file=sys.stderr)
    elif os.environ.get("ANTHROPIC_API_KEY"):
        print("[run.py] WARNING: no .env key found; using the ambient "
              "ANTHROPIC_API_KEY — inside a Claude Code session this is the "
              "subscription credential and will 401 against the first-party API.",
              file=sys.stderr)
    else:
        print("[run.py] ERROR: no first-party ANTHROPIC_API_KEY — set it in "
              "<repo>/.env or $DEFENDER_ENV_FILE (the PydanticAI "
              "engine bills the first-party Anthropic API).", file=sys.stderr)
        return 2

    alert = ns.alert.resolve()
    run_dir = _run.materialize_run_dir(alert, ns.run_id)

    # Case-history bridge — create the OPEN ticket now; closed in the post-steps
    # below (engine-agnostic helper, shared with run.py). Opt-in; non-fatal.
    ticket_writer = None
    if ns.update_ticket:
        from defender.scripts.case_history import ticket_writer as _tw
        _tw.open_case_ticket(run_dir)
        ticket_writer = _tw

    salt = json.loads((run_dir / "meta.json").read_text()).get("salt", "")
    model = driver.resolve_main_model(ns.model)
    print(f"[run.py] run_dir={run_dir} model={model}", file=sys.stderr)

    summary = asyncio.run(driver.run_investigation(
        alert_path=run_dir / "alert.json",
        run_dir=run_dir,
        run_id=run_dir.name,
        defender_dir=DEFENDER_DIR,
        salt=salt,
        model_name=model,
    ))
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
