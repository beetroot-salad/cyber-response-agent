"""Precomputed ORIENT pack — injected into the main agent's first message.

The runtime loop used to spend ~18 model round-trips before its first gather just
*acquiring context*: enumerating the invlang catalog, `ls`/`cat`-ing the system
SKILLs to discover what's reachable, and grepping this signature's lessons/corpus
— all deterministic, none of it judgment. The `claude -p` engine injected a
`workspace_map` at message 0; the PydanticAI driver dropped that, so the agent
started blind and rediscovered everything by hand.

This module rebuilds that orientation deterministically at run setup and hands it
to the agent up front, so ORIENT is reasoning over given material, not fetching it:

  - **Workspace map** — reachable systems, adapters, query templates, run-dir
    layout (`scripts/workspace_map.py`, the same map `claude -p` injected).
  - **invlang catalog** — every closed-catalog slot + values (`vocab.SLOTS`),
    static spec data identical every run (replaces the `enum` calls).
  - **Lessons for this signature** — `defender-lessons --tags` + the
    `source_signature` hits for the alert's `rule.id` (path + description), the
    exact scan surface the agent greps for at PLAN.
  - **Corpus hypothesis vocabulary** — `hypothesis-vocabulary --signature`, the
    prior `?name`s this rule has used (or the loud-empty banner).

Everything here is what the agent could fetch itself, so it stays free to: the
SKILL still permits `enum`/`defender-lessons`/`hypothesis-*`, and the block tells
it to re-fetch only a slot/lesson not shown. Fail-safe by construction — any
section that can't be built is omitted with a note, never raising, so a degraded
pack just means the agent falls back to fetching that piece live.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

_DEFENDER_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = _DEFENDER_DIR.parent
# scripts/ for workspace_map, repo root for the `defender.skills.invlang` package.
for _p in (str(_DEFENDER_DIR / "scripts"), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_SHIM_TIMEOUT_S = 20


def _shim(argv: list[str], env: dict[str, str]) -> str | None:
    """Run a `defender-*` shim with the run environment; return stdout, or None on
    any failure (the section is then omitted — the agent can still fetch it live)."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, env=env,
            cwd=str(_REPO_ROOT), timeout=_SHIM_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = (proc.stdout or "").strip()
    return out or None


def _catalog() -> str:
    """The full invlang closed-catalog (every slot + values) — static spec data,
    identical every run. Replaces the agent's `defender-invlang enum` calls."""
    from defender.skills.invlang import vocab
    lines = []
    for slot in vocab.list_slots():
        vals = ", ".join(vocab.get_enum(slot))
        lines.append(f"- `{slot}`: {vals}")
    return "\n".join(lines)


def _alert_signature(alert_path: Path) -> str | None:
    try:
        return json.loads(Path(alert_path).read_text())["rule"]["id"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def orientation(run_dir: Path, defender_dir: Path, alert_path: Path) -> str:
    """Assemble the ORIENT pack for this run. Never raises — a section that can't
    be built is skipped with a note. Returns a markdown block for the user prompt."""
    # run.run_env builds PATH(bin/) + DEFENDER_* vars for the shims below. Guarded:
    # orientation() is called from _user_prompt BEFORE the driver's try/except, so a
    # raise here would crash the run at setup — exactly what the fail-safe contract
    # forbids. On failure the shim-backed sections (lessons/corpus) simply omit;
    # the workspace + catalog sections don't need env and still build.
    try:
        import run  # defender/run.py
        env = run.run_env(defender_dir, run_dir)
    except Exception:  # noqa: BLE001 — orientation must never break the run
        env = {}
    sig = _alert_signature(alert_path)

    sections: list[str] = [
        "# Orientation (precomputed — read before Bash-ing enum / defender-lessons "
        "/ hypothesis-vocabulary; re-fetch live only for a slot or lesson not shown "
        "here, or a hypothesis-shape topology lookup, which is query-specific).",
    ]

    # 1. Workspace map (systems, adapters, query templates, run-dir layout).
    try:
        from workspace_map import workspace_map
        sections.append("## Workspace\n" + workspace_map(run_dir).strip())
    except Exception as e:  # noqa: BLE001 — orientation must never break the run
        sections.append(f"## Workspace\n_(unavailable: {e!r} — discover via ls/Read)_")

    # 2. invlang catalog (static closed-catalog slots + values).
    try:
        sections.append(
            "## invlang catalog (closed slots — author `:V type` / `:E rel` / "
            "`class` / `*.kind` from these)\n" + _catalog()
        )
    except Exception as e:  # noqa: BLE001
        sections.append(f"## invlang catalog\n_(unavailable: {e!r} — run `defender-invlang enum`)_")

    # 3. Lessons: viable tags + this signature's hits (path \t description).
    tags = _shim(["defender-lessons", "--tags"], env)
    # re.escape: rule.id is interpolated into a regex defender-lessons compiles.
    # Unescaped metachars would over-match (`.`, `+`) or raise re.error (unbalanced
    # `[`/`(`) → the hits section silently drops. The display strings below keep the
    # raw sig (human-readable); only the grep pattern is escaped.
    hits = (
        _shim(["defender-lessons", f"source_signature:.*{re.escape(sig)}"], env)
        if sig else None
    )
    lesson_lines = []
    if tags:
        lesson_lines.append("### Viable tags\n" + tags)
    if hits:
        lesson_lines.append(
            f"### Hits for `source_signature ~ {sig}` (read the bodies whose "
            f"description fits the lead you're about to write)\n" + hits
        )
    elif sig:
        lesson_lines.append(f"_(no lessons matched `source_signature ~ {sig}`)_")
    if lesson_lines:
        sections.append("## Lessons\n" + "\n\n".join(lesson_lines))

    # 4. Corpus hypothesis vocabulary for this signature (prior ?names, or empty).
    if sig:
        vocab_out = _shim(
            ["defender-invlang", "hypothesis-vocabulary", "--signature", sig], env
        )
        if vocab_out:
            sections.append(
                f"## Corpus hypothesis vocabulary — signature `{sig}` "
                "(reuse these `?name`s where the semantics match)\n" + vocab_out
            )

    return "\n\n".join(sections).strip() + "\n"
