#!/usr/bin/env python3
"""Render a case's `story.md` from the attack runner's own record.

`story.md` is an oracle input, so the hidden/visible split cannot protect it: a
hand-written story can tell the oracle its own answer, or describe a step that never ran.
This renderer's only input is `playground-v2/attacks/runs/<id>/meta.json`, the runner's
record of what it did; it has no access to `expected.yaml`, controls, or result classes.

The story states only: the resolved identity and host pair, each command as issued, its
return code, when it ran, and what it printed.

The renderer also lints its own output against the evaluation vocabulary and refuses to
write a story that trips it (e.g. command text containing `suppressed:`).

Usage: story_from_run.py <runs_dir>/<run-id>/meta.json <out story.md>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

#: Vocabulary only an eval author writes: the scoring frame, never the operation. Also read
#: by `validate_cases.check_case` via `eval_tells_in`. (`tests/test_oracle_golden_693.py`
#: keeps an independent copy to sweep the committed corpus for hand-edited leaks.)
EVAL_TELLS = (
    "oracle", "negative control", "golden", "projection", "every lead",
    "each lead", "expected result", "+event", "+noise", "-noise",
    "result class", "standard environment noise", "suppressed:",
)


def _fmt_block(text: str, indent: str = "    ") -> str:
    lines = [ln for ln in (text or "").strip().splitlines() if ln.strip()]
    return "\n".join(indent + ln for ln in lines) if lines else indent + "(no output)"


def render_story(meta: dict) -> str:
    """The story text for one runner record."""
    resolved = meta.get("resolved") or {}
    steps = meta.get("steps") or []
    identity = resolved.get("source_user") or "unknown"
    target = resolved.get("target_host") or "unknown"
    sources = sorted({s.get("source_host") for s in steps if s.get("source_host")})
    source = sources[0] if len(sources) == 1 else ", ".join(sources) or "unknown"

    out = [
        "1. Activity story",
        "",
        f"The activity runs as `{identity}` from `{source}`, directed at `{target}`.",
        f"It began at {meta.get('started_at', 'an unrecorded time')} and finished at "
        f"{meta.get('finished_at', 'an unrecorded time')}.",
    ]
    # The catalog `description` is not rendered: it describes the default configuration, so
    # a retargeted run would name two targets. Only the runner's resolved facts are used.
    if meta.get("aborted"):
        out += ["", "The run was aborted before completing every step."]

    out += ["", "2. What was executed", ""]
    for i, step in enumerate(steps, 1):
        out += [
            f"Step {i} — on `{step.get('source_host', 'unknown')}` "
            f"as `{step.get('source_user', 'unknown')}`, "
            f"from {step.get('started_at', '?')} to {step.get('ended_at', '?')} "
            f"(exit status {step.get('rc', '?')}):",
            "",
            _fmt_block(step.get("cmd", "")),
            "",
            "It printed:",
            "",
            _fmt_block(step.get("stdout_tail", "")),
        ]
        if (step.get("stderr_tail") or "").strip():
            out += ["", "On its error stream:", "", _fmt_block(step["stderr_tail"])]
        out += [""]
    return "\n".join(out).rstrip() + "\n"


def eval_tells_in(story: str) -> list[str]:
    """Evaluation vocabulary present in a story — must always be empty."""
    lowered = story.lower()
    return [tell for tell in EVAL_TELLS if tell in lowered]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("meta", type=Path, help="playground-v2/attacks/runs/<id>/meta.json")
    p.add_argument("out", type=Path, help="story.md to write")
    ns = p.parse_args(argv)

    meta = json.loads(ns.meta.read_text(encoding="utf-8"))  # lint-whole-read: ok — operator-only eval tooling over operator-curated golden-case files (evals/oracle_golden/); never read by a long-lived host process
    story = render_story(meta)

    found = eval_tells_in(story)
    if found:
        # Refuse rather than warn: a leaked answer invalidates every projection of the case.
        print(f"!! rendered story contains evaluation vocabulary {found} — refusing to "
              f"write. Fix the scenario's command text or the renderer.", file=sys.stderr)
        return 1

    ns.out.parent.mkdir(parents=True, exist_ok=True)
    ns.out.write_text(story, encoding="utf-8")
    print(f"wrote {ns.out} ({len(story.splitlines())} lines, "
          f"{len(meta.get('steps') or [])} steps)")
    return 0


if __name__ == "__main__":  # lint-log-setup: ok — stdlib-only: run by path with no `defender` on the import path, so it cannot import the setup
    sys.exit(main())
