#!/usr/bin/env python3
"""Render a case's `story.md` from the attack runner's own record (#711 M9).

`story.md` is the one oracle-visible file the hidden/visible split cannot
protect: it is deliberately an oracle INPUT, and the seed negative control
managed to tell the oracle in its own story that it was a negative control and
"must therefore return `0` for every lead". A hand-written story is exposed to
that leak on every capture.

A renderer is not merely cheaper than hand-authoring — it is **safer**, because
it structurally cannot leak the evaluation into an oracle input. It has no access
to `expected.yaml`, to controls, or to any result class; its only input is
`playground-v2/attacks/runs/<id>/meta.json`, the runner's record of what it
actually did. And it cannot invent a step, which is the other way a story makes
the oracle "wrong" for a reason that is not the oracle's fault.

The rendered story states only: the resolved identity and host pair, each command
as the runner issued it, its return code, when it ran, and what it printed. That
is what the procedure doc asks a human for ("state only what happened"), and it
is exactly what `playground-v2/attacks/runs/<id>/meta.json` holds. (That record is
the attack runner's own, unrelated to the defender run metadata #647 retired.)

Belt and braces: the renderer lints its OWN output against the evaluation
vocabulary and refuses to write a story that trips it, so a scenario whose
command text happened to contain e.g. `suppressed:` fails loudly here rather
than quietly teaching the oracle its answer.

Usage: story_from_run.py <runs_dir>/<run-id>/meta.json <out story.md>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

#: Kept in sync with `_EVAL_TELLS` in the golden-set case linter. Vocabulary only
#: an eval author writes — the scoring frame, never the operation.
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
    # The catalog `description` is NOT rendered, and that is load-bearing. It
    # describes the scenario's DEFAULT configuration, so a retargeted run gets a
    # story that contradicts itself: `ssh-brute-force-canary --target db-1`
    # produced a story whose header said db-1 and whose description said
    # "hammers canary-1's SSH ... failed auth events on canary-1's sshd". The
    # oracle then has two different targets in one input, and any projection it
    # makes is a measurement of the contradiction rather than of the oracle.
    # Two #711 pilot cases were retired for exactly this.
    #
    # Only the runner's RESOLVED facts are rendered. A renderer that cannot
    # reach static catalog prose cannot leak a default into a story.
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


def leaks(story: str) -> list[str]:
    """Evaluation vocabulary present in a story — must always be empty."""
    lowered = story.lower()
    return [tell for tell in EVAL_TELLS if tell in lowered]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("meta", type=Path, help="playground-v2/attacks/runs/<id>/meta.json")
    p.add_argument("out", type=Path, help="story.md to write")
    ns = p.parse_args(argv)

    meta = json.loads(ns.meta.read_text(encoding="utf-8"))
    story = render_story(meta)

    found = leaks(story)
    if found:
        # Refuse rather than warn: a leaked answer in an oracle input invalidates
        # every projection the case will ever record, and it is invisible after
        # the fact because the story is SUPPOSED to be visible.
        print(f"!! rendered story contains evaluation vocabulary {found} — refusing to "
              f"write. Fix the scenario's command text or the renderer.", file=sys.stderr)
        return 1

    ns.out.parent.mkdir(parents=True, exist_ok=True)
    ns.out.write_text(story, encoding="utf-8")
    print(f"wrote {ns.out} ({len(story.splitlines())} lines, "
          f"{len(meta.get('steps') or [])} steps)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
