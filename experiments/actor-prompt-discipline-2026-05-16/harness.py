#!/usr/bin/env python3
"""Actor-prompt discipline experiment harness.

Generates actor stories for a (variant, fixture, seed) cell and grades
them with the rubric judge. Routes through defender.learning.loop.invoke_actor
so menu sampling, archetype assignment, settings, and lessons-actor add-dir
stay identical to production.

Actor model: pinned to claude-sonnet-4-6 (matches production ACTOR_MODEL
default), no --effort flag (production doesn't pass one).

Usage:
    python harness.py generate --variant e1-terse-goal --fixture live-5710 --seeds 1,2,3,4
    python harness.py grade    --variant e1-terse-goal --fixture live-5710 --seeds 1,2,3,4
    python harness.py run      --variant e1-terse-goal --fixture live-5710 --seeds 1,2,3,4   # both
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

EXP_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXP_DIR.parents[1]
ACTOR_MD = REPO_ROOT / "defender" / "learning" / "actor.md"
RUBRIC_MD = EXP_DIR / "rubric.md"

ACTOR_MODEL = "claude-sonnet-4-6"   # matches production default
JUDGE_MODEL = "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# Variant patching
# ---------------------------------------------------------------------------

CURRENT_SECTION_2 = (
    "**2. Goal.** What this specific operation achieves end-to-end. "
    "Tie to actor model and entry point."
)

TERSE_SECTION_2 = (
    "**2. Goal.** *One sentence* naming the immediate upstream constraint "
    "that makes the entry point plausible (e.g., what the attacker needs "
    "to have already accomplished). No lateral movement, no end objective, "
    "no exfil chain."
)

E2_EXPLICIT_AXES = (
    " Operational parameters (count, cadence, fan-out, target breadth, "
    "dwell time) must be committed at **magnitude-tier resolution only**: "
    "count as one/few/many; cadence as seconds/minutes/hours/days; fan-out "
    "as single/few/many. Specific values (e.g., \"every 70 seconds\", "
    "\"3 hosts\") are forbidden — they invite refutation on cosmetic "
    "detail rather than load-bearing axes."
)

E2_FREEFORM = (
    " Commit operational parameters at the coarsest resolution that still "
    "makes the story falsifiable. If the exact value isn't load-bearing, "
    "state the magnitude tier (seconds vs. minutes vs. hours; single vs. "
    "recurring) rather than a specific number. Cosmetic specificity is a "
    "liability — the judge will refute you on it."
)

E2_LOAD_BEARING = (
    " Distinguish load-bearing specifics from cosmetic ones. A detail is "
    "load-bearing if its refutation would refute the story's malicious "
    "thesis — if a defender finding the exact opposite would force the "
    "disposition to flip. Keep load-bearing specifics. For cosmetic details "
    "— where the exact value doesn't change the story — state the order of "
    "magnitude (seconds vs. minutes vs. hours; single vs. few vs. many; "
    "bytes vs. kilobytes vs. megabytes) rather than committing to a number. "
    "Don't pick numbers at random just to sound concrete."
)

PREAMBLE_TAIL = (
    "added detail that the alert or lead set could refute is a liability, "
    "not strength."
)


def _apply_dropped_goal(text: str) -> str:
    assert CURRENT_SECTION_2 in text
    text = text.replace(f"\n{CURRENT_SECTION_2}\n\n", "\n")
    text = text.replace("**3. Bypass.**", "**2. Bypass.**")
    text = text.replace(
        "Otherwise, four sections, in order:",
        "Otherwise, three sections, in order:",
    )
    return text


def patched_actor_md(variant: str) -> str:
    """Return actor.md text with the variant patch applied.

    E2 variants layer on top of the e1-dropped-goal winner from Stage 1a.
    """
    text = ACTOR_MD.read_text()

    if variant == "e1-current-goal":
        return text
    if variant == "e1-terse-goal":
        assert CURRENT_SECTION_2 in text, "Section 2 anchor not found"
        return text.replace(CURRENT_SECTION_2, TERSE_SECTION_2)
    if variant == "e1-dropped-goal":
        return _apply_dropped_goal(text)
    # E2 variants compose on the E1 winner (dropped-goal) and then append
    # to the preamble's first paragraph.
    if variant.startswith("e2-"):
        text = _apply_dropped_goal(text)
        if variant == "e2-current-spec":
            return text
        if variant == "e2-explicit-axes":
            assert PREAMBLE_TAIL in text
            return text.replace(PREAMBLE_TAIL, PREAMBLE_TAIL + E2_EXPLICIT_AXES)
        if variant == "e2-freeform-rule":
            assert PREAMBLE_TAIL in text
            return text.replace(PREAMBLE_TAIL, PREAMBLE_TAIL + E2_FREEFORM)
    # Stage-2 combined winner: dropped-goal + freeform-rule
    if variant == "combined-dropped-freeform":
        text = _apply_dropped_goal(text)
        assert PREAMBLE_TAIL in text
        return text.replace(PREAMBLE_TAIL, PREAMBLE_TAIL + E2_FREEFORM)
    # Stage-3 candidate: dropped-goal + load-bearing-aware specificity
    if variant == "combined-dropped-load-bearing":
        text = _apply_dropped_goal(text)
        assert PREAMBLE_TAIL in text
        return text.replace(PREAMBLE_TAIL, PREAMBLE_TAIL + E2_LOAD_BEARING)
    raise SystemExit(f"unknown variant: {variant}")


# ---------------------------------------------------------------------------
# Cell layout
# ---------------------------------------------------------------------------


def cell_dir(variant: str, fixture: str, seed: int) -> Path:
    # Stage inferred from variant prefix.
    if variant.startswith("e1-"):
        stage = "stage1a-e1"
    elif variant.startswith("e2-"):
        stage = "stage1b-e2"
    else:
        stage = "stage2"
    return EXP_DIR / "runs" / stage / variant / f"{fixture}-seed{seed:02d}"


def fixture_dir(fixture: str) -> Path:
    d = EXP_DIR / "fixtures" / fixture
    if not (d / "alert.json").is_file() or not (d / "actor_input.yaml").is_file():
        raise SystemExit(
            f"fixture {fixture} missing alert.json or actor_input.yaml in {d}"
        )
    return d


# ---------------------------------------------------------------------------
# Streamed claude wrapper — concatenates every assistant text message so
# multi-message actor outputs aren't truncated by `--output-format text`.
# Production loop.py uses text mode which silently drops earlier assistant
# texts (e.g., Section 0 emitted before lessons-corpus tool calls). For
# evaluation we need the full story regardless of how the actor split it.
# ---------------------------------------------------------------------------


def _run_claude_streamed(
    system_prompt_path,
    user_prompt: str,
    model: str,
    *,
    settings_path=None,
    add_dir=None,
    permission_mode=None,
    session_id=None,
) -> str:
    cmd = [
        "claude", "-p",
        "--model", model,
        "--output-format", "stream-json",
        "--verbose",  # required for stream-json with -p
        "--include-partial-messages",  # harmless if unsupported; safe to drop
        "--system-prompt-file", str(system_prompt_path),
    ]
    # The --include-partial-messages flag isn't universally supported; pop it
    # if claude rejects the cmd on first probe. Simpler: omit unless needed.
    cmd = [a for a in cmd if a != "--include-partial-messages"]
    if settings_path is not None:
        cmd += ["--settings", str(settings_path)]
    if add_dir is not None:
        cmd += ["--add-dir", str(add_dir)]
    if permission_mode is not None:
        cmd += ["--permission-mode", permission_mode]
    if session_id is not None:
        cmd += ["--session-id", session_id]
    proc = subprocess.run(
        cmd, input=user_prompt, capture_output=True, text=True, timeout=600,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"claude -p (stream-json) failed (rc={proc.returncode}):\n"
            f"stderr: {proc.stderr[-2000:]}"
        )
    parts: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = ev.get("message") or {}
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    txt = item.get("text", "")
                    if txt:
                        parts.append(txt)
        elif isinstance(content, str) and content:
            parts.append(content)
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Generation — calls into defender.learning.loop.invoke_actor
# ---------------------------------------------------------------------------


def generate(variant: str, fixture: str, seed: int) -> Path:
    out = cell_dir(variant, fixture, seed)
    out.mkdir(parents=True, exist_ok=True)
    if (out / "story.md").is_file():
        print(f"[skip] {out.relative_to(EXP_DIR)} already has story.md")
        return out / "story.md"

    # Stage the patched actor prompt next to the run dir so it's auditable.
    patched_path = out / "actor.md.patched"
    patched_path.write_text(patched_actor_md(variant))

    fx = fixture_dir(fixture)
    # The seed is derived from learning_run_dir.name. Use a deterministic
    # name per (variant, fixture, seed) so menu+archetype are reproducible.
    learning_run = out / "loop_artifacts"
    learning_run.mkdir(exist_ok=True)
    # _actor_seed reads learning_run_dir.name, so override via symlink/rename:
    # simplest is to make the dir name encode the seed.
    seeded = out / f"loop-seed-{variant}-{fixture}-{seed:04d}"
    if seeded.exists():
        shutil.rmtree(seeded)
    seeded.mkdir()

    # loop.py uses sibling-module imports (`import mitre_corpus`), so add
    # defender/learning/ to sys.path, not REPO_ROOT.
    sys.path.insert(0, str(REPO_ROOT / "defender" / "learning"))
    import loop  # type: ignore

    # Pin model and patched prompt. Also swap `_run_claude` for a
    # stream-json variant so multi-message actor outputs (Section 0
    # emitted before tool calls, Sections 1-3 after) aren't truncated
    # by --output-format text. See _run_claude_streamed below.
    orig_prompt = loop.ACTOR_PROMPT
    orig_model = loop.ACTOR_MODEL
    orig_run = loop._run_claude
    loop.ACTOR_PROMPT = patched_path
    loop.ACTOR_MODEL = ACTOR_MODEL
    loop._run_claude = _run_claude_streamed
    try:
        story = loop.invoke_actor(
            alert_path=fx / "alert.json",
            actor_input_path=fx / "actor_input.yaml",
            learning_run_dir=seeded,
        )
    finally:
        loop.ACTOR_PROMPT = orig_prompt
        loop.ACTOR_MODEL = orig_model
        loop._run_claude = orig_run

    (out / "story.md").write_text(story)
    # Keep the menu + archetype the actor saw for audit.
    for tail in ("actor_archetype.txt", "actor_menu.txt", "actor_trace.jsonl"):
        src = seeded / tail
        if src.is_file():
            shutil.copy2(src, out / tail)
    print(f"[gen]  {out.relative_to(EXP_DIR)}  ({len(story)} chars)")
    return out / "story.md"


# ---------------------------------------------------------------------------
# Grading — rubric judge via claude -p
# ---------------------------------------------------------------------------


def grade(variant: str, fixture: str, seed: int) -> Path:
    out = cell_dir(variant, fixture, seed)
    story_path = out / "story.md"
    if not story_path.is_file():
        raise SystemExit(f"no story at {story_path}; run generate first")
    grade_path = out / "grade.json"
    if grade_path.is_file():
        print(f"[skip] {grade_path.relative_to(EXP_DIR)} already exists")
        return grade_path

    fx = fixture_dir(fixture)
    alert = (fx / "alert.json").read_text().rstrip()
    story = story_path.read_text().rstrip()
    user = (
        f"<variant>{variant}</variant>\n"
        f"<alert>\n{alert}\n</alert>\n"
        f"<story>\n{story}\n</story>\n"
    )
    cmd = [
        "claude", "-p",
        "--model", JUDGE_MODEL,
        "--output-format", "text",
        "--system-prompt-file", str(RUBRIC_MD),
    ]
    last_raw = ""
    for attempt in range(3):
        proc = subprocess.run(cmd, input=user, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise SystemExit(f"rubric judge failed: {proc.stderr[-500:]}")
        last_raw = proc.stdout.strip()
        cleaned = last_raw
        # Tolerate ```json … ``` fences the judge sometimes adds.
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[: -3].rstrip()
        try:
            parsed = json.loads(cleaned)
            grade_path.write_text(json.dumps(parsed, indent=2) + "\n")
            break
        except json.JSONDecodeError:
            print(f"[retry {attempt+1}/3] {out.relative_to(EXP_DIR)} bad JSON, re-rolling")
            continue
    else:
        (out / "grade.raw.txt").write_text(last_raw)
        raise SystemExit(f"rubric output did not parse as JSON after 3 tries; raw at {out / 'grade.raw.txt'}")
    print(f"[grade] {out.relative_to(EXP_DIR)}  {parsed}")
    return grade_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_seeds(s: str) -> list[int]:
    return [int(x) for x in s.split(",") if x.strip()]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("cmd", choices=["generate", "grade", "run"])
    p.add_argument("--variant", required=True)
    p.add_argument("--fixture", required=True)
    p.add_argument("--seeds", required=True, help="comma-separated, e.g. 1,2,3,4")
    args = p.parse_args()

    for seed in parse_seeds(args.seeds):
        if args.cmd in ("generate", "run"):
            generate(args.variant, args.fixture, seed)
        if args.cmd in ("grade", "run"):
            grade(args.variant, args.fixture, seed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
