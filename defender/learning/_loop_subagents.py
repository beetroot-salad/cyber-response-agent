"""Subagent seam: `claude -p` invocation today, Claude Agent SDK tomorrow.

`Subagents` is the port — orchestration depends only on it ("give me the actor's
story", "project the telemetry", "judge the encounter"). `ClaudePrintSubagents` is
the adapter that owns every `claude -p`-specific detail (stream-json parsing,
`--session-id` transcript-file copy, the settings/add-dir/permission-mode flags). A
future `SdkSubagents` swaps the adapter without touching orchestration, validators,
persistence, or the test fakes.

The actual invocation lives in module-level `invoke_*` functions; the adapter methods
are thin wrappers that also assemble each step's inputs. `replay_actor.py` drives the
free functions directly.
"""
from __future__ import annotations

import hashlib
import json
import random
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Protocol

import yaml

import mitre_corpus
from _loop_persist import derive_alert_rule_key
from _prologue import extract_case_entities

from _loop_config import (
    ACTOR_BENIGN_PROMPT,
    ACTOR_EFFORT,
    ACTOR_MODEL,
    ACTOR_PROMPT,
    ACTOR_SETTINGS,
    BENIGN_ACTOR_EFFORT,
    BENIGN_ACTOR_MODEL,
    BENIGN_ACTOR_SETTINGS,
    BENIGN_JUDGE_EFFORT,
    BENIGN_JUDGE_MODEL,
    FOOTPRINT_EFFORT,
    FOOTPRINT_MODEL,
    FOOTPRINT_PROMPT,
    JUDGE_BENIGN_PROMPT,
    JUDGE_EFFORT,
    JUDGE_MODEL,
    JUDGE_PROMPT,
    LESSONS_ACTOR_DIR,
    LESSONS_ENVIRONMENT_DIR,
    LoopError,
    PROJECT_SCRIPT,
    REPO_ROOT,
    SUBAGENT_TIMEOUT,
    _log,
)


# ---------------------------------------------------------------------------
# claude -p transport
# ---------------------------------------------------------------------------


def _run_claude(
    system_prompt_path: Path,
    user_prompt: str,
    model: str,
    *,
    settings_path: Path | None = None,
    add_dir: Path | list[Path] | None = None,
    permission_mode: str | None = None,
    session_id: str | None = None,
    effort: str | None = None,
) -> str:
    """One-shot ``claude -p`` call, returning concatenated assistant text.

    Optional kwargs scope the tool surface (settings + add-dir + permission-mode)
    and pin the session id so the caller can copy the persistent transcript after
    the call. ``effort`` pins reasoning depth; None inherits the global default.

    stream-json + concat all assistant text messages: `--output-format text`
    returns only the final assistant message, silently dropping earlier assistant
    text when the prompt does tool calls mid-output (e.g. the actor emits Section 0,
    consults the lessons corpus, then emits Sections 1-3). Concatenating across
    messages keeps the prompt's design intent intact regardless of tool use.
    """
    cmd = [
        "claude",
        "-p",
        "--model", model,
        "--output-format", "stream-json",
        "--verbose",  # required for stream-json with -p
        "--system-prompt-file", str(system_prompt_path),
    ]
    if effort is not None:
        cmd += ["--effort", effort]
    if settings_path is not None:
        cmd += ["--settings", str(settings_path)]
    if add_dir is not None:
        for d in (add_dir if isinstance(add_dir, list) else [add_dir]):
            cmd += ["--add-dir", str(d)]
    if permission_mode is not None:
        cmd += ["--permission-mode", permission_mode]
    if session_id is not None:
        cmd += ["--session-id", session_id]

    proc = subprocess.run(
        cmd,
        input=user_prompt,
        capture_output=True,
        text=True,
        timeout=SUBAGENT_TIMEOUT,
        cwd=str(REPO_ROOT),
    )
    if proc.returncode != 0:
        raise LoopError(
            f"claude -p failed (rc={proc.returncode}):\nstderr: {proc.stderr[-2000:]}"
        )
    return "\n\n".join(_extract_assistant_text_parts(proc.stdout))


def _extract_assistant_text_parts(stdout: str) -> list[str]:
    parts: list[str] = []
    for raw in stdout.splitlines():
        line = raw.strip()
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
    return parts


def _transcript_path(session_id: str) -> Path:
    """Persistent transcript Claude Code writes for ``--session-id``.

    Path = ``~/.claude/projects/{sanitized-cwd}/{session_id}.jsonl`` where the
    sanitization is ``cwd.replace('/', '-')``.
    """
    cwd_slug = str(REPO_ROOT).replace("/", "-")
    return Path.home() / ".claude" / "projects" / cwd_slug / f"{session_id}.jsonl"


def _copy_transcript(session_id: str, dst: Path) -> None:
    src = _transcript_path(session_id)
    if src.is_file():
        shutil.copy2(src, dst)
    else:
        _log(f"transcript not found at {src}; skipping {dst.name}")


def _section(tag: str, body: str, comment: str | None = None) -> str:
    inner = f"<!-- {comment} -->\n" if comment else ""
    return f"<{tag}>\n{inner}{body.rstrip()}\n</{tag}>\n"


def _actor_seed(run_id: str) -> int:
    """Stable per-run seed for menu sampling and archetype choice."""
    return int(hashlib.sha256(run_id.encode()).hexdigest()[:8], 16)


def is_skip_story(actor_story: str) -> bool:
    for line in actor_story.splitlines():
        s = line.strip()
        if not s:
            continue
        return s.startswith("SKIP:")
    return False


# ---------------------------------------------------------------------------
# Per-step invocation (free functions; the adapter wraps these)
# ---------------------------------------------------------------------------


def project_actor_input(run_dir: Path, actor_out: Path) -> None:
    cmd = [sys.executable, str(PROJECT_SCRIPT), str(run_dir), "--actor-out", str(actor_out)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise LoopError(
            f"project_lead_sequence.py failed (rc={proc.returncode}):\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    if not actor_out.is_file():
        raise LoopError(f"actor projection did not produce {actor_out}")


def invoke_actor(alert_path: Path, actor_input_path: Path, learning_run_dir: Path) -> str:
    rng = random.Random(_actor_seed(learning_run_dir.name))
    archetype = rng.choice(["internal", "external"])
    menu_text = mitre_corpus.format_menu(mitre_corpus.sample_menu(rng))
    (learning_run_dir / "actor_archetype.txt").write_text(archetype + "\n")
    (learning_run_dir / "actor_menu.txt").write_text(menu_text + "\n")

    alert_rule_key = derive_alert_rule_key(json.loads(alert_path.read_text()))
    user = (
        _section("alert", alert_path.read_text())
        + _section("alert_rule_id", alert_rule_key,
                   "canonical rule key; pass verbatim to environment-fact retrieval")
        + _section("actor_input", actor_input_path.read_text(),
                   "lead sequence projected for the actor")
        + _section("actor_archetype", archetype)
        + _section("mitre_menu", menu_text)
    )
    session_id = str(uuid.uuid4())
    story = _run_claude(
        ACTOR_PROMPT, user, model=ACTOR_MODEL, effort=ACTOR_EFFORT,
        settings_path=ACTOR_SETTINGS,
        add_dir=[LESSONS_ACTOR_DIR, LESSONS_ENVIRONMENT_DIR],
        permission_mode="acceptEdits", session_id=session_id,
    )
    _copy_transcript(session_id, learning_run_dir / "actor_trace.jsonl")
    return story


def invoke_actor_benign(
    alert_path: Path,
    case_entities: str,
    alert_rule_key: str,
    learning_run_dir: Path,
) -> str:
    """Benign (ops-teamer) actor for the FP direction — no MITRE menu.

    Reconstructs the authorized operation from the alert + the environment lessons
    it retrieves via ``lessons_env_retrieve.py``, keyed by ``case_entities`` +
    ``alert_rule_key`` (both handed in so the actor uses the same deterministic
    anchor the observation + forward-check use).
    """
    user = (
        _section("alert", alert_path.read_text())
        + _section("alert_rule_id", alert_rule_key)
        + _section("case_entities", case_entities)
    )
    session_id = str(uuid.uuid4())
    story = _run_claude(
        ACTOR_BENIGN_PROMPT, user, model=BENIGN_ACTOR_MODEL, effort=BENIGN_ACTOR_EFFORT,
        settings_path=BENIGN_ACTOR_SETTINGS, add_dir=LESSONS_ENVIRONMENT_DIR,
        permission_mode="acceptEdits", session_id=session_id,
    )
    _copy_transcript(session_id, learning_run_dir / "actor_benign_trace.jsonl")
    return story


def telemetry_vocabulary(lead_sequence: dict) -> str:
    """Routable-vocabulary block for the footprint prompt, derived from the leads'
    structured ``filters`` — the *canonical* layer the router matches on, not the
    vendor-physical fields in raw sample docs.

    Two lists, both lifted straight from ``filters`` so they align with the router
    by construction (no closed field-name list, no physical/logical guesswork):

    - ``data_source`` tokens — distinct ``filters.index`` with the trailing
      wildcard/separator stripped (``logs-falco.alerts-*`` -> ``logs-falco.alerts``),
      i.e. the exact value ``event_satisfies`` compares ``data_source`` against.
    - canonical event field names — distinct ``filters.predicates[].event_attr``,
      the names the router reads off each event.

    Returns ``""`` when no lead carries a structured filter (nothing to ground;
    the footprint falls back to descriptive tokens and the run is degenerate
    anyway).
    """
    tokens: list[str] = []
    fields: list[str] = []
    for entry in lead_sequence.get("entries") or []:
        for q in entry.get("queries") or []:
            f = q.get("filters")
            if not isinstance(f, dict):
                continue
            idx = f.get("index")
            if isinstance(idx, str) and idx:
                core = idx.rstrip("*").rstrip("-.")   # mirror event_satisfies' core
                if core:
                    tokens.append(core)
            for pred in f.get("predicates") or []:
                attr = pred.get("event_attr") if isinstance(pred, dict) else None
                for a in (attr if isinstance(attr, (list, tuple)) else [attr]):
                    if isinstance(a, str) and a:
                        fields.append(a)
    tokens = list(dict.fromkeys(tokens))   # dedup, preserve first-seen order
    fields = list(dict.fromkeys(fields))
    if not tokens and not fields:
        return ""
    out: list[str] = []
    if tokens:
        out.append(
            "Streams this deployment's telemetry lands in — emit `data_source` as one "
            "of these exact tokens (one stream per event). For a stream not listed, use "
            "a short descriptive token (it will read as uncovered, which is correct):"
        )
        out += [f"- {t}" for t in tokens]
    if fields:
        if out:
            out.append("")
        out.append(
            "Canonical field names — when an event carries one of these entities, use "
            "exactly this key (other native fields are still fine to add):"
        )
        out += [f"- {a}" for a in fields]
    return "\n".join(out)


def invoke_footprint(
    alert_path: Path, actor_story_path: Path, vocabulary: str = ""
) -> str:
    """Oracle stage A: enumerate the story's telemetry footprint.

    Sees the alert, the story, and the deployment's telemetry *vocabulary*
    (data_source tokens + canonical field names from the leads' filters) — but
    **not** the leads themselves: no queries, filters, windows, or coverage, so
    there is still nothing to overload. The vocabulary grounds the tokens the
    footprint emits so stage B (``_oracle_router.route``) can place each event by
    containment instead of relying on the model to guess vendor index names.
    """
    user = (
        _section("alert", alert_path.read_text())
        + _section("actor_story", actor_story_path.read_text())
    )
    if vocabulary:
        user += _section(
            "telemetry_vocabulary", vocabulary,
            "the deployment's data_source tokens + canonical field names; emit events "
            "using these so they land in the right stream. Vocabulary only — NOT the "
            "defender's queries, filters, windows, or coverage.",
        )
    return _run_claude(
        FOOTPRINT_PROMPT, user, model=FOOTPRINT_MODEL, effort=FOOTPRINT_EFFORT
    )


def _invoke_judge(
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    alert_path: Path,
    investigation_path: Path,
    lead_sequence_path: Path,
    actor_story_path: Path,
    projected_telemetry_path: Path,
    learning_run_dir: Path,
) -> str:
    user = (
        _section("alert", alert_path.read_text())
        + _section("investigation", investigation_path.read_text())
        + _section(
            "lead_sequence", lead_sequence_path.read_text(),
            "the defender's actual executed queries per lead position — the "
            "authoritative record of what was queried (index, filter, window). "
            "investigation.md is the narrative; this is ground truth for coverage.",
        )
        + _section("actor_story", actor_story_path.read_text())
        + _section("projected_telemetry", projected_telemetry_path.read_text())
    )
    session_id = str(uuid.uuid4())
    _log(f"step={label} session_id={session_id}")
    try:
        return _run_claude(
            prompt_path, user, model=model, session_id=session_id, effort=effort
        )
    finally:
        _copy_transcript(session_id, learning_run_dir / trace_name)


def invoke_judge(alert_path, investigation_path, lead_sequence_path, actor_story_path,
                 projected_telemetry_path, learning_run_dir) -> str:
    return _invoke_judge(
        JUDGE_PROMPT, JUDGE_MODEL, JUDGE_EFFORT, "judge_trace.jsonl", "judge",
        alert_path, investigation_path, lead_sequence_path, actor_story_path,
        projected_telemetry_path, learning_run_dir,
    )


def invoke_judge_benign(alert_path, investigation_path, lead_sequence_path,
                        actor_story_path, projected_telemetry_path,
                        learning_run_dir) -> str:
    """FP-direction judge: a routine story that SURVIVES is the FP signal; emits the
    environment-observation stream alongside defender findings."""
    return _invoke_judge(
        JUDGE_BENIGN_PROMPT, BENIGN_JUDGE_MODEL, BENIGN_JUDGE_EFFORT,
        "judge_benign_trace.jsonl", "judge-benign",
        alert_path, investigation_path, lead_sequence_path, actor_story_path,
        projected_telemetry_path, learning_run_dir,
    )


# ---------------------------------------------------------------------------
# The injectable port + its claude -p adapter
# ---------------------------------------------------------------------------


class Subagents(Protocol):
    def actor(self, run_dir: Path, learning_run_dir: Path) -> str: ...
    def actor_benign(self, run_dir: Path, learning_run_dir: Path,
                     alert_rule_key: str) -> str: ...
    def footprint(self, run_dir: Path, actor_story_path: Path) -> str: ...
    def judge(self, run_dir: Path, actor_story_path: Path,
              projected_telemetry_path: Path, learning_run_dir: Path) -> str: ...
    def judge_benign(self, run_dir: Path, actor_story_path: Path,
                     projected_telemetry_path: Path, learning_run_dir: Path) -> str: ...


class ClaudePrintSubagents:
    """Default adapter — assembles each step's inputs and shells out to ``claude -p``."""

    def actor(self, run_dir: Path, learning_run_dir: Path) -> str:
        actor_input_path = learning_run_dir / "actor_input.yaml"
        project_actor_input(run_dir, actor_input_path)
        return invoke_actor(run_dir / "alert.json", actor_input_path, learning_run_dir)

    def actor_benign(self, run_dir: Path, learning_run_dir: Path,
                     alert_rule_key: str) -> str:
        case_entities = extract_case_entities(run_dir / "investigation.md")
        return invoke_actor_benign(
            run_dir / "alert.json", case_entities, alert_rule_key, learning_run_dir
        )

    def footprint(self, run_dir: Path, actor_story_path: Path) -> str:
        lead_sequence = yaml.safe_load((run_dir / "lead_sequence.yaml").read_text()) or {}
        vocab = telemetry_vocabulary(lead_sequence)
        return invoke_footprint(run_dir / "alert.json", actor_story_path, vocab)

    def judge(self, run_dir: Path, actor_story_path: Path,
              projected_telemetry_path: Path, learning_run_dir: Path) -> str:
        return invoke_judge(
            run_dir / "alert.json", run_dir / "investigation.md",
            run_dir / "lead_sequence.yaml",
            actor_story_path, projected_telemetry_path, learning_run_dir,
        )

    def judge_benign(self, run_dir: Path, actor_story_path: Path,
                     projected_telemetry_path: Path, learning_run_dir: Path) -> str:
        return invoke_judge_benign(
            run_dir / "alert.json", run_dir / "investigation.md",
            run_dir / "lead_sequence.yaml",
            actor_story_path, projected_telemetry_path, learning_run_dir,
        )
