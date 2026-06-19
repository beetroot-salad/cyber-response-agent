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
import os
import random
import shutil
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from defender.learning import lead_repository
from defender.learning import mitre_corpus
from defender.learning._loop_comparison import (
    build_comparison,
    judge_settings_dict,
    parse_investigation_companion,
    render_manifest,
    render_synthesis,
    write_comparison_files,
)
from defender.learning._loop_oracle import (
    assemble_oracle_doc,
    build_lead_user_prompt,
    lead_sample_text,
    parse_lead_events,
)
from defender.learning._loop_persist import derive_alert_rule_key
from defender.learning._loop_validate import dump_oracle_doc
from defender.learning._prologue import extract_case_entities

from defender.learning._loop_config import (
    ACTOR_BENIGN_PROMPT,
    ACTOR_EFFORT,
    ACTOR_MODEL,
    ACTOR_PROMPT,
    ACTOR_SETTINGS,
    BENIGN_ACTOR_EFFORT,
    BENIGN_ACTOR_MODEL,
    BENIGN_ACTOR_SETTINGS,
    JudgeWiring,
    LESSONS_ACTOR_DIR,
    LESSONS_ENVIRONMENT_DIR,
    LoopError,
    ORACLE_EFFORT,
    ORACLE_MAX_CONCURRENCY,
    ORACLE_MODEL,
    ORACLE_PROMPT,
    REPO_ROOT,
    SUBAGENT_TIMEOUT,
    _log,
)


# ---------------------------------------------------------------------------
# claude -p transport
# ---------------------------------------------------------------------------


def _subscription_env() -> dict[str, str]:
    """Env for the ``claude -p`` subagent: strip ``ANTHROPIC_API_KEY`` so the
    call bills against the subscription, never the metered first-party key
    (reserved for the PydanticAI engine — see defender/run_pai.py)."""
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    return env


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
        env=_subscription_env(),
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


def invoke_oracle_lead(lead, story: str, sample_text: str) -> list:
    """Project one lead. Sees only this lead — sanitized ``what_to_summarize`` +
    queries + a scrubbed sample event — plus the story; no goal, no alert, no other lead.
    Returns the lead's ``events`` list (mappings, a single baseline-diff marker, or empty).

    ``lead`` is a ``lead_repository.JoinedLead``.
    """
    user = build_lead_user_prompt(lead, story, sample_text)
    raw = _run_claude(ORACLE_PROMPT, user, model=ORACLE_MODEL, effort=ORACLE_EFFORT)
    return parse_lead_events(raw, lead.lead_id)


def invoke_oracle(run_dir: Path, actor_story_path: Path) -> str:
    """Run the per-lead oracle over a run's leads and assemble the doc.

    One ``claude -p`` per lead, fanned out concurrently (bounded by
    ``ORACLE_MAX_CONCURRENCY``); results are reassembled in lead order into the
    ``{projections: [{lead_id, events}]}`` doc the validator + judge consume. Reads the
    leads from the joined two-table surface. Returns the serialized YAML string.
    """
    story = actor_story_path.read_text()
    leads = lead_repository.joined(run_dir)
    samples = [lead_sample_text(jl) for jl in leads]
    max_workers = max(1, min(ORACLE_MAX_CONCURRENCY, len(leads) or 1))
    events_per_lead: list = [None] * len(leads)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_to_idx = {
            pool.submit(invoke_oracle_lead, jl, story, s): i
            for i, (jl, s) in enumerate(zip(leads, samples))
        }
        try:
            # Surface the first failing lead as soon as it completes (rather than after
            # every sibling finishes) and cancel any leads still queued behind the cap.
            for fut in as_completed(fut_to_idx):
                events_per_lead[fut_to_idx[fut]] = fut.result()
        except Exception:
            for f in fut_to_idx:
                f.cancel()
            raise
    projections = [
        (jl.lead_id, events) for jl, events in zip(leads, events_per_lead)
    ]
    return dump_oracle_doc(assemble_oracle_doc(projections))


def _run_judge_claude(
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    *,
    settings_path: Path | None = None,
    add_dir: Path | list[Path] | None = None,
    permission_mode: str | None = None,
) -> str:
    """Shared tail for both judge paths: session id + ``claude -p`` + transcript copy."""
    session_id = str(uuid.uuid4())
    _log(f"step={label} session_id={session_id}")
    try:
        return _run_claude(
            prompt_path, user, model=model, session_id=session_id, effort=effort,
            settings_path=settings_path, add_dir=add_dir, permission_mode=permission_mode,
        )
    finally:
        _copy_transcript(session_id, learning_run_dir / trace_name)


@dataclass(frozen=True)
class JudgeInvocation:
    """The assembled grounded-judge call (either direction) — a pure-ish seam for testing."""

    user_text: str
    add_dirs: list
    settings_path: Path
    comparison_paths: list


def build_judge_invocation(
    run_dir: Path,
    actor_story_path: Path,
    projected_telemetry_path: Path,
    learning_run_dir: Path,
    *,
    comparison_dirname: str = "comparison",
    settings_name: str = "judge-settings.resolved.json",
) -> JudgeInvocation:
    """Assemble the grounded judge call: write the per-lead comparison files + the per-run
    read-only settings, and build the context message. The comparison join + synthesis are
    the structural grounding (the judge can't avoid seeing the actuals); jq over the
    add-dir'd ``gather_raw/`` is its discretionary verification surface for absence-checks.

    ``comparison_dirname`` / ``settings_name`` are per-direction so the adversarial and
    benign legs — which run **concurrently** on an ``inconclusive`` case over a shared
    ``learning_run_dir`` — write disjoint files: their projections differ, so a single
    shared ``comparison/{lead_id}.md`` would let one leg clobber the other's grounding.
    """
    run_dir = Path(run_dir)
    learning_run_dir = Path(learning_run_dir)
    gather_raw = run_dir / "gather_raw"
    comparison_dir = learning_run_dir / comparison_dirname

    companion = parse_investigation_companion(run_dir)
    comparisons = build_comparison(run_dir, projected_telemetry_path, companion=companion)
    comparison_paths = write_comparison_files(comparisons, comparison_dir, gather_raw)

    settings_path = learning_run_dir / settings_name
    settings_path.write_text(
        json.dumps(judge_settings_dict(gather_raw, comparison_dir), indent=2)
    )
    add_dirs = [d for d in (gather_raw, comparison_dir) if d.is_dir()]

    report = run_dir / "report.md"
    user = (
        _section("alert", (run_dir / "alert.json").read_text())
        + _section(
            "report", report.read_text() if report.is_file() else "(report.md missing)",
            "the defender's disposition + rationale — the claim you are scoring",
        )
        + _section("actor_story", actor_story_path.read_text())
        + _section(
            "synthesis", render_synthesis(companion),
            "the defender's cross-lead hypotheses, belief movement, authorization "
            "reasoning, and conclusion — WHY it reached the disposition",
        )
        + _section(
            "coverage_manifest", lead_repository.render_joined_yaml(run_dir),
            "the authoritative record of what was queried per lead (id, params, "
            "status) — ground truth for coverage",
        )
        + _section(
            "comparison_files", render_manifest(comparisons),
            f"per-lead projection-vs-actual files under {comparison_dir} — read each at "
            f"its turn; query the full payloads under {gather_raw} with jq to check "
            "absence (the refute primitive), never inferring it from the sample",
        )
    )
    return JudgeInvocation(
        user_text=user, add_dirs=add_dirs, settings_path=settings_path,
        comparison_paths=comparison_paths,
    )


def invoke_judge(wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
                 projected_telemetry_path: Path, learning_run_dir: Path) -> str:
    """Grounded judge for either direction: write the per-lead comparison files +
    read-only settings (under the wiring's per-direction names), then score against the
    actual evidence (per-lead comparison files + jq over ``gather_raw/``), not the
    narrative. The direction rides in ``wiring`` (adversarial vs benign prompt/model/
    effort + disjoint comparison/settings names); for the benign leg, a routine story
    that SURVIVES is the FP signal."""
    inv = build_judge_invocation(
        run_dir, actor_story_path, projected_telemetry_path, learning_run_dir,
        comparison_dirname=wiring.comparison_dirname, settings_name=wiring.settings_name,
    )
    return _run_judge_claude(
        wiring.prompt_path, wiring.model, wiring.effort, wiring.trace_name, wiring.label,
        inv.user_text, learning_run_dir,
        settings_path=inv.settings_path, add_dir=inv.add_dirs, permission_mode=None,
    )


# ---------------------------------------------------------------------------
# The injectable port + its claude -p adapter
# ---------------------------------------------------------------------------


class Subagents(Protocol):
    def actor(self, run_dir: Path, learning_run_dir: Path) -> str: ...
    def actor_benign(self, run_dir: Path, learning_run_dir: Path,
                     alert_rule_key: str) -> str: ...
    def oracle(self, run_dir: Path, actor_story_path: Path) -> str: ...
    def judge(self, wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
              projected_telemetry_path: Path, learning_run_dir: Path) -> str: ...


class ClaudePrintSubagents:
    """Default adapter — assembles each step's inputs and shells out to ``claude -p``."""

    def actor(self, run_dir: Path, learning_run_dir: Path) -> str:
        # The actor-facing view is queries-only (no goal / what_to_summarize) —
        # written as a real side-artifact for transcripts/visualizers.
        actor_input_path = learning_run_dir / "actor_input.yaml"
        actor_input_path.write_text(lead_repository.render_actor_view_yaml(run_dir))
        return invoke_actor(run_dir / "alert.json", actor_input_path, learning_run_dir)

    def actor_benign(self, run_dir: Path, learning_run_dir: Path,
                     alert_rule_key: str) -> str:
        case_entities = extract_case_entities(run_dir / "investigation.md")
        return invoke_actor_benign(
            run_dir / "alert.json", case_entities, alert_rule_key, learning_run_dir
        )

    def oracle(self, run_dir: Path, actor_story_path: Path) -> str:
        return invoke_oracle(run_dir, actor_story_path)

    def judge(self, wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
              projected_telemetry_path: Path, learning_run_dir: Path) -> str:
        return invoke_judge(
            wiring, run_dir, actor_story_path, projected_telemetry_path, learning_run_dir,
        )
