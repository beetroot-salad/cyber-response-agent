#!/usr/bin/env python3
"""Defender learning-loop orchestrator.

Per-run-dir API: ``loop.py <run_dir>``. One case at a time.

Steps:
  1. Normalize disposition from ``report.md`` YAML frontmatter (no
     regex fallback). Skip if disposition ``∉ {benign, inconclusive}``.
  2. Project ``lead_sequence.yaml`` to the actor view via
     ``defender/scripts/project_lead_sequence.py --actor-out``.
  3. Invoke the actor (gray-box adversarial). SKIP short-circuits to
     persist + exit with no findings.
  4. Invoke the telemetry oracle against alert + actor story + full
     lead_sequence + per-lead exemplars. Output is per-lead synthesized
     events: "if the attack had happened, this is what each lead would
     have surfaced." Parse YAML, validate shape.
  5. Invoke the judge against alert + investigation + actor story +
     projected_telemetry. Parse YAML, validate shape.
  6. Persist per-run artifacts under ``defender/learning/runs/<run_id>/``.
  7. Filter ``detection-confirmed`` (audit-only) and append the rest to
     ``defender/learning/_pending/findings.jsonl``.
  8. If pending count >= ``LEARNING_AUTHOR_THRESHOLD`` (default 5), call
     ``author.run_batch`` — see ``defender/learning/author.py``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Re-exec into defender/.venv if launched against a different interpreter.
# Compare unresolved paths — the venv python is typically a symlink to the
# system interpreter, so .resolve() would collapse both sides and skip the
# re-exec even when site-packages differ.
_VENV_PY = Path(__file__).resolve().parents[2] / "defender" / ".venv" / "bin" / "python3"
if _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import fcntl
import hashlib
import json
import random
import re
import shutil
import subprocess
from typing import Any

import yaml

import mitre_corpus


REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
RUNS_DIR = LEARNING_DIR / "runs"
PENDING_DIR = LEARNING_DIR / "_pending"
PENDING_FILE = PENDING_DIR / "findings.jsonl"
ACTOR_OBSERVATIONS_FILE = PENDING_DIR / "actor_observations.jsonl"
ACTOR_OBSERVATIONS_CONSUMED_FILE = PENDING_DIR / "actor_observations.consumed.jsonl"
ACTOR_OBSERVATIONS_LOCK_FILE = PENDING_DIR / ".actor.lock"

# Benign (false-positive) direction — environment-observation queue.
ENVIRONMENT_OBSERVATIONS_FILE = PENDING_DIR / "environment_observations.jsonl"
ENVIRONMENT_OBSERVATIONS_CONSUMED_FILE = (
    PENDING_DIR / "environment_observations.consumed.jsonl"
)
ENVIRONMENT_OBSERVATIONS_LOCK_FILE = PENDING_DIR / ".environment.lock"

ACTOR_PROMPT = LEARNING_DIR / "actor.md"
ORACLE_PROMPT = LEARNING_DIR / "oracle.md"
JUDGE_PROMPT = LEARNING_DIR / "judge.md"
JUDGE_BENIGN_PROMPT = LEARNING_DIR / "judge_benign.md"
PROJECT_SCRIPT = REPO_ROOT / "defender" / "scripts" / "project_lead_sequence.py"

DISPOSITION_ENUM = {"benign", "inconclusive", "malicious"}
# Direction dispatch: the adversarial actor hunts false negatives on
# closed/uncertain dispositions; the benign actor hunts false positives on
# escalated/uncertain ones. ``inconclusive`` runs both.
ADVERSARIAL_DISPOSITIONS = {"benign", "inconclusive"}
BENIGN_DISPOSITIONS = {"malicious", "inconclusive"}

GROUND_TRUTH_FILE = "ground_truth.yaml"

OUTCOME_ENUM = {"caught", "survived", "undecidable", "incoherent", "skip-passthrough"}
# Benign judge outcomes mirror the adversarial enum: ``survived`` always means
# "the defender failed to handle the story" — FN-risk adversarially, FP-risk here.
BENIGN_OUTCOME_ENUM = {
    "survived",
    "refuted",
    "undecidable",
    "incoherent",
    "skip-passthrough",
}
QUEUEABLE_FINDING_TYPES = {
    "lead-set",
    "lead-quality",
    "analyze-discipline",
    "observability",
}
ALL_FINDING_TYPES = QUEUEABLE_FINDING_TYPES | {"detection-confirmed"}
# Benign defender findings share the queueable types; ``disposition-confirmed``
# is the FP-direction audit-only type (the adversarial ``detection-confirmed``
# analog — a justified escalation, filtered out of the queued lessons).
BENIGN_ALL_FINDING_TYPES = QUEUEABLE_FINDING_TYPES | {"disposition-confirmed"}
ACTOR_OBSERVATION_TYPES = {"misprediction", "framing-choice", "discarded-class"}

ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "claude-sonnet-4-6")
BENIGN_ACTOR_MODEL = os.environ.get("BENIGN_ACTOR_MODEL", "claude-sonnet-4-6")
ORACLE_MODEL = os.environ.get("ORACLE_MODEL", "claude-sonnet-4-6")
JUDGE_MODEL = os.environ.get("JUDGE_MODEL", "claude-sonnet-4-6")
BENIGN_JUDGE_MODEL = os.environ.get("BENIGN_JUDGE_MODEL", "claude-sonnet-4-6")
SUBAGENT_TIMEOUT = int(os.environ.get("LEARNING_SUBAGENT_TIMEOUT_SECONDS", "450"))

ACTOR_SETTINGS = LEARNING_DIR / "actor-settings.json"
LESSONS_ACTOR_DIR = REPO_ROOT / "defender" / "lessons-actor"

ACTOR_BENIGN_PROMPT = LEARNING_DIR / "actor_benign.md"
BENIGN_ACTOR_SETTINGS = LEARNING_DIR / "benign-actor-settings.json"
LESSONS_ENVIRONMENT_DIR = REPO_ROOT / "defender" / "lessons-environment"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LoopError(Exception):
    """Fatal orchestrator error — caller should stop processing this run."""


# ---------------------------------------------------------------------------
# Step 1: Normalize disposition
# ---------------------------------------------------------------------------


def _parse_frontmatter(text: str) -> dict[str, Any]:
    """Parse leading ``---`` / ``---`` YAML frontmatter. Strict."""
    if not text.startswith("---\n"):
        raise LoopError("report.md missing leading '---' frontmatter fence")
    end = text.find("\n---", 4)
    if end == -1:
        raise LoopError("report.md missing closing '---' frontmatter fence")
    block = text[4:end]
    try:
        data = yaml.safe_load(block)
    except yaml.YAMLError as e:
        raise LoopError(f"report.md frontmatter is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise LoopError("report.md frontmatter is not a YAML mapping")
    return data


def normalize_disposition(report_path: Path) -> str:
    if not report_path.is_file():
        raise LoopError(f"report.md not found: {report_path}")
    text = report_path.read_text()
    try:
        fm = _parse_frontmatter(text)
    except LoopError as e:
        head = "\n".join(text.splitlines()[:30])
        raise LoopError(f"{e}\n--- {report_path} (head) ---\n{head}") from e
    disp = fm.get("disposition")
    if disp not in DISPOSITION_ENUM:
        raise LoopError(
            f"report.md disposition={disp!r} not in {sorted(DISPOSITION_ENUM)}"
        )
    return disp


# ---------------------------------------------------------------------------
# Step 2: Actor projection (delegates to project_lead_sequence.py)
# ---------------------------------------------------------------------------


def project_actor_input(run_dir: Path, actor_out: Path) -> None:
    cmd = [
        sys.executable,
        str(PROJECT_SCRIPT),
        str(run_dir),
        "--actor-out",
        str(actor_out),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise LoopError(
            f"project_lead_sequence.py failed (rc={proc.returncode}):\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    if not actor_out.is_file():
        raise LoopError(f"actor projection did not produce {actor_out}")


# ---------------------------------------------------------------------------
# Step 3 + 4: Subagent invocation
# ---------------------------------------------------------------------------


def _run_claude(
    system_prompt_path: Path,
    user_prompt: str,
    model: str,
    *,
    settings_path: Path | None = None,
    add_dir: Path | None = None,
    permission_mode: str | None = None,
    session_id: str | None = None,
) -> str:
    """One-shot ``claude -p`` call. Returns stdout.

    Optional kwargs scope the agent's tool surface (settings file +
    add-dir + permission-mode) and pin the session id so the caller
    can locate the persistent transcript at
    ``~/.claude/projects/-{cwd}/{session_id}.jsonl`` after the call
    returns. The whole subprocess is bounded by ``SUBAGENT_TIMEOUT``.
    """
    # stream-json + concat all assistant text messages. `--output-format text`
    # returns only the final assistant message, which silently drops earlier
    # assistant text when the prompt does tool calls mid-output (e.g. the
    # actor emits Section 0, consults the lessons corpus, then emits Sections
    # 1-3 — text mode loses Section 0). Concatenating across messages keeps
    # the prompt's design intent intact regardless of tool use.
    cmd = _build_run_claude_cmd(
        system_prompt_path, model,
        settings_path=settings_path, add_dir=add_dir,
        permission_mode=permission_mode, session_id=session_id,
    )
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
            f"claude -p failed (rc={proc.returncode}):\n"
            f"stderr: {proc.stderr[-2000:]}"
        )
    return "\n\n".join(_extract_assistant_text_parts(proc.stdout))


def _build_run_claude_cmd(
    system_prompt_path: Path,
    model: str,
    *,
    settings_path: Path | None,
    add_dir: Path | None,
    permission_mode: str | None,
    session_id: str | None,
) -> list[str]:
    cmd = [
        "claude",
        "-p",
        "--model", model,
        "--output-format", "stream-json",
        "--verbose",  # required for stream-json with -p
        "--system-prompt-file", str(system_prompt_path),
    ]
    if settings_path is not None:
        cmd += ["--settings", str(settings_path)]
    if add_dir is not None:
        cmd += ["--add-dir", str(add_dir)]
    if permission_mode is not None:
        cmd += ["--permission-mode", permission_mode]
    if session_id is not None:
        cmd += ["--session-id", session_id]
    return cmd


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
    """Persistent transcript path Claude Code writes for ``--session-id``.

    Path = ``~/.claude/projects/{sanitized-cwd}/{session_id}.jsonl``
    where sanitization is ``cwd.replace('/', '-')`` (leading ``/`` →
    leading ``-`` since the path starts with a slash).
    """
    cwd_slug = str(REPO_ROOT).replace("/", "-")
    return Path.home() / ".claude" / "projects" / cwd_slug / f"{session_id}.jsonl"


def _actor_seed(run_id: str) -> int:
    """Stable per-run seed for menu sampling and archetype choice."""
    return int(hashlib.sha256(run_id.encode()).hexdigest()[:8], 16)


def invoke_actor(
    alert_path: Path,
    actor_input_path: Path,
    learning_run_dir: Path,
) -> str:
    rng = random.Random(_actor_seed(learning_run_dir.name))
    archetype = rng.choice(["internal", "external"])
    menu = mitre_corpus.sample_menu(rng)
    menu_text = mitre_corpus.format_menu(menu)

    (learning_run_dir / "actor_archetype.txt").write_text(archetype + "\n")
    (learning_run_dir / "actor_menu.txt").write_text(menu_text + "\n")

    user = (
        "<alert>\n"
        f"{alert_path.read_text().rstrip()}\n"
        "</alert>\n"
        "<actor_input>\n"
        "<!-- lead sequence projected for the actor -->\n"
        f"{actor_input_path.read_text().rstrip()}\n"
        "</actor_input>\n"
        "<actor_archetype>\n"
        f"{archetype}\n"
        "</actor_archetype>\n"
        "<mitre_menu>\n"
        f"{menu_text}\n"
        "</mitre_menu>\n"
    )
    import uuid as _uuid
    session_id = str(_uuid.uuid4())
    story = _run_claude(
        ACTOR_PROMPT,
        user,
        model=ACTOR_MODEL,
        settings_path=ACTOR_SETTINGS,
        add_dir=LESSONS_ACTOR_DIR,
        permission_mode="acceptEdits",
        session_id=session_id,
    )
    src = _transcript_path(session_id)
    dst = learning_run_dir / "actor_trace.jsonl"
    if src.is_file():
        shutil.copy2(src, dst)
    else:
        _log(f"actor transcript not found at {src}; skipping actor_trace.jsonl")
    return story


def extract_case_entities(investigation_path: Path) -> str:
    """Extract the prologue's classified entities as `type:class` tokens.

    The benign actor retrieves environment lessons by classification. The
    case entities come from the CONTEXTUALIZE prologue (`:V prologue.vertices`),
    which is alert-derived — not lead/gather output — so handing them to the
    actor preserves its blind-to-leads stance. Returns a comma-joined,
    de-duplicated `type:class` string (e.g. ``process:nc,socket:tcp``); empty
    string if the file or block is absent.

    The dense row is ``id|type|class|ident|attrs?`` and the `class` column is
    already the `type:class`-qualified token (`process:nc`, `socket:tcp`) — i.e.
    exactly the selector vocabulary ``lessons_env_retrieve`` parses. Emit it
    verbatim; re-joining it to the `type` column would double-prefix
    (`process:process:nc`) and never match a `{type, class}` lesson selector.
    """
    if not investigation_path.is_file():
        return ""
    seen: list[str] = []
    in_block = False
    for line in investigation_path.read_text().splitlines():
        s = line.strip()
        if s.startswith(":V prologue.vertices"):
            in_block = True
            continue
        if in_block:
            if not s or s.startswith(":") or s.startswith("```"):
                break
            cols = s.split("|")
            if len(cols) >= 3 and cols[0].strip().startswith("v-"):
                tok = cols[2].strip()
                if tok and tok not in seen:
                    seen.append(tok)
    return ",".join(seen)


def invoke_actor_benign(
    alert_path: Path,
    case_entities: str,
    learning_run_dir: Path,
) -> str:
    """Run the benign (ops-teamer) actor for the false-positive direction.

    Mirrors ``invoke_actor`` but takes no MITRE menu: the actor reconstructs
    the authorized operation from the alert and the environment lessons it
    retrieves (by ``case_entities`` + the alert's rule id) via
    ``lessons_env_retrieve.py``. Returns the story (or a ``SKIP:`` line).
    """
    user = (
        "<alert>\n"
        f"{alert_path.read_text().rstrip()}\n"
        "</alert>\n"
        "<case_entities>\n"
        f"{case_entities}\n"
        "</case_entities>\n"
    )
    import uuid as _uuid
    session_id = str(_uuid.uuid4())
    story = _run_claude(
        ACTOR_BENIGN_PROMPT,
        user,
        model=BENIGN_ACTOR_MODEL,
        settings_path=BENIGN_ACTOR_SETTINGS,
        add_dir=LESSONS_ENVIRONMENT_DIR,
        permission_mode="acceptEdits",
        session_id=session_id,
    )
    src = _transcript_path(session_id)
    dst = learning_run_dir / "actor_benign_trace.jsonl"
    if src.is_file():
        shutil.copy2(src, dst)
    else:
        _log(f"benign actor transcript not found at {src}; skipping actor_benign_trace.jsonl")
    return story


_RAW_SAMPLE_HEADER_RE = re.compile(r"^### Raw Sample Events\b.*$", re.MULTILINE)
_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)


def _scrub_skeleton(value, key=None):
    """Replace concrete leaf values with a type/field skeleton.

    Strings become `<key>` (or `<string>` if no key context); numbers go
    to 0; booleans go to `false`; nulls stay null. Lists collapse to a
    single scrubbed element preserving inner shape. Dicts recurse,
    threading the parent key down so child strings can be tagged with
    their field name.
    """
    if isinstance(value, dict):
        return {k: _scrub_skeleton(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_skeleton(value[0], key)] if value else []
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return 0
    if isinstance(value, str):
        return f"<{key}>" if key else "<string>"
    return value  # null


def redact_exemplar(text: str) -> str:
    """Reduce a `gather_raw/{position}.json` to a schema-only skeleton.

    The oracle is supposed to project events from the actor story alone;
    handing it the full gather_raw leaks the *actual* lead result and
    contaminates the projected-vs-actual comparison the judge later does.

    Two-stage redaction:
      1. Drop everything outside the `### Raw Sample Events` block
         (Summary, Aggregations, Count Breakdown, Sample Events) so
         counts and per-event values from non-schema sections are gone.
      2. Inside the Raw Sample Events block, parse the embedded JSON and
         replace every concrete leaf with a `<field-name>` placeholder
         (or 0 / false / null for non-strings). The oracle sees the
         field/nesting/type skeleton with no values it could mirror.

    If no Raw Sample Events block is present, return a placeholder; the
    oracle has the system + template + params from `lead_sequence.yaml`
    and must project shape from those.
    """
    header_m = _RAW_SAMPLE_HEADER_RE.search(text)
    if not header_m:
        return "(no schema sample available for this position)"
    block = text[header_m.start():]
    header_line = block.split("\n", 1)[0]

    json_m = _JSON_BLOCK_RE.search(block)
    if not json_m:
        return f"{header_line}\n(schema sample not in JSON form; skeleton unavailable)"
    try:
        sample = json.loads(json_m.group(1))
    except json.JSONDecodeError:
        return f"{header_line}\n(could not parse schema sample as JSON; skeleton unavailable)"

    skeleton = _scrub_skeleton(sample)
    return f"{header_line} (values scrubbed — type/field skeleton only)\n\n```json\n{json.dumps(skeleton, indent=2)}\n```"


def assemble_exemplar_bundle(source_run_dir: Path, lead_sequence_text: str) -> str:
    """Concatenate per-lead schema samples — one block per lead position.

    Only the `### Raw Sample Events` portion of each `gather_raw/{position}.json`
    is included; counts, aggregations, and sample summaries are dropped so
    the oracle cannot mirror the defender's actual results.
    """
    doc = yaml.safe_load(lead_sequence_text)
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        raise LoopError("lead_sequence.yaml has no `entries` list")
    blocks: list[str] = []
    for entry in doc["entries"]:
        position = entry.get("position")
        queries = entry.get("queries") or []
        qid = (queries[0] or {}).get("id", "?") if queries else "?"
        result_ref = entry.get("result_ref") or f"gather_raw/{position}.json"
        path = source_run_dir / result_ref
        if path.is_file():
            body = redact_exemplar(path.read_text())
        else:
            body = "(no exemplars on disk for this position)"
        blocks.append(
            f'<exemplar position="{position}" query="{qid}" result_ref="{result_ref}">\n'
            f"{body}\n"
            f"</exemplar>"
        )
    return "\n".join(blocks)


def invoke_oracle(
    alert_path: Path,
    actor_story_path: Path,
    lead_sequence_path: Path,
    exemplar_bundle: str,
) -> str:
    user = (
        "<alert>\n"
        f"{alert_path.read_text().rstrip()}\n"
        "</alert>\n"
        "<actor_story>\n"
        f"{actor_story_path.read_text().rstrip()}\n"
        "</actor_story>\n"
        "<lead_sequence>\n"
        f"{lead_sequence_path.read_text().rstrip()}\n"
        "</lead_sequence>\n"
        "<exemplars>\n"
        "<!-- defender's actual gather_raw/{position}.json — schema reference, values scrubbed -->\n"
        f"{exemplar_bundle.rstrip()}\n"
        "</exemplars>\n"
    )
    return _run_claude(ORACLE_PROMPT, user, model=ORACLE_MODEL)


def invoke_judge(
    alert_path: Path,
    investigation_path: Path,
    actor_story_path: Path,
    projected_telemetry_path: Path,
    learning_run_dir: Path,
) -> str:
    user = (
        "<alert>\n"
        f"{alert_path.read_text().rstrip()}\n"
        "</alert>\n"
        "<investigation>\n"
        f"{investigation_path.read_text().rstrip()}\n"
        "</investigation>\n"
        "<actor_story>\n"
        f"{actor_story_path.read_text().rstrip()}\n"
        "</actor_story>\n"
        "<projected_telemetry>\n"
        f"{projected_telemetry_path.read_text().rstrip()}\n"
        "</projected_telemetry>\n"
    )
    import uuid as _uuid
    session_id = str(_uuid.uuid4())
    _log(f"step=judge session_id={session_id}")
    try:
        out = _run_claude(JUDGE_PROMPT, user, model=JUDGE_MODEL, session_id=session_id)
    finally:
        src = _transcript_path(session_id)
        dst = learning_run_dir / "judge_trace.jsonl"
        if src.is_file():
            shutil.copy2(src, dst)
    return out


def invoke_judge_benign(
    alert_path: Path,
    investigation_path: Path,
    actor_story_path: Path,
    projected_telemetry_path: Path,
    learning_run_dir: Path,
) -> str:
    """Run the false-positive-direction judge on the benign actor's story.

    Same four-artifact contract as ``invoke_judge``; the prompt inverts the
    outcome (a routine story that SURVIVES is the FP signal) and emits the
    environment-observation stream alongside defender findings.
    """
    user = (
        "<alert>\n"
        f"{alert_path.read_text().rstrip()}\n"
        "</alert>\n"
        "<investigation>\n"
        f"{investigation_path.read_text().rstrip()}\n"
        "</investigation>\n"
        "<actor_story>\n"
        f"{actor_story_path.read_text().rstrip()}\n"
        "</actor_story>\n"
        "<projected_telemetry>\n"
        f"{projected_telemetry_path.read_text().rstrip()}\n"
        "</projected_telemetry>\n"
    )
    import uuid as _uuid
    session_id = str(_uuid.uuid4())
    _log(f"step=judge-benign session_id={session_id}")
    try:
        out = _run_claude(
            JUDGE_BENIGN_PROMPT, user, model=BENIGN_JUDGE_MODEL, session_id=session_id
        )
    finally:
        src = _transcript_path(session_id)
        dst = learning_run_dir / "judge_benign_trace.jsonl"
        if src.is_file():
            shutil.copy2(src, dst)
    return out


def is_skip_story(actor_story: str) -> bool:
    for line in actor_story.splitlines():
        s = line.strip()
        if not s:
            continue
        return s.startswith("SKIP:")
    return False


# ---------------------------------------------------------------------------
# Judge YAML validation
# ---------------------------------------------------------------------------


def _outcome_keyword_in(outcome_value: Any, enum: set[str]) -> str:
    if not isinstance(outcome_value, str):
        raise LoopError(f"judge `outcome` is not a string: {type(outcome_value)}")
    # Tolerate the model fusing the keyword with a rationale clause
    # ("survived. The defender's investigation…"): split on the first
    # whitespace or sentence-punctuation boundary, take the head token.
    first = re.split(r"[\s.,;:]", outcome_value.strip(), maxsplit=1)[0]
    if first not in enum:
        raise LoopError(f"judge outcome keyword {first!r} not in {sorted(enum)}")
    return first


def _outcome_keyword(outcome_value: Any) -> str:
    return _outcome_keyword_in(outcome_value, OUTCOME_ENUM)


def _benign_outcome_keyword(outcome_value: Any) -> str:
    return _outcome_keyword_in(outcome_value, BENIGN_OUTCOME_ENUM)


_FENCE_RE = None  # filled lazily; tiny stdlib re import kept local to use site


def strip_yaml_fence(text: str) -> str:
    """Strip a leading code fence and/or a stray opening/closing XML tag.

    Models routinely wrap structured output in a code fence or a phantom
    `<content>...</content>` envelope even when the prompt forbids it;
    the loop accepts these tics rather than fail on them. Belt to the
    XML-envelope suspenders in the user prompt — switching the input
    envelope to XML removed the trigger, this absorbs any residue.

    Stripping is shallow: only one fence/tag layer is removed, and only
    if it surrounds the entire payload.
    """
    import re

    s = text.strip()
    # Drop everything up to and including a closing </thinking> or </think>
    # tag — reasoning-model output convention sometimes leaks through, with
    # the actual answer following the closing tag.
    m = re.search(r"</[a-zA-Z_][\w-]*?think[a-zA-Z_]*>\s*\n", s) or re.search(
        r"</think(?:ing)?>\s*\n", s
    )
    if m:
        s = s[m.end():].strip()
    m = re.match(r"\A```(?:yaml|yml)?\s*\n(.*?)\n```\s*\Z", s, re.DOTALL)
    if m:
        s = m.group(1).strip()
    # Drop a leading preamble before a fenced YAML block — models
    # occasionally emit "Let me construct..." before the actual YAML
    # despite the prompt's no-preamble contract.
    m = re.search(r"^```(?:yaml|yml)?\s*\n(.*?)\n```", s, re.DOTALL | re.MULTILINE)
    if m and not s.startswith("```"):
        s = m.group(1).strip()
    # Strip a wrapping <tag>...</tag> envelope (e.g. <content>, <output>).
    m = re.match(r"\A<([a-zA-Z_][\w-]*)\s*>\s*\n(.*?)\n\s*</\1>\s*\Z", s, re.DOTALL)
    if m:
        s = m.group(2).strip()
    # Strip a dangling trailing close tag with no matching opener.
    s = re.sub(r"\n\s*</[a-zA-Z_][\w-]*>\s*\Z", "", s)
    # Strip a dangling trailing close fence with no matching opener.
    s = re.sub(r"\n\s*```\s*\Z", "", s)
    return s


_ORACLE_PROJECTION_KEYS = {"position", "system", "template", "events"}


def validate_oracle_doc(doc: Any, expected_positions: list[int]) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise LoopError("oracle YAML did not parse to a mapping")
    if set(doc.keys()) != {"projections"}:
        raise LoopError(
            f"oracle YAML must have exactly one top-level key `projections`; "
            f"got {sorted(doc.keys())}"
        )
    projections = doc["projections"]
    if not isinstance(projections, list):
        raise LoopError("oracle `projections` is not a list")
    if len(projections) != len(expected_positions):
        raise LoopError(
            f"oracle projections count {len(projections)} != "
            f"lead_sequence positions count {len(expected_positions)}"
        )
    for i, p in enumerate(projections):
        _validate_oracle_projection(i, p, expected_positions[i])
    return doc


def _validate_oracle_projection(i: int, p: Any, expected_position: int) -> None:
    if not isinstance(p, dict):
        raise LoopError(f"projection[{i}] is not a mapping")
    missing = _ORACLE_PROJECTION_KEYS - set(p.keys())
    if missing:
        raise LoopError(f"projection[{i}] missing keys: {sorted(missing)}")
    extra = set(p.keys()) - _ORACLE_PROJECTION_KEYS
    if extra:
        raise LoopError(f"projection[{i}] has unexpected keys: {sorted(extra)}")
    if p["position"] != expected_position:
        raise LoopError(
            f"projection[{i}].position={p['position']!r} != "
            f"expected {expected_position!r}"
        )
    events = p["events"]
    if not isinstance(events, list):
        raise LoopError(f"projection[{i}].events is not a list")
    for j, ev in enumerate(events):
        if not isinstance(ev, dict):
            raise LoopError(
                f"projection[{i}].events[{j}] is not a mapping (got {type(ev).__name__})"
            )


def validate_judge_doc(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise LoopError("judge YAML did not parse to a mapping")
    _require_judge_keys(doc)
    findings = doc["defender_findings"]
    if not isinstance(findings, list):
        raise LoopError("judge `defender_findings` is not a list")
    for i, f in enumerate(findings):
        _validate_judge_finding(i, f)
    if "actor_observations" in doc:
        _validate_judge_actor_observations(doc["actor_observations"])
    return doc


def _require_judge_keys(doc: dict) -> None:
    for key in ("outcome", "outcome_rationale", "defender_findings"):
        if key not in doc:
            raise LoopError(f"judge YAML missing required key: {key}")
    if _outcome_keyword(doc["outcome"]) == "skip-passthrough":
        return
    for key in ("encounter_analysis", "confidence"):
        if key not in doc:
            raise LoopError(f"judge YAML missing required key: {key}")


def _validate_judge_actor_observations(observations: Any) -> None:
    if not isinstance(observations, list):
        raise LoopError("judge `actor_observations` is not a list")
    for i, o in enumerate(observations):
        _validate_actor_observation(i, o)


def _validate_judge_finding(i: int, f: Any) -> None:
    if not isinstance(f, dict):
        raise LoopError(f"finding[{i}] is not a mapping")
    for k in ("type", "subject_anchor", "subject_topic", "finding", "citations"):
        if k not in f:
            raise LoopError(f"finding[{i}] missing key: {k}")
    for k in ("subject_anchor", "subject_topic"):
        v = f[k]
        if not isinstance(v, str) or not v.strip():
            raise LoopError(f"finding[{i}].{k} must be a non-empty string")
    if f["type"] not in ALL_FINDING_TYPES:
        raise LoopError(
            f"finding[{i}].type={f['type']!r} not in {sorted(ALL_FINDING_TYPES)}"
        )
    if not isinstance(f["citations"], list):
        raise LoopError(f"finding[{i}].citations is not a list")


def _validate_actor_observation(i: int, o: Any) -> None:
    if not isinstance(o, dict):
        raise LoopError(f"actor_observations[{i}] is not a mapping")
    for k in ("type", "subject_anchor", "subject_topic", "observation"):
        if k not in o:
            raise LoopError(f"actor_observations[{i}] missing key: {k}")
        v = o[k]
        if not isinstance(v, str) or not v.strip():
            raise LoopError(
                f"actor_observations[{i}].{k} must be a non-empty string"
            )
    if o["type"] not in ACTOR_OBSERVATION_TYPES:
        raise LoopError(
            f"actor_observations[{i}].type={o['type']!r} not in "
            f"{sorted(ACTOR_OBSERVATION_TYPES)}"
        )


def validate_judge_benign_doc(doc: Any) -> dict[str, Any]:
    """Validate the benign (FP-direction) judge document.

    Mirrors ``validate_judge_doc`` against the benign outcome enum + finding
    types, and adds the optional ``environment_observations`` stream that the
    benign judge emits for the lessons-environment corpus.
    """
    if not isinstance(doc, dict):
        raise LoopError("benign judge YAML did not parse to a mapping")
    for key in ("outcome", "outcome_rationale", "defender_findings"):
        if key not in doc:
            raise LoopError(f"benign judge YAML missing required key: {key}")
    if _benign_outcome_keyword(doc["outcome"]) != "skip-passthrough":
        for key in ("encounter_analysis", "confidence"):
            if key not in doc:
                raise LoopError(f"benign judge YAML missing required key: {key}")
    findings = doc["defender_findings"]
    if not isinstance(findings, list):
        raise LoopError("benign judge `defender_findings` is not a list")
    for i, f in enumerate(findings):
        _validate_benign_finding(i, f)
    if "environment_observations" in doc:
        obs = doc["environment_observations"]
        if not isinstance(obs, list):
            raise LoopError("benign judge `environment_observations` is not a list")
        for i, o in enumerate(obs):
            _validate_environment_observation(i, o)
    return doc


def _validate_benign_finding(i: int, f: Any) -> None:
    if not isinstance(f, dict):
        raise LoopError(f"benign finding[{i}] is not a mapping")
    for k in ("type", "subject_anchor", "subject_topic", "finding", "citations"):
        if k not in f:
            raise LoopError(f"benign finding[{i}] missing key: {k}")
    for k in ("subject_anchor", "subject_topic"):
        v = f[k]
        if not isinstance(v, str) or not v.strip():
            raise LoopError(f"benign finding[{i}].{k} must be a non-empty string")
    if f["type"] not in BENIGN_ALL_FINDING_TYPES:
        raise LoopError(
            f"benign finding[{i}].type={f['type']!r} not in "
            f"{sorted(BENIGN_ALL_FINDING_TYPES)}"
        )
    if not isinstance(f["citations"], list):
        raise LoopError(f"benign finding[{i}].citations is not a list")


def _validate_environment_observation(i: int, o: Any) -> None:
    if not isinstance(o, dict):
        raise LoopError(f"environment_observations[{i}] is not a mapping")
    for k in ("alert_rule_ids", "relevance_criteria", "fact"):
        if k not in o:
            raise LoopError(f"environment_observations[{i}] missing key: {k}")
    rule_ids = o["alert_rule_ids"]
    if not isinstance(rule_ids, list) or not rule_ids:
        raise LoopError(
            f"environment_observations[{i}].alert_rule_ids must be a non-empty "
            "list (the retrieval anchor)"
        )
    for k in ("relevance_criteria", "fact"):
        if not isinstance(o[k], str) or not o[k].strip():
            raise LoopError(
                f"environment_observations[{i}].{k} must be a non-empty string"
            )
    # ``entities`` is optional (a fact may apply regardless of entities), but
    # when present each selector must carry type + class. The no-identity
    # discipline is the curator's + forward-check's job, not this structural gate.
    for sel in o.get("entities") or []:
        if not isinstance(sel, dict) or "type" not in sel or "class" not in sel:
            raise LoopError(
                f"environment_observations[{i}].entities selectors must be "
                "{type, class} mappings"
            )


# ---------------------------------------------------------------------------
# Step 5: Persistence
# ---------------------------------------------------------------------------


PERSIST_COPY_FILES = (
    "alert.json",
    "report.md",
    "investigation.md",
    "lead_sequence.yaml",
)


def _copy_shared_inputs(run_dir: Path, learning_run_dir: Path) -> None:
    learning_run_dir.mkdir(parents=True, exist_ok=True)
    for name in PERSIST_COPY_FILES:
        src = run_dir / name
        if not src.is_file():
            raise LoopError(f"missing source artifact for persist: {src}")
        shutil.copy2(src, learning_run_dir / name)


def _write_source_refs(
    run_dir: Path,
    learning_run_dir: Path,
    normalized_disposition: str,
    alert_rule_key: str,
) -> None:
    source_refs = {
        "paths": {
            "source_run_dir": str(run_dir),
            "alert": str(run_dir / "alert.json"),
            "report": str(run_dir / "report.md"),
            "investigation": str(run_dir / "investigation.md"),
            "lead_sequence": str(run_dir / "lead_sequence.yaml"),
        },
        "normalized_disposition": normalized_disposition,
        "alert_rule_key": alert_rule_key,
    }
    (learning_run_dir / "source_refs.yaml").write_text(yaml.safe_dump(source_refs))


def persist_run(
    run_dir: Path,
    learning_run_dir: Path,
    actor_story: str,
    judge_yaml_text: str | None,
    normalized_disposition: str,
    alert_rule_key: str,
    oracle_yaml_text: str | None = None,
) -> None:
    """Persist the adversarial-direction per-run artifacts.

    `oracle_yaml_text` and `judge_yaml_text` are expected to be the
    fence-stripped, validated YAML — i.e. the text that downstream
    consumers will parse. Caller-side code fences (if any) belong in a
    `*.raw.txt` companion, not in the canonical `.yaml`.
    """
    _copy_shared_inputs(run_dir, learning_run_dir)
    (learning_run_dir / "actor_story.md").write_text(actor_story)
    if oracle_yaml_text is not None:
        (learning_run_dir / "projected_telemetry.yaml").write_text(oracle_yaml_text)
    if judge_yaml_text is not None:
        (learning_run_dir / "judge_findings.yaml").write_text(judge_yaml_text)
    _write_source_refs(run_dir, learning_run_dir, normalized_disposition, alert_rule_key)


def persist_run_benign(
    run_dir: Path,
    learning_run_dir: Path,
    actor_benign_story: str,
    judge_benign_yaml_text: str | None,
    normalized_disposition: str,
    alert_rule_key: str,
    oracle_benign_yaml_text: str | None = None,
) -> None:
    """Persist the benign-direction artifacts under direction-suffixed names.

    Shares the four input copies + source_refs with ``persist_run`` (an
    ``inconclusive`` run that ran both directions writes them once each; the
    copies are idempotent). The actor story, projection, and judge output use
    ``*_benign`` names so the two directions never collide in one run dir.
    """
    _copy_shared_inputs(run_dir, learning_run_dir)
    (learning_run_dir / "actor_benign_story.md").write_text(actor_benign_story)
    if oracle_benign_yaml_text is not None:
        (learning_run_dir / "projected_telemetry_benign.yaml").write_text(
            oracle_benign_yaml_text
        )
    if judge_benign_yaml_text is not None:
        (learning_run_dir / "judge_benign_findings.yaml").write_text(
            judge_benign_yaml_text
        )
    _write_source_refs(run_dir, learning_run_dir, normalized_disposition, alert_rule_key)


# ---------------------------------------------------------------------------
# Step 6: Append to queue
# ---------------------------------------------------------------------------


def _slugify(s: str) -> str:
    out = []
    prev_dash = False
    for ch in str(s).lower():
        if ch.isalnum():
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    return "".join(out).strip("-") or "unkeyed"


def derive_alert_rule_key(alert: dict) -> str:
    """POC-grade vendor-neutral key derivation per task §findings.jsonl."""
    rule = alert.get("rule")
    if isinstance(rule, dict) and rule.get("id") not in (None, ""):
        return f"rule-{rule['id']}"
    sig = alert.get("signature")
    if isinstance(sig, str) and sig.strip():
        return _slugify(sig)
    top_id = alert.get("id")
    if isinstance(top_id, (str, int)) and str(top_id).strip():
        return _slugify(str(top_id))
    return "unkeyed"


def _source_run_dir(learning_run_dir: Path) -> str:
    """Repo-relative path with trailing slash — the source_run_dir
    convention shared by both ``_pending/`` queues."""
    return str(learning_run_dir.relative_to(REPO_ROOT)) + "/"


def _load_jsonl_ids(path: Path, key: str) -> set[str]:
    """Return the set of ``entry[key]`` strings in a JSONL file.

    Missing file → empty set. Malformed lines are skipped, matching
    the tolerance ``author.read_batch`` applies on the consumer side.
    """
    if not path.is_file():
        return set()
    ids: set[str] = set()
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        v = obj.get(key)
        if isinstance(v, str):
            ids.add(v)
    return ids


def _append_jsonl(path: Path, rows: list[dict]) -> int:
    """Append ``rows`` to ``path`` as JSONL (one row per line)."""
    if not rows:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return len(rows)


def _acquire_actor_observations_lock() -> Any:
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    fh = ACTOR_OBSERVATIONS_LOCK_FILE.open("a+")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    return fh


def _release_observations_lock(fh: Any) -> None:
    """Release any flock-held observation-queue lock (actor or environment)."""
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def append_findings(
    judge_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
    *,
    direction: str = "adversarial",
) -> int:
    """Append queueable defender findings to the shared pending queue.

    Both directions feed ``defender/learning/_pending/findings.jsonl`` →
    ``defender/lessons/``. The audit-only finding type is filtered out
    (``detection-confirmed`` adversarially, ``disposition-confirmed`` for the
    benign FP direction). Each row is tagged with ``direction`` so the shared
    curator (author.py) can apply the right ground-truth gate — a confident FN
    needs a ``benign`` disposition, a confident FP needs ``malicious``.
    Benign finding ids live in a ``benign/`` namespace so the two directions
    never collide on the same ``run_id``. Returns the number appended.
    """
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    if direction == "benign":
        outcome = _benign_outcome_keyword(judge_doc["outcome"])
        audit_only_type = "disposition-confirmed"
        namespace = "benign/"
    else:
        outcome = _outcome_keyword(judge_doc["outcome"])
        audit_only_type = "detection-confirmed"
        namespace = ""
    appended = 0
    with PENDING_FILE.open("a") as fh:
        for n, f in enumerate(judge_doc["defender_findings"]):
            if f["type"] == audit_only_type:
                continue
            entry = {
                "schema_version": 1,
                "finding_id": f"{run_id}/{namespace}{n}",
                "run_id": run_id,
                "alert_rule_key": alert_rule_key,
                "direction": direction,
                "type": f["type"],
                "subject_anchor": f["subject_anchor"],
                "subject_topic": f["subject_topic"],
                "finding": f["finding"],
                "judge_outcome": outcome,
                "citations": f["citations"],
                "source_run_dir": str(
                    learning_run_dir.relative_to(REPO_ROOT)
                ) + "/",
            }
            fh.write(json.dumps(entry) + "\n")
            appended += 1
    return appended


def append_actor_observations(
    judge_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
) -> int:
    """Append judge ``actor_observations`` to the actor pending queue.

    One row per observation, deduped on ``observation_id`` against both
    the active queue and the consumed history so re-running the persist
    stage on a case never replays observations the author has already
    decided on (committed, skipped, or pre-consumed as idempotent). The
    producer's only outcome filter is ``skip-passthrough`` (defensive —
    the judge does not emit observations on SKIP); the author owns the
    caught/incoherent/survived policy.
    """
    outcome = _outcome_keyword(judge_doc["outcome"])
    if outcome == "skip-passthrough":
        return 0
    observations = judge_doc.get("actor_observations") or []
    if not observations:
        return 0
    lock_fh = _acquire_actor_observations_lock()
    try:
        existing = _load_jsonl_ids(ACTOR_OBSERVATIONS_FILE, "observation_id")
        existing |= _load_jsonl_ids(
            ACTOR_OBSERVATIONS_CONSUMED_FILE, "observation_id"
        )
        src = _source_run_dir(learning_run_dir)
        rows: list[dict] = []
        for i, obs in enumerate(observations):
            obs_id = f"{run_id}/{i}"
            if obs_id in existing:
                continue
            rows.append({
                "observation_id": obs_id,
                "run_id": run_id,
                "observation_index": i,
                "alert_rule_key": alert_rule_key,
                "type": obs["type"],
                "subject_anchor": obs["subject_anchor"],
                "subject_topic": obs["subject_topic"],
                "observation": obs["observation"],
                "judge_outcome": outcome,
                "source_run_dir": src,
            })
        return _append_jsonl(ACTOR_OBSERVATIONS_FILE, rows)
    finally:
        _release_observations_lock(lock_fh)


def _acquire_environment_observations_lock() -> Any:
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    fh = ENVIRONMENT_OBSERVATIONS_LOCK_FILE.open("a+")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    return fh


def append_environment_observations(
    judge_benign_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
) -> int:
    """Append benign-judge ``environment_observations`` to the env queue.

    The FP-direction mirror of ``append_actor_observations``: one row per
    observation, deduped on ``observation_id`` against the active + consumed
    env queues. Rows carry the retrieval keys the curator and
    ``verify_forward_env.py`` read directly (``alert_rule_ids``, ``entities``,
    ``subject``, ``relevance_criteria``, ``fact``). ``skip-passthrough`` emits
    nothing (defensive — the judge emits no observations on SKIP).
    """
    outcome = _benign_outcome_keyword(judge_benign_doc["outcome"])
    if outcome == "skip-passthrough":
        return 0
    observations = judge_benign_doc.get("environment_observations") or []
    if not observations:
        return 0
    lock_fh = _acquire_environment_observations_lock()
    try:
        existing = _load_jsonl_ids(ENVIRONMENT_OBSERVATIONS_FILE, "observation_id")
        existing |= _load_jsonl_ids(
            ENVIRONMENT_OBSERVATIONS_CONSUMED_FILE, "observation_id"
        )
        src = _source_run_dir(learning_run_dir)
        rows: list[dict] = []
        for i, obs in enumerate(observations):
            obs_id = f"{run_id}/{i}"
            if obs_id in existing:
                continue
            rows.append({
                "observation_id": obs_id,
                "run_id": run_id,
                "observation_index": i,
                "alert_rule_key": alert_rule_key,
                "subject": obs.get("subject"),
                "alert_rule_ids": obs["alert_rule_ids"],
                "entities": obs.get("entities") or [],
                "relevance_criteria": obs["relevance_criteria"],
                "fact": obs["fact"],
                "citations": obs.get("citations") or [],
                "judge_outcome": outcome,
                "source_run_dir": src,
            })
        return _append_jsonl(ENVIRONMENT_OBSERVATIONS_FILE, rows)
    finally:
        _release_observations_lock(lock_fh)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _log(msg: str) -> None:
    print(f"[loop] {msg}", file=sys.stderr)


def read_ground_truth(run_dir: Path) -> dict | None:
    """Return parsed ground_truth.yaml if the run dir carries one, else None.

    Held-out runs carry a ``ground_truth.yaml`` propagated from the fixture
    by ``defender/run.py``. The persist stage uses this to suppress queue
    appends — ``defender_findings`` and ``actor_observations`` from held-out
    runs must never feed back into the learning corpora.
    """
    path = run_dir / GROUND_TRUTH_FILE
    if not path.is_file():
        return None
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        raise LoopError(f"{path}: malformed YAML: {e}") from e
    if not isinstance(doc, dict):
        raise LoopError(f"{path}: expected a mapping at top level")
    return doc


def is_held_out(run_dir: Path) -> bool:
    """True if this run dir's ground_truth.yaml declares ``held_out: true``."""
    gt = read_ground_truth(run_dir)
    return bool(gt and gt.get("held_out") is True)


def _invoke_lead_author(run_dir: Path) -> None:
    """Catalog/template refinement. Independent of disposition + actor/judge."""
    _log("step=lead-author")
    sys.path.insert(0, str(LEARNING_DIR))
    try:
        import lead_author as _lead_author  # type: ignore[import-not-found]
    finally:
        sys.path.pop(0)
    try:
        rc = _lead_author.run(run_dir)
        if rc != 0:
            _log(f"lead-author returned rc={rc} (continuing — defender is experimental)")
    except (subprocess.SubprocessError, OSError) as e:
        # Narrow swallow: child-process / filesystem hiccups don't tank the loop.
        # ImportError, NameError, TypeError, etc. propagate so regressions fail loudly.
        _log(f"lead-author crashed: {e!r} (continuing)")


def _directions_for(disposition: str) -> list[str]:
    """Which learning directions a disposition triggers, in run order.

    ``benign`` → adversarial only (hunt the missed attack); ``malicious`` →
    benign only (hunt the over-escalation); ``inconclusive`` → both.
    """
    directions: list[str] = []
    if disposition in ADVERSARIAL_DISPOSITIONS:
        directions.append("adversarial")
    if disposition in BENIGN_DISPOSITIONS:
        directions.append("benign")
    return directions


def _run_oracle(
    run_dir: Path,
    learning_run_dir: Path,
    actor_story_path: Path,
    out_name: str,
) -> Path:
    """Project the story's telemetry footprint; write + validate the YAML.

    Shared by both directions — only the actor story and output filename
    differ. Returns the path to the written ``projected_telemetry`` YAML.
    """
    lead_sequence_path = run_dir / "lead_sequence.yaml"
    lead_sequence_text = lead_sequence_path.read_text()
    exemplar_bundle = assemble_exemplar_bundle(run_dir, lead_sequence_text)
    oracle_yaml_text = invoke_oracle(
        run_dir / "alert.json", actor_story_path, lead_sequence_path, exemplar_bundle
    )
    expected_positions = [
        e.get("position")
        for e in (yaml.safe_load(lead_sequence_text) or {}).get("entries", [])
    ]
    stripped = strip_yaml_fence(oracle_yaml_text)
    raw_path = learning_run_dir / (Path(out_name).stem + ".raw.txt")
    try:
        validate_oracle_doc(yaml.safe_load(stripped), expected_positions)
    except (yaml.YAMLError, LoopError) as e:
        raw_path.write_text(oracle_yaml_text)
        raise LoopError(f"oracle YAML invalid: {e}") from e
    out_path = learning_run_dir / out_name
    out_path.write_text(stripped)
    if stripped != oracle_yaml_text:
        raw_path.write_text(oracle_yaml_text)
    return out_path


def _run_adversarial(
    run_dir: Path,
    learning_run_dir: Path,
    disposition: str,
    alert_rule_key: str,
    run_id: str,
    held_out: bool,
) -> bool:
    """Adversarial direction: actor → oracle → judge → persist → append.

    Returns True if findings/observations were appended (i.e. the direction
    produced queue rows worth triggering the curators for).
    """
    _log("step=project (adversarial)")
    actor_input_path = learning_run_dir / "actor_input.yaml"
    project_actor_input(run_dir, actor_input_path)

    _log("step=actor")
    actor_story = invoke_actor(run_dir / "alert.json", actor_input_path, learning_run_dir)
    actor_story_path = learning_run_dir / "actor_story.md"
    actor_story_path.write_text(actor_story)

    if is_skip_story(actor_story):
        _log("actor emitted SKIP — persisting, no findings")
        persist_run(
            run_dir, learning_run_dir, actor_story,
            judge_yaml_text=None,
            normalized_disposition=disposition, alert_rule_key=alert_rule_key,
        )
        return False

    _log("step=oracle")
    projected_path = _run_oracle(
        run_dir, learning_run_dir, actor_story_path, "projected_telemetry.yaml"
    )

    judge_yaml_text = invoke_judge(
        run_dir / "alert.json", run_dir / "investigation.md",
        actor_story_path, projected_path, learning_run_dir,
    )
    judge_stripped = strip_yaml_fence(judge_yaml_text)
    try:
        judge_doc = validate_judge_doc(yaml.safe_load(judge_stripped))
    except (yaml.YAMLError, LoopError) as e:
        (learning_run_dir / "judge_findings.raw.txt").write_text(judge_yaml_text)
        raise LoopError(f"judge YAML invalid: {e}") from e
    if judge_stripped != judge_yaml_text:
        (learning_run_dir / "judge_findings.raw.txt").write_text(judge_yaml_text)

    _log("step=persist (adversarial)")
    persist_run(
        run_dir, learning_run_dir, actor_story, judge_stripped,
        disposition, alert_rule_key, oracle_yaml_text=projected_path.read_text(),
    )

    if held_out:
        _log("held_out=true — adversarial appends suppressed")
        return False

    n_f = append_findings(judge_doc, run_id, alert_rule_key, learning_run_dir)
    n_o = append_actor_observations(judge_doc, run_id, alert_rule_key, learning_run_dir)
    _log(f"appended {n_f} finding(s), {n_o} actor observation(s)")
    return True


def _run_benign(
    run_dir: Path,
    learning_run_dir: Path,
    disposition: str,
    alert_rule_key: str,
    run_id: str,
    held_out: bool,
) -> bool:
    """Benign (FP) direction: actor → oracle → benign judge → persist → append.

    Mirrors ``_run_adversarial``; the benign actor reconstructs the routine
    operation (no MITRE menu, retrieves environment lessons by the case's
    prologue entities) and the benign judge inverts the outcome. Returns True
    if queue rows were appended.
    """
    _log("step=case-entities (benign)")
    case_entities = extract_case_entities(run_dir / "investigation.md")

    _log("step=actor-benign")
    actor_story = invoke_actor_benign(
        run_dir / "alert.json", case_entities, learning_run_dir
    )
    actor_story_path = learning_run_dir / "actor_benign_story.md"
    actor_story_path.write_text(actor_story)

    if is_skip_story(actor_story):
        _log("benign actor emitted SKIP — persisting, no findings")
        persist_run_benign(
            run_dir, learning_run_dir, actor_story,
            judge_benign_yaml_text=None,
            normalized_disposition=disposition, alert_rule_key=alert_rule_key,
        )
        return False

    _log("step=oracle (benign)")
    projected_path = _run_oracle(
        run_dir, learning_run_dir, actor_story_path,
        "projected_telemetry_benign.yaml",
    )

    judge_yaml_text = invoke_judge_benign(
        run_dir / "alert.json", run_dir / "investigation.md",
        actor_story_path, projected_path, learning_run_dir,
    )
    judge_stripped = strip_yaml_fence(judge_yaml_text)
    try:
        judge_doc = validate_judge_benign_doc(yaml.safe_load(judge_stripped))
    except (yaml.YAMLError, LoopError) as e:
        (learning_run_dir / "judge_benign_findings.raw.txt").write_text(judge_yaml_text)
        raise LoopError(f"benign judge YAML invalid: {e}") from e
    if judge_stripped != judge_yaml_text:
        (learning_run_dir / "judge_benign_findings.raw.txt").write_text(judge_yaml_text)

    _log("step=persist (benign)")
    persist_run_benign(
        run_dir, learning_run_dir, actor_story, judge_stripped,
        disposition, alert_rule_key, oracle_benign_yaml_text=projected_path.read_text(),
    )

    if held_out:
        _log("held_out=true — benign appends suppressed")
        return False

    n_f = append_findings(
        judge_doc, run_id, alert_rule_key, learning_run_dir, direction="benign"
    )
    n_e = append_environment_observations(
        judge_doc, run_id, alert_rule_key, learning_run_dir
    )
    _log(f"appended {n_f} finding(s), {n_e} environment observation(s)")
    return True


def run_one(run_dir: Path) -> int:
    run_id = run_dir.name

    # Lead-author runs unconditionally — catalog refinement is independent of
    # disposition, actor SKIP, and held-out flags.
    _invoke_lead_author(run_dir)

    _log(f"run_id={run_id} step=normalize")
    disposition = normalize_disposition(run_dir / "report.md")
    directions = _directions_for(disposition)
    if not directions:
        _log(f"disposition={disposition} — no learning direction; skipping")
        return 0

    alert = json.loads((run_dir / "alert.json").read_text())
    alert_rule_key = derive_alert_rule_key(alert)
    learning_run_dir = RUNS_DIR / run_id
    learning_run_dir.mkdir(parents=True, exist_ok=True)
    held_out = is_held_out(run_dir)
    _log(
        f"step=dispatch disposition={disposition} directions={directions} "
        f"alert_rule_key={alert_rule_key} held_out={held_out}"
    )

    ran_adversarial = False
    ran_benign = False
    for direction in directions:
        if direction == "adversarial":
            ran_adversarial = _run_adversarial(
                run_dir, learning_run_dir, disposition, alert_rule_key, run_id, held_out
            )
        else:
            ran_benign = _run_benign(
                run_dir, learning_run_dir, disposition, alert_rule_key, run_id, held_out
            )

    # Curator triggers (threshold-gated). The shared defender-findings curator
    # fires if either direction appended; the per-corpus actor/environment
    # curators fire only for the direction that produced their queue.
    if ran_adversarial or ran_benign:
        _maybe_trigger_author(
            pending_file=PENDING_FILE,
            threshold_env="LEARNING_AUTHOR_THRESHOLD",
            module_name="author",
            label="author",
            log_prefix="step=author",
            pending_label="pending",
        )
    if ran_adversarial:
        _maybe_trigger_author(
            pending_file=ACTOR_OBSERVATIONS_FILE,
            threshold_env="LEARNING_AUTHOR_ACTOR_THRESHOLD",
            module_name="author_actor",
            label="author_actor",
            log_prefix="step=author_actor",
            pending_label="actor_pending",
        )
    if ran_benign:
        _maybe_trigger_author(
            pending_file=ENVIRONMENT_OBSERVATIONS_FILE,
            threshold_env="LEARNING_AUTHOR_ENV_THRESHOLD",
            module_name="author_actor_benign",
            label="author_actor_benign",
            log_prefix="step=author_actor_benign",
            pending_label="env_pending",
        )

    return 0


def _maybe_trigger_author(
    *,
    pending_file: Path,
    threshold_env: str,
    module_name: str,
    label: str,
    log_prefix: str,
    pending_label: str,
) -> None:
    """Run the named curator module if the pending queue meets its threshold."""
    threshold = int(os.environ.get(threshold_env, "5"))
    pending_count = 0
    if pending_file.is_file():
        pending_count = sum(
            1 for line in pending_file.read_text().splitlines() if line.strip()
        )
    if pending_count < threshold:
        _log(
            f"{pending_label}={pending_count} threshold={threshold} "
            f"— {label} not invoked"
        )
        return
    _log(f"{log_prefix} {pending_label}={pending_count} threshold={threshold}")
    # Sibling module — loop.py is invoked as a script, so we
    # import by file path rather than via package syntax.
    sys.path.insert(0, str(LEARNING_DIR))
    try:
        mod = __import__(module_name)
    finally:
        sys.path.pop(0)
    rc = mod.run_batch()
    if rc != 0:
        _log(f"{label} returned rc={rc} (queue intact, retry next tick)")


_HELP_EPILOG = """\
Direction dispatch (by the defender's normalized disposition):
  benign        → adversarial direction only (hunt the missed attack / FN)
  malicious     → benign direction only      (hunt the over-escalation / FP)
  inconclusive  → both directions
A disposition that maps to no direction is skipped.

Inputs (must exist in <run_dir>):
  alert.json            verbatim alert input
  report.md             YAML frontmatter with disposition ∈ {benign, inconclusive, malicious}
  investigation.md      defender's invlang audit log
  lead_sequence.yaml    projected lead set (emitted by defender/scripts/project_lead_sequence.py)
  gather_raw/{N}.json   raw query payloads referenced by lead_sequence

Outputs:
  defender/learning/runs/<run_id>/
    actor_input.yaml               adversarial actor-facing projection (queries only)
    actor_story.md / *_benign.md   per-direction story (or "SKIP: ...")
    projected_telemetry[_benign].yaml  oracle's per-lead synthesized events
    judge_findings[_benign].yaml   judge classification + queueable findings
  defender/learning/_pending/findings.jsonl
    appended queueable defender findings (both directions, tagged `direction`);
    when count >= LEARNING_AUTHOR_THRESHOLD the lessons curator (author.py) runs.
  defender/learning/_pending/actor_observations.jsonl   (adversarial direction)
    when count >= LEARNING_AUTHOR_ACTOR_THRESHOLD, author_actor.py runs.
  defender/learning/_pending/environment_observations.jsonl   (benign direction)
    when count >= LEARNING_AUTHOR_ENV_THRESHOLD, author_actor_benign.py runs.

Environment:
  ACTOR_MODEL / BENIGN_ACTOR_MODEL     claude model for the adversarial / benign actor
                                       (default: claude-sonnet-4-6)
  ORACLE_MODEL                         claude model for the telemetry oracle —
                                       cheap projection work, no reasoning
                                       (default: claude-haiku-4-5)
  JUDGE_MODEL / BENIGN_JUDGE_MODEL     claude model for the adversarial / benign judge
                                       (default: claude-sonnet-4-6)
  LEARNING_SUBAGENT_TIMEOUT_SECONDS    per-subagent timeout (default: 300)
  LEARNING_AUTHOR_THRESHOLD            pending findings before author runs (default: 5)
  LEARNING_AUTHOR_ACTOR_THRESHOLD      pending actor observations before
                                       author_actor runs (default: 5)
  LEARNING_AUTHOR_ENV_THRESHOLD        pending environment observations before
                                       author_actor_benign runs (default: 5)
  LEARNING_AUTHOR_ACTOR_MODEL          claude model for the actor lessons curator
                                       (default: claude-sonnet-4-6)

Typical use: invoked in-process by `defender/run.py` after the runtime loop
exits. Run standalone with `python3 defender/learning/loop.py <run_dir>` to
re-process an existing run dir (e.g. after a judge-parse failure).

Exit codes: 0 success / 0 skipped (no direction for disposition, or actor SKIP) /
            2 LoopError / 64 usage.
"""


def main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="defender/learning/loop.py",
        description=(
            "Defender learning-loop orchestrator. Given a finished defender "
            "run dir, runs actor → oracle → judge, persists artifacts under "
            "defender/learning/runs/<run_id>/, and queues findings for the "
            "lessons curator."
        ),
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("run_dir", type=Path, help="Defender run dir (e.g. /tmp/defender-runs/<run_id>)")
    ns = parser.parse_args(argv[1:])

    run_dir = ns.run_dir.resolve()
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 1
    try:
        return run_one(run_dir)
    except LoopError as e:
        print(f"[loop] FATAL: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
