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

ACTOR_PROMPT = LEARNING_DIR / "actor.md"
ORACLE_PROMPT = LEARNING_DIR / "oracle.md"
JUDGE_PROMPT = LEARNING_DIR / "judge.md"
PROJECT_SCRIPT = REPO_ROOT / "defender" / "scripts" / "project_lead_sequence.py"

DISPOSITION_ENUM = {"benign", "inconclusive", "malicious"}
DISPOSITION_RUN = {"benign", "inconclusive"}  # malicious skipped at MVP

GROUND_TRUTH_FILE = "ground_truth.yaml"

OUTCOME_ENUM = {"caught", "survived", "undecidable", "incoherent", "skip-passthrough"}
QUEUEABLE_FINDING_TYPES = {
    "lead-set",
    "lead-quality",
    "analyze-discipline",
    "observability",
}
ALL_FINDING_TYPES = QUEUEABLE_FINDING_TYPES | {"detection-confirmed"}

CLAUDE_MODEL = os.environ.get("LEARNING_CLAUDE_MODEL", "claude-haiku-4-5")
SUBAGENT_TIMEOUT = int(os.environ.get("LEARNING_SUBAGENT_TIMEOUT_SECONDS", "300"))


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


def _run_claude(system_prompt_path: Path, user_prompt: str) -> str:
    """One-shot ``claude -p`` call. Returns stdout."""
    cmd = [
        "claude",
        "-p",
        "--model",
        CLAUDE_MODEL,
        "--output-format",
        "text",
        "--system-prompt-file",
        str(system_prompt_path),
    ]
    proc = subprocess.run(
        cmd,
        input=user_prompt,
        capture_output=True,
        text=True,
        timeout=SUBAGENT_TIMEOUT,
    )
    if proc.returncode != 0:
        raise LoopError(
            f"claude -p failed (rc={proc.returncode}):\n"
            f"stderr: {proc.stderr[-2000:]}"
        )
    return proc.stdout


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
    return _run_claude(ACTOR_PROMPT, user)


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
    return _run_claude(ORACLE_PROMPT, user)


def invoke_judge(
    alert_path: Path,
    investigation_path: Path,
    actor_story_path: Path,
    projected_telemetry_path: Path,
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
    return _run_claude(JUDGE_PROMPT, user)


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


def _outcome_keyword(outcome_value: Any) -> str:
    if not isinstance(outcome_value, str):
        raise LoopError(f"judge `outcome` is not a string: {type(outcome_value)}")
    # Tolerate the model fusing the keyword with a rationale clause
    # ("survived. The defender's investigation…"): split on the first
    # whitespace or sentence-punctuation boundary, take the head token.
    first = re.split(r"[\s.,;:]", outcome_value.strip(), maxsplit=1)[0]
    if first not in OUTCOME_ENUM:
        raise LoopError(
            f"judge outcome keyword {first!r} not in {sorted(OUTCOME_ENUM)}"
        )
    return first


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
        if not isinstance(p, dict):
            raise LoopError(f"projection[{i}] is not a mapping")
        missing = _ORACLE_PROJECTION_KEYS - set(p.keys())
        if missing:
            raise LoopError(f"projection[{i}] missing keys: {sorted(missing)}")
        extra = set(p.keys()) - _ORACLE_PROJECTION_KEYS
        if extra:
            raise LoopError(f"projection[{i}] has unexpected keys: {sorted(extra)}")
        if p["position"] != expected_positions[i]:
            raise LoopError(
                f"projection[{i}].position={p['position']!r} != "
                f"expected {expected_positions[i]!r}"
            )
        events = p["events"]
        if not isinstance(events, list):
            raise LoopError(f"projection[{i}].events is not a list")
        for j, ev in enumerate(events):
            if not isinstance(ev, dict):
                raise LoopError(
                    f"projection[{i}].events[{j}] is not a mapping (got {type(ev).__name__})"
                )
    return doc


def validate_judge_doc(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise LoopError("judge YAML did not parse to a mapping")
    for key in ("outcome", "outcome_rationale", "defender_findings"):
        if key not in doc:
            raise LoopError(f"judge YAML missing required key: {key}")
    outcome = _outcome_keyword(doc["outcome"])
    if outcome != "skip-passthrough":
        for key in ("encounter_analysis", "confidence"):
            if key not in doc:
                raise LoopError(f"judge YAML missing required key: {key}")
    findings = doc["defender_findings"]
    if not isinstance(findings, list):
        raise LoopError("judge `defender_findings` is not a list")
    for i, f in enumerate(findings):
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
    return doc


# ---------------------------------------------------------------------------
# Step 5: Persistence
# ---------------------------------------------------------------------------


PERSIST_COPY_FILES = (
    "alert.json",
    "report.md",
    "investigation.md",
    "lead_sequence.yaml",
)


def persist_run(
    run_dir: Path,
    learning_run_dir: Path,
    actor_story: str,
    judge_yaml_text: str | None,
    normalized_disposition: str,
    alert_rule_key: str,
    oracle_yaml_text: str | None = None,
) -> None:
    """Persist the per-run artifacts.

    `oracle_yaml_text` and `judge_yaml_text` are expected to be the
    fence-stripped, validated YAML — i.e. the text that downstream
    consumers will parse. Caller-side code fences (if any) belong in a
    `*.raw.txt` companion, not in the canonical `.yaml`.
    """
    learning_run_dir.mkdir(parents=True, exist_ok=True)
    for name in PERSIST_COPY_FILES:
        src = run_dir / name
        if not src.is_file():
            raise LoopError(f"missing source artifact for persist: {src}")
        shutil.copy2(src, learning_run_dir / name)
    (learning_run_dir / "actor_story.md").write_text(actor_story)
    if oracle_yaml_text is not None:
        (learning_run_dir / "projected_telemetry.yaml").write_text(oracle_yaml_text)
    if judge_yaml_text is not None:
        (learning_run_dir / "judge_findings.yaml").write_text(judge_yaml_text)
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


def append_findings(
    judge_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
) -> int:
    """Append non-detection-confirmed findings to the pending queue.

    Returns the number of findings appended.
    """
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    outcome = _outcome_keyword(judge_doc["outcome"])
    appended = 0
    with PENDING_FILE.open("a") as fh:
        for n, f in enumerate(judge_doc["defender_findings"]):
            if f["type"] == "detection-confirmed":
                continue
            entry = {
                "schema_version": 1,
                "finding_id": f"{run_id}/{n}",
                "run_id": run_id,
                "alert_rule_key": alert_rule_key,
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
    doc = yaml.safe_load(path.read_text()) or {}
    if not isinstance(doc, dict):
        raise LoopError(f"{path}: expected a mapping at top level")
    return doc


def is_held_out(run_dir: Path) -> bool:
    """True if this run dir's ground_truth.yaml declares ``held_out: true``."""
    gt = read_ground_truth(run_dir)
    return bool(gt and gt.get("held_out") is True)


def run_one(run_dir: Path) -> int:
    run_id = run_dir.name
    _log(f"run_id={run_id} step=normalize")
    disposition = normalize_disposition(run_dir / "report.md")

    if disposition not in DISPOSITION_RUN:
        _log(f"disposition={disposition} — skipping (MVP only runs {sorted(DISPOSITION_RUN)})")
        return 0

    alert = json.loads((run_dir / "alert.json").read_text())
    alert_rule_key = derive_alert_rule_key(alert)
    learning_run_dir = RUNS_DIR / run_id
    learning_run_dir.mkdir(parents=True, exist_ok=True)

    _log(f"step=project disposition={disposition} alert_rule_key={alert_rule_key}")
    actor_input_path = learning_run_dir / "actor_input.yaml"
    project_actor_input(run_dir, actor_input_path)

    _log("step=actor")
    actor_story = invoke_actor(
        run_dir / "alert.json", actor_input_path, learning_run_dir
    )
    actor_story_path = learning_run_dir / "actor_story.md"
    actor_story_path.write_text(actor_story)

    if is_skip_story(actor_story):
        _log("actor emitted SKIP — persisting and exiting with no findings")
        persist_run(
            run_dir,
            learning_run_dir,
            actor_story,
            judge_yaml_text=None,
            normalized_disposition=disposition,
            alert_rule_key=alert_rule_key,
        )
        return 0

    _log("step=oracle")
    lead_sequence_path = run_dir / "lead_sequence.yaml"
    lead_sequence_text = lead_sequence_path.read_text()
    exemplar_bundle = assemble_exemplar_bundle(run_dir, lead_sequence_text)
    oracle_yaml_text = invoke_oracle(
        run_dir / "alert.json",
        actor_story_path,
        lead_sequence_path,
        exemplar_bundle,
    )
    expected_positions = [
        e.get("position")
        for e in (yaml.safe_load(lead_sequence_text) or {}).get("entries", [])
    ]
    oracle_yaml_stripped = strip_yaml_fence(oracle_yaml_text)
    try:
        oracle_doc = yaml.safe_load(oracle_yaml_stripped)
        validate_oracle_doc(oracle_doc, expected_positions)
    except (yaml.YAMLError, LoopError) as e:
        (learning_run_dir / "projected_telemetry.raw.txt").write_text(oracle_yaml_text)
        raise LoopError(f"oracle YAML invalid: {e}") from e
    projected_telemetry_path = learning_run_dir / "projected_telemetry.yaml"
    projected_telemetry_path.write_text(oracle_yaml_stripped)
    if oracle_yaml_stripped != oracle_yaml_text:
        (learning_run_dir / "projected_telemetry.raw.txt").write_text(oracle_yaml_text)

    _log("step=judge")
    judge_yaml_text = invoke_judge(
        run_dir / "alert.json",
        run_dir / "investigation.md",
        actor_story_path,
        projected_telemetry_path,
    )
    judge_yaml_stripped = strip_yaml_fence(judge_yaml_text)
    try:
        judge_doc = yaml.safe_load(judge_yaml_stripped)
        judge_doc = validate_judge_doc(judge_doc)
    except (yaml.YAMLError, LoopError) as e:
        (learning_run_dir / "judge_findings.raw.txt").write_text(judge_yaml_text)
        raise LoopError(f"judge YAML invalid: {e}") from e
    if judge_yaml_stripped != judge_yaml_text:
        (learning_run_dir / "judge_findings.raw.txt").write_text(judge_yaml_text)

    _log("step=persist")
    persist_run(
        run_dir,
        learning_run_dir,
        actor_story,
        judge_yaml_stripped,
        disposition,
        alert_rule_key,
        oracle_yaml_text=oracle_yaml_stripped,
    )

    if is_held_out(run_dir):
        _log(
            "step=append held_out=true — defender_findings and "
            "actor_observations suppressed from _pending/ queues"
        )
        return 0

    _log("step=append")
    n_appended = append_findings(judge_doc, run_id, alert_rule_key, learning_run_dir)
    _log(f"appended {n_appended} finding(s) to {PENDING_FILE}")

    threshold = int(os.environ.get("LEARNING_AUTHOR_THRESHOLD", "5"))
    pending_count = sum(
        1 for line in PENDING_FILE.read_text().splitlines() if line.strip()
    )
    if pending_count >= threshold:
        _log(f"step=author pending={pending_count} threshold={threshold}")
        # Sibling module — loop.py is invoked as a script, so we
        # import author by file path rather than via package syntax.
        sys.path.insert(0, str(LEARNING_DIR))
        try:
            import author as _author  # type: ignore[import-not-found]
        finally:
            sys.path.pop(0)
        rc = _author.run_batch()
        if rc != 0:
            _log(f"author returned rc={rc} (queue intact, retry next tick)")
    else:
        _log(f"pending={pending_count} threshold={threshold} — author not invoked")

    return 0


_HELP_EPILOG = """\
Inputs (must exist in <run_dir>):
  alert.json            verbatim alert input
  report.md             YAML frontmatter with disposition ∈ {benign, inconclusive, malicious}
                        ('malicious' is skipped at MVP — actor has nothing to bypass)
  investigation.md      defender's invlang audit log
  lead_sequence.yaml    projected lead set (emitted by defender/scripts/project_lead_sequence.py)
  gather_raw/{N}.json   raw query payloads referenced by lead_sequence

Outputs:
  defender/learning/runs/<run_id>/
    actor_input.yaml          actor-facing projection (queries only, no goals/results)
    actor_story.md            adversarial counterfactual narrative (or "SKIP: ...")
    projected_telemetry.yaml  oracle's per-lead synthesized events
    judge_findings.yaml       judge classification + queueable findings
  defender/learning/_pending/findings.jsonl
    appended queueable findings; when count >= LEARNING_AUTHOR_THRESHOLD,
    the lessons curator (author.py) is invoked automatically.

Environment:
  LEARNING_CLAUDE_MODEL          claude model for actor/oracle/judge subagents
                                 (default: claude-haiku-4-5)
  LEARNING_SUBAGENT_TIMEOUT_SECONDS  per-subagent timeout (default: 300)
  LEARNING_AUTHOR_THRESHOLD      pending findings before author runs (default: 5)

Typical use: invoked in-process by `defender/run.py` after the runtime loop
exits. Run standalone with `python3 defender/learning/loop.py <run_dir>` to
re-process an existing run dir (e.g. after a judge-parse failure).

Exit codes: 0 success / 0 skipped (malicious or actor SKIP) /
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
