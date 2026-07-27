"""The two-pass judge: measure the envelope, then grade the projection against it.

The passes are separate calls and the split is load-bearing. The LABEL pass answers
"what did this envelope actually do?" from telemetry alone — it is shown neither the
story nor the oracle's projection. The VERDICT pass answers "did the projection
faithfully represent that?" and receives the label pass's output as the measurement of
record. Merging them would let a confident projection colour the measurement, and the
label pass's calibration set (hand-derived labels, none of them produced with a
projection in view) would stop being like-for-like.

The judge is `claude-opus-5`, deliberately not the oracle's own `glm-5.2`: a same-model
judge shares the failure modes this suite exists to catch — inferring suppression from
absence, accepting a plausible-shaped event the telemetry does not carry.

It is reached through `claude -p` rather than the Anthropic API — see `call_model` for
what that changes and what keeps it honest.

Because the judge runs at score time, the score is non-deterministic and the judge is
part of the tag: `tag_suffix()` carries the resolved model, the effort, and a hash over
BOTH prompts, so editing either is a new tag requiring a re-score.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

GOLDEN_DIR = Path(__file__).resolve().parent
LABEL_PROMPT = GOLDEN_DIR / "prompts" / "label.md"
VERDICT_PROMPT = GOLDEN_DIR / "prompts" / "verdict.md"

DEFAULT_JUDGE_MODEL = "claude-opus-5"
#: `high` is already Opus 5's default. Pinned explicitly anyway so the effort that ran
#: is recorded in the tag and cannot drift under us if a default changes.
DEFAULT_JUDGE_EFFORT = "high"

#: Rows kept per payload before the rest is declared away. A judge that silently
#: received a slice would infer absence from it; the prompts forbid that only because
#: `truncated` tells them a slice is what they got.
MAX_ROWS_PER_PAYLOAD = 40

LABEL_KINDS = frozenset(
    {"present", "indistinguishable", "suppressed", "absent", "state-only", "undecidable"}
)
LABEL_UNDECIDABLE_REASONS = frozenset(
    {"insufficient-baseline", "truncated-payload", "payload-shape-unreadable"}
)
VERDICT_UNDECIDABLE_REASONS = LABEL_UNDECIDABLE_REASONS | {
    "ambiguous-story",
    "contradicts-measurement",
}
CAUSES = frozenset({
    "C-FABRICATED-VALUE", "C-MISSED-DELTA", "C-INVENTED-DELTA", "C-SUPPRESS-UNBASELINED",
    "C-NOISE-AS-EVENT", "C-EVENT-AS-NOISE", "C-INTENT-SCOPE", "C-HETERO-UNDER", "C-OTHER",
})


class GrammarError(ValueError):
    """The model's output did not parse as the closed grammar its prompt mandates."""


def judge_model() -> str:
    return os.environ.get("JUDGE_MODEL") or DEFAULT_JUDGE_MODEL


def judge_effort() -> str:
    return os.environ.get("JUDGE_EFFORT") or DEFAULT_JUDGE_EFFORT


def prompts_sha8() -> str:
    """A hash over BOTH prompts — editing either is a new tag."""
    digest = hashlib.sha256()
    for path in (LABEL_PROMPT, VERDICT_PROMPT):
        digest.update(path.read_bytes())
    return digest.hexdigest()[:8]


def tag_suffix(model: str, effort: str) -> str:
    """The judge half of a score tag. Callers pass the RESOLVED model, never the
    configured default — two machines must not produce identically-named tags from
    different judges."""
    return f"judge-{model}-{effort}_{prompts_sha8()}"


# --------------------------------------------------------------------------- inputs

@dataclass(frozen=True)
class LeadInputs:
    """Everything both passes read, assembled once per lead."""

    case_id: str
    lead_id: str
    lead: dict
    sample: str
    observed: list[dict]
    baseline: list[dict]
    environment_notes: dict
    story: str


def _bounded(payload: Any) -> tuple[Any, bool]:
    """Bound an ES|QL payload's rows; return `(payload, was_cut)`.

    Only the ES|QL `{query, columns, row_count, values}` shape has a row array to bound —
    50 of the tree's 135 payloads are a lookup system's own response instead (a cmdb host
    record, an identity user, a threat-intel verdict, a bare list), and one carries its
    own `truncated` flag from the source. Those pass through untouched: they are small,
    and rewriting a shape we do not model is how a judge ends up grading our edit.
    """
    if not isinstance(payload, dict):
        return payload, False
    values = payload.get("values")
    if not isinstance(values, list) or len(values) <= MAX_ROWS_PER_PAYLOAD:
        return payload, False
    return {
        **payload,
        "values": values[:MAX_ROWS_PER_PAYLOAD],
        # The TRUE count survives the cut — the prompts forbid inferring absence from a
        # slice, which only means anything if the full size is still visible.
        "row_count": payload.get("row_count", len(values)),
    }, True


#: What a payload file that was never written looks like to the judge. `build_case.py`
#: copies the run's raw payloads verbatim, so a zero-byte file means the capture never
#: recorded that query's result — 12 of them are in the tree. Rendering it as an empty
#: result set would ask the judge to infer absence from a missing measurement, which is
#: the error class this whole suite exists to catch.
UNREADABLE_NOTE = (
    "this query's payload was never recorded by the capture. It is NOT an empty result "
    "set and carries no evidence either way"
)


def _payload_entry(path: Path) -> dict:
    """One observed payload as the judge sees it: `payload` plus the flags about it.

    `truncated` sits BESIDE the payload rather than inside it — one source system emits
    its own `truncated` field, and overwriting that would tell the judge our bound was
    the source's.
    """
    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return {"unreadable": True, "note": UNREADABLE_NOTE}
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"unreadable": True, "note": f"{UNREADABLE_NOTE} ({exc})"}
    payload, was_cut = _bounded(doc)
    entry: dict = {"payload": payload}
    if was_cut:
        entry["truncated"] = True
    return entry


def _control(record: dict) -> dict:
    payload, was_cut = _bounded(record.get("payload"))
    control = {
        "name": record.get("name"),
        "window": record.get("window"),
        # The load-bearing bit: an empty window that was never live means "not
        # measured", not "nothing routine happens here".
        "window_live": record.get("live"),
        "payload": payload,
    }
    if was_cut:
        control["truncated"] = True
    return control


def lead_systems(lead: dict) -> set[str]:
    """The systems a lead's queries read, from their `query_id` prefixes.

    `query_id` is `{system}.{kebab-name}` (defender/CLAUDE.md), so a lead's systems are a
    property of the envelope rather than an attribution anyone made. Both the label
    pass's calibration (`audit_judge`) and the report's slice axis (`score.system_of`)
    key off this, and they must not drift apart.
    """
    return {(q.get("query_id") or "").split(".")[0] for q in lead.get("queries") or []}


def load_leads(case_dir: Path) -> list[dict]:
    text = (case_dir / "oracle_visible" / "leads.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load_lead_inputs(case_dir: Path, lead_id: str) -> LeadInputs:
    leads = {row["lead_id"]: row for row in load_leads(case_dir)}
    if lead_id not in leads:
        raise KeyError(f"{case_dir.name} has no lead {lead_id}")

    observed_dir = case_dir / "hidden" / "observed" / lead_id
    observed = [
        {"seq": int(p.stem), **_payload_entry(p)}
        for p in sorted(observed_dir.glob("*.json"), key=lambda p: int(p.stem))
    ] if observed_dir.is_dir() else []

    controls_dir = case_dir / "hidden" / "controls" / lead_id
    baseline = []
    if controls_dir.is_dir():
        for path in sorted(controls_dir.glob("*.json"), key=lambda p: int(p.stem)):
            record = json.loads(path.read_text(encoding="utf-8"))
            baseline.append({
                "seq": record.get("seq", int(path.stem)),
                "controls": [_control(c) for c in record.get("controls") or []],
            })

    sample_path = case_dir / "oracle_visible" / "samples" / f"{lead_id}.txt"
    env_path = case_dir / "environment.yaml"
    return LeadInputs(
        case_id=case_dir.name,
        lead_id=lead_id,
        lead=leads[lead_id],
        sample=sample_path.read_text(encoding="utf-8") if sample_path.exists() else "",
        observed=observed,
        baseline=baseline,
        environment_notes=yaml.safe_load(env_path.read_text(encoding="utf-8")) or {},
        story=(case_dir / "oracle_visible" / "story.md").read_text(encoding="utf-8"),
    )


def _block(name: str, body: Any) -> str:
    rendered = body if isinstance(body, str) else yaml.safe_dump(
        body, sort_keys=False, allow_unicode=True, default_flow_style=False
    )
    return f"<{name}>\n{rendered.rstrip()}\n</{name}>"


def label_user_prompt(inputs: LeadInputs) -> str:
    """The measurement pass's payload. Carries NEITHER the story nor the projection —
    see the module docstring; this exclusion is the whole point of the split."""
    return "\n\n".join([
        _block("lead", inputs.lead),
        _block("sample", inputs.sample),
        _block("observed", inputs.observed),
        _block("baseline", inputs.baseline),
        _block("environment_notes", inputs.environment_notes),
    ])


def verdict_user_prompt(inputs: LeadInputs, projection: Any, measurement: dict) -> str:
    """The grading pass's payload: the same telemetry, plus what the oracle saw, plus
    what it emitted, plus the label pass's reading as the measurement of record."""
    return "\n\n".join([
        _block("story", inputs.story),
        _block("lead", inputs.lead),
        _block("sample", inputs.sample),
        _block("observed", inputs.observed),
        _block("baseline", inputs.baseline),
        _block("environment_notes", inputs.environment_notes),
        _block("measurement", measurement),
        _block("projection", projection),
    ])


# --------------------------------------------------------------------------- parsing

def _document(raw: str) -> dict:
    text = raw.strip()
    # The prompts forbid a fence; a model that adds one anyway has produced a
    # readable document, and rejecting it would charge the oracle for the judge's slip.
    if text.startswith("```"):
        lines = [ln for ln in text.splitlines() if not ln.strip().startswith("```")]
        text = "\n".join(lines).strip()
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise GrammarError(f"output is not YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise GrammarError(f"output is not a mapping: {type(doc).__name__}")
    return doc


def parse_label(raw: str) -> dict:
    doc = _document(raw)
    kind = doc.get("delta_kind")
    if kind not in LABEL_KINDS:
        raise GrammarError(f"delta_kind {kind!r} not in {sorted(LABEL_KINDS)}")
    reason = doc.get("undecidable_reason")
    if kind == "undecidable":
        if reason not in LABEL_UNDECIDABLE_REASONS:
            raise GrammarError(f"undecidable needs a reason, got {reason!r}")
    elif reason is not None:
        raise GrammarError(f"undecidable_reason {reason!r} on a decided label {kind!r}")
    hetero = doc.get("heterogeneous")
    if hetero not in (True, False, None):
        raise GrammarError(f"heterogeneous {hetero!r} is not true/false/null")
    evidence = doc.get("evidence")
    if not isinstance(evidence, str) or not evidence.strip():
        raise GrammarError("evidence is missing or empty")
    return {
        "delta_kind": kind,
        "undecidable_reason": reason,
        "heterogeneous": hetero,
        "evidence": evidence.strip(),
    }


def parse_verdict(raw: str) -> dict:
    doc = _document(raw)
    if "faithful" not in doc:
        raise GrammarError("no `faithful` key")
    faithful = doc["faithful"]
    if faithful not in (True, False, None):
        raise GrammarError(f"faithful {faithful!r} is not true/false/null")
    reason, cause = doc.get("undecidable_reason"), doc.get("cause")
    if faithful is None:
        if reason not in VERDICT_UNDECIDABLE_REASONS:
            raise GrammarError(f"undecidable needs a reason, got {reason!r}")
    elif reason is not None:
        raise GrammarError(f"undecidable_reason {reason!r} on a decided verdict")
    if faithful is False:
        if cause not in CAUSES:
            raise GrammarError(f"cause {cause!r} not in {sorted(CAUSES)}")
    elif cause is not None:
        raise GrammarError(f"cause {cause!r} on a verdict that is not false")
    rationale = doc.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        raise GrammarError("rationale is missing or empty")
    form_notes = doc.get("form_notes")
    return {
        "faithful": faithful,
        "undecidable_reason": reason,
        "cause": cause,
        "form_notes": form_notes if isinstance(form_notes, str) else None,
        "rationale": rationale.strip(),
    }


# ----------------------------------------------------------------------------- calls

@dataclass(frozen=True)
class CallResult:
    """What one judge call produced, plus who actually produced it.

    `model` is read back from the runner rather than echoed from the request: the
    design's rule is that a tag records the RESOLVED judge, so that two machines cannot
    mint identically-named tags from different models.
    """

    text: str
    model: str
    effort: str
    cost_usd: float | None = None


#: `(instructions, user, model, effort) -> CallResult`. The seam tests inject through.
CallFn = Callable[[str, str, str, str], CallResult]

CLAUDE_BIN = os.environ.get("CLAUDE_BIN") or "claude"
CALL_TIMEOUT_SECONDS = 900

#: Every tool the runner would otherwise offer. A judge that can read the filesystem can
#: read `expected.yaml`, and a measurement that consulted the answer key is not one. The
#: empty allowlist is the guard; this denylist is the belt to its braces.
_DENIED_TOOLS = (
    "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,Task,TodoWrite,NotebookEdit,"
    "BashOutput,KillShell,SlashCommand,Skill"
)


def call_model(instructions: str, user: str, model: str, effort: str) -> CallResult:
    """One single-turn, tool-free judge call, through `claude -p`.

    NOT a bare API call, and the difference is worth stating: the judge runs inside the
    Claude Code harness, so ~11k tokens of runner scaffolding precede our instructions.
    That prefix is byte-identical across every lead, so it is created once and read from
    cache thereafter (~$0.006/call) — but it is there, and a prompt-level finding about
    this judge is a finding about the judge-inside-the-runner.

    Three things keep it honest:

    * **No tools.** An empty allowlist plus an explicit denylist. Verified: asked to read
      a file, it answers that it has no file-reading tool.
    * **A neutral working directory.** Run from an empty temp dir, so no CLAUDE.md, git
      status or repo listing is discovered — which both stabilises the cacheable prefix
      and keeps the case tree out of the judge's reach by a second route.
    * **No inherited API key.** `ANTHROPIC_API_KEY` is dropped from the child's
      environment so the runner uses its own credentials.
    """
    with tempfile.TemporaryDirectory(prefix="oracle-judge-") as neutral:
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        proc = subprocess.run(
            [CLAUDE_BIN, "-p",
             "--model", model,
             "--effort", effort,
             "--system-prompt", instructions,
             "--allowed-tools", "",
             "--disallowed-tools", _DENIED_TOOLS,
             "--strict-mcp-config",
             "--no-session-persistence",
             "--output-format", "json"],
            input=user, capture_output=True, text=True, encoding="utf-8",
            cwd=neutral, env=env, timeout=CALL_TIMEOUT_SECONDS, check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError(f"{CLAUDE_BIN} exited {proc.returncode}: {proc.stderr.strip()[:400]}")
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{CLAUDE_BIN} did not emit JSON: {proc.stdout[:400]}") from exc
    if report.get("is_error") or report.get("subtype") != "success":
        raise RuntimeError(f"judge call failed: {report.get('result') or report}")

    # Read the model back rather than trusting the request. A run that silently fell
    # back to another model must not be ledgered under the tag we asked for.
    used = [name for name in report.get("modelUsage") or {} if name == model]
    if not used:
        raise RuntimeError(
            f"asked for {model!r} but the run reports {sorted(report.get('modelUsage') or {})}"
        )
    return CallResult(text=report["result"], model=model, effort=effort,
                      cost_usd=report.get("total_cost_usd"))


#: How many attempts one pass gets before its GrammarError propagates.
GRAMMAR_ATTEMPTS = 3


def _reparse_note(error: Exception) -> str:
    """The only thing a retry adds: a complaint about the ENVELOPE, never the judgement.

    The first version of the retry re-sent a byte-identical payload, on the reasoning
    that a retry is for a malformed envelope around a real judgement and not for a
    verdict we dislike. That reasoning is right and this preserves it — nothing here
    describes the telemetry, the projection, or what a good answer looks like. It names
    the parse failure and the YAML rule that avoids it.

    It was needed: a real case-005 verdict wrote its `rationale` as a plain scalar
    containing `pam_unix(sshd:auth): authentication failure`, and a plain YAML scalar
    cannot carry `: `. Two identical attempts both produced it, because nothing told the
    model its output had not parsed.
    """
    return (
        "\n\n<retry>\n"
        f"Your previous response did not parse: {error}\n"
        "Emit the SAME judgement again, unchanged in substance, as a single valid YAML "
        "document. Do not reconsider it — only its form was wrong. Most often the cause "
        "is a multi-word value written as a plain scalar while containing `: ` or `#`; "
        "write every prose value as a block scalar (`key: |` then an indented line).\n"
        "</retry>"
    )


def _pass(prompt_path: Path, user: str, parse, *, model: str, effort: str,
          call: CallFn) -> dict:
    """Run one pass, re-asking on a grammar failure until `GRAMMAR_ATTEMPTS` are spent.

    Only the envelope complaint changes between attempts — see `_reparse_note`. The
    payload the judgement is made from is byte-identical every time.
    """
    instructions = prompt_path.read_text(encoding="utf-8")
    payload = user
    for attempt in range(GRAMMAR_ATTEMPTS):
        result = call(instructions, payload, model, effort)
        try:
            parsed = parse(result.text)
            break
        except GrammarError as exc:
            if attempt == GRAMMAR_ATTEMPTS - 1:
                raise
            payload = user + _reparse_note(exc)
    # Provenance, not grammar: which judge actually answered, recorded per lead so the
    # committed artifact can be checked against the tag it was filed under.
    return {**parsed, "judge_model": result.model, "judge_effort": result.effort,
            "cost_usd": result.cost_usd}


def label_lead(inputs: LeadInputs, *, model: str | None = None, effort: str | None = None,
               call: CallFn = call_model) -> dict:
    return _pass(LABEL_PROMPT, label_user_prompt(inputs), parse_label,
                 model=model or judge_model(), effort=effort or judge_effort(), call=call)


def verdict_lead(inputs: LeadInputs, projection: Any, measurement: dict, *,
                 model: str | None = None, effort: str | None = None,
                 call: CallFn = call_model) -> dict:
    return _pass(VERDICT_PROMPT, verdict_user_prompt(inputs, projection, measurement),
                 parse_verdict,
                 model=model or judge_model(), effort=effort or judge_effort(), call=call)
