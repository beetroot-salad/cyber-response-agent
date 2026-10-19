"""The two-pass judge: measure the envelope, then grade the projection against it.

The LABEL pass answers "what did this envelope actually do?" from telemetry alone, shown
neither the story nor the projection. The VERDICT pass answers "did the projection
faithfully represent that?" given the label as the measurement of record. Separate calls,
so a confident projection cannot colour the measurement, and the label pass stays
comparable with its hand-labelled calibration set.

The judge is `claude-opus-5`, not the oracle's own `glm-5.2`: a same-model judge shares
the failure modes this suite exists to catch. It runs through `claude -p` (see
`call_model`).

The judge is part of the score tag: `tag_suffix()` carries the resolved model, the effort,
and a hash over both prompts, so editing either requires a re-score.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import yaml

from defender import _yaml

from defender._model import model
from defender._io import read_bytes_capped, read_text_utf8

GOLDEN_DIR = Path(__file__).resolve().parent
LABEL_PROMPT = GOLDEN_DIR / "prompts" / "label.md"
VERDICT_PROMPT = GOLDEN_DIR / "prompts" / "verdict.md"

DEFAULT_JUDGE_MODEL = "claude-opus-5"
#: Pinned (though it is the default) so the tag records it and it cannot drift.
DEFAULT_JUDGE_EFFORT = "high"

#: Rows kept per payload. Cut payloads are flagged `truncated` so the judge does not infer
#: absence from a slice.
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


# lint-dup: ok — same names as learning/core/config.py but a different judge (the calibration
# judge, not the loop's classifier), and its values feed the score tag, so a change there must
# not re-tag committed scores.
#
# The env var names ARE shared with `learning/core/config.py` (different defaults): setting
# either here also retargets the family judge, and an unroutable model then fails `run.py`'s
# all-roles preflight.
def judge_model() -> str:  # lint-dup: ok — see the note above
    return os.environ.get("JUDGE_MODEL") or DEFAULT_JUDGE_MODEL


def judge_effort() -> str:  # lint-dup: ok — see the note above
    return os.environ.get("JUDGE_EFFORT") or DEFAULT_JUDGE_EFFORT


def prompts_sha8() -> str:
    """A hash over both prompts; editing either is a new tag."""
    digest = hashlib.sha256()
    for path in (LABEL_PROMPT, VERDICT_PROMPT):
        digest.update(read_bytes_capped(path))
    return digest.hexdigest()[:8]


def tag_suffix(model: str, effort: str) -> str:
    """The judge half of a score tag. Callers pass the resolved model, never the configured
    default, so two machines cannot mint the same tag from different judges."""
    return f"judge-{model}-{effort}_{prompts_sha8()}"


# inputs

@model(frozen=True)
class LeadInputs:
    """Everything both passes read, assembled once per lead."""

    case_id: str
    lead_id: str
    #: The lead as a model sees it (`lead_for_model`), not the raw `leads.jsonl` row.
    lead: dict
    sample: str
    observed: list[dict]
    baseline: list[dict]
    environment_notes: dict
    story: str


def _bounded(payload: Any) -> tuple[Any, bool]:
    """Bound an ES|QL payload's rows; return `(payload, was_cut)`.

    Only the ES|QL `{query, columns, row_count, values}` shape is bounded. Other payloads
    (lookup-system responses) are small and pass through untouched.
    """
    if not isinstance(payload, dict):
        return payload, False
    values = payload.get("values")
    if not isinstance(values, list) or len(values) <= MAX_ROWS_PER_PAYLOAD:
        return payload, False
    return {
        **payload,
        "values": values[:MAX_ROWS_PER_PAYLOAD],
        # Keep the true count so the full size stays visible.
        "row_count": payload.get("row_count", len(values)),
    }, True


#: Shown for a zero-byte or unparseable payload: the capture never recorded that result, and
#: presenting it as an empty result set would invite inferring absence.
UNREADABLE_NOTE = (
    "this query's payload was never recorded by the capture. It is NOT an empty result "
    "set and carries no evidence either way"
)


def _payload_entry(path: Path) -> dict:
    """One observed payload as the judge sees it: `payload` plus the flags about it.

    `truncated` sits beside the payload, not inside it: one source system emits its own
    `truncated` field.
    """
    raw = read_text_utf8(path)
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
        # An empty window that was never live means "not measured", not "nothing routine".
        "window_live": record.get("live"),
        "payload": payload,
    }
    if was_cut:
        control["truncated"] = True
    return control


def lead_systems(lead: dict) -> set[str]:
    """The systems a lead's queries read, from their `query_id` prefixes.

    `query_id` is `{system}.{kebab-name}`. Shared by `audit_judge` and `score.system_of` so
    calibration and report slices agree.
    """
    return {(q.get("query_id") or "").split(".")[0] for q in lead.get("queries") or []}


def load_case_leads(case_dir: Path) -> list[dict]:
    text = read_text_utf8(case_dir / "oracle_visible" / "leads.jsonl")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


#: The lead fields a judge pass may reason about. An allowlist, so a plumbing field (e.g.
#: `seq`) added to `leads.jsonl` cannot reach a prompt: that would change the measurement
#: under an unchanged `prompts_sha8` and label cache key, so a rebuilt case
#: would be labelled from a different input shape than its siblings under one tag.
#:
#: #1054 is an accepted instance: `hidden/`'s ES|QL payloads were re-encoded to the
#: positional shape under an unchanged tag, so `case-006-authorized-keys-db1` and
#: `case-007-lotl-web1` (no label cache) would be labelled from a different encoding than
#: the other leads. See `audits/README.md`'s 2026-09-19 note.
MODEL_LEAD_FIELDS = ("lead_id", "goal", "what_to_summarize", "queries")
MODEL_QUERY_FIELDS = ("query_id", "params")


def lead_for_model(lead: dict) -> dict:
    """The `leads.jsonl` row projected down to what a judge prompt should carry."""
    out = {k: lead[k] for k in MODEL_LEAD_FIELDS if k in lead}
    if "queries" in out:
        out["queries"] = [{k: q[k] for k in MODEL_QUERY_FIELDS if k in q}
                          for q in out["queries"]]
    return out


def load_lead_inputs(case_dir: Path, lead_id: str) -> LeadInputs:
    leads = {row["lead_id"]: row for row in load_case_leads(case_dir)}
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
            record = json.loads(read_text_utf8(path))
            baseline.append({
                "seq": record.get("seq", int(path.stem)),
                "controls": [_control(c) for c in record.get("controls") or []],
            })

    sample_path = case_dir / "oracle_visible" / "samples" / f"{lead_id}.txt"
    env_path = case_dir / "environment.yaml"
    # Must be a mapping; refused here so the error names the file rather than surfacing as a
    # `ValidationError` from `LeadInputs`.
    environment_notes = _yaml.safe_load(read_text_utf8(env_path)) or {}
    if not isinstance(environment_notes, dict):
        raise ValueError(
            f"{env_path}: environment.yaml must be a YAML mapping, "
            f"got {type(environment_notes).__name__}")
    return LeadInputs(
        case_id=case_dir.name,
        lead_id=lead_id,
        lead=lead_for_model(leads[lead_id]),
        sample=read_text_utf8(sample_path) if sample_path.exists() else "",
        observed=observed,
        baseline=baseline,
        environment_notes=environment_notes,
        story=read_text_utf8(case_dir / "oracle_visible" / "story.md"),
    )


def _block(name: str, body: Any) -> str:
    rendered = body if isinstance(body, str) else _yaml.safe_dump(
        body, sort_keys=False, allow_unicode=True, default_flow_style=False
    )
    return f"<{name}>\n{rendered.rstrip()}\n</{name}>"


def label_user_prompt(inputs: LeadInputs) -> str:
    """The measurement pass's payload. Carries neither the story nor the projection."""
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


# parsing

def _document(raw: str) -> dict:
    text = raw.strip()
    # The prompts forbid a fence, but a fenced document is still readable.
    if text.startswith("```"):
        lines = [ln for ln in text.splitlines() if not ln.strip().startswith("```")]
        text = "\n".join(lines).strip()
    try:
        doc = _yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise GrammarError(f"output is not YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise GrammarError(f"output is not a mapping: {type(doc).__name__}")
    return doc


def parse_label(raw: str) -> dict:
    doc = _document(raw)
    kind = doc.get("delta_kind")
    # `isinstance` before each frozenset membership test: an unhashable list/mapping would
    # raise `TypeError`, which `_pass`'s retry loop does not catch. Tri-states use
    # `isinstance(x, bool)` because `0 == False` would let a YAML integer through.
    if not isinstance(kind, str) or kind not in LABEL_KINDS:
        raise GrammarError(f"delta_kind {kind!r} not in {sorted(LABEL_KINDS)}")
    reason = doc.get("undecidable_reason")
    if kind == "undecidable":
        if not isinstance(reason, str) or reason not in LABEL_UNDECIDABLE_REASONS:
            raise GrammarError(f"undecidable needs a reason, got {reason!r}")
    elif reason is not None:
        raise GrammarError(f"undecidable_reason {reason!r} on a decided label {kind!r}")
    hetero = doc.get("heterogeneous")
    if not (isinstance(hetero, bool) or hetero is None):
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


def parse_verdict_reply(raw: str) -> dict:
    doc = _document(raw)
    if "faithful" not in doc:
        raise GrammarError("no `faithful` key")
    faithful = doc["faithful"]
    if not (isinstance(faithful, bool) or faithful is None):
        raise GrammarError(f"faithful {faithful!r} is not true/false/null")
    reason, cause = doc.get("undecidable_reason"), doc.get("cause")
    if faithful is None:
        if not isinstance(reason, str) or reason not in VERDICT_UNDECIDABLE_REASONS:
            raise GrammarError(f"undecidable needs a reason, got {reason!r}")
    elif reason is not None:
        raise GrammarError(f"undecidable_reason {reason!r} on a decided verdict")
    if faithful is False:
        if not isinstance(cause, str) or cause not in CAUSES:
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


# calls

@model(frozen=True)
class CallResult:
    """What one judge call produced, plus who actually produced it.

    `model` is read back from the runner, not echoed from the request, so a tag records the
    judge that actually ran.
    """

    text: str
    model: str
    effort: str
    cost_usd: float | None = None


#: `(instructions, user, model, effort) -> CallResult`. The seam tests inject through.
CallFn = Callable[[str, str, str, str], CallResult]

CLAUDE_BIN = os.environ.get("CLAUDE_BIN") or "claude"
CALL_TIMEOUT_SECONDS = 900

#: Every tool the runner would otherwise offer, denied as a backstop to the empty allowlist: a
#: judge that can read the filesystem can read `expected.yaml`.
_DENIED_TOOLS = (
    "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,Task,TodoWrite,NotebookEdit,"
    "BashOutput,KillShell,SlashCommand,Skill"
)


def call_model(instructions: str, user: str, model: str, effort: str) -> CallResult:
    """One single-turn, tool-free judge call, through `claude -p`.

    Not a bare API call: ~11k tokens of runner scaffolding (identical across leads, so
    cached) precede our instructions, and findings about this judge are about the
    judge-inside-the-runner.

    * **No tools**: an empty allowlist plus an explicit denylist.
    * **A neutral working directory**: an empty temp dir, so no CLAUDE.md, git status or
      repo listing is discovered; stabilises the cached prefix and keeps the case tree out
      of reach.
    * **No inherited API key**: `ANTHROPIC_API_KEY` is dropped so the runner uses its own
      credentials.
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

    # A silent fallback to another model must not be filed under the requested tag.
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
    """What a retry appends: a complaint about the envelope's form, never the judgement.

    A byte-identical re-send would reproduce the commonest failure (a plain scalar containing
    `: `), so it names the parse error and the YAML rule that avoids it.
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

    Only the appended `_reparse_note` changes between attempts.
    """
    instructions = read_text_utf8(prompt_path)
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
    # Per-lead provenance, so the artifact can be checked against its tag.
    return {**parsed, "judge_model": result.model, "judge_effort": result.effort,
            "cost_usd": result.cost_usd}


def sole_judge(answers: Iterable[dict], *, what: str) -> str:
    """The one judge that answered all of `answers`, or a `RuntimeError` naming the set.

    Catches a run that silently fell back mid-sweep and would file two judges' answers under
    one tag. `what` names the batch in the message. An empty batch (reachable when every case
    is defective or derived) gets its own message.
    """
    resolved = {answer["judge_model"] for answer in answers}
    if not resolved:
        raise RuntimeError(f"{what} has no replies to read a judge off")
    if len(resolved) != 1:
        raise RuntimeError(f"{what} ran on more than one judge: {sorted(resolved)}")
    return resolved.pop()


def total_cost(answers: Iterable[dict]) -> float | None:
    """What a batch of replies cost, or `None` if no reply priced itself.

    `None` means unknown, and must not be reported as `$0.0`."""
    priced = [answer["cost_usd"] for answer in answers if answer.get("cost_usd") is not None]
    return round(sum(priced), 4) if priced else None


def label_lead(inputs: LeadInputs, *, model: str | None = None, effort: str | None = None,
               call: CallFn = call_model) -> dict:
    return _pass(LABEL_PROMPT, label_user_prompt(inputs), parse_label,
                 model=model or judge_model(), effort=effort or judge_effort(), call=call)


def verdict_lead(inputs: LeadInputs, projection: Any, measurement: dict, *,
                 model: str | None = None, effort: str | None = None,
                 call: CallFn = call_model) -> dict:
    return _pass(VERDICT_PROMPT, verdict_user_prompt(inputs, projection, measurement),
                 parse_verdict_reply,
                 model=model or judge_model(), effort=effort or judge_effort(), call=call)
