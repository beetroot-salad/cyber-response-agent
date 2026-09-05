"""The judge's model call: the correlating prompt, lenient parse / strict validate, evidence
grounding, and one write per (world, draw) (#921 M2, D2, D3, D4, O1, O8, O9).

D2 — the judge runs under `AgentRole.QUESTIONER`'s existing definition, with `agent_id`
prefix `"judge:"`. `AgentRole.JUDGE` is already bound to the old pipeline's `JUDGE_DEF`, and the
registry admits one definition per key (`agent_definition.build_registry`), so a second
definition cannot register beside it until #922 frees the key.

Model and effort come from `learning.core.config.judge_model()`/`judge_effort()` — read at call
time in `learning/judge/__init__.py` and threaded into the `StageWiring` the orchestration
builds, never from `questioner_model()`.

THE TWO JUDGES SHARE THOSE KNOBS, and that is a limitation rather than a design. `JUDGE_MODEL`
and `JUDGE_EFFORT` already name the OLD pipeline judge's model, so setting either retargets
both; this module went through `config`'s accessors rather than spelling the same
`env_str("JUDGE_MODEL", …)` a second time, because two copies of one default is drift waiting
to happen and buys no separation at all. Separating them means a knob NAME of this judge's own,
which the spec's fixtures pin to the shared spelling — so it is a change to make deliberately,
not a side effect of reading the env twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender._untrusted import message_salt, wrap
from defender.learning._prompt import stage_user_message, titled_section
from defender.learning.core.validate import normalize_judge_yaml
from defender.learning.judge._errors import JudgeRefused
from defender.learning.judge.render import JudgeInput

#: The judge's own reply-level outcome vocabulary — NOT `_vocab.JUDGE_OUTCOME_ENUM`. That
#: vocabulary is the FAMILY's word (`caught|survived|undecidable|discard|corpus-contradiction`,
#: shared by the queue row, the family record and the curator gate); a raw reply never emits
#: `caught`/`survived`/`undecidable` (only the mechanical pass computes those), and it CAN emit
#: `gradable`, which is not a family word at all. Local because nothing else has to agree with
#: it — `_vocab.py`'s own admission rule.
_REPLY_OUTCOME_ENUM = frozenset({"gradable", "discard", "corpus-contradiction"})

#: The finding bucket vocabulary — closed, and NEVER coerced to the nearest member (a
#: lookalike is rejected, not rounded).
_BUCKET_ENUM = frozenset(
    {"lead-set", "lead-quality", "analyze-discipline", "decision-discipline", "observability"})

_ROLE_PROMPT = Path(__file__).resolve().parent / "role.md"

#: Each rendered section's own heading, in the order the prompt presents them. The four the
#: task sentence calls "the joined views" keep the numbering the measured arm used, so a reader
#: of the reply can name which view a finding came from; the manifest, the document and the
#: report are the graded world's own bytes and are titled for what they are.
SECTION_TITLES: dict[str, str] = {
    "manifest": "THE FAMILY MANIFEST (the graded world last; every other world counterfactual)",
    "leads": "VIEW 1 — PER-LEAD CHAIN (goal -> params -> payload -> summary -> document rows "
             "-> resolutions)",
    "coverage": "VIEW 2 — COVERAGE (what this world asked on the family's holding system)",
    "siblings": "VIEW 3 — SIBLING TRIALS OF THIS SAME ALERT",
    "lessons": "VIEW 4 — LESSONS LOADED INTO THIS WORLD (name, path, and the body at its "
               "recorded commit)",
    "spread": "TRIAL SPREAD (the dispositions those sibling trials reached, tallied)",
    "document": "THE GRADED WORLD'S OWN investigation.md",
    "report": "THE GRADED WORLD'S OWN report.md",
}



def _normalize_reply_outcome(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    outcome = value.strip().casefold()
    return outcome if outcome in _REPLY_OUTCOME_ENUM else None


@dataclass(frozen=True)
class Finding:
    bucket: str
    claim: str
    root_cause: str
    anchor: str
    topic: str
    evidence: list[str] = field(default_factory=list)
    discriminator_related: bool = False


@dataclass(frozen=True)
class JudgeReply:
    episode_outcome: str
    noise_floor_note: str
    correlations: list[Any]
    scope_checks: list[Any]
    derivations: list[Any]
    findings: list[Finding]


def _require_dict(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise JudgeRefused(
            f"the judge's reply did not parse to a mapping (got {type(doc).__name__})")
    return doc


def _require_list(doc: dict[str, Any], key: str) -> list[Any]:
    if key not in doc:
        raise JudgeRefused(f"the judge's reply is missing the {key!r} pass table")
    value = doc[key]
    if not isinstance(value, list):
        raise JudgeRefused(f"the judge's reply's {key!r} must be a list")
    return value


def _parse_finding(raw: Any, index: int) -> Finding:
    if not isinstance(raw, dict):
        raise JudgeRefused(f"finding[{index}] is not a mapping")
    for key in ("bucket", "claim", "root_cause", "anchor", "topic", "evidence"):
        if key not in raw:
            raise JudgeRefused(f"finding[{index}] is missing {key!r}")
    bucket = raw["bucket"]
    if not isinstance(bucket, str) or bucket not in _BUCKET_ENUM:
        raise JudgeRefused(
            f"finding[{index}].bucket={bucket!r} is not one of {sorted(_BUCKET_ENUM)} — a "
            "lookalike is rejected, never coerced to the nearest member")
    evidence = raw["evidence"]
    if not isinstance(evidence, list):
        raise JudgeRefused(f"finding[{index}].evidence must be a list")
    return Finding(
        bucket=bucket, claim=str(raw["claim"]), root_cause=str(raw["root_cause"]),
        anchor=str(raw["anchor"]), topic=str(raw["topic"]),
        evidence=[str(e) for e in evidence],
        discriminator_related=bool(raw.get("discriminator_related", False)),
    )


def validate_reply(text: str) -> JudgeReply:
    """Parse `text` LENIENTLY (a fence with prose around it recovers cleanly — C12) and
    validate STRICTLY: nothing is read off the reply before this returns."""
    import yaml

    cleaned = normalize_judge_yaml(text)
    try:
        doc = yaml.safe_load(cleaned)
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"the judge's reply is not valid YAML: {bad}") from bad
    doc = _require_dict(doc)

    outcome = _normalize_reply_outcome(doc.get("episode_outcome"))
    if outcome is None:
        raise JudgeRefused(
            f"the judge's reply's episode_outcome={doc.get('episode_outcome')!r} is not one "
            f"of {sorted(_REPLY_OUTCOME_ENUM)}")
    correlations = _require_list(doc, "correlations")
    scope_checks = _require_list(doc, "scope_checks")
    derivations = _require_list(doc, "derivations")
    findings_raw = doc.get("findings")
    if not isinstance(findings_raw, list):
        raise JudgeRefused("the judge's reply's findings must be a list")
    findings = [_parse_finding(f, i) for i, f in enumerate(findings_raw)]
    noise = doc.get("noise_floor_note")
    return JudgeReply(
        episode_outcome=outcome, noise_floor_note=str(noise) if noise is not None else "",
        correlations=correlations, scope_checks=scope_checks, derivations=derivations,
        findings=findings,
    )


def _resolves(pointer: str, world_dir: Path) -> bool:
    """J13(a): does this evidence pointer resolve inside the GRADED WORLD's own subtree —
    never the episode, never a sibling's archive, whatever bytes exist at the target."""
    if not isinstance(pointer, str) or not pointer:
        return False
    path_part = pointer.split("#", 1)[0]
    if not path_part or Path(path_part).is_absolute():
        return False
    try:
        root = world_dir.resolve()
        candidate = (world_dir / path_part).resolve()
        candidate.relative_to(root)
    except (OSError, ValueError):
        return False
    return candidate.is_file()


def _draw_document(reply: JudgeReply, *, world_dir: Path) -> dict[str, Any]:
    """O1: a finding with no resolving pointer is dropped and the drop is counted; a finding
    with one resolving pointer stands, with its unresolved pointers recorded on it."""
    kept: list[dict[str, Any]] = []
    dropped = 0
    for finding in reply.findings:
        # ONE resolution pass per pointer: "did any resolve" and "which did not" are two reads
        # of the same answer, and asking twice `stat`s every pointer of every finding twice.
        unresolved = [p for p in finding.evidence if not _resolves(p, world_dir)]
        if len(unresolved) == len(finding.evidence):
            dropped += 1
            continue
        kept.append({
            "bucket": finding.bucket, "claim": finding.claim, "root_cause": finding.root_cause,
            "anchor": finding.anchor, "topic": finding.topic, "evidence": finding.evidence,
            "unresolved_evidence": unresolved,
            "discriminator_related": finding.discriminator_related,
        })
    return {
        "episode_outcome": reply.episode_outcome, "noise_floor_note": reply.noise_floor_note,
        "correlations": reply.correlations, "scope_checks": reply.scope_checks,
        "derivations": reply.derivations, "findings": kept, "dropped_findings": dropped,
    }


def _build_prompt(judge_input: JudgeInput, *, world_label: str) -> str:
    """D4: the correlating prompt, parameterised by the graded world's label. Wording names
    hand-offs, never entities or systems; keeps the 20-row cap and the quote-any-colon rule
    that made 15/15 replies parse strictly (C12)."""
    task = (
        f"World {world_label} has run; grade it.\n\n"
        "Compare it against the four joined views below: its per-lead chain (goal, params, "
        "payload, summary, document rows, resolutions), its coverage of the family's "
        "discriminator, the sibling trials of this same alert, and the lessons it loaded — "
        "plus the trial spread. Every OTHER world is marked counterfactual: withhold its "
        "overlay from your reasoning and never cite its facts as facts about the graded "
        "world.\n\n"
        "Before findings, run three passes and report each as its own table:\n"
        "1. CORRELATION — for every fact reachable across two joined rows, name the hand-off.\n"
        "2. SCOPE — for every lead touching the holding system, name the index, window and "
        "scope key it actually used.\n"
        "3. DERIVATION — for every held row, say whether it was derived from a payload the "
        "defender actually read, or invented.\n\n"
        "Cap any table at 20 rows. Quote any YAML scalar containing a colon — that is what "
        "made every reply of the correlating prompt's own trial parse strictly.\n\n"
        "Reply as one YAML mapping: episode_outcome (one of the three episode-outcome words — "
        "gradable, or the discard word, or the two-word corpus/world contradiction outcome), "
        "noise_floor_note, correlations, scope_checks, derivations, findings (each: bucket "
        "[lead-set|lead-quality|analyze-discipline|decision-discipline|observability], claim, "
        "root_cause, anchor, topic, evidence, discriminator_related).\n"
    )
    sections = judge_input.as_prompt_sections()
    titled = [titled_section(SECTION_TITLES[name], sections[name]) for name in SECTION_TITLES]
    salt = message_salt(task, *titled)
    # ONE tag, "untrusted", on every section: the reader contract names sections by their
    # run-salted frame, not by tag, and the suite's own frame regex (`_triplet_947.
    # UNTRUSTED_FRAME`) matches only `-untrusted` — a per-section tag name would silently
    # leave every body outside what the suite recognises as an untrusted frame at all.
    #
    # SO THE SECTION'S NAME IS ITS TITLE, INSIDE THE FRAME. The arm this prompt is ported from
    # headed each view (`## VIEW 1 — PER-LEAD CHAIN …` through `## VIEW 4 — TRIAL SPREAD …`),
    # and the port dropped them: eight identically-tagged bodies concatenated with no names,
    # under a task that says "compare it against the four joined views below". Coverage rows,
    # sibling rows and spread rows are all bullet lists, so they ran together indistinguishably.
    # The title goes INSIDE the frame (`_prompt.titled_section`, the questioner's own spelling)
    # because a heading in the host region beside a framed body is one an attacker can imitate
    # from inside the body.
    body = stage_user_message(salt, *(wrap(section, "untrusted", salt) for section in titled))
    return task + body


__all__ = ["Finding", "JudgeReply", "_build_prompt", "validate_reply"]
