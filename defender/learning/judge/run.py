"""The judge's model call: the correlating prompt, lenient parse / strict validate, evidence
grounding, and one write per (world, draw).

The judge runs under its own deny-all `AgentRole.JUDGE` (`JUDGE_DEF`, `agent_id` prefix
`"judge:"`). One deny-all key per package: a grant added to `QUESTIONER_DEF` cannot reach the
judge, and granting the judge anything must be said in this file. `agent_id` partitions traces,
never policies, so the separation has to be the key. (The two policies differ only in
`deny_reason`, which only the bash gate reads, so the judge never actually sees it.)

Model and effort are read at call time from `config.judge_model()`/`judge_effort()` and threaded
into the `StageWiring`. `JUDGE_DEF` names the same accessors for builds outside that wiring, but
its `effort` is a plain string evaluated once at import, so it is only a default.

`JUDGE_MODEL` and `JUDGE_EFFORT` are shared: `evals/oracle_golden/judge.py` reads both with
different defaults (`claude-opus-5` / `high` vs `kimi-k3` / `medium`) and tags its scores with the
resolved model, so setting either knob affects both. And `run.py`'s all-roles preflight checks
every registered definition's model at investigation startup, so a `JUDGE_MODEL` no provider
routes makes every alert run (and `--resume` sibling) exit rc 2. Separating them needs a knob
name of the judge's own.
"""

from __future__ import annotations

from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import Any, ClassVar

from defender.run_repository import artifact_file
from defender._untrusted import message_salt, wrap
from defender.learning._prompt import stage_user_message, titled_section
from defender._episode_paths import LAYOUT
from defender.learning.core.config import (
    QUEUEABLE_FINDING_TYPES,
    judge_effort,
    judge_model,
)
from defender.learning.core.validate import MalformedReply, reply_document_text
from defender.learning.judge._errors import JudgeRefused
from defender.learning.judge.render import UNTRUSTED_TAG, JudgeInput
from defender.runtime.agent_definition import AgentDefinition
from defender.runtime.agent_role import AgentRole
from defender._vocab import JUDGE_OUTCOME_ENUM, normalized_judge_outcome

#: The judge's refusal text, carried on its compiled policy. Only the bash gate reads it, which
#: this tool-less role never invokes, so it surfaces to operators rather than to a draw.
#:
#: Where a deny reason is shown it is prompt surface, so it names no program or capability the
#: role lacks (that would teach a dead one). The grant gate checks programs; tools are kept out
#: by hand. It describes exactly what the prompt holds: one world plus its control.
_JUDGE_DENY_REASON = (
    "Blocked: nothing is reachable from a judge draw. This episode was archived before the "
    "call began, and the world under grading — with the control it is compared against — was "
    "rendered into the prompt you already hold. There is no path left to resolve and no "
    "system left to ask, and a grade that reached for more would be grading something other "
    "than what was served. Answer from the prompt, as one YAML verdict document — bare, not "
    "inside a code fence, with nothing before or after it."
)


@model(frozen=True)
class JudgeDeps:
    """Zero fields: a field would be a channel to state this deny-all role must not have, since
    everything the judge reads is inlined by the host in one user message. `role` is a
    `ClassVar`, which is how `build_stage_agent` finds the definition.

    Not an `AgentDeps` subclass: that is the run scope (run dir, policy, box executor), and
    `bind(JUDGE_DEF, ...)` refuses by name, as there is no run for this role.
    """

    role: ClassVar[AgentRole] = AgentRole.JUDGE


#: The family judge's whole policy. Every grant surface is omitted (deny-all default) rather
#: than spelled as an empty grant, which a one-word edit would reopen.
JUDGE_DEF = AgentDefinition(
    role=AgentRole.JUDGE,
    model=judge_model,
    effort=judge_effort(),
    deps_cls=JudgeDeps,
    deny_reason=_JUDGE_DENY_REASON,
)

#: The judge's reply-level outcome vocabulary — not `_vocab.JUDGE_OUTCOME_ENUM`, which is the
#: family's word (the family-scope reply's `verdict_word`). A world reply says whether its world
#: can be judged at all.
_REPLY_OUTCOME_ENUM = frozenset({"gradable", "discard", "corpus-contradiction"})

#: What each reply-level outcome means, keyed by the word, so every member reaches the prompt
#: with a criterion; `_outcome_guidance` refuses if the two sets disagree.
_OUTCOME_GUIDANCE: dict[str, str] = {
    "gradable": (
        "this world ran and its record can be judged. THIS IS THE ORDINARY ANSWER, and it is "
        "still the answer when the investigator did badly: a world whose investigator never "
        "asked where the facts would show, never re-opened a lead, or closed over an open "
        "hypothesis is a world you can judge, and those are exactly the findings worth having"
    ),
    "discard": (
        "this world cannot be measured because the MEASUREMENT is spoilt — the live systems "
        "drifted from the capture on the calls that matter, or what the world was asked is not "
        "what it was answered. Nothing about the investigator's conduct puts an episode here"
    ),
    "corpus-contradiction": (
        "the world's own facts contradict the capture it was branched from, so the archive "
        "disagrees with itself and no verdict read off it means anything. Evidence the "
        "investigator never looked at is NOT a contradiction; it is a gradable world in which "
        "the investigator did not look"
    ),
}


def _outcome_guidance() -> str:
    """The episode-outcome words and their criteria, one line each.

    Refuses rather than rendering a partial list: an unexplained outcome is chosen by guessing,
    and a wrong guess can discard every finding in the draw.
    """
    missing = sorted(_REPLY_OUTCOME_ENUM - set(_OUTCOME_GUIDANCE))
    if missing:
        raise JudgeRefused(
            f"the judge's prompt has no criterion for episode_outcome {missing} — the "
            "validator accepts them and the model would be choosing by guesswork")
    return "".join(
        f"- `{word}` — {_OUTCOME_GUIDANCE[word]}.\n" for word in sorted(_REPLY_OUTCOME_ENUM)
    )

#: The two `subject` literals. Matched exactly everywhere (no case-fold, no trim), so this
#: selector and the appender's guard agree by construction.
SUBJECT_DEFENDER = "defender"
SUBJECT_WORLD = "world"

#: The bucket a world-scope reply gives when the world shows no investigator failure (M19=A):
#: recorded on the family record, never enqueued (the queue's own set refuses it).
NO_BUCKET = "none"
#: The one bucket the host refuses for a world whose reply names no served system (M20=A).
LEAD_SET = "lead-set"

#: A world's bucket — the judge model's own answer (O11), never computed: the queue's defender
#: finding types (O11's four plus `observability`, M19=A) and the explicit `none`.
WORLD_BUCKETS = frozenset(QUEUEABLE_FINDING_TYPES) | {NO_BUCKET}

#: What each world bucket means, keyed by the word, so every member reaches the prompt with a
#: criterion; `_bucket_guidance` refuses if the two sets disagree.
_BUCKET_GUIDANCE: dict[str, str] = {
    "lead-set": (
        "the investigator never asked a SERVED system where this world's facts would show — "
        "its lead set missed them. Only a served system can be missed: if every system the "
        "facts touch is outside SERVED SYSTEMS, the investigator could not have looked, and "
        "this bucket is refused for that world"
    ),
    "lead-quality": (
        "it asked the right served system, but in a way that could not show the facts — the "
        "wrong window, scope or entity"
    ),
    "analyze-discipline": (
        "it was shown the facts and did not carry them into its conclusion; its resolutions "
        "did not move"
    ),
    "decision-discipline": (
        "it was shown the facts and its resolutions moved, yet its verdict still disagrees with "
        "the world's declared verdict"
    ),
    "observability": (
        "the facts could not reach it for a reason outside its own conduct — the grant refused "
        "the call, an adapter could not load — so the gap is in what the deployment lets an "
        "investigator see"
    ),
    "none": (
        "no investigator failure — it reached the declared verdict, or nothing here shows it "
        "went wrong. Recorded, never queued"
    ),
}


def _bucket_guidance() -> str:
    """The world buckets and their criteria, one line each; refuses a partial list."""
    missing = sorted(WORLD_BUCKETS - set(_BUCKET_GUIDANCE))
    if missing:
        raise JudgeRefused(
            f"the judge's prompt has no criterion for bucket {missing} — the validator accepts "
            "them and the model would be choosing by guesswork")
    return "".join(f"- `{word}` — {_BUCKET_GUIDANCE[word]}.\n" for word in sorted(WORLD_BUCKETS))


#: Examples of a world-subject finding bucket shown in the prompt — not a closed set.
EXAMPLE_WORLD_BUCKETS = ("shape-invention", "fact-story-gap", "undiscriminating-family")


class _OpenBucketVocabulary:
    """The world lane's bucket vocabulary: every string is a member, nothing else is.

    Open so a model's novel reading of a world is admitted. Empty and whitespace-only buckets
    are admitted too, stored verbatim, so that drift stays observable."""

    def __contains__(self, item: object) -> bool:
        return isinstance(item, str)


#: The finding bucket vocabulary, selected by subject. The defender arm is the queue's own
#: `QUEUEABLE_FINDING_TYPES` (never coerced to a nearest member), so the validator and
#: `enqueue._validate_row` accept the same set; the world arm is open.
_BUCKET_ENUM: dict[str, Any] = {
    SUBJECT_DEFENDER: frozenset(QUEUEABLE_FINDING_TYPES),
    SUBJECT_WORLD: _OpenBucketVocabulary(),
}

_ROLE_PROMPT = Path(__file__).resolve().parent / "role.md"

#: Each rendered section's heading. Titles sit inside the frame with their bodies.
SECTION_TITLES: dict[str, str] = {
    "manifest": "THE FAMILY (the judged world's facts and declared verdict; every other "
                "world's facts withheld; the systems this tenant serves)",
    "family": "PRE-FLIGHT'S RECORD OF THE FAMILY (its outcome, the worlds that could not be "
              "judged, the calls it could not replay, and the calls whose live answer drifted "
              "from the capture)",
    "calls": "VIEW 1 — EVERY CALL THE JUDGED WORLD'S INVESTIGATOR MADE (its decision word, and "
             "for a changed answer its claim and verifier verdict)",
    "answers": "VIEW 2 — THE ANSWERS THOSE CALLS WERE SERVED, by call number",
    "leads": "VIEW 3 — PER-LEAD CHAIN (goal -> params -> payload -> refused -> summary -> "
             "resolutions)",
    "lessons": "VIEW 5 — LESSONS THAT REACHED THIS WORLD (name, how it reached the model — "
               "read, or pushed as a description only — and the body at its recorded commit "
               "for you to judge against, whether or not the model read it)",
    "document": "THE JUDGED WORLD'S OWN investigation.md",  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "report": "THE JUDGED WORLD'S OWN report.md",  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "oracle": "THE JUDGED WORLD'S FROZEN TELEMETRY AND IDENTIFIER COLLISIONS (its oracle-side "
              "record)",
    "samples": "REAL EXAMPLE ANSWERS PER SERVED SYSTEM (the samples record, one section per "
               "system)",
}


def _normalize_reply_outcome(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    outcome = value.strip().casefold()
    return outcome if outcome in _REPLY_OUTCOME_ENUM else None


@model(frozen=True)
class Finding:
    bucket: str
    subject: str
    claim: str
    root_cause: str
    anchor: str
    topic: str
    evidence: list[str] = field(default_factory=list)
    discriminator_related: bool = False


@model(frozen=True)
class JudgeReply:
    """One validated reply. `bucket`/`systems` are the world scope's (O11: the model's own
    answer); `verdict_word` is the family scope's (a `JUDGE_OUTCOME_ENUM` member, M19=A)."""

    episode_outcome: str
    noise_floor_note: str
    correlations: list[Any]
    scope_checks: list[Any]
    derivations: list[Any]
    findings: list[Finding]
    bucket: str | None = None
    systems: list[str] = field(default_factory=list)
    verdict_word: str | None = None


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


def _parse_finding(raw: Any, index: int, *, scope: str) -> Finding:  # noqa: C901 — one set of checks over one raw finding
    if not isinstance(raw, dict):
        raise JudgeRefused(f"finding[{index}] is not a mapping")
    for key in ("bucket", "subject", "claim", "root_cause", "anchor", "topic", "evidence"):
        if key not in raw:
            raise JudgeRefused(f"finding[{index}] is missing {key!r}")
    # Present-and-null is missing: `str(None)` below would manufacture the content "None",
    # which downstream non-empty checks cannot catch.
    for key in ("claim", "root_cause", "anchor", "topic"):
        if raw[key] is None:
            raise JudgeRefused(
                f"finding[{index}].{key} is null — a null is refused rather than rendered as "
                "the string 'None', which reads downstream as content the model never wrote")
    # Exact match: a near-miss (`"World"`, `" world"`) is refused, so the validator and the
    # appender's guard cannot disagree about the channel.
    subject = raw["subject"]
    if subject not in (SUBJECT_DEFENDER, SUBJECT_WORLD):
        raise JudgeRefused(
            f"finding[{index}].subject={subject!r} is not one of "
            f"{sorted((SUBJECT_DEFENDER, SUBJECT_WORLD))!r} — no case-fold and no trim, so a "
            "finding whose subject nobody stated exactly is a finding no channel can route")
    if scope == "family" and subject != SUBJECT_WORLD:
        raise JudgeRefused(
            f"finding[{index}].subject={subject!r} — the family call may emit only "
            f"subject: {SUBJECT_WORLD!r} findings; it never judges the investigator")
    bucket = raw["bucket"]
    bucket_enum = _BUCKET_ENUM[subject]
    if not isinstance(bucket, str) or bucket not in bucket_enum:
        raise JudgeRefused(
            f"finding[{index}].bucket={bucket!r} is not a valid {subject} bucket — a lookalike "
            "is rejected, never coerced to the nearest member")
    evidence = raw["evidence"]
    if not isinstance(evidence, list):
        raise JudgeRefused(f"finding[{index}].evidence must be a list")
    # Keys an older prompt asked for (a world, a pattern, a holding system) are ignored, never
    # carried: the pass stamps the world itself, and nothing downstream reads the other two.
    return Finding(
        bucket=bucket, subject=subject, claim=str(raw["claim"]),
        root_cause=str(raw["root_cause"]), anchor=str(raw["anchor"]), topic=str(raw["topic"]),
        evidence=[str(e) for e in evidence],
        discriminator_related=bool(raw.get("discriminator_related", False)),
    )


def _world_verdict(doc: dict[str, Any], *,
                   served_systems: Any) -> tuple[str, list[str]]:
    """A world reply's own `bucket` and `systems`, exactly as written, or `JudgeRefused`.

    The host's one rule on the bucket (M20=A): `lead-set` is refused when the reply's systems
    share nothing with `served_systems` — an investigator cannot miss what it could not ask. It
    refuses; it never substitutes a bucket. `served_systems=None` (a bare validation, no family
    in hand) skips that rule."""
    if "bucket" not in doc:
        raise JudgeRefused("the judge's reply carries no bucket for its world")
    bucket = doc["bucket"]
    if not isinstance(bucket, str) or bucket not in WORLD_BUCKETS:
        raise JudgeRefused(
            f"the judge's reply's bucket={bucket!r} is not one of {sorted(WORLD_BUCKETS)} — a "
            "lookalike is rejected, never coerced to the nearest member")
    from defender.runtime.verbs import is_system_name

    systems = doc.get("systems")
    if not isinstance(systems, list) or not all(isinstance(s, str) for s in systems):
        raise JudgeRefused(
            f"the judge's reply's systems={systems!r} must be a list of system names")
    # Matched exactly against the roster's own name rule (N03): a spelling no roster can hold
    # (`IDP`) is refused, never normalised onto the name it resembles.
    misspelled = [s for s in systems if not is_system_name(s)]
    if misspelled:
        raise JudgeRefused(
            f"the judge's reply's systems name {misspelled!r}, which no roster can hold as a "
            "system name — refused rather than normalised")
    if bucket == LEAD_SET and served_systems is not None \
            and not set(systems) & {str(s) for s in served_systems}:
        raise JudgeRefused(
            f"the judge's reply says bucket={LEAD_SET!r} for a world whose systems {systems!r} "
            f"share nothing with the served systems {sorted(served_systems)!r} — the "
            "investigator could not have looked, so the lead set cannot have missed it (M20)")
    return bucket, list(systems)


def validate_reply(text: str, *, scope: str = "world",
                   served_systems: Any = None) -> JudgeReply:
    """Read `text` as one bare document and validate strictly: nothing is read off the reply
    before this returns.

    `scope` is which call the reply came from: `"world"` carries the world's `bucket` and
    `systems` and may emit either finding subject; `"family"` carries the family's
    `verdict_word` and may emit only `subject: world` findings. `served_systems` is the
    family's recorded list, for the `lead-set` refusal (`_world_verdict`).

    The shape rule is `reply_document_text`'s: exactly one document (bare, or in exactly one
    code fence), else refused — never guessed at. A repeated key is refused too: YAML keeps
    the last copy silently, so the reply would mean whichever one won."""
    import yaml

    from defender._yaml import duplicate_key_paths, safe_load

    # An injected seam may return a non-string; refuse it as this draw's failure rather than
    # raising an `AttributeError` the draw loop does not contain.
    if not isinstance(text, str):
        raise JudgeRefused(
            f"the judge seam returned {type(text).__name__}, not the reply text this design "
            "parses — one draw is unusable, which is not the episode's grade")
    try:
        cleaned = reply_document_text(text)
    except MalformedReply as shape:
        raise JudgeRefused(f"the judge's reply is not one bare document: {shape}") from shape
    try:
        # `_yaml.safe_load` converts `RecursionError` (deep nesting) and constructor
        # `ValueError`s (e.g. out-of-range timestamps) into `yaml.YAMLError`, so a bad reply
        # costs only its draw.
        doc = safe_load(cleaned)
        repeated = duplicate_key_paths(cleaned)
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"the judge's reply is not valid YAML: {bad}") from bad
    doc = _require_dict(doc)
    if repeated:
        raise JudgeRefused(f"the judge's reply repeats key(s) {list(repeated)}")

    outcome = _normalize_reply_outcome(doc.get("episode_outcome"))
    if outcome is None:
        raise JudgeRefused(
            f"the judge's reply's episode_outcome={doc.get('episode_outcome')!r} is not one "
            f"of {sorted(_REPLY_OUTCOME_ENUM)}")
    bucket: str | None = None
    systems: list[str] = []
    verdict_word: str | None = None
    if scope == "family":
        verdict_word = normalized_judge_outcome(doc.get("verdict_word"))
        if verdict_word is None:
            raise JudgeRefused(
                f"the family reply's verdict_word={doc.get('verdict_word')!r} is not one of "
                f"{sorted(JUDGE_OUTCOME_ENUM)}")
    else:
        bucket, systems = _world_verdict(doc, served_systems=served_systems)
    correlations = _require_list(doc, "correlations")
    scope_checks = _require_list(doc, "scope_checks")
    derivations = _require_list(doc, "derivations")
    findings_raw = doc.get("findings")
    if not isinstance(findings_raw, list):
        raise JudgeRefused("the judge's reply's findings must be a list")
    findings = [_parse_finding(f, i, scope=scope) for i, f in enumerate(findings_raw)]
    noise = doc.get("noise_floor_note")
    return JudgeReply(
        episode_outcome=outcome, noise_floor_note=str(noise) if noise is not None else "",
        correlations=correlations, scope_checks=scope_checks, derivations=derivations,
        findings=findings, bucket=bucket, systems=systems, verdict_word=verdict_word,
    )


def _world_evidence_files() -> tuple[str, ...]:
    """The episode-level files a `subject: world` evidence pointer may also name, by bare name
    only (never a prefix a traversal could pass). Defender findings stay world-subtree-only.

    A function rather than an import-time tuple, so it follows renames of the records.
    """
    return tuple(str(name) for name in (LAYOUT.samples, LAYOUT.outcome, LAYOUT.judge))


def _family_evidence_files() -> tuple[str, ...]:
    """The subset the family-level call is actually shown: no samples document, since that
    call is never rendered a sample."""
    samples = str(LAYOUT.samples)
    return tuple(n for n in _world_evidence_files() if n != samples)


def _resolves(pointer: str, world_dir: Path, *, subject: str = SUBJECT_DEFENDER,
              scope: str = "world") -> bool:
    """Does this evidence pointer resolve inside the judged world's own subtree (never a
    sibling's archive)? For a `subject: world` finding only, the episode-level allowlist is
    also admitted, by name.

    `scope` narrows that allowlist to what the call was shown: the family call sees no sample,
    and this is the one place both lanes pass through, so the refusal lives here."""
    if not isinstance(pointer, str) or not pointer:
        return False
    path_part = pointer.split("#", 1)[0]
    if not path_part or Path(path_part).is_absolute():
        return False
    try:
        root = world_dir.resolve()
        candidate = (world_dir / path_part).resolve()
        candidate.relative_to(root)
    # `RuntimeError`: `resolve()` raises it on a symlink cycle, which a box-writable subtree
    # can contain.
    except (OSError, RuntimeError, ValueError):
        pass
    else:
        if artifact_file(candidate):
            return True
    # No existence check here: `judge.yaml` is written after the draws, so a pointer to it can
    # never exist yet. The bare-name test refuses every traversal shape.
    allowed = _family_evidence_files() if scope == "family" else _world_evidence_files()
    return subject == SUBJECT_WORLD and path_part in allowed \
        and Path(path_part).name == path_part


def cites_sample(finding: dict[str, Any], *, samples: Any,
                 served_systems: Any = None) -> bool:
    """Does this finding cite `samples.yaml` anywhere but a served system's own section?

    A citation passes only as `samples.yaml#<system>` where `<system>` is a key of the samples
    record (exact spelling — no case-fold, no trim) holding real answers (`verbs`), and, when
    `served_systems` is given, one of them (O16). A section the record marks `unavailable`, a
    lookalike, an old pattern key, a dot-dot fragment or a bare `samples.yaml` all fail.

    Keyed on the evidence, not the bucket, since the world vocabulary is open and a bucket
    check is evadable by rewording. `True` means the finding must not be queued."""
    record = samples if isinstance(samples, dict) else {}
    served = None if served_systems is None else {str(s) for s in served_systems}
    for pointer in finding.get("evidence") or ():
        if not isinstance(pointer, str):
            continue
        prefix, _has_fragment, system = pointer.partition("#")
        if prefix != str(LAYOUT.samples):
            continue
        section = record.get(system)
        if not (isinstance(section, dict) and isinstance(section.get("verbs"), dict)):
            return True
        if served is not None and system not in served:
            return True
    return False


def _draw_document(reply: JudgeReply, *, world_dir: Path,
                   scope: str = "world") -> dict[str, Any]:
    """The draw document: a finding with no resolving pointer is dropped and counted; one with
    any resolving pointer stands, with its unresolved pointers recorded. `scope` goes to
    `_resolves`.

    @owns bucket — a world draw's `bucket`/`systems` are the reply's own, written here and
    nowhere else; the pass and the page read them back off this document."""
    kept: list[dict[str, Any]] = []
    dropped = 0
    for finding in reply.findings:
        unresolved = [p for p in finding.evidence
                     if not _resolves(p, world_dir, subject=finding.subject, scope=scope)]
        if len(unresolved) == len(finding.evidence):
            dropped += 1
            continue
        kept.append({
            "bucket": finding.bucket, "subject": finding.subject, "claim": finding.claim,
            "root_cause": finding.root_cause, "anchor": finding.anchor, "topic": finding.topic,
            "evidence": finding.evidence, "unresolved_evidence": unresolved,
            "discriminator_related": finding.discriminator_related,
        })
    doc: dict[str, Any] = {"episode_outcome": reply.episode_outcome}
    if scope == "family":
        doc["verdict_word"] = reply.verdict_word
    else:
        doc["bucket"] = reply.bucket
        doc["systems"] = list(reply.systems)
    doc.update({
        "noise_floor_note": reply.noise_floor_note,
        "correlations": reply.correlations, "scope_checks": reply.scope_checks,
        "derivations": reply.derivations, "findings": kept, "dropped_findings": dropped,
    })
    return doc


#: The ledger's decision words as the judge is told them — every call row in VIEW 1 names one.
_DECISION_GLOSSARY = (
    "HOW EACH CALL WAS ANSWERED. Every call in VIEW 1 names one of these decision words:\n"
    "- `passthrough`: the live system's own answer, unchanged — the world's facts did not "
    "touch this call.\n"
    "- `oracle`: an answer changed so this world's facts show in it. Its claim says what was "
    "added, removed or changed, and its verifier verdict whether an independent check passed. "
    "\"claim unavailable\" means no claim was stored for that call: never treat such an answer "
    "as verified.\n"
    "- `real-error`: the live system answered with an error, and the investigator saw that "
    "error. An outage of a served system is telemetry the investigator could have reasoned "
    "about — it is not a reason the investigator could not look.\n"
    "- `refused`: the call was turned away before it reached any system (a verb the grant does "
    "not hold); the world asked and was not answered.\n"
    "- `fault`: the system's adapter could not load; nothing was asked.\n\n"
)


def _build_prompt(judge_input: JudgeInput) -> str:
    """The correlating prompt for the judged world. Wording names hand-offs, never entities
    or systems; the 20-row cap and the quote-any-colon rule are what make replies parse
    strictly.

    The label comes off the rendered input only, so the prompt cannot name a different world
    from the one rendered."""
    label = judge_input.world_label
    task = (
        f"World {label} has run; judge it.\n\n"  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        "This family was branched from a captured investigation. Each non-control world carries "
        "natural-language FACTS that hold in that world and not in the capture. While the "
        "world's investigator ran, every call it made was answered live, and an answer was "
        "changed only where the world's facts touch it. You are shown the judged world's facts "
        "and declared verdict, the systems this tenant serves, every call its investigator made "
        "and how each was answered, its leads, document and verdict, the lessons it loaded, real "
        "example answers per served system, and pre-flight's record of the family. Every OTHER world's facts are withheld: "
        "never cite another world as a fact about the judged world.\n\n"
        f"{_DECISION_GLOSSARY}"
        # What a `refused:` entry means, in host text. Otherwise a harness refusal reads as
        # "never queried", yielding a `lead-set` lesson telling the investigator to run a query
        # it is not granted. Spelled the way `family.render_refused` prints it.
        "READ A LEAD'S `refused:` LINE BEFORE JUDGING ITS COVERAGE. Each entry there is an "
        "attempt that reached NO system — it is not a query, and it is not the absence of "
        "one. `external=true` means the harness or the deployment withheld it (a verb the "
        "investigator's role is not granted, an adapter that could not load): the investigator "
        "asked and was refused before the call was made, so the finding is `observability` "
        f"(subject: {SUBJECT_DEFENDER}) and NEVER `lead-set` — do not author a lesson telling "
        "the investigator to run a query it is not granted. `external=false` is the "
        "investigator's own conduct (a rejected call, a repeat the guard refused, a reducer it "
        "broke) and is judged as such. Every refused entry is a `∅.`-prefixed row in this "
        "world's own `executed_queries.jsonl`, which is the `evidence` pointer for a finding "
        "about it.\n\n"
        "YOUR VERDICT ON THIS WORLD IS ONE `bucket`, chosen by you from exactly these:\n"
        f"{_bucket_guidance()}"
        "and `systems`: the list of systems this world's facts touch, by name (a system outside "
        "SERVED SYSTEMS is named too — that is how a world nobody could have looked at is "
        "told apart).\n\n"
        "Before findings, run three passes and report each as its own table:\n"
        "1. CORRELATION — for every fact that can be followed across two joined rows, name the "
        "hand-off.\n"
        "2. SCOPE — for every lead touching a system the facts touch, name the window, scope "
        "and entity it actually used.\n"
        "3. DERIVATION — for every held row, say whether it was derived from an answer the "
        "investigator actually read, or invented.\n\n"
        "Cap any table at 20 rows. Quote any YAML scalar containing a colon — that is what "
        "made every reply of the correlating prompt's own trial parse strictly.\n\n"
        f"Reply as one YAML mapping, bare — not inside a code fence, with nothing before or "
        f"after it: bucket (exactly one of {' | '.join(sorted(WORLD_BUCKETS))}), systems (a "
        "list), episode_outcome (exactly one of "
        f"{' | '.join(sorted(_REPLY_OUTCOME_ENUM))}), "
        "noise_floor_note, correlations, scope_checks, derivations, findings (each: bucket, "
        f"subject [{SUBJECT_DEFENDER}|{SUBJECT_WORLD}], claim, "
        # The validator's own defender bucket set, rendered so prompt and validator agree. The
        # world vocabulary is open, so only examples are shown for it.
        f"a subject: {SUBJECT_DEFENDER} finding's bucket is one of "
        f"[{'|'.join(sorted(_BUCKET_ENUM[SUBJECT_DEFENDER]))}]; a subject: {SUBJECT_WORLD} "
        f"finding's bucket is your own free text naming what is wrong with the WORLD itself "
        f"rather than the investigator — for example {', '.join(EXAMPLE_WORLD_BUCKETS)} — "
        "root_cause, anchor, topic, evidence, discriminator_related). Every finding names its "
        f"subject: a {SUBJECT_DEFENDER} finding is about how the investigator investigated; a "
        f"{SUBJECT_WORLD} finding is about the instrument itself — an invented answer shape, a "
        "story the facts do not back, or (family call only) that the family failed to "
        "discriminate at all — and is never authored as a lesson for the investigator.\n\n"
        # The shape of `evidence`, stated: otherwise a model writes prose, which either fails
        # validation or is discarded as unresolvable, silently losing every finding.
        "`evidence` IS A LIST OF POINTERS INTO THE JUDGED WORLD'S OWN FILES, never prose and "
        "never a quotation. Each entry is a path RELATIVE to that world's directory, "
        "optionally with a `#fragment` naming what in the file you mean — for example "
        "`report.md`, `investigation.md#ANALYZE`, `gather_summaries/l-001.md`. A "
        f"{SUBJECT_WORLD} finding may also cite `{LAYOUT.samples}#<system>` — one served "
        "system's own section of the example answers, spelled exactly as its heading. An "
        "absolute path, a path climbing out of the world, and a path naming a file that is not "
        "there all fail to resolve, and A FINDING WHOSE POINTERS ALL FAIL TO RESOLVE IS "
        "DISCARDED — so put what you actually read in this world's archive here, and put the "
        "words you would have quoted in `claim` and `root_cause` instead. "
        "`discriminator_related` is a boolean.\n\n"
        "WHICH episode_outcome, and it decides whether your findings are kept at all:\n"
        f"{_outcome_guidance()}"
        f"{' and '.join(sorted(_REPLY_OUTCOME_ENUM - {'gradable'}))} DISCARD EVERY FINDING YOU "
        "WRITE — the family record becomes the only artifact. Choose one of them for a fault "
        "in the archive, never as a comment on how the investigator performed.\n"
    )
    sections = judge_input.as_prompt_sections()
    # Iterate the sections, not the titles: `as_prompt_sections` owns the set the payload cap
    # is charged over, so a section is never capped and then silently not sent. An untitled
    # section is titled by its key.
    titled = [titled_section(SECTION_TITLES.get(name, name.upper()), body)
              for name, body in sections.items()]
    salt = message_salt(task, *titled)
    # One tag on every section: sections are identified by their salted frame, and the frame
    # regex matches only `-untrusted`. Each section is named by its title inside the frame,
    # since a heading outside it could be imitated from inside a body.
    body = stage_user_message(salt, *(wrap(section, UNTRUSTED_TAG, salt) for section in titled))
    return task + body


def _render_family_manifest(manifest: dict[str, Any]) -> str:
    """Every world's story, axis, declared verdict and facts, withholding none: unlike the
    per-world call, the family call asks whether the whole set separates."""
    from defender.learning.judge.family import _control_declared

    lines = [f"discriminator: {family_predicate(manifest)}",
             f"served systems: {', '.join(served_systems_of(manifest)) or '(none recorded)'}",
             f"source disposition (base/control world): {_control_declared(manifest)!r}"]
    for world in manifest.get("worlds") or ():
        if not isinstance(world, dict):
            continue
        lines.append(
            f"world {world.get('world_id')} (role {world.get('role')}): "
            f"story={world.get('story')!r} axis={world.get('axis')!r} "
            f"disposition_declared={world.get('disposition_declared')!r}")
        for fact in world.get("facts") or ():
            if isinstance(fact, dict):
                lines.append(f"  fact {fact.get('fact_id')}: {fact.get('statement')}")
    return "\n".join(lines) + "\n"


def _render_family_rows(rows: list[dict[str, Any]]) -> str:
    """Every world's judged row, joined across the family: declared and reached verdicts, the
    bucket and systems the per-world calls gave, or why the world was not judged."""
    lines = []
    for row in rows:
        if row.get("ungradable"):
            lines.append(f"world {row.get('world')}: NOT JUDGED — {row.get('ungradable_reason')}")
            continue
        lines.append(
            f"world {row.get('world')}: declared={row.get('declared')!r} "
            f"verdict={row.get('verdict')!r} bucket={row.get('bucket')!r} "
            f"systems={row.get('systems')!r}")
    return "\n".join(lines) + "\n" if lines else "No worlds are recorded.\n"


def family_predicate(manifest: dict[str, Any]) -> str:
    """The discriminator's predicate text (the only field a v2 discriminator keeps)."""
    block = manifest.get("discriminator")
    predicate = block.get("predicate") if isinstance(block, dict) else None
    return str(predicate) if predicate is not None else "(no predicate recorded)"


def served_systems_of(manifest: dict[str, Any]) -> list[str]:
    """The manifest's recorded `served_systems` (M21=A: the recorded list governs the judge,
    never a tenant lookup)."""
    raw = manifest.get("served_systems")
    return [str(s) for s in raw] if isinstance(raw, list) else []


def _build_family_prompt(*, manifest: dict[str, Any], rows: list[dict[str, Any]],
                         family_text: str) -> str:
    """The family-level prompt: whether the family separates on the discriminator, and the
    family's word. Shown every world's facts, pre-flight's record and every world's row.

    The reply is entirely `subject: world` findings plus the family's `verdict_word`."""
    words = sorted(JUDGE_OUTCOME_ENUM)
    task = (
        # The shared role prompt is written for the per-world call; its one-world framing and
        # withheld-sibling rule are overridden here, since the role file's text is pinned.
        "This is the FAMILY-LEVEL call. The role prompt's \"one archived, branched world\" "
        "framing and its withheld-sibling rule DO NOT APPLY here: you are shown every world "
        "deliberately, and citing one world's facts while reasoning about another is the "
        "whole point of this call.\n\n"
        "Judge this WHOLE FAMILY of sibling worlds — never any single world. You are shown "
        "every world's facts, pre-flight's record of the family and every world's judged row; "
        "nothing here is withheld.\n\n"
        "Answer family-level questions: did the worlds SEPARATE on the discriminator (did the "
        "investigators' verdicts follow each world's declared verdict), and did the family ask "
        "it at all?\n\n"
        "Give the family's word as `verdict_word`, exactly one of "
        f"{' | '.join(words)}:\n"
        "- `caught` — every judged world's investigator reached its declared verdict.\n"
        "- `survived` — at least one judged world's investigator did not, in a family that "
        "separates: this is the word lessons are authored from.\n"
        "- `undecidable` — the family cannot say (no world contrasts with the control, or too "
        "little was judged).\n"
        "- `discard` — the measurement is spoilt (the live systems drifted on the calls that "
        "matter).\n"
        "- `corpus-contradiction` — the worlds' facts contradict the capture they were branched "
        "from.\n\n"
        f"Reply as one YAML mapping, bare — not inside a code fence, with nothing before or "
        f"after it: verdict_word, episode_outcome (exactly one of "
        f"{' | '.join(sorted(_REPLY_OUTCOME_ENUM))}), noise_floor_note, correlations, "
        "scope_checks, derivations, findings (each: bucket [your own free text — for example "
        f"{', '.join(EXAMPLE_WORLD_BUCKETS)}], subject (always {SUBJECT_WORLD!r} — this call "
        "never judges the investigator), claim, root_cause, anchor, topic, evidence, "
        "discriminator_related). A family-level finding is about the FAMILY as a whole.\n\n"
        # Family pointers resolve against `worlds/family/`, which holds only draw files, so
        # only the allowlisted episode-level files can resolve.
        "`evidence` IS A LIST OF POINTERS, never prose and never a quotation. A family-level "
        f"finding may cite ONLY these episode-level files by bare name: "
        f"{', '.join(f'`{name}`' for name in _family_evidence_files())}, optionally with a "
        "`#fragment` naming what in the file you mean. Any other path fails to resolve, and A "
        "FINDING WHOSE POINTERS ALL FAIL TO RESOLVE IS DISCARDED.\n\n"
        f"{_outcome_guidance()}"
    )
    sections = {
        "manifest": _render_family_manifest(manifest),
        "family": family_text,
        "worlds": _render_family_rows(rows),
    }
    titled = [titled_section(SECTION_TITLES.get(name, name.upper()), body)
              for name, body in sections.items()]
    salt = message_salt(task, *titled)
    body = stage_user_message(salt, *(wrap(section, UNTRUSTED_TAG, salt) for section in titled))
    return task + body


__all__ = [
    "EXAMPLE_WORLD_BUCKETS", "Finding", "JUDGE_DEF", "JudgeDeps", "JudgeReply", "LEAD_SET",
    "NO_BUCKET", "SUBJECT_DEFENDER", "SUBJECT_WORLD", "WORLD_BUCKETS", "_build_family_prompt",
    "_build_prompt", "cites_sample", "family_predicate", "served_systems_of", "validate_reply",
]
