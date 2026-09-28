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

from defender._run_paths import artifact_file
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
#: family's word. A reply never emits `caught`/`survived`/`undecidable` (the mechanical pass
#: computes those) and can emit `gradable`, which is not a family word.
_REPLY_OUTCOME_ENUM = frozenset({"gradable", "discard", "corpus-contradiction"})

#: What each reply-level outcome means, keyed by the word, so every member reaches the prompt
#: with a criterion; `_outcome_guidance` refuses if the two sets disagree.
_OUTCOME_GUIDANCE: dict[str, str] = {
    "gradable": (
        "this world ran and its record can be judged. THIS IS THE ORDINARY ANSWER, and it is "
        "still the answer when the defender did badly: a world whose defender never queried "
        "the discriminating system, never re-opened a lead, or closed over an open hypothesis "
        "is a world you can grade, and those are exactly the findings worth having"
    ),
    "discard": (
        "this world cannot be measured because the MEASUREMENT is spoilt — the control "
        "drifted, or what the world was asked is not what it served. Nothing about the "
        "defender's conduct puts an episode here"
    ),
    "corpus-contradiction": (
        "the world's own staged corpus contradicts the capture it was branched from, so the "
        "archive disagrees with itself and no verdict read off it means anything. Evidence "
        "the defender never looked at is NOT a contradiction; it is a gradable world in which "
        "the defender did not look"
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

#: Examples of a world-subject bucket shown in the prompt — not a closed set.
EXAMPLE_WORLD_BUCKETS = (
    "unreachable-difference", "shape-invention", "story-overlay-gap", "undiscriminating-family",
)


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

#: Each rendered section's heading. The four "joined views" are numbered so a reply can name
#: which view a finding came from.
SECTION_TITLES: dict[str, str] = {
    "manifest": "THE FAMILY MANIFEST (the graded world last; every other world counterfactual)",
    "leads": "VIEW 1 — PER-LEAD CHAIN (goal -> params -> payload -> refused -> summary -> "
             "resolutions)",
    "coverage": "VIEW 2 — COVERAGE (what this world asked on the family's holding system)",
    "siblings": "VIEW 3 — SIBLING TRIALS OF THIS SAME ALERT",
    "lessons": "VIEW 4 — LESSONS THAT REACHED THIS WORLD (name, how it reached the model — "
               "read, or pushed as a description only — and the body at its recorded commit "
               "for you to grade against, whether or not the model read it)",
    "spread": "TRIAL SPREAD (the dispositions those sibling trials reached, tallied)",
    "document": "THE GRADED WORLD'S OWN investigation.md",  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "report": "THE GRADED WORLD'S OWN report.md",  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "sample": "THE QUESTIONER'S OWN SAMPLE (the real document, per staged pattern, this "
              "world's overlay was authored from)",
    "review": "THIS WORLD'S OWN REVIEW RECORD (what the capture's own vocabulary could and "
              "could not show)",
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
    #: World-lane-only content, carried to build a questioner-channel row. `world` is never
    #: trusted as identity; the pass stamps its own.
    pattern: str | None = None
    holding_system: str | None = None
    world: str | None = None


@model(frozen=True)
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
    if scope == "family":
        # The family reply is entirely `subject: world` and may name no world; a model naming
        # one is refused rather than silently overridden.
        if subject != SUBJECT_WORLD:
            raise JudgeRefused(
                f"finding[{index}].subject={subject!r} — the family call may emit only "
                f"subject: {SUBJECT_WORLD!r} findings; it never grades the defender")
        if raw.get("world") is not None:
            raise JudgeRefused(
                f"finding[{index}] names world={raw.get('world')!r} — a family-level finding "
                "is about the family and may not name a member of it")
    bucket = raw["bucket"]
    bucket_enum = _BUCKET_ENUM[subject]
    if not isinstance(bucket, str) or bucket not in bucket_enum:
        raise JudgeRefused(
            f"finding[{index}].bucket={bucket!r} is not a valid {subject} bucket — a lookalike "
            "is rejected, never coerced to the nearest member")
    evidence = raw["evidence"]
    if not isinstance(evidence, list):
        raise JudgeRefused(f"finding[{index}].evidence must be a list")
    for key in ("pattern", "holding_system", "world"):
        if key in raw and raw[key] is not None and not isinstance(raw[key], str):
            raise JudgeRefused(f"finding[{index}].{key} must be a string when present")
    return Finding(
        bucket=bucket, subject=subject, claim=str(raw["claim"]),
        root_cause=str(raw["root_cause"]), anchor=str(raw["anchor"]), topic=str(raw["topic"]),
        evidence=[str(e) for e in evidence],
        discriminator_related=bool(raw.get("discriminator_related", False)),
        pattern=raw.get("pattern"), holding_system=raw.get("holding_system"),
        world=raw.get("world"),
    )


def validate_reply(text: str, *, scope: str = "world") -> JudgeReply:
    """Read `text` as one bare document and validate strictly: nothing is read off the reply
    before this returns.

    `scope` is which call the reply came from: `"world"` may emit either subject; `"family"`
    may emit only `subject: world` findings naming no world.

    The shape rule is `reply_document_text`'s: exactly one document (bare, or in exactly one
    code fence), else refused — never guessed at."""
    import yaml

    from defender._yaml import safe_load

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
    findings = [_parse_finding(f, i, scope=scope) for i, f in enumerate(findings_raw)]
    noise = doc.get("noise_floor_note")
    return JudgeReply(
        episode_outcome=outcome, noise_floor_note=str(noise) if noise is not None else "",
        correlations=correlations, scope_checks=scope_checks, derivations=derivations,
        findings=findings,
    )


def _world_evidence_files() -> tuple[str, ...]:
    """The three episode-level files a `subject: world` evidence pointer may also name, by
    bare name only (never a prefix a traversal could pass). Defender findings stay
    world-subtree-only.

    A function rather than an import-time tuple, so it follows renames of the records.
    """
    return tuple(str(name) for name in (LAYOUT.samples, LAYOUT.review, LAYOUT.judge))


def _family_evidence_files() -> tuple[str, ...]:
    """The subset the family-level call is actually shown: no samples document, since that
    call is never rendered a sample."""
    samples = str(LAYOUT.samples)
    return tuple(n for n in _world_evidence_files() if n != samples)


def _resolves(pointer: str, world_dir: Path, *, subject: str = SUBJECT_DEFENDER,
              scope: str = "world") -> bool:
    """Does this evidence pointer resolve inside the graded world's own subtree (never a
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


def cites_sample(finding: dict[str, Any], *, unavailable_patterns: Any = None) -> bool:
    """Does this finding's evidence cite `samples.yaml` for a pattern this world's row says had
    no sample?

    Keyed on the evidence, not the bucket, since the world vocabulary is open and a bucket
    check is evadable by rewording.

    `unavailable_patterns` is the row's `sample_unavailable_patterns`: a citation of an
    available pattern is admitted; one with no fragment is refused iff any pattern was
    unavailable; `None` (never recorded) refuses every `samples.yaml` citation."""
    for pointer in finding.get("evidence") or ():
        if not isinstance(pointer, str):
            continue
        prefix, has_fragment, fragment = pointer.partition("#")
        if prefix != str(LAYOUT.samples):
            continue
        if unavailable_patterns is None:
            return True
        if not has_fragment:
            if unavailable_patterns:
                return True
            continue
        if fragment in unavailable_patterns:
            return True
    return False


def _draw_document(reply: JudgeReply, *, world_dir: Path,
                   scope: str = "world") -> dict[str, Any]:
    """The draw document: a finding with no resolving pointer is dropped and counted; one with
    any resolving pointer stands, with its unresolved pointers recorded. `scope` goes to
    `_resolves`."""
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
            "pattern": finding.pattern, "holding_system": finding.holding_system,
            "world": finding.world,
        })
    return {
        "episode_outcome": reply.episode_outcome, "noise_floor_note": reply.noise_floor_note,
        "correlations": reply.correlations, "scope_checks": reply.scope_checks,
        "derivations": reply.derivations, "findings": kept, "dropped_findings": dropped,
    }


def _build_prompt(judge_input: JudgeInput) -> str:
    """The correlating prompt for the graded world. Wording names hand-offs, never entities
    or systems; the 20-row cap and the quote-any-colon rule are what make replies parse
    strictly.

    The label comes off the rendered input only, so the prompt cannot name a different world
    from the one rendered."""
    label = judge_input.world_label
    task = (
        f"World {label} has run; grade it.\n\n"  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        "Compare it against the four joined views below: its per-lead chain (goal, params, "
        "payload, refused, summary, resolutions), its coverage of the family's "
        "discriminator, the sibling trials of this same alert, and the lessons it loaded — "
        "plus the trial spread. Every OTHER world is marked counterfactual: withhold its "
        "overlay from your reasoning and never cite its facts as facts about the graded "
        "world.\n\n"
        # What a `refused:` entry means, in host text. Otherwise a harness refusal reads as
        # "never queried", yielding a `lead-set` lesson telling the defender to run a query it
        # is not granted. Spelled the way `family.render_refused` prints it.
        "READ A LEAD'S `refused:` LINE BEFORE GRADING ITS COVERAGE. Each entry there is an "
        "attempt that reached NO system — it is not a query, and it is not the absence of "
        "one. `external=true` means the harness or the estate withheld it (a verb the "
        "defender's role is not granted, an adapter that could not load): the defender asked "
        "and was refused before the call was made, so for a lead whose refusal is external "
        "on the family's holding system the finding is `observability` (subject: "
        f"{SUBJECT_DEFENDER}) and NEVER `lead-set` — do not author a lesson telling the "
        "defender to run a query it is not granted. `external=false` is the defender's own "
        "conduct (a rejected call, a repeat the guard refused, a reducer it broke) and grades "
        "as such. Every refused entry is a `∅.`-prefixed row in this world's own "
        "`executed_queries.jsonl`, which is the `evidence` pointer for a finding about it. "
        "A `source: refused` row in VIEW 2 is the served ledger's word for the same event "
        "(a denied call), or for a call the estate seam itself turned away; either way the "
        "world asked and was not answered — it counts as having queried, not as a query "
        "that ran, and it is not a second refusal to grade.\n\n"
        "Before findings, run three passes and report each as its own table:\n"
        "1. CORRELATION — for every fact reachable across two joined rows, name the hand-off.\n"
        "2. SCOPE — for every lead touching the holding system, name the index, window and "
        "scope key it actually used.\n"
        "3. DERIVATION — for every held row, say whether it was derived from a payload the "
        "defender actually read, or invented.\n\n"
        "Cap any table at 20 rows. Quote any YAML scalar containing a colon — that is what "
        "made every reply of the correlating prompt's own trial parse strictly.\n\n"
        # The validator's own outcome set, rendered with criteria below, so the model neither
        # guesses the literals nor picks a discarding outcome for a defender failure.
        f"Reply as one YAML mapping, bare — not inside a code fence, with nothing before or "
        f"after it: episode_outcome (exactly one of "
        f"{' | '.join(sorted(_REPLY_OUTCOME_ENUM))}), "
        "noise_floor_note, correlations, scope_checks, derivations, findings (each: bucket, "
        f"subject [{SUBJECT_DEFENDER}|{SUBJECT_WORLD}], claim, "
        # The validator's own defender bucket set, rendered so prompt and validator agree. The
        # world vocabulary is open, so only examples are shown for it.
        f"a subject: {SUBJECT_DEFENDER} finding's bucket is one of "
        f"[{'|'.join(sorted(_BUCKET_ENUM[SUBJECT_DEFENDER]))}]; a subject: {SUBJECT_WORLD} "
        f"finding's bucket is your own free text naming what is wrong with the WORLD itself "
        f"rather than the defender — for example {', '.join(EXAMPLE_WORLD_BUCKETS)} — "
        "root_cause, anchor, topic, evidence, discriminator_related). Every finding names its "
        f"subject: {SUBJECT_DEFENDER} finding is about how the defender investigated; a "
        f"{SUBJECT_WORLD} finding is about the instrument itself — an invented shape, a story "
        "the overlay does not back, or (family call only) that the family failed to "
        "discriminate at all — and is never authored as a lesson for the defender.\n\n"
        # `enqueue._validate_world_row` requires both; the pass can fill them in from the row,
        # but the reply is where they belong.
        f"A subject: {SUBJECT_WORLD} finding MUST also carry `pattern` (the staged corpus "
        "pattern the observation is about, copied verbatim from the manifest overlay or the "
        "sample header — never invented) and `holding_system` (the discriminator's own holding "
        "system). Both are non-empty strings; a world finding without them cannot be "
        "routed.\n\n"
        # The shape of `evidence`, stated: otherwise a model writes prose, which either fails
        # validation or is discarded as unresolvable, silently losing every finding.
        "`evidence` IS A LIST OF POINTERS INTO THE GRADED WORLD'S OWN FILES, never prose and "
        "never a quotation. Each entry is a path RELATIVE to that world's directory, "
        "optionally with a `#fragment` naming what in the file you mean — for example "
        "`report.md`, `investigation.md#ANALYZE`, `gather_summaries/l-001.md`. An absolute "
        "path, a path climbing out of the world, and a path naming a file that is not there "
        "all fail to resolve, and A FINDING WHOSE POINTERS ALL FAIL TO RESOLVE IS DISCARDED — "
        "so put what you actually read in this world's archive here, and put the words you "
        "would have quoted in `claim` and `root_cause` instead. "
        "`discriminator_related` is a boolean.\n\n"
        "WHICH episode_outcome, and it decides whether your findings are kept at all:\n"
        f"{_outcome_guidance()}"
        f"{' and '.join(sorted(_REPLY_OUTCOME_ENUM - {'gradable'}))} DISCARD EVERY FINDING YOU "
        "WRITE — the family record becomes the only artifact. Choose one of them for a fault "
        "in the archive, never as a comment on how the defender performed.\n"
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
    """Every world's story, axis, declared disposition and overlay, withholding none: unlike
    the per-world call, the family call asks whether the whole set separates."""
    from defender.learning.judge.family import _control_declared

    lines = [f"discriminator: {manifest.get('discriminator')}",
             f"source disposition (base/control world): {_control_declared(manifest)!r}"]
    for world in manifest.get("worlds") or ():
        if not isinstance(world, dict):
            continue
        lines.append(
            f"world {world.get('world_id')} (role {world.get('role')}): "
            f"story={world.get('story')!r} axis={world.get('axis')!r} "
            f"disposition_declared={world.get('disposition_declared')!r} "
            f"overlay={world.get('overlay')}")
    return "\n".join(lines) + "\n"


def _render_family_mechanical_rows(grade: Any) -> str:
    """Every world's mechanical row, joined across the family, with each world's verdict."""
    worlds = grade["worlds"] if isinstance(grade, dict) else grade.worlds
    lines = []
    for row in worlds:
        lines.append(
            f"world {row.get('world')}: declared={row.get('declared')!r} "
            f"verdict={row.get('verdict')!r} bucket={row.get('bucket')!r} "
            f"withheld_reason={row.get('withheld_reason')!r} "
            f"difference_shown={row.get('difference_shown')!r} "
            f"reachable_by_capture={row.get('reachable_by_capture')!r} "
            f"ungradable={row.get('ungradable', False)!r}")
    return "\n".join(lines) + "\n" if lines else "No worlds are recorded.\n"


def _build_family_prompt(*, manifest: dict[str, Any], grade: Any,
                         review: dict[str, Any]) -> str:
    """The family-level prompt: whether the family separates on the discriminator. Shown every
    world's overlay, the review record and every mechanical row.

    The reply is entirely `subject: world` and may name no `world`."""
    import yaml

    task = (
        # The shared role prompt is written for the per-world call; its one-world framing and
        # withheld-sibling rule are overridden here, since the role file's text is pinned.
        "This is the FAMILY-LEVEL call. The role prompt's \"one archived, branched world\" "
        "framing and its withheld-sibling rule DO NOT APPLY here: you are shown every world "
        "deliberately, and citing one world's overlay while reasoning about another is the "
        "whole point of this call.\n\n"
        "Judge this WHOLE FAMILY of sibling worlds — never any single world. You are shown "
        "every world's overlay, the family's review record and every world's own mechanical "
        "facts; nothing here is withheld.\n\n"
        "Answer only family-level questions: did the worlds SEPARATE on the discriminator (did "
        "at least one measuring world's verdict disagree from another's, or from what its own "
        "difference should have produced), and did the envelope actually ask it?\n\n"
        f"Reply as one YAML mapping, bare — not inside a code fence, with nothing before or "
        f"after it: episode_outcome (exactly one of "
        f"{' | '.join(sorted(_REPLY_OUTCOME_ENUM))}), noise_floor_note, correlations, "
        "scope_checks, derivations, findings (each: bucket [your own free text — for example "
        f"{', '.join(EXAMPLE_WORLD_BUCKETS)}], subject (always {SUBJECT_WORLD!r} — this call "
        "never grades the defender), claim, root_cause, anchor, topic, evidence, "
        "discriminator_related). A family-level finding is about the FAMILY as a whole and "
        "must NEVER name a `world` — do not add a `world` key to any finding. It MUST carry "
        "`pattern` (a staged corpus pattern this family is about) and `holding_system` (the "
        "discriminator's own holding system), both non-empty strings: the questioner channel's "
        "appender refuses a row without them.\n\n"
        # Family pointers resolve against `worlds/family/`, which holds only draw files, so
        # only the allowlisted episode-level files can resolve.
        "`evidence` IS A LIST OF POINTERS, never prose and never a quotation. A family-level "
        f"finding may cite ONLY these episode-level files by bare name: "
        f"{', '.join(f'`{name}`' for name in _family_evidence_files())}, optionally with a "
        "`#fragment` naming what in the file you mean (for example "
        f"`{LAYOUT.review}#worlds.b.reachability`). Any other path fails to resolve, and A FINDING "
        "WHOSE POINTERS ALL FAIL TO RESOLVE IS DISCARDED.\n\n"
        f"{_outcome_guidance()}"
    )
    sections = {
        "manifest": _render_family_manifest(manifest),
        "review": yaml.safe_dump(review, sort_keys=False) if review else
                 f"no {LAYOUT.review} is recorded for this episode\n",
        "mechanical": _render_family_mechanical_rows(grade),
    }
    titled = [titled_section(name.upper(), body) for name, body in sections.items()]
    salt = message_salt(task, *titled)
    body = stage_user_message(salt, *(wrap(section, UNTRUSTED_TAG, salt) for section in titled))
    return task + body


__all__ = [
    "EXAMPLE_WORLD_BUCKETS", "Finding", "JUDGE_DEF", "JudgeDeps", "JudgeReply",
    "SUBJECT_DEFENDER", "SUBJECT_WORLD", "_build_family_prompt", "_build_prompt",
    "validate_reply",
]
