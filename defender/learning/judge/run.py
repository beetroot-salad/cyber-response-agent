"""The judge's model call: the correlating prompt, lenient parse / strict validate, evidence
grounding, and one write per (world, draw) (#921 M2, D2, D3, D4, O1, O8, O9).

D2 — the judge runs under ITS OWN `AgentRole.JUDGE`, declared here as `JUDGE_DEF` with
`agent_id` prefix `"judge:"`. It borrowed the questioner's definition until #1008: the registry
admits one definition per key (`agent_definition.build_registry`) and the key was held by the
OLD pipeline's judge, so a second definition could not register beside it. #922 retired that
pipeline and freed the word; the family judge is a different role that wanted the same one.

WHAT THE OWN KEY BUYS, stated carefully because the easy version of this sentence is false.
The two policies are NOT identical: they are empty on every grant surface and differ in
`deny_reason`. But that one differing field has a single runtime reader — the bash gate — and
a role registering no tools never produces a gate decision at all, so the refusal text is a
fact about the compiled object rather than something this judge will ever be shown.

The benefit that actually holds is PROSPECTIVE: a grant added to `QUESTIONER_DEF` cannot reach
the judge, and the diff that would grant the judge something has to say so in the judge's own
file. `agent_id` partitions traces, never policies (`runtime/agent_role.py` states that rule),
so the separation had to be the key. The enum's own comment carries the general form: one
deny-all key per PACKAGE, which is why the branch package's comparator stays under QUESTIONER
while this package holds its own.

Model and effort come from `learning.core.config.judge_model()`/`judge_effort()` — read at call
time in `learning/judge/__init__.py` and threaded into the `StageWiring` the orchestration
builds, never from `questioner_model()`. `JUDGE_DEF` names the same two accessors so that a
build made OUTSIDE that wiring reaches the judge's knobs rather than another role's; but only
`model` is a thunk. `effort` is a plain string field, so `judge_effort()` runs once at import
and a later `JUDGE_EFFORT` cannot move it — which is why the wiring, not the definition, is
what the driven path reads, and why the definition's effort is a default for out-of-band
readers rather than a live one.

`JUDGE_MODEL` AND `JUDGE_EFFORT` ARE NOT THIS JUDGE'S ALONE, and the collision is live rather
than historical. #922 retired the OLD pipeline judge that used to share them, but
`evals/oracle_golden/judge.py` still reads both env vars directly, with DIFFERENT defaults
(`claude-opus-5` / `high` against this module's `kimi-k3` / `medium`) and folds the resolved
model into the tag it scores golden cases under. So setting either knob for this judge re-tags
that harness's scores, and setting it for the harness retargets this judge.

Registering this definition widened that blast radius one step further, and it is worth knowing
before touching either name: `run.py`'s all-roles preflight iterates EVERY registered
definition's model config at INVESTIGATION startup, so a `JUDGE_MODEL` naming a model no
provider routes now exits an ordinary alert run — and every `--resume` sibling — with rc 2,
before any judge is reached. That is a property of registration, shared with `QUESTIONER_MODEL`
and not new in kind; what IS new is that this knob has a second reader outside the loop.
Separating them means a knob NAME of this judge's own, which is a deliberate change with
fixtures behind it, not a side effect of reading the env twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from defender._run_paths import artifact_file
from defender._untrusted import message_salt, wrap
from defender.learning._prompt import stage_user_message, titled_section
from defender.learning.core.config import (
    QUEUEABLE_FINDING_TYPES,
    judge_effort,
    judge_model,
)
from defender.learning.core.validate import normalize_judge_yaml
from defender.learning.judge._errors import JudgeRefused
from defender.learning.judge.render import UNTRUSTED_TAG, JudgeInput
from defender.runtime.agent_definition import AgentDefinition
from defender.runtime.agent_role import AgentRole

#: The judge's refusal text, carried on its compiled policy.
#:
#: WHO READS THIS, stated plainly because the comment here used to imply the model does. It
#: does not: `deny_reason` reaches only `AgentPolicy` and from there the bash gate, which a
#: role registering no bash tool never invokes. The module docstring above says the same. So
#: this string is a property of the compiled object and of the operator surface that prints
#: it — which is why the judge holding its OWN is worth having, and also why its benefit is
#: prospective rather than something a draw will ever be shown.
#:
#: A deny reason is PROMPT SURFACE wherever it IS shown, so it names no program and no
#: capability this role lacks: a reason mentioning a command or a tool this lane denies
#: teaches a dead one. The grant gate sweeps every registered policy for the program half
#: (g1, in the #575 gate suite); the tool half it cannot see, so it is a rule kept by hand.
#:
#: AND IT IS WRITTEN, not derived from the questioner's by substitution. An earlier draft was
#: that role's sentence with three noun phrases swapped and the closing clauses byte-identical
#: — which passes every "is it the same string" check while being, in the only sense that
#: matters, the same refusal.
#:
#: WHAT IT CLAIMS IS WHAT THE PROMPT ACTUALLY HOLDS. A draft said "every world's record ... the
#: sibling run dirs" were framed into the prompt; `render.render` builds the input for ONE
#: non-control world plus the control it is compared against, so the wider claim was false in
#: the very string whose purpose is to stop the model reaching for more.
_JUDGE_DENY_REASON = (
    "Blocked: nothing is reachable from a judge draw. This episode was archived before the "
    "call began, and the world under grading — with the control it is compared against — was "
    "rendered into the prompt you already hold. There is no path left to resolve and no "
    "system left to ask, and a grade that reached for more would be grading something other "
    "than what was served. Answer from the prompt, as one YAML verdict document."
)


@dataclass(frozen=True)
class JudgeDeps:
    """Frozen, and carrying NOTHING but its role — zero fields, on purpose.

    Modelled on `QuestionerDeps` and for the same reason: a field here would be a channel. An
    episode dir, a world label or an archived trajectory reachable from inside a deny-all call
    is exactly the state this role is defined not to have — everything the judge reads is
    joined and inlined in one user message by the host before the call is made. `role` is a
    `ClassVar`, so it is not a field either; it is how `build_stage_agent` finds the definition
    (`learning/_pydantic_stage.py`) and how the trace names the call.

    It does NOT subclass `AgentDeps`, and that departure is the point. `AgentDeps` IS the run
    scope — run dir, compiled policy, box executor, cwd anchor — so inheriting it would hand
    this role a handle on every tree it may not touch. Nothing binds it either:
    `bind(JUDGE_DEF, ...)` refuses BY NAME (`agent_definition.bind`), because there is no run
    for a role whose entire input arrived in one prompt.
    """

    role: ClassVar[AgentRole] = AgentRole.JUDGE


#: The family judge's whole policy. Every grant surface `AgentDefinition` carries is an
#: OMISSION over its deny-all default — no tool set, no bash shape, no write shape, no verb
#: grant — rather than an empty grant line, which a one-word edit reopens while the diff still
#: reads as a tweak. That includes the tool set, which the questioner does spell out as an
#: empty one: the field default already IS empty, so spelling it buys nothing but a place to
#: type a capability into.
JUDGE_DEF = AgentDefinition(
    role=AgentRole.JUDGE,
    model=judge_model,
    effort=judge_effort(),
    deps_cls=JudgeDeps,
    deny_reason=_JUDGE_DENY_REASON,
)

#: The judge's own reply-level outcome vocabulary — NOT `_vocab.JUDGE_OUTCOME_ENUM`. That
#: vocabulary is the FAMILY's word (`caught|survived|undecidable|discard|corpus-contradiction`,
#: shared by the queue row, the family record and the curator gate); a raw reply never emits
#: `caught`/`survived`/`undecidable` (only the mechanical pass computes those), and it CAN emit
#: `gradable`, which is not a family word at all. Local because nothing else has to agree with
#: it — `_vocab.py`'s own admission rule.
_REPLY_OUTCOME_ENUM = frozenset({"gradable", "discard", "corpus-contradiction"})

#: What each reply-level outcome MEANS, keyed by the word itself — so the prompt spells every
#: member exactly once and a member added to the enum above cannot reach the model as a bare
#: word with no criterion. Naming them a second time in prose was how the first version of this
#: guidance was written, and a hand-typed list beside a rendered one is the drift the rendering
#: was there to prevent: `_outcome_guidance` refuses when the two sets disagree, so a new
#: outcome fails loudly here rather than silently arriving unexplained.
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

    Refuses rather than rendering a partial list: an outcome the validator accepts and the
    prompt cannot explain is one the model chooses by guessing, and a live draw that guessed
    wrote five sound findings and then discarded all of them by choosing a degenerate word.
    """
    missing = sorted(_REPLY_OUTCOME_ENUM - set(_OUTCOME_GUIDANCE))
    if missing:
        raise JudgeRefused(
            f"the judge's prompt has no criterion for episode_outcome {missing} — the "
            "validator accepts them and the model would be choosing by guesswork")
    return "".join(
        f"- `{word}` — {_OUTCOME_GUIDANCE[word]}.\n" for word in sorted(_REPLY_OUTCOME_ENUM)
    )

#: The two `subject` literals (#1007 O1/M6). Exactly two string literals — no case-fold and no
#: trim anywhere, which is what makes this selector and the appender's own guard agree by
#: construction rather than by convention.
SUBJECT_DEFENDER = "defender"
SUBJECT_WORLD = "world"

#: The four names that reach the prompt as EXAMPLES of a world-subject bucket — never a closed
#: set (R2/G-3): `validate_reply` refuses no bucket string outside this tuple.
EXAMPLE_WORLD_BUCKETS = (
    "unreachable-difference", "shape-invention", "story-overlay-gap", "undiscriminating-family",
)


class _OpenBucketVocabulary:
    """The world lane's bucket vocabulary (#1007 R2, accepted gap G-3): every STRING is a
    member, and nothing else is. Deliberately open — the design's example names
    (`unreachable-difference`, `shape-invention`, `story-overlay-gap`, `undiscriminating-family`)
    are PROMPT EXAMPLES, not a closed set, so a model's own novel reading of a world is admitted
    rather than rejected. `isinstance` alone, never truthiness: an empty or whitespace-only
    bucket is still a string and is admitted, stored verbatim — the drift a human declined to
    filter out before it can be observed."""

    def __contains__(self, item: object) -> bool:
        return isinstance(item, str)


#: The finding bucket vocabulary, SELECTED BY SUBJECT (#1007 O8/M10 + R2): the defender arm is
#: the queue's own closed set — NEVER coerced to the nearest member (a lookalike is rejected,
#: not rounded) — and the world arm is open. ONE lookup, so the two arms cannot drift into
#: disagreeing about which subject they are validating.
#:
#: THE DEFENDER ARM IS THE QUEUE'S OWN SET, not a fifth hand-typed copy of the same five words.
#: Every defender finding this validator admits becomes a queue row whose `type` is that
#: bucket, and `enqueue._validate_row` accepts it against `QUEUEABLE_FINDING_TYPES` — so the two
#: must be the same set or the pair disagrees in one direction or the other. Spelled here,
#: adding a sixth family bucket to `config.FAMILY_ONLY_FINDING_TYPES` widened the queue and left
#: this validator refusing every reply that used it, counted as a malformed reply, with the draw
#: file removed and no error above `malformed_replies`.
_BUCKET_ENUM: dict[str, Any] = {
    SUBJECT_DEFENDER: frozenset(QUEUEABLE_FINDING_TYPES),
    SUBJECT_WORLD: _OpenBucketVocabulary(),
}

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


@dataclass(frozen=True)
class Finding:
    bucket: str
    subject: str
    claim: str
    root_cause: str
    anchor: str
    topic: str
    evidence: list[str] = field(default_factory=list)
    discriminator_related: bool = False
    #: World-lane-only content (#1007 M6/A3): carried through so the pass can build a
    #: questioner-channel row, but IDENTITY (which world) is never taken from here — the pass
    #: stamps its own `world` from the draw's own world directory, never the model's claim.
    pattern: str | None = None
    holding_system: str | None = None
    world: str | None = None


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


def _parse_finding(raw: Any, index: int, *, scope: str) -> Finding:  # noqa: C901 — the field checks, subject partition and family-scope rules are one demand over one raw finding
    if not isinstance(raw, dict):
        raise JudgeRefused(f"finding[{index}] is not a mapping")
    for key in ("bucket", "subject", "claim", "root_cause", "anchor", "topic", "evidence"):
        if key not in raw:
            raise JudgeRefused(f"finding[{index}] is missing {key!r}")
    # A PRESENT-AND-NULL KEY IS A MISSING ONE. `key not in raw` is satisfied by `anchor:` with
    # nothing after it, and the coercion below then turns `None` into the four-character string
    # `"None"` — which is not content-less, so `enqueue._validate_row`'s "subject_anchor must be
    # a non-empty string" guard passes it, and a twelve-key row whose subject is the word None
    # reaches the shared queue and the curator. The queue's rule cannot be enforced downstream
    # of a coercion that manufactures content, so the refusal is here, where the value is still
    # the model's own.
    for key in ("claim", "root_cause", "anchor", "topic"):
        if raw[key] is None:
            raise JudgeRefused(
                f"finding[{index}].{key} is null — a null is refused rather than rendered as "
                "the string 'None', which reads downstream as content the model never wrote")
    # `subject` (#1007 O1/M6): the partition itself. NO CASE-FOLD, NO TRIM — a near-miss
    # (`"World"`, `" world"`, `"defender\n"`) is refused exactly like a bucket lookalike, so the
    # validator and the appender's own guard cannot come to disagree about which channel a row
    # belongs on.
    subject = raw["subject"]
    if subject not in (SUBJECT_DEFENDER, SUBJECT_WORLD):
        raise JudgeRefused(
            f"finding[{index}].subject={subject!r} is not one of "
            f"{sorted((SUBJECT_DEFENDER, SUBJECT_WORLD))!r} — no case-fold and no trim, so a "
            "finding whose subject nobody stated exactly is a finding no channel can route")
    if scope == "family":
        # M5/A1: the family reply is itself `subject: world` in its entirety, and may name no
        # world — the pass owns identity for a family-level observation (`world: null`), and a
        # model attributing one to whichever world it found memorable is refused here rather
        # than silently overridden.
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
    """Parse `text` LENIENTLY (a fence with prose BEFORE it recovers cleanly — C12) and
    validate STRICTLY: nothing is read off the reply before this returns.

    `scope` (#1007 M4/M5) is which call this reply came from: `"world"` (the default) is a
    per-world draw, which may emit either subject; `"family"` is the family-level draw, which
    may emit only `subject: world` findings naming no world (M5/A1).

    "Around" was the claim and it is true of every shape but ONE: a reply whose FIRST
    character is the fence and that then adds a closing sentence. `strip_yaml_fence`'s
    unanchored rule is guarded by `not s.startswith("```")`, so leading prose is what arms it
    — a fence with prose on BOTH sides recovers, and a fence at position 0 with prose after it
    is stripped by no rule and refused here as invalid YAML. One draw lost, and at the default
    draw count that is the whole world's grade. Left standing deliberately: three attempts at
    the obvious repair each silently returned the WRONG fenced block as the verdict on some
    other shape, which is worse than the refusal, and what a reply carrying several fenced
    blocks means has never been settled. Tracked as its own issue rather than guessed at
    here — and no test pins the shape, so the sentence above is prose, not a gate."""
    import yaml

    from defender._yaml import safe_load

    # A NON-STRING REPLY IS THIS DESIGN'S REFUSAL, not an `AttributeError`. The seam is
    # `judge: Any` — the design's own injection point — so a seam that returns `None` on a
    # refusal (or a result object, or a dict) is a live shape, and `normalize_judge_yaml`'s
    # first act is `text.strip()`. The draw loop contains `JudgeRefused` and nothing else, and
    # `grade_episode`'s conversion set names neither `AttributeError` nor `TypeError` — so one
    # such reply took the WHOLE pass down: every already-completed world's draws thrown away
    # and no `judge.yaml` written, which is the blast radius the malformed-reply arm exists to
    # eliminate.
    if not isinstance(text, str):
        raise JudgeRefused(
            f"the judge seam returned {type(text).__name__}, not the reply text this design "
            "parses — one draw is unusable, which is not the episode's grade")
    cleaned = normalize_judge_yaml(text)
    try:
        # `_yaml.safe_load`, not PyYAML's: it converts a `RecursionError` (a reply nested too
        # deeply) and a constructor `ValueError` (an out-of-range implicit timestamp) into
        # `yaml.YAMLError`, and neither is a `YAMLError` on its own. The reply is MODEL-authored,
        # so both are shapes to meet — and neither is in `grade_episode`'s conversion set either,
        # so one such reply took the whole pass down as a bare interpreter error rather than
        # costing its own draw.
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


#: S7: the exactly-three episode-level files a `subject: world` evidence pointer may ALSO name
#: — an allowlist of resolved TARGETS (bare names only, never a prefix a traversal could dress
#: up to pass), never a widen of the whole episode dir. The defender arm is unchanged: world-
#: subtree-only.
_WORLD_EVIDENCE_FILES = ("samples.yaml", "review.yaml", "judge.yaml")


def _resolves(pointer: str, world_dir: Path, *, subject: str = SUBJECT_DEFENDER) -> bool:
    """J13(a): does this evidence pointer resolve inside the GRADED WORLD's own subtree — never
    a sibling's archive, whatever bytes exist at the target. For a `subject: world` finding
    ONLY, S7 widens this to also admit exactly the three episode-level files named above, by
    NAME — never a directory prefix, never the episode dir wholesale."""
    if not isinstance(pointer, str) or not pointer:
        return False
    path_part = pointer.split("#", 1)[0]
    if not path_part or Path(path_part).is_absolute():
        return False
    try:
        root = world_dir.resolve()
        candidate = (world_dir / path_part).resolve()
        candidate.relative_to(root)
    # `_run_paths._RESOLVE_ERRORS`' OWN THREE CLASSES, not two of them. `resolve()` on a hostile
    # operand raises `RuntimeError` for a symlink cycle — and the graded world's subtree is a
    # box's rw bind, so a pointer aimed at one is an ordinary shape to meet. `RuntimeError` is in
    # neither this frame's handler nor `grade_episode`'s conversion set, so it escaped the whole
    # pass as a bare traceback AFTER every world's model calls had been paid for.
    except (OSError, RuntimeError, ValueError):
        pass
    else:
        if artifact_file(candidate):
            return True
    # NO EXISTENCE CHECK on the widened branch, deliberately: `judge.yaml` is the pass's OWN
    # output, written only after every world's draws complete, so an evidence pointer citing it
    # from INSIDE the very draw that is producing it can never find it on disk yet — the
    # allowlist is by NAME (`path_part in _WORLD_EVIDENCE_FILES`, `Path(path_part).name ==
    # path_part` already refuses every traversal shape in the negative test, since a hostile
    # operand's `.name` is never equal to the whole pointer), never by a stat this pass cannot
    # honestly perform on its own future output.
    return subject == SUBJECT_WORLD and path_part in _WORLD_EVIDENCE_FILES \
        and Path(path_part).name == path_part


def cites_sample(finding: dict[str, Any]) -> bool:
    """A1(b): does this finding's evidence cite `samples.yaml`, BY NAME, whatever its fragment?

    Anchored on the EVIDENCE rather than on the `shape-invention` bucket literal, because R2's
    world vocabulary is open (G-3) — a refusal keyed on one string is evadable by a model that
    spells the same claim differently. A world whose row reads `sample_unavailable` refuses
    every finding this returns `True` for and keeps every other one, whatever its bucket
    (#1007, `test_a_finding_citing_an_unavailable_sample_is_refused_whatever_its_bucket`)."""
    for pointer in finding.get("evidence") or ():
        if isinstance(pointer, str) and pointer.split("#", 1)[0] == "samples.yaml":
            return True
    return False


def _draw_document(reply: JudgeReply, *, world_dir: Path) -> dict[str, Any]:
    """O1: a finding with no resolving pointer is dropped and the drop is counted; a finding
    with one resolving pointer stands, with its unresolved pointers recorded on it."""
    kept: list[dict[str, Any]] = []
    dropped = 0
    for finding in reply.findings:
        # ONE resolution pass per pointer: "did any resolve" and "which did not" are two reads
        # of the same answer, and asking twice `stat`s every pointer of every finding twice.
        unresolved = [p for p in finding.evidence
                     if not _resolves(p, world_dir, subject=finding.subject)]
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
    """D4: the correlating prompt, parameterised by the graded world's label. Wording names
    hand-offs, never entities or systems; keeps the 20-row cap and the quote-any-colon rule
    that made 15/15 replies parse strictly (C12).

    THE LABEL COMES OFF THE RENDERED INPUT, and there is no keyword to override it with.
    `JudgeInput.world_label` is the world `render` actually assembled these views for; taking it
    a second time as a keyword gave one value two carriers with nothing holding them in
    agreement — a caller could render `b` and prompt for `c` and no type, test or assertion
    would notice — and no caller in this repo ever passed it (`defender/CLAUDE.md`: resolve an
    optional input once at the boundary, never re-coalesce it in the body)."""
    label = judge_input.world_label
    task = (
        f"World {label} has run; grade it.\n\n"
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
        # THE VALIDATOR'S OWN SET, rendered — the same treatment the bucket enum below already
        # gets, and for the same reason. The three words were DESCRIBED rather than written
        # ("the discard word", "the two-word corpus/world contradiction outcome"), so the model
        # had to guess both the literal strings and, with nothing said at all about when each
        # applies, the criteria. It guessed the strings right and the criteria wrong: a live
        # draw wrote five sound findings about the defender's gathering and then chose
        # `corpus-contradiction`, which discards every one of them (O7), over an episode its own
        # note described as the defender never pulling the payload — which is `gradable`.
        f"Reply as one YAML mapping: episode_outcome (exactly one of "
        f"{' | '.join(sorted(_REPLY_OUTCOME_ENUM))}), "
        "noise_floor_note, correlations, scope_checks, derivations, findings (each: bucket, "
        f"subject [{SUBJECT_DEFENDER}|{SUBJECT_WORLD}], claim, "
        # THE VALIDATOR'S OWN SET, rendered — not a sixth hand-typed copy of the same five
        # words. `_BUCKET_ENUM[SUBJECT_DEFENDER]` is derived from `QUEUEABLE_FINDING_TYPES`, so
        # a bucket added there widened what a reply may carry and was never named to the model,
        # and a bucket removed there left the prompt advertising one every reply using it is
        # refused for — counted as a malformed reply, with the draw file removed and no error
        # above `malformed_replies`. THE WORLD VOCABULARY IS DELIBERATELY OPEN (R2): the four
        # names below are EXAMPLES, not an enum, so no exhaustive list is rendered for it.
        f"a subject: {SUBJECT_DEFENDER} finding's bucket is one of "
        f"[{'|'.join(sorted(_BUCKET_ENUM[SUBJECT_DEFENDER]))}]; a subject: {SUBJECT_WORLD} "
        f"finding's bucket is your own free text naming what is wrong with the WORLD itself "
        f"rather than the defender — for example {', '.join(EXAMPLE_WORLD_BUCKETS)} — "
        "root_cause, anchor, topic, evidence, discriminator_related). Every finding names its "
        f"subject: {SUBJECT_DEFENDER} finding is about how the defender investigated; a "
        f"{SUBJECT_WORLD} finding is about the instrument itself — an invented shape, a story "
        "the overlay does not back, or (family call only) that the family failed to "
        "discriminate at all — and is never authored as a lesson for the defender.\n\n"
        # THE SHAPE OF `evidence`, stated. The field list above names it and stops, so a model
        # that reads "evidence" writes the English sense of the word — a sentence quoting what
        # it saw. The reply validator requires a LIST and refuses the reply outright, which
        # counts a malformed reply, deletes the draw and grades the world on nothing; and a
        # list of prose would then have been dropped one step later by `_draw_document`, which
        # discards any finding whose pointers all fail to resolve. Both failures are silent
        # above `malformed_replies`, so the judge produced no findings at all and said only
        # that its own reply was malformed.
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
    # ITERATE THE SECTIONS, not the titles. `as_prompt_sections` owns the set (and `_cap_sections`
    # charges the payload cap over it), so driving the assembly from `SECTION_TITLES` made a view
    # added there but not here rendered, capped, charged its equal share of the operator's
    # `JUDGE_PAYLOAD_CAP` — and then silently never sent, with no exception and no log line. A
    # section with no title of its own is titled by its key rather than dropped; the reverse
    # mistake (a title with no section) was a bare `KeyError` out of the whole pass.
    titled = [titled_section(SECTION_TITLES.get(name, name.upper()), body)
              for name, body in sections.items()]
    salt = message_salt(task, *titled)
    # ONE tag, `UNTRUSTED_TAG`, on every section: the reader contract names sections by their
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
    body = stage_user_message(salt, *(wrap(section, UNTRUSTED_TAG, salt) for section in titled))
    return task + body


def _render_family_manifest(manifest: dict[str, Any]) -> str:
    """Every world's story, axis, declared disposition and overlay — WITHHOLDING NONE. The
    per-world call's whole point is that a sibling's overlay must never reach it (O5/J14); the
    family call's whole question is whether the SET separates, so withholding a member here
    makes that question unanswerable (#1007, `test_the_family_call_is_shown_every_world`)."""
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
    """Every world's mechanical row (M3) — the same facts the per-world call sees about itself,
    joined here across the whole family, plus each world's completed-draw verdict."""
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
    """M5: one call per draw, judging what no single world can — whether the FAMILY separates
    on the discriminator. Shown every world's overlay, the review record and every mechanical
    row; withholds none (unlike the per-world call, which withholds every sibling's).

    The reply is `subject: {SUBJECT_WORLD!r}` in its entirety (A1: the family reply IS a world-
    subject reply, never a defender one) and may name no `world` — a family-level observation is
    about the set, not about any one member of it."""
    import yaml

    task = (
        "Judge this WHOLE FAMILY of sibling worlds — never any single world. You are shown "
        "every world's overlay, the family's review record and every world's own mechanical "
        "facts; nothing here is withheld.\n\n"
        "Answer only family-level questions: did the worlds SEPARATE on the discriminator (did "
        "at least one measuring world's verdict disagree from another's, or from what its own "
        "difference should have produced), and did the envelope actually ask it?\n\n"
        f"Reply as one YAML mapping: episode_outcome (exactly one of "
        f"{' | '.join(sorted(_REPLY_OUTCOME_ENUM))}), noise_floor_note, correlations, "
        "scope_checks, derivations, findings (each: bucket [your own free text — for example "
        f"{', '.join(EXAMPLE_WORLD_BUCKETS)}], subject (always {SUBJECT_WORLD!r} — this call "
        "never grades the defender), claim, root_cause, anchor, topic, evidence, "
        "discriminator_related). A family-level finding is about the FAMILY as a whole and "
        "must NEVER name a `world` — do not add a `world` key to any finding.\n\n"
        f"{_outcome_guidance()}"
    )
    sections = {
        "manifest": _render_family_manifest(manifest),
        "review": yaml.safe_dump(review, sort_keys=False) if review else
                 "no review.yaml is recorded for this episode\n",
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
