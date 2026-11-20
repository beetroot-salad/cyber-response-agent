"""The questioner: a deny-all role that authors one family of sibling worlds."""
from __future__ import annotations

from defender._model import model
from pathlib import Path
from collections.abc import Sequence
from typing import Any, ClassVar

import json
import logging

from pydantic_ai import ModelRetry

from defender.configuration import env_str
from defender._io import read_guarded, read_text_utf8
from defender.records.formats import FamilyError, check_composed_world, check_composed_worlds
from defender.records import RunPaths
from defender._untrusted import message_salt
from defender.learning._prompt import section_text, stage_user_message, titled_section
from defender.learning._pydantic_stage import TypedOutput
from defender.learning.core.config import ReplyUnusable
from defender.investigation.agent_definition import AgentDefinition, ToolSet
from defender._agent_role import AgentRole
from defender.investigation.branch import BranchError
from defender.skills.invlang.parser import scan_fences

_logger = logging.getLogger(__name__)

#: Re-asks one call may make when its reply is refused (#1579): at most 1 + this many requests per
#: call, so a questioner that cannot answer is bounded with no operator present.
QUESTIONER_REPLY_RETRIES = 2

#: The untrusted frame tag every captured artifact this role sees is wrapped in.
UNTRUSTED_TAG = "untrusted"

#: The seats, in family order. The role letter is assigned by seat, not taken from the reply,
#: so roles are always distinct (a model could return two `B`s).
WORLD_SEATS: tuple[str, ...] = ("B", "C")

#: World A is not authored: it is the capture (no facts, null axis), which makes it the
#: control.
BASE_WORLD_LABEL = "a"
BASE_WORLD_ROLE = "A"

_PROMPTS = Path(__file__).resolve().parent

_QUESTIONER_DENY_REASON = (
    "Blocked: the questioner is a pure authoring projection — its entire input is inlined in "
    "the user prompt by the host and its entire output is the arguments of the one output tool "
    "this call offers. It runs no other tools: no data-source adapters, no run-dir reads, no "
    "writes, no shell. Call that output tool with your reply; plain text is not an answer."
)


def questioner_model() -> str:
    """The questioner's model, read at call time so an env override reaches it."""
    return env_str("QUESTIONER_MODEL", "kimi-k3")


def questioner_effort() -> str:
    return env_str("QUESTIONER_EFFORT", "medium")


@model(frozen=True)
class QuestionerDeps:
    """Frozen, with no fields: only a `role` ClassVar naming the call.

    A field would be a channel to state (a run dir, a world label) this role must not have. It
    does not subclass `AgentDeps`, which is the run scope (run dir, policy, box executor).
    `bind(QUESTIONER_DEF, …)` refuses by name: there is no run for a role whose whole input is
    inlined by the host."""

    role: ClassVar[AgentRole] = AgentRole.QUESTIONER


QUESTIONER_DEF = AgentDefinition(
    role=AgentRole.QUESTIONER,
    model=questioner_model,
    effort=questioner_effort(),
    tools=ToolSet(),
    deps_cls=QuestionerDeps,
    deny_reason=_QUESTIONER_DENY_REASON,
)


def _prompt(name: str) -> str:
    """One shipped prompt, read from this package."""
    return read_text_utf8(_PROMPTS / name)


def _measurement_header(source_run_dir: Path, episode_dir: Path,
                        served_systems: Sequence[str] = ()) -> str:
    """The names this family is being authored for, as host text.

    Unframed because the operator and host chose these names (run, episode, the served systems
    the launch's gather grant decided); none is attacker-influenced. The run and episode let the
    story identify which episode it belongs to.

    The served systems are stated explicitly and alike — no system gets guidance another does
    not: they are the whole of what the investigator can ask, so a fact placed anywhere else is
    one no query in the episode can show.
    """
    served = ", ".join(f"`{s}`" for s in served_systems)
    return (
        "## The measurement\n\n"
        f"This family is authored for episode `{episode_dir.name}`, "
        f"branching the finished run `{source_run_dir.name}`.\n"
        + (f"\nThe tenant serves exactly these systems: {served}. They are the whole of what "
           "the investigator can ask, so every fact a world asserts must be one at least one of "
           "them would reflect.\n" if served else "")
    )


def _samples_section(samples: Any, served_systems: Sequence[str]) -> str:
    """The samples document (`samples.yaml`): real example answers from the capture, per served
    system and per verb, so the author sees what each system actually returns.

    Untrusted like the rest of the capture. Every served system is listed: one whose section is
    unavailable carries its reason, one the capture never asked says so, rather than vanishing.
    """
    if not isinstance(samples, dict) or not served_systems:
        return ""
    blocks: list[str] = []
    for system in served_systems:
        section = samples.get(system)
        if not isinstance(section, dict):
            blocks.append(f"system {system}: no example was recorded")
            continue
        reason = section.get("unavailable")
        if isinstance(reason, str):
            blocks.append(f"system {system}: unavailable — {reason}")
            continue
        verbs = section.get("verbs")
        if not isinstance(verbs, dict) or not verbs:
            blocks.append(f"system {system}: the capture never asked this system")
            continue
        lines = [f"system {system}:"]
        for verb, texts in verbs.items():
            lines.append(f"  verb {verb}:")
            for text in texts if isinstance(texts, list) else [texts]:
                lines.append(f"    {text if isinstance(text, str) else json.dumps(text, default=str)}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


@model(frozen=True)
class _Capture:
    """The captured inputs as rendered section bodies, ready to be framed.

    Every call gets the capture itself, not just Call 1's summary of it. Rendered once (they are
    large and identical across seats) but framed per call, since each message has its own salt:
    each body goes inside its frame and its title (`_TITLES`) outside it, as host text (#1234
    A10). An empty `samples` or `lessons` is a section the call omits.
    """

    leads: str
    alert: str
    frontier: str
    samples: str = ""
    lessons: str = ""


#: Each captured section's host title, outside its frame (`titled_section`).
_TITLES = {
    "leads": "The joined leads at the branch point",
    "alert": "The alert this investigation started from",
    "frontier": "The investigation document at the branch point",
    "samples": "Real example answers from each served system, taken from the capture, grouped "
               "by verb — what a fact you author will look like when the investigator asks",
    "lessons": "Pitfalls this questioner corpus recorded about worlds it authored before",
}


#: Cap on the questioner's own lessons in a prompt (same 20-row convention as the judge's).
_QUESTIONER_LESSONS_CAP = 20


def _questioner_lessons_section(lessons: Any, *, served_systems: Sequence[str]) -> str:
    """Every candidate lesson path, read, screened and selected — the section body, or ""."""
    if not lessons:
        return ""
    from defender._frontmatter import FrontmatterError, split_frontmatter
    from defender._io import TEXT_READ_ERRORS, read_text_utf8
    from defender._yaml import duplicate_top_level_key

    served = set(served_systems)
    chosen: dict[str, str] = {}
    for path in lessons:
        path = Path(path)
        try:
            text = read_text_utf8(path)
        except TEXT_READ_ERRORS as unreadable:
            _logger.warning(f"questioner lesson {path.name} skipped: it could not be read "
                            f"({type(unreadable).__name__})")
            continue
        try:
            fm, raw, body = split_frontmatter(text)
        except FrontmatterError as bad:
            _logger.warning(f"questioner lesson {path.name} skipped: {bad}")
            continue
        # The raw frontmatter only: on the whole file (markdown body included) the YAML parse
        # fails and `duplicate_top_level_key` returns `False`, so the guard would never fire.
        if duplicate_top_level_key(raw):
            _logger.warning(f"questioner lesson {path.name} skipped: its frontmatter repeats a "
                            "top-level key")
            continue
        systems = fm.get("systems")
        if "systems" in fm and not _lesson_systems_ok(systems):
            _logger.warning(f"questioner lesson {path.name} skipped: its systems is {systems!r}, "
                            "not a list of system names")
            continue
        if not isinstance(systems, list) or not served.intersection(systems):
            continue
        if body:
            chosen[path.name] = body
    if not chosen:
        return ""
    capped = [chosen[name] for name in sorted(chosen)][:_QUESTIONER_LESSONS_CAP]
    return "\n\n---\n\n".join(capped)


def _lesson_systems_ok(systems: Any) -> bool:
    """A lesson's `systems`: a list of non-empty strings. An empty list is well-formed (the
    seed lesson's) and selects nothing."""
    return isinstance(systems, list) and all(isinstance(s, str) and s for s in systems)


def _capture_sections(*, leads: Any, alert: Any, frontier: str, samples: Any = None,
                      lessons: Any = None, served_systems: Sequence[str] = ()) -> _Capture:
    return _Capture(
        leads=section_text(leads),
        alert=section_text(alert),
        frontier=section_text(frontier),
        samples=_samples_section(samples, served_systems),
        lessons=_questioner_lessons_section(lessons, served_systems=served_systems),
    )


def _base_world(family: dict[str, Any], source_disposition: str | None) -> dict[str, Any]:
    """World A, composed rather than authored by a call of its own.

    No facts, a null axis and the base role are imposed, never read from a reply: they make A
    the control, and a fact would change the world the others are measured against.

    The declared disposition is call 1's `base_disposition` when that key is present (a blank
    or null one is refused by the world rule, never replaced), else the disposition the source
    run's closing record committed (`source_disposition`, read by the launcher before any model
    call; #1534). If both are silent the key is left absent so the world rule refuses."""
    world: dict[str, Any] = {"story": family.get("base_story")}
    declared = family.get("base_disposition", source_disposition)
    if declared is not None or "base_disposition" in family:
        world["disposition_declared"] = declared
    world.update({
        "label": BASE_WORLD_LABEL,
        "role": BASE_WORLD_ROLE,
        "axis": None,
        # M07=A: the control world carries an explicit empty fact list.
        "facts": [],
    })
    return world


def _family_prompt(header: str, capture: _Capture) -> str:
    """Call 1's whole message: the task and header (host text, unframed), then the framed
    capture.
    """
    salt = message_salt(capture.leads, capture.alert, capture.frontier, capture.samples,
                        capture.lessons)
    return (
        f"{_prompt('family.md')}\n{header}\n"
        + stage_user_message(
            salt,
            titled_section(_TITLES["leads"], capture.leads, salt=salt, tag=UNTRUSTED_TAG),
            titled_section(_TITLES["alert"], capture.alert, salt=salt, tag=UNTRUSTED_TAG),
            titled_section(_TITLES["frontier"], capture.frontier, salt=salt, tag=UNTRUSTED_TAG),
            *([titled_section(_TITLES["samples"], capture.samples, salt=salt, tag=UNTRUSTED_TAG)]
              if capture.samples else []),
            # Lessons go to Call 1 only: it names the discriminator and base story, which is
            # what the lessons are about.
            *([titled_section(_TITLES["lessons"], capture.lessons, salt=salt, tag=UNTRUSTED_TAG)]
              if capture.lessons else []),
        )
    )


def _world_prompt(seat: str, *, axis: Any, family_reply: Any, header: str,  # noqa: PLR0913 — the seat, its plan and the capture, plus a revision's conflict
                  capture: _Capture, revision: Any = None) -> str:
    """The prompt for one world-authoring seat.

    `family_reply` is re-wrapped as untrusted (Call 1 read attacker-influenced text), in this
    message's own salt, minted after the reply exists so Call 1's model has never seen it."""
    seeded = section_text(family_reply)
    conflict = section_text(revision) if revision is not None else ""
    salt = message_salt(seeded, capture.leads, capture.alert, capture.frontier, capture.samples,
                        conflict)
    axis_line = f"Your axis, as call 1 named it: {axis}\n" if axis is not None else ""
    # A revision has its own prompt: it returns the facts that `world.md` tells a seat never to.
    return (
        f"{_prompt('world.md' if revision is None else 'revise.md')}\n"
        f"## Your seat\n\nYou are authoring the world in seat {seat}.\n{axis_line}\n"
        + f"{header}\n"
        + stage_user_message(
            salt,
            *([titled_section("Conflict with what the run already saw", conflict, salt=salt,
                              tag=UNTRUSTED_TAG)] if revision is not None else []),
            titled_section(f"Call 1's output (seat {seat} authors against this)", seeded,
                           salt=salt, tag=UNTRUSTED_TAG),
            titled_section(_TITLES["leads"], capture.leads, salt=salt, tag=UNTRUSTED_TAG),
            titled_section(_TITLES["alert"], capture.alert, salt=salt, tag=UNTRUSTED_TAG),
            titled_section(_TITLES["frontier"], capture.frontier, salt=salt, tag=UNTRUSTED_TAG),
            # The seat sees the samples too: its story must be one the served systems can tell.
            *([titled_section(_TITLES["samples"], capture.samples, salt=salt, tag=UNTRUSTED_TAG)]
              if capture.samples else []),
        )
    )


def read_frontier(source_run_dir: Path, *, fences_at: int) -> str:
    """The source run's investigation document as it stood after `fences_at` invlang fences.

    `source_run_dir` is a prior box's rw bind, so `investigation.md` may be a planted symlink;
    it is read without following links, since the bytes go into a model prompt. The refusal
    names the file, not the link target (which the planter chose).

    Returns the invlang prefix itself rather than a rendering of the derived `Frontier`, so the
    questioner reads what the investigator wrote and there is no second projection of invlang.
    """
    document = RunPaths(source_run_dir).investigation
    # `read_guarded` checks the open descriptor, so there is no check-then-act window between
    # an lstat and the read in which the entry could be swapped.
    text, refusal = read_guarded(document)
    if text is None:
        raise BranchError(
            f"{document}: {document.name} is not a regular file ({refusal}) — the source run "
            "dir is a box's rw bind, so an entry there that is not what it claims to be was "
            "planted; refusing to read it into a prompt"
        )
    bodies = scan_fences(text).bodies
    kept = bodies[:max(0, fences_at)]
    return "\n\n".join(f"```invlang\n{body}\n```" for body in kept)


#: The fields a seat authors. Everything else (label, facts) is Call 1's plan, which must be
#: coherent across worlds; a seat elaborates, it does not re-plan.
SEAT_AUTHORED_FIELDS: frozenset[str] = frozenset({"story", "axis", "disposition_declared",
                                                  "label_basis"})


#: The most characters one pre-branch answer, and all of them together, take in the check.
_PREBRANCH_ANSWER_CAP = 4000
_PREBRANCH_TOTAL_CAP = 60_000


def _prebranch_section(prebranch: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The pre-branch calls and their recorded answers as the check reads them, newest first,
    each answer cut to its cap and the whole within its total."""
    out: list[dict[str, Any]] = []
    total = 0
    for entry in reversed(list(prebranch)):
        text = section_text(entry.get("answer"))
        if len(text) > _PREBRANCH_ANSWER_CAP:
            text = f"{text[:_PREBRANCH_ANSWER_CAP]} ... [cut: {len(text)} characters]"
        if total + len(text) > _PREBRANCH_TOTAL_CAP:
            break
        total += len(text)
        out.append({"call": entry.get("call"), "answer": text})
    return out


#: The keys call 1 may return, each planned world may carry, and a revision may add to a seat's.
_PLAN_KEYS = frozenset({"base_story", "base_disposition", "discriminator", "worlds"})
_PLANNED_KEYS = frozenset({"label", "axis", "facts"})
_REVISION_KEYS = SEAT_AUTHORED_FIELDS | {"facts"}

_PLAN_SCHEMA: dict[str, Any] = {"type": "object", "properties": {
    "base_story": {"type": "string"}, "base_disposition": {"type": "string"},
    "discriminator": {"type": "object", "properties": {"predicate": {"type": "string"}}},
    "worlds": {"type": "array", "items": {"type": "object", "properties": {
        "label": {"type": "string"}, "axis": {"type": "string"}, "facts": {"type": "array"}}}}}}
_SEAT_SCHEMA: dict[str, Any] = {"type": "object", "properties": {
    "story": {"type": "string"}, "axis": {"type": "string"},
    "disposition_declared": {"type": "string"}, "label_basis": {"type": "string"}}}
_REVISION_SCHEMA: dict[str, Any] = {"type": "object", "properties": {
    **_SEAT_SCHEMA["properties"], "facts": {"type": "array"}}}
_CHECK_SCHEMA = {"type": "object", "properties": {"conflicts": {"type": "array"}}}


def _retry_with(why: object) -> ModelRetry:
    return ModelRetry(str(why))


def _closed_to(mapping: Any, allowed: frozenset[str], *, what: str) -> dict[str, Any]:
    """`mapping` as a dict whose keys are all in `allowed`: every call kind is closed, so a key
    the model wrote is refused in-call, never dropped later."""
    if not isinstance(mapping, dict):
        raise _retry_with(f"{what} must be a mapping, got {type(mapping).__name__}")
    if "world_id" in mapping:
        raise _retry_with("world_id is host-assigned; author descriptive fields only")
    extra = sorted(str(k) for k in mapping if k not in allowed)
    if extra:
        raise _retry_with(f"{what} has key(s) {', '.join(extra)} that this call does not take; "
                      f"it takes only {', '.join(sorted(allowed))}")
    return mapping


def _planned_entry(entry: Any) -> dict[str, Any]:
    if isinstance(entry, dict) and "world_id" in entry:
        raise _retry_with("world_id is host-assigned; author descriptive fields only")
    return _closed_to(entry, _PLANNED_KEYS, what="a planned world")


def _placeholder_world(plan: dict[str, Any], role: str) -> dict[str, Any]:
    """A planned world as the manifest gate would see it once its seat wrote the fields the
    plan does not carry (placeholders that pass: the seat's own values are checked at its call)."""
    return {"story": "", "disposition_declared": "benign", **plan, "role": role}


def _plan_check(source_disposition: str | None) -> Any:
    """Call 1's check: everything call 1 decides, composed and run through the manifest gate's
    rules, so a plan the gate would refuse is refused while call 1 can still fix it."""
    def check(reply: Any) -> None:
        family = _closed_to(reply, _PLAN_KEYS, what="the plan")
        entries = family.get("worlds")
        if not isinstance(entries, list) or not entries:
            raise _retry_with("worlds must be a non-empty list of the worlds you plan")
        planned = [_planned_entry(entry) for entry in entries]
        worlds = [_base_world(family, source_disposition),
                  *(_placeholder_world(plan, _seat_letter(i)) for i, plan in enumerate(planned))]
        try:
            check_composed_worlds(base_story=family.get("base_story"),
                                  discriminator=family.get("discriminator"), worlds=worlds)
        except FamilyError as refused:
            raise _retry_with(refused) from refused
    return check


def _seat_check(plan: dict[str, Any], seat: str) -> Any:
    def check(reply: Any) -> None:
        authored = _closed_to(reply, SEAT_AUTHORED_FIELDS, what=f"seat {seat}'s reply")
        try:
            check_composed_world({**plan, **authored, "role": seat}, where=f"seat {seat}")
        except FamilyError as refused:
            raise _retry_with(refused) from refused
    return check


def _revision_check(world: dict[str, Any], seat: str) -> Any:
    def check(reply: Any) -> None:
        authored = _closed_to(reply, _REVISION_KEYS, what=f"seat {seat}'s revision")
        facts = authored.get("facts")
        if not (isinstance(facts, list) and facts):
            raise _retry_with("facts must be present and non-empty: the facts the run's answers "
                          "contradicted are never kept")
        try:
            check_composed_world({**world, **authored}, where=f"the revision of seat {seat}")
        except FamilyError as refused:
            raise _retry_with(refused) from refused
    return check


def _premise_check(reply: Any) -> None:
    """The conflicts list's shape. Entries naming an unknown label, or carrying other keys, are
    dropped by the reader, not refused (P4): refusing a whole check for a stray label would
    exhaust it and keep a contradicted world."""
    doc = _closed_to(reply, frozenset({"conflicts"}), what="the premise check")
    if not isinstance(doc.get("conflicts"), list):
        raise _retry_with("conflicts must be a list (empty when nothing conflicts)")


def _ask_typed(invoke: Any, prompt: str, *, agent_id: str, name: str, description: str,
         schema: dict, check: Any) -> dict[str, Any]:
    """One typed call: the accepted mapping, after the call site runs the same check on what the
    seam returned. In production that repeats a deterministic check; under a test fake it is the
    only run, so fakes meet the real rules. A refusal here is the call's `ReplyUnusable`."""
    output = TypedOutput(name=name, description=description, schema=schema, check=check,
                         retries=QUESTIONER_REPLY_RETRIES)
    reply = invoke(prompt, role=AgentRole.QUESTIONER, agent_id=agent_id, output=output)
    mapping, requests = reply if isinstance(reply, tuple) else (reply, 1)
    try:
        check(mapping)
    except ModelRetry as refused:
        reason = str(refused)
        raise ReplyUnusable(f"{agent_id}: {reason}", reason=reason, requests=requests) from refused
    return dict(mapping)


def _unusable_text(failed: BaseException) -> str:
    """How a degraded call is logged: a refusal by its reason, a host failure by its exception."""
    if isinstance(failed, ReplyUnusable):
        return f"its reply was unusable after {failed.requests} requests: {failed.reason}"
    return repr(failed)


def _premise_prompt(*, family: dict[str, Any], worlds: Sequence[dict[str, Any]],
                    prebranch: Sequence[dict[str, Any]]) -> str:
    story = section_text({"base_story": family.get("base_story"),
                          "discriminator": family.get("discriminator")})
    shown = section_text([{k: w.get(k) for k in ("label", "axis", "facts")} for w in worlds])
    calls = section_text(_prebranch_section(prebranch))
    salt = message_salt(story, shown, calls)
    return (f"{_prompt('premise.md')}\n"
            + stage_user_message(
                salt,
                titled_section("The base story", story, salt=salt, tag=UNTRUSTED_TAG),
                titled_section("The worlds", shown, salt=salt, tag=UNTRUSTED_TAG),
                titled_section("The calls the run made before the branch point, with their "
                               "answers", calls, salt=salt, tag=UNTRUSTED_TAG)))


def _conflicts(check: Any, *, family: dict[str, Any], worlds: Sequence[dict[str, Any]],
               prebranch: Sequence[dict[str, Any]], agent_id: str) -> dict[str, list[dict]]:
    """The check's conflicts by world label. A call that cannot be answered raises: the caller
    keeps the family as authored (`author_family`)."""
    labels = {str(w.get("label")) for w in worlds}
    doc = _ask_typed(check, _premise_prompt(family=family, worlds=worlds, prebranch=prebranch),
               agent_id=agent_id, name="conflicts",
               description="Report the worlds whose facts the run's earlier answers contradict.",
               schema=_CHECK_SCHEMA, check=_premise_check)
    found: dict[str, list[dict]] = {}
    for entry in doc["conflicts"]:
        if isinstance(entry, dict) and str(entry.get("label")) in labels:
            found.setdefault(str(entry["label"]), []).append(
                {k: entry.get(k) for k in ("fact_id", "evidence")})
    return found


def _rebuilt(world: dict[str, Any], conflicts: list[dict], *, invoke: Any,  # noqa: PLR0913 — the world, its conflicts and what its seat was shown
             family_reply: Any, header: str, capture: _Capture) -> dict[str, Any] | None:
    """`world` as its seat rebuilds it against `conflicts`, or None when the rebuild fails: a
    reply the call cannot get right, or a host failure, drops this world alone."""
    seat = str(world.get("role"))
    try:
        authored = _ask_typed(
            invoke, _world_prompt(seat, axis=world.get("axis"), family_reply=family_reply,
                                  header=header, capture=capture, revision=conflicts),
            agent_id=f"questioner:{seat.lower()}:revise", name="revision",
            description="Return the seat's world rebuilt with facts the run's answers do not contradict.",
            schema=_REVISION_SCHEMA, check=_revision_check(world, seat))
    except Exception as failed:  # noqa: BLE001 — a rebuild that fails drops its world alone
        _logger.warning(f"seat {seat}'s revision failed ({_unusable_text(failed)}); its world is "
                        "dropped")
        return None
    return {**world, **authored}


def _still_conflicting(check: Any, rebuilt: dict[str, dict[str, Any]], *,
                       family: dict[str, Any],
                       prebranch: Sequence[dict[str, Any]]) -> dict[str, list[dict]]:
    """The second check over the rebuilt worlds. One that fails confirms none of them."""
    try:
        return _conflicts(check, family=family, worlds=list(rebuilt.values()),
                          prebranch=prebranch, agent_id="questioner:check:2")
    except Exception as failed:  # noqa: BLE001 — an unconfirmed rebuild is not kept
        _logger.warning(f"the premise re-check failed ({_unusable_text(failed)}); the rebuilt worlds are "
                        "dropped")
        return {label: [] for label in rebuilt}


def _held_to_history(  # noqa: C901, PLR0913 — one rule over each failure path; the worlds, the two seams and what the seats were shown
        worlds: list[dict[str, Any]], *, check: Any, invoke: Any, family: dict[str, Any],
        family_reply: Any, header: str, capture: _Capture,
        prebranch: Sequence[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict]]:
    """#1561: the authored worlds checked against the run's pre-branch answers, settled world by
    world under one rule: a world the check never named is kept as authored; a named world is
    kept only once its seat's rebuild passed the second check; anything else drops it. So a
    failure anywhere (no evidence, a first check that faults or cannot be read, a rebuild or a
    second check that does) never refuses the family and never keeps a world found false.
    Returns the worlds kept and the record of each world the check named."""
    if not prebranch:
        return worlds, []
    try:
        conflicts = _conflicts(check, family=family, worlds=worlds, prebranch=prebranch,
                               agent_id="questioner:check")
    except Exception as failed:  # noqa: BLE001 — a check that fails names no world
        _logger.warning(f"the premise check failed ({_unusable_text(failed)}); no world is named")
        return worlds, []
    record: dict[str, dict] = {}
    rebuilt: dict[str, dict[str, Any]] = {}
    for world in worlds:
        label = str(world.get("label"))
        if label not in conflicts:
            continue
        record[label] = {"label": label, "conflicts": conflicts[label], "revised": False,
                         "dropped": True, "original_facts": world.get("facts")}
        world_rebuilt = _rebuilt(world, conflicts[label], invoke=invoke,
                                 family_reply=family_reply, header=header, capture=capture)
        if world_rebuilt is not None:
            record[label]["revised"] = True
            rebuilt[label] = world_rebuilt
    if rebuilt:
        still = _still_conflicting(check, rebuilt, family=family, prebranch=prebranch)
        for label in rebuilt:
            if label in still:
                record[label]["conflicts_after"] = still[label]
            else:
                record[label]["dropped"] = False
    out: list[dict[str, Any]] = []
    for world in worlds:
        label = str(world.get("label"))
        if label not in record:
            out.append(world)
        elif not record[label]["dropped"]:
            out.append(rebuilt[label])
    return out, list(record.values())


def _planned_worlds(family: dict[str, Any]) -> list[dict[str, Any]]:
    """The worlds Call 1 planned, in order (its check has accepted them: labels, axes and facts,
    each entry closed). Each seat call then writes one world's story; the fan-out is as wide as
    the plan."""
    return [dict(entry) for entry in family["worlds"]]


def _seat_letter(index: int) -> str:
    """The role letter for the `index`-th non-base seat: B, then C, then onward.

    Assigned, never taken from a reply, so two seats can never share a role.
    """
    return WORLD_SEATS[index] if index < len(WORLD_SEATS) else chr(ord("B") + index)


def _call_or_refuse_episode(what: str, invoke: Any, prompt: str, **spec: Any) -> dict[str, Any]:
    """A call the family cannot be composed without: one that cannot be answered refuses the
    episode, naming the call and the last reason."""
    try:
        return _ask_typed(invoke, prompt, **spec)
    except ReplyUnusable as unusable:
        raise BranchError(
            f"{what}: the questioner's reply was unusable after {unusable.requests} requests: "
            f"{unusable.reason}") from unusable


def author_family(  # noqa: PLR0913 — one keyword per captured input plus `lessons`; the caller resolves every optional at the boundary, so splitting this would re-coalesce them elsewhere
    *,
    source_run_dir: Path,
    episode_dir: Path,
    invoke: Any,
    leads: Any,
    alert: Any,
    frontier: str,
    served_systems: Sequence[str] = (),
    samples: Any = None,
    lessons: Any = None,
    source_disposition: str | None = None,
    premise_check: Any = None,
    prebranch: Sequence[dict[str, Any]] = (),
    record_revisions: Any = None,
) -> dict[str, Any]:
    """Author one family document: one family call plus one call per planned world.
    `source_disposition` is the source run's committed disposition (its closing record), or
    `None` when it never closed.

    With `premise_check` (a seam like `invoke`), the worlds are then held to `prebranch`, the
    source run's pre-branch calls with their recorded answers (#1561): a world contradicting them
    is revised once by its seat or dropped, and `record_revisions(entries)` is handed what was."""
    served = list(dict.fromkeys(served_systems))
    header = _measurement_header(Path(source_run_dir), Path(episode_dir), served)
    # Rendered once for all calls; framing is per call because the salt is.
    capture = _capture_sections(leads=leads, alert=alert, frontier=frontier, samples=samples,
                                lessons=lessons, served_systems=served)
    family = _call_or_refuse_episode(
        "call 1 (the base story and discriminator)", invoke, _family_prompt(header, capture),
        agent_id="questioner", name="plan",
        description="Return the base story, base disposition, discriminator and planned worlds.",
        schema=_PLAN_SCHEMA, check=_plan_check(source_disposition))
    # The seats are shown call 1's accepted document, rendered as JSON.
    family_reply = family

    worlds: list[dict[str, Any]] = [_base_world(family, source_disposition)]
    for seat_index, plan in enumerate(_planned_worlds(family)):
        seat = _seat_letter(seat_index)
        authored = _call_or_refuse_episode(
            f"the call authoring seat {seat}", invoke,
            _world_prompt(seat, axis=plan.get("axis"), family_reply=family_reply, header=header,
                          capture=capture),
            agent_id=f"questioner:{seat.lower()}", name="world",
            description="Return this seat's story, axis, declared disposition and label basis.",
            schema=_SEAT_SCHEMA, check=_seat_check(plan, seat))
        # Plan underneath, the seat's fields on top (its `axis` supersedes the planned one),
        # role last.
        worlds.append({**plan, **authored, "role": seat})

    if premise_check is not None:
        kept, revisions = _held_to_history(
            worlds[1:], check=premise_check, invoke=invoke, family=family,
            family_reply=family_reply, header=header, capture=capture, prebranch=prebranch)
        worlds = [worlds[0], *kept]
        if record_revisions is not None:
            record_revisions(revisions)

    return {
        "base_story": family.get("base_story"),
        "discriminator": family.get("discriminator"),
        "worlds": worlds,
    }


__all__ = [
    "BASE_WORLD_LABEL",
    "BASE_WORLD_ROLE",
    "QUESTIONER_DEF",
    "QUESTIONER_REPLY_RETRIES",
    "QuestionerDeps",
    "UNTRUSTED_TAG",
    "SEAT_AUTHORED_FIELDS",
    "WORLD_SEATS",
    "author_family",
    "questioner_effort",
    "questioner_model",
    "read_frontier",
]
