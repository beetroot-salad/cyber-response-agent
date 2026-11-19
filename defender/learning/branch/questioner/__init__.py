"""The questioner: a deny-all role that authors one family of sibling worlds."""
from __future__ import annotations

from defender._model import model
from pathlib import Path
from collections.abc import Sequence
from typing import Any, ClassVar

import json
import logging

import yaml

from defender import _yaml
from defender.configuration import env_str
from defender._io import read_guarded, read_text_utf8
from defender.records.formats import FamilyError, parse_facts, read_report
from defender.records import RunPaths, artifact_file
from defender._untrusted import message_salt
from defender.learning._prompt import section_text, stage_user_message, titled_section
from defender.learning.core.validate import MalformedReply, reply_document_text
from defender.investigation.agent_definition import AgentDefinition, ToolSet
from defender._agent_role import AgentRole
from defender.investigation.branch import BranchError
from defender.skills.invlang.parser import scan_fences

_logger = logging.getLogger(__name__)

#: One model request per call. A reply whose text is not YAML is asked again as a new call
#: (#1579), bounded by `MALFORMED_REPLY_LIMIT` across the whole family, not by this limit.
QUESTIONER_REQUEST_LIMIT = 1

#: #1579: the unparsable replies one family authoring tolerates. Every questioner call of the
#: family (call 1, each seat, the premise check and re-check, each revision) counts on one breaker;
#: the reply that reaches this limit trips it, and an open breaker asks no further call. So a
#: family pays at most `MALFORMED_REPLY_LIMIT - 1` re-asks.
MALFORMED_REPLY_LIMIT = 3

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
    "the user prompt by the host and its entire output is one YAML document. It runs no tools: "
    "no data-source adapters, no run-dir reads, no writes, no shell. Emit the document directly "
    "— bare, not inside a code fence, with nothing before or after it."
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


class _ReplyUnparsable(BranchError):
    """A reply whose text is not YAML syntax: a random fault of free-form output, so asked
    again (#1579). An alias, a second document, a too-deep nesting or a non-mapping is refused
    as before."""


def _reply_document(reply: Any, *, what: str) -> dict[str, Any]:
    """One model reply as a mapping.

    Text is parsed as YAML, which refuses aliases. A dict (already parsed by the driver) is
    held to the same rule: one whose parts are shared or cyclic is refused, as an alias would
    have been, so the family is a tree whichever way the reply arrived. Anything else is a
    refusal naming the call, so a missing document never composes into a family that reads as
    merely incomplete.
    """
    doc: Any = reply
    if isinstance(reply, dict):
        try:
            _yaml.refuse_shared(reply)
        except yaml.YAMLError as e:
            raise BranchError(f"{what}: the questioner's reply is not a YAML document: {e}") from e
    elif isinstance(reply, str):
        # Exactly one document, bare or in one code fence (the judge's rule too). A reply with
        # two candidate documents is refused rather than guessed at. The launcher turns
        # `BranchError` into `LauncherRefused`.
        try:
            text = reply_document_text(reply)
        except MalformedReply as shape:
            raise BranchError(
                f"{what}: the questioner's reply is not one bare document: {shape}") from shape
        try:
            doc = _yaml.safe_load(text)
        except (yaml.scanner.ScannerError, yaml.parser.ParserError) as e:
            # Syntax only: an alias, a second document or a too-deep nesting is refused at once.
            raise _ReplyUnparsable(
                f"{what}: the questioner's reply is not a YAML document: {e}") from e
        except yaml.YAMLError as e:
            raise BranchError(f"{what}: the questioner's reply is not a YAML document: {e}") from e
    if not isinstance(doc, dict):
        raise BranchError(
            f"{what}: the questioner returned {type(doc).__name__}, not a document — "
            "the family cannot be composed from it"
        )
    worlds = doc.get("worlds")
    if "world_id" in doc or (isinstance(worlds, list) and any(
            isinstance(world, dict) and "world_id" in world for world in worlds)):
        raise BranchError(f"{what}: world_id is host-assigned; author descriptive fields only")
    return dict(doc)


class _Breaker:
    """#1579: one family authoring's count of unparsable replies, over every questioner call."""

    def __init__(self, limit: int = MALFORMED_REPLY_LIMIT) -> None:
        self.limit = limit
        self.failures = 0

    def asker(self, seam: Any) -> Any:
        """`seam` (`invoke` or `premise_check`) as `ask(prompt, *, agent_id, what) -> document`."""
        def ask(prompt: str, *, agent_id: str, what: str) -> dict[str, Any]:
            return self.ask_raw(seam, prompt, agent_id=agent_id, what=what)[1]
        return ask

    def ask_raw(self, seam: Any, prompt: str, *, agent_id: str,
                what: str) -> tuple[Any, dict[str, Any]]:
        """The reply that parsed, as the model gave it, and its document."""
        attempt = 0
        while True:
            if self.failures >= self.limit:
                raise BranchError(
                    f"{what}: not asked: {self.failures} questioner replies of this family did "
                    "not parse, and the breaker is open")
            # A re-ask is its own call, with an id no first ask has (`questioner:check:2` is
            # the re-check's): calls sharing an id overwrite each other's trace.
            reply = seam(prompt if attempt == 0 else f"{prompt}\n{_prompt('retry.md')}",
                         role=AgentRole.QUESTIONER,
                         agent_id=agent_id if attempt == 0 else f"{agent_id}:retry{attempt}")
            try:
                return reply, _reply_document(reply, what=what)
            except _ReplyUnparsable as unparsable:
                self.failures += 1
                attempt += 1
                if self.failures >= self.limit:
                    raise BranchError(
                        f"{unparsable} (reply {self.failures} of this family that did not "
                        "parse: the breaker is open)") from unparsable.__cause__
                _logger.warning(f"{what}: the reply did not parse ({self.failures} of "
                                f"{self.limit}); asked again")


def _captured_disposition(source_run_dir: Path) -> str | None:
    """The disposition the source run itself published in `report.md`, or `None`.

    Screened with `artifact_file` first: the source run dir is a prior box's rw bind, and
    `read_report` follows symlinks. An unreadable report is not an error here; `parse_family`
    names the field if no source supplies it."""
    report = RunPaths(source_run_dir).report
    if not artifact_file(report):
        return None
    return read_report(report).disposition


def _declared_base_world(family: dict[str, Any]) -> dict[str, Any]:
    """The base world Call 1 declared, if it declared one (seat invariants are re-imposed)."""
    worlds = family.get("worlds")
    if not isinstance(worlds, list):
        return {}
    for entry in worlds:
        if not isinstance(entry, dict):
            continue
        if entry.get("role") == BASE_WORLD_ROLE or entry.get("label") == BASE_WORLD_LABEL:
            return dict(entry)
    return {}


def _base_world(family: dict[str, Any], source_run_dir: Path) -> dict[str, Any]:
    """World A, composed rather than authored by a call of its own.

    No facts, a null axis and the base role are imposed, never read from a reply: they make A
    the control, and a fact would change the world the others are measured against.

    The declared disposition is taken from, in order: Call 1's `base_disposition`, the base
    entry in Call 1's `worlds`, the source run's `report.md`. If all are silent the key is left
    absent so `parse_family` refuses rather than a verdict being defaulted."""
    world: dict[str, Any] = _declared_base_world(family)
    declared = (
        family.get("base_disposition")
        or world.get("disposition_declared")
        or _captured_disposition(source_run_dir)
    )
    if declared is not None:
        world["disposition_declared"] = declared
    elif "disposition_declared" in world:
        del world["disposition_declared"]
    if "label_basis" not in world and "base_label_basis" in family:
        world["label_basis"] = family["base_label_basis"]
    world.setdefault("story", family.get("base_story"))
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
    """The check's conflicts by world label. A reply the host cannot read raises: the caller
    keeps the family as authored (`author_family`)."""
    labels = {str(w.get("label")) for w in worlds}
    doc = check(_premise_prompt(family=family, worlds=worlds, prebranch=prebranch),
                agent_id=agent_id, what="the premise check")
    found: dict[str, list[dict]] = {}
    for entry in doc.get("conflicts") or ():
        if isinstance(entry, dict) and str(entry.get("label")) in labels:
            found.setdefault(str(entry["label"]), []).append(
                {k: entry.get(k) for k in ("fact_id", "evidence")})
    return found


def _revised_facts(authored: dict[str, Any], *, seat: str) -> list[dict[str, Any]] | None:
    """A revision's facts, held to the family's own rule for a world's facts (`parse_facts`),
    or None: a revision whose facts would not parse drops its world, never the family."""
    facts = authored.get("facts")
    if not (isinstance(facts, list) and facts):
        return None
    try:
        parse_facts(facts, f"the revision of seat {seat}")
    except FamilyError as refused:
        _logger.warning(f"seat {seat}'s revised facts are refused ({refused}); its world is "
                        "dropped")
        return None
    return [dict(f) for f in facts]


def _rebuilt(world: dict[str, Any], conflicts: list[dict], *, invoke: Any,  # noqa: PLR0913 — the world, its conflicts and what its seat was shown
             family_reply: Any, header: str, capture: _Capture) -> dict[str, Any] | None:
    """`world` as its seat rebuilds it against `conflicts`, or None when the rebuild fails or
    returns facts the family would refuse."""
    seat = str(world.get("role"))
    try:
        authored = invoke(_world_prompt(seat, axis=world.get("axis"), family_reply=family_reply,
                                        header=header, capture=capture, revision=conflicts),
                          agent_id=f"questioner:{seat.lower()}:revise",
                          what=f"the revision of seat {seat}")
    except Exception as failed:  # noqa: BLE001 — a rebuild that fails drops its world alone
        _logger.warning(f"seat {seat}'s revision failed ({failed!r}); its world is dropped")
        return None
    facts = _revised_facts(authored, seat=seat)
    if facts is None:
        return None
    return {**world, **{k: v for k, v in authored.items() if k in SEAT_AUTHORED_FIELDS},
            "facts": facts}


def _still_conflicting(check: Any, rebuilt: dict[str, dict[str, Any]], *,
                       family: dict[str, Any],
                       prebranch: Sequence[dict[str, Any]]) -> dict[str, list[dict]]:
    """The second check over the rebuilt worlds. One that fails confirms none of them."""
    try:
        return _conflicts(check, family=family, worlds=list(rebuilt.values()),
                          prebranch=prebranch, agent_id="questioner:check:2")
    except Exception as failed:  # noqa: BLE001 — an unconfirmed rebuild is not kept
        _logger.warning(f"the premise re-check failed ({failed!r}); the rebuilt worlds are "
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
        _logger.warning(f"the premise check failed ({failed!r}); no world is named")
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
    """The non-base worlds Call 1 planned, in order.

    Call 1 decides labels, axes and facts so the worlds form one comparison around a
    discriminator; each seat call then writes one world's story. The fan-out is as wide as the
    plan.
    """
    worlds = family.get("worlds")
    if not isinstance(worlds, list):
        return []
    return [dict(entry) for entry in worlds
            if isinstance(entry, dict)
            and entry.get("role") != BASE_WORLD_ROLE
            and entry.get("label") != BASE_WORLD_LABEL]


def _seat_letter(index: int) -> str:
    """The role letter for the `index`-th non-base seat: B, then C, then onward.

    Assigned, never taken from a reply, so two seats can never share a role.
    """
    return WORLD_SEATS[index] if index < len(WORLD_SEATS) else chr(ord("B") + index)


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
    premise_check: Any = None,
    prebranch: Sequence[dict[str, Any]] = (),
    record_revisions: Any = None,
) -> dict[str, Any]:
    """Author one family document: one family call plus one call per planned world, each
    asked again when its reply is not YAML, under one breaker for the whole family (#1579).

    With `premise_check` (a seam like `invoke`), the worlds are then held to `prebranch`, the
    source run's pre-branch calls with their recorded answers (#1561): a world contradicting them
    is revised once by its seat or dropped, and `record_revisions(entries)` is handed what was."""
    served = list(dict.fromkeys(served_systems))
    header = _measurement_header(Path(source_run_dir), Path(episode_dir), served)
    # Rendered once for all calls; framing is per call because the salt is.
    capture = _capture_sections(leads=leads, alert=alert, frontier=frontier, samples=samples,
                                lessons=lessons, served_systems=served)
    breaker = _Breaker()
    ask = breaker.asker(invoke)
    # The reply as given, not its document: the seats are shown call 1's own text.
    family_reply, family = breaker.ask_raw(invoke, _family_prompt(header, capture),
                                           agent_id="questioner",
                                           what="call 1 (the base story and discriminator)")
    axes = family.get("axes")
    axes = list(axes) if isinstance(axes, list) else []

    planned = _planned_worlds(family) or [{} for _ in WORLD_SEATS]
    worlds: list[dict[str, Any]] = [_base_world(family, Path(source_run_dir))]
    for seat_index, plan in enumerate(planned):
        seat = _seat_letter(seat_index)
        authored = ask(
            _world_prompt(
                seat,
                axis=plan.get("axis") if plan.get("axis") is not None else (
                    axes[seat_index] if seat_index < len(axes) else None),
                family_reply=family_reply,
                header=header,
                capture=capture,
            ),
            agent_id=f"questioner:{seat.lower()}",
            what=f"the call authoring seat {seat}",
        )
        # Plan underneath, only seat-authored fields on top, role last: otherwise a seat that
        # echoed the prompt's example facts would assert a difference nobody planned.
        world = {**plan,
                 **{k: v for k, v in authored.items() if k in SEAT_AUTHORED_FIELDS},
                 "role": seat}
        worlds.append(world)

    if premise_check is not None:
        kept, revisions = _held_to_history(
            worlds[1:], check=breaker.asker(premise_check), invoke=ask, family=family,
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
    "QUESTIONER_REQUEST_LIMIT",
    "QuestionerDeps",
    "UNTRUSTED_TAG",
    "SEAT_AUTHORED_FIELDS",
    "WORLD_SEATS",
    "author_family",
    "questioner_effort",
    "questioner_model",
    "read_frontier",
]
