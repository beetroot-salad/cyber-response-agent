"""The questioner: a deny-all role that authors one family of sibling worlds.

An operator names a finished run and a branch point; sibling worlds are then run from that
point. This module owns the authoring half — the model calls that turn the captured past into a
`family.yaml` the launcher validates, stages and runs. It opens no cluster, spawns no process
and writes no manifest.

The role grants nothing, by omission: `tools=ToolSet()`, no `bash_shapes`, `write_shapes` or
`verb_grant`. `AgentDefinition`'s defaults are deny-all, so any widening has to add a grant in
this file where a reviewer sees it; spelled-out empty grants would make widening a one-word
edit. The role needs nothing: its input is inlined by the host and its output is one YAML
document.

The host, not the model, fans out (one family call, then one call per authored world): a tool
the model could call would be a new capability inside a deny-all role.

WHY THREE CALLS SHARE ONE ROLE KEY: the rule (`agent_role.py`) is one key per package, not per
grant. These calls and the comparator's are all branch-package machinery. They are told apart by
`agent_id` (`questioner`, `questioner:b`, `questioner:c`), which the wire log and per-id trace
partition on, so a duplicate id would silently overwrite a trace. Another package (e.g. the
family judge) holds its own key even with an equally empty policy, so a grant added here cannot
reach it.

Every input is wrapped in an untrusted frame, including Call 1's own reply before it seeds the
world calls: the capture (leads, alert, investigation document) was written in a box's rw bind
and is attacker-reachable, and a model restating it does not clean it.

Messages go through `learning._prompt.stage_user_message` so they carry the reader contract, and
the frames are passed literally so `scripts/lint/lint_stage_prompt_frames.py` can inspect them.

One salt per call (`_untrusted.message_salt`), not per family: Call 1's reply is framed into the
later calls, so a salt Call 1's model had seen would be a delimiter the framed party holds. One
salt is shared across a message's sections, so "matching frame tags in this message" holds for
the set.
"""
from __future__ import annotations

from defender._model import model
from pathlib import Path
from collections.abc import Sequence
from typing import Any, ClassVar

import json
import yaml

from defender import _yaml
from defender._env import env_str
from defender._io import read_guarded
from defender._report import read_report
from defender._run_paths import RunPaths, artifact_file
from defender._untrusted import message_salt, wrap
from defender.learning._prompt import stage_user_message, titled_section
from defender.learning.core.validate import MalformedReply, reply_document_text
from defender.runtime.agent_definition import AgentDefinition, ToolSet
from defender.runtime.agent_role import AgentRole
from defender.runtime.branch import BranchError
from defender.skills.invlang.parser import scan_fences

#: One model call per seat, no retries: a retry loop would spend money with no operator present.
QUESTIONER_REQUEST_LIMIT = 1

#: The untrusted frame tag every captured artifact this role sees is wrapped in.
UNTRUSTED_TAG = "untrusted"

#: The seats, in family order. The role letter is assigned by seat, not taken from the reply,
#: so roles are always distinct (a model could return two `B`s).
WORLD_SEATS: tuple[str, ...] = ("B", "C")

#: World A is not authored: it is the capture (empty overlay, null axis), which makes it the
#: control.
BASE_WORLD_ID = "a"
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
    return (_PROMPTS / name).read_text(encoding="utf-8")


def _measurement_header(source_run_dir: Path, episode_dir: Path,
                       stageable_patterns: Sequence[str] = ()) -> str:
    """The names this family is being authored for, as host text.

    Unframed because the operator and host chose these names (run, episode, configured
    patterns); none is attacker-influenced. The run and episode let the story identify which
    episode it belongs to.

    The stageable patterns are stated explicitly: `parse_family` refuses an overlay keyed on
    any other pattern, after all calls have been paid for, so the model must not guess.
    """
    stageable = ", ".join(f"`{p}`" for p in stageable_patterns)
    return (
        "## The measurement\n\n"
        f"This family is authored for episode `{episode_dir.name}`, "
        f"branching the finished run `{source_run_dir.name}`.\n"
        + (f"\nThe corpus half of an overlay may key ONLY these base patterns: {stageable}. "
           "Any other pattern names a corpus this episode cannot address, and the family is "
           "refused.\n" if stageable else "")
    )


def _corpus_section(samples: Any) -> str:
    """One real document per corpus, so the author can match field names and value shapes.

    Untrusted like the rest of the capture. A pattern whose queries all came back empty is
    listed with no document rather than omitted: "asked, and held nothing" distinguishes a dead
    corpus from a live one.
    """
    if not isinstance(samples, dict) or not samples:
        return ""
    lines: list[str] = []
    for pattern, document in samples.items():
        if document:
            lines.append(f"{pattern}:\n{json.dumps(document, indent=2, default=str)}")
        else:
            lines.append(f"{pattern}:\n(every query against this corpus returned no rows)")
    return titled_section(
        "One real document from each corpus this investigation queried — match these field "
        "names and value shapes when you author documents to inject",
        "\n\n".join(lines))


@model(frozen=True)
class _Capture:
    """The captured inputs as rendered section bodies, ready to be framed.

    Every call gets the capture itself, not just Call 1's summary of it. Rendered once (they are
    large and identical across seats) but framed per call, since each message has its own salt.
    """

    leads: str
    alert: str
    frontier: str
    corpora: str = ""
    lessons: str = ""


#: Cap on the questioner's own lessons in a prompt (same 20-row convention as the judge's).
_QUESTIONER_LESSONS_CAP = 20


def _questioner_lessons_section(lessons: Any, *, stageable_patterns: Sequence[str]) -> str:
    """Every candidate lesson path, read, screened and selected — the section body, or "".

    `lessons` is the launcher's unread glob of `defender/lessons-questioner/`. A lesson with a
    duplicated top-level frontmatter key is skipped (`safe_load` resolves repeats last-wins
    silently, which would let a model-authored value steer the `pattern` selector). A lesson
    whose `pattern` is not stageable in this episode is not selected. The cap applies after
    selection, so matching lessons are never crowded out.
    """
    if not lessons:
        return ""
    from defender._frontmatter import FrontmatterError, split_frontmatter
    from defender._io import TEXT_READ_ERRORS, read_text_utf8
    from defender._yaml import duplicate_top_level_key

    stageable = set(stageable_patterns)
    bodies: list[str] = []
    for path in lessons:
        try:
            text = read_text_utf8(Path(path))
        except TEXT_READ_ERRORS:
            continue
        try:
            fm, raw, body = split_frontmatter(text)
        except FrontmatterError:
            continue
        # The raw frontmatter only: on the whole file (markdown body included) the YAML parse
        # fails and `duplicate_top_level_key` returns `False`, so the guard would never fire.
        if duplicate_top_level_key(raw):
            continue
        # `isinstance` first: `pattern` is unchecked model-authored frontmatter, and an
        # unhashable value (`[logs-*]`) would raise `TypeError` on the set lookup, breaking
        # every later episode until the file is deleted.
        pattern = fm.get("pattern")
        if not isinstance(pattern, str) or pattern not in stageable:
            continue
        if body:
            bodies.append(body)
    if not bodies:
        return ""
    capped = bodies[:_QUESTIONER_LESSONS_CAP]
    return titled_section(
        "Pitfalls this questioner corpus recorded about worlds it authored before",
        "\n\n---\n\n".join(capped))


def _capture_sections(*, leads: Any, alert: Any, frontier: str,
                      corpus_samples: Any = None, lessons: Any = None,
                      stageable_patterns: Sequence[str] = ()) -> _Capture:
    return _Capture(
        leads=titled_section("The joined leads at the branch point", leads),
        alert=titled_section("The alert this investigation started from", alert),
        frontier=titled_section("The investigation document at the branch point", frontier),
        corpora=_corpus_section(corpus_samples),
        lessons=_questioner_lessons_section(lessons, stageable_patterns=stageable_patterns),
    )


def _reply_document(reply: Any, *, what: str) -> dict[str, Any]:
    """One model reply as a mapping.

    A dict (already parsed by the driver) is taken as-is; text is parsed as YAML. Anything else
    is a refusal naming the call, so a missing document never composes into a family that reads
    as merely incomplete.
    """
    doc: Any = reply
    if isinstance(reply, str):
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
        except yaml.YAMLError as e:
            raise BranchError(f"{what}: the questioner's reply is not a YAML document: {e}") from e
    if not isinstance(doc, dict):
        raise BranchError(
            f"{what}: the questioner returned {type(doc).__name__}, not a document — "
            "the family cannot be composed from it"
        )
    return dict(doc)


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
        if entry.get("role") == BASE_WORLD_ROLE or entry.get("world_id") == BASE_WORLD_ID:
            return dict(entry)
    return {}


def _base_world(family: dict[str, Any], source_run_dir: Path) -> dict[str, Any]:
    """World A, composed rather than authored by a call of its own.

    Empty overlay, null axis and the base role are imposed, never read from a reply: they make A
    the control, and a non-empty overlay would edit the world the others are measured against.

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
        "world_id": BASE_WORLD_ID,
        "role": BASE_WORLD_ROLE,
        "axis": None,
        "overlay": {},
    })
    return world


def _family_prompt(header: str, capture: _Capture) -> str:
    """Call 1's whole message: the task and header (host text, unframed), then the framed
    capture.
    """
    salt = message_salt(capture.leads, capture.alert, capture.frontier, capture.corpora,
                        capture.lessons)
    return (
        f"{_prompt('family.md')}\n{header}\n"
        + stage_user_message(
            salt,
            wrap(capture.leads, UNTRUSTED_TAG, salt),
            wrap(capture.alert, UNTRUSTED_TAG, salt),
            wrap(capture.frontier, UNTRUSTED_TAG, salt),
            *([wrap(capture.corpora, UNTRUSTED_TAG, salt)] if capture.corpora else []),
            # Lessons go to Call 1 only: it names the discriminator and base story, which is
            # what the lessons are about.
            *([wrap(capture.lessons, UNTRUSTED_TAG, salt)] if capture.lessons else []),
        )
    )


def _world_prompt(seat: str, *, axis: Any, family_reply: Any, header: str,
                  capture: _Capture) -> str:
    """The prompt for one world-authoring seat.

    `family_reply` is re-wrapped as untrusted (Call 1 read attacker-influenced text), in this
    message's own salt, minted after the reply exists so Call 1's model has never seen it."""
    seeded = titled_section(f"Call 1's output (seat {seat} authors against this)", family_reply)
    salt = message_salt(seeded, capture.leads, capture.alert, capture.frontier, capture.corpora)
    axis_line = f"Your axis, as call 1 named it: {axis}\n" if axis is not None else ""
    return (
        f"{_prompt('world.md')}\n"
        f"## Your seat\n\nYou are authoring the world in seat {seat}.\n{axis_line}\n"
        f"{header}\n"
        + stage_user_message(
            salt,
            wrap(seeded, UNTRUSTED_TAG, salt),
            wrap(capture.leads, UNTRUSTED_TAG, salt),
            wrap(capture.alert, UNTRUSTED_TAG, salt),
            wrap(capture.frontier, UNTRUSTED_TAG, salt),
            # The seat sees the corpora too: its story must match the fields and value shapes
            # of the staged documents.
            *([wrap(capture.corpora, UNTRUSTED_TAG, salt)] if capture.corpora else []),
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


#: The fields a seat authors. Everything else (world id, overlay) is Call 1's plan, which must be
#: coherent across worlds; a seat elaborates, it does not re-plan.
SEAT_AUTHORED_FIELDS: frozenset[str] = frozenset({"story", "axis", "disposition_declared",
                                                  "label_basis"})


def _planned_worlds(family: dict[str, Any]) -> list[dict[str, Any]]:
    """The non-base worlds Call 1 planned, in order.

    Call 1 decides ids, axes and overlays so the worlds form one comparison around a
    discriminator; each seat call then writes one world's story. The fan-out is as wide as the
    plan.
    """
    worlds = family.get("worlds")
    if not isinstance(worlds, list):
        return []
    return [dict(entry) for entry in worlds
            if isinstance(entry, dict)
            and entry.get("role") != BASE_WORLD_ROLE
            and entry.get("world_id") != BASE_WORLD_ID]


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
    stageable_patterns: Sequence[str] = (),
    corpus_samples: Any = None,
    lessons: Any = None,
) -> dict[str, Any]:
    """Author one family document: one family call plus one call per planned world.

    Returns the raw composed dict; the launcher validates it with `parse_family`, the single
    validator, before anything is staged.

    `source_run_dir` and `episode_dir` are only named in the prompt, never read. The captured
    inputs arrive already read: the host owns every read of a model-writable tree.

    Composition: base world A, then the authored worlds in seat order with roles assigned by
    seat. The launcher adds the measurement facts (`episode_id`, `source_run_dir`,
    `source_run_id`, `branch_message_id`, `fences_at`, `as_of`, `continuation_prompt`).

    `lessons` is the unread candidate list of questioner-corpus paths; they are screened and
    selected against `stageable_patterns` and reach Call 1 only.
    """
    header = _measurement_header(Path(source_run_dir), Path(episode_dir),
                                 stageable_patterns)
    # Rendered once for all calls; framing is per call because the salt is.
    capture = _capture_sections(leads=leads, alert=alert, frontier=frontier,
                                corpus_samples=corpus_samples, lessons=lessons,
                                stageable_patterns=stageable_patterns)
    family_reply = invoke(
        _family_prompt(header, capture),
        role=AgentRole.QUESTIONER,
        agent_id="questioner",
    )
    family = _reply_document(family_reply, what="call 1 (the base story and discriminator)")
    axes = family.get("axes")
    axes = list(axes) if isinstance(axes, list) else []

    planned = _planned_worlds(family) or [{} for _ in WORLD_SEATS]
    worlds: list[dict[str, Any]] = [_base_world(family, Path(source_run_dir))]
    for seat_index, plan in enumerate(planned):
        seat = _seat_letter(seat_index)
        reply = invoke(
            _world_prompt(
                seat,
                axis=plan.get("axis") if plan.get("axis") is not None else (
                    axes[seat_index] if seat_index < len(axes) else None),
                family_reply=family_reply,
                header=header,
                capture=capture,
            ),
            role=AgentRole.QUESTIONER,
            agent_id=f"questioner:{seat.lower()}",
        )
        authored = _reply_document(reply, what=f"the call authoring seat {seat}")
        # Plan underneath, only seat-authored fields on top, role last: otherwise a seat that
        # echoed the prompt's example overlay would stage a difference nobody planned.
        world = {**plan,
                 **{k: v for k, v in authored.items() if k in SEAT_AUTHORED_FIELDS},
                 "role": seat}
        worlds.append(world)

    return {
        "base_story": family.get("base_story"),
        "discriminator": family.get("discriminator"),
        "worlds": worlds,
    }


__all__ = [
    "BASE_WORLD_ID",
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
