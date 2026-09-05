"""The QUESTIONER: a deny-all role that authors one family of sibling worlds (#947 M1/O1).

WHAT THIS IS. An operator names a finished run and a branch point; three sibling worlds are
then run from that point. This module owns the authoring half — the three model calls that turn
the captured past into a `family.yaml` the launcher validates, stages and runs. It owns nothing
else: it opens no cluster, spawns no process and writes no manifest.

WHY THE ROLE GRANTS NOTHING. `QUESTIONER_DEF` is modelled on `ORACLE_DEF`
(`learning/pipeline/oracle_engine.py`): `tools=ToolSet()`, no `bash_shapes`, no `write_shapes`,
no `verb_grant`. Every one of those is an OMISSION rather than an empty grant line, and that is
deliberate — `AgentDefinition`'s defaults are deny-all, so a questioner that could reach
anything would have to have a grant ADDED to it in this file, in a diff, where a reviewer sees
it. A definition that spelled its own empty grants would make the same widening a one-word
edit. The role needs nothing: its whole input is inlined in the user prompt by the host, and
its whole output is one YAML document.

WHY THE HOST FANS OUT, NOT THE MODEL. Three calls, host-orchestrated, exactly as the oracle's
per-lead fan-out is (`pipeline/oracle/run.py`). A "diff tool" the model could call would be a
new capability class inside a deny-all role (design N9); the seat structure — one family call,
then one call per authored world — is a property of the experiment, so the host owns it.

WHY THREE CALLS SHARE ONE ROLE KEY. `agent_role.py` states the rule: nothing about a call's
identity is keyed on the role. A second role key would buy a second compiled policy over the
same (empty) grant and a second place for the two to drift apart. What separates the calls is
the `agent_id` they carry — `questioner`, `questioner:b`, `questioner:c` — which is what the
wire log and the per-id trace partition on, so a duplicate id would silently overwrite a call's
trace rather than fail.

WHY EVERY INPUT IS WRAPPED, INCLUDING OUR OWN OUTPUT. The questioner's entire input is the
CAPTURED PAST: joined leads, an alert and an investigation document, all written in a run dir
that was a box's rw bind, all reachable by whoever the investigation was about. So each reaches
the prompt inside an untrusted frame, and Call 1's own reply is re-wrapped before it seeds
Calls 2 and 3 — taint does not stop being taint because a model has restated it. A payload that
steered the base story must not reach the world-authoring calls as trusted framing.

THROUGH `learning._prompt.stage_user_message`, like every other stage that assembles a model
message, and that is a correction rather than a flourish. Assembled by f-string this role — the
one role whose ENTIRE input is attacker-reachable capture — was the only one whose message
carried no reader contract, so nothing in the prompt said that only run-salted frames delimit
sections or that a heading inside a frame is data. The gate that watches for exactly this
(`scripts/lint/lint_stage_prompt_frames.py`) inspects the ARGUMENTS to `stage_user_message`, so
a stage that never calls it is a stage the gate cannot see; the frames below are spelled at the
call literally, not splatted from a list, so they are arguments the gate reads.

ONE SALT PER CALL, minted after the bodies are in hand and re-minted while it occurs in any of
them (`_untrusted.message_salt`). Per call and not per family, because Call 1's reply is framed
into Calls 2 and 3: a salt Call 1's model had already seen would be a delimiter the framed
party holds, which is #875 F-1 exactly. Shared across one message's sections, because that is
what makes the contract's "matching run-salted frame tags in this message" true of a SET.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import yaml

from defender import _yaml
from defender._env import env_str
from defender._io import read_guarded
from defender._report import REPORT_NAME, read_report
from defender._run_paths import artifact_file
from defender._untrusted import message_salt, wrap
from defender.learning._prompt import stage_user_message, titled_section
from defender.learning.core.validate import strip_yaml_fence
from defender.runtime.agent_definition import AgentDefinition, ToolSet
from defender.runtime.agent_role import AgentRole
from defender.runtime.branch import BranchError
from defender.skills.invlang.parser import scan_fences

#: One model call per seat, and never a retry loop inside one: a questioner that could ask
#: again on its own would spend the operator's money without an operator in the room.
QUESTIONER_REQUEST_LIMIT = 1

#: The untrusted frame tag every captured artifact this role sees is wrapped in.
UNTRUSTED_TAG = "untrusted"

#: The seats, in the order the family lists them. The ROLE letter is a property of the seat,
#: not of what the model returned in it: a family whose worlds are told apart by their roles is
#: only readable if the roles are distinct, and a model asked to name its own role can hand
#: back two `B`s. The launcher's `parse_family` refuses that; assigning by seat means it never
#: has to.
WORLD_SEATS: tuple[str, ...] = ("B", "C")

#: World A is not authored at all. It IS the capture: an empty overlay stages nothing, and a
#: null axis says so — there is no difference to declare, which is what makes it the control.
BASE_WORLD_ID = "a"
BASE_WORLD_ROLE = "A"

_PROMPTS = Path(__file__).resolve().parent

_QUESTIONER_DENY_REASON = (
    "Blocked: the questioner is a pure authoring projection — its entire input is inlined in "
    "the user prompt by the host and its entire output is one YAML document. It runs no tools: "
    "no data-source adapters, no run-dir reads, no writes, no shell. Emit the document directly."
)


def questioner_model() -> str:
    """The questioner's model, read at CALL time so an env override reaches it.

    Lives here rather than in `learning/core/config.py` for the same reason the prompts do: the
    branch experiment is one package, and a stage's model thunk read at import would freeze
    before any test or operator could steer it (`config.py`'s own note on the frozen read)."""
    return env_str("QUESTIONER_MODEL", "kimi-k3")


def questioner_effort() -> str:
    return env_str("QUESTIONER_EFFORT", "medium")


@dataclass(frozen=True)
class QuestionerDeps:
    """Frozen, and carrying NOTHING but its role — zero fields, deliberately.

    A field here would be a channel: a run dir, a world label or a trajectory reachable from
    inside a deny-all call is exactly the state this role is defined not to have. `role` is a
    `ClassVar`, so it is not a field either; it is how the registry and the trace name the call.

    This is why it does NOT subclass `AgentDeps`, and the departure is the point rather than an
    oversight. `AgentDeps` IS the run scope — run dir, compiled policy, box executor, cwd
    anchor — so inheriting it would give the questioner exactly the eleven fields this class
    exists to not have, and every one of them is a handle on a tree the role may not touch.
    Nothing binds it: `bind(QUESTIONER_DEF, …)` refuses by name (`agent_definition.bind`), the
    way the curator's non-bindable definition already does, because there is no run for a role
    whose entire input is inlined in one prompt by the host."""

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
    """One shipped prompt, read from THIS package.

    The prompts live under `learning/branch/questioner/` and not under `learning/pipeline/`:
    the pipeline tree is on its way out (#922), and a prompt parked there would be deleted with
    a stage that has nothing to do with this one."""
    return (_PROMPTS / name).read_text(encoding="utf-8")


def _measurement_header(source_run_dir: Path, episode_dir: Path) -> str:
    """The two names this family is being authored FOR, as host text.

    Host text and not a frame: both are names the operator and the host chose (a runs-base
    entry and an episode directory), so neither is attacker-influenced the way the artifacts
    INSIDE those directories are. They are in the prompt because a questioner that could not
    say which run and which episode it is authoring for cannot say so in the story either, and
    the story is what a later reader uses to tell one episode's worlds from another's."""
    return (
        "## The measurement\n\n"
        f"This family is authored for episode `{episode_dir.name}`, "
        f"branching the finished run `{source_run_dir.name}`.\n"
    )


@dataclass(frozen=True)
class _Capture:
    """The three captured inputs as rendered SECTION BODIES, ready to be framed.

    Spelled once because every call gets all three: a world author that could not see the
    capture would be authoring against Call 1's summary of it, which is the one artifact in
    this fan-out that no human wrote. Rendered once because they are routinely hundreds of
    kilobytes and cannot vary between seats — but not FRAMED once, because a frame's salt
    belongs to the message it delimits and each call in the fan-out is a message of its own.
    """

    leads: str
    alert: str
    frontier: str


def _capture_sections(*, leads: Any, alert: Any, frontier: str) -> _Capture:
    """The three captured inputs, rendered."""
    return _Capture(
        leads=titled_section("The joined leads at the branch point", leads),
        alert=titled_section("The alert this investigation started from", alert),
        frontier=titled_section("The investigation document at the branch point", frontier),
    )


def _reply_document(reply: Any, *, what: str) -> dict[str, Any]:
    """One model reply as a mapping.

    Two shapes reach here and both are real. A driver that already parsed the reply hands back
    a dict, and it is taken as-is; a raw model hands back text, which is parsed as YAML (which
    subsumes JSON). Anything else — a list, a scalar, a `None` from an empty completion — is a
    refusal naming the call, because a questioner that returned no document must not be
    composed into a family that then reads as merely incomplete.
    """
    doc: Any = reply
    if isinstance(reply, str):
        try:
            # NORMALISED BEFORE PARSING, like every other reader of a model reply in this repo
            # (the judge's `validate_reply`, the oracle sampler, `learning/loop`). Both prompts
            # SHOW the required document inside a ```yaml fence, so a fenced reply is the model
            # doing what it was asked; parsing the raw text made `safe_load` refuse on the
            # backtick and abort the whole episode on call 1.
            doc = _yaml.safe_load(strip_yaml_fence(reply))
        except yaml.YAMLError as e:
            raise BranchError(f"{what}: the questioner's reply is not a YAML document: {e}") from e
    if not isinstance(doc, dict):
        raise BranchError(
            f"{what}: the questioner returned {type(doc).__name__}, not a document — "
            "the family cannot be composed from it"
        )
    return dict(doc)


def _captured_disposition(source_run_dir: Path) -> str | None:
    """The disposition the SOURCE RUN itself published, or `None` if it published none.

    World A is the capture, so the verdict it declares is the one the real investigation
    actually reached — and that is written down, in the source run's `report.md`, rather than
    something a model has to remember. This is the last of the three places to look precisely
    because it is the most authoritative: it is consulted when neither call-1 field named one.

    Read through `_report.read_report`, which owns what a report headline MEANS (its
    frontmatter split and the `normalized_disposition` vocabulary), and screened first with
    `artifact_file` for the same reason `read_frontier` screens: the source run dir is a prior
    box's rw bind, and `read_report` reaches the file through `is_file()`/`read_text_soft`,
    which follow a planted link. A report that cannot be read is not an error here — the two
    call-1 fields are the primary sources, and `parse_family` names the field if all three are
    silent."""
    report = Path(source_run_dir) / REPORT_NAME
    if not artifact_file(report):
        return None
    return read_report(report).disposition


def _declared_base_world(family: dict[str, Any]) -> dict[str, Any]:
    """The base world Call 1 declared, if it declared one.

    Call 1 is asked for the family half, and a model that has just written the base STORY often
    writes the base WORLD beside it. Taking that entry when it is there means the capture's
    declared disposition comes from the call that read the capture; the seat invariants are
    re-imposed on it either way."""
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

    A IS the capture, so there is nothing for a model to choose: its overlay is empty, its axis
    is the null sentinel that says it declares no difference, and its role is the base letter.
    Those are imposed here and never read back from a reply — they are what makes A the control,
    and a model that returned a non-empty overlay for it would have staged an edit into the
    world the other two are measured against.

    The declared DISPOSITION is not imposed, because it is a claim about a real investigation.
    Three places are asked, in this order, and every one of them is a place the answer was
    already written rather than one this module could invent:

    1. Call 1's `base_disposition` — the field the prompt asks for by name;
    2. the base-role entry in Call 1's own `worlds` list, when the reply carried one;
    3. the source run's published `report.md` headline — the verdict the investigation reached.

    If all three are silent the key is left ABSENT, so `parse_family` refuses naming
    `disposition_declared` rather than this module defaulting a verdict into the manifest."""
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
    """Call 1's whole message: the task, the names it authors for, then the framed capture.

    THE TASK AND THE HEADER STAY OUTSIDE THE FRAMES, and that is what the frames are for. Both
    are host text — a shipped prompt file and two directory names the operator and the host
    chose — and a message whose every byte sat inside a frame would be a message with no
    instruction in it. `stage_user_message` puts the reader contract at the head of the framed
    region, so what follows the contract is exactly the region it speaks about.
    """
    salt = message_salt(capture.leads, capture.alert, capture.frontier)
    return (
        f"{_prompt('family.md')}\n{header}\n"
        + stage_user_message(
            salt,
            wrap(capture.leads, UNTRUSTED_TAG, salt),
            wrap(capture.alert, UNTRUSTED_TAG, salt),
            wrap(capture.frontier, UNTRUSTED_TAG, salt),
        )
    )


def _world_prompt(seat: str, *, axis: Any, family_reply: Any, header: str,
                  capture: _Capture) -> str:
    """The prompt for one world-authoring seat.

    `family_reply` is re-wrapped here, and that is the point of the function: it is Call 1's
    OWN output, and Call 1 read attacker-influenced text. Handing it over as host framing would
    let a payload that steered the base story instruct the two calls that decide what gets
    staged and run.

    AND IN THIS MESSAGE'S OWN SALT, which is minted below and which Call 1's model has never
    seen — the reply was already in hand when it was minted. A family-wide salt would hand the
    framed party the delimiter of the frame its own words arrive in."""
    seeded = titled_section(f"Call 1's output (seat {seat} authors against this)", family_reply)
    salt = message_salt(seeded, capture.leads, capture.alert, capture.frontier)
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
        )
    )


def read_frontier(source_run_dir: Path, *, fences_at: int) -> str:
    """The source run's investigation document as it stood after `fences_at` invlang fences.

    SCREENED FIRST, and that is the whole reason this function exists rather than a `read_text`
    at the call site. `source_run_dir` is a prior box's rw bind: every artifact in it was
    written by a model, and an entry there may be a symlink that model planted. The shipped
    readers of this same file (`_frontier.frontier_at_branch`, `_seed.seed_investigation`) go
    through `read_text_soft`, which FOLLOWS a link — so a link planted at `investigation.md`
    hands the target's bytes to whoever reads it, and here that is a model prompt. `artifact_file`
    is the repo's `lstat`-ing regular-file screen: it judges the ENTRY, not what it points at,
    and a link fails it.

    The refusal names the file, not the resolved target: the operator needs to know which
    artifact of theirs is not what it claims to be, and naming the target would print whatever
    path the planter chose.

    WHAT IT RETURNS is the invlang PREFIX — the fenced content as of the branch point — rather
    than a rendering of the derived `Frontier` struct. The prefix is what the investigation
    itself is written in, so the questioner reads the same text the investigator wrote; a prose
    rendering of the open slots would be a second projection of invlang that could disagree with
    `skills/invlang` about what the document says.
    """
    document = Path(source_run_dir) / "investigation.md"
    # `read_guarded`, not `artifact_file` then `read_text`. The lstat-then-read pair is a
    # check-then-act window on a path in a prior box's rw bind: the entry can be replaced
    # between the two, and the bytes that then reach this prompt are the link target's.
    # `read_guarded` asks plainness of the OPEN DESCRIPTOR, so there is no window — which is
    # exactly why `_seed.seed_investigation` was moved onto it for this same file in this same
    # tree, and it is the seam `defender/CLAUDE.md` names for reads out of a box-writable tree.
    text, refusal = read_guarded(document)
    if text is None:
        raise BranchError(
            f"{document}: investigation.md is not a regular file ({refusal}) — the source run "
            "dir is a box's rw bind, so an entry there that is not what it claims to be was "
            "planted; refusing to read it into a prompt"
        )
    bodies = scan_fences(text).bodies
    kept = bodies[:max(0, fences_at)]
    return "\n\n".join(f"```invlang\n{body}\n```" for body in kept)


#: The fields a SEAT authors. Everything else about a world — which world it is and what its
#: difference IS — is the family's plan, declared by Call 1, because the plan has to be coherent
#: ACROSS the worlds: two seats each choosing their own id, or each staging their own corpus,
#: compose into a family whose arms are not a comparison of anything. A seat elaborates; it does
#: not re-plan.
SEAT_AUTHORED_FIELDS: frozenset[str] = frozenset({"story", "axis", "disposition_declared",
                                                  "label_basis"})


def _planned_worlds(family: dict[str, Any]) -> list[dict[str, Any]]:
    """The non-base worlds Call 1 planned, in the order it planned them.

    THE PLAN IS CALL 1'S, and that is what makes the fan-out a fan-out. Call 1 reads the capture
    once and decides which differences are worth authoring — the ids, the axes and the overlays
    that will actually be staged; calls 2 and 3 then write one world's STORY each, against that
    plan and against the same capture. A family whose overlays were each chosen by a call that
    had not seen its sibling's would be a set of unrelated worlds rather than a triplet with a
    discriminator, and it is the discriminator that makes the comparison mean anything.

    THE COUNT COMES FROM HERE TOO. A family the plan declares with one non-base world costs one
    seat call, not two — the fan-out is as wide as the plan, so a plan the launcher then refuses
    is refused after one call rather than after a fixed three.
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

    ASSIGNED, never taken from a reply. A role is the world's NAME in every report and in the
    identity gate's distinctness rule, so a model that returned the same letter for two seats
    would compose a family whose arms cannot be told apart — and it would do so silently, since
    each reply is honest on its own. The seat is a fact about the fan-out, which is the
    launcher's, so the launcher's side of the seam sets it.
    """
    return WORLD_SEATS[index] if index < len(WORLD_SEATS) else chr(ord("B") + index)


def author_family(
    *,
    source_run_dir: Path,
    episode_dir: Path,
    invoke: Any,
    leads: Any,
    alert: Any,
    frontier: str,
) -> dict[str, Any]:
    """Author one family document: three model calls, one role key, three identities.

    Returns the RAW composed dict rather than a parsed `Family`. Validation belongs to the
    launcher, which calls `runtime.branch._family.parse_family` on the document it is about to
    write — one validator, at the boundary where the refusal can name the field and abort the
    episode before anything is staged or paid for. A second validation here would be a second
    opinion about what a family IS.

    `source_run_dir` and `episode_dir` are NAMED, never read: only their names reach the prompt
    (`_measurement_header`), because a caller that could not say which run and which episode a
    family was authored for could compose one for the wrong episode. The captured inputs
    themselves arrive already read (`leads`, `alert`, `frontier`) — the host owns every read of a
    model-writable tree; see `read_frontier` for what such a read has to do.

    The composition is fixed here and nowhere else: base world A, then the two authored worlds
    in seat order, their roles assigned BY SEAT. The family-level fields come from Call 1. The
    launcher supplies the derived half (`episode_id`, `source_run_dir`, `source_run_id`,
    `branch_message_id`, `fences_at`, `as_of`) and the operator's `continuation_prompt`, because
    those are facts about the measurement rather than anything a model may choose.
    """
    header = _measurement_header(Path(source_run_dir), Path(episode_dir))
    # RENDERED ONCE, ABOVE THE FAN-OUT. Every call in this function is handed the same capture
    # — the joined leads, the alert and the whole frontier, routinely hundreds of kilobytes —
    # and spelled inside the seat loop it was rebuilt per seat for a value that cannot vary
    # between them. The FRAMING is per call, because the salt is (see `_world_prompt`).
    capture = _capture_sections(leads=leads, alert=alert, frontier=frontier)
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
        # THE PLAN UNDERNEATH, THE SEAT'S OWN FIELDS ON TOP, THE ROLE IMPOSED LAST. Written the
        # other way round — the seat's whole document with the plan as a fallback — a seat that
        # echoed the prompt's example overlay back would silently stage a difference the family
        # never planned, and the launcher would review a world nobody authored.
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
