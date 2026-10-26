"""The family manifest: the one document a sibling is told, and the schema that gates it."""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator, Mapping
from defender._model import model
from pathlib import Path
from typing import Any, cast

import yaml

from defender import _yaml
from defender.episodes._episode_handle import Episode
from defender.episodes._episode_paths import LAYOUT
from defender._io import Bound
from defender.records._run_id import episode_id_fault, mint_uuid, uuid_id_fault
from defender._shown import quoted
from defender.episodes._world_label import (
    RESERVED_WORLD_LABELS, is_reserved_world_label, reserved_label_fault, world_label_fault,
)
from defender._vocab import (
    DISPOSITION_ENUM,
    DISPOSITION_VALUES,
    HOST_ONLY_DISPOSITION,
    normalized_disposition,
)
from defender.records import RunId
from defender.runtime.verbs import SYSTEM_MAX_LEN, is_system_name

#: The base world's role: the control every other world is compared against. Exactly one world
#: claims it, and it declares `facts: []` — its oracle only serves a live-read base as the world
#: stood at the fork (#1255 D3), never a fact.
BASE_ROLE = "A"

#: The two bases a world's declared disposition may rest on; `policy-rule` is the default.
LABEL_BASES: frozenset[str] = frozenset({"policy-rule", "judgment"})

#: Bounds on a fact's model-authored parts. Every fact reaches an oracle and a verifier prompt
#: verbatim, so each is bounded where it is read rather than wherever it is next rendered.
STATEMENT_MAX_LEN = 4000
ENTITY_MAX_LEN = 256
ENTITIES_MAX = 64
FACT_ID_MAX_LEN = 64

#: Every top-level field the manifest declares. Unknown ones refuse. `source_run_dir` is no
#: longer written (#1105 PR 2, decision A): an old manifest carrying it still loads, and its
#: value is never read — the source is `source_run_id`, opened in the request's tenant's runs.
#: `continuation_prompt` likewise (#1255 D1, P4): an arm is told nothing on arrival, so an old
#: manifest's prompt loads and is never read.
_FAMILY_FIELDS = (
    "episode_id", "source_run_dir", "source_run_id", "branch_message_id", "fences_at",
    "as_of", "continuation_prompt", "served_systems", "base_story", "discriminator", "worlds",
)

#: Every field a world entry declares.
_WORLD_FIELDS = (
    "label", "world_id", "role", "story", "axis", "disposition_declared", "label_basis", "facts",
)

#: Every field a fact declares.
_FACT_FIELDS = ("fact_id", "statement", "entities")

#: The fields a manifest written before the oracle carries, by where they sit (sequence items
#: and `<<` merges collapsed). Their presence refuses the manifest, empty or null included:
#: such a manifest describes a world as a patch table and a staged corpus, and is not translated.
_PREDATING: dict[tuple[str, ...], str] = {
    ("worlds", "overlay"): "overlay",
    ("discriminator", "holding_system"): "discriminator.holding_system",
    ("discriminator", "envelope"): "discriminator.envelope",
    ("captured_patterns",): "captured_patterns",
    ("configured_patterns",): "configured_patterns",
}

#: The discriminator's two old fields, as words inside a discriminator written as text.
_PREDATING_IN_TEXT = re.compile(r"\b(holding_system|envelope)\b")


class FamilyError(Exception):
    """A manifest this design cannot honestly run.

    A fault about the document, never a corpus contradiction or an unreachable difference (those
    are about what the estate said).
    """


class ManifestPredatesOracle(FamilyError):
    """A manifest written before the oracle: it carries a field only the staging design had.

    Its own class so a reader that shows a refusal (the episode page) can tell an archive of
    the old design from a damaged manifest."""


# ---------------------------------------------------------------------------------------
# a manifest that predates the oracle
# ---------------------------------------------------------------------------------------


def _predating_fields(locations: Iterator[tuple[tuple[str, ...], str | None]]) -> list[str]:
    """The old fields among `locations` (`_yaml.written_locations`' shape), in first-seen order."""
    found: dict[str, None] = {}
    for path, scalar in locations:
        where = tuple(step for step in path if step not in (_yaml.ITEM, "<<"))
        if (name := _PREDATING.get(where)) is not None:
            found[name] = None
        elif where == ("discriminator",) and isinstance(scalar, str):
            for word in _PREDATING_IN_TEXT.findall(scalar):
                found[f"discriminator.{word}"] = None
    return list(found)


def _document_locations(doc: Any) -> Iterator[tuple[tuple[str, ...], str | None]]:
    """`_yaml.written_locations` over a document already in memory: every node's path and its
    text when it is a string. Iterative and identity-guarded, so a cyclic document ends."""
    stack: list[tuple[tuple[str, ...], Any]] = [((), doc)]
    seen: set[int] = set()
    while stack:
        path, node = stack.pop()
        yield path, node if isinstance(node, str) else None
        if isinstance(node, (dict, list)):
            if id(node) in seen:
                continue
            seen.add(id(node))
        if isinstance(node, dict):
            stack.extend(((*path, k if isinstance(k, str) else "?"), v) for k, v in node.items())
        elif isinstance(node, list):
            stack.extend(((*path, _yaml.ITEM), v) for v in node)


def _refuse_predating(fields: list[str]) -> None:
    if fields:
        raise ManifestPredatesOracle(
            f"the manifest predates the oracle: it carries {', '.join(fields)} — a world is now "
            "the natural-language `facts` it asserts and the family records its "
            "`served_systems`; a manifest written for staging and patching is not translated, "
            "so author the family again")


def refuse_predating_text(text: str) -> None:
    """Refuse manifest TEXT carrying any pre-oracle field, before it is loaded.

    Read off what the text writes, not what loading keeps: a repeated `discriminator:` would
    otherwise hide one carrying `holding_system`, and an aliased value would refuse the load
    for the alias before the old field was ever named. Checked first, so the reason a reader
    reports for an old manifest is always that it predates the oracle."""
    _refuse_predating(_predating_fields(_yaml.written_locations(text)))


# ---------------------------------------------------------------------------------------
# facts
# ---------------------------------------------------------------------------------------


@model(frozen=True)
class Fact:
    """One thing a world asserts about the estate, in words, and the entities it is about."""

    fact_id: str
    statement: str
    entities: tuple[str, ...]


def _not_text(value: Any) -> str:
    """How a refusal names a value that is not a string: YAML reads an unquoted `no`, `007` or
    `2026-05-25` as something other than its spelling."""
    return (f"{quoted(value)} (a {type(value).__name__}, not text — YAML reads an unquoted "
            "`no`, `007` or date as something other than its spelling; write it quoted)")


def _printable_fault(value: Any, *, bound: int) -> str | None:
    """Why `value` is not a bounded printable name, or `None`."""
    if not isinstance(value, str):
        return _not_text(value)
    if not value:
        return f"{quoted(value)}, which is empty"
    if len(value) > bound:
        return f"{quoted(value)}, which is over the {bound}-character bound"
    if not value.isprintable():
        return f"{quoted(value)}, which carries a control character"
    return None


def _parse_fact(raw: Any, at: str) -> Fact:
    """One fact, refused naming the field (and the entity) that failed."""
    if not isinstance(raw, dict):
        raise FamilyError(f"{at} must be a mapping of fact_id, statement and entities, got "
                          f"{type(raw).__name__}")
    unknown = [quoted(k) for k in raw if k not in _FACT_FIELDS]
    if unknown:
        raise FamilyError(f"{at} names unknown field(s) {', '.join(unknown)}")
    for name in _FACT_FIELDS:
        if name not in raw:
            raise FamilyError(f"{at} carries no {name}")
    fact_id = raw["fact_id"]
    if (why := _printable_fault(fact_id, bound=FACT_ID_MAX_LEN)) is not None:
        raise FamilyError(f"{at}.fact_id is {why}")
    return Fact(fact_id=fact_id, statement=_checked_statement(raw["statement"], at),
                entities=_checked_entities(raw["entities"], at))


def _checked_statement(statement: Any, at: str) -> str:
    if not isinstance(statement, str):
        raise FamilyError(f"{at}.statement is {_not_text(statement)}")
    # Length first, so a megabyte statement is refused without a scan.
    if len(statement) > STATEMENT_MAX_LEN:
        raise FamilyError(f"{at}.statement is {len(statement)} characters, over the "
                          f"{STATEMENT_MAX_LEN}-character bound")
    if not statement.strip():
        raise FamilyError(f"{at}.statement is blank — a fact is the sentence the world asserts")
    return statement


def _checked_entities(entities: Any, at: str) -> tuple[str, ...]:
    """A fact's entities: any printable non-blank names, bounded. Refused, never dropped, and
    the refusal names the entity — an entity is data everywhere and is never a path component."""
    if not isinstance(entities, list):
        raise FamilyError(f"{at}.entities must be a list of entity names, got "
                          f"{type(entities).__name__}")
    if not entities:
        raise FamilyError(f"{at}.entities is empty — a fact names the entities it is about")
    if len(entities) > ENTITIES_MAX:
        raise FamilyError(f"{at}.entities names {len(entities)} entities, over the "
                          f"{ENTITIES_MAX}-entity bound")
    for entity in entities:
        why = _printable_fault(entity, bound=ENTITY_MAX_LEN)
        if why is None and not entity.strip():
            # The judge matches an entity as a literal substring of a lead's params (#1234 M2):
            # a whitespace-only one would touch every lead.
            why = f"{quoted(entity)}, which is only whitespace"
        if why is not None:
            raise FamilyError(
                f"{at}.entities names {why} — an entity is any printable non-blank name up "
                f"to {ENTITY_MAX_LEN} characters")
    return tuple(entities)


def _parse_facts(raw: Any, at: str) -> tuple[Fact, ...]:
    """A world's facts: a list (the control world's is the explicit `[]`), fact_ids unique."""
    if raw is None:
        raise FamilyError(
            f"{at}.facts is absent or null — every world declares its facts, and the control "
            "world declares `facts: []`")
    if not isinstance(raw, list):
        raise FamilyError(f"{at}.facts must be a list of facts, got {type(raw).__name__}")
    facts: list[Fact] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw):
        fact = _parse_fact(entry, f"{at}.facts[{i}]")
        if fact.fact_id in seen:
            raise FamilyError(
                f"{at}.facts names fact_id {quoted(fact.fact_id)} twice — a fact_id is how a "
                "served row is attributed to its fact, so it is unique within a world")
        seen.add(fact.fact_id)
        facts.append(fact)
    return tuple(facts)


# ---------------------------------------------------------------------------------------
# the world
# ---------------------------------------------------------------------------------------


@model(frozen=True)
class World:
    """One sibling's declaration: what it is, what it asserts, and the facts that make it differ."""

    label: str
    world_id: str
    role: str | None
    story: str
    axis: str | None
    disposition_declared: str
    label_basis: str
    facts: tuple[Fact, ...]


def parse_world(raw: Any, *, where: str = "worlds") -> World:
    """Validate one world entry, naming the field that refused."""
    if not isinstance(raw, dict):
        raise FamilyError(f"{where} entry must be a mapping, got {type(raw).__name__}")
    label = raw.get("label")
    if (why := world_label_fault(label, at=where)) is not None:
        raise FamilyError(why)
    world_id = raw.get("world_id")
    if (why := uuid_id_fault(world_id, "world")) is not None:
        raise FamilyError(f"{where}[{quoted(label)}]: {why}")
    assert isinstance(label, str)
    assert isinstance(world_id, str)
    at = f"{where}[{quoted(label)}]"
    unknown = [quoted(k) for k in raw if k not in _WORLD_FIELDS]
    if unknown:
        raise FamilyError(f"{at} names unknown field(s) {', '.join(unknown)}")
    role = raw.get("role")
    if role is not None and (not isinstance(role, str) or not role):
        raise FamilyError(f"{at}.role must be a label or the null replicate sentinel")
    story = raw.get("story")
    if not isinstance(story, str):
        raise FamilyError(f"{at}.story must be a string")
    facts = _parse_facts(raw.get("facts"), at)
    if role == BASE_ROLE and facts:
        raise FamilyError(
            f"{at} is the control world (role {BASE_ROLE!r}) but declares facts — the control "
            "is served the base answers with no oracle, so it declares `facts: []`")
    return World(
        label=label, world_id=world_id, role=role, story=story,
        axis=_check_axis(raw.get("axis"), at, role),
        disposition_declared=_check_disposition(raw.get("disposition_declared"), at),
        label_basis=_check_label_basis(raw.get("label_basis"), at),
        facts=facts,
    )


def _check_axis(axis: Any, at: str, role: str | None) -> str | None:
    """The difference this world names, or null for none.

    The sentinel is null; an empty string on a non-base world would be a difference it cannot
    name, recorded as though it were comparable.
    """
    if axis is not None and not isinstance(axis, str):
        raise FamilyError(f"{at}.axis must be a string or null")
    if axis == "" and role != BASE_ROLE:
        raise FamilyError(
            f"{at}.axis is the empty string — the sentinel for 'no axis' is null, so an empty "
            "string is a world declaring a difference it cannot name")
    return axis


def _check_disposition(raw: Any, at: str) -> str:
    """The world's declared disposition, through `_vocab`'s own normalizer.

    Not a local membership test: the value is model-authored from attacker-influenced data, and
    `_vocab` owns what it means (including a zero-width strip a plain `in` would miss).

    This is an authoring surface — the questioner writes it and the judge grades the world's run
    against it — so the host-only member (`unresolved`), which the normalizer admits, is refused
    here. The message is model-facing and names what to declare instead.
    """
    disposition = normalized_disposition(raw)
    if disposition is None:
        raise FamilyError(
            f"{at}.disposition_declared is {raw!r}, outside the shipped disposition "
            f"vocabulary {sorted(DISPOSITION_ENUM)}")
    if disposition == HOST_ONLY_DISPOSITION:
        allowed = ", ".join(d for d in DISPOSITION_VALUES if d != HOST_ONLY_DISPOSITION)
        raise FamilyError(
            f"{at}.disposition_declared is {HOST_ONLY_DISPOSITION!r}, which the host records "
            f"when it terminates a run without a settled finding — a world may not declare it. "
            f"A world whose investigator should not be able to settle the case declares "
            f"`inconclusive`. Declare one of: {allowed}.")
    return disposition


def _check_label_basis(raw: Any, at: str) -> str:
    """What the declared disposition rests on; omitted means the weaker `policy-rule` claim."""
    # Type first: the membership test hashes the value, and a model-authored `{...}` or `[...]`
    # would raise `TypeError` instead of the `FamilyError` a sibling's `run.py` catches.
    basis = "policy-rule" if raw is None else raw
    if not isinstance(basis, str) or basis not in LABEL_BASES:
        raise FamilyError(f"{at}.label_basis is {basis!r}, outside {sorted(LABEL_BASES)}")
    return basis


# ---------------------------------------------------------------------------------------
# the family
# ---------------------------------------------------------------------------------------


@model(frozen=True)
class Family:
    """The whole manifest, loaded."""

    episode_id: str
    source_run_id: str
    branch_message_id: int
    fences_at: int
    as_of: dt.datetime
    #: The systems the tenant's gather grant served when the launcher authored the family,
    #: recorded so no later reader resolves a tenant. The live grant still governs every query.
    served_systems: tuple[str, ...]
    base_story: str
    #: The discriminator's text, `{"predicate": ...}`.
    discriminator: dict
    worlds: list[World]

    def world(self, label: str) -> World:
        for candidate in self.worlds:
            if candidate.label == label:
                return candidate
        raise FamilyError(
            f"the manifest declares no world {quoted(label)}; it declares "
            f"{[w.label for w in self.worlds]}")

    def world_by_id(self, world_id: str) -> World:
        for world in self.worlds:
            if world.world_id == world_id:
                return world
        raise FamilyError(f"world UUID {quoted(world_id)} is not declared by this manifest")


def parse_as_of(raw: Any, *, where: str = "as_of") -> dt.datetime:
    """T0, as an aware UTC moment, or the fault that says why it is not one.

    A naive or non-UTC moment would skew every timestamp a sibling mints by a consistent amount
    nothing downstream can see.
    """
    if isinstance(raw, dt.datetime):
        moment = raw
    elif isinstance(raw, str):
        try:
            # lint-parse: ok — `_clock.parse_iso_utc` reads a naive value as UTC; this seam must
            # see naivety so it can refuse it below.
            moment = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as bad:
            raise FamilyError(f"{where} {raw!r} is not an ISO-8601 moment: {bad}") from bad
    else:
        raise FamilyError(f"{where} must be an ISO-8601 UTC moment, got {raw!r}")
    if moment.tzinfo is None:
        raise FamilyError(
            f"{where} {raw!r} is naive — a moment with no zone names no instant, and every "
            "timestamp a sibling mints from it would be the afternoon it executed")
    if moment.utcoffset() != dt.timedelta(0):
        raise FamilyError(
            f"{where} {raw!r} is not UTC (offset {moment.utcoffset()!r}) — a non-UTC moment "
            "formats a trailing `Z` that lies by exactly that offset")
    return moment


def _check_scalars(doc: dict) -> None:
    """Every manifest field whose only rule is its own type."""
    for scalar in ("episode_id", "source_run_id", "base_story"):
        if not isinstance(doc.get(scalar), str) or not doc.get(scalar):
            raise FamilyError(f"the manifest's {scalar} must be a non-empty string")
    for number in ("branch_message_id", "fences_at"):
        value = doc.get(number)
        if not isinstance(value, int) or isinstance(value, bool):
            raise FamilyError(f"the manifest's {number} must be an integer")


def _parse_served_systems(raw: Any) -> tuple[str, ...]:
    """The recorded served systems: text system names, de-duplicated in order.

    Shape only: the launcher records the grant's own systems, and the live grant still decides
    every query. A name is text in the roster's alphabet because each keys a samples section, a
    judge prompt section and a lesson's selection, and is compared exactly."""
    if not isinstance(raw, list):
        raise FamilyError(
            f"the manifest's served_systems must be a list of system names, got "
            f"{type(raw).__name__}")
    for name in raw:
        if not isinstance(name, str):
            raise FamilyError(f"the manifest's served_systems names {_not_text(name)}")
        if not is_system_name(name):
            raise FamilyError(
                f"the manifest's served_systems names {quoted(name)}, which is not a system "
                "name (lower-case ASCII letters, digits and '-', starting with a letter or "
                f"digit, at most {SYSTEM_MAX_LEN} characters)")
    return tuple(dict.fromkeys(raw))


def _parse_discriminator(raw: Any) -> dict:
    """The discriminator: its `predicate` text and nothing else."""
    if not isinstance(raw, dict):
        raise FamilyError(
            f"the manifest's discriminator must be a mapping holding its predicate, got "
            f"{type(raw).__name__}")
    unknown = [quoted(k) for k in raw if k != "predicate"]
    if unknown:
        raise FamilyError(
            f"the manifest's discriminator names unknown field(s) {', '.join(unknown)} — it "
            "holds only its predicate")
    predicate = raw.get("predicate")
    if not isinstance(predicate, str) or not predicate.strip():
        raise FamilyError("the manifest's discriminator.predicate must be a non-empty string")
    return {"predicate": predicate}


def _check_roster_capacity(world_count: int) -> None:
    from defender.records import RunRefused, check_arm_roster_capacity

    try:
        check_arm_roster_capacity(world_count)
    except RunRefused as refused:
        raise FamilyError(str(refused)) from refused


def _parse_worlds(raw_worlds: Any) -> list[World]:
    """The declared worlds: non-empty, labels usable and distinct, exactly one base."""
    if not isinstance(raw_worlds, list):
        raise FamilyError(
            f"the manifest's worlds must be a list, got {type(raw_worlds).__name__}")
    if not raw_worlds:
        raise FamilyError(
            "the manifest declares no worlds — the questioner's flow produces the base plus "
            "two by construction, and the family would have nothing to run")
    _check_roster_capacity(len(raw_worlds))
    worlds = [parse_world(entry) for entry in raw_worlds]
    _check_labels([w.label for w in worlds])
    ids = [w.world_id for w in worlds]
    if len(set(ids)) != len(ids):
        raise FamilyError("the manifest assigns one world UUID to multiple worlds")
    bases = [w.label for w in worlds if w.role == BASE_ROLE]
    if len(bases) != 1:
        raise FamilyError(
            f"exactly one world must carry the base role {BASE_ROLE!r}; {len(bases)} do "
            f"({bases}) — the base is the control every other world is compared against")
    return worlds


def _check_labels(labels: list[str]) -> None:
    """Labels are distinct selectors; they never name filesystem entries."""
    seen: set[str] = set()
    for label in labels:
        if (why := world_label_fault(label)) is not None:
            raise FamilyError(why)
        if label in seen:
            raise FamilyError(f"world label {quoted(label)} is declared twice")
        seen.add(label)


def parse_family(doc: Any) -> Family:
    """Validate a raw manifest document into `Family`, naming the field that refused.

    A document carrying a pre-oracle field is refused for that first, whatever else is wrong
    with it."""
    if not isinstance(doc, dict):
        raise FamilyError(f"the manifest must be a mapping, got {type(doc).__name__}")
    _refuse_predating(_predating_fields(_document_locations(doc)))
    unknown = [quoted(k) for k in doc if k not in _FAMILY_FIELDS]
    if unknown:
        raise FamilyError(
            f"the manifest names unknown top-level field(s) {', '.join(unknown)} — a document "
            "edited after review must not load as if the edit were part of the contract")
    _check_scalars(doc)
    served_systems = _parse_served_systems(doc.get("served_systems"))
    discriminator = _parse_discriminator(doc.get("discriminator"))
    as_of = parse_as_of(doc.get("as_of"))
    worlds = _parse_worlds(doc.get("worlds"))
    return Family(
        episode_id=doc["episode_id"],
        source_run_id=doc["source_run_id"], branch_message_id=doc["branch_message_id"],
        fences_at=doc["fences_at"], as_of=as_of,
        served_systems=served_systems,
        base_story=doc["base_story"],
        discriminator=discriminator, worlds=worlds,
    )


def runnable_worlds(family: Family) -> list[World]:
    """The worlds the launcher starts by default; the null replicate arm (`role: null`) loads but
    runs only when an operator asks for it."""
    return [w for w in family.worlds if w.role is not None]


def load_family(view: Bound, *, expected_episode_id: str) -> Family:
    """Read and validate the manifest of the episode `view` is bound at, whose id must be
    `expected_episode_id` — the episode folder's own name (R5)."""
    return parse_family(_read_document(view, expected_episode_id=expected_episode_id))


def load_manifest_document(view: Bound, *, expected_episode_id: str) -> dict:
    """The manifest as the mapping it is on disk, held to every rule `load_family` holds it to.

    For a reader that keeps the document's own spelling (the judge, the episode page): it reads
    through the same gate as the sibling, so no reader accepts a manifest another refuses."""
    doc = _read_document(view, expected_episode_id=expected_episode_id)
    parse_family(doc)  # refuses anything but a mapping
    return cast(dict, doc)


def manifest_world_ids(view: Bound, *, expected_episode_id: str) -> list[str]:
    """Return world UUIDs in declaration order after validating the persisted manifest.

    The rooted loader binds it to the expected episode; the full family schema validates
    the label-to-UUID mapping before a reader compares it with the arm roster.
    """
    doc = _read_document(view, expected_episode_id=expected_episode_id)
    if not isinstance(doc, dict) or doc.get("episode_id") != expected_episode_id:
        raise FamilyError(f"the manifest ({LAYOUT.family}) does not name episode "
                          f"{quoted(expected_episode_id)}")
    return [world.world_id for world in parse_family(doc).worlds]


def _read_manifest(view: Bound) -> str:
    """The manifest's text, read through the view: nothing below the episode dir is followed,
    so a planted link is never read or certified. An absent or refused manifest is
    `FamilyError`, naming the record (a view holds no path)."""
    rec = view.read(LAYOUT.family)
    if rec.text is None:
        raise FamilyError(f"the manifest ({LAYOUT.family}) could not be read: "
                          f"{'absent' if rec.absent else rec.reason}")
    return rec.text


def _read_document(view: Bound, *, expected_episode_id: str) -> object:
    """The manifest deserialized but not yet narrowed; typed `object` so only `parse_family`
    produces a `Family`. A pre-oracle field is refused off the text first, before the load can
    collapse or refuse what carries it.

    The one place every reader loads a manifest (R5): the expected episode id is a required
    keyword, and a manifest naming another episode is refused here, before any other rule,
    naming both ids — a manifest copied or moved into another episode's folder never loads as
    that episode's. A manifest naming none is `parse_family`'s to refuse."""
    text = _read_manifest(view)
    refuse_predating_text(text)
    try:
        doc = _yaml.safe_load(text)
    except yaml.YAMLError as bad:
        raise FamilyError(f"the manifest ({LAYOUT.family}) could not be read: {bad}") from bad
    if isinstance(doc, dict) and "episode_id" in doc and doc["episode_id"] != expected_episode_id:
        raise FamilyError(
            f"the manifest ({LAYOUT.family}) names episode {quoted(doc['episode_id'])}, but it "
            f"was read from episode {quoted(expected_episode_id)}'s folder — a manifest is its "
            "own episode's alone")
    return doc


def accept_family(document: dict) -> tuple[dict, Family]:
    """Assign identities to an authored declaration once, before publication or preflight.

    The questioner supplies labels and facts. A declaration supplying any world UUID is
    refused; every subsequent reader requires the persisted UUID and never mints one.
    """
    doc = dict(document)
    entries = doc.get("worlds")
    if isinstance(entries, list):
        worlds = []
        for entry in entries:
            if not isinstance(entry, dict):
                worlds.append(entry)
                continue
            if "world_id" in entry:
                raise FamilyError("world_id is host-assigned; a declaration supplies label only")
            worlds.append({**entry, "world_id": mint_uuid()})
        doc["worlds"] = worlds
    family = parse_family(doc)
    check_identities(family)
    return doc, family


def world_id_for(document: Mapping[str, Any], label: str) -> str:
    """Resolve a label through the manifest's persisted, strictly validated identity map."""
    return parse_family(dict(document)).world(label).world_id


def label_for_world_id(document: Mapping[str, Any], world_id: str) -> str:
    """Resolve a stored world UUID; an unrelated archive entry is never a world label."""
    return parse_family(dict(document)).world_by_id(world_id).label


def write_family(episode: Episode, doc: dict) -> Path:
    """Render the manifest into `episode` through a structured dumper, never by hand.

    Scalars are model-authored; an f-string writer would let one carrying `episode_id: hijacked`
    on a second line inject a key. The dumper quotes any string YAML would read as something
    else (`on`, `null`, `007`), so every name reads back as the text it was.
    """
    family = parse_family(doc)
    if family.episode_id != episode.dir.name:
        raise FamilyError(f"the manifest names episode {quoted(family.episode_id)}, "
                          f"but publication targets {quoted(episode.dir.name)}")
    manifest = episode.family
    manifest.create(
        _yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False))
    return manifest.path


# ---------------------------------------------------------------------------------------
# identity: one gate, before anything is launched
# ---------------------------------------------------------------------------------------

def refuse_reserved_world_label(label: str, *, at: str) -> None:
    """Refuse a reserved label; called wherever a world is parsed, not only by the launcher.
    The rule and its words are `_world_label.reserved_label_fault`'s."""
    if (why := reserved_label_fault(label, at=at)) is not None:
        raise FamilyError(why)


def check_identities(family: Family) -> None:
    """Hold directly constructed families to the same label, UUID and role rules."""
    _check_roster_capacity(len(family.worlds))
    roles: dict[str, str] = {}
    ids: set[str] = set()
    _check_labels([world.label for world in family.worlds])
    for world in family.worlds:
        if (why := uuid_id_fault(world.world_id, "world")) is not None:
            raise FamilyError(why)
        if world.world_id in ids:
            raise FamilyError("the manifest assigns one world UUID to multiple worlds")
        ids.add(world.world_id)
        if world.role is not None:
            if world.role in roles:
                raise FamilyError(f"worlds {roles[world.role]!r} and {world.label!r} "
                                  f"both declare role {world.role!r}")
            roles[world.role] = world.label


@model(frozen=True)
class ResumeWorld:
    """A sibling's persisted world UUID, label, declaration and optional arm-run roster.

    The world UUID exists before preflight and survives independently of whether any arm runs.
    The label selects a declaration; only UUIDs name its files or served call IDs.
    """

    world_id: str
    label: str
    episode_dir: Path
    facts: tuple[Fact, ...]
    as_of: dt.datetime
    family: Family
    arm_ids: dict[str, RunId] | None = None

    @property
    def ledger_path(self) -> Path:
        """This world's own ledger, beside the family's primed base recording."""
        return self.episode_dir / "served" / f"{self.world_id}.jsonl"



def resume_world_from(family: Family, world_label: str, episode_dir: Path, *,
                      arm_ids: Mapping[str, RunId] | None = None) -> ResumeWorld:
    """The world `world_label` names in `family`, or the fault that says it declares none.
    `arm_ids` is the episode's arm roster when the caller holds it (see `ResumeWorld`).

    Called before the run dir is materialised, so an operator typo leaves no empty run dir.
    """
    world = family.world(world_label)
    return ResumeWorld(
        world_id=world.world_id,
        label=world_label, episode_dir=Path(episode_dir), facts=world.facts,
        as_of=family.as_of, family=family,
        arm_ids=None if arm_ids is None else dict(arm_ids),
    )


def family_identities(family: Family, arm_ids: Mapping[str, RunId]) -> frozenset[str]:
    """Known opaque identities for redaction: episode, worlds and arm runs.

    Labels are descriptive selectors and are not redaction targets. Source run IDs remain
    available in the resumed transcript and are not added here.
    """
    return frozenset({family.episode_id, *(world.world_id for world in family.worlds),
                      *(str(arm) for arm in arm_ids.values())})


def refuse_bad_episode_id(episode_id: str) -> None:
    """Refuse an episode id that cannot name an episode folder of its own: canonical lowercase
    UUID text only (`_run_id.episode_id_fault`, the one statement of the rule)."""
    if (why := episode_id_fault(episode_id)) is not None:
        raise FamilyError(f"the manifest's episode id is not usable: {why}")


__all__ = [
    "BASE_ROLE",
    "Fact",
    "Family",
    "FamilyError",
    "LABEL_BASES",
    "ManifestPredatesOracle",
    "RESERVED_WORLD_LABELS",
    "ResumeWorld",
    "World",
    "check_identities",
    "family_identities",
    "is_reserved_world_label",
    "refuse_reserved_world_label",
    "load_family",
    "load_manifest_document",
    "manifest_world_ids",
    "parse_as_of",
    "parse_family",
    "parse_world",
    "refuse_bad_episode_id",
    "refuse_predating_text",
    "resume_world_from",
    "runnable_worlds",
    "write_family",
    "accept_family",
    "world_id_for",
    "label_for_world_id",
]
