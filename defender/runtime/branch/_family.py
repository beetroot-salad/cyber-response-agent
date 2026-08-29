"""The family manifest: the one document a sibling is told, and the schema that gates it.

#947's M2. `episodes/<id>/family.yaml` carries three authors in one document — the launcher's
derived half (episode id, source run, branch point, T0), the operator's instrument field
(`continuation_prompt`), and the questioner's authored half (the base story, the discriminator
and the worlds) — and `run.py --resume <manifest> --world X` derives everything else from it.

THE SCHEMA LIVES IN THE RUNTIME, not in `learning/`, because the RUNTIME reads it: a resumed
run must not import the learning tree to know which world it is. Learning writes through the
same loader, so the questioner's raw output is validated into `Family` before any other step
reads it, and a refusal names the offending field rather than merely saying the document is bad.

STRICT, in both directions (§7 FORK-5). An unknown top-level field is refused rather than
ignored — a manifest a human edited after review must not load as if the edit were part of the
contract — and every closed vocabulary the document names is the SHIPPED one (`_vocab`'s
disposition enum, the serving grant's systems) rather than a second, looser list beside it.

The model authors free text into this document, so every model-authored scalar is written back
through a structured dumper and never through string interpolation (S41): a `base_story`
carrying `episode_id: hijacked` on its second line is one opaque scalar on the way out and the
same string on the way back in, and the entity keys of the patch table — which ARE rendered as
keys — carry a bounded, validated domain of their own (§7 NEW-1).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from defender._io import guarded_mkdir, write_guarded
from defender._run_id import (
    CASE_STABLE_REQUIRED,
    RUN_ID_ALLOWED,
    is_case_stable_id,
    is_valid_run_id,
)
from defender._vocab import DISPOSITION_ENUM, normalized_disposition
from defender.scripts.adapters.confinement import ViewNameError, refuse_unnameable_world

#: The manifest's filename inside an episode directory. Named once: the launcher writes it, the
#: sibling reads it, and the archive keeps it.
MANIFEST_NAME = "family.yaml"

#: The base world's role. `A` is the control every other world is compared against, and the
#: loader enforces that exactly one world claims it.
BASE_ROLE = "A"

#: The system whose difference is STAGED rather than patched. A patch table naming it is an
#: authoring slip the estate's applier already refuses; the loader refuses it one step earlier,
#: where the field can still be named.
STAGED_SYSTEM = "elastic"  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads

#: The six state systems an entity patch may name — the serving roster minus the staged one.
#: Spelled here rather than imported from `runtime.driver` because this module is on the
#: RESUME path's import graph and must not pull the driver in to read a manifest.
PATCHABLE_SYSTEMS: frozenset[str] = frozenset({
    "cmdb", "identity", "threat-intel", "change-mgmt", "ticket", "host-state",
})

#: The two bases a world's declared disposition may rest on. `policy-rule` is the default: a
#: world that omits the field is asserting the shipped rule, not a judgment.
LABEL_BASES: frozenset[str] = frozenset({"policy-rule", "judgment"})

#: What a patch-table ENTITY key may be. The entity is rendered AS A KEY in a document a model
#: authored the value of, so its domain is bounded the way the system key's is (§7 NEW-1): a
#: leading alphanumeric, then alphanumerics and the three separators a hostname carries. No
#: whitespace, no `:`, no `/`, no `.` run that could climb a path.
_ENTITY_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")

#: Every top-level field the manifest declares. Unknown ones refuse.
_FAMILY_FIELDS = (
    "episode_id", "source_run_dir", "source_run_id", "branch_message_id", "fences_at",
    "as_of", "continuation_prompt", "base_story", "discriminator", "worlds",
)

#: Every field a world entry declares.
_WORLD_FIELDS = (
    "world_id", "role", "story", "axis", "disposition_declared", "label_basis", "overlay",
)


class FamilyError(Exception):
    """A manifest this design cannot honestly run.

    A FAULT, never a corpus contradiction and never an unreachable difference: `is_contradiction`
    answers False for every instance, because the review's three outcome classes are about what
    the ESTATE said and this class is about what the document says (S33/S36).
    """


def is_contradiction(_error: BaseException) -> bool:
    """Is this refusal a corpus contradiction? Never, for a manifest fault.

    Published beside the class so a caller classifying a replay difference asks one question
    rather than matching on a type it would have to keep in step.
    """
    return False


# ---------------------------------------------------------------------------------------
# the overlay
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ElasticEntry:
    """One base pattern's staged difference: what is added, and what is taken away."""

    inject: list[dict] = field(default_factory=list)
    #: The exclusion predicate, UNNARROWED on purpose. The loader admits any document shape a
    #: model can author — a mapping, a bare list, a bare string — because the thing that decides
    #: whether a predicate is admissible is `staging.check_exclusion_predicate`'s ALLOW-LIST over
    #: clause types, and it can only refuse a shape by name if that shape reaches it. Narrowed to
    #: `dict` here, an unparseable predicate would be refused by the loader with a message about
    #: types rather than by the gate with a message about the grammar, and the gate's own
    #: refusals would become unreachable.
    exclude: Any = None


@dataclass(frozen=True)
class Overlay:
    """A world's difference, as data.

    Two halves, keyed the way the two mechanisms consume them: `patches` by system then entity
    then field, and its staged half by the base pattern that half stages. Both normalise to
    ABSENT when empty —
    an overlay whose halves are present and empty is world A, not an authored difference — so
    `touches_of` can be derived from the keys rather than stored beside them.
    """

    patches: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    elastic: dict[str, ElasticEntry] = field(default_factory=dict)  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads


def parse_overlay(raw: Any, *, where: str = "overlay") -> Overlay:
    """Validate one overlay document into `Overlay`, naming the field that refused."""
    if raw is None:
        return Overlay()
    if not isinstance(raw, dict):
        raise FamilyError(f"{where} must be a mapping, got {type(raw).__name__}")
    unknown = sorted(set(raw) - {"patches", "elastic"})  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads
    if unknown:
        raise FamilyError(f"{where} names unknown field(s) {unknown}")
    return Overlay(patches=_parse_patches(raw.get("patches"), where),
                   elastic=_parse_elastic(raw.get("elastic"), where))  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads


def _parse_patches(raw: Any, where: str) -> dict[str, dict[str, dict[str, Any]]]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise FamilyError(f"{where}.patches must be a mapping, got {type(raw).__name__}")
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for system, table in raw.items():
        if system == STAGED_SYSTEM:
            raise FamilyError(
                f"{where}.patches names {system!r}, which is STAGED rather than patched — its "
                "difference lives in the documents the engine read, so a patch table naming it "
                "would be dropped in silence while every row still read honestly")
        if system not in PATCHABLE_SYSTEMS:
            raise FamilyError(
                f"{where}.patches names {system!r}, which is not one of the six state systems "
                f"{sorted(PATCHABLE_SYSTEMS)}")
        if not isinstance(table, dict):
            raise FamilyError(
                f"{where}.patches[{system!r}] must be a mapping of entity to fields")
        entities: dict[str, dict[str, Any]] = {}
        for entity, fields_ in table.items():
            _check_entity(entity, where, system)
            if not isinstance(fields_, dict):
                raise FamilyError(
                    f"{where}.patches[{system!r}][{entity!r}] must be a mapping of field to "
                    "value")
            entities[entity] = dict(fields_)
        if entities:
            out[system] = entities
    return out


def _check_entity(entity: Any, where: str, system: str) -> None:
    """The patch table's entity KEY has a bounded domain the way its system key does.

    Refused rather than escaped: the entity is written back as a mapping key, and a key
    carrying document-structural or path syntax is a key a later reader resolves differently
    from the one the model meant. `_ENTITY_RE` admits what a hostname or an account name is
    spelled with and nothing that could open a second key or climb a path.
    """
    if not isinstance(entity, str) or not _ENTITY_RE.match(entity):
        raise FamilyError(
            f"{where}.patches[{system!r}] names entity {entity!r}, which is outside the entity "
            "domain — an entity is rendered as a KEY, so it may carry only alphanumerics and "
            "'.', '_', '-' after a leading alphanumeric")


def _parse_elastic(raw: Any, where: str) -> dict[str, ElasticEntry]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise FamilyError(f"{where}.elastic must be a mapping, got {type(raw).__name__}")  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads
    out: dict[str, ElasticEntry] = {}
    for pattern, entry in raw.items():
        if not isinstance(pattern, str) or not pattern:
            raise FamilyError(f"{where}.elastic names a non-string base pattern {pattern!r}")  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads
        parsed = _parse_elastic_entry(entry, f"{where}.elastic[{pattern!r}]")  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads
        if parsed is not None:
            out[pattern] = parsed
    return out


def _parse_elastic_entry(entry: Any, at: str) -> ElasticEntry | None:
    """One base pattern's staged difference, or `None` when it declares none.

    An entry that stages nothing is not a declared difference, so it normalises to ABSENT
    rather than to an empty entry — which is what keeps `touches_of` derivable from the
    overlay's keys alone, instead of from a walk of what each key happens to hold.
    """
    if entry is None:
        return None
    if not isinstance(entry, dict):
        raise FamilyError(f"{at} must be a mapping")
    unknown = sorted(set(entry) - {"inject", "exclude"})
    if unknown:
        raise FamilyError(f"{at} names unknown field(s) {unknown}")
    inject = entry.get("inject") or []
    if not isinstance(inject, list) or any(not isinstance(d, dict) for d in inject):
        raise FamilyError(f"{at}.inject must be a list of documents")
    exclude = entry.get("exclude")
    if exclude is not None and not isinstance(exclude, (dict, list, str)):
        raise FamilyError(f"{at}.exclude must be a query document or null")
    if not inject and exclude is None:
        return None
    return ElasticEntry(inject=[dict(d) for d in inject], exclude=exclude)


def touches_of(overlay: Overlay) -> tuple[str, ...]:
    """The systems this overlay's difference touches, DERIVED on every read.

    `World.touches` retires as an authored field (D2): a stored set is a second place for the
    answer to live, and the one that drifts is the one that stops staging. The patch systems
    plus the staged system when that half is non-empty, in a stable order.
    """
    systems = set(overlay.patches)
    if overlay.elastic:  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads
        systems.add(STAGED_SYSTEM)
    return tuple(sorted(systems))


# ---------------------------------------------------------------------------------------
# the world
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class World:
    """One sibling's declaration: what it is, what it asserts, and how it differs."""

    world_id: str
    role: str | None
    story: str
    axis: str | None
    disposition_declared: str
    label_basis: str
    overlay: Overlay

    @property
    def touches(self) -> tuple[str, ...]:  # noqa: D401 — derived, never stored
        """The systems this world's difference touches, from its overlay alone."""
        return touches_of(self.overlay)


def parse_world(raw: Any, *, where: str = "worlds") -> World:
    """Validate one world entry, naming the field that refused."""
    if not isinstance(raw, dict):
        raise FamilyError(f"{where} entry must be a mapping, got {type(raw).__name__}")
    unknown = sorted(set(raw) - set(_WORLD_FIELDS))
    if unknown:
        raise FamilyError(f"{where} entry names unknown field(s) {unknown}")
    world_id = raw.get("world_id")
    if not isinstance(world_id, str) or not world_id:
        raise FamilyError(f"{where} entry carries no world_id")
    at = f"{where}[{world_id!r}]"
    role = raw.get("role")
    if role is not None and (not isinstance(role, str) or not role):
        raise FamilyError(f"{at}.role must be a label or the null replicate sentinel")
    story = raw.get("story")
    if not isinstance(story, str):
        raise FamilyError(f"{at}.story must be a string")
    return World(
        world_id=world_id, role=role, story=story,
        axis=_check_axis(raw.get("axis"), at, role),
        disposition_declared=_check_disposition(raw.get("disposition_declared"), at),
        label_basis=_check_label_basis(raw.get("label_basis"), at),
        overlay=parse_overlay(raw.get("overlay"), where=f"{at}.overlay"),
    )


def _check_axis(axis: Any, at: str, role: str | None) -> str | None:
    """The difference this world claims to name, or the null sentinel that says it names none.

    THE HOUSE SENTINEL IS NULL. An empty string is a real value, so a non-base world declaring
    one is declaring a difference it cannot name — a world nothing downstream can compare,
    recorded as though it were comparable.
    """
    if axis is not None and not isinstance(axis, str):
        raise FamilyError(f"{at}.axis must be a string or null")
    if axis == "" and role != BASE_ROLE:
        raise FamilyError(
            f"{at}.axis is the empty string — the sentinel for 'no axis' is null, so an empty "
            "string is a world declaring a difference it cannot name")
    return axis


def _check_disposition(raw: Any, at: str) -> str:
    """The world's declared disposition, through the VOCABULARY'S OWN NORMALIZER.

    Never a membership test written here. A world's declared disposition is the same value the
    report's headline is, authored by a model reading attacker-influenced data, and `_vocab`
    owns what one MEANS — including the zero-width strip a borrowed `in DISPOSITION_ENUM`
    silently loses (#785: one parser, six interpreters, three of which disagreed).
    """
    disposition = normalized_disposition(raw)
    if disposition is None:
        raise FamilyError(
            f"{at}.disposition_declared is {raw!r}, outside the shipped disposition "
            f"vocabulary {sorted(DISPOSITION_ENUM)}")
    return disposition


def _check_label_basis(raw: Any, at: str) -> str:
    """What the declared disposition RESTS on, defaulting to the shipped rule.

    A world that omits the field is asserting the policy rule, not a judgment: the default is
    the WEAKER claim, so an omission can never be read as a stronger one.
    """
    basis = "policy-rule" if raw is None else raw
    if basis not in LABEL_BASES:
        raise FamilyError(f"{at}.label_basis is {basis!r}, outside {sorted(LABEL_BASES)}")
    return str(basis)


# ---------------------------------------------------------------------------------------
# the family
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Family:
    """The whole manifest, loaded."""

    episode_id: str
    source_run_dir: str
    source_run_id: str
    branch_message_id: int
    fences_at: int
    as_of: dt.datetime
    continuation_prompt: str
    base_story: str
    discriminator: dict
    worlds: list[World]

    def world(self, world_id: str) -> World:
        for candidate in self.worlds:
            if candidate.world_id == world_id:
                return candidate
        raise FamilyError(
            f"the manifest declares no world {world_id!r}; it declares "
            f"{[w.world_id for w in self.worlds]}")


def parse_as_of(raw: Any, *, where: str = "as_of") -> dt.datetime:
    """T0, as an aware UTC moment, or the fault that says why it is not one.

    A naive moment names no instant and an offset one formats a trailing `Z` that lies by its
    offset — every timestamp a sibling mints would be wrong by the same amount, consistently,
    which is the kind of wrong nothing downstream can see.
    """
    if isinstance(raw, dt.datetime):
        moment = raw
    elif isinstance(raw, str):
        try:
            # lint-parse: ok — `_clock.parse_iso_utc` is the project's owner of this parse and
            # is deliberately the WRONG normalizer here: it READS A NAIVE VALUE AS UTC, which is
            # right for a precedent store sorting a mixed batch and is exactly the collapse this
            # demand refuses. A naive T0 is the fault (S2) — every timestamp a sibling mints
            # from it is the afternoon it executed — so this seam has to be able to see the
            # difference the shared helper exists to erase, and then refuses on it below.
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
    for scalar in ("episode_id", "source_run_dir", "source_run_id", "continuation_prompt",
                   "base_story"):
        if not isinstance(doc.get(scalar), str) or not doc.get(scalar):
            raise FamilyError(f"the manifest's {scalar} must be a non-empty string")
    for number in ("branch_message_id", "fences_at"):
        value = doc.get(number)
        if not isinstance(value, int) or isinstance(value, bool):
            raise FamilyError(f"the manifest's {number} must be an integer")


def _parse_worlds(raw_worlds: Any) -> list[World]:
    """The declared worlds, with the family's own cardinality rule applied to the list.

    EXACTLY ONE BASE, refused here rather than discovered later: the base is the control every
    other world is compared against, so a family with two has no control and one with none has
    nothing to compare to. And an EMPTY list is refused by name — the questioner's flow produces
    the base plus two by construction, so an empty one is a document that lost its worlds.
    """
    if not isinstance(raw_worlds, list):
        raise FamilyError(
            f"the manifest's worlds must be a list, got {type(raw_worlds).__name__}")
    if not raw_worlds:
        raise FamilyError(
            "the manifest declares no worlds — the questioner's flow produces the base plus "
            "two by construction, and step 5 would have nothing to start")
    worlds = [parse_world(entry) for entry in raw_worlds]
    bases = [w.world_id for w in worlds if w.role == BASE_ROLE]
    if len(bases) != 1:
        raise FamilyError(
            f"exactly one world must carry the base role {BASE_ROLE!r}; {len(bases)} do "
            f"({bases}) — the base is the control every other world is compared against")
    return worlds


def _check_overlay_keys(worlds: list[World], captured_patterns: tuple[str, ...]) -> None:
    """Every staged overlay key names a corpus this episode can actually address.

    A configured corpus pattern, or one the capture's own FROM sources name, and nothing else.
    An invented pattern is a world staging a corpus no query in this episode addresses — a
    difference that is staged, recorded, and unobservable.
    """
    allowed = set(captured_patterns) | set(_configured_patterns())
    for world in worlds:
        for pattern in world.overlay.elastic:  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads
            if pattern not in allowed:
                raise FamilyError(
                    f"worlds[{world.world_id!r}].overlay.elastic names {pattern!r}, which is "  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads
                    "neither a configured corpus pattern nor one the capture's own FROM "
                    f"sources name ({sorted(allowed)})")


def parse_family(doc: Any, *, captured_patterns: tuple[str, ...] = ()) -> Family:
    """Validate a raw manifest document into `Family`, naming the field that refused.

    `captured_patterns` are the FROM sources the capture itself names. An overlay's staged half
    may key a configured corpus pattern or one of these and nothing else: an invented pattern is
    a world staging a corpus no query in this episode addresses, which stages a difference
    nothing can observe.
    """
    if not isinstance(doc, dict):
        raise FamilyError(f"the manifest must be a mapping, got {type(doc).__name__}")
    unknown = sorted(set(doc) - set(_FAMILY_FIELDS))
    if unknown:
        raise FamilyError(
            f"the manifest names unknown top-level field(s) {unknown} — a document edited "
            "after review must not load as if the edit were part of the contract")
    _check_scalars(doc)
    discriminator = doc.get("discriminator")
    if not isinstance(discriminator, dict) or not discriminator:
        raise FamilyError("the manifest's discriminator must be a non-empty mapping")
    as_of = parse_as_of(doc.get("as_of"))
    worlds = _parse_worlds(doc.get("worlds"))
    _check_overlay_keys(worlds, captured_patterns)
    return Family(
        episode_id=doc["episode_id"], source_run_dir=doc["source_run_dir"],
        source_run_id=doc["source_run_id"], branch_message_id=doc["branch_message_id"],
        fences_at=doc["fences_at"], as_of=as_of,
        continuation_prompt=doc["continuation_prompt"], base_story=doc["base_story"],
        discriminator=dict(discriminator), worlds=worlds,
    )


def _configured_patterns() -> tuple[str, ...]:
    """The corpus patterns this deployment configures, read where the adapter reads them.

    Imported lazily: the manifest loader sits on the resume path and must not pull the adapter
    tree in merely to know the two default patterns.
    """
    from defender.learning.branch.estate.stagers.elastic import configured_patterns  # lint-shippable: ok — the manifest's own field name; the overlay's staged half is spelled this in `family.yaml` and the loader must name the key it reads

    return configured_patterns()


def runnable_worlds(family: Family) -> list[World]:
    """The worlds the launcher starts by default.

    The null replicate arm (`role: null`) LOADS and is not run: it is admitted by the data
    model so an operator can ask for it, not selected unless they do.
    """
    return [w for w in family.worlds if w.role is not None]


def load_family(path: Path, *, captured_patterns: tuple[str, ...] = ()) -> Family:
    """Read and validate the manifest at `path`."""
    return parse_family(_read_document(Path(path)), captured_patterns=captured_patterns)


def _read_document(path: Path) -> object:
    """The manifest's bytes, deserialized and NOT yet narrowed.

    Split from `load_family` so the parse and the narrowing are two statements with two types:
    this frame promises `object`, which is what a deserializer actually hands back, and
    `parse_family` is the one seam that turns it into a `Family`. Folded together, the
    deserializer's `Any` flowed straight into a `-> Family` return and type-checked clean over
    a promise the runtime never made.
    """
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as bad:
        raise FamilyError(f"the manifest at {path} could not be read: {bad}") from bad


def write_family(episode_dir: Path, doc: dict) -> Path:
    """Render the manifest into `episode_dir` through a STRUCTURED dumper, never by hand.

    S41's guarantee, and the reason this is a function rather than a `write_text` at the call
    site: every scalar in this document is model-authored, and one carrying `episode_id:
    hijacked` on its second line is a whole sibling key if the writer is an f-string. The
    dumper quotes and escapes; re-reading yields the same string and no key the text tried to
    introduce.
    """
    episode_dir = Path(episode_dir)
    # The episode directory is its own trust root: it is created under the CONFIGURED
    # episodes root, which is host-controlled, and everything below it is reachable
    # from a sibling box's rw bind.
    guarded_mkdir(episode_dir, base=episode_dir.parent)
    manifest = episode_dir / MANIFEST_NAME
    # GUARDED, because the episode dir is reachable from a box's rw bind: a link planted at the
    # manifest's name would send the family's own contract out of the episode, and every sibling
    # reads that document to learn which world it is.
    write_guarded(
        manifest,
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False))
    return manifest


def manifest_digest(path: Path) -> str:
    """The manifest's content digest, recorded in the review and re-checked on resume."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_manifest_digest(path: Path, recorded: str) -> None:
    """Refuse a manifest whose bytes changed since the review recorded them."""
    actual = manifest_digest(path)
    if actual != recorded:
        raise FamilyError(
            f"the manifest at {path} has a digest of {actual[:12]} but the review recorded "
            f"{str(recorded)[:12]} — a manifest edited between review and run is not the "
            "document the review accepted")


# ---------------------------------------------------------------------------------------
# identity: one gate, before anything is staged (§7 FORK-4)
# ---------------------------------------------------------------------------------------

#: The world label the family's own shared capture is written under. No world may claim it: a
#: world that did would append its live rows into the recording its siblings replay.
RESERVED_WORLD_LABELS: frozenset[str] = frozenset({"base"})


def check_identities(family: Family) -> None:
    """ONE gate over the whole manifest, before anything is staged.

    Every rule the downstream names would each have refused at a different depth, and refused
    there they cost a primed episode and however many siblings had already run: the label must
    be nameable in a view, the labels must be distinct case-folded, none may be the reserved
    base-capture name, the roles must be distinct, and each composed world token must round-trip
    the naming rule the four comparing sites read it back through.
    """
    seen: dict[str, str] = {}
    roles: dict[str, str] = {}
    token_head = episode_token_for(family.episode_id)
    for world in family.worlds:
        label = world.world_id
        if label.casefold() in RESERVED_WORLD_LABELS:
            raise FamilyError(
                f"world label {label!r} is the reserved name of the family's own base capture "
                "— a world claiming it would append its live rows into the recording its "
                "siblings replay")
        try:
            refuse_unnameable_world(label)
        except ViewNameError as bad:
            raise FamilyError(f"world label {label!r} cannot name a view: {bad}") from bad
        folded = label.casefold()
        if folded in seen:
            raise FamilyError(
                f"world labels {seen[folded]!r} and {label!r} are one label wherever the "
                "filesystem folds case, and each names a run dir, a ledger file and a staged "
                "corpus")
        seen[folded] = label
        if world.role is not None:
            if world.role in roles:
                raise FamilyError(
                    f"worlds {roles[world.role]!r} and {label!r} both declare role "
                    f"{world.role!r} — a family is a set of DIFFERENT worlds, and two arms "
                    "sharing a role cannot be told apart in any report")
            roles[world.role] = label
        token = f"{token_head}.{label}"
        try:
            refuse_unnameable_world(label)
        except ViewNameError as bad:  # pragma: no cover — covered by the label check above
            raise FamilyError(f"world token {token!r} does not round-trip: {bad}") from bad


def episode_token_for(episode_id: str, *, override: str | None = None) -> str:
    """The episode's own token: the id with its separators normalised to one spelling.

    INJECTIVE, and not by a plain character replacement: the run-id grammar admits BOTH `-` and
    `_`, so folding one onto the other would map two distinct episode ids onto one token — and
    the token is what the sweep's glob and every world token are built from, so a collision
    there is one episode tearing down another's live names. `-` and `_` are therefore escaped
    to distinct sequences before the separator is chosen.

    NAMEABLE, because the token is the head of every world token and therefore of every staged
    alias. An id that cannot render is not permanently unbranchable: `override` is the escape
    the operator names, and it is held to exactly the same rule.
    """
    if override is not None:
        return _nameable_token(override, f"--episode-token {override!r}")
    # CASEFOLDED, because an alias name cannot carry upper case and a view named above the case
    # rule is not refused by the cluster — it is answered with an empty result, so the world
    # reads as one that changed nothing. This is not a loss of injectivity in practice:
    # `refuse_bad_episode_id` holds every episode id the launcher accepts to `is_case_stable_id`,
    # so for those ids the fold is the identity, and an id reaching here unfolded came from a
    # caller that has not been through that gate.
    escaped = episode_id.replace("_", "__").replace("-", ".").casefold()
    return _nameable_token(escaped, f"episode id {episode_id!r}")


def _nameable_token(token: str, origin: str) -> str:
    """`token`, or the fault every alias built from it would have raised.

    Held to the WORLD-ID rule rather than to a looser one: the composed world token is
    `f"{episode_token}.{world_id}"` and it is that whole string `world_view` renders into an
    alias, so a token this rule admits and the alias rule does not is a name nothing can stage.
    """
    try:
        refuse_unnameable_world(token)
    except ViewNameError as bad:
        raise FamilyError(
            f"{origin} does not render to a nameable episode token ({bad}) — pass an explicit "
            "token instead; every world token and every staged alias is built from it") from bad
    if not token or not token[0].isalnum():
        raise FamilyError(
            f"{origin} does not render to a nameable episode token: {token!r} does not start "
            "with an alphanumeric")
    return token


def world_token_for(episode_token: str, world_label: str) -> str:
    """The ONE spelling of a world's identity: `f"{episode_token}.{label}"`.

    Four sites compare a world — the staged alias name's head, the world ledger's filename, the
    ledger rows a sibling writes, and the applier's staging decision — and every one of them
    reads this. Two spellings would be the join-breaker the registry of names exists to prevent.
    """
    return f"{episode_token}.{world_label}"


@dataclass(frozen=True)
class ResumeWorld:
    """What a sibling process IS, from the manifest alone.

    `world_id` is the composed TOKEN rather than the short label, deliberately: the estate seam
    (`WorldRegistry`, `WorldApplier`, `Ledger.for_world`) reads `world_id` and turns it into an
    alias name, a ledger filename and a row key, and every one of those must carry the episode
    so two episodes' world `b` are two worlds. The short label survives beside it as `label`,
    which is what the manifest, the run id and the archive directory are keyed on.
    """

    world_id: str
    label: str
    episode_dir: Path
    overlay: Overlay
    as_of: dt.datetime
    family: Family

    @property
    def token(self) -> str:
        """The composed world token — the same string `world_id` carries, named for readers."""
        return self.world_id

    @property
    def touches(self) -> tuple[str, ...]:
        """Derived from the overlay on every read; never a stored field (D2)."""
        return touches_of(self.overlay)

    @property
    def ledger_path(self) -> Path:
        """This world's own ledger, beside the family's primed base recording."""
        return self.episode_dir / "served" / f"{self.world_id}.jsonl"

    @property
    def run_id(self) -> str:
        """This sibling's run id: the episode id joined to its world label."""
        return f"{self.family.episode_id}-{self.label}"


def resume_world_from(family: Family, world_label: str, episode_dir: Path) -> ResumeWorld:
    """The world `world_label` names in `family`, or the fault that says it declares no such one.

    Refused HERE, before the run dir is materialised and before any box starts: a label the
    manifest does not declare is an operator typo, and discovering it after materialisation
    leaves a run dir nothing will ever fill.
    """
    world = family.world(world_label)
    return ResumeWorld(
        world_id=world_token_for(episode_token_for(family.episode_id), world_label),
        label=world_label, episode_dir=Path(episode_dir), overlay=world.overlay,
        as_of=family.as_of, family=family,
    )


def refuse_bad_episode_id(episode_id: str) -> None:
    """Refuse an episode id that cannot name a directory of its own.

    The id is joined straight into the episode dir's path and into every sibling's run id, so a
    token carrying a separator plants the family's capture outside the episodes root, and two
    spellings of one id are one directory wherever the filesystem folds case.
    """
    if not is_valid_run_id(episode_id):
        raise FamilyError(
            f"episode id {episode_id!r} is not usable (allowed: {RUN_ID_ALLOWED}) — it names "
            "a directory and half of every sibling's run id")
    if not is_case_stable_id(episode_id):
        raise FamilyError(
            f"episode id {episode_id!r} is not usable ({CASE_STABLE_REQUIRED}) — use "
            f"{episode_id.casefold()!r}")


__all__ = [
    "BASE_ROLE",
    "ElasticEntry",
    "Family",
    "FamilyError",
    "LABEL_BASES",
    "MANIFEST_NAME",
    "Overlay",
    "PATCHABLE_SYSTEMS",
    "RESERVED_WORLD_LABELS",
    "ResumeWorld",
    "World",
    "check_identities",
    "check_manifest_digest",
    "episode_token_for",
    "is_contradiction",
    "load_family",
    "manifest_digest",
    "parse_as_of",
    "parse_family",
    "parse_overlay",
    "parse_world",
    "refuse_bad_episode_id",
    "resume_world_from",
    "runnable_worlds",
    "touches_of",
    "world_token_for",
    "write_family",
]
