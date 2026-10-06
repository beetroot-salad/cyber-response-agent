"""The family manifest: the one document a sibling is told, and the schema that gates it.

`episodes/<id>/family.yaml` carries three authors: the launcher's derived half (episode id,
source run, branch point, T0), the operator's `continuation_prompt`, and the questioner's
authored half (base story, discriminator, worlds). `run.py --resume <manifest> --world X`
derives everything else from it.

The schema lives in the runtime because a resumed run must not import the learning tree to know
which world it is. Learning validates the questioner's output through the same loader.

Strict both ways: an unknown top-level field is refused (a manifest edited after review must not
load as if the edit were part of the contract), and every closed vocabulary is the shipped one.
Model-authored scalars are written through a structured dumper, never string interpolation, so a
`base_story` carrying `episode_id: hijacked` round-trips as one opaque scalar.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import field
from defender._model import model
from pathlib import Path
from collections.abc import Callable
from typing import Any

import yaml

from defender import _yaml
from defender._episode_handle import Episode
from defender._episode_paths import LAYOUT
from defender._io import Bound
from defender._run_id import episode_id_fault
from defender._world_label import (
    RESERVED_WORLD_LABELS, is_reserved_world_label, reserved_label_fault,
)
from defender.run_repository import run_name_fault
from defender._vocab import (
    DISPOSITION_ENUM,
    DISPOSITION_VALUES,
    HOST_ONLY_DISPOSITION,
    normalized_disposition,
)
from defender.scripts.adapters.confinement import ViewNameError, refuse_unnameable_world
from defender._query_rules import ParamsTooDeep, _json_safe_params

#: The base world's role: the control every other world is compared against. Exactly one world
#: claims it.
BASE_ROLE = "A"

#: The system whose difference is staged rather than patched. The loader refuses a patch table
#: naming it, where the field can still be named.
STAGED_SYSTEM = "elastic"  # lint-shippable: ok — the manifest's own field name for the overlay's staged half

#: The six state systems an entity patch may name — the serving roster minus the staged one.
#: Spelled here rather than imported from `runtime.driver`: the resume path must not pull the
#: driver in to read a manifest.
PATCHABLE_SYSTEMS: frozenset[str] = frozenset({
    "cmdb", "identity", "threat-intel", "change-mgmt", "ticket", "host-state",
})

#: The two bases a world's declared disposition may rest on; `policy-rule` is the default.
LABEL_BASES: frozenset[str] = frozenset({"policy-rule", "judgment"})

#: What a patch-table entity key may be. The entity is rendered as a key in a model-authored
#: document, so it is bounded to hostname-like spelling: no whitespace, `:`, or `/`.
_ENTITY_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")

#: Every top-level field the manifest declares. Unknown ones refuse.
_FAMILY_FIELDS = (
    "episode_id", "source_run_dir", "source_run_id", "branch_message_id", "fences_at",
    "as_of", "continuation_prompt", "captured_patterns", "configured_patterns", "base_story",
    "discriminator", "worlds",
)

#: Every field a world entry declares.
_WORLD_FIELDS = (
    "world_id", "role", "story", "axis", "disposition_declared", "label_basis", "overlay",
)


class FamilyError(Exception):
    """A manifest this design cannot honestly run.

    A fault about the document, never a corpus contradiction or an unreachable difference (those
    are about what the estate said).
    """


def is_contradiction(_error: BaseException) -> bool:
    """Is this refusal a corpus contradiction? Never, for a manifest fault."""
    return False


# ---------------------------------------------------------------------------------------
# the overlay
# ---------------------------------------------------------------------------------------


@model(frozen=True)
class ElasticEntry:
    """One base pattern's staged difference: what is added, and what is taken away."""

    inject: list[dict] = field(default_factory=list)
    #: The exclusion predicate, left unnarrowed: `staging.check_exclusion_predicate`'s allow-list
    #: decides admissibility and can only refuse a shape by name if that shape reaches it.
    exclude: Any = None


@model(frozen=True)
class Overlay:
    """A world's difference, as data.

    `patches` is keyed system → entity → field; the staged half by base pattern. Both normalise
    to absent when empty (an empty overlay is world A), so `touches_of` derives from the keys.
    """

    patches: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    elastic: dict[str, ElasticEntry] = field(default_factory=dict)  # lint-shippable: ok — the manifest's own field name for the overlay's staged half


def parse_overlay(raw: Any, *, where: str = "overlay") -> Overlay:
    """Validate one overlay document into `Overlay`, naming the field that refused."""
    if raw is None:
        return Overlay()
    if not isinstance(raw, dict):
        raise FamilyError(f"{where} must be a mapping, got {type(raw).__name__}")
    unknown = sorted(set(raw) - {"patches", "elastic"})  # lint-shippable: ok — the manifest's own field name for the overlay's staged half
    if unknown:
        raise FamilyError(f"{where} names unknown field(s) {unknown}")
    return Overlay(patches=_parse_patches(raw.get("patches"), where),
                   elastic=_parse_elastic(raw.get("elastic"), where))  # lint-shippable: ok — the manifest's own field name for the overlay's staged half


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
            entities[entity] = _checked_fields(fields_, f"{where}.patches[{system!r}][{entity!r}]")
        if entities:
            out[system] = entities
    return out


def _check_entity(entity: Any, where: str, system: str) -> None:
    """Refuse an entity key outside `_ENTITY_RE`.

    Refused rather than escaped: the entity is written back as a mapping key, and one carrying
    structural or path syntax would be resolved differently by a later reader.
    """
    if not isinstance(entity, str) or not _ENTITY_RE.match(entity):
        raise FamilyError(
            f"{where}.patches[{system!r}] names entity {entity!r}, which is outside the entity "
            "domain — an entity is rendered as a KEY, so it may carry only alphanumerics and "
            "'.', '_', '-' after a leading alphanumeric")


def _checked_fields(fields_: Any, at: str) -> dict[str, Any]:
    """One entity's field table, refused as `FamilyError` unless it is a mapping keyed by str.

    YAML 1.1 reads a bare `on:`/`yes:`/`1:` key as a bool or int; unchecked, that would surface
    as pydantic's `ValidationError` from `Overlay(...)`, which no caller handles.
    """
    if not isinstance(fields_, dict):
        raise FamilyError(f"{at} must be a mapping of field to value")
    bad = [k for k in fields_ if not isinstance(k, str)]
    if bad:
        raise FamilyError(
            f"{at} names non-string field(s) {bad!r} — a field is a key in a model-authored "
            "document, and YAML reads a bare `on`/`yes`/`1` as something other than its "
            "spelling")
    return dict(fields_)


def _parse_elastic(raw: Any, where: str) -> dict[str, ElasticEntry]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise FamilyError(f"{where}.elastic must be a mapping, got {type(raw).__name__}")  # lint-shippable: ok — the manifest's own field name for the overlay's staged half
    out: dict[str, ElasticEntry] = {}
    for pattern, entry in raw.items():
        if not isinstance(pattern, str) or not pattern:
            raise FamilyError(f"{where}.elastic names a non-string base pattern {pattern!r}")  # lint-shippable: ok — the manifest's own field name for the overlay's staged half
        parsed = _parse_elastic_entry(entry, f"{where}.elastic[{pattern!r}]")  # lint-shippable: ok — the manifest's own field name for the overlay's staged half
        if parsed is not None:
            out[pattern] = parsed
    return out


def _parse_elastic_entry(entry: Any, at: str) -> ElasticEntry | None:
    """One base pattern's staged difference, or `None` when it stages nothing.

    Normalising empty to absent keeps `touches_of` derivable from the overlay's keys alone.
    """
    if entry is None:
        return None
    if not isinstance(entry, dict):
        raise FamilyError(f"{at} must be a mapping")
    unknown = sorted(set(entry) - {"inject", "exclude"})
    if unknown:
        raise FamilyError(f"{at} names unknown field(s) {unknown}")
    # `is None`, not `or`: `inject: {}` / `0` / `""` are falsy non-lists that must reach the
    # isinstance check and be refused, not coalesce to an empty injection.
    inject = entry.get("inject")
    inject = [] if inject is None else inject
    if not isinstance(inject, list) or any(not isinstance(d, dict) for d in inject):
        raise FamilyError(f"{at}.inject must be a list of documents")
    exclude = entry.get("exclude")
    if exclude is not None and not isinstance(exclude, (dict, list, str)):
        raise FamilyError(f"{at}.exclude must be a query document or null")
    if not inject and exclude is None:
        return None
    return ElasticEntry(inject=[dict(d) for d in inject], exclude=exclude)


def touches_of(overlay: Overlay) -> tuple[str, ...]:
    """The systems this overlay touches, derived on every read (a stored copy could drift).

    The patch systems plus the staged system when that half is non-empty, sorted.
    """
    systems = set(overlay.patches)
    if overlay.elastic:  # lint-shippable: ok — the manifest's own field name for the overlay's staged half
        systems.add(STAGED_SYSTEM)
    return tuple(sorted(systems))


# ---------------------------------------------------------------------------------------
# the world
# ---------------------------------------------------------------------------------------


@model(frozen=True)
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
    refuse_reserved_world_label(world_id, at=at)
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
    # would raise `TypeError` instead of the `FamilyError` `run.py --resume` catches.
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
    source_run_dir: str
    source_run_id: str
    branch_message_id: int
    fences_at: int
    as_of: dt.datetime
    continuation_prompt: str
    #: The base patterns the capture's own queries addressed, recorded by the launcher. Stored
    #: rather than re-derived so every later reader judges overlays against the same set; a
    #: source run that changed since would otherwise make a sibling refuse its own manifest.
    captured_patterns: tuple[str, ...]
    base_story: str
    discriminator: dict
    worlds: list[World]
    #: The episode tenant's configured corpus patterns the launcher judged the overlays against,
    #: recorded for the same reason as `captured_patterns`; no later reader resolves a tenant.
    configured_patterns: tuple[str, ...] = ()

    def world(self, world_id: str) -> World:
        for candidate in self.worlds:
            if candidate.world_id == world_id:
                return candidate
        raise FamilyError(
            f"the manifest declares no world {world_id!r}; it declares "
            f"{[w.world_id for w in self.worlds]}")


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
    for scalar in ("episode_id", "source_run_dir", "source_run_id", "continuation_prompt",
                   "base_story"):
        if not isinstance(doc.get(scalar), str) or not doc.get(scalar):
            raise FamilyError(f"the manifest's {scalar} must be a non-empty string")
    for number in ("branch_message_id", "fences_at"):
        value = doc.get(number)
        if not isinstance(value, int) or isinstance(value, bool):
            raise FamilyError(f"the manifest's {number} must be an integer")


def _parse_worlds(raw_worlds: Any) -> list[World]:
    """The declared worlds: non-empty, with exactly one base (the control)."""
    if not isinstance(raw_worlds, list):
        raise FamilyError(
            f"the manifest's worlds must be a list, got {type(raw_worlds).__name__}")
    if not raw_worlds:
        raise FamilyError(
            "the manifest declares no worlds — the questioner's flow produces the base plus "
            "two by construction, and the family would have nothing to run")
    worlds = [parse_world(entry) for entry in raw_worlds]
    bases = [w.world_id for w in worlds if w.role == BASE_ROLE]
    if len(bases) != 1:
        raise FamilyError(
            f"exactly one world must carry the base role {BASE_ROLE!r}; {len(bases)} do "
            f"({bases}) — the base is the control every other world is compared against")
    return worlds


def _check_overlay_keys(
    worlds: list[World], captured_patterns: tuple[str, ...],
    configured_patterns: tuple[str, ...],
) -> None:
    """Every staged overlay key names a configured pattern or one the capture's FROM names.

    An invented pattern would stage a difference no query in this episode can observe.
    """
    allowed = set(captured_patterns) | set(configured_patterns)
    for world in worlds:
        for pattern in world.overlay.elastic:  # lint-shippable: ok — the manifest's own field name for the overlay's staged half
            if pattern not in allowed:
                raise FamilyError(
                    f"worlds[{world.world_id!r}].overlay.elastic names {pattern!r}, which is "  # lint-shippable: ok — the manifest's own field name for the overlay's staged half
                    "neither a configured corpus pattern nor one the capture's own FROM "
                    f"sources name ({sorted(allowed)})")



def _parse_captured_patterns(raw: Any, *, field: str = "captured_patterns") -> tuple[str, ...]:
    """A recorded pattern list (`captured_patterns` or `configured_patterns`), deduplicated.

    Absent is empty (older manifests lack the field). A present value that is not a list of
    non-empty strings is refused rather than read as empty.
    """
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise FamilyError(
            f"the manifest's {field} must be a list, got {type(raw).__name__}")
    out: list[str] = []
    for entry in raw:
        if not isinstance(entry, str) or not entry:
            raise FamilyError(
                f"the manifest's {field} names {entry!r}, which is not a pattern")
        out.append(entry)
    return tuple(dict.fromkeys(out))

def parse_family(
    doc: Any, *, captured_patterns: tuple[str, ...] = (),
    configured_patterns: Callable[[], tuple[str, ...]] = lambda: (),
) -> Family:
    """Validate a raw manifest document into `Family`, naming the field that refused.

    `captured_patterns` are the capture's FROM sources; `configured_patterns` supplies the
    tenant's corpus patterns (this loader reads no settings). An overlay's staged half may key
    only one of those. Sets recorded in the document win over the arguments, so a re-reader
    judges against what authored it. `configured_patterns` is called only for a manifest that
    records no configured set; a reader passing none admits only the captured set.
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
    envelope = discriminator.get("envelope")
    # The envelope is a model-authored call the review runs before any ledger could refuse it.
    if isinstance(envelope, dict):
        try:
            _json_safe_params(envelope.get("params"), field="discriminator.envelope.params")
        except ParamsTooDeep as too_deep:
            raise FamilyError(f"the manifest's {too_deep}") from too_deep
    as_of = parse_as_of(doc.get("as_of"))
    worlds = _parse_worlds(doc.get("worlds"))
    # The document's own record first: only the authoring call, which has no record yet, relies
    # on the argument.
    recorded = _parse_captured_patterns(doc.get("captured_patterns"))
    recorded_configured = _parse_captured_patterns(
        doc.get("configured_patterns"), field="configured_patterns")
    configured = recorded_configured or tuple(configured_patterns())
    _check_overlay_keys(worlds, recorded or tuple(captured_patterns), configured)
    return Family(
        episode_id=doc["episode_id"], source_run_dir=doc["source_run_dir"],
        source_run_id=doc["source_run_id"], branch_message_id=doc["branch_message_id"],
        fences_at=doc["fences_at"], as_of=as_of,
        continuation_prompt=doc["continuation_prompt"],
        captured_patterns=recorded or tuple(captured_patterns),
        base_story=doc["base_story"],
        discriminator=dict(discriminator), worlds=worlds,
        configured_patterns=configured,
    )


def runnable_worlds(family: Family) -> list[World]:
    """The worlds the launcher starts by default; the null replicate arm (`role: null`) loads but
    runs only when an operator asks for it."""
    return [w for w in family.worlds if w.role is not None]


def load_family(
    view: Bound, *, captured_patterns: tuple[str, ...] = (),
    configured_patterns: Callable[[], tuple[str, ...]] = lambda: (),
) -> Family:
    """Read and validate the manifest of the episode `view` is bound at."""
    return parse_family(_read_document(view), captured_patterns=captured_patterns,
                        configured_patterns=configured_patterns)


def _read_manifest(view: Bound) -> str:
    """The manifest's text, read through the view: nothing below the episode dir is followed,
    so a planted link is never read or certified. An absent or refused manifest is
    `FamilyError`, naming the record (a view holds no path)."""
    rec = view.read(LAYOUT.family)
    if rec.text is None:
        raise FamilyError(f"the manifest ({LAYOUT.family}) could not be read: "
                          f"{'absent' if rec.absent else rec.reason}")
    return rec.text


def _read_document(view: Bound) -> object:
    """The manifest deserialized but not yet narrowed; typed `object` so only `parse_family`
    produces a `Family`."""
    text = _read_manifest(view)
    try:
        return _yaml.safe_load(text)
    except yaml.YAMLError as bad:
        raise FamilyError(f"the manifest ({LAYOUT.family}) could not be read: {bad}") from bad


def write_family(episode: Episode, doc: dict) -> Path:
    """Render the manifest into `episode` through a structured dumper, never by hand.

    Scalars are model-authored; an f-string writer would let one carrying `episode_id: hijacked`
    on a second line inject a key.
    """
    manifest = episode.family
    manifest.write(
        _yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False))
    return manifest.path


def manifest_digest(view: Bound) -> str:
    """The manifest's content digest, recorded in the review and re-checked on resume.

    Uses the same read as `_read_document`, so a planted link is never certified.
    """
    return hashlib.sha256(_read_manifest(view).encode("utf-8")).hexdigest()


def check_manifest_digest(view: Bound, recorded: str) -> None:
    """Refuse a manifest whose bytes changed since the review recorded them."""
    actual = manifest_digest(view)
    if actual != recorded:
        raise FamilyError(
            f"the manifest ({LAYOUT.family}) has a digest of {actual[:12]} but the review "
            f"recorded {str(recorded)[:12]} — a manifest edited between review and run is not "
            "the document the review accepted")


# ---------------------------------------------------------------------------------------
# identity: one gate, before anything is staged
# ---------------------------------------------------------------------------------------

def refuse_reserved_world_label(label: str, *, at: str) -> None:
    """Refuse a reserved label; called wherever a world is parsed, not only by the launcher.
    The rule and its words are `_world_label.reserved_label_fault`'s."""
    if (why := reserved_label_fault(label, at=at)) is not None:
        raise FamilyError(why)


def check_identities(family: Family) -> None:  # noqa: C901 — one gate over the whole manifest, kept together
    """One gate over every identity rule, before anything is staged.

    Each rule would otherwise refuse downstream after a primed episode and running siblings: the
    label must name a view and a run, labels must be distinct case-folded and not reserved,
    roles must be distinct, and each composed world token must be nameable.
    """
    # Roles first: that rule is the family's, and two arms sharing a role make every report
    # unreadable — the more fundamental fault to report.
    roles: dict[str, str] = {}
    for world in family.worlds:
        if world.role is None:
            continue
        if world.role in roles:
            raise FamilyError(
                f"worlds {roles[world.role]!r} and {world.world_id!r} both declare role "
                f"{world.role!r} — a family is a set of DIFFERENT worlds, and two arms sharing "
                "a role cannot be told apart in any report")
        roles[world.role] = world.world_id
    seen: dict[str, str] = {}
    token_head = episode_token_for(family.episode_id)
    for world in family.worlds:
        label = world.world_id
        # Defense in depth: `parse_world` already refuses this, but a `Family` can be built
        # directly.
        refuse_reserved_world_label(label, at="")
        try:
            refuse_unnameable_world(label)
        except ViewNameError as bad:
            raise FamilyError(f"world label {label!r} cannot name a view: {bad}") from bad
        # The label must also name a run: each sibling's run dir is `{episode_id}-{label}`. The
        # view and run-id grammars overlap but neither contains the other (the view rule admits
        # `wörld`, `a+b`, `a:b`), and the label is model-authored, so one off the run-id grammar
        # would otherwise fail in every child after the family is staged.
        if (why := run_name_fault(f"{family.episode_id}-{label}")) is not None:
            raise FamilyError(
                f"world label {label!r} cannot name this episode's sibling run: {why} — each "
                "sibling is a run dir named for its world, so a label the runs repository would "
                "not admit as a run name (its length and the sidecar shapes included) is "
                "refused by every child after the whole family has been authored, staged and "
                "reviewed")
        folded = label.casefold()
        if folded in seen:
            raise FamilyError(
                f"world labels {seen[folded]!r} and {label!r} are one label wherever the "
                "filesystem folds case, and each names a run dir, a ledger file and a staged "
                "corpus")
        seen[folded] = label
        # Check the composed token itself, built the same way the comparing sites build it.
        token = world_token_for(token_head, label)
        try:
            refuse_unnameable_world(token)
        except ViewNameError as bad:
            raise FamilyError(f"world token {token!r} does not round-trip: {bad}") from bad


def episode_token_for(episode_id: str) -> str:
    """The episode's own token: the id with `-` folded to `.`, injectively.

    The run-id grammar admits `-`, `_` and `.`, so `_` escapes to `__` and `.` to `_p` before
    `-` folds onto `.`; otherwise two ids (e.g. `...-2026.01-n5` and `...-2026-01-n5`) would
    share a token, and the sweep would tear down one episode's live names for another's.

    Takes no override: an episode's namespace derives from its id alone, and ids this could
    refuse are already refused by `refuse_bad_episode_id`.
    """
    # Casefolded because an alias cannot carry upper case, and the cluster answers such a view
    # with an empty result rather than an error. Injectivity holds for launcher-accepted ids,
    # which `refuse_bad_episode_id` requires to be case-stable.
    # Order matters: `_` doubles first, then `.` becomes `_p`, then `-` takes the freed `.`.
    escaped = episode_id.replace("_", "__").replace(".", "_p").replace("-", ".").casefold()
    return _nameable_token(escaped, f"episode id {episode_id!r}")


def _nameable_token(token: str, origin: str) -> str:
    """`token`, or the fault every alias built from it would have raised.

    Held to the world-id rule because the whole composed world token is rendered into an alias.
    """
    try:
        refuse_unnameable_world(token)
    except ViewNameError as bad:
        raise FamilyError(
            f"{origin} does not render to a nameable episode token ({bad}) — name a fresh "
            "source run or branch point; every world token and every staged alias is built "
            "from it") from bad
    if not token or not token[0].isalnum():
        raise FamilyError(
            f"{origin} does not render to a nameable episode token: {token!r} does not start "
            "with an alphanumeric")
    return token


def world_token_for(episode_token: str, world_label: str) -> str:
    """The one spelling of a world's identity: `f"{episode_token}.{label}"`.

    Used by every site that compares worlds (alias head, ledger filename and rows, applier). The
    label may not contain `.`: the episode token already does, so a dotted label would let two
    (episode, label) pairs compose to one token.
    """
    if "." in world_label:
        raise FamilyError(
            f"world label {world_label!r} carries '.', the world token's own delimiter — "
            "two distinct (episode, label) pairs would compose to one world token")
    return f"{episode_token}.{world_label}"


@model(frozen=True)
class ResumeWorld:
    """What a sibling process is, from the manifest alone.

    `world_id` is the composed token, not the short label: the estate seam turns it into alias
    names, ledger filenames and row keys, which must carry the episode. `label` is what the
    manifest, run id and archive directory are keyed on.
    """

    world_id: str
    label: str
    episode_dir: Path
    overlay: Overlay
    as_of: dt.datetime
    family: Family

    @property
    def token(self) -> str:
        """The composed world token (same as `world_id`)."""
        return self.world_id

    @property
    def touches(self) -> tuple[str, ...]:
        """Derived from the overlay on every read."""
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
    """The world `world_label` names in `family`, or the fault that says it declares none.

    Called before the run dir is materialised, so an operator typo leaves no empty run dir.
    """
    world = family.world(world_label)
    return ResumeWorld(
        world_id=world_token_for(episode_token_for(family.episode_id), world_label),
        label=world_label, episode_dir=Path(episode_dir), overlay=world.overlay,
        as_of=family.as_of, family=family,
    )


def refuse_bad_episode_id(episode_id: str) -> None:
    """Refuse an episode id that cannot name a directory of its own.

    The id is joined into the episode dir's path and every sibling's run id, so it must be a
    run id with room for a sibling (`_run_id.episode_id_fault`, the one statement of the rule).
    """
    if (why := episode_id_fault(episode_id)) is not None:
        raise FamilyError(f"episode id {episode_id!r} is not usable: {why} — it names a "
                          "directory and half of every sibling's run id")


__all__ = [
    "BASE_ROLE",
    "ElasticEntry",
    "Family",
    "FamilyError",
    "LABEL_BASES",
    "Overlay",
    "PATCHABLE_SYSTEMS",
    "RESERVED_WORLD_LABELS",
    "ResumeWorld",
    "World",
    "check_identities",
    "check_manifest_digest",
    "episode_token_for",
    "is_contradiction",
    "is_reserved_world_label",
    "refuse_reserved_world_label",
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
