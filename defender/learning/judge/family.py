"""The judge's archive readers: per-world facts read off each world's own archived record.

Every fact reads ONE world's own `served/<world_token>.jsonl`, its archived
`report.md`/`investigation.md`, and the manifest — never `served/base.jsonl`, never a sibling,
never the comparator. Nothing here decides a bucket: the judge MODEL decides each world's bucket
from what these readers put in front of it (O11).

The manifest is read through the runtime loader's own gate (`load_manifest_document`), so a
manifest the sibling refuses — one predating the oracle, a label off the world-token rule — is
refused here too, plus a repeated key, which YAML would otherwise resolve silently.

Where a refusal stops: a fault in the MANIFEST (duplicate or case-colliding label, a label that
cannot name a directory or collides with a real run) refuses the whole pass, because the
manifest says which worlds there are. A fault in one world's own archive stops at that world:
absent inputs (tier 1) and malformed ones (tier 2) both mark it `ungradable` with no model call,
and a malformed world also carries `malformed: true`, so "not there" and "there and wrong" stay
distinguishable on the record.

This module is also the one home of the episode archive's record readers (`raw_manifest`,
`read_samples_record`, `read_world_facts`, `screened_yaml_mapping`) and the accessors in
`__all__`, shared by the judge's input builder (`render.py`) and the episode page. The world's
leads and queries come off `lead_repository.joined`.
"""

from __future__ import annotations

from collections.abc import Callable
import json
from dataclasses import field
from defender._model import model
from typing import Annotated, Any

from pydantic import SkipValidation

from pathlib import Path, PurePath, PurePosixPath

from defender._io import Bound, bind
from defender._report import ReportRead, parse_report_text
from defender._run_id import is_valid_run_id
from defender._vocab import normalized_disposition
from defender._episode_paths import LAYOUT, WORLD_LEAVES, EpisodePaths
from defender.learning.branch.ledger import (
    normalized_source,
    request_key,
)
from defender.learning.judge._errors import JudgeRefused
from defender.learning.lead_repository import JoinedLead, QueryRow, joined
from defender.runtime.branch._family import (
    BASE_ROLE,
    FamilyError,
    ManifestPredatesOracle,
    load_manifest_document,
    is_reserved_world_label,
    world_token_for,
)
from defender.runtime.circuit_breaker import DENIED_ERROR_CLASS, INFRA_ERROR_CLASS
from defender.runtime.run_end import RunEnd, parse_record
from defender.runtime.verbs import is_system_name
from defender._query_rules import (
    ABOVE_GUARD_QUERY_ID,
    BASH_SHIM_QUERY_ID,
    DENIED_QUERY_ID,
    REPEAT_TRIP_QUERY_ID,
)
from defender.skills.invlang._walkers import iter_resolutions
from defender.skills.invlang.parser import NO_OPEN_BLOCK, parse_dense_companion, scan_fences


def screened_yaml_mapping(
    bound: Bound, name: str | PurePath, *, what: str, empty_ok: bool = False,
) -> dict[str, Any] | None:
    """A YAML mapping at `name` (relative to `bound`) through the screened read, or `None`
    only when nothing is at the name.

    The episode dir is reachable from a sibling box's rw bind, so an entry at the name may be a
    planted link. Absent is an ordinary absence the caller decides about; anything present that
    is not the record (a link, an unreadable entry, a torn document, a non-mapping) is
    `JudgeRefused`, naming the relative name and never the operator's tree.

    `empty_ok`: a present document that YAML reads as `None` (empty, or `null`) is `{}` rather
    than a refusal — for a sample, "nothing recorded yet" and "present but empty" are the same."""
    import yaml

    from defender._yaml import safe_load

    rec = bound.read(name)
    if rec.absent:
        return None
    if rec.text is None:
        raise JudgeRefused(f"{what}: {rec.refusal}")
    try:
        doc = safe_load(rec.text)
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"{what}: {name} could not be read: {bad}") from bad
    if doc is None and empty_ok:
        return {}
    if not isinstance(doc, dict):
        raise JudgeRefused(f"{what}: {name} is not a mapping")
    return doc


def _default_samples_reader(bound: Bound, name: str | PurePath) -> dict[str, Any]:
    """`samples.yaml`, read permissively: absent, unreadable or unparseable all read as `{}`.

    A sample is evidence for narrow claims only, so a damaged file costs those claims their
    evidence, never the grade."""
    import yaml

    from defender._yaml import safe_load

    rec = bound.read(name)
    if rec.text is None:
        return {}
    try:
        doc = safe_load(rec.text) or {}
    except yaml.YAMLError:
        return {}
    return doc if isinstance(doc, dict) else {}


def read_samples_record(bound: Bound, *, reader: Any = None) -> dict[str, Any]:
    """`samples.yaml`, parsed once per caller — the question-writer's real example answers keyed
    by served system (`{<system>: {verbs: {<verb>: [<answer>, ...]}}}` or `{<system>:
    {unavailable: <reason>}}`, O16), archived into the episode so it survives a pruned source
    run."""
    read = reader if reader is not None else _default_samples_reader
    return read(bound, LAYOUT.samples)


def raw_manifest(episode_dir: Path) -> dict[str, Any]:
    """The manifest as a mapping, or `JudgeRefused`.

    Screened like the launcher's own read: the episode dir is box-reachable, and a link the
    launcher refuses must not be one the grader honours. Absent is a refusal too."""
    with bind(Path(episode_dir)) as bound:
        return read_manifest(bound)


def read_manifest(bound: Bound) -> dict[str, Any]:
    """`raw_manifest` through the pass's own bound reader: the runtime loader's own gate
    (`_family.load_manifest_document`), so a manifest the sibling refuses — one predating the
    oracle, a label off the world-token rule, a hostile system name — is refused here too,
    before any of it reaches a prompt or a page. A repeated key is refused as well: YAML keeps
    the last spelling silently, and the judge and the page must not read a document whose
    meaning depends on which copy won.

    The refusal is `JudgeRefused` raised FROM the loader's `FamilyError`, so a caller can tell
    an archive of the old design (`ManifestPredatesOracle` as the cause) from a damaged one."""
    from defender._yaml import duplicate_key_paths

    try:
        doc = load_manifest_document(bound)
    except ManifestPredatesOracle as old:
        raise JudgeRefused(str(old)) from old
    except FamilyError as refused:
        raise JudgeRefused(f"the manifest ({LAYOUT.family}) is unreadable: {refused}") from refused
    rec = bound.read(LAYOUT.family)
    repeated = duplicate_key_paths(rec.text) if rec.text is not None else ()
    if repeated:
        raise JudgeRefused(
            f"the manifest ({LAYOUT.family}) is unreadable: it repeats key(s) {list(repeated)} — "
            "YAML would keep the last copy silently")
    return doc


def leads_by_id(world_dir: Path) -> dict[str, JoinedLead]:
    """The world's leads off `lead_repository.joined` over the archived world dir, indexed by
    lead id, in one parse per world.

    Link refusal is the surface's own, applied separately to the lead files and the queries
    table, so a bad table leaves every lead with its goal and no queries."""
    return {lead.lead_id: lead for lead in joined(world_dir)}


#: The `kind` word the leads view gives each sentinel origin, keyed on the writer's literal;
#: an unknown `∅.` id renders as the bare `refused`. `∅.above-repeat-guard` splits on
#: `error_class`: `infra` is an adapter-load fault, `agent-fixable` a schema rejection or an
#: undeclared name. Model-facing only.
_SENTINEL_KINDS: dict[str, str] = {
    REPEAT_TRIP_QUERY_ID: "repeat-refused",
    BASH_SHIM_QUERY_ID: "reducer-failed",
    DENIED_QUERY_ID: "denied",
}
_ADAPTER_FAULT_KIND = "adapter-fault"
_REJECTED_KIND = "rejected-before-dispatch"
_UNKNOWN_SENTINEL_KIND = "refused"
_DENIED_KIND = _SENTINEL_KINDS[DENIED_QUERY_ID]

#: Error classes of a refusal that was the harness's or estate's doing, not the defender's: an
#: adapter that could not load or a shim the box killed (`infra`), and an ungranted verb
#: (`denied`). The row's writer already decided this when it chose the exit code, so it is read
#: off `error_class` alone rather than a second table keyed on origin.
_EXTERNAL_ERROR_CLASSES = frozenset({INFRA_ERROR_CLASS, DENIED_ERROR_CLASS})


def is_external_refusal(row: QueryRow) -> bool:
    """Was this `∅.` row's refusal the harness's or the estate's doing rather than the
    defender's? Printed as `external=` in the leads view."""
    return row.error_class in _EXTERNAL_ERROR_CLASSES


def _name_or_blank(name: str) -> str:
    """`name` when it is shaped like a system/verb name, else `""`.

    The queries table is box-writable, so a row's "name" may be arbitrary prose; this keeps free
    text out of the prompt. Shape only — membership is not checked."""
    return name if is_system_name(name) else ""


def _refused_from_sentinel(row: QueryRow) -> dict[str, Any]:
    """One `refused` entry off a `∅.` row, named columns only.

    `verb` appears only on a `denied` row: elsewhere it is the model's raw string, while a
    denial names a verb the adapter declares."""
    external = is_external_refusal(row)
    if row.query_id == ABOVE_GUARD_QUERY_ID:
        kind = _ADAPTER_FAULT_KIND if external else _REJECTED_KIND
    else:
        kind = _SENTINEL_KINDS.get(row.query_id, _UNKNOWN_SENTINEL_KIND)
    entry: dict[str, Any] = {"kind": kind, "system": _name_or_blank(row.system)}
    if kind == _DENIED_KIND:
        entry["verb"] = _name_or_blank(row.verb)
    entry["external"] = external
    return entry


def refused_entries(lead: JoinedLead | None) -> list[dict[str, Any]]:  # lint-owns: ok — `verbs.read_roster`'s `refused` is a different field under the same name
    """@owns refused — the `refused` link of the per-lead chain: every attempt the lead made
    that reached no system, off its `∅.` rows in the surface's seq order. `[]` for an unknown
    lead."""
    if lead is None:
        return []
    return [_refused_from_sentinel(row) for row in lead.sentinels]


def has_refusals(lead: JoinedLead) -> bool:
    """Would `refused_entries(lead)` be non-empty?"""
    return bool(lead.sentinels)


def render_refused(entries: list[dict[str, Any]]) -> str:
    """The `refused:` line's value as the prompt prints it: `[]`, or
    `[kind=denied system=ticket verb=get-ticket external=true]` per entry, comma-separated.

    Not the list's `repr`: the judge prompt's rule is keyed on the lowercase `external=true` /
    `external=false` spelling."""
    if not entries:
        return "[]"
    def _v(v: Any) -> str:
        return str(v).lower() if isinstance(v, bool) else str(v)
    return "[" + ", ".join(
        " ".join(f"{k}={_v(v)}" for k, v in entry.items()) for entry in entries
    ) + "]"


def lead_chain(world: Bound, lead_id: str, resolutions_by_lead: dict[str, list[dict]],
               *, leads: dict[str, JoinedLead]) -> dict[str, Any]:
    """One lead's chain for the leads view: goal -> params -> payload -> refused -> summary ->
    resolutions. `leads` is `leads_by_id` computed once by the caller; `world` is the world's
    own sub-bind.

    `refused` shows attempts that reached no system, so a lead that was only refused does not
    read as one that never queried. Every link is a named `QueryRow` field; raw rows are never
    stringified into the prompt, where they would spend the payload cap on unusable bytes."""
    # The id is model-authored and becomes a path here: a traversing token would put another
    # world's files into this world's prompt as facts about it.
    safe = names_one_file(lead_id)
    lead = leads.get(lead_id)
    goal = lead.goal if lead is not None else None
    queries = lead.queries if lead is not None else []
    params = queries[0].params if queries else None
    # `world.read` walks no-follow from the world's own handle, so a linked directory or leaf is
    # refused by the read itself.
    summary = None
    if not safe:
        summary = ("(this lead id does not name a file inside this world, so no gather summary "
                   "was read for it)")
    else:
        # Model-written text in a box-writable tree: an undecodable byte is ordinary, and a
        # refused read becomes the summary text (world-relative name only) rather than failing
        # the episode.
        name = WORLD_LEAVES.gather_summary(lead_id)
        rec = world.read(name, errors="replace")
        if rec.text is not None:
            summary = rec.text
        elif not rec.absent:
            summary = f"(the gather summary: {name} could not be read: {rec.reason})"
    return {
        "goal": goal, "params": params, "payload": [q.payload_digest for q in queries],
        "summary": summary,
        "resolutions": resolutions_by_lead.get(lead_id, []),
        "refused": refused_entries(lead),
    }


def json_mapping(bound: Bound, name: str | PurePath) -> dict[str, Any] | None:
    """One JSON artifact at `name` (relative to `bound`) as a mapping, or `None` when it is
    absent, unreadable, undecodable or not a mapping.

    The one home for both the tolerance policy and the link policy: these files sit in a
    box-reachable tree, and a followed link at e.g. `provenance.json` would hand the pass an
    attacker-chosen commit. The bound read never follows a link at the name or above it."""
    return json_mapping_of(bound.read(name).text)


def json_mapping_of(text: str | None) -> dict[str, Any] | None:
    """`json_mapping`'s parse half over bytes a caller has already read (`None` for none)."""
    if text is None:
        return None
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def episode_id_of(doc: dict[str, Any]) -> str:
    """The manifest's `episode_id`, or `JudgeRefused` (a bare `KeyError` is not a class the
    entry point converts into a refusal)."""
    episode_id = doc.get("episode_id")
    if not isinstance(episode_id, str) or not episode_id:
        raise JudgeRefused("the manifest's episode_id is not a usable string")
    return episode_id


def discriminator_of(doc: dict[str, Any]) -> dict[str, Any]:
    """The manifest's `discriminator` block as a mapping, `{}` when it is not one (including
    present-but-null)."""
    block = doc.get("discriminator")
    return block if isinstance(block, dict) else {}


def _control_declared(doc: dict[str, Any]) -> Any:
    for world in doc.get("worlds") or ():
        if isinstance(world, dict) and world.get("role") == BASE_ROLE:
            return world.get("disposition_declared")
    return None


def _non_control_worlds(doc: dict[str, Any]) -> list[dict[str, Any]]:
    raw = doc.get("worlds")
    if not isinstance(raw, list):
        raise JudgeRefused("the manifest's worlds is not a list")
    # A model-authored list can hold non-mapping entries. Dropping them silently would grade a
    # family missing an arm as though complete, so the residue refuses the pass.
    entries = [w for w in raw if isinstance(w, dict)]
    dropped = [w for w in raw if not isinstance(w, dict)]
    if dropped:
        raise JudgeRefused(
            f"the manifest's worlds list holds {len(dropped)} entr"
            f"{'y' if len(dropped) == 1 else 'ies'} that are not mappings ({dropped[:3]!r}) — "
            "a world entry is an object, and dropping one silently would grade a family that "
            "is missing an arm as though the arm had never been declared")
    seen: dict[str, str] = {}
    for entry in entries:
        label = entry.get("world_id")
        if not isinstance(label, str) or not label:
            raise JudgeRefused("a world entry carries no world_id")
        folded = label.casefold()
        if folded in seen and seen[folded] != label:
            raise JudgeRefused(
                f"world labels {seen[folded]!r} and {label!r} are one label wherever the "
                "filesystem folds case — the manifest is refused rather than picking either "
                "entry silently")
        if folded in seen:
            raise JudgeRefused(
                f"two world entries both carry the label {label!r} — the manifest is ambiguous "
                "at the one join every per-world fact goes through")
        seen[folded] = label
    return [w for w in entries if w.get("role") != BASE_ROLE]


def world_label_names_directory(episode_id: str, label: str) -> bool:
    """Whether `label` may be joined into a per-world path (`worlds/<label>/…`,
    `runs/<episode_id>-<label>/`); shared by the grading pass and the episode page.

    Both spellings are checked: the launcher checks only the concatenation, whose first
    character is the episode id's, so `..` would pass it and turn `worlds/<label>` into the
    episode dir."""
    return is_valid_run_id(label) and is_valid_run_id(f"{episode_id}-{label}")


def _check_world_labels(
    episode_id: str, worlds: list[dict[str, Any]], *, runs_base: Path | None,
) -> None:
    """Refuse a world label that cannot be used as a name, before any path is built from it.

    - Reserved labels (`base`, `family`, `family_<n>`): re-checked here because `grade_episode`
      can run over an episode that never passed the launcher, and a world labeled `family`
      would collide with the family-level call's finding ids and archive path.
    - The label must name a directory (`world_label_names_directory`): it is model-authored and
      joined straight into every per-world path.
    - It must not collide with a real run under the runs base, which the last-segment resolver
      for `source_run_dir` would otherwise resolve to wrong-but-real content."""
    for world in worlds:
        label = world.get("world_id")
        if isinstance(label, str) and is_reserved_world_label(label):
            raise JudgeRefused(
                f"world label {label!r} is reserved — it is the family's own base capture, the "
                "family-level judge call, or one of that call's own `family_<n>` draws — a "
                "graded world claiming it would collide with the family call's own agent id "
                "and archive path (M5)")
        if isinstance(label, str) and not world_label_names_directory(episode_id, label):
            raise JudgeRefused(
                f"world label {label!r} cannot name a directory of its own, or this episode's "
                f"sibling run ({episode_id}-{label}) — the label is joined straight into every "
                "per-world path this pass reads and writes, so a label off that grammar reads "
                "and writes outside the world it names")
    if runs_base is None:
        return
    base = Path(runs_base)
    for world in worlds:
        label = world.get("world_id")
        # Wider than `is_dir()`: anything at the name (a file, a link, a broken link) is
        # reachable by the resolver, and `is_dir()` would follow a planted link.
        if isinstance(label, str) and (
                (base / label).exists() or (base / label).is_symlink()):
            raise JudgeRefused(
                f"world label {label!r} collides with a real run under the operator's runs "
                f"base ({base / label}) — a family row's source_run_dir naming this label "
                "would resolve to that run's content rather than this world's own archive; "
                "rename one of the two")


def mapping_key(mapping: dict[str, Any]) -> str:
    """The canonical `(system, verb, params)` key of any mapping carrying those three.

    Shared by every reader that dedups served ledger rows by call."""
    params = mapping.get("params")
    return request_key(str(mapping.get("system") or ""), str(mapping.get("verb") or ""),
                       params if isinstance(params, dict) else {})


def names_one_file(lead_id: object) -> bool:
    """Is `lead_id` a single path component this pass may join into a path?

    Lead ids are model-authored (any token in a `:T resolutions` row). A separator or `..` would
    read out of the graded world — e.g. a sibling's `report.md`, disposition included — into
    this world's prompt. The row is still carried as evidence; only the path is refused. NUL is
    barred because the bound primitive raises on it."""
    return (isinstance(lead_id, str) and bool(lead_id) and "\x00" not in lead_id
            and lead_id not in (".", "..") and lead_id == Path(lead_id).name)


def summary_lead_ids(world: Bound) -> set[str]:
    """The stem of every regular `*.md` file in the world's `gather_summaries/` (a link, a
    directory or a bare `.md` names none). Shared by the judge prompt and the page."""
    summaries = world.under(WORLD_LEAVES.gather_summaries).entries()
    return {name[:-3] for name in summaries.files() if name.endswith(".md") and len(name) > 3}


def scope_params(row: dict[str, Any]) -> dict[str, Any]:
    """A served row's params as asked — `asked_params` when present, `params` otherwise.

    Shared so no reader scores a retargeted index as the scope the model asked for."""
    asked = row.get("asked_params")
    params = asked if isinstance(asked, dict) else row.get("params")
    return params if isinstance(params, dict) else {}


def _read_world_ledger(
    bound: Bound, name: str, world_token: str,
) -> tuple[list[dict[str, Any]], int, Any]:
    """This world's own decision rows, first-row-wins on a duplicate key; a malformed line
    (unparseable, or a `source` outside the ledger's decision words) is skipped and counted.

    Absent is returned as the read's absent state for the caller to decide; only a refused
    read (e.g. a link at the name) raises `JudgeRefused`."""
    rows, malformed, rec = bound.read_jsonl(name)
    if rec.refusal is not None:
        raise JudgeRefused(f"the ledger could not be read: {rec.refusal}")
    kept: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in rows:
        if normalized_source(row.get("source")) is None:
            malformed += 1
            continue
        if row.get("world_id") != world_token:
            # A family-tier row or another world's row: inert here, and not malformed.
            continue
        key = mapping_key(row)
        if key not in kept:
            kept[key] = row
            order.append(key)
    return [kept[k] for k in order], malformed, rec


def _resolution_facts(
    text: str, *, world: str,
) -> tuple[bool, dict[str, list[dict[str, Any]]], tuple[str, ...]]:
    """`resolution_moved`, the document's resolution rows grouped by lead id, and everything
    the read could not land.

    Rows come from the invlang parser, which owns what a `:T resolutions` row is; the lead is
    the enclosing finding's id. `before != after` on any row counts as moved ("was the hand-off
    revisited", not "did the net state move"). An unclosed fence refuses (the caller contains
    it to this world).

    The complement is returned, not dropped: orphaned headers, unparseable rows and rows with no
    lead id, so the caller can put them on the record."""
    scan = scan_fences(text)
    if scan.open_tail is not None:
        raise JudgeRefused(
            f"world {world!r}: investigation.md has an unclosed invlang fence — a truncated "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "document cannot be graded")
    companion, warnings = parse_dense_companion(text)
    moved = False
    by_lead: dict[str, list[dict[str, Any]]] = {}
    # The parser's complement too. `NO_OPEN_BLOCK` is included because a resolutions block whose
    # header line the tokenizer refused (e.g. a trailing comment on it) files every row under
    # that name; without it the whole block would vanish silently.
    unlanded = [
        f"the invlang parser could not read a `{w.block}` row: {w.reason}" for w in warnings
        if getattr(w, "block", "").startswith(":T resolutions")
        or getattr(w, "block", "") == NO_OPEN_BLOCK
    ]
    for lead_id, row in iter_resolutions(companion):
        if not isinstance(lead_id, str) or not lead_id:
            unlanded.append(
                f"a resolution row carries no lead id to group it under: {dict(row)!r}")
            continue
        if not names_one_file(lead_id):
            # Kept, but no path is built from it; the record names the row.
            unlanded.append(
                f"a resolution row's lead id {lead_id!r} does not name a file inside this "
                "world, so no per-lead artifact was read for it")
        by_lead.setdefault(lead_id, []).append(dict(row))
        before, after = row.get("before"), row.get("after")
        if before is not None and after is not None and before != after:
            moved = True
    return moved, by_lead, (*scan.orphaned_headers, *unlanded)


def _read_archived_text(bound: Bound, name: str | PurePath, *, world: str, role: str) -> Any:
    """One archived document through the world-archive screen. Absent is returned as the
    read's `.absent` state; a refused read (link, hard link, undecodable) raises
    `JudgeRefused` naming the relative name, never the operator's tree."""
    rec = bound.read(name)
    if rec.refusal is not None:
        raise JudgeRefused(f"world {world!r}: {rec.refusal}")
    return rec


def _read_verdict(report: ReportRead, *, world: str) -> str:
    """The world's archived headline as `_report` decided it, or `JudgeRefused`.

    `normalized_disposition` is exact, so a headline laced with e.g. a zero-width character
    arrives as `None` and is refused rather than coerced."""
    if report.disposition is None:
        raise JudgeRefused(
            f"world {world!r}: {report.reason or 'report.md carries no usable disposition'}")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    return report.disposition


def _check_gather_summaries(world: Bound, *, label: str, referenced_leads: frozenset[str]) -> None:
    """Refuse a world whose `gather_summaries/` is short of a lead its own document references
    — a partial archive, contained to this world. An absent directory is `_archive_notes`'
    business, not this check's."""
    summaries = world.under(WORLD_LEAVES.gather_summaries).entries()
    if summaries.entries is None:
        return
    # A traversing id names a file outside this world; it must not satisfy the check.
    missing = sorted(
        lead for lead in referenced_leads
        if names_one_file(lead) and not summaries.has_file(f"{lead}.md"))
    if missing:
        raise JudgeRefused(
            f"world {label!r}: gather_summaries/ is short {missing} — the archive left this "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "world's supporting directory short of a lead its own investigation.md references; "
            "refusing rather than grading on a thinner view than it appears to have")


@model(frozen=True)
class WorldFacts:
    """One world's archived record (ledger, investigation, report), read once per grading pass
    and shared between the pass and the render."""

    #: `SkipValidation`: the ledger is the largest thing a pass holds and `dict[str, Any]`
    #: checks nothing inside a row, so validation would only copy every row.
    ledger_rows: Annotated[list[dict[str, Any]], SkipValidation]
    malformed_rows: int
    investigation_text: str
    #: The report as `_report` read it, so no consumer re-decides the headline from the bytes.
    report: ReportRead
    resolution_moved: bool
    resolutions_by_lead: dict[str, list[dict[str, Any]]]
    #: What reading the document did not land (lines outside every fence, unparseable
    #: resolution rows, rows with no lead id) — evidence the pass could not see, for the record.
    unlanded_document_rows: tuple[str, ...] = ()
    #: The world's leads (`leads_by_id`); `{}` unless the caller passes `read_world_facts` a
    #: `leads` callable.
    leads: dict[str, JoinedLead] = field(default_factory=dict)

    @property
    def referenced_leads(self) -> frozenset[str]:
        """The lead ids this world's own `:T resolutions` rows name."""
        return frozenset(self.resolutions_by_lead)


def world_ledger_name(label: str, *, episode_token: str) -> str:
    """The relative name of a world's served ledger, shared by every reader and refusal."""
    return str(LAYOUT.served_world(world_token_for(episode_token, label)))


def _read_run_end_record(world: Bound) -> RunEnd | None:
    """The archived run-end record, or `None` when absent, unreadable or not a valid record.
    Interpretation is `run_end.parse_record`'s alone, shared with the ticket lane."""
    return parse_record(json_mapping(world, WORLD_LEAVES.run_end))


def read_archived_report(bound: Bound, name: str | PurePath) -> ReportRead:
    """`report.md` through the world-archive screen: a link, hard link or FIFO reads as a
    report with no headline (never followed); nothing at the name is `ReportRead.absent`.

    Never hands a path to `read_report`, whose `is_file()` + read would follow a link planted
    between screen and open; the bytes go through `parse_report_text` instead."""
    rec = bound.read(name)
    if rec.absent:
        return ReportRead(disposition=None, reason=None, frontmatter={}, body="", text="",
                          absent=True)
    if rec.text is None:
        return ReportRead(
            disposition=None,
            reason=f"{WORLD_LEAVES.report} could not be read: {rec.refusal}",
            frontmatter={}, body="", text="")
    return parse_report_text(rec.text)


@model(frozen=True)
class InvestigationFacts:
    """What one world's archived `investigation.md` says on its own. Separate from the ledger
    read so a reader wanting only the document (the episode page) does not lose it to a
    ledger refusal."""

    investigation_text: str
    resolution_moved: bool
    resolutions_by_lead: dict[str, list[dict[str, Any]]]
    unlanded_document_rows: tuple[str, ...] = ()
    #: Nothing at the name at all — distinct from an empty document.
    absent: bool = False

    @property
    def referenced_leads(self) -> frozenset[str]:
        """The lead ids this world's own `:T resolutions` rows name."""
        return frozenset(self.resolutions_by_lead)


def read_investigation_facts(bound: Bound, *, world: str) -> InvestigationFacts:
    """`worlds/<label>/investigation.md` alone: text and resolution facts, `.absent` when
    missing, `JudgeRefused` when present but unreadable."""
    name = LAYOUT.world(world).investigation
    rec = _read_archived_text(bound, name, world=world, role=str(WORLD_LEAVES.investigation))
    if rec.absent:
        return InvestigationFacts(
            investigation_text="", resolution_moved=False, resolutions_by_lead={}, absent=True)
    moved, by_lead, unlanded = _resolution_facts(rec.text, world=world)
    return InvestigationFacts(
        investigation_text=rec.text, resolution_moved=moved, resolutions_by_lead=by_lead,
        unlanded_document_rows=unlanded)


def read_world_ledger(bound: Bound, label: str, *, episode_token: str,
                      ) -> tuple[list[dict[str, Any]], int, Any]:
    """This world's served-ledger rows, malformed-row count and the read record. Refuses on an
    unreadable ledger; a missing one is reported through the record's absent state."""
    return _read_world_ledger(bound, world_ledger_name(label, episode_token=episode_token),
                              world_token_for(episode_token, label))


def read_world_facts(bound: Bound, label: str, *, episode_token: str,
                     leads: Callable[[], dict[str, JoinedLead]] | None = None,
                     absent_ledger_ok: bool = False) -> WorldFacts:
    """Read one world's archived record — ledger, then document, then report — for the
    grading path. Unlike the standalone readers, an absent input refuses here: grading has
    nothing to return for a world it cannot see.

    `absent_ledger_ok` reads an absent served ledger as no calls. The pass sets it: whether a
    world ran is its own record's to say (`world_records/`, S8), so an archived world with no
    ledger is one whose investigator made no call that reached it.

    `leads` is deferred (`leads_by_id` takes a `Path`, not a bound reader) and runs only after
    the three reads pass, so a planted link at `worlds/<label>` is refused by the document read
    first. Set on the one construction because `dataclasses.replace` on a `@model` would copy
    the whole ledger."""
    ledger_name = world_ledger_name(label, episode_token=episode_token)
    ledger_rows, malformed, ledger_read = read_world_ledger(bound, label, episode_token=episode_token)
    if ledger_read.absent and not absent_ledger_ok:
        raise JudgeRefused(f"the ledger ({ledger_name}) could not be read: nothing is at that name")
    document = read_investigation_facts(bound, world=label)
    if document.absent:
        raise JudgeRefused(
            f"world {label!r}: {LAYOUT.world(label).investigation} could not be read: "
            "nothing is at that name")
    report = read_archived_report(bound, LAYOUT.world(label).report)
    if report.absent:
        raise JudgeRefused(
            f"world {label!r}: {LAYOUT.world(label).report} could not be read: "
            "nothing is at that name")
    return WorldFacts(
        ledger_rows=ledger_rows, malformed_rows=malformed,
        investigation_text=document.investigation_text,
        report=report,
        resolution_moved=document.resolution_moved,
        resolutions_by_lead=document.resolutions_by_lead,
        unlanded_document_rows=document.unlanded_document_rows,
        leads=leads() if leads is not None else {},
    )


def _archive_notes(world: Bound, *, facts: WorldFacts) -> list[str]:
    """What this world's archive is missing without being malformed, as notes for the record:
    document rows the read could not land, and `gather_summaries/` absent while the document
    names leads (absent is noted; short is refused by `_check_gather_summaries`)."""
    notes: list[str] = []
    if facts.unlanded_document_rows:
        first = facts.unlanded_document_rows[0].strip()
        notes.append(
            f"investigation.md has {len(facts.unlanded_document_rows)} row(s) or block(s) this "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"pass could not read ({first[:120]!r}…) — they are outside every invlang fence, "
            "unreadable to the parser, or carry no lead id, so this world's resolution facts "
            "are read from what landed alone")
    if facts.referenced_leads and world.under(WORLD_LEAVES.gather_summaries).entries().entries is None:
        notes.append(
            f"gather_summaries/ is absent while investigation.md names "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"{sorted(facts.referenced_leads)} — this world is graded on a thinner view than "
            "its own document claims")
    return notes


def _missing_required_input(
    bound: Bound, *, label: str, ledger_name: str, declared: Any, run_inputs_required: bool = True,
) -> str | None:
    # Each input must be a regular file in its parent's listing (never followed): the tree is
    # box-writable, so a link counts as missing. An absent parent means its first input is
    # missing; a parent that exists but cannot be listed decides nothing here — the read that
    # follows refuses it as malformed. `run_inputs_required=False` is the pass's own reading:
    # the served ledger (absent: no call reached it, `read_world_facts`' `absent_ledger_ok`)
    # and the alert (absent: the sibling union and rule key fall back) are not required —
    # whether a world ran is its own record's to say (S8).
    served_dir = LAYOUT.served
    served = bound.under(served_dir).entries()
    if run_inputs_required and (served.absent or (
            served.entries is not None
            and not served.has_file(str(PurePosixPath(ledger_name).relative_to(served_dir))))):
        return f"served ledger ({ledger_name})"
    world = bound.under(LAYOUT.world(label).dir).entries()
    if world.absent or (world.entries is not None
                        and not world.has_file(WORLD_LEAVES.report.name)):
        return str(WORLD_LEAVES.report)
    if world.entries is not None:
        if not world.has_file(WORLD_LEAVES.investigation.name):
            return str(WORLD_LEAVES.investigation)
        if run_inputs_required and not world.has_file(WORLD_LEAVES.alert.name):
            return str(WORLD_LEAVES.alert)
    if not isinstance(declared, str) or not declared:
        return "disposition_declared"
    return None


def read_world(  # noqa: PLR0911 — one tier rule, one return per way a world is set aside
    bound: Bound, world: dict[str, Any], *, episode_dir: Path, episode_token: str,
) -> tuple[dict[str, Any], WorldFacts | None]:
    """One non-control world's row and archived facts, or the row alone marked `ungradable`
    when the archive cannot be put in front of the judge (cut short, an input missing, a
    malformed input). Decides no bucket.

    @owns ungradable — the sole producer of a world row's `ungradable`/`ungradable_reason`/
    `malformed` from its archive (the pass adds the O5 failed worlds' rows itself)."""
    label = world["world_id"]
    raw_declared = world.get("disposition_declared")
    row: dict[str, Any] = {"world": label, "declared": normalized_disposition(raw_declared)}
    ledger_name = world_ledger_name(label, episode_token=episode_token)

    # A world the host cut short before the model decided is never graded (its report is the
    # host's, not a verdict) — unless the model had already closed.
    end = _read_run_end_record(bound.under(LAYOUT.world(label).dir))
    if end is not None and end.truncated_by is not None and not end.closed_before_cut:
        row["ungradable"] = True
        row["cut_short"] = end.truncated_by
        row["ungradable_reason"] = (
            f"world {label!r}: its run ended {end.truncated_by!r} — the host's report is not "
            "a verdict")
        return row, None

    missing = _missing_required_input(
        bound, label=label, ledger_name=ledger_name, declared=raw_declared,
        run_inputs_required=False)
    if missing is not None:
        row["ungradable"] = True
        row["ungradable_reason"] = f"world {label!r} is missing its {missing}"
        return row, None
    if row["declared"] is None:
        row["ungradable"] = True
        row["ungradable_reason"] = (
            f"world {label!r}: the manifest's disposition_declared {raw_declared!r} is outside "
            "the disposition vocabulary — this world has no ground truth to grade against")
        return row, None

    world_bound = bound.under(LAYOUT.world(label).dir)
    try:
        facts = read_world_facts(
            bound, label, episode_token=episode_token,
            leads=lambda: _repository_leads(world_bound, Path(episode_dir), label),
            absent_ledger_ok=True)
        _check_gather_summaries(world_bound, label=label, referenced_leads=facts.referenced_leads)
        verdict = _read_verdict(facts.report, world=label)
    except JudgeRefused as malformed:
        row["ungradable"] = True
        row["malformed"] = True
        row["ungradable_reason"] = str(malformed)
        return row, None

    row.update(verdict=verdict, resolution_moved=facts.resolution_moved,
               malformed_rows=facts.malformed_rows, served_nothing=not facts.ledger_rows)
    notes = _archive_notes(world_bound, facts=facts)
    if notes:
        row["integrity_notes"] = notes
    return row, facts


def non_control_worlds(doc: dict[str, Any], *, runs_base: Path | None) -> list[dict[str, Any]]:
    """The manifest's non-control world entries, each label checked usable as a name
    (`_check_world_labels`) before any path is built from it."""
    worlds = _non_control_worlds(doc)
    _check_world_labels(episode_id_of(doc), worlds, runs_base=runs_base)
    return worlds


def _repository_leads(world: Bound, episode_dir: Path, label: str) -> dict[str, JoinedLead]:
    """`leads_by_id` over `worlds/<label>`, only once the bind's listing shows a real
    directory there."""
    listing = world.entries()
    if listing.entries is None:
        raise JudgeRefused(
            f"world {label!r}: {LAYOUT.world(label).dir} could not be listed: "
            f"{listing.reason or 'nothing is at that name'}")
    # `.at(...)`, not `.world(label)`: the minting accessor's case-stability rule would refuse
    # a declared label that names a real directory.
    return leads_by_id(EpisodePaths(episode_dir).at(LAYOUT.world(label).dir))


def is_gradable_row(row: Any) -> bool:
    """Did this world contribute to the family's word? Shared so every site treats a truthy
    non-`True` `ungradable` the same way."""
    return isinstance(row, dict) and not row.get("ungradable")


__all__ = [
    "InvestigationFacts", "WorldFacts",
    "discriminator_of", "episode_id_of",
    "is_gradable_row", "json_mapping", "json_mapping_of", "lead_chain", "leads_by_id", "mapping_key",
    "names_one_file", "non_control_worlds", "raw_manifest", "read_manifest",
    "refused_entries", "has_refusals", "render_refused", "is_external_refusal",
    "read_archived_report", "read_investigation_facts", "read_samples_record", "read_world",
    "read_world_facts", "read_world_ledger", "scope_params",
    "summary_lead_ids", "world_ledger_name",
    "screened_yaml_mapping", "world_label_names_directory",
]
