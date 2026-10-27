"""The judge's archive readers: per-world facts read off each world's own archived record."""

from __future__ import annotations

from collections.abc import Callable
import json
from dataclasses import field
from defender._model import model
from typing import Annotated, Any

from pydantic import SkipValidation

from pathlib import Path, PurePath

from defender._io import Bound
from defender.records._report import ReportRead, parse_report_text
from defender._vocab import normalized_disposition
from defender.records._episode_paths import LAYOUT, WORLD_LEAVES, EpisodePaths
from defender.learning.branch.ledger import (
    normalized_source,
)
from defender.learning.judge._errors import JudgeRefused
from defender.learning.lead_repository import JoinedLead, QueryRow, joined
from defender.records._family import (
    BASE_ROLE,
    FamilyError,
    ManifestPredatesOracle,
    load_manifest_document,
    parse_family,
)
from defender.systems.circuit_breaker import DENIED_ERROR_CLASS, INFRA_ERROR_CLASS
from defender.records.run_end import (
    TRUNCATED_BY_EXECUTED_QUERIES,
    TRUNCATED_BY_SERVED_LEDGER,
    RunEnd,
    parse_record,
)
from defender.kit.verbs import is_system_name
from defender.knowledge._query_rules import (
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
    only when nothing is at the name."""
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


def read_manifest(bound: Bound, *, expected_episode_id: str) -> dict[str, Any]:
    """The manifest as a mapping, or `JudgeRefused`, through the pass's own bound reader (the
    walked episode's view): the runtime loader's own gate (`_family.load_manifest_document`),
    so a manifest the sibling refuses — one predating the oracle, a label off the world-token
    rule, a hostile system name, an `episode_id` other than `expected_episode_id` (the folder
    it was read from, #1187 R5) — is refused here too, before any of it reaches a prompt or a
    page. A repeated key is refused as well: YAML keeps the last spelling silently, and the
    judge and the page must not read a document whose meaning depends on which copy won."""
    from defender._yaml import duplicate_key_paths

    try:
        doc = load_manifest_document(bound, expected_episode_id=expected_episode_id)
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







from defender.learning.judge._records import (
    _admitted_query_table as _admitted_query_table,
    _joined_row as _joined_row,
    _refuse_unwritable as _refuse_unwritable,
    mapping_key as mapping_key,
    read_call_join as read_call_join,
    read_call_records as read_call_records,
    read_query_table as read_query_table,
    read_served_ledger as read_served_ledger,
    world_ledger_name as world_ledger_name,
)



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
    """This world's own decision rows, every one kept in ledger order (A2: the ledger is read in
    full — two rows for one `(system, verb, params)` are two calls). A malformed line
    (unparseable, or a `source` outside the ledger's decision words) is skipped and counted; a
    row of another world (or none) is inert here. The lenient read, for the page;
    `read_call_records` is the grading read, which refuses either instead.

    Absent is returned as the read's absent state for the caller to decide; only a refused
    read (e.g. a link at the name) raises `JudgeRefused`."""
    rows, malformed, rec = bound.read_jsonl(name)
    if rec.refusal is not None:
        raise JudgeRefused(f"the ledger could not be read: {rec.refusal}")
    kept: list[dict[str, Any]] = []
    for row in rows:
        if normalized_source(row.get("source")) is None:
            malformed += 1
            continue
        if row.get("world_id") == world_token:
            kept.append(row)
    return kept, malformed, rec


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

    #: The host-minted world UUID carried by ledger rows and the run half of call IDs.
    token: str

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
    #: The grading read's extras (`read_world`, A3): the query table whole, the oracle store's
    #: forged rows, and the lead ids whose gather summary read plain. Empty off the page's reads.
    table_rows: Annotated[list[dict[str, Any]], SkipValidation] = field(default_factory=list)
    forged_rows: Annotated[list[dict[str, Any]], SkipValidation] = field(default_factory=list)
    summary_leads: frozenset[str] = frozenset()

    @property
    def referenced_leads(self) -> frozenset[str]:
        """The lead ids this world's own `:T resolutions` rows name."""
        return frozenset(self.resolutions_by_lead)


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
    """`worlds/<world-uuid>/investigation.md` alone: text and resolution facts, `.absent` when
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


def read_world_ledger(bound: Bound, world_id: str,
                      ) -> tuple[list[dict[str, Any]], int, Any]:
    """This world's served-ledger rows, malformed-row count and the read record. Refuses on an
    unreadable ledger; a missing one is reported through the record's absent state."""
    return _read_world_ledger(bound, world_ledger_name(world_id),
                              world_id)


def read_world_facts(bound: Bound, label: str, *, world_id: str,  # noqa: PLR0913 — the grading read's extras ride on the one construction
                     leads: Callable[[], dict[str, JoinedLead]] | None = None,
                     absent_ledger_ok: bool = False,
                     call_records: tuple[list[dict[str, Any]], list[dict[str, Any]]] | None = None,
                     forged_rows: list[dict[str, Any]] | None = None,
                     summary_leads: frozenset[str] = frozenset()) -> WorldFacts:
    """Read one world's archived record — ledger, then document, then report — for the
    grading path. Unlike the standalone readers, an absent input refuses here: grading has
    nothing to return for a world it cannot see."""
    ledger_name = world_ledger_name(world_id)
    if call_records is not None:
        table_rows, ledger_rows = call_records
        malformed = 0
    else:
        table_rows = []
        ledger_rows, malformed, ledger_read = read_world_ledger(
            bound, world_id)
        if ledger_read.absent and not absent_ledger_ok:
            raise JudgeRefused(
                f"the ledger ({ledger_name}) could not be read: nothing is at that name")
    document = read_investigation_facts(bound, world=world_id)
    if document.absent:
        raise JudgeRefused(
            f"world {label!r}: {LAYOUT.world(world_id).investigation} could not be read: "
            "nothing is at that name")
    report = read_archived_report(bound, LAYOUT.world(world_id).report)
    if report.absent:
        raise JudgeRefused(
            f"world {label!r}: {LAYOUT.world(world_id).report} could not be read: "
            "nothing is at that name")
    return WorldFacts(
        ledger_rows=ledger_rows, malformed_rows=malformed,
        investigation_text=document.investigation_text,
        report=report,
        resolution_moved=document.resolution_moved,
        resolutions_by_lead=document.resolutions_by_lead,
        unlanded_document_rows=document.unlanded_document_rows,
        leads=leads() if leads is not None else {},
        table_rows=table_rows, forged_rows=list(forged_rows or ()),
        summary_leads=summary_leads, token=world_id,
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


def _missing_required_input(bound: Bound, *, world_id: str, declared: Any) -> str | None:
    """The first file a world's context needs that is not in its parent's listing at all, or
    `None`. Absent is a state, not a refusal (K2): it marks the world ungradable without
    `malformed`. A name that IS listed but is not a plain file (a link, a FIFO, a directory)
    is not missing: the read that follows refuses it as malformed, naming it (A3). An absent
    world directory means its report is missing; one that exists but cannot be listed decides
    nothing here — the read refuses it. The served ledger and the alert are not required (no
    call reached the ledger; the rule key falls back): whether a world ran is its own
    record's to say (S8)."""
    world = bound.under(LAYOUT.world(world_id).dir).entries()
    if world.absent:
        return str(WORLD_LEAVES.report)
    if world.entries is not None:
        for leaf in (WORLD_LEAVES.report, WORLD_LEAVES.investigation,
                     WORLD_LEAVES.executed_queries):
            if leaf.name not in world.entries:
                return str(leaf)
    if not isinstance(declared, str) or not declared:
        return "disposition_declared"
    return None


def read_world(  # noqa: PLR0911 — one tier rule, one return per way a world is set aside
    bound: Bound, world: dict[str, Any], *, episode_dir: Path,
) -> tuple[dict[str, Any], WorldFacts | None]:
    """One non-control world's row and archived facts, or the row alone marked `ungradable`
    when the archive cannot be put in front of the judge (cut short, an input missing, a
    malformed input). Decides no bucket.

    @owns ungradable — the sole producer of a world row's `ungradable`/`ungradable_reason`/
    `malformed` from its archive (the pass adds the O5 failed worlds' rows itself)."""
    label, world_id = world["label"], world["world_id"]
    raw_declared = world.get("disposition_declared")
    row: dict[str, Any] = {"world": label, "declared": normalized_disposition(raw_declared)}

    # A world the host cut short before the model decided is never graded (its report is the
    # host's, not a verdict) — unless the model had already closed. A cut by a failed write of
    # a call record names that record's file (A12).
    end = _read_run_end_record(bound.under(LAYOUT.world(world_id).dir))
    if end is not None and end.truncated_by is not None and not end.closed_before_cut:
        failed_write = {
            TRUNCATED_BY_EXECUTED_QUERIES: str(LAYOUT.world(world_id).executed_queries),
            TRUNCATED_BY_SERVED_LEDGER: world_ledger_name(world_id),
        }.get(end.truncated_by)
        row["ungradable"] = True
        row["cut_short"] = end.truncated_by
        row["ungradable_reason"] = (
            f"world {label!r}: its run ended {end.truncated_by!r}"
            + (f" (the write of {failed_write} failed)" if failed_write else "")
            + " — the host's report is not a verdict")
        return row, None

    missing = _missing_required_input(bound, world_id=world_id, declared=raw_declared)
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

    world_bound = bound.under(LAYOUT.world(world_id).dir)
    try:
        # The usability read (A3): every file this run's context needs, plain, within limits
        # and well-formed — the call records first, so a damaged table is refused before the
        # lead reader (which takes a path) ever opens it.
        call_records = read_call_records(bound, world_id)
        forged = _read_oracle_store(bound, world)
        summaries = _read_summaries(world_bound, label=label)
        _read_run_records(world_bound, label=label)
        facts = read_world_facts(
            bound, label, world_id=world_id,
            leads=lambda: _repository_leads(world_bound, Path(episode_dir), world_id),
            absent_ledger_ok=True, call_records=call_records, forged_rows=forged,
            summary_leads=summaries)
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


def _read_oracle_store(bound: Bound, world: dict[str, Any]) -> list[dict[str, Any]]:
    """A world's frozen forged rows (`oracle/<X>/forged.jsonl`), read whole and well-formed: a
    planted world with no store is a failed read (A24), and every row must name one of that
    world's own facts (A3). The control legitimately has no store (its facts are `[]`); one it
    has is read under the same rule."""
    label, world_id = world["label"], world["world_id"]
    name = LAYOUT.oracle_dir(world_id) / "forged.jsonl"
    rows, torn, rec = bound.read_jsonl(name)
    if rec.refusal is not None:
        raise JudgeRefused(f"world {label!r}: {rec.refusal}")
    if rec.absent:
        if world.get("role") == BASE_ROLE:
            return []
        # The store is the directory: the oracle leaves `forged.jsonl` out when it froze no row
        # (K5: its empty records are absent), so a store holding no forged file is an empty
        # store. No readable directory is a planted world with no store (R6b): a failed read.
        if bound.under(LAYOUT.oracle_dir(world_id)).entries().entries is None:
            raise JudgeRefused(f"world {label!r}: its oracle store ({name}) is absent — a "
                               "planted world's built layer is part of what it is judged on")
        return []
    if torn:
        raise JudgeRefused(f"world {label!r}: {name} holds {torn} line(s) that do not parse "
                           "as a row")
    own = {f.get("fact_id") for f in world.get("facts") or () if isinstance(f, dict)}
    for index, row in enumerate(rows):
        if not isinstance(row.get("fact_id"), str):
            raise JudgeRefused(f"world {label!r}: {name} row {index} has a malformed fact_id "
                               f"({row.get('fact_id')!r}); expected a string")
    foreign = [row.get("fact_id") for row in rows if row.get("fact_id") not in own]
    if foreign:
        raise JudgeRefused(f"world {label!r}: {name} holds forged rows for facts this world "
                           f"does not declare ({foreign[:3]!r})")
    _refuse_unwritable(rows, label=label, name=name)
    return rows


def _read_run_records(world: Bound, *, label: str) -> None:
    """The run records a world's context reads beside its call records (A3): `alert.json`
    (the alert the run answered, a JSON mapping) and `lessons_loaded.jsonl` (the lessons it
    was shown, every line a row). Either may be absent — no alert archived (the rule key falls
    back), no lesson loaded — but one that is present must read plain, within limits and
    well-formed, or the world is malformed, naming the file."""
    alert = world.read(WORLD_LEAVES.alert)
    if alert.refusal is not None:
        raise JudgeRefused(f"world {label!r}: {alert.refusal}")
    if not alert.absent:
        mapping = json_mapping_of(alert.text)
        if mapping is None:
            raise JudgeRefused(f"world {label!r}: {WORLD_LEAVES.alert} is not a JSON mapping")
        _refuse_unwritable([mapping], label=label, name=str(WORLD_LEAVES.alert))
    rows, torn, lessons = world.read_jsonl(WORLD_LEAVES.lessons_loaded)
    if lessons.refusal is not None:
        raise JudgeRefused(f"world {label!r}: {lessons.refusal}")
    if torn:
        raise JudgeRefused(f"world {label!r}: {WORLD_LEAVES.lessons_loaded} holds {torn} "
                           "line(s) that do not parse as a row")
    _refuse_unwritable(rows, label=label, name=str(WORLD_LEAVES.lessons_loaded))


def _read_summaries(world: Bound, *, label: str) -> frozenset[str]:
    """The lead ids whose `gather_summaries/<lead>.md` reads plain. A listing or a summary the
    no-follow reader refuses (a linked folder, a link, a FIFO) is a failed read (A3); an absent
    folder is `_archive_notes`' business."""
    folder = world.under(WORLD_LEAVES.gather_summaries)
    listing = folder.entries()
    if listing.entries is None:
        if listing.absent:
            return frozenset()
        raise JudgeRefused(f"world {label!r}: {WORLD_LEAVES.gather_summaries} could not be "
                           f"listed: {listing.reason}")
    kept: set[str] = set()
    for name in listing.entries:
        if not name.endswith(".md") or len(name) <= len(".md"):
            continue
        rec = folder.read(name, errors="replace")
        if rec.text is None:
            raise JudgeRefused(f"world {label!r}: the gather summary {name!r} in "
                               f"{WORLD_LEAVES.gather_summaries} could not be read: "
                               f"{rec.reason}")
        kept.add(name[:-len(".md")])
    return frozenset(kept)


def control_world(doc: dict[str, Any]) -> dict[str, Any]:
    """The validated manifest's unique control entry."""
    try:
        parse_family(doc)
    except FamilyError as refused:
        raise JudgeRefused(str(refused)) from refused
    controls = [world for world in doc["worlds"] if world.get("role") == BASE_ROLE]
    if len(controls) != 1:
        raise JudgeRefused(f"the manifest declares {len(controls)} control worlds, not one")
    return controls[0]

def non_control_worlds(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The validated manifest's non-control worlds in declaration order."""
    try:
        parse_family(doc)
    except FamilyError as refused:
        raise JudgeRefused(str(refused)) from refused
    return [world for world in doc["worlds"] if world.get("role") != BASE_ROLE]

def _repository_leads(world: Bound, episode_dir: Path, world_id: str) -> dict[str, JoinedLead]:
    """`leads_by_id` over `worlds/<world-uuid>`, only once the bind's listing shows a real
    directory there."""
    listing = world.entries()
    if listing.entries is None:
        raise JudgeRefused(
            f"world {world_id!r}: {LAYOUT.world(world_id).dir} could not be listed: "
            f"{listing.reason or 'nothing is at that name'}")
    return leads_by_id(EpisodePaths(episode_dir).world(world_id).dir)


def is_gradable_row(row: Any) -> bool:
    """Did this world contribute to the family's word? Shared so every site treats a truthy
    non-`True` `ungradable` the same way."""
    return isinstance(row, dict) and not row.get("ungradable")


__all__ = [
    "InvestigationFacts", "WorldFacts", "control_world", "read_call_records",
    "read_call_join", "read_query_table", "read_served_ledger",
    "discriminator_of", "episode_id_of",
    "is_gradable_row", "json_mapping", "json_mapping_of", "lead_chain", "leads_by_id", "mapping_key",
    "names_one_file", "non_control_worlds", "read_manifest",
    "refused_entries", "has_refusals", "render_refused", "is_external_refusal",
    "read_archived_report", "read_investigation_facts", "read_samples_record", "read_world",
    "read_world_facts", "read_world_ledger", "scope_params",
    "summary_lead_ids", "world_ledger_name",
    "screened_yaml_mapping",
]
