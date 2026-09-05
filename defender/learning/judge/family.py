"""The mechanical half: five per-world facts, read off X's own archived record (#921).

THE AMENDED DESIGN, not the refuted bucket table. Every fact below reads ONE world's own
`served/<world_token>.jsonl`, that world's own archived `report.md`/`investigation.md`, and the
manifest — never `served/base.jsonl`, never a comparison with any sibling, never a comparator
call. `delta_o` and the mutation/undeclared membership test are not imported here and never
will be; see `test_921_family_pass_never_reads_served_base_and_never_calls_the_comparator`.

WHY THIS MODULE DOES NOT USE `runtime.branch._family.load_family`/`parse_family`. Those own the
STRICT schema a resumable sibling process is refused to start without — in particular
`disposition_declared` is a REQUIRED field there, and a manifest missing it on one world raises
before any world's data is readable at all. J5 tier 1 needs the opposite: an ABSENT
`disposition_declared` marks THAT ONE WORLD `ungradable`, named and excluded, while its
siblings still grade — a family record with something to say, not a refusal of the whole pass.
So this module reads the manifest's raw YAML itself, doing only the checks J1/J5-tier-2/J5-
tier-3/F-3 name, and leaves the strict schema to the launcher that actually starts a sibling.

WHERE A REFUSAL STOPS. A fault in the MANIFEST refuses the whole pass, because the manifest is
what says which worlds there are: an unvalidated holding system (J1), a duplicate or
case-colliding label, a label that cannot name a directory, a label colliding with a real run.
A fault in ONE WORLD'S OWN ARCHIVE stops at that world — absent inputs (tier 1) and malformed
ones (tier 2) both mark it `ungradable` with the reason on the record, and its siblings still
grade. The two tiers stay distinguishable: a malformed world carries `malformed: true` beside
`ungradable`, so "the artifact is not there" and "the artifact is there and wrong" are still
different answers on the record, which is the distinction A8 probed against `verdicts`. What
changed is only the blast radius, not the classification — a malformed artifact used to unwind
the pass, so one bad file in one world cost every sibling its grade and left no record at all.

MECHANICAL BUCKET, FROM FACTS NOT FROM AN EMPTY SET. Per non-control world X (H = the family's
validated holding system):

| condition | bucket |
|---|---|
| no row on H at all | `lead-set` |
| rows on H exist, none `staged`/`patched` (and no `refused` row on H) | `lead-quality` |
| a `refused` or `fault`-adjacent H interaction, no doctored answer served | no bucket (F-1) |
| a doctored answer was served, verdict == declared | no bucket |
| a doctored answer was served, no resolution moved, verdict != declared | `analyze-discipline` |
| a doctored answer was served, a resolution moved, verdict != declared | `decision-discipline` |

`verdict == declared` while every H row is `passthrough` (queried, never shown anything) is
flagged `agreed-without-evidence` rather than bucketed — an outcome, not a defect. A `fault` row
on H makes the world `ungradable` (J5's tier rule) rather than any of the above; a `refused` row
on H counts as having queried (F-1) and excludes the world from every failure bucket without
making it ungradable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender._io import read_guarded, read_jsonl_rows_report
from defender._run_paths import artifact_dir, artifact_file
from defender._report import ReportRead, read_report
from defender._run_id import is_valid_run_id
from defender._vocab import normalized_disposition
from defender.learning.branch.ledger import (
    APPLIER_DECISIONS,
    FAULT,
    PASSTHROUGH,
    REFUSED,
    STAGED,
    normalized_source,
    request_key,
)
from defender.learning.branch.archive import ALERT_NAME, GATHER_SUMMARIES_DIRNAME
from defender.learning.judge._errors import JudgeRefused
from defender.run_common import resolve_runs_base
from defender.runtime.branch._family import (
    BASE_ROLE,
    MANIFEST_NAME,
    episode_token_for,
    world_token_for,
)
from defender.skills.invlang._walkers import iter_resolutions
from defender.skills.invlang.parser import NO_OPEN_BLOCK, parse_dense_companion, scan_fences



@dataclass
class FamilyGrade:
    """The mechanical pass's own output: per-world rows plus the family's word.

    `worlds` carries EVERY declared non-control world, ungradable ones included (J5: an
    exclusion has to be traceable on the record). `graded_worlds` names the ones that
    contributed to `verdict_word`. `world_facts` is what this pass READ, per world it got as
    far as reading — handed on so the render does not open the same three files again; it is
    an in-memory by-product of the pass and is not part of `judge.yaml`."""

    episode_dir: Path
    worlds: list[dict[str, Any]] = field(default_factory=list)
    verdict_word: str = "undecidable"
    graded_worlds: frozenset[str] = field(default_factory=frozenset)
    world_facts: dict[str, WorldFacts] = field(default_factory=dict)


def _raw_manifest(episode_dir: Path) -> dict[str, Any]:
    import yaml

    from defender._yaml import safe_load

    path = Path(episode_dir) / MANIFEST_NAME
    # THE SCREENED READ THE MANIFEST'S OWNER MAKES, not a plain `read_text`. `_family.
    # _read_document` reads this same file through `read_guarded` for a stated reason — "the
    # episode dir is reachable from a sibling box's rw bind, so an entry at the manifest's name
    # may be a link the model planted — and a plain `read_text` follows the link the write side
    # refuses". The judge reads the same bytes to decide which worlds there are, what H is and
    # what each world's ground truth is, so a link the launcher refuses must not be one the
    # grader honours. `read_guarded` folds ABSENT in with the alias refusal; both are "you have
    # no content", and both were already this design's refusal here.
    text, refusal = read_guarded(path)
    if text is None:
        raise JudgeRefused(f"the manifest at {path} could not be read: {refusal}")
    try:
        # THE HARDENED LOADER. `RecursionError` out of a deeply nested manifest is neither a
        # `YAMLError` nor a `ValueError`, so it escaped both this handler and `grade_episode`'s
        # conversion set; `_yaml.safe_load` is the one home for that conversion.
        doc = safe_load(text)
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"the manifest at {path} could not be read: {bad}") from bad
    if not isinstance(doc, dict):
        raise JudgeRefused(f"the manifest at {path} is not a mapping")
    return doc


def episode_id_of(doc: dict[str, Any]) -> str:
    """The manifest's `episode_id`, or this design's refusal.

    ONE accessor because two readers want it and both build paths from it. Indexing
    `doc["episode_id"]` raises `KeyError` — a `LookupError`, so it is not one of the classes
    the entry point converts into a refusal, and it reached a caller as a bare traceback on a
    manifest the mechanical pass refuses cleanly."""
    episode_id = doc.get("episode_id")
    if not isinstance(episode_id, str) or not episode_id:
        raise JudgeRefused("the manifest's episode_id is not a usable string")
    return episode_id


def discriminator_of(doc: dict[str, Any]) -> dict[str, Any]:
    """The manifest's `discriminator` block as a mapping, `{}` when it is not one.

    `doc.get("discriminator", {})` returns `None` for a key that is PRESENT and null, and
    `.get()` on that raises `AttributeError` — a class no caller of this pass names."""
    block = doc.get("discriminator")
    return block if isinstance(block, dict) else {}


def _holding_system(doc: dict[str, Any]) -> str:
    """J1: `H` validated at manifest load — present, non-empty, a served-system name after
    strip+casefold. Refuses loudly otherwise; every per-world fact keys on `system == H`."""
    from defender.learning.branch.estate.stagers.dispatch import STAGERS
    from defender.runtime.branch._family import PATCHABLE_SYSTEMS

    served = {s.casefold() for s in (set(STAGERS) | set(PATCHABLE_SYSTEMS))}
    raw = discriminator_of(doc).get("holding_system")
    candidate = raw.strip().casefold() if isinstance(raw, str) else None
    if not candidate or candidate not in served:
        raise JudgeRefused(
            f"the manifest's discriminator.holding_system is {raw!r}, not one of the seven "
            f"served-system names {sorted(served)} (after strip+casefold) — H is unvalidated "
            "model text and every per-world fact keys on system == H, so a bogus or absent "
            "holding_system routes every non-control world to lead-set")
    return candidate


def _control_declared(doc: dict[str, Any]) -> Any:
    for world in doc.get("worlds") or ():
        if isinstance(world, dict) and world.get("role") == BASE_ROLE:
            return world.get("disposition_declared")
    return None


def _non_control_worlds(doc: dict[str, Any]) -> list[dict[str, Any]]:
    raw = doc.get("worlds")
    if not isinstance(raw, list):
        raise JudgeRefused("the manifest's worlds is not a list")
    # EXHAUSTIVELY CLASSIFIED, with the residue reported (defender/CLAUDE.md's `lint-selection`
    # rule). A `worlds` list is model-authored, so an entry that is not a mapping is a real
    # shape to meet — a bare label string from a model that emitted a list of names. Filtering
    # it out silently produced a `FamilyGrade` naming only the survivors and a `judge.yaml` that
    # reads like a complete family, with the dropped arm indistinguishable from one never
    # declared. It is the MANIFEST that says which worlds there are, so this refuses the pass
    # the way every other manifest fault does.
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


def _check_world_labels(episode_id: str, worlds: list[dict[str, Any]]) -> None:
    """Two rules about the label as a NAME, both applied before any path is built from it.

    THE LABEL HAS TO NAME A DIRECTORY. Every per-world read in this pass joins the label
    straight into a path (`worlds/<label>/…`, `worlds/<label>/judge/`), and the label is
    MODEL-authored manifest text this module deliberately does not run the launcher's strict
    schema over. A label carrying a separator or `..` therefore reaches `guarded_mkdir` as a
    target outside the episode, which answers with a bare `ValueError` — a class no caller of
    this pass names, so an otherwise-clean episode ends in a traceback rather than a refusal.
    The grammar is the launcher's own (`_run_id.is_valid_run_id` over `{episode_id}-{label}`,
    the same spelling `_family.check_identities` applies), so the two gates cannot drift.

    F-3: a world label colliding with a real run under the operator's runs base is refused at
    manifest load — the last-segment resolver every family row's `source_run_dir` reaches would
    otherwise resolve to wrong-but-real content instead of failing loudly."""
    for world in worlds:
        label = world.get("world_id")
        # BOTH SPELLINGS. The concatenation is the launcher's own check (`_family.
        # check_identities` applies exactly it), and it is not enough on its own: the grammar
        # tests the FIRST character for `isalnum`, and in `f"{episode_id}-{label}"` that
        # character is the episode id's — so `..`, `.` and `-` all pass it, and `..` is the one
        # value that turns `worlds/<label>` back into the episode dir itself. Asking the same
        # grammar of the bare label closes that, and asking it of the concatenation too keeps
        # this gate agreeing with the launcher's.
        if isinstance(label, str) and not (
                is_valid_run_id(label) and is_valid_run_id(f"{episode_id}-{label}")):
            raise JudgeRefused(
                f"world label {label!r} cannot name a directory of its own, or this episode's "
                f"sibling run ({episode_id}-{label}) — the label is joined straight into every "
                "per-world path this pass reads and writes, so a label off that grammar reads "
                "and writes outside the world it names")
    try:
        base = resolve_runs_base()
    except Exception:  # noqa: BLE001 — an unconfigured runs base means nothing to collide with
        return
    for world in worlds:
        label = world.get("world_id")
        # `exists() or is_symlink()`, WIDER than `is_dir()` and deliberately so: this is a
        # COLLISION probe, and anything at all standing at the label's name under the operator's
        # runs base — a link, a file, a broken link — is a name the last-segment resolver can
        # reach. `is_dir()` also followed a link planted at that name to answer about its target.
        if isinstance(label, str) and (
                (base / label).exists() or (base / label).is_symlink()):
            raise JudgeRefused(
                f"world label {label!r} collides with a real run under the operator's runs "
                f"base ({base / label}) — a family row's source_run_dir naming this label "
                "would resolve to that run's content rather than this world's own archive; "
                "rename one of the two")


def mapping_key(mapping: dict[str, Any]) -> str:
    """The canonical `(system, verb, params)` key of ANY mapping that carries those three.

    ONE home, because two mappings in this design carry them and their keys must be comparable:
    a served ledger row, and the manifest's discriminator envelope. They were two `def`s in two
    modules doing the same three coercions around `ledger.request_key` — the copy jscpd cannot
    see and the duplicate-helper gate cannot either, since it keys on the symbol name. They have
    to AGREE for the drift check to match a recorded key at all, so a change to one silently
    stopping the other from matching is the whole hazard."""
    params = mapping.get("params")
    # THE KEYS ARE STRINGIFIED FIRST. `request_key` ends in `json.dumps(..., sort_keys=True)`,
    # whose `default=str` rescues an unserialisable VALUE and does nothing for a key: a params
    # mapping with mixed key types sorts `int` against `str` and raises `TypeError` — a class
    # `grade_episode`'s conversion set does not name, out of `_control_drift_discard` AFTER
    # every world's draws have been made. A ledger row's params come from JSONL and are already
    # string-keyed, so this changes no recorded key; the manifest's `discriminator.envelope` is
    # model-authored YAML and is the one mapping that can carry others.
    if isinstance(params, dict):
        params = {str(k): v for k, v in params.items()}
    return request_key(str(mapping.get("system") or ""), str(mapping.get("verb") or ""),
                       params if isinstance(params, dict) else {})


def names_one_file(lead_id: object) -> bool:
    """Is `lead_id` a name this pass may join into a path?

    A lead id is MODEL-AUTHORED. `iter_resolutions` hands back whatever token the document's own
    `:T resolutions` row put where a lead id goes — any non-whitespace text — and every per-lead
    read joins it straight into `worlds/<X>/gather_summaries/<lead>.md` and
    `gather_raw/<lead>.lead.json`. A token carrying a separator or `..` therefore reads OUT of
    the graded world, and the leads view puts what it read INTO the prompt: a `[../../c/report
    ...]` row makes a counterfactual sibling's whole `report.md` — its disposition included —
    read as a fact about the graded world, which is the one thing O5/J14's withholding exists to
    stop. The world LABEL is screened for exactly this reason (`_check_world_labels`); this is
    the same hazard one directory down. The row itself is still carried (it is evidence); what
    is refused is building a path out of it."""
    return (isinstance(lead_id, str) and bool(lead_id)
            and lead_id not in (".", "..") and lead_id == Path(lead_id).name)


def scope_params(row: dict[str, Any]) -> dict[str, Any]:
    """A served row's params AS ASKED — `asked_params` when present, `params` otherwise (J4).

    One home for the same reason: the scope fact and the coverage view both read this pair, and
    a reader that took `params` where the other took `asked_params` would score a prepared
    retargeted index as the scope the model asked for (G6, A4 executed)."""
    asked = row.get("asked_params")
    params = asked if isinstance(asked, dict) else row.get("params")
    return params if isinstance(params, dict) else {}


def _read_world_ledger(path: Path, world_token: str) -> tuple[list[dict[str, Any]], int]:
    """J3: this world's own decision rows, first-row-wins on a duplicate pair-key, a malformed
    line skipped and counted rather than failing the world.

    The rows-plus-count split is `_io.read_jsonl_rows_report`'s own contract, so the physical
    read is ITS loop and not a second one here: it reads with `errors="replace"`, which is what
    turns a served ledger carrying one undecodable byte into a counted malformed row instead of
    a `UnicodeDecodeError` thrown out of the whole grading pass. What this function adds is the
    SEMANTIC half the shared reader cannot know about — a row whose `source` is not one of the
    ledger's own decision words is malformed for this reader even though it parsed."""
    # `artifact_file`, the same `lstat` posture `Ledger._absorb` takes on these very bytes: the
    # served ledger sits under the episode dir and a link at its name would have another file's
    # rows read as this world's decisions.
    if not artifact_file(path):
        raise JudgeRefused(f"the ledger at {path} is absent")
    parsed, malformed = read_jsonl_rows_report(path)
    kept: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in parsed:
        if normalized_source(row.get("source")) is None:
            malformed += 1
            continue
        if row.get("world_id") != world_token:
            # A family-tier row (`world_id: null`) or a stray row for a different world (J2):
            # inert to every per-world fact, and not a malformed line either.
            continue
        key = mapping_key(row)
        if key not in kept:
            kept[key] = row
            order.append(key)
    return [kept[k] for k in order], malformed


def _own_h_rows(rows: list[dict[str, Any]], holding_system: str) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        system = row.get("system")
        if isinstance(system, str) and system.strip().casefold() == holding_system:
            out.append(row)
    return out


def _scope_discriminated_row(row: dict[str, Any]) -> bool:
    """J4: read `asked_params` when present, `params` otherwise; a mapping missing one of the
    three named keys is NOT DISCRIMINATING, not a refusal."""
    params = scope_params(row)
    return bool(params) and all(
        params.get(k) is not None for k in ("index", "window", "scope_key"))


def _resolution_facts(
    text: str, *, world: str,
) -> tuple[bool, dict[str, list[dict[str, Any]]], tuple[str, ...]]:
    """`resolution_moved`, the document's own resolution ROWS grouped by lead id, and the
    block-opening lines the fences ORPHANED.

    THROUGH THE INVLANG PARSER, which owns what a `:T resolutions` row IS. This module used to
    read the block itself, and against a real archived document it read NOTHING: it matched
    `:T resolutions` only when the block opened its fence (in a real document it sits after
    `:V`/`:H`/`:R` blocks in the same fence) and then parsed the body as YAML, which invlang
    rows are not — `h-001  null -> ++    [l-001 r1 severe :: reason]` is a table row, not a
    mapping. Run against the repo's own golden investigation it returned `moved=False` and no
    rows, so `decision-discipline` was unreachable, the leads view's resolutions line was
    always empty, and every check keyed on the referenced leads never fired. The lead a
    resolution belongs to is the enclosing finding's id, which the walker supplies and a
    per-row `lead` key never did.

    `before != after` on ANY row is enough (J4: "was the hand-off revisited", not "did the net
    state move") — an oscillating lead's first qualifying row is not discarded for the net
    state. A document with an unclosed invlang fence is malformed: it refuses, and the
    caller contains that refusal to the world it is about (J5 tier 2).

    THE COMPLEMENT IS RETURNED, NOT DROPPED (defender/CLAUDE.md, #932). `scan_fences` hands
    back `orphaned_headers` alongside `bodies` precisely so a reader cannot take the content
    and lose what fell outside it in silence; the caller puts the orphans on the world's
    record."""
    scan = scan_fences(text)
    if scan.open_tail is not None:
        raise JudgeRefused(
            f"world {world!r}: investigation.md has an unclosed invlang fence — a truncated "
            "document cannot be graded")
    companion, warnings = parse_dense_companion(text)
    moved = False
    by_lead: dict[str, list[dict[str, Any]]] = {}
    # THE PARSER'S OWN COMPLEMENT TOO, not just the fences'. A row the tokenizer could not read
    # raises a `ParseWarning` and lands nowhere; a row whose enclosing finding carries no id has
    # nothing to group it under. Both used to be dropped here in silence — inside the very
    # function whose docstring says the complement is returned — so a world whose resolutions
    # were malformed graded exactly like one that had none, which is the failure this reader was
    # rewritten to stop.
    # AND `NO_OPEN_BLOCK`, which is where a whole resolutions block lands when its HEADER is the
    # line the tokenizer refused. `_orphan_warning` files the header and every row under it under
    # that one name, not under `:T resolutions` — so a trailing comment on the header
    # (`:T resolutions   # after the branch`) made the block vanish from `by_lead`, from
    # `moved`, AND from this complement, and `_archive_notes` then had nothing to report either:
    # a world that DID revisit a hand-off graded `analyze-discipline` with nothing on the record
    # saying evidence had been lost. `scan_fences.orphaned_headers` cannot cover it — those rows
    # are INSIDE a fence.
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
            # SAID OUT LOUD, not dropped and not read through: nothing joins this token into a
            # path (`names_one_file`), so the world's supporting files for it are never opened,
            # and the operator is told which rows this pass would not follow.
            unlanded.append(
                f"a resolution row's lead id {lead_id!r} does not name a file inside this "
                "world, so no per-lead artifact was read for it")
        by_lead.setdefault(lead_id, []).append(dict(row))
        before, after = row.get("before"), row.get("after")
        if before is not None and after is not None and before != after:
            moved = True
    return moved, by_lead, (*scan.orphaned_headers, *unlanded)


def _read_archived_text(path: Path, *, world: str, role: str) -> str:
    """One archived document's text, with an unreadable one answered as this design's refusal.

    A bare `read_text` here raises `UnicodeDecodeError` on an archived document carrying one
    undecodable byte — a `ValueError`, not an `OSError`, so it escapes every handler between
    here and the launcher and takes an otherwise-clean episode down with it."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as bad:
        raise JudgeRefused(f"world {world!r}: {role} could not be read: {bad}") from bad


def _read_verdict(report: ReportRead, *, world: str) -> str:
    """X's own archived headline, as `_report.read_report` already decided it.

    THROUGH THAT READER AND NOT A REGEX OF OUR OWN. `read_report` owns what a report's headline
    IS for every consumer in this repo — the questioner, the evals, the visualizer, the ticket
    bridge — and it parses the `---` frontmatter the close gate actually writes, so a value the
    gate legitimately quoted reads the same here as it does everywhere else. A local
    `^disposition:` line match agrees with it only on the unquoted spelling and only while the
    key stays first in the file.

    `read_report` already asks `normalized_disposition`, which is EXACT by decision (#923: the
    zero-width strip used to live inside it and it COERCED — `malicious` with a zero-width
    space in it read back as `malicious`, a committed close no reader could tell from a clean
    one). So a laced headline arrives here as `disposition=None` with a reason, which is what
    the judge — the one reader that must not be fooled by it — refuses on."""
    if report.disposition is None:
        raise JudgeRefused(
            f"world {world!r}: {report.reason or 'report.md carries no usable disposition'}")
    return report.disposition


def _check_gather_summaries(world_dir: Path, *, world: str, referenced_leads: frozenset[str]) -> None:
    """F-7: a partial archive — all five required inputs present, `gather_summaries/` short of
    a lead its own document references — is MALFORMED, refused and NAMING the input that was
    short, which is what tells an operator a partial archive from a genuine one. The refusal is
    contained to this world by `_grade_world` (J5 tier 2), so the siblings still grade."""
    summaries = world_dir / GATHER_SUMMARIES_DIRNAME
    if not artifact_dir(summaries):
        return
    # `names_one_file` FIRST: a lead id off that grammar stats a path outside this world's
    # subtree, so F-7 would answer about a file the archive was never supposed to hold — and a
    # traversing id that happens to resolve to a real file elsewhere would make the check PASS
    # on a genuinely short archive.
    missing = sorted(
        lead for lead in referenced_leads
        if names_one_file(lead) and not artifact_file(summaries / f"{lead}.md"))
    if missing:
        raise JudgeRefused(
            f"world {world!r}: gather_summaries/ is short {missing} — the archive left this "
            "world's supporting directory short of a lead its own investigation.md references; "
            "refusing rather than grading on a thinner view than it appears to have")


@dataclass(frozen=True)
class WorldFacts:
    """One world's archived record, read ONCE per grading pass.

    The mechanical pass and the render both want the same three files — the served ledger, the
    investigation document and the report — and both used to open all three for themselves, so
    a two-world episode parsed six files twice over. This is the one read; `grade_family` hands
    what it read to the caller on `FamilyGrade.world_facts`, and `render.render` takes it as an
    optional input and reads for itself only when nobody has read for it."""

    ledger_rows: list[dict[str, Any]]
    malformed_rows: int
    investigation_text: str
    #: The report AS `_report.read_report` READ IT — its headline, its reason when there is
    #: none, and its bytes. The bytes alone would make every consumer re-decide what the
    #: headline is, which is the duplication this field exists to stop.
    report: ReportRead
    resolution_moved: bool
    resolutions_by_lead: dict[str, list[dict[str, Any]]]
    #: What reading this world's document did NOT land: block-opening lines written OUTSIDE
    #: every invlang fence, resolution rows the parser could not read, and rows with no lead id
    #: to group them under. Carried so the caller can put them on the record — each one is
    #: evidence the grading pass could not see, and silence about it reads exactly like a world
    #: that had none.
    unlanded_document_rows: tuple[str, ...] = ()

    @property
    def referenced_leads(self) -> frozenset[str]:
        """The lead ids this world's own `:T resolutions` rows name."""
        return frozenset(self.resolutions_by_lead)


def world_ledger_path(episode_dir: Path, label: str, *, episode_token: str) -> Path:
    """The one spelling of a world's own served ledger, so its two readers cannot drift."""
    return Path(episode_dir) / "served" / f"{world_token_for(episode_token, label)}.jsonl"


def read_world_facts(episode_dir: Path, label: str, *, episode_token: str) -> WorldFacts:
    """Read one world's archived record: the ledger, the document and the report, once."""
    world_dir = Path(episode_dir) / "worlds" / label
    ledger_path = world_ledger_path(episode_dir, label, episode_token=episode_token)
    ledger_rows, malformed = _read_world_ledger(
        ledger_path, world_token_for(episode_token, label))
    text = _read_archived_text(
        world_dir / "investigation.md", world=label, role="investigation.md")
    moved, by_lead, unlanded = _resolution_facts(text, world=label)
    return WorldFacts(
        ledger_rows=ledger_rows, malformed_rows=malformed, investigation_text=text,
        report=read_report(world_dir / "report.md"),
        resolution_moved=moved, resolutions_by_lead=by_lead,
        unlanded_document_rows=unlanded,
    )


def _archive_notes(world_dir: Path, *, world: str, facts: WorldFacts) -> list[str]:
    """What this world's archive is missing WITHOUT being malformed — said on the record.

    Two states that used to pass in silence. A `:T resolutions` block written outside every
    invlang fence is resolution evidence no reader above the fence scan can see, so the world
    grades as though it never revisited a hand-off. And `gather_summaries/` ABSENT while the
    document names leads is the same thinner-view hazard F-7 refuses a SHORT directory for —
    but absence is J5 tier 1's shape (an input that is not there), not tier 2's (an input that
    is there and wrong), so it is named here rather than raised on. Either way the operator
    reads why the world graded on less than it appears to have."""
    notes: list[str] = []
    if facts.unlanded_document_rows:
        first = facts.unlanded_document_rows[0].strip()
        notes.append(
            f"investigation.md has {len(facts.unlanded_document_rows)} row(s) or block(s) this "
            f"pass could not read ({first[:120]!r}…) — they are outside every invlang fence, "
            "unreadable to the parser, or carry no lead id, so this world's resolution facts "
            "are read from what landed alone")
    summaries = world_dir / GATHER_SUMMARIES_DIRNAME
    if facts.referenced_leads and not artifact_dir(summaries):
        notes.append(
            f"gather_summaries/ is absent while investigation.md names "
            f"{sorted(facts.referenced_leads)} — this world is graded on a thinner view than "
            "its own document claims")
    return notes


def _missing_required_input(
    *, world_dir: Path, ledger_path: Path, alert_path: Path, declared: Any,
) -> str | None:
    # `artifact_file` on every one of them. These four decide whether a world is graded at all,
    # they are read straight afterwards, and they live in a tree three boxes had an rw bind on —
    # so `is_file()` admits a link and the world is then graded against whatever it points at.
    if not artifact_file(ledger_path):
        return f"served ledger ({ledger_path})"
    if not artifact_file(world_dir / "report.md"):
        return "report.md"
    if not artifact_file(world_dir / "investigation.md"):
        return "investigation.md"
    if not artifact_file(alert_path):
        return ALERT_NAME
    if not isinstance(declared, str) or not declared:
        return "disposition_declared"
    return None


def _grade_world(  # noqa: C901, PLR0912, PLR0915 — the tier rule and the bucket state machine are one demand (J5 + the mechanical bucket table); splitting them would let a caller reach the bucket logic on a world the tier rule never cleared
    episode_dir: Path, world: dict[str, Any], *, episode_token: str, holding_system: str,
) -> tuple[dict[str, Any], WorldFacts | None]:
    label = world["world_id"]
    raw_declared = world.get("disposition_declared")
    # ONE COLUMN, ONE VOCABULARY. `declared` is the NORMALIZED value on every row that has one
    # and `None` on every row that does not — never the raw manifest text on some rows and the
    # normalized value on others, which is what an early `declared: raw` gave a world that then
    # returned ungradable, and which put two spellings of one word in one table.
    row: dict[str, Any] = {"world": label, "declared": normalized_disposition(raw_declared)}
    world_dir = Path(episode_dir) / "worlds" / label
    ledger_path = world_ledger_path(episode_dir, label, episode_token=episode_token)
    alert_path = world_dir / ALERT_NAME

    missing = _missing_required_input(
        world_dir=world_dir, ledger_path=ledger_path, alert_path=alert_path,
        declared=raw_declared)
    if missing is not None:
        row["ungradable"] = True
        row["ungradable_reason"] = f"world {label!r} is missing its {missing}"
        return row, None

    # THE DECLARED SIDE GOES THROUGH THE SAME NORMALIZER AS THE VERDICT, and this is the only
    # place either is resolved. `disposition_declared` is raw model-authored manifest text —
    # this module deliberately skips `parse_family`, the one thing that validates the field —
    # so comparing a normalized verdict against it directly made `verdict != declared` true for
    # EVERY world of a manifest that merely capitalised the word, which reads out as a family
    # that survived when it was caught, with a fabricated finding queued for authoring per
    # world. A value that is not a disposition at all makes THAT ONE WORLD ungradable, named
    # and excluded the same way an absent one does (J5 tier 1) — its siblings still grade.
    declared = row["declared"]
    if declared is None:
        row["ungradable"] = True
        row["ungradable_reason"] = (
            f"world {label!r}: the manifest's disposition_declared {raw_declared!r} is outside "
            "the disposition vocabulary — this world has no ground truth to grade against")
        return row, None

    # J5 TIER 2, CONTAINED TO THE WORLD IT IS ABOUT. Reading this world's own archived record
    # is where a MALFORMED input shows up — a headline outside the vocabulary, a document
    # truncated inside an open fence, a `gather_summaries/` left short by a mid-copy fault. The
    # refusal used to unwind the whole pass, so one bad artifact in one world cost every SIBLING
    # its grade, ran no draws, and left no `judge.yaml` at all: the operator got a traceback
    # where the record would have said "b graded, c excluded and here is why". Absent and
    # malformed stay DIFFERENT ANSWERS, which is the distinction A8 probed and the tier rule
    # exists for — `malformed` is on the row beside `ungradable`, so a reader can still tell an
    # artifact that is not there from one that is there and wrong.
    try:
        facts = read_world_facts(episode_dir, label, episode_token=episode_token)
        h_rows = _own_h_rows(facts.ledger_rows, holding_system)
        faulted = next((r for r in h_rows if r.get("source") == FAULT), None)

        resolution_moved = facts.resolution_moved
        _check_gather_summaries(world_dir, world=label, referenced_leads=facts.referenced_leads)
        verdict = _read_verdict(facts.report, world=label)
    except JudgeRefused as malformed:
        row["ungradable"] = True
        row["malformed"] = True
        row["ungradable_reason"] = str(malformed)
        return row, None

    from defender.learning.branch.estate.stagers.dispatch import STAGERS

    stagers = {s.casefold() for s in STAGERS}
    integrity_notes: list[str] = _archive_notes(
        world_dir, world=label, facts=facts)
    doctored = False
    # THE LEDGER'S OWN WORDS, imported rather than re-spelled. `ledger.py` defines these and
    # `normalized_source` exists precisely so no second module re-derives membership in that
    # vocabulary (#785: one parser, N interpreters, some of which disagree on the same bytes).
    # A literal here goes silently False the day a member is re-spelled, and a family then
    # reads `lead-quality` where it should read `decision-discipline`, with no error anywhere.
    doctoring = APPLIER_DECISIONS - {PASSTHROUGH}
    for r in h_rows:
        if r.get("source") in doctoring:
            doctored = True
            if r.get("source") == STAGED and holding_system not in stagers:
                integrity_notes.append(
                    f"a 'staged' row was recorded on {holding_system!r}, a patch-only system — "
                    "reported, not reclassified")

    holding_queried = bool(h_rows)
    scope_discriminated = any(_scope_discriminated_row(r) for r in h_rows)
    has_refused = any(r.get("source") == REFUSED for r in h_rows)

    row.update(
        holding_queried=holding_queried, scope_discriminated=scope_discriminated,
        doctored_answer_served=doctored, resolution_moved=resolution_moved,
        verdict=verdict, malformed_rows=facts.malformed_rows,
    )
    if integrity_notes:
        row["integrity_notes"] = integrity_notes

    if faulted is not None:
        # J5's tier rule: a faulted call makes the world ungradable — excluded from
        # `verdict_word` — but F-1 still wants the facts on the record (`holding_queried` is
        # true; a faulted call is evidence the defender asked correctly).
        row["ungradable"] = True
        row["ungradable_reason"] = (
            f"world {label!r}: a call on {holding_system!r} faulted "
            f"({faulted.get('payload_text', '')!r}) — the defender is not graded on a call "
            "the estate could not answer")
        row["bucket"] = None
        return row, facts

    bucket: str | None
    flag: str | None = None
    if not holding_queried:
        bucket = "lead-set"
    elif not doctored:
        # "agreed-without-evidence" needs the world to have genuinely exhausted its asking of
        # H — more than one distinct call — before "it agreed and was shown nothing" reads as
        # an honest non-defect rather than as a lead the world tried once, narrowly, and
        # happened to still land on the right side of.
        #
        # AND NOT A REFUSED ROW AMONG THEM. This module's own table defines the flag as
        # `verdict == declared` while every H row is `passthrough` — queried, and shown
        # nothing. A refused row is the estate declining to answer at all, which is a
        # CAPABILITY outcome (F-1), and stamping it `agreed-without-evidence` tells an
        # operator the defender agreed having been shown nothing when in fact it was never
        # answered. Tested before the flag rather than after it, because the flag branch used
        # to win and `elif has_refused` was then unreachable for exactly this world.
        if verdict == declared and len(h_rows) >= 2 and not has_refused:
            bucket = None
            flag = "agreed-without-evidence"
        elif has_refused:
            # F-1: a refused H interaction counts as having queried, and is excluded from the
            # failure buckets rather than defaulted into `lead-set`.
            bucket = None
        else:
            bucket = "lead-quality"
    else:
        if verdict == declared:
            bucket = None
        elif resolution_moved:
            bucket = "decision-discipline"
        else:
            bucket = "analyze-discipline"
    row["bucket"] = bucket
    if flag is not None:
        row["flag"] = flag
    return row, facts


def is_gradable_row(row: Any) -> bool:
    """Did this world contribute to the family's word? ONE predicate, because four sites asked
    it and two of them asked it differently: `r.get("ungradable") is not True` here against
    `not r.get("ungradable")` in the orchestration and the appender, which disagree for every
    truthy non-`True` value a hand-edited or model-written `judge.yaml` can carry — so
    `graded_worlds` on the record could name a world the enqueue had silently skipped."""
    return isinstance(row, dict) and not row.get("ungradable")


def grade_family(episode_dir: Path, *, manifest: dict[str, Any] | None = None) -> FamilyGrade:
    """The mechanical pass: five facts and a bucket per non-control world, plus the family's
    `verdict_word`. Self-contained over `episode_dir` alone — no comparison, no comparator
    call, order-independent across worlds (O3).

    Refuses only for a fault in the MANIFEST, which is what says which worlds there are. A
    fault in one world's own archive marks that world `ungradable` and grades the rest — see
    the module docstring on where a refusal stops.

    `manifest` is THE PASS'S OWN PARSE, when the caller has one — the same hand-over `render`
    already takes. The orchestration reads and parses `family.yaml` immediately before calling
    this, so without it one pass read and parsed the same file twice, and the episode dir is a
    tree a box can reach: there was no guarantee the two documents were the same document."""
    episode_dir = Path(episode_dir)
    doc = manifest if manifest is not None else _raw_manifest(episode_dir)
    holding_system = _holding_system(doc)
    worlds = _non_control_worlds(doc)
    episode_id = episode_id_of(doc)
    _check_world_labels(episode_id, worlds)
    episode_token = episode_token_for(episode_id)

    rows: list[dict[str, Any]] = []
    facts: dict[str, WorldFacts] = {}
    for world in worlds:
        row, read = _grade_world(episode_dir, world, episode_token=episode_token,
                                holding_system=holding_system)
        rows.append(row)
        if read is not None:
            facts[row["world"]] = read
    # The control's declared disposition through the SAME normalizer the graded worlds' went
    # through: the contrast below is a comparison between the two, and normalizing one side
    # only would make a manifest that spelled the control's word differently read as a contrast
    # that is not there.
    control_declared = normalized_disposition(_control_declared(doc))
    graded = frozenset(r["world"] for r in rows if is_gradable_row(r))
    contrasting = {
        r["world"] for r in rows
        if r["world"] in graded and r.get("declared") is not None
        and r.get("declared") != control_declared
    }
    if not contrasting:
        word = "undecidable"
    elif all(r["verdict"] == r["declared"] for r in rows if r["world"] in graded):
        word = "caught"
    else:
        word = "survived"
    return FamilyGrade(episode_dir=episode_dir, worlds=rows, verdict_word=word,
                       graded_worlds=graded, world_facts=facts)


__all__ = [
    "FamilyGrade", "WorldFacts", "discriminator_of", "episode_id_of", "grade_family",
    "is_gradable_row", "mapping_key", "names_one_file", "read_world_facts", "scope_params",
]
