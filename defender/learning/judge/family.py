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

`verdict == declared` while every H row is `passthrough` (queried, never shown anything) still
buckets `lead-quality` (#1007/N8 retired the old flag this table used to carve out here — see
O4's withholding ladder for what now distinguishes an honest agreement from a lucky one). A
`fault` row on H makes the world `ungradable` (J5's tier rule) rather than any of the above; a
`refused` row on H counts as having queried (F-1) and excludes the world from every failure
bucket without making it ungradable.

THIS MODULE IS ALSO THE ONE HOME of the episode archive's record readers (`raw_manifest`,
`read_review_record`, `read_samples_record`, `read_world_facts`, `screened_yaml_mapping`) and of
the derived accessors named in `__all__` (#1025 O8, prep 2), imported by the judge's input
builder (`render.py`) and by the episode page rather than re-implemented. NOT YET HERE, and
still read by the input builder on its own: `render.episode_alert` / `_world_alert_id` /
`_read_provenance`, its `lessons_loaded.jsonl` read and its `gather_summaries/*.md` walk, and
`enqueue.draws_on_disk` (the per-draw documents). The record NAMES are `branch/archive.py`'s
and the world-table paths are `RunPaths`'s — imported, not re-spelled.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender._io import read_guarded, read_jsonl_rows, read_jsonl_rows_report
from defender._run_paths import RunPaths, artifact_dir, artifact_file
from defender._report import ReportRead, read_report
from defender._run_id import is_valid_run_id
from defender._vocab import normalized_disposition
from defender.learning.branch.ledger import (
    APPLIER_DECISIONS,
    FAULT,
    PASSTHROUGH,
    PATCHED,
    REFUSED,
    STAGED,
    normalized_source,
    request_key,
)
from defender.learning.branch.archive import (
    ALERT_NAME,
    GATHER_SUMMARIES_DIRNAME,
    REVIEW_NAME,
    SAMPLES_NAME,
    WORLDS_DIRNAME,
)
from defender.learning.judge._errors import JudgeRefused
from defender.run_common import resolve_runs_base
from defender.runtime.branch._family import (
    BASE_ROLE,
    MANIFEST_NAME,
    episode_token_for,
    is_reserved_world_label,
    world_token_for,
)
from defender.skills.invlang._walkers import iter_resolutions
from defender.skills.invlang.parser import NO_OPEN_BLOCK, parse_dense_companion, scan_fences

#: The ONE bucket the mechanical pass itself mints on the world lane (M3 row 4 + O4's "including
#: row 1"). Every other world bucket in this design is a model's own string (R2's open
#: vocabulary) — this is the sole arithmetic one.
MECHANICAL_WORLD_BUCKET = "unreachable-difference"

#: `withheld_reason`'s closed domain (O4's own cells plus the episode-wide one).
WITHHELD_MEASURED_NOTHING = "measured_nothing"
WITHHELD_CAPTURE_UNADDRESSED = "capture_unaddressed"
WITHHELD_REACHABILITY_UNMEASURED = "reachability_unmeasured"
WITHHELD_EPISODE_INCOMPLETE = "episode_incomplete"


def screened_yaml_mapping(path: Path, *, what: str) -> dict[str, Any] | None:
    """A YAML mapping at `path` through THE SCREENED READ, or `None` only when NOTHING is at
    the name.

    ONE HOME for the read every episode-level record makes: the file sits in the episode dir,
    a tree a sibling box's rw bind reaches, so an entry at its name may be a link the model
    planted — and `is_file()`/`read_text` follow the link the write side refuses. `read_guarded`
    asks the plainness question of the open descriptor itself. It folds ABSENT in with the
    alias refusal, and here they must stay apart: nothing at the name is an ordinary absence
    (an ungraded episode, an unwritten record) the caller decides about, while SOMETHING that
    is not the record — a link, an unreadable entry, a torn document, a non-mapping — is
    `JudgeRefused`. `_yaml.safe_load` is the hardened loader: a `RecursionError` out of a
    deeply nested document is neither a `YAMLError` nor a `ValueError`, and it converts it.
    Spelled twice (the manifest and the idempotency record), the two reads had already drifted
    on their exception sets."""
    import yaml

    from defender._yaml import safe_load

    if not (path.exists() or path.is_symlink()):
        return None
    text, refusal = read_guarded(path)
    if text is None:
        raise JudgeRefused(f"{what} at {path} could not be read: {refusal}")
    try:
        doc = safe_load(text)
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"{what} at {path} could not be read: {bad}") from bad
    if not isinstance(doc, dict):
        raise JudgeRefused(f"{what} at {path} is not a mapping")
    return doc


def _default_review_reader(path: Path) -> dict[str, Any]:
    """`review.yaml`, through the same guarded read every other episode-dir read in this pass
    makes. ABSENT reads as `{}` (there is nothing to read); an ALIASED entry is this design's
    refusal, because something is there and it is not the record."""
    import yaml

    from defender._yaml import safe_load

    if not (path.exists() or path.is_symlink()):
        return {}
    text, refusal = read_guarded(path)
    if text is None:
        raise JudgeRefused(f"{path} could not be read: {refusal}")
    try:
        doc = safe_load(text) or {}
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"{path} could not be read: {bad}") from bad
    return doc if isinstance(doc, dict) else {}


def read_review_record(episode_dir: Path, *, reader: Any = None) -> dict[str, Any]:
    """`review.yaml`, parsed ONCE per caller. The ONE home for this read: `judge/__init__.py`'s
    own orchestration and `family.grade_family` both want it, and the episode dir is a tree a
    box can reach — two independent parses had no guarantee of agreeing (#1007,
    `test_grade_family_reads_the_review_record_once_through_the_guarded_reader`)."""
    read = reader if reader is not None else _default_review_reader
    return read(Path(episode_dir) / REVIEW_NAME)


def _default_samples_reader(path: Path) -> dict[str, Any]:
    """`samples.yaml`, read PERMISSIVELY: absent, unreadable or unparseable all read as `{}`,
    never a `JudgeRefused`. Unlike `_default_review_reader`, this is deliberate (#1007 M4,
    `test_a_corrupt_or_absent_samples_file_sets_sample_unavailable_for_every_pattern`): the
    review record is load-bearing for O2/O4's withholding ladder, so a fault there ends the
    pass; the sample is evidence for one narrow claim (shape-invention) per world, so one
    damaged file costs those claims their evidence and nothing else — never the whole grade."""
    import yaml

    from defender._yaml import safe_load

    if not (path.exists() or path.is_symlink()):
        return {}
    text, _refusal = read_guarded(path)
    if text is None:
        return {}
    try:
        doc = safe_load(text) or {}
    except yaml.YAMLError:
        return {}
    return doc if isinstance(doc, dict) else {}


def read_samples_record(episode_dir: Path, *, reader: Any = None) -> dict[str, Any]:
    """`samples.yaml`, parsed once per caller — the questioner's own reference document per
    staged pattern, moved into the episode archive at step 2 so it survives a pruned source run
    (#1007 O5/M4)."""
    read = reader if reader is not None else _default_samples_reader
    return read(Path(episode_dir) / SAMPLES_NAME)


def world_review_block(review: dict[str, Any], label: str) -> dict[str, Any] | None:
    """This world's own `reachability` sub-block off the review record, or `None` when the
    review carries no entry for this label at all (a manifest/review disagreement, J-shaped:
    joined BY NAME, never by position — #1007
    `test_a_label_present_in_only_one_artifact_reads_as_an_absent_block`)."""
    worlds = review.get("worlds")
    entry = worlds.get(label) if isinstance(worlds, dict) else None
    if not isinstance(entry, dict):
        return None
    block = entry.get("reachability")
    return block if isinstance(block, dict) else None


#: The M1 fields a #1007 review writes onto every non-control world's reachability block. A
#: review carrying none of them anywhere never ran M1's capture re-ask at all, which is a
#: different fact from "M1 ran and this world's block is missing".
_M1_REACHABILITY_KEYS = ("capture_addressed", "reachable_by_capture", "capture_replays")


def _review_measured_reachability(review: dict[str, Any]) -> bool:
    """Did M1's capture re-ask run in the review this record came from (#1007)?

    Three states, not two. NO WORLD ENTRIES AT ALL is a review that never went through #1007's
    review step (`worlds: {}` — every pre-#1007 fixture): nothing to withhold on. ENTRIES WITH
    REACHABILITY BLOCKS THAT CARRY NONE OF M1'S OWN KEYS is a REAL pre-#1007 record —
    `review._record` always writes one entry per world, so a non-emptiness test read those as
    participating, and every world whose H rows showed nothing was then withheld as
    `capture_unaddressed` (a reason that is false about that episode) with `verdict_word`
    collapsing to `undecidable`. ANYTHING ELSE participates: a block carrying an M1 key, and
    also entries with no block at all, which is "M1 ran and this world's block is missing" —
    the case `test_an_absent_reachability_block_withholds_and_never_mints_unreachable_
    difference` pins as `reachability_unmeasured`.

    THE CONTROL'S OWN BLOCK IS NOT EVIDENCE EITHER WAY, and skipping it is what makes the third
    state reachable in production at all. `review._reachability` adds M1's keys only `if not
    is_control` — while `review._review_world` writes a `reachability` block for EVERY world
    including the base one — so every real #1007 record carries at least one M1-key-less block.
    Counted, it made "M1 ran and this world's block is missing" indistinguishable from a
    pre-#1007 record for any family whose graded worlds' blocks were all absent, and the whole
    withholding ladder went dark (`withheld_reason` forced to `None` family-wide) exactly where
    it is most needed. The fixtures never saw it: they write no control entry."""
    worlds = review.get("worlds")
    if not isinstance(worlds, dict) or not worlds:
        return False
    blocks = [entry["reachability"] for entry in worlds.values()
              if isinstance(entry, dict) and entry.get("role") != BASE_ROLE
              and isinstance(entry.get("reachability"), dict)]
    if not blocks:
        return True
    return any(key in block for block in blocks for key in _M1_REACHABILITY_KEYS)


@dataclass(frozen=True)
class ReachabilityFacts:
    """O2's three executed facts, read off ONE world's review block and validated against
    their own bool|null domain — never coerced (#1007, `test_a_non_boolean_reachable_by_capture
    _reads_as_unmeasured`)."""

    present: bool
    reachable_by_capture: bool | None
    capture_addressed: bool
    capture_reasks_faulted: int
    injected_retrieved: Any
    injected_present: Any


def _reachability_facts(block: dict[str, Any] | None) -> ReachabilityFacts:
    if block is None:
        return ReachabilityFacts(
            present=False, reachable_by_capture=None, capture_addressed=False,
            capture_reasks_faulted=0, injected_retrieved=None, injected_present=None)
    raw = block.get("reachable_by_capture")
    reachable = raw if isinstance(raw, bool) else None
    faulted = block.get("capture_reasks_faulted")
    return ReachabilityFacts(
        present=True, reachable_by_capture=reachable,
        capture_addressed=block.get("capture_addressed") is True,
        # `not isinstance(faulted, bool)`: `bool` IS an `int` subclass, so a `review.yaml`
        # whose `capture_reasks_faulted` is `true` would otherwise be accepted verbatim AS the
        # count — the one coercion this class exists not to make.
        capture_reasks_faulted=(
            faulted if isinstance(faulted, int) and not isinstance(faulted, bool) else 0),
        injected_retrieved=block.get("injected_retrieved"),
        injected_present=block.get("injected_present"))


def _withheld_reason(*, difference_shown: bool, facts: ReachabilityFacts) -> str | None:
    """O4's ladder row 4, as a pure function of what O2/O3 measured — independent of which
    mechanical bucket the row falls into, so a `lead-set`/`lead-quality` world can be withheld
    exactly as a doctored one can (#1007, `test_a_reachable_world_that_showed_nothing_still_
    enqueues_lead_set` is the positive control)."""
    if difference_shown:
        return None
    if not facts.present:
        return WITHHELD_REACHABILITY_UNMEASURED
    if not facts.capture_addressed:
        return WITHHELD_CAPTURE_UNADDRESSED
    if facts.reachable_by_capture is True:
        return None
    if facts.reachable_by_capture is False:
        return WITHHELD_MEASURED_NOTHING
    return WITHHELD_REACHABILITY_UNMEASURED


def declares_difference(overlay: Any) -> bool:
    """Does this world's overlay declare ANY difference — an injection, an exclusion or a
    patch? The three overlay halves are three spellings of one claim ("this world differs"),
    which is why the mechanical world finding checks all three rather than the injection alone
    (#1007, `test_unreachable_difference_fires_for_inject_exclude_and_patch_alike`)."""
    if not isinstance(overlay, dict):
        return False
    if overlay.get("patches"):
        return True
    staged = overlay.get("elastic")  # lint-shippable: ok — the manifest's own field name; see runtime/branch/_family.py's own suppression on the same field
    if isinstance(staged, dict):
        for spec in staged.values():  # lint-shippable: ok — the manifest's own field name
            if isinstance(spec, dict) and (spec.get("inject") or spec.get("exclude")):
                return True
    return False


def _mechanical_world_finding(
    *, label: str, pattern: str, holding_system: str,
) -> dict[str, Any]:
    """The ONE finding the mechanical pass itself mints: `unreachable-difference`, tagged
    `provenance: mechanical` so a same-bucket model draw of the same world never collapses onto
    it (#1007, `test_a_mechanical_world_finding_is_told_from_a_model_drawn_one_by_provenance`)."""
    return {
        "bucket": MECHANICAL_WORLD_BUCKET, "subject": "world",
        "claim": f"world {label!r}'s declared difference could not be reproduced live against "
                 "the capture's own vocabulary",
        "root_cause": "no completed re-ask of a captured query naming this world's staged "
                       "pattern (or, for a patch, its host-side replay) differed from the base",
        "anchor": f"world {label}", "topic": "reachability",
        "evidence": [f"{REVIEW_NAME}#worlds.{label}.reachability"],
        "pattern": pattern, "holding_system": holding_system, "provenance": "mechanical",
    }


def world_pattern(overlay: Any, *, holding_system: str) -> str:
    """The pattern a world row's queue entry cites — the first staged corpus pattern the
    overlay names, or the holding system's own name for a patch-only world (no such pattern
    exists to name).

    A SINGLE, REPRESENTATIVE value, used only where one anchor string is what the caller needs
    (the mechanical `unreachable-difference` finding's own `pattern` field, a per-WORLD claim
    about reachability that names no particular corpus). For anything that must be right per
    STAGED PATTERN — `sample_unavailable`, the judge's own `sample` prompt section (O5) — see
    `staged_patterns` below; `world_pattern` reducing to "the first one" is exactly the gap
    O5's own falsifier names for those two."""
    return next(iter(staged_patterns(overlay)), holding_system)


def staged_patterns(overlay: Any) -> list[str]:
    """EVERY staged pattern this world's overlay names, in a stable order — the
    domain O5 quantifies over ("per staged pattern"), never reduced to one.

    A world staging into two staged patterns and shown a sample for only one is exactly O5's
    falsifier: `sample_unavailable` read `false` (because SOME pattern had a sample) while the
    judge was rendered nothing for the pattern it was never shown. Empty for a patch-only world
    — no pattern exists to enumerate, and the caller falls back to the holding system's
    own name (`world_pattern`) for its single anchor use."""
    if isinstance(overlay, dict):
        staged = overlay.get("elastic")  # lint-shippable: ok — the manifest's own field name; see runtime/branch/_family.py's own suppression on the same field
        if isinstance(staged, dict) and staged:
            return sorted(str(k) for k in staged)
    return []


def sample_patterns(overlay: Any, *, holding_system: str) -> list[str]:
    """The patterns a world is graded and rendered PER: `staged_patterns`, or for a patch-only
    world the holding system's own name — the single anchor `world_pattern` also falls back
    to. ONE spelling, so the row's `sample_unavailable_patterns` and the prompt's sample
    section quantify over the same list; spelled at each site, the fallback for a patch-only
    world could change in one and not the other with no test between them."""
    return staged_patterns(overlay) or [holding_system]


@dataclass
class FamilyGrade:
    """The mechanical pass's own output: per-world rows plus the family's word.

    `worlds` carries EVERY declared non-control world, ungradable ones included (J5: an
    exclusion has to be traceable on the record). `graded_worlds` names the ones that
    contributed to `verdict_word`. `world_facts` is what this pass READ, per world it got as
    far as reading — handed on so the render does not open the same three files again; it is
    an in-memory by-product of the pass and is not part of `judge.yaml`.

    `measuring_worlds` (#1007) is the subset of `graded_worlds` whose `withheld_reason` is
    `None` — the ones `verdict_word` is computed over. `withheld_worlds` is graded worlds NOT in
    that set."""

    episode_dir: Path
    worlds: list[dict[str, Any]] = field(default_factory=list)
    verdict_word: str = "undecidable"
    graded_worlds: frozenset[str] = field(default_factory=frozenset)
    world_facts: dict[str, WorldFacts] = field(default_factory=dict)
    measuring_worlds: frozenset[str] = field(default_factory=frozenset)
    withheld_worlds: frozenset[str] = field(default_factory=frozenset)


def raw_manifest(episode_dir: Path) -> dict[str, Any]:
    """The manifest as a mapping, or this design's refusal.

    THE SCREENED READ THE MANIFEST'S OWNER MAKES (`screened_yaml_mapping`), not a plain
    `read_text`: `_family._read_document` reads this same file through `read_guarded` for a
    stated reason — "the episode dir is reachable from a sibling box's rw bind, so an entry at
    the manifest's name may be a link the model planted — and a plain `read_text` follows the
    link the write side refuses". The judge reads the same bytes to decide which worlds there
    are, what H is and what each world's ground truth is, so a link the launcher refuses must
    not be one the grader honours. ABSENT is a refusal here too: an episode with no manifest
    has nothing to grade."""
    path = Path(episode_dir) / MANIFEST_NAME
    doc = screened_yaml_mapping(path, what="the manifest")
    if doc is None:
        raise JudgeRefused(f"the manifest at {path} could not be read: nothing is at that name")
    return doc


def queries_by_lead(world_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """The world's ISSUED queries, grouped by lead, in ONE parse.

    Called once per world rather than once per lead: the per-lead chain used to re-read and
    re-parse `executed_queries.jsonl` inside its own comprehension, so a world with N leads
    parsed the same table N times.

    THE SENTINEL PARTITION IS THE WRITER'S OWN, through `is_reserved_query_id` — the same
    predicate `lead_repository.QueryRow.is_sentinel` asks, so a fourth sentinel partitions here
    on the day it is defined. A `∅.`-prefixed row records the lead's CONDUCT (a repeat the
    guard refused, a call the argument schema turned back, a failed reducer shim); nothing it
    describes reached a system of record. Grouped in with the rest they reached VIEW 1 as
    queries the world issued and payload digests it read — under a task that asks the model to
    say, per held row, "whether it was derived from a payload the defender actually read, or
    invented". That is a defender failure invented out of a call the defender was refused.
    `lead_repository.actor_view`'s docstring records this exact bug being fixed once already,
    for the actor."""
    from defender.scripts.gather_tools.record_query import is_reserved_query_id

    eq_path = RunPaths(world_dir).executed_queries
    # `artifact_file` on every entry this module admits out of the archived world dir — the
    # `lstat` posture `archive.py` applies when it WRITES these names (`lead_repository`'s own
    # readers of this table still follow a link at it; the two are reconciled in a follow-up).
    # A link admitted here puts another tree's rows into VIEW 1 as this world's own conduct.
    if not artifact_file(eq_path):
        return {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in read_jsonl_rows(eq_path):
        lead_id = row.get("lead_id")
        query_id = row.get("query_id")
        if isinstance(query_id, str) and is_reserved_query_id(query_id):
            continue
        if isinstance(lead_id, str):
            grouped.setdefault(lead_id, []).append(row)
    return grouped


def lead_chain(world_dir: Path, lead_id: str, resolutions_by_lead: dict[str, list[dict]],
               *, issued: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """One lead's chain — goal, first params, payload digests, gather summary, the issued rows
    and the lead's resolutions — off the world's archived files, with `issued` being
    `queries_by_lead(world_dir)` computed ONCE by the caller (a world with N leads used to
    parse the queries table N times)."""
    goal = None
    # THE ID IS MODEL-AUTHORED and this is where it becomes a path. `names_one_file` refuses a
    # token that would read outside the graded world — a `[../../c/report ...]` resolution row
    # otherwise put a counterfactual sibling's whole `report.md` into this world's own prompt,
    # under `- summary:`, as a fact about the world being graded (O5/J14).
    safe = names_one_file(lead_id)
    # THE DIRECTORY IS SCREENED AS WELL AS THE LEAF. `artifact_file` lstats the entry it is
    # given, so a link planted at `gather_raw/` (or `gather_summaries/`) itself would put
    # another tree's regular files through a leaf check that passes — the same `artifact_dir`
    # posture `lead_repository.load_leads` takes on the lead table.
    gather_raw = RunPaths(world_dir).gather_raw
    lead_file = gather_raw / f"{lead_id}.lead.json"
    if safe and artifact_dir(gather_raw) and artifact_file(lead_file):
        data = json_mapping(lead_file)
        if data is not None:
            goal = data.get("goal")
    queries = issued.get(lead_id, [])
    params = queries[0].get("params") if queries else None
    summaries_dir = world_dir / GATHER_SUMMARIES_DIRNAME
    summary_path = summaries_dir / f"{lead_id}.md"
    summary = None
    if not safe:
        summary = ("(this lead id does not name a file inside this world, so no gather summary "
                   "was read for it)")
    elif artifact_dir(summaries_dir) and artifact_file(summary_path):
        # `errors="replace"`, not a bare read. This is MODEL-WRITTEN text in a tree the box can
        # write, so an undecodable byte in it is an ordinary thing to meet; raising here would
        # be an unreadable summary costing the whole episode its grade, and the substitution
        # character is exactly what the judge should be shown of a byte nobody can read.
        summary = summary_path.read_text(encoding="utf-8", errors="replace")
    return {
        "goal": goal, "params": params, "payload": [q.get("payload_digest") for q in queries],
        "summary": summary, "document_rows": queries,
        "resolutions": resolutions_by_lead.get(lead_id, []),
    }


def json_mapping(path: Path) -> dict[str, Any] | None:
    """One JSON artifact as a mapping, or `None` when it is not readable as one.

    ONE HOME for the tolerance policy — which exception classes are survivable and whether a
    non-mapping counts as unreadable — because five readers in this package want the same
    answer (`alert.json` twice, `provenance.json`, a lead's `.lead.json`, and the enqueue's own
    episode alert). Spelled per site, a class that has to be added later (a `RecursionError` out
    of a deeply nested document is neither `OSError` nor `ValueError`) has to be found five
    times, and the sites are far enough apart that only a grep finds them.

    AND ONE HOME FOR THE LINK POLICY. Every one of those five files sits in a tree a box can
    reach, and three of the five callers have no `lstat` screen of their own — a plain
    `read_text` at `worlds/<X>/provenance.json` followed a planted link and handed the pass an
    attacker-chosen `commit` to `git show` every lesson at. `read_guarded` asks the plainness
    question of the open descriptor itself (`O_NOFOLLOW`, a link count of one, a regular file),
    and answers absent, unreadable and undecodable the same way this reader already did:
    `None`."""
    text, _refusal = read_guarded(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


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
    otherwise resolve to wrong-but-real content instead of failing loudly.

    RESERVED LABELS, CHECKED HERE TOO. `_family.check_identities` refuses `"base"`/`"family"`
    at manifest load, but `grade_episode` is a directly-callable entry point over a
    `review.yaml`/manifest that need not have passed through the launcher (a re-entered or
    hand-assembled episode) — so this gate re-checks the same reserved set independently,
    rather than trusting a validation the caller may have skipped. Without it, a world literally
    labeled `"family"` mints the SAME `finding_id`/`source_run_dir` coordinate and the SAME
    `worlds/family/judge/` archive path as the family-level call's own draws (M5,
    `build_finding_row`'s `label == "family"` branch) — the collision M5's own docstring claims
    can never happen."""
    for world in worlds:
        label = world.get("world_id")
        if isinstance(label, str) and is_reserved_world_label(label):
            # THE PREDICATE OWNS TWO RULES, so the message names both rather than only the set
            # arm — `is_reserved_world_label` also matches the `family_<n>` DRAW shape (#1007),
            # and a label refused for that arm was being told it had claimed a reserved name it
            # is not, sending an operator to rename away from a set its label was never in.
            raise JudgeRefused(
                f"world label {label!r} is reserved — it is the family's own base capture, the "
                "family-level judge call, or one of that call's own `family_<n>` draws — a "
                "graded world claiming it would collide with the family call's own agent id "
                "and archive path (M5)")
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


def own_h_rows(rows: list[dict[str, Any]], holding_system: str) -> list[dict[str, Any]]:
    """The world's ledger rows ON H — each row's `system`, after strip+casefold, equal to
    `holding_system`.

    PRECONDITION: `holding_system` is ALREADY the folded spelling — `_holding_system(doc)`'s
    answer, which is also what every world row carries as its own `holding_system` field. The
    manifest's raw `discriminator.holding_system` (unfolded, mixed case) compared here answers
    no rows at all; a reader outside the pass takes H off the row, not off the manifest."""
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
    world_dir = Path(episode_dir) / WORLDS_DIRNAME / label
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
    review_block: dict[str, Any] | None = None, episode_incomplete: bool = False,
    withholding_applies: bool = True, samples: dict[str, Any],
) -> tuple[dict[str, Any], WorldFacts | None]:
    """@owns has_refused, @owns sample_unavailable, @owns sample_unavailable_patterns — the
    SOLE producer of these three world-row fields; the comments beside each say why. In the
    DOCSTRING, not a comment, because that is where `lint_unowned_field` reads the claim from:
    a second producer anywhere fails the duplicate-owner gate only if this one is registered."""
    label = world["world_id"]
    raw_declared = world.get("disposition_declared")
    # ONE COLUMN, ONE VOCABULARY. `declared` is the NORMALIZED value on every row that has one
    # and `None` on every row that does not — never the raw manifest text on some rows and the
    # normalized value on others, which is what an early `declared: raw` gave a world that then
    # returned ungradable, and which put two spellings of one word in one table.
    # `holding_system` IS ON EVERY ROW THIS FRAME RETURNS, including the three ungradable early
    # returns below. It is the PASS's own value (the manifest's single validated
    # `discriminator.holding_system`), not a measurement, so a world the tier rule excluded
    # still carries it — and `enqueue_report`'s `family_holding_system` scavenges it off these
    # rows to stamp the family-level lane's own required keys. Set only in the terminal
    # `row.update(...)`, an episode whose worlds are ALL ungradable left it `""` there, and
    # every family-level finding — the one thing that episode shape exists to report — was
    # refused by `_validate_world_row`'s non-empty-string rule and filed as a model defect.
    row: dict[str, Any] = {"world": label, "declared": normalized_disposition(raw_declared),
                           "holding_system": holding_system}
    world_dir = Path(episode_dir) / WORLDS_DIRNAME / label
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
        h_rows = own_h_rows(facts.ledger_rows, holding_system)
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

    # M2's witness (O3): `differs_from_base` is written ONLY on `staged` rows, and its domain
    # is `bool | null` — `null` when the witness read itself faulted. NOT FALSE is the rule for
    # BOTH readings this field must survive: a pre-#1007 fixture (or any non-staged system's
    # row) that never carries the key at all reads as `.get(...) is None`, identically to a
    # witness that ran and faulted — and neither is the one fact this field exists to record
    # ("the payload served genuinely differed"), so both lean toward NOT excusing the defender
    # rather than toward withholding a real finding. `patched` rows carry no witness at all
    # (M2's own scope) and count unconditionally: H1 already makes the applier report `PATCHED`
    # only when the merged content differs from what an unpatched read would have served, so
    # RS-2's "PATCHED implied shown, wrongly" is closed at ITS root rather than by a second
    # witness here.
    difference_shown = any(
        r.get("source") == PATCHED
        or (r.get("source") == STAGED and r.get("differs_from_base") is not False)
        for r in h_rows)

    facts_o2 = _reachability_facts(review_block)
    if not withholding_applies:
        # M1 never participated in this review at all (see `grade_family`'s own comment) — O4's
        # whole withholding ladder, `episode_incomplete` included, has nothing to withhold ON:
        # a review record with no per-world reachability data anywhere is a review that never
        # went through #1007's review step at all (every pre-#1007 fixture), and "no served
        # row anywhere" reads exactly like the ordinary "the sibling queried nothing" case those
        # fixtures already pin — not evidence the episode died mid-run.
        withheld_reason = None
    else:
        withheld_reason = (
            WITHHELD_EPISODE_INCOMPLETE if episode_incomplete
            else _withheld_reason(difference_shown=difference_shown, facts=facts_o2))

    # THE MECHANICAL WORLD FINDING IS NOT GATED ON `episode_incomplete`. Reachability is a
    # REVIEW-TIME fact (M1's capture re-ask, step 4) — decided before any sibling even runs
    # (step 5) — so it exists independently of whether the sibling ever queried anything; only
    # the DEFENDER lane's withholding depends on whether the episode ran at all
    # (`test_unreachable_difference_fires_even_with_no_row_on_the_holding_system`, whose own
    # served ledger is empty and still mints this finding).
    mechanical_findings: list[dict[str, Any]] = []
    pattern = world_pattern(world.get("overlay"), holding_system=holding_system)
    if (not difference_shown and facts_o2.reachable_by_capture is False
            and declares_difference(world.get("overlay"))):
        mechanical_findings.append(_mechanical_world_finding(
            label=label, pattern=pattern, holding_system=holding_system))
    # `sample_unavailable` / `sample_unavailable_patterns` — the SOLE producer of both row
    # fields (owned in the docstring). #1007 M4/O5: no sample was captured for a staged
    # pattern — matched by EXACT string, never case-folded (a differently-cased overlay pattern
    # stages a different index and would otherwise be graded against another corpus's
    # document). A pattern present but mapped to `null` reads identically to an absent key —
    # both are "nothing to compare against"
    # (`test_a_corrupt_or_absent_samples_file_sets_sample_unavailable_for_every_pattern`).
    #
    # OVER EVERY STAGED PATTERN, not `world_pattern`'s single representative one — a world
    # staging into two staged patterns and shown a sample for only one is O5's own falsifier
    # (`test_a_two_pattern_world_names_each_patterns_sample_availability_independently`).
    # `sample_unavailable_patterns` is that per-pattern detail; `sample_unavailable` stays the
    # aggregate bool ("was ANY staged pattern's sample missing") the existing single-pattern
    # tests and `judge/__init__.py`'s blanket callers already read.
    world_staged_patterns = sample_patterns(world.get("overlay"), holding_system=holding_system)
    sample_unavailable_patterns = [
        p for p in world_staged_patterns if samples.get(p) is None]
    sample_unavailable = bool(sample_unavailable_patterns)

    row.update(
        holding_queried=holding_queried, scope_discriminated=scope_discriminated,
        doctored_answer_served=doctored, resolution_moved=resolution_moved,
        # `has_refused` (owned in the docstring) — STORED beside the flags the ladder below
        # reads, because the `lead-quality` / `None` branch turns on it and a reader of the row
        # (the episode page, #1025 O3) could otherwise not tell a world excused for a refusal
        # from one that queried nothing worth grading. The SAME local the ladder branches on,
        # never re-derived.
        has_refused=has_refused,
        verdict=verdict, malformed_rows=facts.malformed_rows,
        # SAID SEPARATELY from `holding_queried: false`, because the two are different failures
        # and the lesson each deserves is different. A world with no rows on the holding system
        # may still have queried elsewhere; a world that served NOTHING AT ALL never made a
        # single live call, so its staged difference was never consulted and its verdict is not
        # a measurement — the sibling closed without ever opening its own world.
        #
        # From the ROWS, not from the file: the writer creates a world's ledger when the world
        # starts (`Ledger.declare`), so an absent file is once again an incomplete archive and
        # J5's tier rule keeps its meaning. Derived from absence, this fact and that refusal
        # would be competing readings of one missing file.
        served_nothing=not facts.ledger_rows,
        # #1007's per-world facts (O2/O3/O4/M3), the row shape `test_grade_episode_returns_
        # extended_record` pins.
        difference_shown=difference_shown,
        reachable_by_capture=facts_o2.reachable_by_capture,
        capture_addressed=facts_o2.capture_addressed,
        capture_reasks_faulted=facts_o2.capture_reasks_faulted,
        injected_retrieved=facts_o2.injected_retrieved,
        injected_present=facts_o2.injected_present,
        withheld_reason=withheld_reason,
        # `world_findings` starts as exactly the mechanical ones and the orchestration EXTENDS
        # it with this world's own model-drawn `subject: world` findings once its draws
        # complete (#1007 M4) — the row reads as "every world finding about this world", while
        # `mechanical_world_findings` stays the STABLE subset `enqueue_report`'s dedicated
        # fixed-coordinate walk enqueues (never re-walking `world_findings`, which would double
        # -count a model draw already enqueued through the per-draw loop).
        world_findings=list(mechanical_findings),
        mechanical_world_findings=mechanical_findings,
        sample_unavailable=sample_unavailable,
        sample_unavailable_patterns=sample_unavailable_patterns,
        # THE PASS'S OWN `pattern`/`holding_system`, on the row (A3: identity belongs to the
        # pass). `enqueue_report` fills either one in on a model-drawn world finding that
        # omitted it, so `_validate_world_row`'s non-empty-string rule is met by a value this
        # pass derived rather than by one a model had to remember to emit.
        pattern=pattern,
        holding_system=holding_system,
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
    agreed_without_difference = False
    if not holding_queried:
        bucket = "lead-set"
    elif not doctored:
        # F-1: a refused H interaction counts as having queried, and is excluded from the
        # failure buckets rather than defaulted into `lead-quality`. The OLD "agreed-without-
        # evidence" special case (verdict == declared while every H row is passthrough) is
        # REMOVED (N8): O4's withholding ladder above now carries that distinction — a world
        # that agreed having been shown nothing still buckets `lead-quality`, and whether its
        # finding is actually enqueued turns on `withheld_reason` (reachable_by_capture), not
        # on a bucket-level flag.
        bucket = None if has_refused else "lead-quality"
    elif difference_shown:
        # Ladder row 3 — UNCHANGED.
        if verdict == declared:
            bucket = None
        elif resolution_moved:
            bucket = "decision-discipline"
        else:
            bucket = "analyze-discipline"
    else:
        # Ladder row 4: staged/patched rows exist, but nothing was SHOWN.
        if facts_o2.reachable_by_capture is True:
            # "the sibling scoped the difference out; a captured query would have shown it" —
            # a real coverage gap regardless of the eventual verdict.
            bucket = "lead-quality"
        elif verdict == declared:
            bucket = None
            agreed_without_difference = True
        elif resolution_moved:
            bucket = "decision-discipline"
        else:
            bucket = "analyze-discipline"
    row["bucket"] = bucket
    row["agreed_without_difference"] = agreed_without_difference
    return row, facts


def is_gradable_row(row: Any) -> bool:
    """Did this world contribute to the family's word? ONE predicate, because four sites asked
    it and two of them asked it differently: `r.get("ungradable") is not True` here against
    `not r.get("ungradable")` in the orchestration and the appender, which disagree for every
    truthy non-`True` value a hand-edited or model-written `judge.yaml` can carry — so
    `graded_worlds` on the record could name a world the enqueue had silently skipped."""
    return isinstance(row, dict) and not row.get("ungradable")


def _episode_has_any_served_row(
    episode_dir: Path, worlds: list[dict[str, Any]], *, episode_token: str,
) -> bool:
    """Was ANY row served anywhere in this episode — not merely on the holding system?

    A LIGHTWEIGHT pre-check, read separately from `_grade_world`'s own ledger read: whether the
    episode is complete at all has to be known BEFORE any single world's `withheld_reason` can
    be computed (#1007, `test_an_episode_killed_before_the_sibling_ran_withholds_with_episode_
    incomplete`), so this reads first and cheaply rather than threading a two-pass state machine
    through `_grade_world` itself. A world whose ledger cannot even be read (J5 tier 1/2, which
    `_grade_world` will mark `ungradable` on its own pass) contributes nothing here either way."""
    for world in worlds:
        label = world.get("world_id")
        if not isinstance(label, str) or not label:
            continue
        path = world_ledger_path(episode_dir, label, episode_token=episode_token)
        try:
            rows, _malformed = _read_world_ledger(
                path, world_token_for(episode_token, label))
        except JudgeRefused:
            continue
        if rows:
            return True
    return False


def grade_family(
    episode_dir: Path, *, manifest: dict[str, Any] | None = None,
    review: dict[str, Any] | None = None, review_reader: Any = None,
    samples: dict[str, Any] | None = None,
) -> FamilyGrade:
    """The mechanical pass: per-world facts and a bucket per non-control world, plus the
    family's `verdict_word`. Self-contained over `episode_dir` alone — no comparator call,
    order-independent across worlds (O3).

    Refuses only for a fault in the MANIFEST, which is what says which worlds there are. A
    fault in one world's own archive marks that world `ungradable` and grades the rest — see
    the module docstring on where a refusal stops.

    `manifest` is THE PASS'S OWN PARSE, when the caller has one — the same hand-over `render`
    already takes. `review` is likewise the caller's own already-parsed record (#1007's
    orchestration reads it once for its own outcome check and hands it over here); when neither
    is given, this pass reads `review.yaml` itself, through `review_reader` when injected,
    EXACTLY ONCE regardless of world count (#1007, `test_grade_family_reads_the_review_record_
    once_through_the_guarded_reader`).

    `samples` IS THE SAME HAND-OVER, and for the same reason `review` is. `samples.yaml` sits
    in the box-reachable episode dir, and `judge/__init__._grade_episode` parses it to thread
    into every `render` — so a second, independent parse here let the mechanical row's
    `sample_unavailable_patterns` and the `sample` prompt section that claims to explain it
    come off two different documents, which is exactly what `manifest=`/`review=` exist to
    prevent. Absent, this pass reads it itself, permissively (`read_samples_record` —
    absent/unparseable reads as `{}`), to compute each row's `sample_unavailable` (#1007
    M4/O5)."""
    episode_dir = Path(episode_dir)
    doc = manifest if manifest is not None else raw_manifest(episode_dir)
    holding_system = _holding_system(doc)
    worlds = _non_control_worlds(doc)
    episode_id = episode_id_of(doc)
    _check_world_labels(episode_id, worlds)
    episode_token = episode_token_for(episode_id)
    review_doc = review if review is not None else read_review_record(
        episode_dir, reader=review_reader)
    samples_doc = samples if samples is not None else read_samples_record(episode_dir)

    # GATED ON THERE BEING A SIBLING TO SPEAK OF (len(worlds) >= 2). A single-world episode
    # whose one world queried nothing is structurally identical to the ordinary "no row on H"
    # case the withholding ladder already reads correctly off `reachable_by_capture` alone
    # (`test_a_reachable_world_that_showed_nothing_still_enqueues_lead_set`, one world, empty
    # ledger, `reachable_by_capture: true` — NOT episode_incomplete). "The episode died before
    # any sibling ran" is a fact only a FAMILY OF SIBLINGS can be caught in — there is nothing
    # for one lone world to have been killed before.
    episode_incomplete = len(worlds) >= 2 and not _episode_has_any_served_row(
        episode_dir, worlds, episode_token=episode_token)
    # DID M1 PARTICIPATE IN THIS REVIEW AT ALL? A review record whose `worlds` carries no entry
    # for ANY world (never run through M1's capture re-ask — every #921/#947 fixture predating
    # #1007, which write `review.yaml` with `worlds: {}`) is a DIFFERENT fact from "M1 ran and
    # this particular world's block is missing" (`test_a_label_present_in_only_one_artifact_
    # reads_as_an_absent_block`, where OTHER worlds in the same record do carry a block). Only
    # the second is withheld as `reachability_unmeasured`; the first withholds nothing; O2/O4
    # are additive facts a review that never measured them at all cannot make.
    # ASKED OF THE M1 KEYS THEMSELVES, never of "the `worlds` map is non-empty". A REAL
    # pre-#1007 `review.yaml` carries one entry per world (`review._record` always writes them)
    # whose `reachability` block simply lacks M1's own fields — so a non-emptiness test reads
    # `m1_participates` True there, `capture_addressed` is absent hence False, and every world
    # whose H rows showed nothing is withheld as `capture_unaddressed`: a reason that is false
    # about that episode, and `verdict_word` collapses to `undecidable` with every defender
    # finding diverted to `withheld_findings`. Only the `worlds: {}` fixtures were caught.
    m1_participates = _review_measured_reachability(review_doc)

    rows: list[dict[str, Any]] = []
    facts: dict[str, WorldFacts] = {}
    for world in worlds:
        label = world.get("world_id")
        block = (world_review_block(review_doc, label)
                if m1_participates and isinstance(label, str) else None)
        row, read = _grade_world(episode_dir, world, episode_token=episode_token,
                                holding_system=holding_system, review_block=block,
                                episode_incomplete=episode_incomplete,
                                withholding_applies=m1_participates, samples=samples_doc)
        rows.append(row)
        if read is not None:
            facts[row["world"]] = read
    # The control's declared disposition through the SAME normalizer the graded worlds' went
    # through: the contrast below is a comparison between the two, and normalizing one side
    # only would make a manifest that spelled the control's word differently read as a contrast
    # that is not there.
    control_declared = normalized_disposition(_control_declared(doc))
    graded = frozenset(r["world"] for r in rows if is_gradable_row(r))
    # #1007/O4: `verdict_word` is computed over MEASURING worlds only — a graded world whose
    # `withheld_reason` is set contributed no observation the family's word can rest on, exactly
    # as an ungradable one already did not (`test_a_withheld_world_does_not_vote_in_verdict_
    # word`, `test_verdict_word_is_undecidable_when_no_world_measured`).
    measuring = frozenset(
        r["world"] for r in rows if r["world"] in graded and r.get("withheld_reason") is None)
    withheld = graded - measuring
    contrasting = {
        r["world"] for r in rows
        if r["world"] in measuring and r.get("declared") is not None
        and r.get("declared") != control_declared
    }
    if not contrasting:
        word = "undecidable"
    elif all(r["verdict"] == r["declared"] for r in rows if r["world"] in measuring):
        word = "caught"
    else:
        word = "survived"
    return FamilyGrade(episode_dir=episode_dir, worlds=rows, verdict_word=word,
                       graded_worlds=graded, world_facts=facts,
                       measuring_worlds=measuring, withheld_worlds=withheld)


__all__ = [
    "FamilyGrade", "MECHANICAL_WORLD_BUCKET", "ReachabilityFacts", "WorldFacts",
    "declares_difference", "discriminator_of", "episode_id_of", "grade_family",
    "is_gradable_row", "json_mapping", "lead_chain", "mapping_key", "names_one_file",
    "own_h_rows", "queries_by_lead", "raw_manifest", "read_review_record",
    "read_samples_record", "read_world_facts", "sample_patterns", "scope_params",
    "screened_yaml_mapping", "staged_patterns", "world_pattern", "world_review_block",
]
