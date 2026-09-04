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

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender._text import strip_zero_width
from defender._vocab import normalized_disposition
from defender.learning.branch.ledger import normalized_source, request_key
from defender.learning.judge._errors import JudgeRefused
from defender.run_common import resolve_runs_base
from defender.runtime.branch._family import BASE_ROLE, episode_token_for, world_token_for
from defender.skills.invlang.parser import scan_fences

#: `report.md`'s bare `disposition: <word>` line, as this archive's fixtures write it (no YAML
#: frontmatter fence — see the module docstring on why `_report.read_report` is not used here).
_DISPOSITION_LINE_RE = re.compile(r"^disposition:\s*(.*?)\s*$", re.MULTILINE)


@dataclass
class FamilyGrade:
    """The mechanical pass's own output: per-world rows plus the family's word.

    `worlds` carries EVERY declared non-control world, ungradable ones included (J5: an
    exclusion has to be traceable on the record). `graded_worlds` names the ones that
    contributed to `verdict_word`."""

    episode_dir: Path
    worlds: list[dict[str, Any]] = field(default_factory=list)
    verdict_word: str = "undecidable"
    graded_worlds: frozenset[str] = field(default_factory=frozenset)


def _raw_manifest(episode_dir: Path) -> dict[str, Any]:
    import yaml

    path = Path(episode_dir) / "family.yaml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as bad:
        raise JudgeRefused(f"the manifest at {path} could not be read: {bad}") from bad
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"the manifest at {path} could not be read: {bad}") from bad
    if not isinstance(doc, dict):
        raise JudgeRefused(f"the manifest at {path} is not a mapping")
    return doc


def _holding_system(doc: dict[str, Any]) -> str:
    """J1: `H` validated at manifest load — present, non-empty, a served-system name after
    strip+casefold. Refuses loudly otherwise; every per-world fact keys on `system == H`."""
    from defender.learning.branch.estate.stagers.dispatch import STAGERS
    from defender.runtime.branch._family import PATCHABLE_SYSTEMS

    served = {s.casefold() for s in (set(STAGERS) | set(PATCHABLE_SYSTEMS))}
    discriminator = doc.get("discriminator")
    raw = discriminator.get("holding_system") if isinstance(discriminator, dict) else None
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
    entries = [w for w in raw if isinstance(w, dict)]
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


def _check_run_id_collision(episode_id: str, worlds: list[dict[str, Any]]) -> None:
    """F-3: a world label colliding with a real run under the operator's runs base is refused
    at manifest load — the last-segment resolver every family row's `source_run_dir` reaches
    would otherwise resolve to wrong-but-real content instead of failing loudly."""
    try:
        base = resolve_runs_base()
    except Exception:  # noqa: BLE001 — an unconfigured runs base means nothing to collide with
        return
    for world in worlds:
        label = world.get("world_id")
        if isinstance(label, str) and (base / label).is_dir():
            raise JudgeRefused(
                f"world label {label!r} collides with a real run under the operator's runs "
                f"base ({base / label}) — a family row's source_run_dir naming this label "
                "would resolve to that run's content rather than this world's own archive; "
                "rename one of the two")


def _row_key(row: dict[str, Any]) -> str:
    return request_key(str(row.get("system") or ""), str(row.get("verb") or ""),
                       row.get("params") if isinstance(row.get("params"), dict) else {})


def _read_world_ledger(path: Path, world_token: str) -> tuple[list[dict[str, Any]], int]:
    """J3: this world's own decision rows, first-row-wins on a duplicate pair-key, a malformed
    line skipped and counted rather than failing the world."""
    if not path.is_file():
        raise JudgeRefused(f"the ledger at {path} is absent")
    text = path.read_text(encoding="utf-8")
    kept: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    malformed = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if not isinstance(row, dict) or normalized_source(row.get("source")) is None:
            malformed += 1
            continue
        if row.get("world_id") != world_token:
            # A family-tier row (`world_id: null`) or a stray row for a different world (J2):
            # inert to every per-world fact, and not a malformed line either.
            continue
        key = _row_key(row)
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
    asked = row.get("asked_params")
    params = asked if isinstance(asked, dict) else row.get("params")
    if not isinstance(params, dict):
        return False
    return all(params.get(k) is not None for k in ("index", "window", "scope_key"))


def _resolution_facts(text: str, *, world: str) -> tuple[bool, frozenset[str]]:  # noqa: C901 — one small state machine over one document's fences; splitting it would separate the malformed-fence check from the rows it guards
    """`resolution_moved` plus the lead ids the document's own `:T resolutions` rows name.

    Reads every `:T resolutions` fence body in the world's OWN archived document — the
    manifest's `fences_at` has no reachable relationship to a per-world archived document's
    fence positions in this design's own hand-built fixtures (`archived_judge_world`'s local
    `fences_at` parameter is never threaded into `family.yaml`), so slicing by it would make
    this fact permanently `False`. Declared as a mechanism deviation in the PR body.

    `before != after` on ANY row is enough (J4: "was the hand-off revisited", not "did the net
    state move") — an oscillating lead's first qualifying row is not discarded for the net
    state. A document with an unclosed invlang fence is malformed and refuses the pass loudly.
    """
    scan = scan_fences(text)
    if scan.open_tail is not None:
        raise JudgeRefused(
            f"world {world!r}: investigation.md has an unclosed invlang fence — a truncated "
            "document cannot be graded")
    moved = False
    leads: set[str] = set()
    for body in scan.bodies:
        stripped = body.strip()
        if not stripped.startswith(":T resolutions"):
            continue
        rest = stripped[len(":T resolutions"):]
        try:
            import yaml

            rows = yaml.safe_load(rest) if rest.strip() else []
        except Exception as bad:  # noqa: BLE001 — any parse fault here is this block's own
            raise JudgeRefused(
                f"world {world!r}: investigation.md's `:T resolutions` block could not be "
                f"read: {bad}") from bad
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            raise JudgeRefused(
                f"world {world!r}: investigation.md's `:T resolutions` block is not a list "
                "of rows")
        for row in rows:
            if not isinstance(row, dict):
                continue
            lead = row.get("lead")
            if isinstance(lead, str) and lead:
                leads.add(lead)
            before, after = row.get("before"), row.get("after")
            if before is not None and after is not None and before != after:
                moved = True
    return moved, frozenset(leads)


def _read_verdict(report_path: Path, *, world: str) -> str:
    try:
        text = report_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as bad:
        raise JudgeRefused(f"world {world!r}: report.md could not be read: {bad}") from bad
    match = _DISPOSITION_LINE_RE.search(text)
    raw = match.group(1) if match else None
    cleaned = strip_zero_width(raw).strip() if isinstance(raw, str) else raw
    verdict = normalized_disposition(cleaned)
    if verdict is None:
        raise JudgeRefused(
            f"world {world!r}: report.md disposition {raw!r} is outside the disposition "
            "vocabulary")
    return verdict


def _check_gather_summaries(world_dir: Path, *, world: str, referenced_leads: frozenset[str]) -> None:
    """F-7: a partial archive — all five required inputs present, `gather_summaries/` short of
    a lead its own document references — is MALFORMED, refused loudly and NAMING the input
    that was short, which is what tells an operator a partial archive from a genuine one."""
    summaries = world_dir / "gather_summaries"
    if not summaries.is_dir():
        return
    missing = sorted(lead for lead in referenced_leads if not (summaries / f"{lead}.md").is_file())
    if missing:
        raise JudgeRefused(
            f"world {world!r}: gather_summaries/ is short {missing} — the archive left this "
            "world's supporting directory short of a lead its own investigation.md references; "
            "refusing rather than grading on a thinner view than it appears to have")


def _missing_required_input(
    *, world_dir: Path, ledger_path: Path, alert_path: Path, declared: Any,
) -> str | None:
    if not ledger_path.is_file():
        return f"served ledger ({ledger_path})"
    if not (world_dir / "report.md").is_file():
        return "report.md"
    if not (world_dir / "investigation.md").is_file():
        return "investigation.md"
    if not alert_path.is_file():
        return "alert.json"
    if not isinstance(declared, str) or not declared:
        return "disposition_declared"
    return None


def _grade_world(  # noqa: C901, PLR0912 — the tier rule and the bucket state machine are one demand (J5 + the mechanical bucket table); splitting them would let a caller reach the bucket logic on a world the tier rule never cleared
    episode_dir: Path, world: dict[str, Any], *, episode_token: str, holding_system: str,
) -> dict[str, Any]:
    label = world["world_id"]
    row: dict[str, Any] = {"world": label, "declared": world.get("disposition_declared")}
    world_dir = Path(episode_dir) / "worlds" / label
    ledger_path = Path(episode_dir) / "served" / f"{world_token_for(episode_token, label)}.jsonl"
    alert_path = world_dir / "alert.json"

    missing = _missing_required_input(
        world_dir=world_dir, ledger_path=ledger_path, alert_path=alert_path,
        declared=world.get("disposition_declared"))
    if missing is not None:
        row["ungradable"] = True
        row["ungradable_reason"] = f"world {label!r} is missing its {missing}"
        return row

    ledger_rows, malformed_count = _read_world_ledger(
        ledger_path, world_token_for(episode_token, label))
    h_rows = _own_h_rows(ledger_rows, holding_system)
    faulted = next((r for r in h_rows if r.get("source") == "fault"), None)

    text = (world_dir / "investigation.md").read_text(encoding="utf-8")
    resolution_moved, referenced_leads = _resolution_facts(text, world=label)
    _check_gather_summaries(world_dir, world=label, referenced_leads=referenced_leads)
    verdict = _read_verdict(world_dir / "report.md", world=label)

    from defender.learning.branch.estate.stagers.dispatch import STAGERS

    stagers = {s.casefold() for s in STAGERS}
    integrity_notes: list[str] = []
    doctored = False
    for r in h_rows:
        if r.get("source") in ("staged", "patched"):
            doctored = True
            if r.get("source") == "staged" and holding_system not in stagers:
                integrity_notes.append(
                    f"a 'staged' row was recorded on {holding_system!r}, a patch-only system — "
                    "reported, not reclassified")

    holding_queried = bool(h_rows)
    scope_discriminated = any(_scope_discriminated_row(r) for r in h_rows)
    has_refused = any(r.get("source") == "refused" for r in h_rows)
    declared = world.get("disposition_declared")

    row.update(
        holding_queried=holding_queried, scope_discriminated=scope_discriminated,
        doctored_answer_served=doctored, resolution_moved=resolution_moved,
        verdict=verdict, malformed_rows=malformed_count,
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
        return row

    bucket: str | None
    flag: str | None = None
    if not holding_queried:
        bucket = "lead-set"
    elif not doctored:
        # "agreed-without-evidence" needs the world to have genuinely exhausted its asking of
        # H — more than one distinct call — before "it agreed and was shown nothing" reads as
        # an honest non-defect rather than as a lead the world tried once, narrowly, and
        # happened to still land on the right side of.
        if verdict == declared and len(h_rows) >= 2:
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
    return row


def grade_family(episode_dir: Path) -> FamilyGrade:
    """The mechanical pass: five facts and a bucket per non-control world, plus the family's
    `verdict_word`. Self-contained over `episode_dir` alone — no comparison, no comparator
    call, order-independent across worlds (O3)."""
    episode_dir = Path(episode_dir)
    doc = _raw_manifest(episode_dir)
    holding_system = _holding_system(doc)
    worlds = _non_control_worlds(doc)
    episode_id = doc.get("episode_id")
    if not isinstance(episode_id, str) or not episode_id:
        raise JudgeRefused("the manifest's episode_id is not a usable string")
    _check_run_id_collision(episode_id, worlds)
    episode_token = episode_token_for(episode_id)

    rows = [
        _grade_world(episode_dir, world, episode_token=episode_token,
                    holding_system=holding_system)
        for world in worlds
    ]
    control_declared = _control_declared(doc)
    graded = frozenset(r["world"] for r in rows if r.get("ungradable") is not True)
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
                       graded_worlds=graded)


__all__ = ["FamilyGrade", "grade_family"]
