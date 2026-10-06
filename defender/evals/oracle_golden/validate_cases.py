#!/usr/bin/env python3
"""Lint the golden-set case tree, and report how complete it is.

These are checks on samples, not code, so they run as a CLI that exits non-zero rather than
as pytest sweeps (the tools themselves are tested under `defender/tests/evals/`). Checks:

  structure          every file the README promises is present
  environment        every case carries the notes both judge passes read
  identity           manifest and directory name agree, so a copied case cannot pass
                     for another
  story hygiene      no story states the expected result (`story.md` is an oracle
                     input, so the hidden/visible split cannot catch this)
  replay boundary    no code literal in `replay.py` names `hidden/`
  split, unit        every case carries both, and a derived case inherits its base's
  held-out ledger    every held-out score is in the append-only ledger with a matching
                     hash, so a rewrite, a deletion, or a second run under one tag fail
  seq keying         every observed payload is named for a seq some query in
                     `leads.jsonl` is keyed by, so a control cannot baseline a different
                     query's envelope
  controls           every stored control measures the window its record declares
  known defects      the accepted-invalid registry still describes the tree it waives

Some committed control records carry a known-invalid measurement that cannot be repaired in
code (their windows sit behind a `LIMIT`/`KEEP` that already reduced the rows); repairing one
needs a capture session against the live stack. They are listed in `known_defects.yaml`
instead of failing the run, and printed on every run. The registry is itself checked: an
entry whose record no longer carries the defect, or names a missing record, fails. A new
defect anywhere else still exits 1.

The second half is a completeness report, not pass/fail: how many leads carry observed
telemetry or a baseline, how many controls landed on a window where the stack was down, and
how many payloads are zero-byte (a query that errored at capture). These are the
instrument's limits, printed so nobody assumes they are zero.

Usage: validate_cases.py [<cases_dir>] [--quiet]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender import _yaml  # noqa: E402
from defender.evals.oracle_golden import controls as CONTROLS  # noqa: E402
from defender.evals.oracle_golden.score import (  # noqa: E402
    DERIVED_KINDS, forbidden_values, is_derived, required_values,
)
from defender.evals.oracle_golden.story_from_run import eval_tells_in  # noqa: E402
from defender._io import read_bytes_capped, read_text_utf8

GOLDEN_DIR = Path(__file__).resolve().parent
LEDGER = GOLDEN_DIR / "held_out_ledger.yaml"
KNOWN_DEFECTS = GOLDEN_DIR / "known_defects.yaml"

REQUIRED_FILES = ("manifest.yaml", "environment.yaml",
                  "oracle_visible/story.md", "oracle_visible/leads.jsonl")


def _leads_of(case_dir: Path) -> dict[str, dict]:
    out = {}
    text = read_text_utf8(case_dir / "oracle_visible" / "leads.jsonl")
    for line in text.splitlines():
        if line.strip():
            row = json.loads(line)
            out[row["lead_id"]] = row
    return out


# checks

def check_case(case_dir: Path, by_id: dict[str, dict],
               known: dict[tuple[str, str, int], dict] | None = None) -> list[str]:
    """Every problem with one case, as human-readable lines.

    `known` is the accepted-defect registry (`load_known_defects`).
    """
    problems: list[str] = []
    name = case_dir.name

    for rel in REQUIRED_FILES:
        if not (case_dir / rel).is_file():
            problems.append(f"{name}: missing {rel}")
    if problems:
        return problems          # nothing below can run without these

    manifest = _yaml.safe_load(read_text_utf8(case_dir / "manifest.yaml")) or {}
    problems += check_identity(case_dir, manifest)
    problems += check_environment(case_dir)

    story = read_text_utf8(case_dir / "oracle_visible" / "story.md")
    tells = eval_tells_in(story)
    if tells:
        problems.append(f"{name}: story.md leaks the evaluation frame: {tells}")

    problems += check_split_and_unit(name, manifest, by_id)
    problems += check_expectation(name, manifest)
    problems += check_clause_text(case_dir, manifest)
    problems += check_seq_keying(case_dir)
    problems += check_controls(case_dir, known)
    return problems


def load_known_defects(path: Path = KNOWN_DEFECTS) -> dict[tuple[str, str, int], dict]:
    """The control records whose stored measurement is accepted as invalid.

    Keyed by `(case, lead, seq)`, matching `hidden/controls/<lead>/<seq>.json`, so an entry
    names exactly one record.

    Raises on a malformed entry, unlike the artifact readers: this is operator-authored
    config, and a mistyped key (e.g. `seq: "1"`) would silently waive nothing.
    """
    if not path.is_file():
        return {}
    doc = _yaml.safe_load(read_text_utf8(path))
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise ValueError(f"{path.name}: expected a mapping, found {type(doc).__name__}")
    raw = doc.get("entries") or []
    if not isinstance(raw, list):
        raise ValueError(f"{path.name}: `entries` must be a list, found "
                         f"{type(raw).__name__}")
    out: dict[tuple[str, str, int], dict] = {}
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path.name}: entry {i} is a {type(entry).__name__}, "
                             f"not a mapping")
        case, lead, seq = entry.get("case"), entry.get("lead"), entry.get("seq")
        if not isinstance(case, str) or not isinstance(lead, str):
            raise ValueError(f"{path.name}: entry {i} needs string `case` and `lead`, "
                             f"found {case!r} and {lead!r}")
        # `bool` is an `int` subclass; `seq: true` is never meant as record 1.
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise ValueError(f"{path.name}: entry {i} ({case}/{lead}) needs an integer "
                             f"`seq`, found {seq!r}")
        key = (case, lead, seq)
        if key in out:
            raise ValueError(f"{path.name}: {case}/{lead}/{seq}.json is listed twice — "
                             f"one record, one entry, or a repair deletes only one of them")
        out[key] = entry
    return out


def check_known_defects(cases_dir: Path,
                        known: dict[tuple[str, str, int], dict]) -> list[str]:
    """The registry must still describe the tree it waives.

    Fails an entry whose record is missing, or no longer carries the defect (a stale entry
    would waive the next real defect at that key), re-checking the record rather than
    trusting the entry.
    """
    problems = []
    for (case, lead, seq), entry in sorted(known.items()):
        record = cases_dir / case / "hidden" / "controls" / lead / f"{seq}.json"
        if not record.is_file():
            problems.append(
                f"{KNOWN_DEFECTS.name}: names {case}/{lead}/{seq}.json, which does not "
                f"exist — remove the entry, or restore the record it waives")
            continue
        if (case, lead, seq) not in control_problems_by_record(cases_dir / case):
            problems.append(
                f"{KNOWN_DEFECTS.name}: {case}/{lead}/{seq}.json no longer carries the "
                f"{entry.get('defect', '?')} defect it is listed for. Delete this entry "
                f"in the same change that repaired the record — left behind, it waives "
                f"the next real defect at this key")
    return problems


def check_seq_keying(case_dir: Path) -> list[str]:
    """A lead's queries must be keyed by the seq its observed payloads are named for.

    `judge.load_lead_inputs` joins `hidden/observed/<lead>/{seq}.json` to
    `hidden/controls/<lead>/{seq}.json` by whatever `controls.lead_queries` answers, which
    falls back to list position when `leads.jsonl` has no `seq` field. Position diverges from
    seq once `∅.` sentinels are split out, and `check_controls` cannot see that (both sides
    used the position). The payload filenames carry the real seq, so this checks against them.
    """
    observed_root = case_dir / "hidden" / "observed"
    if not observed_root.is_dir() or not (case_dir / "oracle_visible" / "leads.jsonl").is_file():
        return []
    keyed: dict[str, set[int]] = {}
    for lead_id, seq, _ in CONTROLS.lead_queries(case_dir):
        keyed.setdefault(lead_id, set()).add(seq)

    problems = []
    for lead_dir in sorted(p for p in observed_root.iterdir() if p.is_dir()):
        # Fewer payloads than queries is normal (no by-ref payload, no file); a payload seq
        # no query is keyed by is the failure.
        named = {int(p.stem) for p in lead_dir.glob("*.json") if p.stem.isdigit()}
        stray = sorted(named - keyed.get(lead_dir.name, set()))
        if stray:
            problems.append(
                f"{case_dir.name}: {lead_dir.name} carries observed payload(s) "
                f"{stray} that no query in leads.jsonl is keyed by "
                f"{sorted(keyed.get(lead_dir.name, set()))} — the controls keyed off those "
                f"numbers baseline a different query's envelope, and `judge._control` drops "
                f"the query string, so nothing downstream can see the mispairing")
    return problems


def check_controls(case_dir: Path,
                   known: dict[tuple[str, str, int], dict] | None = None) -> list[str]:
    """Every stored control must actually measure the window its record claims.

    Records listed in `known_defects.yaml` are omitted here; `main` prints them and
    `check_known_defects` audits them.

    A wrong control is silent downstream: `judge._control` drops the query string, so a live
    window that measured the wrong thing reads as an empty baseline and the lead grades
    `present`. Zero rows alone is not the signature (most empty live controls are honest); a
    query that does not filter to its declared window is. Two known forms:

      - an added clause landing after another command (ES|QL separates commands with `|`,
        so in `FROM idx | LIMIT 1` a later filter sees one arbitrary row);
      - crossed shifted bounds (`< start AND >= end`), unsatisfiable yet accepted by ES|QL.

    Whether a clause was added or shifted is read from the lead's own query, since the two
    can look identical in the control.
    """
    tracked = known or {}
    return [problem
            for key, found in control_problems_by_record(case_dir).items()
            if key not in tracked
            for problem in found]


def control_problems_by_record(case_dir: Path) -> dict[tuple[str, str, int], list[str]]:
    """`check_controls`'s findings, kept under the `(case, lead, seq)` each belongs to.

    Record granularity lets `known_defects.yaml` be applied and audited per record, so one
    unrepaired record cannot keep another's stale entry alive.
    """
    controls_dir = case_dir / "hidden" / "controls"
    if not controls_dir.is_dir() or not (case_dir / "oracle_visible" / "leads.jsonl").is_file():
        return {}
    name = case_dir.name
    # `object` in the key: the lookup seq comes from an untrusted record, and `"seq": "1"`
    # must miss and be reported rather than be narrowed away.
    originals: dict[tuple[str, object], str] = {
        (lead_id, seq): params.get("query") or ""
        for lead_id, seq, params in CONTROLS.lead_queries(case_dir)}

    by_record: dict[tuple[str, str, int], list[str]] = {}
    for path in sorted(controls_dir.rglob("*.json")):
        # Keyed by the path, which is what registry entries name; a record whose own fields
        # disagree is reported below.
        try:
            key = (name, path.parent.name, int(path.stem))
        except ValueError:
            key = (name, path.parent.name, -1)
        problems = by_record.setdefault(key, [])
        # An unreadable record is a problem line, not a traceback that ends the sweep.
        try:
            record = json.loads(read_text_utf8(path))
        except json.JSONDecodeError as exc:
            problems.append(f"{name}: {path.parent.name}/{path.name} is not readable "
                            f"JSON ({exc})")
            continue
        if not isinstance(record, dict):
            problems.append(f"{name}: {path.parent.name}/{path.name} is a "
                            f"{type(record).__name__}, not a control record")
            continue
        # The directory is what `judge.load_lead_inputs` joins on, whatever the record claims.
        lead_id = path.parent.name
        rel = f"{lead_id}/{path.name}"
        declared = record.get("lead_id")
        if declared is not None and declared != lead_id:
            problems.append(
                f"{name}: {rel} records lead_id {declared!r} but sits under {lead_id}/ — "
                f"`judge.load_lead_inputs` joins a control to its observed payloads by the "
                f"DIRECTORY, so this baselines a lead it does not name")
        original = originals.get((lead_id, record.get("seq")))
        if original is None:
            problems.append(
                f"{name}: {rel} keys to (lead {lead_id}, seq {record.get('seq')!r}), which "
                f"is not a query in leads.jsonl — the control cannot be paired with the "
                f"observed payload it baselines")
            continue
        # No bounds in the lead's own query means `add_esql_window` wrote the clause; a
        # bounded original means `shift_esql_window` moved what was already there.
        was_added = not CONTROLS.esql_bounds(original)
        measured = [*(record.get("controls") or [])]
        if record.get("attack_contribution") is not None:
            measured.append({"name": "attack-contribution", **record["attack_contribution"]})
        for entry in measured:
            problems += _control_problems(f"{name}: {rel}", entry, was_added=was_added)
    return {k: v for k, v in by_record.items() if v}


def _control_problems(where: str, entry: object, *, was_added: bool) -> list[str]:
    """One control's own integrity, against the window it declares."""
    if not isinstance(entry, dict):
        return [f"{where}: control entry is a {type(entry).__name__}, not a record"]
    label = entry.get("name", "?")
    query = entry.get("query") or ""
    window = entry.get("window") or []
    if len(window) != 2:
        return [f"{where} [{label}]: window is {window!r}, not a [start, end] pair"]

    problems = []
    if not CONTROLS.bounds_name_a_window(query):
        return [f"{where} [{label}]: the control query's @timestamp bounds are "
                f"{CONTROLS.esql_operators(query) or 'absent'} — that names no window, so "
                f"this measured something other than the window it records"]

    # Operator-aware, so crossed bounds (`< start AND >= end`) are caught; compared as
    # instants so a literal with different precision is not reported as crossed.
    try:
        want = {">": CONTROLS.parse_iso(window[0]), "<": CONTROLS.parse_iso(window[1])}
    except ValueError as exc:
        return [f"{where} [{label}]: the declared window {window!r} is not a pair of "
                f"timestamps ({exc})"]
    # `strict`: both lists come from the same `_BOUND` matches; a length mismatch is a bug.
    for operator, literal in zip(CONTROLS.esql_operators(query),
                                 CONTROLS.esql_bounds(query), strict=True):
        try:
            measured = CONTROLS.parse_iso(literal)
        except ValueError as exc:
            problems.append(f"{where} [{label}]: the `{operator}` bound {literal!r} is not "
                            f"a timestamp this module can read ({exc})")
            continue
        if measured != want[operator[0]]:
            problems.append(
                f"{where} [{label}]: the `{operator}` bound is {literal}, but the record "
                f"declares the window {window[0]} .. {window[1]} — a bound substituted "
                f"onto the wrong end of the window inverts it, and an unsatisfiable "
                f"predicate returns zero rows that read as an empty baseline")

    if was_added:
        # An added window must sit immediately after the source command; later, it filters
        # rows earlier commands already reduced. Locate it by the command carrying bounds,
        # not a `WHERE @timestamp` prefix (`WHERE @timestamp IS NOT NULL` is no bound).
        commands = [c.strip() for c in CONTROLS.split_commands(query)]
        landed = next((i for i, c in enumerate(commands) if CONTROLS.esql_bounds(c)), None)
        if landed != 1:
            problems.append(
                f"{where} [{label}]: the lead's query carries no @timestamp bound, so this "
                f"window was ADDED — but it landed at command {landed} rather than "
                f"immediately after the source command, behind {commands[1:landed]}. "
                f"Those run FIRST, so this measured a window over rows they had "
                f"already reduced")
    return problems


def check_expectation(name: str, manifest: dict) -> list[str]:
    """A derived case must declare an `expectation:`: the judge never runs on it, so
    without one any projection would pass."""
    if not is_derived(manifest.get("kind")):
        return []
    expectation = manifest.get("expectation") or {}
    if not any(expectation.get(k) for k in
               ("empty_leads", "no_suppression", "no_noise_marker", "must_emit",
                "must_not_emit")):
        return [f"{name}: a {manifest.get('kind')} case declares no `expectation:` — the "
                f"judge never runs on it, so it would pass no matter what the oracle "
                f"emitted. Declare what its story settles."]
    return []


def check_clause_text(case_dir: Path, manifest: dict) -> list[str]:
    """`must_emit` / `must_not_emit` entries are quoted strings, wherever the case keeps them.

    An unquoted timestamp loads as a `datetime` and can never match the projection's text.
    Same readers as the scorer, so the refusal surfaces at commit time; each clause is
    reported separately.
    """
    problems: list[str] = []
    for read in (lambda: forbidden_values(case_dir, manifest),
                 lambda: required_values(manifest.get("expectation") or {})):
        try:
            read()
        except ValueError as e:
            problems.append(f"{case_dir.name}: {e}")
    return problems


def check_identity(case_dir: Path, manifest: dict) -> list[str]:
    """The manifest agrees with the directory name, and an observed case carries its capture."""
    name = case_dir.name
    problems = []
    if manifest.get("case_id") != name:
        problems.append(f"{name}: manifest case_id is {manifest.get('case_id')!r}")
    kind = manifest.get("kind")
    if kind == "observed":
        observed = case_dir / "hidden" / "observed"
        if not observed.is_dir() or not list(observed.iterdir()):
            problems.append(f"{name}: observed case has no hidden/observed payloads")
    elif not is_derived(kind):
        problems.append(f"{name}: kind {kind!r} is not observed|{'|'.join(DERIVED_KINDS)}")
    return problems


def check_environment(case_dir: Path) -> list[str]:
    """`environment.yaml` is an input to both judge passes, not documentation.

    It says whether a cross-window difference is real: which columns rotate across
    lever-ups, how controls were built, what `window_live: false` means.
    """
    name = case_dir.name
    notes = _yaml.safe_load(read_text_utf8(case_dir / "environment.yaml")) or {}
    problems = []
    if not notes.get("capture_environment"):
        problems.append(f"{name}: environment.yaml has no capture_environment")
    columns = (notes.get("unstable_identifiers") or {}).get("columns")
    if not columns:
        problems.append(f"{name}: environment.yaml lists no unstable_identifiers.columns "
                        f"— the judge would read a rotated address as a real delta")
    if not (notes.get("baseline_construction") or {}).get("liveness"):
        problems.append(f"{name}: environment.yaml does not say what window_live means")
    return problems


def check_split_and_unit(name: str, manifest: dict, by_id: dict[str, dict]) -> list[str]:
    """The split and the unit, and a derived case inheriting both."""
    problems = []
    split = manifest.get("split")
    if split not in ("dev", "held-out"):
        problems.append(f"{name}: split must be dev|held-out, got {split!r}")
    unit = manifest.get("unit") or {}
    if not unit.get("activity_family") or not unit.get("host_pair"):
        problems.append(f"{name}: unit needs activity_family and host_pair, got {unit!r}")
    if not manifest.get("capture_environment"):
        problems.append(f"{name}: no capture_environment")

    base_id = manifest.get("base_case")
    if not base_id:
        return problems
    base = by_id.get(base_id)
    if base is None:
        problems.append(f"{name}: base_case {base_id!r} not found")
        return problems
    if base.get("split") != split:
        problems.append(
            f"{name}: split {split!r} != base {base_id} split {base.get('split')!r} — a "
            f"derived case reuses its base's envelope, so a differing split puts one "
            f"capture on both sides")
    if (base.get("unit") or {}) != unit:
        problems.append(f"{name}: unit != base {base_id}'s unit — a derived case is the "
                        f"base's unit shown again, not a new one")
    return problems


def check_held_out_ledger(cases: list[tuple[Path, dict]],
                          ledger_path: Path = LEDGER) -> list[str]:
    """A held-out result is written once per (case, tag) and never rewritten.

    Reading a held-out case cannot be prevented; a result changed after the fact can be
    detected.
    """
    problems = []
    ledger = (_yaml.safe_load(read_text_utf8(ledger_path))
              if ledger_path.is_file() else {})
    entries = {(e["case"], e["tag"]): e for e in (ledger or {}).get("entries") or []}
    if len(entries) != len((ledger or {}).get("entries") or []):
        problems.append(f"{ledger_path.name}: duplicate (case, tag) entries")

    seen = set()
    for case_dir, manifest in cases:
        if manifest.get("split") != "held-out":
            continue
        for score_path in sorted((case_dir / "scores").glob("*.json")):
            key = (case_dir.name, score_path.stem)
            seen.add(key)
            digest = hashlib.sha256(read_bytes_capped(score_path)).hexdigest()
            entry = entries.get(key)
            if entry is None:
                problems.append(f"{case_dir.name}/{score_path.stem}: held-out score has "
                                f"no ledger entry — append one, never rewrite a result")
            elif entry.get("sha256") != digest:
                problems.append(
                    f"{case_dir.name}/{score_path.stem}: held-out score does not match its "
                    f"ledger hash. A held-out result is recorded once per tag; to record a "
                    f"new oracle version, add a NEW tag rather than re-running this one")
    for key in sorted(set(entries) - seen):
        # A `retired` entry (a defective case leaving the suite) may lack its file; any other
        # missing file is a deleted held-out result.
        if entries[key].get("retired"):
            continue
        problems.append(
            f"ledger names {key[0]}/{key[1]} but that score file is absent, and the entry "
            f"carries no `retired:` reason — a held-out result is never removed without one")
    return problems


# completeness

def coverage(case_dir: Path, manifest: dict) -> dict:
    """What this case actually holds — reported, never asserted.

    A lookup lead has no baseline (no `@timestamp` bounds to move), a derived case has no
    telemetry, and a zero-byte payload is a query that errored at capture. None is a defect.
    """
    # A half-built case has no lead set yet; `check_case` reports that, so don't crash here.
    leads = _leads_of(case_dir) if (case_dir / "oracle_visible" / "leads.jsonl").is_file() else {}
    observed_dir, controls_dir = case_dir / "hidden" / "observed", case_dir / "hidden" / "controls"
    observed = {p.name for p in observed_dir.iterdir()} & set(leads) if observed_dir.is_dir() else set()
    controlled = {p.name for p in controls_dir.iterdir()} & set(leads) if controls_dir.is_dir() else set()

    errored = sum(1 for p in observed_dir.rglob("*.json") if p.stat().st_size == 0) \
        if observed_dir.is_dir() else 0
    live = dead = 0
    if controls_dir.is_dir():
        for path in controls_dir.rglob("*.json"):
            for control in json.loads(read_text_utf8(path)).get("controls") or []:
                if control.get("live"):
                    live += 1
                else:
                    dead += 1
    return {
        "case": case_dir.name, "kind": manifest.get("kind"), "split": manifest.get("split"),
        # Its capture cannot answer its leads' question: kept in the tree, excluded from
        # split totals.
        "defective": manifest.get("defective"),
        "unit": f"{(manifest.get('unit') or {}).get('activity_family', '?')} "
                f"{(manifest.get('unit') or {}).get('host_pair', '')}".strip(),
        "leads": len(leads), "observed": len(observed), "baselined": len(controlled),
        "errored_payloads": errored, "controls_live": live, "controls_dead": dead,
    }


def render_coverage(rows: list[dict]) -> str:
    lines = ["", "== coverage (reported, not asserted)",
             f"{'case':<34}{'split':<10}{'leads':>6}{'obs':>5}{'base':>6}"
             f"{'err':>5}{'ctl-live':>10}{'ctl-dead':>10}"]
    for r in rows:
        mark = "  !! DEFECTIVE" if r.get("defective") else ""
        lines.append(f"{r['case']:<34}{r['split'] or '?':<10}{r['leads']:>6}{r['observed']:>5}"
                     f"{r['baselined']:>6}{r['errored_payloads'] or '':>5}"
                     f"{r['controls_live']:>10}{r['controls_dead'] or '':>10}{mark}")
    for split in ("dev", "held-out"):
        sel = [r for r in rows if r["split"] == split and not r.get("defective")]
        if not sel:
            continue
        lines.append(
            f"  {split}: {len(sel)} cases, {len({r['unit'] for r in sel})} units, "
            f"{sum(r['leads'] for r in sel)} leads, "
            f"{sum(r['observed'] for r in sel)} with telemetry, "
            f"{sum(r['baselined'] for r in sel)} with a baseline")
    for r in rows:
        if r.get("defective"):
            lines.append(f"  !! {r['case']} is EXCLUDED from the totals above: "
                         f"{' '.join(str(r['defective']).split())}")
    dead = sum(r["controls_dead"] for r in rows)
    if dead:
        lines.append(f"  !! {dead} controls landed on a window where the stack was not "
                     f"running. A dead window is not an empty baseline — re-measure with "
                     f"offsets that clear the lever-down gaps (controls.py --offsets-days).")
    errored = sum(r["errored_payloads"] for r in rows)
    if errored:
        lines.append(f"  !! {errored} observed payloads are zero-byte: the query errored at "
                     f"capture. They are NOT empty result sets and carry no evidence.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cases_dir", type=Path, nargs="?", default=GOLDEN_DIR / "cases")
    p.add_argument("--quiet", action="store_true", help="problems only, no coverage report")
    ns = p.parse_args(argv)

    case_dirs = sorted(d for d in ns.cases_dir.iterdir() if d.is_dir())
    by_id, cases = {}, []
    for case_dir in case_dirs:
        manifest_path = case_dir / "manifest.yaml"
        manifest = (_yaml.safe_load(read_text_utf8(manifest_path)) or {}
                    if manifest_path.is_file() else {})
        by_id[case_dir.name] = manifest
        cases.append((case_dir, manifest))

    known = load_known_defects()
    problems: list[str] = []
    for case_dir in case_dirs:
        problems += check_case(case_dir, by_id, known)
    problems += check_held_out_ledger(cases)
    problems += check_known_defects(ns.cases_dir, known)

    if not ns.quiet:
        print(render_coverage([coverage(d, m) for d, m in cases]))

    # Printed on every run so waived defects are not forgotten.
    tracked = [k for k in sorted(known) if k[0] in {d.name for d in case_dirs}]
    if tracked:
        print(f"\n!! {len(tracked)} control record(s) carry an ACCEPTED invalid "
              f"measurement ({KNOWN_DEFECTS.name}) — not repairable in code; each needs a "
              f"capture session against the live stack:")
        for key in tracked:
            entry = known[key]
            print(f"     {key[0]}/{key[1]}/{key[2]}.json — {entry.get('defect', '?')} "
                  f"(#{entry.get('issue', '?')}, split: {entry.get('split', '?')})")

    if problems:
        print(f"\n{len(problems)} problem(s):", file=sys.stderr)
        for line in problems:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"\nok: {len(case_dirs)} cases validate")
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    raise SystemExit(main())
