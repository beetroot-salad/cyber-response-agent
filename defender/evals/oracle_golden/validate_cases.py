#!/usr/bin/env python3
"""Lint the golden-set case tree, and report how complete it is (#711, slimmed §9.4).

These are checks on SAMPLES, not assertions about code, so they live here as a CLI that
exits non-zero rather than as pytest sweeps. The engine's own behaviour is tested beside
each module under `defender/tests/evals/`; this validates the artifacts those tools
produce and consume.

Slimmed for the judge redesign. The label-shaped checks are gone — `expected.yaml` is no
longer the scoring contract, so lead-ids-match-labels, `heterogeneous`-recomputation, the
cause-code sidecar and score reproduction all went with `label.py` and the old
`score.py`. What remains is everything that is true regardless of how a lead is graded:

  structure          a case missing a file the README promises is not a case
  environment        every case carries the notes BOTH judge passes read; a case
                     without them is a case the judge cannot read
  identity           manifest and directory name agreeing, so a copied case cannot
                     silently be mistaken for another
  story hygiene      no story states the expected result — the ONE leak the
                     hidden/visible split cannot catch, because `story.md` is
                     deliberately an oracle input
  replay boundary    no code literal in `replay.py` names `hidden/`
  split, unit        every case carries both, and a derived case inherits its base's
  held-out ledger    every held-out score is in the append-only ledger with a matching
                     hash, so a rewrite, a deletion, or a second run under one tag fail

The second half is a COMPLETENESS REPORT rather than a pass/fail: how many leads carry
observed telemetry, how many carry a baseline, how many controls landed on a window
where the stack was not running, and how many payloads the capture failed to record.
None of those is a defect in the tree — a lookup has no baseline by construction, and a
zero-byte payload is a query that errored at capture (`query_tool.py` writes "" on a
non-zero exit). They are the instrument's own limits, and a suite that does not print
them invites the reader to assume they are zero.

Usage: validate_cases.py [<cases_dir>] [--quiet]
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path

import yaml

GOLDEN_DIR = Path(__file__).resolve().parent
LEDGER = GOLDEN_DIR / "held_out_ledger.yaml"

REQUIRED_FILES = ("manifest.yaml", "environment.yaml",
                  "oracle_visible/story.md", "oracle_visible/leads.jsonl")

#: Kinds that carry no capture of their own: they reuse a base case's envelopes and
#: change only the story, so `hidden/` is absent BY DESIGN and its absence is not a gap.
DERIVED_KINDS = ("mutation", "negative-control", "spec-probe")

#: Vocabulary only an eval author writes — the scoring frame, not the operation.
#: Mirrored in `story_from_run.py`, which lints its own rendered output.
EVAL_TELLS = ("oracle", "negative control", "golden", "projection", "every lead",
              "each lead", "expected result", "+event", "+noise", "-noise",
              "result class", "standard environment noise", "suppressed:")


def _leads_of(case_dir: Path) -> dict[str, dict]:
    out = {}
    text = (case_dir / "oracle_visible" / "leads.jsonl").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.strip():
            row = json.loads(line)
            out[row["lead_id"]] = row
    return out


# ------------------------------------------------------------------------- checks

def check_case(case_dir: Path, by_id: dict[str, dict]) -> list[str]:
    """Every problem with one case, as human-readable lines."""
    problems: list[str] = []
    name = case_dir.name

    for rel in REQUIRED_FILES:
        if not (case_dir / rel).is_file():
            problems.append(f"{name}: missing {rel}")
    if problems:
        return problems          # nothing below can run without these

    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    problems += check_identity(case_dir, manifest)
    problems += check_environment(case_dir)

    story = (case_dir / "oracle_visible" / "story.md").read_text(encoding="utf-8").lower()
    tells = [t for t in EVAL_TELLS if t in story]
    if tells:
        problems.append(f"{name}: story.md leaks the evaluation frame: {tells}")

    problems += check_split_and_unit(name, manifest, by_id)
    problems += check_expectation(name, manifest)
    return problems


def check_expectation(name: str, manifest: dict) -> list[str]:
    """A derived case must assert something, because nothing else will.

    An observed case is graded against the judge's measurement of `hidden/`. A derived
    case has no `hidden/`, so the judge never runs on it and `expectation:` is the ONLY
    thing standing between it and a vacuous pass. This check exists because that gap was
    real: after the judge redesign, a forged `neg-001` projection copying the base case's
    burst into all nine leads — the exact window-copying the negative control exists to
    catch — scored clean and exited 0.
    """
    if manifest.get("kind") not in DERIVED_KINDS:
        return []
    expectation = manifest.get("expectation") or {}
    if not any(expectation.get(k) for k in
               ("empty_leads", "no_suppression", "no_noise_marker", "must_emit",
                "must_not_emit")):
        return [f"{name}: a {manifest.get('kind')} case declares no `expectation:` — the "
                f"judge never runs on it, so it would pass no matter what the oracle "
                f"emitted. Declare what its story settles."]
    return []


def check_identity(case_dir: Path, manifest: dict) -> list[str]:
    """The case's own name, agreed by the manifest — so a copied case cannot silently
    pass for another — and the capture an observed case must carry."""
    name = case_dir.name
    problems = []
    if manifest.get("case_id") != name:
        problems.append(f"{name}: manifest case_id is {manifest.get('case_id')!r}")
    kind = manifest.get("kind")
    if kind == "observed":
        observed = case_dir / "hidden" / "observed"
        if not observed.is_dir() or not list(observed.iterdir()):
            problems.append(f"{name}: observed case has no hidden/observed payloads")
    elif kind not in DERIVED_KINDS:
        problems.append(f"{name}: kind {kind!r} is not observed|{'|'.join(DERIVED_KINDS)}")
    return problems


def check_environment(case_dir: Path) -> list[str]:
    """`environment.yaml` is an input to BOTH judge passes, not documentation.

    It carries what decides whether a cross-window difference is real at all: the
    columns that rotate across lever-ups, how the controls were built, what
    `window_live: false` means. A case missing it, or missing the unstable-identifier
    list inside it, is a case the judge will read the environment wrongly.
    """
    name = case_dir.name
    notes = yaml.safe_load((case_dir / "environment.yaml").read_text(encoding="utf-8")) or {}
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
    """#711 AC 1: the split and the unit, and a derived case inheriting both."""
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
    """AC 2: a held-out result is written once per (case, tag) and never rewritten.

    No code seam can stop someone reading a held-out case while editing the prompt — the
    tree is readable by anything with repo access, and the procedure doc says so plainly
    rather than implying otherwise. What IS mechanizable is detecting a result that
    changed after the fact, and that is what this does.
    """
    problems = []
    ledger = (yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
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
            digest = hashlib.sha256(score_path.read_bytes()).hexdigest()
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
        # A `retired` entry is allowed to have no file: retiring a held-out result is how
        # a DEFECTIVE case leaves the suite, and the entry stays behind with its reason so
        # the result is never silently unmade. An entry with no file and no reason is the
        # failure this catches — a held-out score deleted because someone disliked it.
        if entries[key].get("retired"):
            continue
        problems.append(
            f"ledger names {key[0]}/{key[1]} but that score file is absent, and the entry "
            f"carries no `retired:` reason — a held-out result is never removed without one")
    return problems


def check_replay_boundary() -> list[str]:
    """`replay.py` must source every input from `oracle_visible/`."""
    tree = ast.parse((GOLDEN_DIR / "replay.py").read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            continue
        first = next(iter(node.body), None)
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            docstrings.add(id(first.value))
    literals = [n.value for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and id(n) not in docstrings]
    problems = []
    if not any("oracle_visible" in s for s in literals):
        problems.append("replay.py: found no path literals at all — this check is vacuous")
    if [s for s in literals if "hidden" in s]:
        problems.append("replay.py: names the hidden/ tree in code")
    return problems


# ------------------------------------------------------------------ completeness

def coverage(case_dir: Path, manifest: dict) -> dict:
    """What this case actually holds — reported, never asserted.

    A lookup lead has no baseline because a lookup has no `@timestamp` bounds to move;
    a derived case has no telemetry because it was never fired; a zero-byte payload is a
    query that errored at capture. None of those is a defect. Printing them is how the
    reader learns the instrument's limits instead of assuming they are zero.
    """
    # A half-built case — a recruitment still running, or one that failed partway — has
    # no lead set yet. `check_case` already reports it as missing a required file; the
    # coverage report's job is to stay readable beside that, not to die on it.
    leads = _leads_of(case_dir) if (case_dir / "oracle_visible" / "leads.jsonl").is_file() else {}
    observed_dir, controls_dir = case_dir / "hidden" / "observed", case_dir / "hidden" / "controls"
    observed = {p.name for p in observed_dir.iterdir()} & set(leads) if observed_dir.is_dir() else set()
    controlled = {p.name for p in controls_dir.iterdir()} & set(leads) if controls_dir.is_dir() else set()

    errored = sum(1 for p in observed_dir.rglob("*.json") if p.stat().st_size == 0) \
        if observed_dir.is_dir() else 0
    live = dead = 0
    if controls_dir.is_dir():
        for path in controls_dir.rglob("*.json"):
            for control in json.loads(path.read_text(encoding="utf-8")).get("controls") or []:
                if control.get("live"):
                    live += 1
                else:
                    dead += 1
    return {
        "case": case_dir.name, "kind": manifest.get("kind"), "split": manifest.get("split"),
        # A case whose capture cannot answer the question its leads ask. It stays in the
        # tree -- the telemetry is real and the defect is instructive -- but it is not
        # part of any split's totals, because counting it inflates the unit count with a
        # unit nothing was ever measured for.
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
        manifest = (yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
                    if manifest_path.is_file() else {})
        by_id[case_dir.name] = manifest
        cases.append((case_dir, manifest))

    problems: list[str] = []
    for case_dir in case_dirs:
        problems += check_case(case_dir, by_id)
    problems += check_held_out_ledger(cases)
    problems += check_replay_boundary()

    if not ns.quiet:
        print(render_coverage([coverage(d, m) for d, m in cases]))
    if problems:
        print(f"\n{len(problems)} problem(s):", file=sys.stderr)
        for line in problems:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"\nok: {len(case_dirs)} cases validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
