#!/usr/bin/env python3
"""Lint the golden-set case tree (#711).

These are checks on SAMPLES, not assertions about code, so they live here as a
CLI that exits non-zero — the same idiom `score.py` already uses for lead-set
integrity — rather than as pytest sweeps. The engine's own behaviour is tested
next to each module (`test_stats.py`, `test_label.py`, ...); this validates the
artifacts those tools produce and consume.

What it enforces, each paired with the failure it prevents:

  structure          a case missing a file the README promises is not a case
  identity           manifest / expected / directory name agreeing, so a copied
                     case cannot silently score against another's labels
  story hygiene      no story states the expected result — the ONE leak the
                     hidden/visible split cannot catch, because `story.md` is
                     deliberately an oracle input
  replay boundary    no code literal in `replay.py` names `hidden/`
  score reproduction every `scores/<tag>.json` re-derives from its projection, so
                     committed artifacts cannot drift from the scorer that made them
  lead-set integrity no committed projection is missing, extra, or duplicated
  split (#711 AC 1)  every case carries one, and a derived case inherits its base's
  unit               every case carries one, and a derived case inherits its base's
  heterogeneous      matches `label.py`'s recomputation wherever it is measurable
  causes (AC 7)      the sidecar covers EXACTLY the leads the score reports errors
                     on — both directions, so neither a missing cause nor a cause
                     for a clean lead passes
  held-out (AC 2)    every held-out score is in the append-only ledger with a
                     matching hash, so a rewrite, a deletion, or a second run kept
                     under the same tag all fail

Usage: validate_cases.py [<cases_dir>]
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import yaml

GOLDEN_DIR = Path(__file__).resolve().parent
LEDGER = GOLDEN_DIR / "held_out_ledger.yaml"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


SCORE = _load("oracle_golden_score", GOLDEN_DIR / "score.py")
LABEL = _load("oracle_golden_label", GOLDEN_DIR / "label.py")

REQUIRED_FILES = ("manifest.yaml", "expected.yaml",
                  "oracle_visible/story.md", "oracle_visible/leads.jsonl")

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
    expected = yaml.safe_load((case_dir / "expected.yaml").read_text(encoding="utf-8")) or {}

    problems += check_identity(case_dir, manifest, expected)

    leads = _leads_of(case_dir)
    if set(leads) != set(expected.get("leads") or {}):
        problems.append(f"{name}: leads.jsonl ids != expected.yaml ids "
                        f"({sorted(set(leads) ^ set(expected.get('leads') or {}))})")

    story = (case_dir / "oracle_visible" / "story.md").read_text(encoding="utf-8").lower()
    tells = [t for t in EVAL_TELLS if t in story]
    if tells:
        problems.append(f"{name}: story.md leaks the evaluation frame: {tells}")

    problems += check_split_and_unit(name, manifest, by_id)
    problems += check_heterogeneous(case_dir, manifest, expected, leads)
    problems += check_scores(case_dir, manifest, expected)
    return problems


def check_identity(case_dir: Path, manifest: dict, expected: dict) -> list[str]:
    """The case's own name, agreed by both files — so a copied case cannot
    silently score against another's labels — and the ground truth an observed
    case must carry."""
    name = case_dir.name
    problems = []
    if manifest.get("case_id") != name:
        problems.append(f"{name}: manifest case_id is {manifest.get('case_id')!r}")
    if expected.get("case_id") != name:
        problems.append(f"{name}: expected case_id is {expected.get('case_id')!r}")
    if manifest.get("kind") != expected.get("kind"):
        problems.append(f"{name}: manifest kind {manifest.get('kind')!r} != "
                        f"expected kind {expected.get('kind')!r}")
    if manifest.get("kind") == "observed":
        if not (case_dir / "hidden" / "controls.yaml").is_file():
            problems.append(f"{name}: observed case has no hidden/controls.yaml")
        observed = case_dir / "hidden" / "observed"
        if not observed.is_dir() or not list(observed.iterdir()):
            problems.append(f"{name}: observed case has no hidden/observed payloads")
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
            f"{name}: split {split!r} != base {base_id} split {base.get('split')!r} "
            f"— a derived case reuses its base's envelope, so a differing split puts "
            f"one capture on both sides")
    if (base.get("unit") or {}) != unit:
        problems.append(f"{name}: unit != base {base_id}'s unit — a derived case is "
                        f"the base's unit shown again, not a new one")
    return problems


def check_heterogeneous(case_dir: Path, manifest: dict, expected: dict,
                        leads: dict) -> list[str]:
    """AC 6: the flag must equal what the envelope says, wherever that is knowable."""
    if not (case_dir / "hidden" / "observed").is_dir():
        return []               # derived case: nothing of its own was measured
    problems = []
    for lead_id, spec in (expected.get("leads") or {}).items():
        derived = LABEL.label_lead(case_dir, lead_id,
                                   leads.get(lead_id, {}).get("queries", []),
                                   spec["system"], manifest)
        got = derived["heterogeneous"]
        if got is None:
            continue            # not measurable — the labeler declines to assert
        if bool(spec.get("heterogeneous", False)) != got:
            problems.append(
                f"{case_dir.name}/{lead_id}: heterogeneous is "
                f"{spec.get('heterogeneous', False)!r} but the envelope derives {got!r} "
                f"(per-query: {[q['class'] for q in derived['per_query']]})")
    return problems


def _reported_error_leads(summary: dict) -> set[str]:
    """Leads the score artifact reports ANY error on."""
    out = set()
    for row in summary["rows"]:
        if not row["class_match"]:
            out.add(row["lead"])
        for grade in list(row["fields"].values()) + list(row["contradictions"].values()):
            if str(grade).startswith("wrong"):
                out.add(row["lead"])
    return out


def check_scores(case_dir: Path, manifest: dict, expected: dict) -> list[str]:
    """Score reproduction, lead-set integrity, and cause-code coverage."""
    problems = []
    for proj_path in sorted((case_dir / "projections").glob("*.yaml")):
        tag = proj_path.stem
        stored_path = case_dir / "scores" / f"{tag}.json"
        if not stored_path.is_file():
            problems.append(f"{case_dir.name}: no scores/{tag}.json for {proj_path.name}")
            continue
        proj = yaml.safe_load(proj_path.read_text(encoding="utf-8"))
        summary = SCORE.score_projection(expected, proj, proj_path.name)
        if json.dumps(summary, indent=2) + "\n" != stored_path.read_text(encoding="utf-8"):
            problems.append(f"{case_dir.name}: scores/{tag}.json is stale — re-run "
                            f"score.py --json over {proj_path.name}")
            continue
        for key, label in (("missing_leads", "missing from the projection"),
                           ("unscored_leads", "projected but unlabelled"),
                           ("duplicate_leads", "duplicated in the projection")):
            if summary[key]:
                problems.append(f"{case_dir.name}/{tag}: leads {label}: {summary[key]}")

        problems += check_causes(case_dir, tag, summary)
    return problems


def check_causes(case_dir: Path, tag: str, summary: dict) -> list[str]:
    """AC 7: the sidecar covers exactly the reported errors — in both directions.

    The reverse direction is the one that rots: a cause left behind after a
    projection improved would keep asserting a failure that no longer happens.
    """
    problems = []
    errored = _reported_error_leads(summary)
    causes_path = case_dir / "scores" / f"{tag}.causes.yaml"
    sidecar = (yaml.safe_load(causes_path.read_text(encoding="utf-8")) or {}
               if causes_path.is_file() else {})
    declared = set(sidecar.get("causes") or {})

    if not errored:
        if declared:
            problems.append(f"{case_dir.name}/{tag}: causes sidecar names "
                            f"{sorted(declared)} but the score reports no errors")
        return problems
    if not causes_path.is_file():
        problems.append(f"{case_dir.name}/{tag}: {len(errored)} error(s) on "
                        f"{sorted(errored)} but no scores/{tag}.causes.yaml")
        return problems
    if declared != errored:
        problems.append(
            f"{case_dir.name}/{tag}: causes sidecar covers {sorted(declared)} but the "
            f"score reports errors on {sorted(errored)}")
    for lead_id, entry in (sidecar.get("causes") or {}).items():
        if not (entry or {}).get("cause"):
            problems.append(f"{case_dir.name}/{tag}/{lead_id}: no cause code")
    return problems


def check_held_out_ledger(cases: list[tuple[Path, dict]]) -> list[str]:
    """AC 2: a held-out result is written once per (case, tag) and never rewritten.

    No code seam can stop someone reading a held-out case while editing the
    prompt — the tree is readable by anything with repo access, and the procedure
    doc says so plainly rather than implying otherwise. What IS mechanizable is
    detecting a result that changed after the fact, and that is what this does.
    """
    problems = []
    ledger = yaml.safe_load(LEDGER.read_text(encoding="utf-8")) if LEDGER.is_file() else {}
    entries = {(e["case"], e["tag"]): e for e in (ledger or {}).get("entries") or []}
    if len(entries) != len((ledger or {}).get("entries") or []):
        problems.append("held_out_ledger.yaml: duplicate (case, tag) entries")

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
        problems.append(f"ledger names {key[0]}/{key[1]} but that score file is absent")
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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cases_dir", type=Path, nargs="?", default=GOLDEN_DIR / "cases")
    ns = p.parse_args(argv)

    case_dirs = sorted(d for d in ns.cases_dir.iterdir() if d.is_dir())
    if not case_dirs:
        print("!! no cases found — every check below would pass vacuously", file=sys.stderr)
        return 1

    by_id: dict[str, dict] = {}
    for case_dir in case_dirs:
        manifest_path = case_dir / "manifest.yaml"
        if manifest_path.is_file():
            by_id[case_dir.name] = yaml.safe_load(
                manifest_path.read_text(encoding="utf-8")) or {}

    problems: list[str] = []
    for case_dir in case_dirs:
        problems += check_case(case_dir, by_id)
    problems += check_held_out_ledger([(d, by_id.get(d.name, {})) for d in case_dirs])
    problems += check_replay_boundary()

    if problems:
        print(f"!! {len(problems)} problem(s) in {len(case_dirs)} case(s):\n")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"ok — {len(case_dirs)} cases validate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
