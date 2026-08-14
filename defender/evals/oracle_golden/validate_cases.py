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
  controls           every stored control measures the window its record declares, so a
                     baseline that silently measured something else cannot be graded
                     against (#882)

**Two committed control records DO fail the control check today, and that non-zero exit
is the alarm working** — the same standing this tree already gives `score.py`'s four
leaking scores. `case-010-crosstier-web2/hidden/controls/l-006/1.json` and
`case-012-bruteforce-db1/hidden/controls/l-006/6.json` were measured before #882 fixed
the splice, so their windows sit behind a `LIMIT`/`KEEP` that already reduced the rows.
Repairing them means re-running `controls.py` against the live stack, which is a capture
session and not a code change; case-010 is `split: held-out`, so its re-score goes under
a NEW tag rather than a re-run of the recorded one. A caller sweeping the tree must not
read exit 1 as "revert something" — read the problem lines and decide.

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

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.evals.oracle_golden import controls as CONTROLS  # noqa: E402
from defender.evals.oracle_golden.score import DERIVED_KINDS, is_derived  # noqa: E402
from defender.evals.oracle_golden.story_from_run import eval_tells_in  # noqa: E402

GOLDEN_DIR = Path(__file__).resolve().parent
LEDGER = GOLDEN_DIR / "held_out_ledger.yaml"

REQUIRED_FILES = ("manifest.yaml", "environment.yaml",
                  "oracle_visible/story.md", "oracle_visible/leads.jsonl")

# Both read from their owners rather than restated here. `DERIVED_KINDS` was declared twice
# with two different readings of one fact — "no capture of its own, so `hidden/` is absent by
# design" here, "story never fired, so nothing was measured" in `score.py` — which is exactly
# the shape that lets a sixth kind be added to one list and not the other. `audit_judge`
# already reached for `score`'s copy. The eval-tells list was the same story, under a
# keep-in-sync note naming a symbol that lives in neither file.


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

    story = (case_dir / "oracle_visible" / "story.md").read_text(encoding="utf-8")
    tells = eval_tells_in(story)
    if tells:
        problems.append(f"{name}: story.md leaks the evaluation frame: {tells}")

    problems += check_split_and_unit(name, manifest, by_id)
    problems += check_expectation(name, manifest)
    problems += check_controls(case_dir)
    return problems


def check_controls(case_dir: Path) -> list[str]:
    """Every stored control must actually measure the window its record claims (#882).

    A control is the baseline a lead is graded against, and a wrong one is silent all the
    way down: `judge._control` forwards `live` and DROPS the query string, so the label
    pass sees a live window that observed nothing and reads it as "this stream has no
    baseline" — against which every observed row is distinguishable, so the lead grades
    `present`. Nothing downstream can tell that apart from a real empty baseline, which
    is why it has to be caught here, against the artifact.

    Note what this does NOT key on: a zero row count. 327 of the corpus's controls are
    live with zero rows and nearly all are honest — plenty of baselines really are empty
    in their control window. Emptiness is not the signature; a query that does not filter
    to its own declared window is.

    Two ways that has actually happened, both from #882:

      - the added clause landed after another command. `add_esql_window` used to splice
        after `splitlines()[0]`, but ES|QL separates commands with `|`, so a one-line
        `FROM idx | LIMIT 1` took one arbitrary row and THEN filtered it by time.
      - the shifted bounds were crossed. `shift_esql_window` used to bind its
        replacements by POSITION against a pair `esql_window` deliberately returns
        sorted, so a query that wrote its upper bound first got `< start AND >= end` —
        unsatisfiable, and ES|QL runs it happily.

    Which rewrite a record went through is read from the LEAD's own query rather than
    guessed from the control's shape: an added clause and a model-authored one can be
    written identically, and only the original says whether there was a bound to shift.
    """
    controls_dir = case_dir / "hidden" / "controls"
    if not controls_dir.is_dir() or not (case_dir / "oracle_visible" / "leads.jsonl").is_file():
        return []
    name = case_dir.name
    originals = {(lead_id, seq): params.get("query") or ""
                 for lead_id, seq, params in CONTROLS.lead_queries(case_dir)}

    problems = []
    for path in sorted(controls_dir.rglob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        lead_id = record.get("lead_id", path.parent.name)
        rel = f"{lead_id}/{path.name}"
        original = originals.get((lead_id, record.get("seq")))
        if original is None:
            # The pairing itself is broken: this control keys onto no query in the lead
            # set, so whatever it measured, nothing can say what it is a baseline FOR.
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
    return problems


def _control_problems(where: str, entry: dict, *, was_added: bool) -> list[str]:
    """One control's own integrity, against the window it declares."""
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

    # Operator-aware, because that is the whole of what the crossed-pair defect broke:
    # a positional read cannot tell `>= start AND < end` from `< start AND >= end`, and
    # the second is unsatisfiable. Compared as instants rather than strings so a literal
    # written with different precision is not reported as a crossed bound.
    want = {">": CONTROLS.parse_iso(window[0]), "<": CONTROLS.parse_iso(window[1])}
    # `strict`: both lists are one entry per `_BOUND` match, so a length mismatch is not a
    # short query but a broken invariant in the two readers, and it should raise here.
    for operator, literal in zip(CONTROLS.esql_operators(query),
                                 CONTROLS.esql_bounds(query), strict=True):
        if CONTROLS.parse_iso(literal) != want[operator[0]]:
            problems.append(
                f"{where} [{label}]: the `{operator}` bound is {literal}, but the record "
                f"declares the window {window[0]} .. {window[1]} — a bound substituted "
                f"onto the wrong end of the window inverts it, and an unsatisfiable "
                f"predicate returns zero rows that read as an empty baseline")

    if was_added:
        # The lead's query carried no bound, so this clause is one this tool wrote, and
        # it belongs immediately after the source command: there it narrows the row set
        # and CANNOT widen it, which is the only property that makes an added window a
        # control at all. Anywhere later and it filters whatever the commands before it
        # already reduced the rows to.
        commands = [c.strip() for c in query.split("|")]
        if len(commands) < 2 or not commands[1].startswith("WHERE @timestamp"):
            landed = next((i for i, c in enumerate(commands)
                           if c.startswith("WHERE @timestamp")), None)
            problems.append(
                f"{where} [{label}]: the lead's query carries no @timestamp bound, so this "
                f"window was ADDED — but it landed at command {landed} rather than "
                f"immediately after the source command, behind "
                f"{commands[1:landed] if landed else commands[1:]}. Those run FIRST, so "
                f"this measured a window over rows they had already reduced")
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
    elif not is_derived(kind):
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
