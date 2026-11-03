#!/usr/bin/env python3
"""Primary-metric harness: score defender held-out runs against ground truth.

Walks the FIXTURE set (``evaluations/fixtures/held_out/``) and reports defender disposition
correctness. A run is matched to its fixture by the held-out INDEX alone, a JSON Lines file
the operator names (``--index F``), one ``{slug, run_id, freeze, verdict, reason, verified_at}`` row per run, oldest first (#1347).
A run folder's name claims nothing (#1187): every run id is an opaque UUID, minted by the
system and announced as run.py's first stdout line ``run_id=<uuid>`` (#1279).

Ground truth never leaves the fixture dirs: the run dir is readable by the agent, so it
carries no labels and no pointer back to its fixture. The index is host-written and kept
outside every runs and episodes tree, where no box can write it.

Run a fixture's alert with ``--no-learn`` (it keeps a scored run out of the learning corpora),
then append its row to F yourself; nothing launches held-out runs for you (#1279 rev 4)::

    python3 defender/run.py evaluations/fixtures/held_out/<slug>/alert.json --tenant <tenant-uuid> --no-learn
    # first line: run_id=<uuid>  ->  append {"slug": "<slug>", "run_id": "<uuid>"} to F

A run that crashes before announcing its id leaves no row unless you write one, and then the
slug's older row (if any) is scored instead.
For comparable scores, pin every run of one index to one knowledge revision with
``--knowledge-commit <K>`` (#1108 P4 OD10); nothing pins it for you.

Score (an evaluation tool outside the application: it takes no tenant and never resolves
``DEFENDER_DATA_ROOT``; it scores exactly the runs dir it is handed)::

    python3 -m evaluations.held_out "$DEFENDER_DATA_ROOT/<tenant-uuid>/runs" --index F

Every case carries a confirmed ``freeze.yaml`` beside ``ground_truth.yaml`` (one without refuses
the set). Only rows whose ``freeze`` is the case's current freeze digest count; the newest of
them names the run scored, opened by id under the runs dir. A case with no such row, a stale
verdict, a run that read Elasticsearch's ``now`` (to re-run) or three such runs in a row
(unscorable) is listed with its reason, left out of the accuracy, and makes the report
incomplete and the exit non-zero. A slug whose
newest row names a run that is absent, or has no alert record, counts as **wrong** ("launched,
no run record"), as does a run without a parseable ``report.md`` (missing, bad frontmatter,
disposition outside the closed enum, or crashed).
Only a slug with no current-freeze row is "not run". An F inside the runs dir is refused: that tree is the
boxes' own.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections import defaultdict
from pathlib import Path
from typing import NamedTuple

import yaml

from defender import _io
from defender.records import _alert_input
from defender._yaml import safe_load
from defender._model import model
from defender._vocab import DISPOSITION_VALUES, HOST_ONLY_DISPOSITION
from defender.records._report import read_report
from defender.records._run_id import run_id_fault
from defender.records import RUN_LAYOUT, RunPaths
from defender.run_common import HELD_OUT_FIXTURES as FIXTURES_DIR
from defender._io import read_text_utf8

FREEZE_FILE = "freeze.yaml"

#: The failure bucket of a slug whose newest row names a run that is absent or has no alert
#: record (#1187 recheck X2): counted wrong, so a crash before run setup cannot leave the
#: denominator.
NO_RUN_RECORD = "launched, no run record"

#: The dispositions a fixture may be labelled with: every one the agent can author. The host-only
#: `unresolved` is never a right answer, so a label naming it is refused like any other stray one.
LABELS: tuple[str, ...] = tuple(d for d in DISPOSITION_VALUES if d != HOST_ONLY_DISPOSITION)


#: The index verdicts a row may carry (#1347): the post-run fingerprint check's answer.
VERDICTS: tuple[str, ...] = ("valid", "stale")

#: Consecutive dropped rows of one slug and freeze after which the case is unscorable (#1347 D13).
UNSCORABLE_AFTER = 3

#: Elasticsearch's own clock in recorded query text (#1347 D4): `now()` in ES|QL; `now` date math
#: (`now`, `now-1h`, `now/d`) elsewhere. Case-insensitive and wide: a false drop costs a re-run,
#: a missed clock read scores a run whose window slid.
_NOW_CALL = re.compile(r"(?<![\w.])now\s*\(", re.IGNORECASE)
_NOW_MATH = re.compile(r"(?<![\w.\-])now(?!\w)", re.IGNORECASE)
_ELASTIC = "elastic"
_ESQL = "esql"


class FixturesRefused(Exception):  # noqa: N818 — named for its refusal, as `IndexRefused` is
    """A held-out fixture carries a label outside `LABELS`, or no confirmed freeze. Scoring
    refuses the whole set rather than let a typo or an unfrozen case shrink the denominator;
    the message names every such fixture."""


class IndexRefused(Exception):  # noqa: N818 — named for its refusal, as `TenantRefused` is
    """The held-out index is refused — where it sits, how it is reached, or what it holds. The
    message names it; the command line prints it on stderr and exits non-zero."""


def predicted_disposition(run_dir: Path) -> str | None:
    """This run's predicted disposition, or `None` when the report yields no usable headline.
    Degrades rather than raising so one broken report does not stop scoring the rest.
    """
    return read_report(RunPaths(run_dir).report).disposition


@model
class HeldOutAlert:
    slug: str
    alert_path: Path
    ground_truth: dict
    freeze: str = ""


def freeze_digest(doc: object) -> str:
    """The freeze digest (#1347 D13): bare lowercase hex sha256 of the parsed `freeze.yaml` as
    sorted-key compact JSON, so comments, key order and line endings do not change it. Raises
    `TypeError` / `ValueError` for a value canonical JSON cannot carry."""
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _freeze_fault(case: Path) -> tuple[str, str]:
    """`(digest, "")` of `case/freeze.yaml`, or `("", why)` when the case is not frozen and
    confirmed."""
    path = case / FREEZE_FILE
    if not path.is_file():
        return "", f"no {FREEZE_FILE}"
    try:
        doc = safe_load(read_text_utf8(path))
    except (yaml.YAMLError, OSError, ValueError) as e:
        return "", f"unparseable {FREEZE_FILE} ({e})"
    if not isinstance(doc, dict):
        return "", f"{FREEZE_FILE} is not a mapping"
    if not doc.get("confirmed"):
        return "", f"{FREEZE_FILE} is not confirmed"
    try:
        return freeze_digest(doc), ""
    except (TypeError, ValueError) as e:
        return "", f"{FREEZE_FILE} holds a value canonical JSON cannot carry ({e})"


def load_held_out_fixtures(fixtures_dir: Path) -> list[HeldOutAlert]:
    out: list[HeldOutAlert] = []
    unfrozen: list[str] = []
    for child in sorted(fixtures_dir.iterdir()):
        if not child.is_dir():
            continue
        # A fixture is a folder an operator keeps, not a run: its alert is the file by that name.
        alert = child / RUN_LAYOUT.alert.name
        gt = child / "ground_truth.yaml"
        if not gt.is_file():
            continue
        if not alert.is_file():
            print(f"warn: {child.name}: labeled held-out fixture has no {alert.name} "
                  f"— excluded from the eval set", file=sys.stderr)
            continue
        try:
            gt_doc = safe_load(read_text_utf8(gt)) or {}
        except yaml.YAMLError as e:
            print(f"warn: {child.name}: unparseable ground_truth.yaml ({e}) — fixture skipped",
                  file=sys.stderr)
            continue
        if not isinstance(gt_doc, dict) or gt_doc.get("held_out") is not True:
            continue
        digest, why = _freeze_fault(child)
        if why:
            unfrozen.append(f"{child.name} ({why})")
        out.append(HeldOutAlert(child.name, alert, gt_doc, digest))
    _refuse_unfit(out, unfrozen)
    return out


def _refuse_unfit(fixtures: list[HeldOutAlert], unfrozen: list[str]) -> None:
    """Raise `FixturesRefused` naming every fixture with a stray label or no confirmed freeze."""
    stray = [f"{fx.slug} ({fx.ground_truth.get('disposition')!r})" for fx in fixtures
             if fx.ground_truth.get("disposition") not in LABELS]
    faults = []
    if stray:
        faults.append(f"labels outside {list(LABELS)}: {', '.join(stray)}")
    if unfrozen:
        faults.append(f"cases not frozen and confirmed: {', '.join(unfrozen)}")
    if faults:
        raise FixturesRefused("; ".join(faults))


def warn_if_outside_the_net(fixtures_dir: Path) -> bool:
    if fixtures_dir.resolve() == FIXTURES_DIR.resolve():
        return False
    print(f"WARNING: scoring {fixtures_dir}, but the enqueue-time contamination net only "
          f"refuses runs from {FIXTURES_DIR} — runs of these fixtures were NOT held out "
          f"of learning unless they were launched with --no-learn", file=sys.stderr)
    return True


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


class IndexRow(NamedTuple):
    """One index row: the run `run_id` of `slug`, served `freeze` (`None` for a pre-#1347 row),
    with the post-run fingerprint `verdict` and its `reason`."""
    slug: str
    run_id: str
    freeze: str | None
    verdict: str | None
    reason: str


def read_index(index: Path, runs_dir: Path) -> list[IndexRow]:
    """F's rows, oldest first. F inside the runs
    dir — judged at the real places of both, so a link a box planted inside its own run folder
    never puts F inside — is refused: that tree is the boxes' own. So is an F that is absent,
    holds a line that is not a row, or a row whose slug or run id is not text or whose run id
    is not a run id, or whose `freeze` is not text, or which carries a `freeze` and no
    `valid` / `stale` verdict: the index is host-written, and scoring fails closed on one it
    cannot trust. A row without `freeze` is a pre-#1347 row: well-formed, never counted."""
    if _inside(index.resolve(), runs_dir.resolve()):
        raise IndexRefused(f"it is inside the runs dir {runs_dir}, which the boxes can write")
    if not index.is_file():
        raise IndexRefused("it does not exist, or is not a file")
    rows, dropped = _io.read_jsonl_rows_report(index)
    if dropped:
        raise IndexRefused(f"{dropped} of its lines are not JSON objects")
    out: list[IndexRow] = []
    for n, row in enumerate(rows, 1):
        if set(row) == {"knowledge_commit"}:
            continue  # the knowledge pin an index written by the old launcher records (#1108 P4)
        slug, run_id = row.get("slug"), row.get("run_id")
        if not isinstance(slug, str) or not isinstance(run_id, str):
            raise IndexRefused(f"row {n} does not carry a text slug and run_id")
        if (why := run_id_fault(run_id)) is not None:
            raise IndexRefused(f"row {n}'s run_id {run_id!r} is not a run id: {why}")
        freeze, verdict = row.get("freeze"), row.get("verdict")
        if freeze is not None and not isinstance(freeze, str):
            raise IndexRefused(f"row {n}'s freeze is not text")
        if freeze is not None and (not isinstance(verdict, str) or verdict not in VERDICTS):
            raise IndexRefused(f"row {n}'s verdict {verdict!r} is not one of {list(VERDICTS)}")
        reason = row.get("reason")
        out.append(IndexRow(slug, run_id, freeze, verdict, reason if isinstance(reason, str) else ""))
    return out


#: Why a case is listed unscored (#1347 O11), with the heading its section carries.
NOT_RUN, STALE, RERUN, UNSCORABLE = "not run", "stale", "re-run", "unscorable"
_UNSCORED_HEADINGS = {
    NOT_RUN: "Not run (no index row for the case's current freeze; excluded from accuracy)",
    STALE: "Stale (the post-run check found the frozen telemetry changed; excluded from accuracy)",
    RERUN: "Re-run needed (the run read Elasticsearch's clock; dropped, excluded from accuracy)",
    UNSCORABLE: f"Unscorable ({UNSCORABLE_AFTER} dropped runs in a row; excluded from accuracy)",
}


@model
class Scored:

    by_class: dict[str, list[tuple[str, str | None, str]]]
    failures: list[tuple[str, str]]
    unscored: list[tuple[str, str, str]]  # (slug, kind, detail), kind in `_UNSCORED_HEADINGS`

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.by_class.values())

    @property
    def correct(self) -> int:
        return sum(1 for v in self.by_class.values() for _, _, vd in v if vd == "ok")


def _unrecorded(run_dir: Path) -> str | None:
    """Why the run at `run_dir` is no run: absent (nothing at the id, or a link or file there —
    an entry of the runs dir is never followed), or with no readable alert record. `None` for
    a run."""
    try:
        st = os.lstat(run_dir)
    except FileNotFoundError:
        return f"run {run_dir.name} is absent"
    if not stat.S_ISDIR(st.st_mode):
        return f"run {run_dir.name} is absent (not a folder at that id)"
    if _alert_input.read_record(RunPaths(run_dir).alert_record) is None:
        return f"run {run_dir.name} has no alert record"
    return None


def _strings(value: object):
    """Every string inside a JSON value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def reads_the_clock(run_dir: Path) -> bool:
    """Whether the run's recorded Elasticsearch queries use its own `now` (#1347 D4): `now(` in
    ES|QL, `now` date math in any other Elasticsearch call's params (a search's start, end or
    query string). Other systems' params are not scanned. No queries file, or a run dir that is
    a link, has nothing to scan; a file too large to read counts as a read (errs wide)."""
    if run_dir.is_symlink():
        return False
    try:
        rows, _ = _io.read_jsonl_rows_report(RunPaths(run_dir).executed_queries)
    except OSError:
        return True
    for row in rows:
        if row.get("system") != _ELASTIC:
            continue
        pattern = _NOW_CALL if row.get("verb") == _ESQL else _NOW_MATH
        if any(pattern.search(text) for text in _strings(row.get("params"))):
            return True
    return False


def score(fixtures: list[HeldOutAlert], runs_dir: Path,
          rows: list[IndexRow]) -> Scored:
    """Score each fixture from the newest index row bound to its current freeze, the run it
    names opened by id under `runs_dir`. Rows for another freeze, or with none, are set aside
    first. A case is left unscored, with its reason, when it has no such row, the newest says
    stale, the newest run read Elasticsearch's clock (dropped, to be re-run — even if it also
    crashed) or `UNSCORABLE_AFTER` dropped rows in a row end the history."""
    by_class: dict[str, list[tuple[str, str | None, str]]] = defaultdict(list)
    failures: list[tuple[str, str]] = []
    unscored: list[tuple[str, str, str]] = []
    for fx in fixtures:
        bound = [r for r in rows if r.slug == fx.slug and r.freeze == fx.freeze]
        if not bound:
            unscored.append((fx.slug, NOT_RUN, "no index row for the current freeze"))
            continue
        newest = bound[-1]
        if newest.verdict == "stale":
            unscored.append((fx.slug, STALE, newest.reason or "the post-run check found it stale"))
            continue
        if reads_the_clock(runs_dir / newest.run_id):
            streak = 0
            for r in reversed(bound):
                if r.verdict == "stale" or not reads_the_clock(runs_dir / r.run_id):
                    break
                streak += 1
            if streak >= UNSCORABLE_AFTER:
                unscored.append((fx.slug, UNSCORABLE, f"{streak} dropped runs in a row"))
            else:
                unscored.append((fx.slug, RERUN, f"run {newest.run_id} read Elasticsearch's now"))
            continue
        true_disp = str(fx.ground_truth.get("disposition") or "?")
        run_dir = runs_dir / newest.run_id
        absent = _unrecorded(run_dir)
        if absent is not None:
            failures.append((fx.slug, f"{NO_RUN_RECORD} ({absent})"))
            by_class[true_disp].append((fx.slug, None, "wrong"))
            continue
        pred = predicted_disposition(run_dir)
        verdict = "ok" if pred == true_disp else "wrong"
        if pred is None:
            failures.append((fx.slug, "no parseable report.md"))  # lint-run-records: ok — an eval case's own file under the case tree, never a run record
        by_class[true_disp].append((fx.slug, pred, verdict))
    return Scored(by_class, failures, unscored)


def _print_unscored(scored: Scored) -> None:
    for kind, heading in _UNSCORED_HEADINGS.items():
        listed = [(slug, detail) for slug, k, detail in scored.unscored if k == kind]
        if listed:
            print(f"## {heading}")
            for slug, detail in listed:
                print(f"  {slug}: {detail}")
            print()


def report(runs_dir: Path, rows: list[IndexRow],
           fixtures_dir: Path = FIXTURES_DIR) -> int:
    fixtures = load_held_out_fixtures(fixtures_dir)
    if not fixtures:
        print(f"no held-out fixtures found under {fixtures_dir}", file=sys.stderr)
        return 1
    warn_if_outside_the_net(fixtures_dir)

    scored = score(fixtures, runs_dir, rows)
    print(f"# Held-out eval — {scored.total}/{len(fixtures)} fixtures scored, "
          f"{len(scored.failures)} failure(s)")
    if scored.unscored:
        print(f"INCOMPLETE: {len(scored.unscored)} of {len(fixtures)} cases are not scored "
              f"(listed below); the gate stays closed until each is scored.")
    print()
    if not scored.total:
        print(f"no indexed run under {runs_dir} for any held-out fixture", file=sys.stderr)
        print("Aggregate accuracy: n/a — nothing scored")
    else:
        print(f"Aggregate accuracy: {scored.correct}/{scored.total} = "
              f"{scored.correct / scored.total:.1%}")
    print()
    for cls in sorted(scored.by_class):
        items = scored.by_class[cls]
        cls_correct = sum(1 for _, _, vd in items if vd == "ok")
        print(f"## class={cls}  recall={cls_correct}/{len(items)} = "
              f"{cls_correct / len(items):.1%}")
        for name, pred, vd in items:
            tag = "OK   " if vd == "ok" else "WRONG"
            print(f"  {tag}  {name}: predicted={pred!r}")
        print()
    if scored.failures:
        print("## Failure bucket (counted wrong, surfaced separately)")
        for name, reason in scored.failures:
            print(f"  {name}: {reason}")
        print()
    _print_unscored(scored)
    return 0 if scored.total and not scored.unscored else 1


def main(argv: list[str]) -> int:
    """Score the runs dir it is given against `--index F` — required, with no default and no
    tenant option: an evaluation tool outside the application takes no tenant, so scoring never
    resolves `DEFENDER_DATA_ROOT` or accepts one (§7 J50). `--help` resolves nothing."""
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("runs_dir", type=Path, help="directory of run dirs to score")
    p.add_argument("--index", type=Path, required=True,
                   help="the held-out index F of {slug, run_id, freeze, verdict, reason, verified_at} rows, outside the runs dir")
    p.add_argument("--fixtures-dir", type=Path, default=FIXTURES_DIR,
                   help=f"held-out fixtures dir (default: {FIXTURES_DIR})")
    ns = p.parse_args(argv)
    runs_dir = ns.runs_dir
    if not runs_dir.is_dir():
        print(f"runs dir does not exist: {runs_dir}", file=sys.stderr)
        return 2
    try:
        rows = read_index(ns.index, runs_dir)
    except IndexRefused as refused:
        print(f"held_out: the index {ns.index} is refused: {refused}", file=sys.stderr)
        return 2
    try:
        return report(runs_dir, rows, ns.fixtures_dir)
    except FixturesRefused as refused:
        print(f"held_out: the fixtures in {ns.fixtures_dir} are refused: {refused}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
