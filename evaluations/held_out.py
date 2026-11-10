#!/usr/bin/env python3
"""Primary-metric harness: score defender held-out runs against ground truth.

Walks the FIXTURE set (``evaluations/fixtures/held_out/``) and reports defender disposition
correctness. A run is matched to its fixture by the held-out INDEX alone, a JSON Lines file
the operator names (``--index F``), one row per run, oldest first.
A run folder's name claims nothing (#1187): every run id is an opaque UUID, minted by the
system and announced as run.py's first stdout line ``run_id=<uuid>`` (#1279).

Ground truth never leaves the fixture dirs: the run dir is readable by the agent, so it
carries no labels and no pointer back to its fixture. The index is host-written and kept
outside every runs and episodes tree, where no box can write it.

The lab's launcher starts each scored run and writes its row. A run that crashes before its
row leaves its case unscored. For comparable scores, pin every run of one index to one knowledge
revision (#1108 P4 OD10); the row records it.

Score (an evaluation tool outside the application: it takes no tenant and never resolves
``DEFENDER_DATA_ROOT``; it scores exactly the runs dir it is handed)::

    python3 -m evaluations.held_out "$DEFENDER_DATA_ROOT/<tenant-uuid>/runs" --index F

A labelled fixture is a case only with a ``case.yaml`` beside its ground truth, naming a freeze
(``freezes/<freeze-id>/freeze.yaml`` under the fixtures dir). A row is
``{slug, run_id, binding, knowledge, verdict, reason, verified_at}`` and counts only when its
``binding`` equals ``binding(freeze, case)`` of the case as it is now, so changing either file
unbinds older rows. The newest counting row names the run scored, opened by id under the runs
dir. A case with no counting row, or whose newest says ``stale``, is listed with its reason, left
out of the accuracy, and makes the report incomplete and the exit non-zero. A case with a missing
freeze, or a value canonical JSON cannot carry, refuses the set. A case whose newest counting
row names a run that is absent, or has no alert record, counts as **wrong** ("launched, no run
record"), as does a run without a parseable ``report.md`` (missing, bad frontmatter, disposition
outside the closed enum, or crashed). An F inside the runs dir is refused: that tree is the
boxes' own.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

import yaml

# Every `defender` import is deferred to the function that needs it, so `binding` imports with
# only the standard library and PyYAML (the lab imports it).
if TYPE_CHECKING:
    from defender.records import RunPaths  # noqa: F401


def _digest(doc: object) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def binding(freeze_doc: object, case_doc: object) -> str:
    """The binding (#1347 A8): bare lowercase hex sha256 of the canonical JSON
    ``[freeze digest, case digest]``, each digest taken over the parsed YAML document. Canonical
    is sorted keys, compact separators, ASCII-escaped, so comments, key order and line endings
    do not matter. This is the one owner. Raises `TypeError` / `ValueError` for a value
    canonical JSON cannot carry (an unquoted YAML timestamp, say)."""
    return _digest([_digest(freeze_doc), _digest(case_doc)])


#: The failure bucket of a slug whose newest row names a run that is absent or has no alert
#: record (#1187 recheck X2): counted wrong, so a crash before run setup cannot leave the
#: denominator.
NO_RUN_RECORD = "launched, no run record"

#: The index verdicts a row may carry (#1347): the post-run check's answer.
VERDICTS: tuple[str, ...] = ("valid", "stale")

FREEZES_DIR = "freezes"
FREEZE_FILE = "freeze.yaml"
CASE_FILE = "case.yaml"


def _labels() -> tuple[str, ...]:
    from defender._vocab import DISPOSITION_VALUES, HOST_ONLY_DISPOSITION
    return tuple(d for d in DISPOSITION_VALUES if d != HOST_ONLY_DISPOSITION)


def _fixtures_dir() -> Path:
    from defender.run_common import HELD_OUT_FIXTURES
    return HELD_OUT_FIXTURES


def __getattr__(name: str) -> Any:
    """`LABELS` and `FIXTURES_DIR`, resolved on first use (they come from `defender`).

    `LABELS`: the dispositions a fixture may be labelled with, every one the agent can author.
    The host-only `unresolved` is never a right answer, so a label naming it is refused."""
    if name == "LABELS":
        return _labels()
    if name == "FIXTURES_DIR":
        return _fixtures_dir()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class FixturesRefused(Exception):  # noqa: N818 — named for its refusal, as `IndexRefused` is
    """A held-out fixture carries a label outside `LABELS`, or a case without a usable freeze.
    Scoring refuses the whole set rather than let a typo or a broken case shrink the
    denominator; the message names every such fixture."""


class IndexRefused(Exception):  # noqa: N818 — named for its refusal, as `TenantRefused` is
    """The held-out index is refused — where it sits, how it is reached, or what it holds. The
    message names it; the command line prints it on stderr and exits non-zero."""


def predicted_disposition(run_dir: Path) -> str | None:
    """This run's predicted disposition, or `None` when the report yields no usable headline.
    Degrades rather than raising so one broken report does not stop scoring the rest.
    """
    from defender.records import RunPaths
    from defender.records._report import read_report
    return read_report(RunPaths(run_dir).report).disposition


@dataclass(frozen=True)
class HeldOutAlert:
    slug: str
    alert_path: Path
    ground_truth: dict
    binding: str = ""
    age: int | float | None = None  # seconds, T minus the alert's time (case.yaml `age`)


class _CaseFault(Exception):
    """One case cannot be bound; the message says why."""


def _load_yaml(path: Path) -> Any:
    from defender._io import read_text_utf8
    from defender._yaml import safe_load
    try:
        return safe_load(read_text_utf8(path))
    except (yaml.YAMLError, OSError, ValueError) as e:
        raise _CaseFault(f"unparseable {path.name} ({e})") from e


def _freeze_doc(root: Path, freeze_id: object, cache: dict[str, Any]) -> Any:
    if (not isinstance(freeze_id, str) or not freeze_id or freeze_id in (".", "..")
            or Path(freeze_id).name != freeze_id):
        raise _CaseFault(f"freeze {freeze_id!r} is not a freeze id")
    if freeze_id not in cache:
        path = root / FREEZES_DIR / freeze_id / FREEZE_FILE
        if not path.is_file():
            raise _CaseFault(f"freeze {freeze_id} has no {FREEZE_FILE}")
        doc = _load_yaml(path)
        if not isinstance(doc, dict):
            raise _CaseFault(f"{FREEZE_FILE} of {freeze_id} is not a mapping")
        cache[freeze_id] = doc
    return cache[freeze_id]


def _bind_case(root: Path, case_file: Path, cache: dict[str, Any]) -> tuple[str, Any]:
    """`(binding, age)` of the case at `case_file`, or `_CaseFault`."""
    case = _load_yaml(case_file)
    if not isinstance(case, dict):
        raise _CaseFault(f"{CASE_FILE} is not a mapping")
    freeze = _freeze_doc(root, case.get("freeze"), cache)
    try:
        bound = binding(freeze, case)
    except (TypeError, ValueError) as e:
        raise _CaseFault(f"a value canonical JSON cannot carry ({e})") from e
    age = case.get("age")
    return bound, age if isinstance(age, (int, float)) and not isinstance(age, bool) else None


def _labelled(child: Path) -> dict | None:
    """The ground truth of the held-out fixture `child`, or `None` when it is not one (warning
    where a labelled fixture cannot be run)."""
    from defender._io import read_text_utf8
    from defender._yaml import safe_load
    from defender.records import RUN_LAYOUT
    # A fixture is a folder an operator keeps, not a run: its alert is the file by that name.
    alert = child / RUN_LAYOUT.alert.name
    gt = child / "ground_truth.yaml"
    if not gt.is_file():
        return None
    if not alert.is_file():
        print(f"warn: {child.name}: labeled held-out fixture has no {alert.name} "
              f"— excluded from the eval set", file=sys.stderr)
        return None
    try:
        gt_doc = safe_load(read_text_utf8(gt)) or {}
    except yaml.YAMLError as e:
        print(f"warn: {child.name}: unparseable ground_truth.yaml ({e}) — fixture skipped",
              file=sys.stderr)
        return None
    if not isinstance(gt_doc, dict) or gt_doc.get("held_out") is not True:
        return None
    return gt_doc


def load_held_out_fixtures(fixtures_dir: Path) -> list[HeldOutAlert]:
    """The cases under `fixtures_dir`: labelled fixtures with a `case.yaml` (one without is not
    a case). Raises `FixturesRefused` for a stray label or a case that cannot be bound."""
    from defender.records import RUN_LAYOUT
    out: list[HeldOutAlert] = []
    faults: list[str] = []
    freezes: dict[str, Any] = {}
    for child in sorted(fixtures_dir.iterdir()):
        if not child.is_dir() or (gt_doc := _labelled(child)) is None:
            continue
        case_file = child / CASE_FILE
        if not case_file.is_file():
            continue
        try:
            bound, age = _bind_case(fixtures_dir, case_file, freezes)
        except _CaseFault as e:
            faults.append(f"{child.name} ({e})")
            continue
        out.append(HeldOutAlert(child.name, child / RUN_LAYOUT.alert.name, gt_doc, bound, age))
    stray = [f"{fx.slug} ({fx.ground_truth.get('disposition')!r})" for fx in out
             if fx.ground_truth.get("disposition") not in _labels()]
    problems = []
    if stray:
        problems.append(f"labels outside {list(_labels())}: {', '.join(stray)}")
    if faults:
        problems.append(f"cases that cannot be bound: {', '.join(faults)}")
    if problems:
        raise FixturesRefused("; ".join(problems))
    return out


def warn_if_outside_the_net(fixtures_dir: Path) -> bool:
    net = _fixtures_dir()
    if fixtures_dir.resolve() == net.resolve():
        return False
    print(f"WARNING: scoring {fixtures_dir}, but the enqueue-time contamination net only "
          f"refuses runs from {net} — runs of these fixtures were NOT held out "
          f"of learning unless they were launched with --no-learn", file=sys.stderr)
    return True


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


class IndexRow(NamedTuple):
    """One index row: the run `run_id` of `slug`, bound to `binding` (`None` for a row from
    before bindings, which never counts), with the post-run check's `verdict` and `reason`."""
    slug: str
    run_id: str
    binding: str | None
    verdict: str | None
    reason: str


def _row_fault(row: dict) -> str | None:
    """Why `row` is not a well-formed index row, or `None`."""
    from defender.records._run_id import run_id_fault
    slug, run_id = row.get("slug"), row.get("run_id")
    if not isinstance(slug, str) or not isinstance(run_id, str):
        return "does not carry a text slug and run_id"
    if (why := run_id_fault(run_id)) is not None:
        return f"run_id {run_id!r} is not a run id: {why}"
    bound, verdict = row.get("binding"), row.get("verdict")
    if bound is not None and not isinstance(bound, str):
        return "binding is not text"
    if (bound is not None or verdict is not None) and verdict not in VERDICTS:
        return f"verdict {verdict!r} is not one of {list(VERDICTS)}"
    if row.get("knowledge") is not None and not isinstance(row["knowledge"], str):
        return "knowledge is not text"  # null or "" is a pinless launch
    return None


def read_index(index: Path, runs_dir: Path) -> list[IndexRow]:
    """F's rows, oldest first. F inside the runs dir — judged at the real places of both, so a
    link a box planted inside its own run folder never puts F inside — is refused: that tree is
    the boxes' own. So is an F that is absent, holds a line that is not a row, or a malformed
    row (see `_row_fault`): the index is host-written, and scoring fails closed on one it cannot
    trust. A row without `binding` is from before bindings: well-formed, never counted."""
    from defender import _io
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
        if (fault := _row_fault(row)) is not None:
            raise IndexRefused(f"row {n} {fault}")
        reason = row.get("reason")
        out.append(IndexRow(row["slug"], row["run_id"], row.get("binding"), row.get("verdict"),
                            reason if isinstance(reason, str) else ""))
    return out


@dataclass
class Scored:

    by_class: dict[str, list[tuple[str, str | None, str]]]
    failures: list[tuple[str, str]]
    not_run: list[str]
    stale: list[tuple[str, str]] = field(default_factory=list)  # (slug, the row's reason)

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.by_class.values())

    @property
    def correct(self) -> int:
        return sum(1 for v in self.by_class.values() for _, _, vd in v if vd == "ok")

    @property
    def unscored(self) -> int:
        return len(self.not_run) + len(self.stale)


def _unrecorded(run_dir: Path) -> str | None:
    """Why the run at `run_dir` is no run: absent (nothing at the id, or a link or file there —
    an entry of the runs dir is never followed), or with no readable alert record. `None` for
    a run."""
    from defender.records import RunPaths, _alert_input
    try:
        st = os.lstat(run_dir)
    except FileNotFoundError:
        return f"run {run_dir.name} is absent"
    if not stat.S_ISDIR(st.st_mode):
        return f"run {run_dir.name} is absent (not a folder at that id)"
    if _alert_input.read_record(RunPaths(run_dir).alert_record) is None:
        return f"run {run_dir.name} has no alert record"
    return None


def score(fixtures: list[HeldOutAlert], runs_dir: Path, rows: list[IndexRow] | tuple = ()) -> Scored:
    """Score each case from the newest index row bound to its current binding, the run it names
    opened by id under `runs_dir`. Rows of another binding, or none, are set aside first. A case
    is left unscored when it has no such row (not run) or the newest says stale. A frozen
    run's clock is the freeze's (#1347 D15), so no recorded query is read here."""
    by_class: dict[str, list[tuple[str, str | None, str]]] = defaultdict(list)
    failures: list[tuple[str, str]] = []
    not_run: list[str] = []
    stale: list[tuple[str, str]] = []
    for fx in fixtures:
        bound = [r for r in rows if r.slug == fx.slug and r.binding == fx.binding]
        if not bound:
            not_run.append(fx.slug)
            continue
        newest = bound[-1]
        if newest.verdict == "stale":
            stale.append((fx.slug, newest.reason or "the post-run check found it stale"))
            continue
        true_disp = str(fx.ground_truth.get("disposition") or "?")
        _score_run(fx, runs_dir / newest.run_id, true_disp, by_class, failures)
    return Scored(by_class, failures, not_run, stale)


def _score_run(fx: HeldOutAlert, run_dir: Path, true_disp: str,
               by_class: dict[str, list[tuple[str, str | None, str]]],
               failures: list[tuple[str, str]]) -> None:
    absent = _unrecorded(run_dir)
    if absent is not None:
        failures.append((fx.slug, f"{NO_RUN_RECORD} ({absent})"))
        by_class[true_disp].append((fx.slug, None, "wrong"))
        return
    pred = predicted_disposition(run_dir)
    verdict = "ok" if pred == true_disp else "wrong"
    if pred is None:
        failures.append((fx.slug, "no parseable report.md"))  # lint-run-records: ok — an eval case's own file under the case tree, never a run record
    by_class[true_disp].append((fx.slug, pred, verdict))


#: The alert's age at T, in the bands the report names (#1347 A2: the cases are one moment's).
#: Together they cover [0, 6 h]: the last band includes its upper edge. The 6 h is the lab's
#: candidate window, restated here because the scorer imports no lab code.
_AGE_BANDS = ((3600, "under 1 h"), (3 * 3600, "1–3 h"))
_LAST_BAND, _LAST_EDGE = "3–6 h", 6 * 3600


def _age_band(age: int | float | None) -> str:
    if age is None:
        return ""
    if age <= _LAST_EDGE:
        return next((label for limit, label in _AGE_BANDS if age < limit), _LAST_BAND)
    return "over 6 h"


def _print_unscored(scored: Scored) -> None:
    if scored.not_run:
        print("## Not run (no index row bound to the case's current binding; excluded from accuracy)")
        for slug in scored.not_run:
            print(f"  {slug}: not run, no row for the case as it stands now")
        print()
    if scored.stale:
        print("## Needs re-confirmation (the post-run check found the case changed; excluded from accuracy)")
        for slug, reason in scored.stale:
            print(f"  {slug}: needs re-confirmation: {reason}")
        print()


def report(runs_dir: Path, rows: list[IndexRow], fixtures_dir: Path | None = None) -> int:
    fixtures_dir = fixtures_dir if fixtures_dir is not None else _fixtures_dir()
    fixtures = load_held_out_fixtures(fixtures_dir)
    if not fixtures:
        print(f"no held-out fixtures found under {fixtures_dir}", file=sys.stderr)
        return 1
    warn_if_outside_the_net(fixtures_dir)

    scored = score(fixtures, runs_dir, rows)
    ages = {fx.slug: _age_band(fx.age) for fx in fixtures}
    print(f"# Held-out eval — {scored.total}/{len(fixtures)} fixtures scored, "
          f"{len(scored.failures)} failure(s)")
    if scored.unscored:
        print(f"INCOMPLETE: {scored.unscored} of {len(fixtures)} cases are not scored "
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
            band = f"  [age at T: {ages[name]}]" if ages[name] else ""
            print(f"  {tag}  {name}: predicted={pred!r}{band}")
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
                   help="the held-out index F of bound rows, outside the runs dir")
    p.add_argument("--fixtures-dir", type=Path, default=None,
                   help="held-out fixtures dir (default: evaluations/fixtures/held_out)")
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
    fixtures_dir = ns.fixtures_dir or _fixtures_dir()
    try:
        return report(runs_dir, rows, fixtures_dir)
    except FixturesRefused as refused:
        print(f"held_out: the fixtures in {fixtures_dir} are refused: {refused}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
