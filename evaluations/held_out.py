#!/usr/bin/env python3
"""Primary-metric harness: score defender held-out runs against ground truth.

Walks the FIXTURE set (``evaluations/fixtures/held_out/``) and reports defender disposition
correctness. A run is matched to its fixture by the held-out INDEX alone, a JSON Lines file
the operator names (``--index F``), oldest first. A run folder's name claims nothing (#1187):
every run id is an opaque UUID, and the system alone mints it (#1279): a launch never names one.

Rows are of three shapes. A launch ``{slug, launch_id, launched_at}`` is appended before the
run starts; the id row ``{slug, launch_id, run_id}`` is appended once ``run.py`` announces the run
(``run_id=<uuid>`` as its first stdout line); a legacy row ``{slug, run_id}`` (written before #1279)
counts as a launch with its id, at its position. Ground truth never leaves the fixture dirs: the
run dir is readable by the agent, so it carries no labels and no pointer back to its fixture. The
index is host-written and kept outside every runs and episodes tree, where no box can write it.

Launch one held-out run for an explicitly named tenant UUID::

    python3 evaluations/held_out.py launch <slug> --tenant <tenant-uuid> --index F

It refuses an F under the resolved data root (including all tenant learning roots), or reached
through a link; mints a launch id; APPENDS the launch row to F; runs
``run.py <fixture alert> --tenant <tenant-uuid> --no-learn`` (``--no-learn`` keeps a scored run
out of the learning corpora); and appends the id row as soon as the run announces its id, while it
is still running. A run that fails before it announces an id still has its launch row.

Score (an evaluation tool outside the application: it takes no tenant and never resolves
``DEFENDER_DATA_ROOT``; it scores exactly the runs dir it is handed)::

    python3 evaluations/held_out.py "$DEFENDER_DATA_ROOT/<tenant-uuid>/runs" --index F

The newest row per slug names the run scored, opened by id under the runs dir. A slug whose
newest row names a run that is absent, or has no alert record, counts as **wrong** ("launched,
no run record"), as does a run without a parseable ``report.md`` (missing, bad frontmatter,
disposition outside the closed enum, or crashed) — so regressions cannot hide behind crashes.
Only a slug with no row is "not run". An F inside the runs dir is refused: that tree is the
boxes' own.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from collections import defaultdict
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType

import yaml

if (_root := str(Path(__file__).resolve().parents[1])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _io
from defender.records import _alert_input
from defender._yaml import safe_load
from defender._model import model
from defender.records._report import read_report
from defender.records._run_id import run_id_fault
from defender.tenancy._tenant import (
    TenantId, TenantRefused, data_root_contains, data_root_description, resolve_data_root,
)
from defender.run_repository import RUN_LAYOUT, RunPaths
from defender.run_common import HELD_OUT_FIXTURES as FIXTURES_DIR
from defender._io import read_text_utf8

#: The investigation entry point a launch starts.
RUN_PY = Path(__file__).resolve().parents[1] / "defender" / "run.py"
#: The failure bucket of a slug whose newest row names a run that is absent or has no alert
#: record (#1187 recheck X2): counted wrong, so a crash before run setup cannot leave the
#: denominator.
NO_RUN_RECORD = "launched, no run record"
NO_RUN = "launched, no run"
#: Starts run.py for a launch: `spawn(argv, *, env=None, on_line) -> exit code`, `argv` the whole
#: command line (the interpreter, then run.py and its arguments). It hands each line of the child's
#: stdout to `on_line` (no terminator) as the line arrives, then answers the exit code.
Spawn = Callable[..., int]


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


def load_held_out_fixtures(fixtures_dir: Path) -> list[HeldOutAlert]:
    out: list[HeldOutAlert] = []
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
        out.append(HeldOutAlert(child.name, alert, gt_doc))
    return out


def warn_if_outside_the_net(fixtures_dir: Path) -> bool:
    if fixtures_dir.resolve() == FIXTURES_DIR.resolve():
        return False
    print(f"WARNING: scoring {fixtures_dir}, but the enqueue-time contamination net only "
          f"refuses runs from {FIXTURES_DIR} — runs of these fixtures were NOT held out "
          f"of learning unless they were launched with --no-learn", file=sys.stderr)
    return True


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _hold_index_folder(index: Path) -> tuple[_io.Held, Path, str]:
    """F's folder, held by a walk from `/` that follows no link at any level, and F's absolute
    spelling and leaf name. A link at any folder on F's spelling — or at F itself — is refused,
    wherever it leads (where a link leads can change after the check); so is a missing folder,
    a `..`, and anything at F but a regular file. With no link anywhere on it, F's spelling is
    its real place, which is what the root checks judge."""
    absolute = index if index.is_absolute() else Path.cwd() / index
    *folders, leaf = absolute.parts[1:]
    held = _io.hold(Path(absolute.anchor), follow=False)
    try:
        reached = Path(absolute.anchor)
        for name in folders:
            reached = reached / name
            if name == "..":
                raise IndexRefused(f"its spelling steps back up at {reached}; name it without "
                                   "'..'")
            try:
                below = _io.hold_under(held, name)
            except FileNotFoundError:
                raise IndexRefused(f"its folder {reached} does not exist") from None
            except (OSError, ValueError):
                raise IndexRefused(f"it is reached through {reached}, which is a link or not a "
                                   "folder — no link on its path is followed") from None
            held.close()
            held = below
        entry = _io.stat_entry(held.view(), leaf)
        if not entry.absent and (entry.st is None or not stat.S_ISREG(entry.st.st_mode)):
            raise IndexRefused("it is not a regular file; a link or any other entry at its name "
                               "is never followed")
    except BaseException:
        held.close()
        raise
    return held, absolute, leaf


def _fixture(fixtures_dir: Path, slug: str) -> HeldOutAlert | None:
    return next((fx for fx in load_held_out_fixtures(fixtures_dir) if fx.slug == slug), None)


def launch(slug: str, index: Path, fixtures_dir: Path, *, tenant_id: str, spawn: Spawn) -> int:
    """Launch one held-out run of `slug` (Flow 5): refuse a bad F, mint a launch id, append the
    launch row to F — durably, through F's folder held with no link followed — and only then start
    run.py. Its first stdout line announces the run's id (`run_id=<uuid>`); the id row is appended
    at once, while the run goes on. A launch no id row names scores wrong. Returns run.py's exit
    code (non-zero when the first line broke the announce contract); a refusal is `IndexRefused`
    (or `TenantRefused` for the data root), raised before anything is appended or started."""
    tenant_id = TenantId(tenant_id)
    data_root = resolve_data_root()
    fixture = _fixture(fixtures_dir, slug)
    if fixture is None:
        raise IndexRefused(f"no labelled held-out fixture {slug!r} under {fixtures_dir}")
    held, absolute, leaf = _hold_index_folder(index)
    with held:
        if data_root_contains(data_root, absolute):
            raise IndexRefused(f"it is under the data root {data_root_description(data_root)}, where a box or the loop can "
                               "write it")
        launch_id = str(uuid.uuid4())
        _append(held, leaf, {"slug": slug, "launch_id": launch_id,
                             "launched_at": datetime.now(UTC).isoformat()})
        print(f"{slug} launch {launch_id}", flush=True)
        seen = 0
        broken: list[str] = []

        def on_line(line: str) -> None:
            nonlocal seen
            seen += 1
            if seen > 1:
                print(line, flush=True)
                return
            run_id = line.removeprefix("run_id=") if line.startswith("run_id=") else None
            if run_id is None or run_id_fault(run_id) is not None:
                broken.append(line)
                return
            _append(held, leaf, {"slug": slug, "launch_id": launch_id, "run_id": run_id})

        code = spawn([sys.executable, str(RUN_PY), str(fixture.alert_path),
                      "--tenant", tenant_id, "--no-learn"], on_line=on_line)
    if broken:
        print(f"held_out launch: the announce contract was broken: run.py's first line was "
              f"{broken[0]!r}, not run_id=<uuid>; no run id was recorded for launch {launch_id}",
              file=sys.stderr)
        return code or 1
    return code


def _append(held: _io.Held, leaf: str, row: dict) -> None:
    """One durable row onto F through its held folder."""
    text = json.dumps(row)  # lint-jsonl-io: ok — one row through the held folder's no-follow append; `append_jsonl` follows the spelling
    try:
        held.write(leaf, text + "\n", mode="append", durable=True)
    except OSError as exc:
        raise IndexRefused(f"its row could not be appended: {exc.strerror or exc}") from None


def _spawn_run_py(argv: list[str], *, env: dict[str, str] | None = None,
                  on_line: Callable[[str], None]) -> int:
    """Run run.py to completion in its own process: each stdout line goes to `on_line` as it
    arrives (the pipe is read line by line, so the first reaches the launcher while the child
    runs), then the exit code."""
    with subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, text=True,  # noqa: S603 — fixed argv
                          encoding="utf-8", errors="replace") as child:
        assert child.stdout is not None
        for line in child.stdout:
            on_line(line.rstrip("\n"))
        return child.wait()


def read_index(index: Path, runs_dir: Path) -> dict[str, str | None]:
    """`{slug: run_id}` from F's newest launch per slug, by file position (F is append-only;
    `launched_at` is information only). The value is `None` when that launch has no id row: the
    run never announced itself. A legacy `{slug, run_id}` row is a launch with its id.

    F inside the runs dir — judged at the real places of both, so a link a box planted inside its
    own run folder never puts F inside — is refused: that tree is the boxes' own. So is an F that
    is absent, holds a line that is not a row, a row of none of the three shapes, an id row that
    names no earlier launch of its slug or a launch already named, a repeated launch id, or a
    run id that is not a run id: the index is host-written, and scoring fails closed on one it
    cannot trust."""
    if _inside(index.resolve(), runs_dir.resolve()):
        raise IndexRefused(f"it is inside the runs dir {runs_dir}, which the boxes can write")
    if not index.is_file():
        raise IndexRefused("it does not exist, or is not a file")
    rows, dropped = _io.read_jsonl_rows_report(index)
    if dropped:
        raise IndexRefused(f"{dropped} of its lines are not JSON objects")
    launches: dict[str, str] = {}  # launch id -> slug
    named: dict[str, str] = {}  # launch id -> run id
    order: list[tuple[str, str | None, str | None]] = []  # (slug, launch id, legacy run id)
    for n, row in enumerate(rows, 1):
        _admit_row(n, row, launches, named, order)
    newest: dict[str, str | None] = {}
    for slug, launch_id, legacy_run_id in order:
        newest[slug] = legacy_run_id if launch_id is None else named.get(launch_id)
    return newest


def _admit_row(n: int, row: dict, launches: dict[str, str], named: dict[str, str],
               order: list[tuple[str, str | None, str | None]]) -> None:
    """Admit row `n` of F into the three tallies, or refuse it: exactly one of the three shapes
    (legacy, launch, id), with the cross-row rules the shapes carry."""
    keys = set(row)
    slug = row.get("slug")
    if not isinstance(slug, str):
        raise IndexRefused(f"row {n} does not carry a text slug")
    if keys == {"slug", "run_id"}:
        order.append((slug, None, _run_id_of(n, row["run_id"])))
    elif keys == {"slug", "launch_id", "launched_at"}:
        launch_id = _launch_id_of(n, row["launch_id"])
        if not isinstance(row["launched_at"], str) or not row["launched_at"]:
            raise IndexRefused(f"row {n} does not carry a text launched_at")
        if launch_id in launches:
            raise IndexRefused(f"row {n} repeats launch id {launch_id}")
        launches[launch_id] = slug
        order.append((slug, launch_id, None))
    elif keys == {"slug", "launch_id", "run_id"}:
        launch_id = _launch_id_of(n, row["launch_id"])
        if launches.get(launch_id) != slug:
            raise IndexRefused(f"row {n} names launch {launch_id}, which no earlier launch "
                               f"row of slug {slug!r} holds")
        if launch_id in named:
            raise IndexRefused(f"row {n} is a second id row for launch {launch_id}")
        named[launch_id] = _run_id_of(n, row["run_id"])
    else:
        raise IndexRefused(f"row {n} is not a launch, an id or a legacy row (keys {sorted(keys)})")


def _run_id_of(n: int, run_id: object) -> str:
    if not isinstance(run_id, str):
        raise IndexRefused(f"row {n} does not carry a text run_id")
    if (why := run_id_fault(run_id)) is not None:
        raise IndexRefused(f"row {n}'s run_id {run_id!r} is not a run id: {why}")
    return run_id


def _launch_id_of(n: int, launch_id: object) -> str:
    try:
        if isinstance(launch_id, str) and str(uuid.UUID(launch_id)) == launch_id:
            return launch_id
    except ValueError:
        pass
    raise IndexRefused(f"row {n}'s launch_id {launch_id!r} is not canonical UUID text")


@model
class Scored:

    by_class: dict[str, list[tuple[str, str | None, str]]]
    failures: list[tuple[str, str]]
    not_run: list[str]

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


def score(fixtures: list[HeldOutAlert], runs_dir: Path,
          newest: Mapping[str, str | None] = MappingProxyType({})) -> Scored:
    """Score each fixture from the run its newest launch names (`newest`, `{slug: run_id}`),
    opened by id under `runs_dir`. A slug with no launch is not run; one whose newest launch has
    no run id (`None`) is wrong ("launched, no run")."""
    by_class: dict[str, list[tuple[str, str | None, str]]] = defaultdict(list)
    failures: list[tuple[str, str]] = []
    not_run: list[str] = []
    for fx in fixtures:
        if fx.slug not in newest:
            not_run.append(fx.slug)
            continue
        run_id = newest[fx.slug]
        true_disp = str(fx.ground_truth.get("disposition") or "?")
        if run_id is None:
            failures.append((fx.slug, f"{NO_RUN} (the launch announced no run id)"))
            by_class[true_disp].append((fx.slug, None, "wrong"))
            continue
        run_dir = runs_dir / run_id
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
    return Scored(by_class, failures, not_run)


def report(runs_dir: Path, newest: Mapping[str, str | None],
           fixtures_dir: Path = FIXTURES_DIR) -> int:
    fixtures = load_held_out_fixtures(fixtures_dir)
    if not fixtures:
        print(f"no held-out fixtures found under {fixtures_dir}", file=sys.stderr)
        return 1
    warn_if_outside_the_net(fixtures_dir)

    scored = score(fixtures, runs_dir, newest)
    print(f"# Held-out eval — {scored.total}/{len(fixtures)} fixtures scored, "
          f"{len(scored.failures)} failure(s)")
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
    if scored.not_run:
        print("## Not run (no index row — coverage gap, excluded from accuracy)")
        for slug in scored.not_run:
            print(f"  {slug}")
    return 0 if scored.total else 1


def _launch_main(argv: list[str], spawn: Spawn) -> int:
    p = argparse.ArgumentParser(prog="held_out.py launch",
                                description="Launch one held-out run, its index row first.")
    p.add_argument("slug", help="the held-out fixture to run")
    p.add_argument("--tenant", required=True, help="the tenant UUID passed to run.py")
    p.add_argument("--index", type=Path, required=True,
                   help="the held-out index F, outside the data root, the learning state root "
                        "and every link")
    p.add_argument("--fixtures-dir", type=Path, default=FIXTURES_DIR,
                   help=f"held-out fixtures dir (default: {FIXTURES_DIR})")
    ns = p.parse_args(argv)
    try:
        return launch(ns.slug, ns.index, ns.fixtures_dir, tenant_id=ns.tenant, spawn=spawn)
    except IndexRefused as refused:
        print(f"held_out launch: the index {ns.index} is refused: {refused}", file=sys.stderr)
    except TenantRefused as refused:
        print(f"held_out launch: refused before the index {ns.index} was judged: {refused}",
              file=sys.stderr)
    return 2


def main(argv: list[str], *, spawn: Spawn = _spawn_run_py) -> int:
    """`launch <slug> --tenant <tenant-uuid> --index F` starts one held-out run, its index
    row appended first (the
    launch resolves the data root, because it runs run.py). Otherwise score the runs dir it is
    given against `--index F` — required, with no default and no tenant option: an evaluation
    tool outside the application takes no tenant, so scoring never resolves
    `DEFENDER_DATA_ROOT` or accepts one (§7 J50). `--help` resolves nothing. (A runs dir that
    is literally named `launch` is spelled `./launch`.)"""
    if argv[:1] == ["launch"]:
        return _launch_main(argv[1:], spawn)
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("runs_dir", type=Path, help="directory of run dirs to score")
    p.add_argument("--index", type=Path, required=True,
                   help="the held-out index F its launches appended to, outside the runs dir")
    p.add_argument("--fixtures-dir", type=Path, default=FIXTURES_DIR,
                   help=f"held-out fixtures dir (default: {FIXTURES_DIR})")
    ns = p.parse_args(argv)
    runs_dir = ns.runs_dir
    if not runs_dir.is_dir():
        print(f"runs dir does not exist: {runs_dir}", file=sys.stderr)
        return 2
    try:
        newest = read_index(ns.index, runs_dir)
    except IndexRefused as refused:
        print(f"held_out: the index {ns.index} is refused: {refused}", file=sys.stderr)
        return 2
    return report(runs_dir, newest, ns.fixtures_dir)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
