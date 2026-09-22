#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import hashlib
import os
import subprocess
import sys
import dataclasses as _dataclasses
from pathlib import Path
from typing import TYPE_CHECKING

DEFENDER_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEFENDER_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender import _io, _provenance, _tenant  # noqa: E402
from defender._io import guarded_mkdir  # noqa: E402
from defender._run_handle import Run, case_ref  # noqa: E402
from defender._run_id import mint_run_id, refuse_bad_run_id  # noqa: E402
from defender._run_paths import RunPaths, artifact_dir  # noqa: E402

VISUALIZE_SCRIPT = DEFENDER_DIR / "scripts" / "visualize" / "visualize_run.py"

if TYPE_CHECKING:
    from defender.runtime.branch._family import ResumeWorld

DEFAULT_RUNS_BASE = Path("/tmp/defender-runs")


def resolve_runs_base() -> Path:
    base = Path(os.environ.get("DEFENDER_RUNS_BASE", str(DEFAULT_RUNS_BASE)))
    from defender._env import FatalConfigError
    from defender.learning.core.config import learning_state_root

    if base.resolve() == learning_state_root().resolve():
        raise FatalConfigError(
            "DEFENDER_RUNS_BASE and the learning state root "
            "(DEFENDER_LEARNING_STATE_DIR) resolve to the same directory "
            f"({base.resolve()}): the enforced runtime budget pool would be spent by "
            "unenforced learning agents. Point them at distinct directories."
        )
    return base


_GENERIC_ALERT_STEMS = {"alert"}


def _alert_label(alert: Path) -> str:
    return alert.parent.name if alert.stem in _GENERIC_ALERT_STEMS else alert.stem


def _setup_state(run: Run) -> str:
    """What is under this run id already: `absent`, `setup` (only what setup itself writes —
    an interrupted or completed setup, resumable: decision 3) or `ran` (anything else — a
    run has been in this tree, and it is NEVER materialised into a second time: #771's
    stale-mount premise, the sidecars' attribution, the tables' append-only history).

    Judged by name, without following anything: the directory itself must be a real
    directory (a link at the run id is refused), the listing is `_io.bind`'s (lstat), and the
    run-end sidecar beside the directory counts as the run's own trace."""
    run_dir = run.run_dir
    if not _io.entry_present(run_dir):
        return "absent"
    if not artifact_dir(run_dir):
        sys.exit(f"{run_dir} is not a directory — refusing to materialise a run over it")
    with _io.bind(run_dir) as tree:
        listing = tree.entries()
    if listing.reason is not None:
        sys.exit(f"{run_dir} could not be listed ({listing.reason}) — refusing to resume it")
    # What setup writes, and ALL it writes, spelled by the owner: anything else — a table, a
    # wire log, a report — is a directory a run has been in.
    paths = RunPaths(run_dir)
    setup_names = {paths.alert.name, paths.gather_raw.name, paths.provenance.name}
    extra = sorted(set(listing.entries or {}) - setup_names)
    # ANY sidecar beside the directory is a run's trace: the scrub verdict is written at box
    # START (`scrub.write_did_not_run`), so a box that started and died before its first write
    # into the tree still left one — and the box sentinel does not survive a successful probe.
    sidecars = (run.facts.run_end.path, run.facts.scrub_verdict.path, run.facts.accounting.path)
    if extra or any(_io.entry_present(p) for p in sidecars):
        return "ran"
    return "setup"


def materialize_run_dir(
    alert: Path, run_id: str | None, *, model: str | None = None,
    world: ResumeWorld | None = None,
) -> Path:
    """Build (or finish building) the run directory for `run_id`, THROUGH THE HANDLE.

    Every write is one of the handle's guarded, write-once verbs, so nothing here follows a
    link the box may have planted under a reused id, and "resume" needs no ordering of checks:
    a fact is written when absent, kept when present and equal, refused when present and
    different. `world` is the sibling's own `ResumeWorld` when this process is a fork —
    handed in by the launcher that already loaded the manifest, never re-derived from the
    runs base's path (decision 15(1): 'forked' means 'has a family record', and the record is
    the manifest).
    """
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    run_id = _admit_run_id(alert, run_id)
    runs_base = resolve_runs_base()
    # The runs base is the trust root — host-controlled, created plainly (`guarded_mkdir` on
    # its own anchor creates the anchor and judges nothing above it).
    guarded_mkdir(runs_base, base=runs_base)
    # THE TENANT RECORD, created once when absent (#1077 D2) — BEFORE the provenance stamp,
    # which must equal its values, and BEFORE the box exists. A tenant record that fails to
    # parse, or a write that fails (an alias planted at its name, a directory squatting it),
    # PROPAGATES: unlike the provenance stamp below, this is never swallowed into a degraded
    # run — a run with a forged tenant is worse than no run (decision 4/7).
    tenant_record = _tenant.ensure_tenant(runs_base)
    run = Run.for_tenant(tenant_record.tenant_id, run_id, runs_base=runs_base)
    run_dir = run.run_dir
    paths = RunPaths(run_dir)

    state = _setup_state(run)
    if state == "ran":
        sys.exit(
            f"run dir already exists and a run has been in it: {run_dir} — a run id names "
            "one investigation; pick a fresh id (only a directory holding nothing but what "
            "setup writes is resumed)")
    if state == "absent":
        _clear_stale_sidecars(run)
    # The two directories, judged component by component below the runs base — a link at the
    # run id or at `gather_raw` is refused, not descended (`guarded_mkdir`, B8/B10).
    guarded_mkdir(paths.gather_raw, base=runs_base)
    _write_alert_once(run, alert)
    # STAMPED HERE, at the one place a run the box will EXECUTE is ever materialised, so no
    # caller can forget — a branched family's siblings are `run.py --resume` PROCESSES, each of
    # which reaches this call and stamps itself, and `learning/branch/cli.verify_family` is
    # what compares those per-process stamps against each other and against the source run's
    # (#976). Captured BEFORE the box exists and before any agent is alive, because the run dir
    # is the box's rw bind and a stamp written later is a stamp the run could have moved.
    #
    # RE-STAMPED on a resumed setup: the earlier attempt's stamp names the commit and model of
    # a process that never ran anything, and this one is about to. The stamp is the host's and
    # no box has been in this directory (state `setup`), so replacing it replaces nothing a
    # run produced.
    #
    # NOT every run-dir-shaped bundle: the branch archive (`learning/branch/archive.py`)
    # copies each sibling's stamp into `worlds/<X>/` rather than materialising through here,
    # because the stamp of the archive directory itself would name whenever the archive
    # happened to be taken rather than what the investigation executed. Nothing else copies a
    # stamp — in particular the learning loop's own `learning/core` writes none.
    #
    # EVERY RUN CAPTURES ITS OWN, and there is no seam for a caller to hand one in: the branch
    # launcher does NOT take one capture for all N worlds — a launcher-moment record could only
    # ever describe the launcher's process, and the family stamp is a conclusion about the
    # siblings' own per-process records, anchored to the source's.
    if state == "setup":
        # Whatever else stands at the stamp's name (a directory a crashed attempt left) is not
        # removed here; the guarded write below refuses it and `_stamp` says so.
        with contextlib.suppress(OSError):
            paths.provenance.unlink()
    _stamp(
        run, model=model, tenant_id=tenant_record.tenant_id,
        world_id=world.world_id if world is not None else tenant_record.base_world_id,
        parent_run_id=world.family.source_run_id if world is not None else None,
        fork_turn=world.family.branch_message_id if world is not None else None,
    )
    return run_dir


def _admit_run_id(alert: Path, run_id: str | None) -> str:
    """The run id this call will materialise, or the refusal — minted from the alert when the
    operator pinned none."""
    # THE EXPLICIT COLLISION GUARD FIRST (decision 13): it is the rule, and the run-id grammar
    # that also happens to refuse the record's leading underscore (claim C18) is a coincidence.
    if run_id is not None:
        collision = _tenant.refuse_colliding_run_id(run_id)
        if collision is not None:
            sys.exit(str(collision))
    # ONE admission rule for a run id, shared with the handle's constructors — the id minted
    # here is one `Run.for_tenant` admits, and an operator-pinned `--run-id` is held to the
    # same rule (case-stable, so two spellings cannot become one directory).
    try:
        if run_id is None:
            run_id = mint_run_id(_alert_label(alert))
        refuse_bad_run_id(run_id)
    except ValueError as bad:
        sys.exit(f"invalid run id: {bad}")
    return run_id


def _clear_stale_sidecars(run: Run) -> None:
    """A previous attempt under this run id (its dir removed, its id reused) may have left its
    sidecars beside the dir it no longer has (#1047) — ALL THREE, exact-run-id-keyed, never a
    glob over the runs base (#1077 decision 3). Only when the dir is ABSENT: a present dir
    with a sidecar beside it is a run that ended, and is refused."""
    for sidecar in (
        run.facts.run_end.path, run.facts.scrub_verdict.path, run.facts.accounting.path,
    ):
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            sys.exit(f"cannot clear a stale sidecar at {sidecar}: {e!r}")


def _write_alert_once(run: Run, alert: Path) -> None:
    """THE ALERT IS WRITE-ONCE: absent, it is written (through the guarded, exclusive lane — a
    planted entry at the name is refused, never followed); present, it must be THIS alert
    byte for byte, or the id is being reused for a different case."""
    alert_bytes = alert.read_bytes()
    existing, reason = _io.read_bytes_guarded(run.facts.alert.path)
    if existing is None and _io.entry_present(run.facts.alert.path):
        sys.exit(
            f"{run.facts.alert.path} is not a readable plain file ({reason}) — refusing to "
            "resume over it")
    if existing is None:
        run.facts.alert.write(alert_bytes)
    elif existing != alert_bytes:
        sys.exit(
            f"run dir {run.run_dir} already holds a different alert than {alert} — a run id "
            "names one case; pick a fresh id for a different alert")


def _stamp(
    run: Run, *, model: str | None = None,
    tenant_id: str | None = None, world_id: str | None = None,
    parent_run_id: str | None = None, fork_turn: int | None = None,
) -> None:
    """Write the run's stamp, and NEVER take the run down doing it.

    `capture_tree` goes to some length never to raise; a write that raised beside it would
    hand that promise straight back. The failure is real and unexceptional — ENOSPC on the runs
    base, a read-only remount, an alias planted where a previous run left one — and it arrives
    AFTER the run dir exists. (Before #1077 an escaping `OSError` also burned the run id —
    `materialize_run_dir` refused a dir that already existed; decision 3 made an interrupted
    setup resumable, so a retry now finishes what the first call left undone and re-stamps.)

    The asymmetry with the alert write above is the point, not an oversight. A run without its
    alert has no case to investigate and must die. A run without its stamp is a run nobody can
    later prove the code for — worth a loud line on stderr and worth nothing more, because
    `read` already answers "no usable record" for a file that is not there, and an operator
    who needs the guarantee has the announce line saying it is missing."""
    path = run.facts.provenance.path
    try:
        record = _provenance.capture_tree(REPO_ROOT)
        # THE MODEL RIDES WITH THE COMMIT, and is set here rather than by a second write: the
        # stamp is written once, before the box exists, and a model recorded afterwards would
        # be a model recorded into the box's own rw bind. `None` leaves the field absent, which
        # is what every non-branched caller means.
        if model is not None:
            record = _dataclasses.replace(record, model=model)
        # #1077 O4 — both stamp fields equal the tenant record's values, never `None`, for
        # every run the host materialises; D3/D4 — a fork's lineage rides beside them.
        record = _dataclasses.replace(
            record, tenant_id=tenant_id, world_id=world_id,
            parent_run_id=parent_run_id, fork_turn=fork_turn)
        run.facts.provenance.write(record.as_json())
    except OSError as e:
        print(f"[run_common] could not stamp {path}: {e!r} — the run continues UNSTAMPED, so "
              "nothing downstream can prove which code it ran", file=sys.stderr)


def run_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env["DEFENDER_DIR"] = str(defender_dir)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = str(run_dir.parent)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    # PREPENDED, not assigned: this env also drives the adapter/query/orient host
    # subprocesses, which inherit whatever PYTHONPATH the operator's shell set; clobbering it
    # would silently drop those entries.
    env["PYTHONPATH"] = _prepend(str(defender_dir.parent), env.get("PYTHONPATH"))
    return env


def _prepend(head: str, tail: str | None) -> str:
    return f"{head}{os.pathsep}{tail}" if tail else head


class VisualizeFailed(Exception):
    """The visualizer subprocess exited non-zero; the caller must not treat the run dir
    as rendered — a page left over from a prior render is not proof this one succeeded."""


def visualize(run_dir: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(VISUALIZE_SCRIPT), str(run_dir)],
        capture_output=True, text=True, encoding="utf-8"
    )
    sys.stderr.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(f"[run.py] visualize_run failed: {proc.stderr}")
        raise VisualizeFailed(
            f"visualize_run failed for {run_dir} (exit {proc.returncode}): {proc.stderr}")


def cross_check_tables(run_dir: Path) -> None:
    if not RunPaths(run_dir).investigation.is_file():
        return
    try:
        from defender.learning import lead_repository

        xcheck = lead_repository.narration_crosscheck_from_run(run_dir)
    except Exception as e:  # noqa: BLE001 — diagnostics must never break the run
        print(f"[run.py] narration cross-check skipped: {e!r}", file=sys.stderr)
        return
    if not xcheck["ok"]:
        print(
            "[run.py] WARN narration cross-check FAILED — the live tables "
            "disagree with investigation.md's :L rows:",
            file=sys.stderr,
        )
        if xcheck["missing_from_narration"]:
            print(f"[run.py]   table lead_ids with no :L row: {xcheck['missing_from_narration']}", file=sys.stderr)
        if xcheck["queries_without_lead"]:
            print(f"[run.py]   query FKs with no lead sidecar (orphans): {xcheck['queries_without_lead']}", file=sys.stderr)
    if xcheck["leads_without_queries"]:
        print(f"[run.py]   note: leads with no queries (monitor): {xcheck['leads_without_queries']}", file=sys.stderr)


HELD_OUT_FIXTURES = DEFENDER_DIR / "fixtures" / "held-out"


def is_held_out_fixture(alert: Path, fixtures_dir: Path = HELD_OUT_FIXTURES) -> bool:
    try:
        alert.resolve().relative_to(fixtures_dir.resolve())
    except ValueError:
        return False
    return True


def held_out_alert_digests(fixtures_dir: Path = HELD_OUT_FIXTURES) -> set[str]:
    out: set[str] = set()
    if not fixtures_dir.is_dir():
        return out
    for child in sorted(fixtures_dir.iterdir()):
        alert = RunPaths(child).alert
        try:
            out.add(hashlib.sha256(alert.read_bytes()).hexdigest())
        except OSError:
            continue
    return out


def is_held_out_alert_copy(alert: Path, fixtures_dir: Path = HELD_OUT_FIXTURES) -> bool:
    try:
        digest = hashlib.sha256(alert.read_bytes()).hexdigest()
    except OSError:
        return False
    return digest in held_out_alert_digests(fixtures_dir)


def learning_refusal_gate(
    run_dir: Path,
    alert: Path,
    *,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
    truncated_by: str | None = None,
) -> str | None:
    """The ONE refusal predicate both the learning enqueue and the curation enqueue consult.
    Returns the reason a run must be refused, or `None` if it clears every net.

    Held out is checked by CONTENT DIGEST *and* by path containment, because neither net alone
    is the whole set: the digest catches a copy of a fixture taken outside `fixtures_dir`
    (containment misses it by construction), and containment catches anything inside the
    fixture tree that the digest walk never reads — it only digests `<slug>/alert.json`."""
    if truncated_by is not None:
        return f"run was truncated (truncated_by={truncated_by!r}) — a truncated " \
            "investigation must not train the corpus"
    # BOTH nets, not the digest alone — see the docstring; dropping either one narrows the guard.
    if is_held_out_fixture(alert, fixtures_dir) or is_held_out_alert_copy(alert, fixtures_dir):
        return f"{alert} is a held-out eval fixture (or a copy of one) — its findings must " \
            "never feed a corpus it is scored against"
    from defender.runtime import scrub as _scrub

    if not _scrub.tree_verified(run_dir):
        # §7 D2/D9: a tree carrying no scan verdict, or one recording that the walk never ran,
        # is not fed to the learning loop — that crash path is the one most likely to hold what
        # a box planted.
        return f"{run_dir} carries no completed reap-scan verdict — an unverified tree " \
            "must not feed the corpus"
    return None




def enqueue_curation(
    run_dir: Path,
    alert: Path,
    *,
    truncated_by: str | None = None,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
) -> bool:
    """Catalog curation's own trigger, at the investigation boundary — welded to the shared
    refusal predicate rather than left to caller discipline, because this is the caller that
    hands attacker-influenced content (the investigation's goal text, bound parameters,
    rendered queries) to the lead-author curator."""
    reason = learning_refusal_gate(
        run_dir, alert, fixtures_dir=fixtures_dir, truncated_by=truncated_by
    )
    if reason is not None:
        print(f"[run.py] NOT enqueuing for curation: {reason}", file=sys.stderr)
        return False
    from defender.learning.core import markers as _markers
    from defender.learning.core.config import REPO_ROOT as _LEARN_REPO_ROOT
    from defender.learning.core.config import LoopPaths, _env_state_dir

    paths = LoopPaths(repo_root=_LEARN_REPO_ROOT, state_dir=_env_state_dir())
    # The case-key derivation is inside the guard with the write it feeds: it reads the alert
    # off disk, and an alert the operator moved mid-run would otherwise take the
    # investigation's exit status down with it — for a lane already declared cheap to lose.
    try:
        case_id = case_ref(alert.read_bytes())
        _markers.enqueue_case_for_curation(case_id, run_dir, paths)
    except OSError as e:
        print(f"[run.py] NOT enqueuing for curation: could not write the request: {e!r}",
              file=sys.stderr)
        return False
    return True
