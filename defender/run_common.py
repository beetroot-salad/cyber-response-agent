#!/usr/bin/env python3
"""Shared run-dir + post-step helpers for the defender runtime.

The entrypoint (`run.py`, the PydanticAI engine) and the gather/orient tools
import these: `materialize_run_dir` (set up the run dir), `run_env` (the bash
tool's subprocess environment), `cross_check_tables` / `enqueue_learning` /
`visualize` (the post-investigation steps). Engine-agnostic and side-effect-free
to import — the heavier learning imports are done lazily inside the functions
that need them.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

DEFENDER_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEFENDER_DIR.parent
# Put the workspace root on sys.path so `defender.*` namespace imports resolve
# (the learning modules are imported lazily below); see tests/conftest.py.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender._run_paths import RunPaths  # noqa: E402

VISUALIZE_SCRIPT = DEFENDER_DIR / "scripts" / "visualize" / "visualize_run.py"

# The single home for the runtime runs-base literal + its env resolution. Every
# other reader (evals/_secondary_config.py, evals/held_out.py) calls
# resolve_runs_base() instead of re-reading DEFENDER_RUNS_BASE with its own copy of
# the DEFAULT_RUNS_BASE default below.
DEFAULT_RUNS_BASE = Path("/tmp/defender-runs")


def resolve_runs_base() -> Path:
    """The runtime runs base from ``$DEFENDER_RUNS_BASE`` (call time), else the
    default. Resolved here so the env var + default literal have one source.

    REFUSES a runs base that resolves to the same directory as the learning state root
    (#631, Q1): the runtime pool ``budget.json`` lives under the runs base, so pairing
    the two env vars onto one path would let unenforced learning agents spend the
    enforced pool. The disjointness is otherwise emergent from two env-var defaults; here
    it is asserted (a symlink alias to the same dir is the same collision — both sides
    are ``resolve()``-d)."""
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


# Every fixture in this repo is laid out as `{slug}/alert.json`, so the file STEM is the
# constant "alert" and carries no information — the slug lives on the parent dir. A run id
# built from the stem is therefore the same string for every fixture, which also means it
# can never satisfy the eval's run-id convention (`evals/held_out.py:index_runs` matches a
# run dir to its fixture by slug). Fall back to the parent's name in that case.
_GENERIC_ALERT_STEMS = {"alert"}


def _alert_label(alert: Path) -> str:
    """The informative name for ``alert``: its stem, or its parent dir when the stem is
    the layout-generic ``alert`` (see ``_GENERIC_ALERT_STEMS``)."""
    return alert.parent.name if alert.stem in _GENERIC_ALERT_STEMS else alert.stem


def materialize_run_dir(alert: Path, run_id: str | None) -> tuple[Path, str]:
    """Materialize the run dir and mint the run's trust token — `(run_dir, salt)`.

    The pair is promised on the SUCCESS lane only: both guard lanes below exit the
    process outright, above the mint, so a caller unpacking the pair can never receive
    a half-built one.

    The salt is the per-run trust token `runtime/untrusted.wrap` interpolates into the
    quarantine delimiters around untrusted data-source output. It is minted here, in
    process, and returned to the caller — it is never written to the run dir, and no
    consumer reads one back off disk. It comes from `secrets`, NOT from anything an
    outsider can name: deriving it from `run_id` (`{utc_timestamp}-{alert_label}`) would
    hand every delimiter to anyone who can predict the run id.
    """
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    runs_base = resolve_runs_base()
    if run_id is None:
        ts = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{ts}-{_alert_label(alert)}"
    run_dir = runs_base / run_id
    if run_dir.exists():
        sys.exit(f"run dir already exists: {run_dir}")
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    shutil.copy(alert, RunPaths(run_dir).alert)
    salt = secrets.token_hex(8)
    # No ground-truth label is copied in. A fixture's `disposition` is an ANSWER KEY
    # and the run dir is inside the agent's readable workspace; the eval reads labels
    # from the fixture dir it already owns (`evals/held_out.py`), and the learning loop
    # never sees one at all. Contamination is prevented at the enqueue boundary
    # instead — see `enqueue_learning`.
    return run_dir, salt


def run_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    """The bash tool's subprocess environment. `bin/` goes first on PATH so the
    `defender-*` shims resolve by a single stable token regardless of cwd, venv
    path, or compound wrapping; the run-dir anchors the budget/tag accounting and
    the invlang corpus root (`DEFENDER_RUNS_BASE == run_dir.parent`).

    Every billable provider key (`providers.api_key_vars()` — `ANTHROPIC_API_KEY`,
    `FIREWORKS_API_KEY`, …) is stripped: the bash tool runs data-source shims, never
    LLM calls, so no billable key has any business in its environment (the PydanticAI
    engine authenticates in-process from `os.environ`, which this copy leaves
    untouched). Returns a fresh dict — never mutates `os.environ`.

    Carried no `state_root` since #558: the only consumer was the curator's forward-check
    subprocess, which pinned DEFENDER_LEARNING_STATE_DIR here to reach the real source-case
    bundle from a throwaway worktree. The check is an in-process tool now and reads the
    bundle straight off its deps, so there is no subprocess left to pin an env var for."""
    # Local import keeps this module engine-agnostic to import; providers' heavy
    # backends are lazy, so this pulls in no pydantic-ai.
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env["DEFENDER_DIR"] = str(defender_dir)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = str(run_dir.parent)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    return env


def visualize(run_dir: Path) -> None:
    # visualize_run.py renders the judge + runtime pages AND mirrors them into
    # defender/run-visualizations/<run_id>/ (so reviews aren't gated on /tmp
    # surviving). Pre-learn the judge page renders empty (no judge artifacts yet);
    # the off-process learn worker re-renders + re-mirrors the same way once they
    # exist, so the runtime view is the only useful part of this pass.
    proc = subprocess.run(
        [sys.executable, str(VISUALIZE_SCRIPT), str(run_dir)],
        capture_output=True, text=True, encoding="utf-8"
    )
    sys.stderr.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(f"[run.py] visualize_run failed: {proc.stderr}")


def cross_check_tables(run_dir: Path) -> None:
    """Loud structural-integrity check on the two live tables.

    Restores the signal the deleted projection-failure halt used to provide:
    cross-check the leads/queries tables against the `:L` row ids in
    investigation.md. Orphan query rows or a lead the narration forgot are a
    WARN — a structurally degraded run that would otherwise flow silently into
    the oracle/judge; leads with no queries are an informational MONITOR note.
    Never raises — a diagnostic must not abort the post-steps.
    """
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
    """Whether ``alert`` lives under the labeled held-out eval fixture set.

    A PATH check, deliberately — not a label read. It knows where the eval set lives
    and nothing about its schema, so no answer key is opened and no ground-truth
    vocabulary enters the runtime. Containment alone decides, so a fixture whose label
    is missing or malformed is still refused.

    Both sides are resolved before comparing, so a symlink or ``..`` cannot walk out of
    the set and present a held-out alert as an ordinary one.

    Only usable where the FIXTURE path is still in hand — i.e. at the ``run.py`` boundary.
    Once a run dir exists it holds a *copy* at a path that says nothing about its origin;
    ``is_held_out_alert_copy`` is the net for that side.
    """
    try:
        alert.resolve().relative_to(fixtures_dir.resolve())
    except ValueError:
        return False
    return True


def held_out_alert_digests(fixtures_dir: Path = HELD_OUT_FIXTURES) -> set[str]:
    """sha256 of every ``{slug}/alert.json`` under the held-out set.

    Content, not labels: this opens the ALERTS — the same bytes the agent is handed as
    input — and never a ``ground_truth.yaml``. No answer key is read and no ground-truth
    vocabulary enters the caller, exactly as for ``is_held_out_fixture``; the only fact
    derived is "this input is a member of the eval set".
    """
    out: set[str] = set()
    if not fixtures_dir.is_dir():
        return out
    for child in sorted(fixtures_dir.iterdir()):
        alert = RunPaths(child).alert
        try:
            out.add(hashlib.sha256(alert.read_bytes()).hexdigest())
        except OSError:
            # A fixture with no readable alert.json contributes no digest; it also
            # cannot have produced a run, so there is nothing to fail closed about.
            continue
    return out


def is_held_out_alert_copy(alert: Path, fixtures_dir: Path = HELD_OUT_FIXTURES) -> bool:
    """Whether ``alert`` is byte-identical to some held-out fixture's ``alert.json``.

    The run-dir-side twin of ``is_held_out_fixture``. A run dir deliberately carries no
    provenance back to its fixture — no label, no pointer — so a consumer holding only a
    run dir cannot ask a PATH question. It can still ask an IDENTITY one: the alert was
    copied verbatim by ``materialize_run_dir``, so the digest is the surviving link.

    This is what lets the direct LEARN entrypoint (``loop.py <run_dir>``, which never sees
    the fixture path that ``enqueue_learning`` checks) refuse a held-out case too.
    """
    try:
        digest = hashlib.sha256(alert.read_bytes()).hexdigest()
    except OSError:
        return False
    return digest in held_out_alert_digests(fixtures_dir)


def enqueue_learning(run_dir: Path, alert: Path, *, truncated_by: str | None = None) -> bool:
    """Hand the finished run to the off-process LEARN worker by dropping a
    learn-queue marker. The runtime holds SIEM creds; learning is SIEM-free and
    runs in a separate process (loop.py --learn-drain), so the investigation's
    exit no longer waits on — or is rolled back by — the learning chain.

    Held-out fixture runs are REFUSED here. Scoring a run whose findings already
    taught the corpus is measuring the model on its own training data, so the eval
    path launches with ``--no-learn``; this is the net for when someone forgets, or
    runs a held-out alert by hand to debug it. It fails closed: the check is on the
    input path, so it cannot be defeated by a malformed or missing label file.

    A run the budget TRUNCATED (``truncated_by`` set — #631, D8) is REFUSED too: the
    runtime OWNS this check rather than relying on downstream report.md validation, so a
    weakened validator never lets the loop train on a truncated investigation. Compared
    with ``is not None`` (never a falsy-swallow) so "no mark" and "a mark I could not
    read" are not conflated — that shape would suppress learning for every run.

    Returns whether the run was enqueued.
    """
    if truncated_by is not None:
        print(
            f"[run.py] run was truncated (truncated_by={truncated_by!r}) — NOT enqueuing "
            "for learning (a truncated investigation must not train the corpus)",
            file=sys.stderr,
        )
        return False
    if is_held_out_fixture(alert):
        print(
            f"[run.py] {alert.parent.name}/{alert.name} is a held-out eval fixture — NOT "
            "enqueuing for learning (its findings must never feed a corpus it is scored "
            "against)",
            file=sys.stderr,
        )
        return False
    from defender.learning import loop as _loop
    from defender.learning.core.config import REPO_ROOT as _LEARN_REPO_ROOT
    from defender.learning.core.config import LoopPaths, _env_state_dir

    # Resolve the queue layout at CALL time from the live environment, not the import-
    # frozen `DEFAULT_PATHS`: a run that set `DEFENDER_LEARNING_STATE_DIR` after this
    # module imported must drop its marker under THAT state root (and a test pointing it
    # into a tmp dir must not pollute the in-repo default).
    paths = LoopPaths(repo_root=_LEARN_REPO_ROOT, state_dir=_env_state_dir())
    _loop.enqueue_for_learning(run_dir, paths)
    return True
