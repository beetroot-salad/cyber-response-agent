"""A non-numeric loop threshold env var must fail loud as the contracted exit 2,
not crash the author-drain stage with an uncaught ValueError (issue #435).

The drain wake gates (`_has_curator_work` / `_has_lead_author_work`) read their
trigger thresholds with `config.env_int`, which raises `FatalConfigError` (the
layer-neutral misconfig condition from `defender._env`, a `ValueError` subclass) on
a bad value. `FatalConfigError` is *enrolled alongside* `StageAbort` at the drain
catch sites — not a `StageAbort` subclass, since the exit-2 *response* is
learning-only while the *condition* is shared with runtime/. The gate runs at the
top of `_run_worktree_batch`, before any git/PR work, so the `FatalConfigError`
propagates out of the drain to `_run_stage`, which maps it to rc 2.
"""
from __future__ import annotations

import json

import pytest

from defender.learning.core import config  # type: ignore[import-not-found]
from defender.learning.core import orchestrate  # type: ignore[import-not-found]
from defender.learning.core.config import (  # type: ignore[import-not-found]
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    LoopPaths,
)
from defender.learning.leads import lead_author  # type: ignore[import-not-found]


# --- env_int -----------------------------------------------------------------

def test_env_int_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv("LEARNING_AUTHOR_THRESHOLD", raising=False)
    assert config.env_int("LEARNING_AUTHOR_THRESHOLD", 5) == 5


def test_env_int_parses_a_numeric_override(monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "12")
    assert config.env_int("LEARNING_AUTHOR_THRESHOLD", 5) == 12


@pytest.mark.parametrize("bad", ["high", "", "5o"])
def test_env_int_raises_fatal_config_on_non_numeric(monkeypatch, bad):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", bad)
    with pytest.raises(FatalConfigError, match="LEARNING_AUTHOR_THRESHOLD must be an integer"):
        config.env_int("LEARNING_AUTHOR_THRESHOLD", 5)


# --- wake gates raise (not crash) on a bad threshold -------------------------
# The gate propagates the FatalConfigError that env_int raises; it is enrolled
# alongside StageAbort at the drain catch sites, so it still maps to rc 2 (the
# end-to-end `_run_stage(...) == 2` assertions below pin that).

def test_has_curator_work_raises_on_bad_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "high")
    with pytest.raises(FatalConfigError):
        orchestrate._has_curator_work(LoopPaths(repo_root=tmp_path))


def test_has_lead_author_work_raises_on_bad_pitfalls_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "high")
    with pytest.raises(FatalConfigError):
        orchestrate._has_lead_author_work(LoopPaths(repo_root=tmp_path))


def test_has_lead_author_work_raises_on_bad_pitfalls_threshold_with_marker_queued(
    tmp_path, monkeypatch
):
    """The markers-present path: a queued run marker must NOT let a non-numeric
    LEARNING_PITFALLS_THRESHOLD slip past the gate. If the gate short-circuited to True
    on the marker before reading the threshold, the FatalConfigError would only surface
    later inside run_pitfalls, where _drain_pitfalls' broad `except Exception` swallows it
    (exit 0, not the contracted exit 2). The gate reads the threshold up front (#435)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "high")
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)
    with pytest.raises(FatalConfigError, match="LEARNING_PITFALLS_THRESHOLD"):
        orchestrate._has_lead_author_work(paths)


def test_lead_author_max_retries_bad_value_raises_fatal_config(tmp_path, monkeypatch):
    """LEAD_AUTHOR_MAX_RETRIES is read inside the lead-author drain (past the wake gate,
    before the per-marker loop). A non-numeric value must fail loud as FatalConfigError —
    enrolled alongside StageAbort so _run_stage maps it to the contracted exit 2 — not a
    raw ValueError that escapes the catch as an uncontracted exit-1 traceback (#435)."""
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "high")
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)
    with pytest.raises(FatalConfigError, match="LEAD_AUTHOR_MAX_RETRIES"):
        orchestrate._drain_lead_author_markers(paths, lambda _p, _rd: None)


# --- the stage contract: bad threshold -> exit 2, never a traceback ----------

def test_author_drain_bad_threshold_is_fatal_two(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "high")
    paths = LoopPaths(repo_root=tmp_path)
    assert orchestrate._run_stage(lambda: orchestrate.author_drain(paths=paths)) == 2


def test_lead_author_drain_bad_threshold_is_fatal_two(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "high")
    paths = LoopPaths(repo_root=tmp_path)
    assert orchestrate._run_stage(lambda: orchestrate.lead_author_drain(paths=paths)) == 2


# --- happy path: a valid threshold + empty queues still short-circuits to 0 ---

def test_drains_skip_cleanly_with_valid_threshold_and_empty_queues(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "5")
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "5")
    # The author_drain gate also reads the per-direction observation thresholds; clear
    # any ambient non-numeric override so this happy-path assertion can't fail spuriously.
    for sibling in (
        "LEARNING_AUTHOR_ACTOR_THRESHOLD",
        "LEARNING_AUTHOR_ENV_THRESHOLD",
        "LEARNING_AUTHOR_ACTOR_ENV_THRESHOLD",
    ):
        monkeypatch.delenv(sibling, raising=False)
    paths = LoopPaths(repo_root=tmp_path)
    # Empty queues + a parseable threshold -> the gate returns False and the drain
    # skips the worktree without touching git.
    assert orchestrate._run_stage(lambda: orchestrate.author_drain(paths=paths)) == 0
    assert orchestrate._run_stage(lambda: orchestrate.lead_author_drain(paths=paths)) == 0


# --- #438 / #443: StageAbort punches through the per-marker quarantine guards ---
#
# The lift threshold is read DEEP in the per-marker flow (run() -> _prepare_handoffs
# -> _lift_threshold), under _drain_lead_author_markers' broad `except Exception`.
# Pre-#438 a non-numeric LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD quarantined a healthy
# marker as `lead-author-error` (work lost, cause mislabeled, no exit 2). This is the
# one fatal-config path #437's wake-gate reads did NOT cover.


def test_fatal_config_error_is_enrolled_not_subclassed_and_disjoint_from_run_unprocessable():
    """The cause/response split: FatalConfigError is the layer-neutral *condition*
    (a ValueError subclass shared with runtime/ via defender._env), NOT a StageAbort —
    the exit-2 *response* is learning-only, so the type is enrolled alongside StageAbort
    at the catch sites rather than inheriting from it. It stays disjoint from
    RunUnprocessable, so a systemic misconfig can never be mis-read as a per-run
    'quarantine this item' (or vice versa). The exit-2 mapping is pinned behaviorally by
    the `_run_stage(...) == 2` tests, not by a subclass relationship."""
    from defender._env import FatalConfigError as SharedFatalConfigError

    assert FatalConfigError is SharedFatalConfigError  # config re-exports the shared type
    assert issubclass(FatalConfigError, ValueError)
    assert not issubclass(FatalConfigError, StageAbort)
    assert not issubclass(FatalConfigError, RunUnprocessable)
    assert not issubclass(RunUnprocessable, StageAbort)


def test_every_stage_abort_except_clause_in_orchestrate_also_names_fatal_config():
    """The structural guard for #468's cause/response split. FatalConfigError is no
    longer a StageAbort *subclass*, so the exit-2 contract rests on it being NAMED
    alongside StageAbort at every systemic catch site rather than inherited — the type
    system no longer enforces it, so this test does.

    It parses orchestrate.py's AST and asserts every literal ``except`` clause that
    catches ``StageAbort`` also catches ``FatalConfigError``. The risk this defends: the
    drain-design contract is "route the swallow site through _run_or_dead_letter and be
    systemic-fault-safe for free; a hand-rolled ``except`` is the odd-one-out" — and a
    hand-rolled ``except StageAbort: raise`` in a future drain would silently DROP a
    FatalConfigError to per-marker quarantine (exit 0) instead of the contracted exit 2
    (the #438 class of bug). Such a clause fails here.

    Note the two existing sites are covered without overlap: _run_stage's literal
    ``except (StageAbort, FatalConfigError)`` is checked here; _run_or_dead_letter's
    ``except reraise:`` indirection (reraise = (StageAbort, FatalConfigError, *propagate))
    is opaque to the AST and is pinned behaviorally by
    test_run_or_dead_letter_reraises_systemic_faults. A future maintainer who genuinely
    wants a StageAbort-only catch (not a known need) must update this test deliberately."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(orchestrate.__file__).read_text())

    def _caught_names(node: ast.expr | None) -> set[str]:
        """The exception types a handler names: a bare Name, or a tuple of Names.
        An ``except <var>:`` indirection yields just the var name (e.g. 'reraise')."""
        if node is None:
            return set()
        elts = node.elts if isinstance(node, ast.Tuple) else [node]
        return {e.id for e in elts if isinstance(e, ast.Name)}

    orphans = [
        handler.lineno
        for handler in ast.walk(tree)
        if isinstance(handler, ast.ExceptHandler)
        and "StageAbort" in _caught_names(handler.type)
        and "FatalConfigError" not in _caught_names(handler.type)
    ]
    assert not orphans, (
        f"orchestrate.py has `except StageAbort` clause(s) at line(s) {orphans} that "
        "do not also name FatalConfigError. Since #468 FatalConfigError is enrolled "
        "(not subclassed), so it must ride along at every systemic catch site or a "
        "config misconfig is silently dead-lettered instead of mapped to exit 2."
    )


def test_env_int_raises_fatal_config_error_on_non_numeric(monkeypatch):
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "high")
    with pytest.raises(FatalConfigError, match="LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD"):
        lead_author._lift_threshold()


def test_lead_author_marker_drain_reraises_fatal_lift_threshold(tmp_path, monkeypatch):
    """A non-numeric lift threshold surfaces inside the per-marker run as a
    FatalConfigError. _drain_lead_author_markers must RE-RAISE it (systemic) rather than
    quarantine the marker (the broad-guard disposition for per-item failures)."""
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "high")
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)

    # Stand in for the deep read: the real _lift_threshold() (-> env_int) raises the
    # FatalConfigError exactly as run() -> _prepare_handoffs would.
    def _run_lead_author(_paths, _run_dir):
        lead_author._lift_threshold()

    with pytest.raises(FatalConfigError):
        orchestrate._drain_lead_author_markers(paths, _run_lead_author)

    # The marker must NOT have been quarantined — it stays queued to retry once the
    # operator fixes the env (and the drain failed loud instead of losing the work).
    failed_dir = paths.author_queue_dir / "failed"
    assert not (failed_dir / f"{run_dir.name}.json").exists()
    assert (paths.author_queue_dir / f"{run_dir.name}.json").exists()


def test_drain_pitfalls_reraises_fatal_config_error(tmp_path):
    """Defense-in-depth (no current trigger): _drain_pitfalls' broad guard swallows a
    curation hiccup, but a FatalConfigError must propagate to exit 2, not be swallowed."""
    paths = LoopPaths(repo_root=tmp_path)

    def _run_pitfalls(_paths):
        raise FatalConfigError("systemic")

    with pytest.raises(FatalConfigError):
        orchestrate._drain_pitfalls(paths, _run_pitfalls)


# --- #442: the drain CALL SITES wire the primitive correctly -----------------
#
# _run_or_dead_letter's own unit tests (below) pin the primitive's contract in isolation;
# these pin that _drain_lead_author_markers / _drain_pitfalls actually route through it —
# the success unlink, the dead-letter quarantine, the `propagate=(_LeadAuthorRetry,)` retry
# hand-off, and the pitfalls swallow. A primitive that is correct in isolation can still be
# mis-wired at the call site (a dropped `propagate=` would turn every transient into a
# silent quarantine), and the success path is the PR's core change (`else:`/`if drained:`).


def test_lead_author_drain_unlinks_marker_on_success(tmp_path, monkeypatch):
    """A clean lead-author run drains the marker: success makes `if drained:` unlink it, so
    it is neither left queued (re-authored every tick) nor quarantined."""
    monkeypatch.delenv("LEAD_AUTHOR_MAX_RETRIES", raising=False)
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-ok"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)

    orchestrate._drain_lead_author_markers(paths, lambda _p, _rd: None)

    assert not (paths.author_queue_dir / f"{run_dir.name}.json").exists()
    assert not (paths.author_queue_dir / "failed" / f"{run_dir.name}.json").exists()


def test_lead_author_drain_quarantines_a_plain_failure(tmp_path, monkeypatch):
    """A plain (non-systemic) failure is dead-lettered: the marker moves to failed/ with a
    lead-author-error reason and is NOT unlinked as if it had succeeded."""
    monkeypatch.delenv("LEAD_AUTHOR_MAX_RETRIES", raising=False)
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-boom"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)

    def _run_lead_author(_paths, _run_dir):
        raise RuntimeError("poison run dir")

    orchestrate._drain_lead_author_markers(paths, _run_lead_author)

    assert not (paths.author_queue_dir / f"{run_dir.name}.json").exists()
    failed = paths.author_queue_dir / "failed" / f"{run_dir.name}.json"
    assert failed.exists()
    assert "lead-author-error" in json.loads(failed.read_text())["failed"]


def test_lead_author_drain_requeues_a_transient_with_bumped_attempts(tmp_path, monkeypatch):
    """A _LeadAuthorRetry must reach the drain's retry handler via `propagate=`, NOT the
    dead-letter branch: the marker stays queued with a bumped attempt count. This is the
    regression guard for the `propagate=(_LeadAuthorRetry,)` wiring — drop that argument and
    the transient is silently quarantined instead of retried."""
    monkeypatch.delenv("LEAD_AUTHOR_MAX_RETRIES", raising=False)
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-transient"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)

    def _run_lead_author(_paths, _run_dir):
        raise orchestrate._LeadAuthorRetry("rc=None transient")

    orchestrate._drain_lead_author_markers(paths, _run_lead_author)

    marker = paths.author_queue_dir / f"{run_dir.name}.json"
    assert marker.exists()  # left queued for retry, not quarantined
    assert not (paths.author_queue_dir / "failed" / f"{run_dir.name}.json").exists()
    assert json.loads(marker.read_text())["attempts"] == 1


def test_drain_pitfalls_swallows_a_plain_curation_error(tmp_path):
    """The dead-letter branch of _drain_pitfalls: a plain curation hiccup must not wedge the
    drain — it is logged and swallowed, so the call returns normally (the systemic StageAbort
    path is the sibling reraise test)."""
    paths = LoopPaths(repo_root=tmp_path)

    def _run_pitfalls(_paths):
        raise RuntimeError("curation hiccup")

    orchestrate._drain_pitfalls(paths, _run_pitfalls)  # must not raise


# --- #442: the dead-letter contract is enforced by one primitive, not per-site discipline ---
#
# _run_or_dead_letter is the single place "re-raise StageAbort, dead-letter the rest"
# lives, so the invariant has one regression guard instead of one hand-copied clause per
# swallow site (the #438 footgun: a new drain that forgets the re-raise silently regresses).


def test_run_or_dead_letter_returns_true_on_success():
    """A clean run reports success (so the caller can unlink the marker) and never
    invokes the dead-letter callback."""
    calls: list[Exception] = []
    ok = orchestrate._run_or_dead_letter(lambda: None, calls.append)
    assert ok is True
    assert calls == []


def test_run_or_dead_letter_dead_letters_a_plain_exception():
    """A per-item failure is dead-lettered: the callback fires with the exception and the
    helper reports failure (no re-raise) so the serial drain keeps going."""
    calls: list[Exception] = []

    def _boom():
        raise RuntimeError("poison item")

    ok = orchestrate._run_or_dead_letter(_boom, calls.append)
    assert ok is False
    assert len(calls) == 1
    assert isinstance(calls[0], RuntimeError)


def test_run_or_dead_letter_dead_letters_a_run_unprocessable():
    """A RunUnprocessable is a per-run *data* failure (the ~30 validate.py sites): it must
    dead-letter like any other Exception — only the StageAbort family is special."""
    calls: list[Exception] = []

    def _boom():
        raise RunUnprocessable("malformed report.md")

    ok = orchestrate._run_or_dead_letter(_boom, calls.append)
    assert ok is False
    assert len(calls) == 1
    assert isinstance(calls[0], RunUnprocessable)


def test_run_or_dead_letter_reraises_systemic_faults():
    """The systemic family is NEVER dead-lettered — it re-raises past the guard so it
    reaches _run_stage as the contracted exit 2. The callback must not fire. Both a bare
    StageAbort (the learning base — catching it covers any future learning-internal
    systemic type for free) and the enrolled FatalConfigError (the shared misconfig
    condition, named explicitly in the reraise set since it is not a StageAbort) must
    escape — #443/#445."""
    for exc in (StageAbort("systemic fault"), FatalConfigError("non-numeric threshold")):
        calls: list[Exception] = []

        def _boom(exc=exc):
            raise exc

        with pytest.raises((StageAbort, FatalConfigError)):
            orchestrate._run_or_dead_letter(_boom, calls.append)
        assert calls == []


def test_run_or_dead_letter_propagates_declared_control_flow():
    """A type in `propagate` is drain-specific control flow (e.g. _LeadAuthorRetry's
    bounded retry), not a dead-letter: it escapes the guard for the caller to handle,
    and the callback must not fire."""
    calls: list[Exception] = []

    def _boom():
        raise orchestrate._LeadAuthorRetry("transient")

    with pytest.raises(orchestrate._LeadAuthorRetry):
        orchestrate._run_or_dead_letter(
            _boom, calls.append, propagate=(orchestrate._LeadAuthorRetry,)
        )
    assert calls == []


class _StubBranch:
    """A git-free AuthorBranch stand-in for the full-stage exit-2 assertion. do_work
    raises before finish_batch, so only these three methods are exercised; start_batch
    returns a .git-less dir, on which _discard_worktree_changes no-ops."""

    branch_prefix = "lead-author/"

    def __init__(self, wt: object) -> None:
        self._wt = wt

    def open_pr_exists(self) -> bool:
        return False

    def start_batch(self, batch_id: str):
        return self._wt

    def cleanup(self, wt) -> None:
        pass


def test_lead_author_drain_bad_lift_threshold_is_fatal_two(tmp_path, monkeypatch):
    """End-to-end: a queued marker + a bad lift threshold drives the whole
    lead_author_drain stage to the contracted exit 2 (not a quarantine, not exit 0)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "5")  # valid: wake gate must pass
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "high")  # the fatal one
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)

    wt = tmp_path / "wt"
    wt.mkdir()

    def _run_lead_author(_paths, _run_dir):
        lead_author._lift_threshold()

    rc = orchestrate._run_stage(
        lambda: orchestrate.lead_author_drain(
            paths=paths, run_lead_author=_run_lead_author, branch=_StubBranch(wt)
        )
    )
    assert rc == 2


# --- #443: the _run_stage disposition split (the structural guard) -----------
#
# StageAbort (systemic) -> exit 2 on every stage. RunUnprocessable (this run's data
# is bad) -> exit 2 ONLY on the direct single-run path (allow_run_error=True); on a
# drain it PROPAGATES, because a RunUnprocessable reaching a drain's boundary did not
# pass the per-item quarantine guard and is therefore a bug — it must fail loud (a
# traceback), not masquerade as a clean contracted exit 2.


def _raise(exc):
    """A zero-arg stage that raises ``exc`` (closure dodges lambda's no-raise limit)."""
    def _stage():
        raise exc
    return _stage


def test_run_stage_maps_stage_abort_to_exit_two():
    # Both modes: a systemic fault always aborts the stage.
    assert orchestrate._run_stage(_raise(StageAbort("systemic"))) == 2
    assert orchestrate._run_stage(_raise(FatalConfigError("bad cfg"))) == 2
    assert orchestrate._run_stage(
        _raise(StageAbort("systemic")), allow_run_error=True
    ) == 2


def test_run_stage_propagates_run_unprocessable_on_a_drain():
    """The guard: on a drain path (allow_run_error=False, the default) a leaked
    RunUnprocessable propagates uncaught rather than being mapped to a clean exit 2."""
    with pytest.raises(RunUnprocessable, match="bad run"):
        orchestrate._run_stage(_raise(RunUnprocessable("bad run")))


def test_run_stage_maps_run_unprocessable_to_exit_two_on_direct_run():
    """The direct single-run path (loop.py <run_dir>) has no queue to quarantine into,
    so a bad run maps to the contracted exit 2 — the behavior main() preserves."""
    assert orchestrate._run_stage(
        _raise(RunUnprocessable("bad run")), allow_run_error=True
    ) == 2


# main()'s argv -> allow_run_error routing is the load-bearing wiring of the #443 guard:
# the direct <run_dir> path must pass allow_run_error=True (bad run -> exit 2) and every
# drain must pass the default False (a leaked RunUnprocessable propagates). The
# _run_stage tests above pass the flag explicitly, so they can't catch a regression that
# routes the wrong flag to the wrong stage; these drive main() end to end to pin it.


def test_main_direct_run_maps_run_unprocessable_to_exit_two(tmp_path, monkeypatch):
    """`loop.py <run_dir>` wires allow_run_error=True, so a bad run's RunUnprocessable
    maps to the contracted exit 2 rather than an uncontracted exit-1 + traceback."""
    def boom(_run_dir):
        raise RunUnprocessable("bad run data")
    # main() is the CLI dispatch entrypoint; it resolves the module-global stage by argv,
    # so patching the global is the only seam for the wiring under test.
    monkeypatch.setattr(  # lint-monkeypatch: ok — main() CLI dispatch resolves stage by argv
        orchestrate, "run_one", boom
    )
    assert orchestrate.main(["loop.py", str(tmp_path)]) == 2


def test_main_drain_propagates_run_unprocessable(monkeypatch):
    """The drains wire the default allow_run_error=False, so a RunUnprocessable leaking
    to a drain's boundary (a bug that escaped the per-item quarantine guard) propagates
    uncaught rather than masquerading as a clean exit 2."""
    # Same CLI-dispatch seam: main() resolves the drain global by argv.
    monkeypatch.setattr(  # lint-monkeypatch: ok — main() CLI dispatch resolves drain by argv
        orchestrate, "learn_drain", _raise(RunUnprocessable("leaked"))
    )
    with pytest.raises(RunUnprocessable, match="leaked"):
        orchestrate.main(["loop.py", "--learn-drain"])


# --- GitError is a systemic fault (enrolled alongside StageAbort, #460) -------

def test_run_or_dead_letter_reraises_giterror_not_quarantine():
    """A ``GitError`` (a broken local-state git op) dooms the whole batch, so it must
    re-raise out of the dead-letter guard — never be quarantined as a per-marker failure."""
    from defender import _git  # type: ignore[import-not-found]

    dead_lettered: list[Exception] = []

    def boom():
        raise _git.GitError(["status"], 128, "not a git repository")

    with pytest.raises(_git.GitError):
        orchestrate._run_or_dead_letter(boom, dead_lettered.append)
    assert dead_lettered == []  # systemic, not dead-lettered


def test_run_stage_maps_giterror_to_exit_2():
    """At the stage boundary a ``GitError`` becomes the contracted FATAL exit 2."""
    from defender import _git  # type: ignore[import-not-found]

    def stage() -> int:
        raise _git.GitError(["commit"], 1, "pre-commit hook rejected")

    assert orchestrate._run_stage(stage) == 2
