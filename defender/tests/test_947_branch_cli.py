"""#947 — the family launcher's one refusal that is not recoverable later.

`learning/branch/cli.py` is what actually runs an episode: it parses the worlds, primes the
capture, and drives each sibling. Almost everything it can get wrong fails loudly on the spot.
One thing does not.

`open_source_store` derives the source run's `runs_base` as `run_dir.parent` — the same
derivation `driver._default_store_factory` made when the store was written — and then checks it
against the path the writer recorded in the run's case pointer. So a source run parked anywhere
but DIRECTLY under the runs base resolves to a database that was never its own: `open_store`
creates-if-missing, so the handle is live and empty, and the failure surfaces later as
`main_session_id` finding no root session, naming neither the run dir nor the launcher.

Refused at the launcher, where the operator's own argument is still in hand.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def cli_mod():
    """`defender.learning.branch.cli` — imported per test, so a missing target is one failure
    per test rather than one collection error for the file."""
    return importlib.import_module("defender.learning.branch.cli")


@pytest.fixture
def runs_base(tmp_path, monkeypatch):
    """The runs base this process resolves, through the env var that anchors it.

    `setenv`, never `setattr`: the environment IS the seam `resolve_runs_base` reads, and the
    launcher has to consult it at call time rather than at import — a module-level capture would
    make the refusal depend on which order the test files were collected in.
    """
    base = tmp_path / "defender-runs"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(base))
    return base


@pytest.mark.parametrize("where", ["nested", "elsewhere", "the-base-itself"])
def test_a_source_run_parked_off_the_runs_base_is_refused_at_the_launcher(
        tmp_path, runs_base, where):
    """    A source run dir that does not sit directly under the runs base exits rather than
    branching.

    Each shape derives a `runs_base` one level off from the one the source run was written
    under, and each therefore resolves to a well-formed path holding no database at all. That is
    the worst kind of wrong input here: it does not fail, it succeeds against nothing, and the
    fork then inherits an empty lineage while every message downstream names the store rather
    than the argument that chose it.

    `SystemExit`, because this is an operator's own command line — the launcher's failure mode
    is an exit with a message, not a traceback out of a library frame."""
    source = {
        "nested": runs_base / "batch" / "run-source",
        "elsewhere": tmp_path / "somewhere-else" / "run-source",
        "the-base-itself": runs_base,
    }[where]
    source.mkdir(parents=True, exist_ok=True)

    with pytest.raises(SystemExit):
        cli_mod().refuse_distant_source(Path(source))


def test_a_run_directly_under_the_runs_base_is_accepted(tmp_path, runs_base):
    """    The positive control: the ordinary run dir — `<runs base>/<run id>` — is admitted.

    Without it the refusal above is satisfied by a launcher that refuses every source, which
    would be a batch that can never be run at all."""
    source = runs_base / "20260525T153045Z-canary"
    source.mkdir(parents=True, exist_ok=True)

    cli_mod().refuse_distant_source(Path(source))
