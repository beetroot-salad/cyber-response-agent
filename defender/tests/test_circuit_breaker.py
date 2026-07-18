"""Circuit-breaker exit-code taxonomy + the usage-error structured signal.

The breaker counts only genuine infra failures (exit 2 / 124). A usage error —
the agent passing a bad flag / unknown subcommand — must NOT count: adapters
parse argv with `_stub_transport.AdapterArgumentParser`, which exits 64 for any
argparse error, keeping the agent's CLI typos out of the connectivity bucket.
This replaces the old, fragile stderr-phrase heuristic (#301).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[1]

# The workspace root is on sys.path via pytest's `pythonpath = [".."]`, so
# `defender.*` namespace imports resolve.
from defender.scripts.adapters import _stub_transport as transport  # noqa: E402
from defender.runtime import circuit_breaker as cb  # noqa: E402

# #611: six of the seven adapters lost their CLI — a data source is reached through the `query`
# tool now, so those adapters are VERBS registries with no `main()`/`build_parser()`. Only
# `ticket_adapter.py` keeps its argparse CLI (three subprocess consumers pin it), so the exit-64
# usage-error contract is asserted against the ONE surviving CLI. It fails fast at argparse on a
# bad invocation, before touching docker, so it runs with no environment.
_ADAPTERS = ["ticket_adapter.py"]
_ADAPTERS_DIR = _DEFENDER / "scripts" / "adapters"


def test_usage_exit_code_is_reserved():
    assert transport.USAGE_EXIT_CODE == 64


@pytest.mark.parametrize(("exit_code", "counts"), [
    (0, False),    # success
    (1, False),    # query error / not-found — agent's to reason about
    (2, True),     # connectivity / auth / config — the down-system signal
    (64, False),   # usage error (bad flag) — agent's CLI typo, must not trip
    (124, True),   # adapter timeout (synthesized by record_query.capture)
])
def test_is_infra_failure_keys_on_exit_code_only(exit_code, counts):
    assert cb.is_infra_failure(exit_code) is counts


def test_argparse_heuristic_is_gone():
    # The whole point of #301: no stderr-phrase sniffing remains.
    assert not hasattr(cb, "_ARGPARSE_USAGE_RE")


@pytest.mark.parametrize("adapter", _ADAPTERS)
@pytest.mark.parametrize("badargs", [["--no-such-flag"], ["bogus-subcommand"], []])
def test_adapter_usage_errors_exit_64(adapter, badargs):
    """A bad flag, unknown subcommand, or missing-required subcommand all exit 64
    (not argparse's default 2), so the breaker never counts them."""
    proc = subprocess.run(
        [sys.executable, str(_ADAPTERS_DIR / adapter), *badargs],
        capture_output=True, text=True,
    )
    assert proc.returncode == 64, f"{adapter} {badargs}: rc={proc.returncode}\n{proc.stderr}"
    assert not cb.is_infra_failure(proc.returncode)


def test_usage_error_does_not_trip_breaker(tmp_path):
    # Two usage errors in a row leave the breaker untripped (would trip at 2 if
    # they were miscounted as infra).
    cb.record_outcome(tmp_path, "elastic", 64)
    cb.record_outcome(tmp_path, "elastic", 64)
    assert not cb.is_tripped(tmp_path, "elastic")
    assert not (tmp_path / "circuit_breaker.json").exists()  # no-op path writes nothing


def test_two_infra_failures_trip_breaker(tmp_path):
    cb.record_outcome(tmp_path, "elastic", 2)
    cb.record_outcome(tmp_path, "elastic", 2)
    assert cb.is_tripped(tmp_path, "elastic")
