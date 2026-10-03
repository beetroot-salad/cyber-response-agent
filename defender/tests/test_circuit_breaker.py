"""Circuit-breaker exit-code taxonomy + the usage-error structured signal.

The breaker counts only genuine infra failures (exit 2 / 124). A usage error —
the agent passing a bad flag / unknown subcommand — must NOT count: exit 64 is
reserved for it, keeping the agent's CLI typos out of the connectivity bucket.
This replaces the old, fragile stderr-phrase heuristic (#301). No adapter has a
CLI any more (#1107 deleted the last one), so nothing mints 64 itself.
"""
from __future__ import annotations

import pytest

from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters import ticket_adapter
from defender.runtime import circuit_breaker as cb


def test_usage_exit_code_is_reserved():
    assert transport.USAGE_EXIT_CODE == 64


@pytest.mark.parametrize(("exit_code", "counts"), [
    (0, False),
    (1, False),
    (2, True),
    (64, False),
    (124, True),
])
def test_is_infra_failure_keys_on_exit_code_only(exit_code, counts):
    assert cb.is_infra_failure(exit_code) is counts


def test_argparse_heuristic_is_gone():
    assert not hasattr(cb, "_ARGPARSE_USAGE_RE")


def test_no_adapter_has_a_cli_left_to_mistype():
    """The ticket adapter's CLI is gone (#1107): there is no argv an agent can mistype, so no
    adapter exits 64 and the parser class that minted it no longer exists."""
    for name in ("build_parser", "main", "_cli_context"):  # lint-stale-ref: ok — asserts these are gone
        assert not hasattr(ticket_adapter, name), f"ticket_adapter still has `{name}`"
    assert not hasattr(transport, "AdapterArgumentParser")
    assert not cb.is_infra_failure(transport.USAGE_EXIT_CODE)


def test_usage_error_does_not_trip_breaker(tmp_path):
    cb.record_outcome(tmp_path, "elastic", 64)
    cb.record_outcome(tmp_path, "elastic", 64)
    assert not cb.is_tripped(tmp_path, "elastic")
    assert not (tmp_path / "circuit_breaker.json").exists()


def test_two_infra_failures_trip_breaker(tmp_path):
    cb.record_outcome(tmp_path, "elastic", 2)
    cb.record_outcome(tmp_path, "elastic", 2)
    assert cb.is_tripped(tmp_path, "elastic")
