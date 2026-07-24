"""The shared ticket answer-key screen — the invariants both consumers depend on.

``runtime/query_tool.py`` (gather) and ``learning/pipeline/judge/closed_ticket_tool.py`` (the
benign judge) now route their ticket screens through one protocol. These tests pin the parts
that are only meaningful ACROSS the two — the exit-code taxonomy and the self-case identity —
so a change made for one consumer cannot silently diverge the other.
"""
from __future__ import annotations

from types import SimpleNamespace

from defender.runtime.circuit_breaker import INFRA_EXIT_CODES, error_class_for_exit
from defender.runtime.query_tool import DEFAULT_FAULT_EXIT
from defender.runtime.ticket_screen import (
    MALFORMED_EXIT,
    POLICY_REFUSAL_EXIT,
    screen_get,
    screen_list,
    self_case_key,
)
from defender.scripts.adapters.faults import AdapterFault

SELF = "20260723T120000Z-self-case-682"


def _withhold_self(ticket: dict) -> str | None:
    return "withheld" if ticket.get("key") == SELF else None


def test_policy_refusal_never_feeds_the_breaker():
    """A run that legitimately brushes its own case must not trip the ticket breaker: the
    policy code stays outside the infra set, so `record_outcome` ignores it."""
    assert POLICY_REFUSAL_EXIT not in INFRA_EXIT_CODES
    assert error_class_for_exit(POLICY_REFUSAL_EXIT) == "agent-fixable"


def test_policy_refusal_is_distinguishable_from_a_genuine_query_error():
    """The audit trail must tell 'withheld the current case' from 'no such ticket'. The
    adapter's generic business fault (a 404 / non-closed refusal) files exit 1; a policy
    withhold must not collide with it."""
    assert AdapterFault.exit_code != POLICY_REFUSAL_EXIT
    assert POLICY_REFUSAL_EXIT != 0


def test_malformed_envelope_is_infra_and_matches_the_query_tool():
    """A store answering an undocumented shape is broken infra, not an agent-fixable mistake,
    and it classifies identically to the query tool's own adapter-fault code."""
    assert MALFORMED_EXIT == DEFAULT_FAULT_EXIT
    assert error_class_for_exit(MALFORMED_EXIT) == "infra"


def test_self_case_key_is_the_deps_field_not_the_run_dir_basename():
    """The one definition of the case under work. Both consumers read `deps.run_id`; deriving
    it from `run_dir.name` instead would re-split the two screens the moment run-dir naming is
    decoupled from the run id."""
    deps = SimpleNamespace(run_id=SELF, run_dir="/tmp/defender-runs/some-other-name")
    assert self_case_key(deps) == SELF


def test_screen_list_restates_total_to_what_survived():
    """The count must never advertise records the screen removed — a stale `total` beside a
    filtered list misdescribes the envelope to the model."""
    payload = {
        "tickets": [
            {"key": SELF, "summary": "the case itself"},
            {"key": "SOC-1", "summary": "a sibling"},
            "not-a-ticket-object",
        ],
        "total": 3,
        "source": "ticket-store",
    }
    screened, exit_code, detail = screen_list(
        payload, keep=lambda t: t.get("key") != SELF,
    )

    assert (exit_code, detail) == (0, "")
    assert [t["key"] for t in screened["tickets"]] == ["SOC-1"]
    assert screened["total"] == 1
    assert screened["source"] == "ticket-store", "unrelated envelope fields survive"


def test_screen_list_rejects_a_non_envelope_response():
    """`transport.http_get` is typed `dict | list`; the ticket store's contract is the object
    envelope. A bare array is malformed, never guessed at as the ticket list."""
    for payload in ([{"key": "SOC-1"}], {"tickets": "not-a-list"}, None):
        _, exit_code, detail = screen_list(payload, keep=lambda t: True)
        assert exit_code == MALFORMED_EXIT
        assert "malformed ticket store response" in detail


def test_screen_get_withholds_on_the_predicate_and_serves_otherwise():
    other = {"key": "SOC-1", "summary": "a sibling"}
    assert screen_get(other, withhold=_withhold_self) == (other, 0, "")

    payload, exit_code, detail = screen_get({"key": SELF}, withhold=_withhold_self)
    assert (payload, exit_code, detail) == (None, POLICY_REFUSAL_EXIT, "withheld")


def test_screen_get_require_key_is_opt_in():
    """Gather screens by record identity, so a keyless body cannot be proved distinct from the
    current case and is malformed. The judge screens the serialized whole payload, so it needs
    no key — the same helper must serve both."""
    keyless = {"summary": "no identity"}

    _, exit_code, _ = screen_get(keyless, withhold=_withhold_self, require_key=True)
    assert exit_code == MALFORMED_EXIT

    assert screen_get(keyless, withhold=_withhold_self) == (keyless, 0, "")

    _, exit_code, _ = screen_get(["not", "an", "object"], withhold=_withhold_self)
    assert exit_code == MALFORMED_EXIT
