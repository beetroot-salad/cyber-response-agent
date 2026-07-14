"""Impl-time hardening for #611: a verb's ANNOTATIONS are part of its param contract.

`validate_params` checked param NAMES (unknown key, missing required) but not their TYPES, while
`query`'s `params` arrives as `dict[str, Any]` with no per-key JSON schema behind it — so a
model-supplied `limit="20"` sailed past the boundary and raised `TypeError` *inside* the verb
(`min("20", 20)`), where the capture's catch-all maps an unmapped fault to **exit 2** — the code
that means "the system is down".

That is the exit-64 invariant inverted. `circuit_breaker` reserves 2/124 for infra precisely so
"the agent's own CLI typos can't trip the breaker and hide a working system", and before #611
argparse's `type=` enforced it. In-process, `validate_params` is the only thing left that can:
two mistyped calls and a HEALTHY Elasticsearch is DOWN for the rest of the run (
`PER_SYSTEM_FAIL_LIMIT = 2`), five and the run aborts.

The quieter half needs no crash at all: `enabled="false"` is a TRUTHY string, so
`identity.list_users` would have queried the ENABLED users and confidently answered a question
nobody asked.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.verbs import (  # noqa: E402
    ModuleVerbRegistry,
    VerbContext,
    validate_params,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    FakeVerbs,
    VerbRecorder,
)
from defender.tests.e2e.test_query_tool_611 import (  # noqa: E402
    DONE,
    PAYLOAD,
    q,
    run_gather,
)

pytestmark = pytest.mark.e2e

ADAPTERS_DIR = DEFENDER / "scripts" / "adapters"


def clamping(rec: VerbRecorder) -> FakeVerbs:
    """A verb that uses its `int` param the way the REAL one does. `elastic.query` ends in
    `min(limit, RETURNED_DOC_CAP)` (`elastic_cli._build_search_body`), and `min("20", 20)` raises
    `TypeError` — an unmapped fault, which the capture files as exit 2 = infra. The fake carries
    that one line so the whole chain (boundary → verb → fault map → breaker) is exercised for
    real; a fake that merely accepts the string would prove only half the bug."""

    def query(ctx: VerbContext, *, native_query: str, limit: int = 10) -> list[dict]:
        rec.record("query", ctx, {"native_query": native_query, "limit": limit})
        return PAYLOAD[: min(limit, 20)]

    return FakeVerbs({"elastic": {"query": query}})


def typed(rec: VerbRecorder) -> FakeVerbs:
    """A registry whose verb declares one param of each kind the checker must tell apart."""

    def probe(
        ctx: VerbContext, *, native_query: str, limit: int = 10,
        enabled: bool | None = None, index: str | None = None,
        filters: dict[str, str] | None = None,
    ) -> list[dict]:
        rec.record("probe", ctx, {
            "native_query": native_query, "limit": limit,
            "enabled": enabled, "index": index, "filters": filters,
        })
        return PAYLOAD

    return FakeVerbs({"elastic": {"probe": probe}})


# ── the teeth: a mistyped param must never look like a broken system ─────────


def test_a_mistyped_param_is_a_usage_error_not_an_infra_failure(tmp_path):
    """A string where the verb declares `int` is the AGENT's mistake: exit 64, error_class
    agent-fixable, and the verb is never reached. Unvalidated it raised TypeError inside the
    verb and was recorded as exit 2 — "the system is down"."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=clamping(rec), turns=[
        q("elastic", "query", {"native_query": "FROM logs", "limit": "20"}), DONE,
    ], run_id="q611-mistyped")

    assert rec.calls == [], "a mistyped param reached the verb — the type check is not at the boundary"
    row = r.row()
    # Unvalidated: TypeError inside the verb → the catch-all's DEFAULT_FAULT_EXIT → exit 2,
    # error_class "infra" — the agent's own slip, filed as a broken data source.
    assert row["exit_code"] == 64, "a model type slip was not filed as a usage error"
    assert row["error_class"] == "agent-fixable"
    assert r.breaker.get("systems", {}) == {}, "a usage error counted against the circuit breaker"
    assert "limit" in r.gather_saw, "the rejection did not name the offending param"


def test_mistyped_params_cannot_trip_a_healthy_system(tmp_path):
    """PER_SYSTEM_FAIL_LIMIT is 2, so two mistyped calls were enough to mark a LIVE system down
    for the rest of the run. The third call — a well-formed one — must still reach the verb."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=clamping(rec), turns=[
        q("elastic", "query", {"native_query": "FROM logs", "limit": "20"}),
        q("elastic", "query", {"native_query": "FROM logs", "limit": "50"}),
        q("elastic", "query", {"native_query": "FROM logs", "limit": 5}),
        DONE,
    ], run_id="q611-nottripped")

    assert len(rec.calls) == 1, "the well-formed query never ran — the breaker tripped on typos"
    assert [row["exit_code"] for row in r.rows] == [64, 64, 0]
    assert not r.breaker.get("systems", {}).get("elastic", {}).get("tripped_at"), \
        "two of the agent's own type slips tripped the breaker on a healthy system"
    assert r.rows[-1]["payload_status"] == "ok", "the live system did not answer after the typos"


def test_a_truthy_string_cannot_pose_as_a_bool(tmp_path):
    """The silent-wrong half, and the one with no crash to notice: `"false"` is TRUTHY, so an
    unchecked bool param inverts the filter and the agent gets a confident wrong answer."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=typed(rec), turns=[
        q("elastic", "probe", {"native_query": "FROM logs", "enabled": "false"}), DONE,
    ], run_id="q611-strbool")

    assert rec.calls == [], "a string reached a bool param — the filter would have inverted"
    assert r.row()["exit_code"] == 64


def test_a_bool_is_not_an_int(tmp_path):
    """`bool` subclasses `int`, so an unguarded isinstance admits `limit=True` — which reaches
    the arithmetic clamp as a 1."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=typed(rec), turns=[
        q("elastic", "probe", {"native_query": "FROM logs", "limit": True}), DONE,
    ], run_id="q611-boolint")

    assert rec.calls == [], "a bool was admitted as an int"
    assert r.row()["exit_code"] == 64


# ── the positive control: the check is selective, not a blanket deny ─────────


def test_well_typed_params_including_optionals_and_containers_are_admitted(tmp_path):
    """The check must not reject what the verb actually declares: `None` for `X | None`, a dict
    for `dict[str, str]`, an int for `int`. A validator that denies the happy path is worse than
    the bug it fixes."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=typed(rec), turns=[
        q("elastic", "probe", {
            "native_query": "FROM logs", "limit": 5, "enabled": True,
            "index": None, "filters": {"host": "web-1"},
        }), DONE,
    ], run_id="q611-welltyped")

    assert len(rec.calls) == 1, "a well-typed call was rejected"
    assert rec.calls[0].params["filters"] == {"host": "web-1"}
    assert r.row()["exit_code"] == 0


# ── the same contract, against the REAL adapter signatures ───────────────────


@pytest.mark.parametrize(("system", "verb", "params", "why"), [
    ("elastic", "query", {"native_query": "FROM logs", "limit": "20"}, "limit"),
    ("identity", "list-users", {"enabled": "false"}, "enabled"),
    ("ticket", "list-tickets", {"require_closed": "true"}, "require_closed"),
])
def test_the_real_registry_rejects_a_mistyped_param(system, verb, params, why):
    """The shipped adapters, not a fake: each of these signatures has a non-`str` param a model
    can plausibly send as a string, and each was admitted before."""
    fn = ModuleVerbRegistry(ADAPTERS_DIR).verbs(system)[verb]
    reason = validate_params(fn, params)
    assert reason is not None, f"{system}.{verb} admitted a mistyped {why}"
    assert why in reason, f"the rejection does not name the offending param: {reason}"


def test_the_real_registry_admits_its_own_declared_types():
    """Positive control on the real signatures."""
    reg = ModuleVerbRegistry(ADAPTERS_DIR)
    assert validate_params(
        reg.verbs("elastic")["query"], {"native_query": "FROM logs", "limit": 20},
    ) is None
    assert validate_params(
        reg.verbs("identity")["list-users"], {"enabled": False, "role": "admin"},
    ) is None


def test_an_unresolvable_annotation_is_unconstrained_not_denied():
    """A verb whose annotation cannot be evaluated must not deny a well-formed call — the
    checker fails OPEN on its own confusion rather than inventing a rejection the model cannot
    act on. (Fail-closed belongs at the registry, which is where an unknown system/verb dies.)"""

    def broken(ctx, *, thing: NotAType) -> None:  # noqa: F821 — deliberately unresolvable
        ...

    assert validate_params(broken, {"thing": "anything"}) is None
