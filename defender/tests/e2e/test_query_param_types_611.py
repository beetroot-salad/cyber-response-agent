"""Impl-time hardening for #611: a verb's ANNOTATIONS are part of its param contract."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.systems.verb_grant import DENY_ALL  # noqa: E402
from defender.systems.verbs import ModuleVerbRegistry, VerbContext, validate_params  # noqa: E402
from defender.kit.verbs import model_facing_params
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
from defender.systems.verbs import read_roster  # noqa: E402

pytestmark = pytest.mark.e2e

ADAPTERS_DIR = DEFENDER / "integrations"


def clamping(rec: VerbRecorder) -> FakeVerbs:
    """A verb that uses its `int` param the way the REAL one does. `elastic.query` ends in
    `min(limit, RETURNED_DOC_CAP)` (`elastic_adapter._build_search_body`), and `min("20", 20)` raises
    `TypeError` — an unmapped fault, which the capture files as exit 2 = infra. The fake carries"""

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


def test_a_mistyped_param_is_a_usage_error_not_an_infra_failure(tmp_path):
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=clamping(rec), turns=[
        q("elastic", "query", {"native_query": "FROM logs", "limit": "20"}), DONE,
    ], run_id="q611-mistyped")

    assert rec.calls == [], "a mistyped param reached the verb — the type check is not at the boundary"
    row = r.row()
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
    assert [row["exit_code"] for row in r.own_rows] == [64, 64, 0]
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


def test_well_typed_params_including_optionals_and_containers_are_admitted(tmp_path):
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


@pytest.mark.parametrize(("system", "verb", "params", "why"), [
    ("elastic", "query", {"native_query": "FROM logs", "limit": "20"}, "limit"),
    ("identity", "list-users", {"enabled": "false"}, "enabled"),
])
def test_the_real_registry_rejects_a_mistyped_param(system, verb, params, why):
    """The shipped adapters, not a fake: each of these signatures has a non-`str` param a model
    can plausibly BIND and plausibly send as a string, and each was admitted before."""
    fn = ModuleVerbRegistry(read_roster(ADAPTERS_DIR), DENY_ALL).verbs(system)[verb]
    assert why in model_facing_params(fn), (
        f"{why} is not a param a model may bind on {system}.{verb} — this row cannot reach the "
        "type check it exists to measure"
    )
    reason = validate_params(fn, params)
    assert reason is not None, f"{system}.{verb} admitted a mistyped {why}"
    assert why in reason, f"the rejection does not name the offending param: {reason}"


def test_the_real_registry_admits_its_own_declared_types():
    """Positive control on the real signatures."""
    reg = ModuleVerbRegistry(read_roster(ADAPTERS_DIR), DENY_ALL)
    assert validate_params(
        reg.verbs("elastic")["query"], {"native_query": "FROM logs", "limit": 20},
    ) is None
    assert validate_params(
        reg.verbs("identity")["list-users"], {"enabled": False, "role": "admin"},
    ) is None


def test_an_unresolvable_annotation_is_unconstrained_not_denied():

    def broken(ctx, *, thing: NotAType) -> None:  # noqa: F821 — deliberately unresolvable
        ...

    assert validate_params(broken, {"thing": "anything"}) is None
