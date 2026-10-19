from __future__ import annotations

import importlib
import importlib.util
import re
from dataclasses import fields, replace
from pathlib import Path
from typing import Any

import pytest

from defender.tests.live_oracle_1224 import _spec1224 as S

#: A name no provider routes (the sentinel `test_glm_fireworks` uses for the same purpose).
UNROUTABLE = "no-such-vendor/no-such-model"
#: A Fireworks alias the provider tables route (GD-07: the learning roles' own provider).
ROUTABLE = "glm-5.3"
#: The oracle role's effort knob, on the pattern of `QUESTIONER_EFFORT` / `JUDGE_EFFORT`.
KNOB_EFFORT = S.KNOB_EFFORT  # coined in _spec1224 (COINED["knob.effort"])


def _role() -> Any:
    return S.sym(S.AGENT_ROLE, "AgentRole")


def _agents() -> Any:
    return S.sym("agents", "AGENTS")


def _preflight() -> Any:
    return S.sym(S.RUN, "preflight_role_models")


def _providers() -> Any:
    return S.mod("runtime.providers")


def _credentialed(monkeypatch: Any, tmp_path: Path) -> None:
    """Every provider key present (a value that buys nothing) and both oracle knobs routable,
    so a preflight result is about routing — never about whether this box holds a key."""
    env_file = tmp_path / "empty.env"
    env_file.write_text("", encoding="utf-8")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env_file))
    for var in _providers().api_key_vars():
        monkeypatch.setenv(var, "not-a-billable-key")
    monkeypatch.setenv(S.KNOB_MODEL, ROUTABLE)
    monkeypatch.setenv(S.KNOB_CHECK_MODEL, ROUTABLE)


def _logged_role(text: str, role_name: str) -> bool:
    """Does the preflight's log name `role_name` as a whole word (`ORACLE` is not
    `ORACLE_CHECK`)?"""
    return re.search(rf"\b{re.escape(role_name)}\b", text) is not None


def _family() -> dict:
    """A v2 family whose arms carry distinct roles (the launcher refuses two sharing one)."""
    return S.family_v2(worlds=[
        S.control_world("a"),
        S.world_v2("b", facts=[S.fact("f1")], role="B"),
        S.world_v2("c", facts=[S.fact("f2", "bob reset carol's password from 10.0.0.9",
                                      ("bob", "carol", "10.0.0.9"))], role="C"),
    ])


def _launch(where: Path, monkeypatch: Any) -> tuple[Any, Any, Any, Any]:
    """One launch through the REAL launcher with the launcher's OWN role preflight (the seam
    left to production), in a data root of its own. Returns `(launch, estate, oracle,
    verifier)`; the doubles answer text-only, so a pre-flight that reaches them fails its
    worlds (which is still pre-flight spending)."""
    from defender.tests._data_root_1078 import DATA_ROOT_ENV

    where = Path(where)
    (where / "data-root").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(DATA_ROOT_ENV, str(where / "data-root"))
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est = S.estate(where)
    oracle = S.oracle(then=S.text_only())
    verifier = S.verifier(then=S.verdict(True))
    launch = S.launch(where, est, oracle=oracle, verifier=verifier, preflight=None,
                      questioner=S.questioner_for(_family()))
    return launch, est, oracle, verifier


def _assert_spent_nothing(launch: Any, est: Any, oracle: Any, verifier: Any) -> None:
    """A launch refused for its configuration: no sibling, no oracle or verifier turn, no
    tenant read, and nothing charged to a world."""
    assert launch.rc != 0
    assert launch.spawn.launches == [], "a sibling started"
    assert oracle.requests == 0, "pre-flight reached the oracle"
    assert verifier.requests == 0, "pre-flight reached the verifier"
    assert est.calls() == [], "pre-flight read the tenant"
    outcome = S.read_outcome(launch.ep)
    if outcome is not None:
        assert not outcome.get("unservable_worlds"), outcome
        assert outcome.get("outcome") != "unusable", outcome
    for label in S.WORLDS:
        assert S.read_world_record(launch.ep, label) is None, label


def test_1224_oracle_and_its_verifier_are_their_own_roles_with_their_own_model_knobs(
        monkeypatch):
    """ORACLE and ORACLE_CHECK are two new roles apart from VERIFIER, each with a definition, a model knob read at call time whose default routes, and a budget of its own never charged to the investigator."""
    AgentRole, AGENTS = _role(), _agents()
    assert AgentRole.ORACLE.value == "oracle"
    assert AgentRole.ORACLE_CHECK.value == "oracle_check"
    oracle_def, check_def = AGENTS[AgentRole.ORACLE], AGENTS[AgentRole.ORACLE_CHECK]
    assert oracle_def.role is AgentRole.ORACLE
    assert check_def.role is AgentRole.ORACLE_CHECK

    # Read at call time: the same definition answers the knob's new value with no reload.
    monkeypatch.setenv(S.KNOB_MODEL, "glm-5.3")
    monkeypatch.setenv(S.KNOB_CHECK_MODEL, "glm-5.3-flash")
    assert oracle_def.model() == "glm-5.3"
    assert check_def.model() == "glm-5.3-flash"
    monkeypatch.setenv(S.KNOB_MODEL, "kimi-k3")
    assert oracle_def.model() == "kimi-k3"
    assert check_def.model() == "glm-5.3-flash", "the two knobs are not independent"

    # The defaults route: a default no provider routes would stop every branch launch.
    monkeypatch.delenv(S.KNOB_MODEL, raising=False)
    monkeypatch.delenv(S.KNOB_CHECK_MODEL, raising=False)
    for defn in (oracle_def, check_def):
        _providers().provider_for(defn.model())

    # Never charged to the investigator's run budget; the oracle's own budget is its knob's.
    assert not oracle_def.budget_enforced
    assert not check_def.budget_enforced
    settings = S.sym(S.ORACLE, "oracle_settings")
    default, tight = settings({}), settings({S.KNOB_BUDGET: "1e-9"})
    assert tight.budget != default.budget, "the budget knob is not the oracle's budget"


def test_1224_oracle_effort_valid_on_one_provider_only(tmp_path, monkeypatch, caplog):
    """an oracle effort fatal on the provider its model routes to surfaces at the branch launch, to the operator, and never mid-serving as a failure charged to a world."""
    _credentialed(monkeypatch, tmp_path)
    preflight = _preflight()
    monkeypatch.setenv(S.KNOB_MODEL, "kimi-k3")
    monkeypatch.setenv(KNOB_EFFORT, "medium")
    assert preflight(None, branching=True) == 0, "an effort valid on both providers is refused"
    monkeypatch.setenv(KNOB_EFFORT, "xhigh")
    caplog.clear()
    assert preflight(None) == 0, caplog.text
    assert preflight(None, branching=True) == 2
    assert _logged_role(caplog.text, _role().ORACLE.name), caplog.text
    _assert_spent_nothing(*_launch(tmp_path / "fatal-effort", monkeypatch))


@pytest.mark.parametrize(("knob", "role", "bad_values", "spared"), [
    (S.KNOB_MODEL, "ORACLE", ("", UNROUTABLE), None),
    (S.KNOB_CHECK_MODEL, "ORACLE_CHECK", (UNROUTABLE,), "ORACLE"),
], ids=["oracle", "oracle_check"])
def test_1224_oracle_model_knob_is_preflighted_only_where_branching_runs(
        tmp_path, monkeypatch, caplog, knob, role, bad_values, spared):
    """the oracle model knob unset, defaulted or mis-set never stops an alert run's preflight; a branch launch with it unroutable refuses before pre-flight spends anything, charging no world."""
    _credentialed(monkeypatch, tmp_path)
    preflight = _preflight()
    monkeypatch.delenv(knob, raising=False)
    assert preflight(None) == 0
    assert preflight(None, branching=True) == 0, f"the {role} model's default does not route"
    for bad in bad_values:
        monkeypatch.setenv(knob, bad)
        caplog.clear()
        assert preflight(None) == 0, (bad, caplog.text)
        assert preflight(None, branching=True) == 2, bad
        assert _logged_role(caplog.text, role), caplog.text
        if spared:
            assert not _logged_role(caplog.text, spared), f"the routable {spared} role blamed"
        if bad:
            assert bad in caplog.text, caplog.text
        _assert_spent_nothing(*_launch(tmp_path / f"bad-{bad or 'empty'}", monkeypatch))

    monkeypatch.setenv(knob, ROUTABLE)
    _launch_ok, _est, oracle, _verifier = _launch(tmp_path / "routable", monkeypatch)
    assert oracle.requests > 0, "a launch whose models route never reached pre-flight"


def test_1224_run_record_label_check_still_refuses_a_reserved_label(tmp_path):
    """the runs repository's episode-record writer still refuses a reserved world label, naming the rule, and records a well-formed one."""
    from defender import run_repository as R

    H = importlib.import_module("defender.tests.tenant_1105_run_repository._spec1105")
    t = H.tenant(tmp_path / "data")
    runs = H.runs_folder(t)
    H.make_run(runs, "r0")
    for label, why in (("base", "reserved"), ("BASE", "reserved"), ("family", "reserved"),
                       ("family_3", "family_")):
        with pytest.raises(R.RunRefused) as refused:
            R.record_episode_runs(t, "ep", R.RunId.parse("r0"), {label: R.RunId.parse("ep-a")})
        assert why in str(refused.value), (label, str(refused.value))
    R.record_episode_runs(t, "ep", R.RunId.parse("r0"), {"a": R.RunId.parse("ep-a")})
    assert R.episode_runs(t, "ep") == {"a": R.RunId.parse("ep-a")}


def test_1224_redaction_filter_still_masks_what_it_masked_without_the_staged_name_rule():
    """with the staged-name rule gone, the redaction filter still masks run and world tokens and leaves a wv- string alone."""
    redaction = S.mod("learning.branch.redaction")
    redact = redaction.redact_model_visible
    token_text = f"refused: index for run {S.EPISODE_TOKEN}.b is unavailable after 2026-07-28"
    masked = redact(token_text)
    assert S.EPISODE_TOKEN not in masked, masked
    assert masked.startswith("refused: index for run "), masked
    assert masked.endswith(" is unavailable after 2026-07-28"), masked
    view_text = "index 'wv-b-logs-' not found; tried [logs-*,-wv-b-logs-]"
    assert redact(view_text) == view_text
    assert not hasattr(redaction, "_STAGED_NAME")
    assert "VIEW_NAMESPACE" not in S.source_text("learning/branch/redaction.py")


def _confinement_gate(elastic: Any, ctx: Any, index: str) -> str:
    """Did elastic's index confinement refuse `index` for `ctx`, or let the call through to
    the (deliberately unreachable) transport?"""
    ConfinementFault = S.sym("scripts.adapters.confinement", "ConfinementFault")
    TransportFault = S.sym("scripts.adapters.faults", "TransportFault")
    try:
        elastic.VERBS["query"](ctx, native_query="FROM x", index=index)
    except ConfinementFault:
        return "refused"
    except TransportFault:
        return "passed"
    return "answered"


def test_1224_elastic_confine_index_admits_the_same_indices_for_a_run_and_a_sibling(tmp_path):
    """elastic's index confinement admits and refuses exactly the same indices for an ordinary run and for a sibling."""
    H = importlib.import_module("defender.tests.tenant_1107_settings._spec1107")
    root = tmp_path / "tree"
    url = "http://127.0.0.1:1"
    H.plant(root, configs={
        "elastic": (f"ELASTICSEARCH_URL={url}\nKIBANA_URL={url}\nELASTIC_EVENTS_INDEX=logs-*\n"
                    "ELASTIC_ALERTS_INDEX=security-audit-*\nELASTIC_SSL_VERIFY=true\n"
                    "ELASTIC_TRANSPORT=docker-exec\n"
                    "ELASTIC_DOCKER_CONTEXT=no-such-context-1224-test\n"
                    "ELASTIC_ES_CONTAINER=es-1224\nELASTIC_KIBANA_CONTAINER=kibana-1224\n"),
        "host-state": ("HOST_STATE_TRANSPORT=docker-exec\n"
                       "HOST_STATE_DOCKER_CONTEXT=no-such-context-1224-test\n")})
    VerbContext = S.sym(S.VERBS, "VerbContext")
    run_ctx = VerbContext(defender_dir=root, tenant=H.resolve(root), run_dir=tmp_path / "run",
                          env={})
    sibling = {"as_of": S.AS_OF_DT}
    if "world_id" in {f.name for f in fields(VerbContext)}:
        sibling["world_id"] = S.world_token("b")
    sibling_ctx = replace(run_ctx, **sibling)
    elastic = S.mod("scripts.adapters.elastic_adapter")
    assert _confinement_gate(elastic, run_ctx, "logs-*") == "passed"
    assert _confinement_gate(elastic, run_ctx, ".security-7") == "refused"
    for index in ("logs-*", "logs-system.auth-*", "security-audit-*", ".security-7",
                  f"wv-{S.world_token('b')}-logs-", "wv-b-logs-", "wv-a-logs-",
                  "wv-b-security-audit-"):
        on_run = _confinement_gate(elastic, run_ctx, index)
        on_sibling = _confinement_gate(elastic, sibling_ctx, index)
        assert on_run == on_sibling, (index, on_run, on_sibling)
