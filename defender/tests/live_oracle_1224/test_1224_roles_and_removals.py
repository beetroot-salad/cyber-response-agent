"""#1224 — the oracle's two model roles, their scoped preflight, and what M12 deletes.

Two new `AgentRole` members (`ORACLE`, `ORACLE_CHECK`, distinct from the runtime's `VERIFIER`)
each get an agent definition and a model knob read at call time with a cheap default that
routes (M11; GD-06/GD-07: a default that does not route breaks every run). M25=A scopes the
role preflight to the roles a run uses: the oracle roles are checked at branch launch and in
siblings, never on an ordinary alert run, and a misconfigured oracle model is an operator's
configuration error, never an oracle failure charged to a world.

M12 deletes staging (its write door included), the stagers, the applier, the lookups, the
review, and the world-view hooks; the survivors (the run-record label check, the redaction
filter, elastic's index confinement, the shippable-surface lint) keep doing their own job.
Removal tests read the tree (`S.grep_shipped`, `S.source_text`, `importlib.util.find_spec`,
an import census over the AST) and pair every absence with a positive control showing the
census really scans. The role-count pins and test_797's fence are waivers W-01/W-02, not
tests; nothing here re-pins a count.

Preflight failures are logged (`defender.run`'s logger), so they are read off `caplog`.
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import inspect
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


# --------------------------------------------------------------------------------------
# The tree, read: an import census over the AST.
# --------------------------------------------------------------------------------------


def _imports(path: Path) -> set[str]:
    """Every module `path` imports, absolute and relative (resolved), lazy imports included;
    a `from X import y` contributes both `X` and `X.y`."""
    path = Path(path)
    rel = path.relative_to(S.REPO_ROOT).with_suffix("")
    package = rel.parts[:-1]
    out: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = list(package[: len(package) - (node.level - 1)])
                base += [node.module] if node.module else []
                head = ".".join(base)
            else:
                head = node.module or ""
            out.add(head)
            out.update(f"{head}.{alias.name}" for alias in node.names)
    return out


def _string_constants(path: Path) -> set[str]:
    return {node.value for node in ast.walk(ast.parse(Path(path).read_text(encoding="utf-8")))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)}


def _branching_modules() -> list[Path]:
    """Every module on a branching path: the launcher, pre-flight, the estate (the oracle and
    its tools included), and the manifest loader."""
    roots = (S.DEFENDER / "learning" / "branch", S.DEFENDER / "runtime" / "branch")
    return sorted(p for root in roots for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _imports_any(mods: set[str], banned: tuple[str, ...]) -> list[str]:
    return sorted(m for m in mods for b in banned if m == b or m.startswith(b + "."))


# ======================================================================================
# The two roles (M11) and their preflight (M25=A).
# ======================================================================================


def test_1224_oracle_and_its_verifier_are_their_own_roles_with_their_own_model_knobs(
        monkeypatch):
    """d15f_two_roles_with_their_own_knobs — ORACLE and ORACLE_CHECK are two new roles apart from VERIFIER, each with a definition, a model knob read at call time whose default routes, and a budget of its own never charged to the investigator.

    M11; D1: only that the budget is the oracle's own and never the investigator's is pinned,
    never its unit; M25: the default must route, GD-06/GD-07.
    """
    AgentRole, AGENTS = _role(), _agents()
    assert AgentRole.ORACLE.value == "oracle"
    assert AgentRole.ORACLE_CHECK.value == "oracle_check"
    assert AgentRole.VERIFIER not in (AgentRole.ORACLE, AgentRole.ORACLE_CHECK)
    oracle_def, check_def = AGENTS[AgentRole.ORACLE], AGENTS[AgentRole.ORACLE_CHECK]
    assert oracle_def.role is AgentRole.ORACLE
    assert check_def.role is AgentRole.ORACLE_CHECK
    assert oracle_def is not AGENTS[AgentRole.VERIFIER]

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


def test_oracle_role_model_does_not_route_on_a_plain_alert_run(tmp_path, monkeypatch, caplog):
    """b_p039 — a plain alert run's start is not stopped by oracle role models that do not route, while the branching preflight is.

    Adding branching must not make any non-branching run depend on the oracle roles' models or
    keys (inferred from the amendments' fence; M25=A). Observed at the alert run's start gate:
    `run.main`'s role preflight seam defaults to `preflight_role_models` called without
    branching; the positive control is the branching preflight refusing the same
    configuration.
    """
    _credentialed(monkeypatch, tmp_path)
    preflight = _preflight()
    alert_gate = inspect.signature(S.sym(S.RUN, "main")).parameters["preflight"].default
    assert alert_gate(None) == 0, "the alert run's gate fails with every knob routable"
    monkeypatch.setenv(S.KNOB_MODEL, UNROUTABLE)
    monkeypatch.setenv(S.KNOB_CHECK_MODEL, UNROUTABLE)
    caplog.clear()
    assert alert_gate(None) == 0, caplog.text
    assert preflight(None, branching=True) == 2
    assert UNROUTABLE in caplog.text


def test_1224_oracle_effort_valid_on_one_provider_only(tmp_path, monkeypatch, caplog):
    """b_p266 — an oracle effort fatal on the provider its model routes to surfaces at the branch launch, to the operator, and never mid-serving as a failure charged to a world.

    M25=A, human R6b. Applied: the oracle's model routes to Fireworks and its effort is
    `xhigh` (valid on Anthropic, fatal on Fireworks, GD-07).
    """
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
    """o46_oracle_model_preflight — the oracle model knob unset, defaulted or mis-set never stops an alert run's preflight; a branch launch with it unroutable refuses before pre-flight spends anything, charging no world.

    Also the contract of:
    - o47_verifier_model_preflight — an unroutable oracle-check model with a routable oracle model still refuses the branch launch before pre-flight spends, and never stops an alert run (the `oracle_check` case; the routable oracle role is not blamed).
    - b_p040 — an empty or unroutable oracle model knob leaves an alert run's start alone, refuses a sibling's and a launch's preflight naming the role, and a launch so refused spends nothing (the `oracle` case's empty value; M25=A, human R6b).

    M25=A. Positive control: with the knob routable the same launch reaches the oracle.
    """
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


def test_1224_role_preflight_sees_both_oracle_roles_and_refuses_a_role_with_no_definition(
        tmp_path, monkeypatch, caplog):
    """o48_roster_preflight — the branching preflight visits ORACLE and ORACLE_CHECK, fails loudly naming a branching role whose definition is missing, and an alert run's preflight is scoped to the roles it uses.

    M25=A. The missing definition is the registry's entry removed for the test's duration (the
    preflight reads the registry at call time); the role-count pins are W-02 and are not
    re-pinned here.
    """
    _credentialed(monkeypatch, tmp_path)
    AgentRole, AGENTS, preflight = _role(), _agents(), _preflight()
    assert AgentRole.ORACLE in AGENTS
    assert AgentRole.ORACLE_CHECK in AGENTS
    assert preflight(None, branching=True) == 0
    for knob, role in ((S.KNOB_MODEL, AgentRole.ORACLE),
                       (S.KNOB_CHECK_MODEL, AgentRole.ORACLE_CHECK)):
        with monkeypatch.context() as m:
            m.setenv(knob, UNROUTABLE)
            caplog.clear()
            assert preflight(None) == 0, (role.name, caplog.text)
            assert preflight(None, branching=True) == 2, role.name
            assert _logged_role(caplog.text, role.name), caplog.text

    caplog.clear()
    monkeypatch.delitem(AGENTS, AgentRole.ORACLE_CHECK)
    try:
        outcome: Any = preflight(None, branching=True)
    except Exception as loud:  # noqa: BLE001 — a raised refusal is a loud failure too
        outcome = loud
    assert not isinstance(outcome, TypeError), outcome
    assert outcome != 0, "a branching role with no definition was skipped"
    assert _logged_role(caplog.text + str(outcome), AgentRole.ORACLE_CHECK.name), (
        caplog.text, outcome)


# ======================================================================================
# What M12 deletes, and what must survive it.
# ======================================================================================


def test_1224_no_branching_module_reaches_a_write_door():
    """d07d_no_write_door_remains — staging's write door is gone and no module on a branching path imports staging or the cluster transport's write call.

    O6; M12; the census is C13's deferred probe. Positive controls: the census finds the
    serving seam and the transport's own write call where they live, and the oracle module and
    pre-flight are on the path.
    """
    assert importlib.util.find_spec(S.COINED["module.oracle"]) is not None
    assert hasattr(S.mod(S.CLI), S.COINED["fn.preflight"])
    assert S.grep_shipped("def serve_one"), "the census did not scan the estate"
    assert S.grep_shipped("def docker_exec_curl"), "the census did not scan the transport"
    assert importlib.util.find_spec("defender.learning.branch.staging") is None
    for needle in ("write_door", "class _Door", "_Door("):
        assert S.grep_shipped(needle) == [], needle
    branching = _branching_modules()
    assert any(p.name == "registry.py" for p in branching)
    banned = ("defender.learning.branch.staging", "defender.scripts.adapters._stub_transport")
    for path in branching:
        assert not _imports_any(_imports(path), banned), path
        assert "docker_exec_curl" not in path.read_text(encoding="utf-8"), path


def test_1224_branching_imports_no_vendor_module():
    """d17a_no_vendor_code_in_branching — no branching module imports elastic_adapter, esql_text or a stager, and none keys on a lab system's name.

    O1; non-obligation: no per-vendor code, no stagers, no capability tiers. Positive controls:
    the import census sees the registry's own imports, and the name census finds `elastic`
    where a vendor module keys on it.
    """
    registry = S.DEFENDER / "learning" / "branch" / "estate" / "registry.py"
    assert "defender.runtime.verbs" in _imports(registry), "the import census sees nothing"
    adapter = S.DEFENDER / "scripts" / "adapters" / "elastic_adapter.py"
    assert "elastic" in _string_constants(adapter), "the name census sees nothing"
    banned = ("defender.scripts.adapters.elastic_adapter", "defender.scripts.adapters.esql_text",
              "defender.learning.branch.estate.stagers")
    for path in _branching_modules():
        assert not _imports_any(_imports(path), banned), path
        keyed = set(S.LAB_SYSTEMS) & _string_constants(path)
        assert not keyed, (path.relative_to(S.DEFENDER).as_posix(), sorted(keyed))


def test_1224_staging_stagers_applier_lookups_and_review_are_gone():
    """d19a_deleted_modules_are_gone — staging, the stagers, the applier, the lookups and the review are gone and imported by nothing, with validate_world_touches, Step.STAGING, _STAGED_NAME, the sweep and run.py's WorldApplier and configured_patterns fallback.

    Also the contract of:
    - d17e_no_holding_system_anywhere — the only shipped modules naming holding_system are the ones refusing a manifest as predating the oracle.
    - d19b_world_view_hooks_have_no_user — VIEW_NAMESPACE, is_world_view, refuse_unnameable_world and refuse_a_foreign_world_view are gone with no remaining user, and esql_text names none of them.
    - o25_shippable_surface_lint_after_stagers — the shippable-surface lint names no carve-out for the deleted stagers path (its run over the tree and its plants are the CI lint job's).
    - d12b_no_code_bucket — the judge's code-half symbols are absent from the shipped tree. Name absence only: a renamed code half would pass it; the behavioural half is pinned by `test_1224_world_bucket_is_the_judge_models_output` (d12a) and `test_1224_judge_reads_a_real_error_row_and_an_adapter_cannot_load_fault_row_as_decided`.

    M12; RF-10: archive.py holds no cluster staging, so nothing is asserted of it, and
    refuse_unnameable_world in _family.py, redaction's VIEW_NAMESPACE and the registry's
    refuse_a_foreign_world_view are the unnamed consumers; GB-22: esql_text has none today;
    O-25; GB-12; GC-01; GC-02. Positive controls: the surviving registry is found by the same
    probes, and every census finds a survivor before it is trusted to find nothing.
    """
    deleted = ("defender.learning.branch.staging", "defender.learning.branch.estate.stagers",
               "defender.learning.branch.estate.applier",
               "defender.learning.branch.estate.lookups", "defender.learning.branch.review")
    assert importlib.util.find_spec("defender.learning.branch.estate.registry") is not None
    for name in deleted:
        assert importlib.util.find_spec(name) is None, name
    shipped = S.shipped_python()
    assert any(p.name == "registry.py" for p in shipped), "the import census scanned nothing"
    importers = {p.relative_to(S.DEFENDER).as_posix(): _imports_any(_imports(p), deleted)
                 for p in shipped}
    assert {k: v for k, v in importers.items() if v} == {}

    assert S.grep_shipped("def grade_episode"), "the text census scanned nothing"
    for needle in (
            # d19a: staging's helpers and run.py's applier.
            "validate_world_touches", "sweep_glob", "WorldApplier", "STAGING", "_STAGED_NAME",
            # d19b: the world-view hooks.
            "VIEW_NAMESPACE", "is_world_view", "refuse_unnameable_world",
            "refuse_a_foreign_world_view", "ViewNameError",
            # d12b: the judge's code half.
            "def grade_family", "def _grade_family", "def _grade_world",
            "MECHANICAL_WORLD_BUCKET", "withheld_reason", "def _holding_system", "own_h_rows",
            "doctored_answer_served", "_control_drift_discard"):
        found = S.grep_shipped(needle)
        assert found == [], (needle, found)
    run_src = S.source_text("run.py")
    assert "def resume_world" in run_src
    assert "configured_patterns" not in run_src

    holding = sorted({hit.split(":", 1)[0] for hit in S.grep_shipped("holding_system")})
    assert holding, "the old-manifest refusal names holding_system nowhere"
    assert [f for f in holding if S.PREDATES not in S.source_text(f)] == []

    esql = S.DEFENDER / "scripts" / "adapters" / "esql_text.py"
    esql_src = esql.read_text(encoding="utf-8")
    assert "def split_first_command" in esql_src, "the esql census read nothing"
    assert not _imports_any(_imports(esql), ("defender.learning.branch",))
    assert "world_view" not in esql_src

    lint_src = (S.REPO_ROOT / "scripts" / "lint" / "lint_shippable_surface.py").read_text(
        encoding="utf-8")
    assert "EXCLUDED_PREFIXES" in lint_src, "the lint moved"
    assert "estate/stagers" not in lint_src


def test_1224_run_record_label_check_still_refuses_a_reserved_label(tmp_path):
    """d19c_reserved_label_rule_survives — the runs repository's episode-record writer still refuses a reserved world label, naming the rule, and records a well-formed one.

    M12 takes `_world_label.world_view_fault`'s view arm; this writer imports the label rule
    from that module. Positive control: a well-formed label is recorded and read back.
    """
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
    """o27_redaction_filter_survives — with the staged-name rule gone, the redaction filter still masks run and world tokens and leaves a wv- string alone.

    O-27; GB-20.
    """
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
    """o28_confine_index_survives — elastic's index confinement admits and refuses exactly the same indices for an ordinary run and for a sibling.

    O-28; GB-23. Driven through the real elastic adapter over an unreachable tenant (the #632
    plant): an index the gate admits reaches the transport, one it refuses never does.
    Positive controls: an in-bounds index passes and an out-of-bounds one is refused on the
    ordinary run.
    """
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
