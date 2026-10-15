"""#1256 slice C — a granted system down at run start, seen by lead zero (O-6) and by run start
(O-8).

The design (#1256 r2): each granted system's adapter judges, at run start, whether the run's
frozen settings make it usable; one that fails is *down for this run* with its cause
(not configured, or its adapter broken), and every gate refuses it without running the adapter or
charging the breaker.

O-6 — the correlation lead (`l-00c`) on a system down at start ends BEFORE it claims its lead or
spends a gather count, as the withheld ending does, with an ending of its own that names the
cause: never "tripped breaker", never "every call failed", never a run refusal (the run goes on,
MAIN runs, report.md is written, provided gather has another usable system). The ending constant
this contract pins is `lead_zero._spec.ENDING_DOWN_AT_START` (one ending for every start-time
cause; its sentence names the cause, as `tripped_breaker`'s names the system).

O-8 — a run where no granted system is usable at start is refused at start, naming each down
system and its reason: the existing "gather can query nothing" refusal (`require_gather_query`),
applied to the systems granted AND up. Read here, as that rule already reads a health-check-only
grant, as: gather can query only through a non-health-check verb on a system that is up — so a
system granted nothing but its health check, though up, does not save the run.

HOW EACH IS SEEN. Every scenario goes through the production front door (`S.run_alert`: the real
`run.main`, the real driver behind `_ReplayLifecycle`), with the REAL adapters under the checkout
judging the planted tenant's settings (K2). A system is made unusable the way an operator would:
its `config.env` missing a key its adapter requires (`_spec1107.drop_key`), or absent. The
correlation sentence is read from MAIN's opening message's ONE correlation section
(`S.correlation_section`), not from the whole-prose diff `_ending` takes against the summary
control: once O-3 lands the workspace map also names the down system, and that line is not the
lead's ending. The ending names the CAUSE; the check's reason (the missing key) need only reach
MAIN somewhere in its opening message (O-3) — #1222 A2's no-fault-text sentences stand. "No gather count spent" is the run's `subagent_spawns` (the summary control's is 1,
the withheld reference's 0); "never claimed" is l-00c's leads-table row.
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path
from typing import Any

from defender.tests import _tenants1106 as T6
from defender.tests.alert_front_door_1222 import _spec1222 as S
from defender.tests.alert_front_door_1222.test_1222_correlation_endings import (
    _assert_closed,
    _assert_continued,
    _backend,
    _config_fault,
    _fail_alerts,
    _named,
    _pre_trip,
    _q,
    _Scene,
)
from defender.tests.tenant_1107_settings import _spec1107 as S7

#: The ending constant this contract coins (K4's one allowed type-level pin, slice C).
ENDING_NAME = "ENDING_DOWN_AT_START"

#: Words a down-at-start text must never use for a not-configured system: they belong to the
#: breaker's cause (tripped, n failures), which a system down at start never reached (DP4).
TRIPPED_WORDS = ("tripped", "circuit breaker", "infra failure")

#: What the planted broken adapter raises at import — never "not configured" (a different cause).
BROKEN_MARK = "FD1256-PLANTED-ADAPTER-IMPORT-FAILURE"


def _names_system(text: str, system: str) -> bool:
    """`text` names `system` as a word of its own — not as the head of a key that merely starts
    with it (`ELASTICSEARCH_URL`, `CMDB_URL_BASE`), so the check is independent of the reason's."""
    return re.search(rf"(?<![\w-]){re.escape(system)}(?![\w-])", text, re.IGNORECASE) is not None


def _drop(scene: _Scene, system: str, key: str) -> None:
    """`system`'s `config.env` loses `key` — a key its own adapter requires (K6: the planted
    tenant starts complete, so this one edit is the only thing down)."""
    S7.drop_key(scene.tenant.knowledge, system, key)


def _down_lead() -> dict[str, Any]:
    """l-00c's script and backend on a down system: three calls, each answered as the system's
    real adapter answers today when its settings are missing (RJ-07: `ConfigFault`, exit 2). A
    run that dispatches the lead anyway is seen doing so — calls recorded, the breaker charged,
    and at base the ending is 'tripped breaker'."""
    return {"backend": _fail_alerts(_config_fault),
            "leads": {S.L3: [_q(1), _q(2), _q(3), S.text("FD1256-DOWN-NARRATION")]}}


def _section(d: S.Drive) -> str:
    """The body of MAIN's ONE correlation section (frames kept): where l-00c's ending is named."""
    _head, body = S.correlation_section(d.opening_message)
    return body


def _assert_never_started(d: S.Drive, what: str) -> None:
    """l-00c ended before its claim and its gather count (as withheld does), ran no adapter and
    charged nothing."""
    assert not d.router.dispatched(S.L3), f"{what}: l-00c was dispatched on a system down at start"
    assert not d.has_sidecar(S.L3), (
        f"{what}: l-00c claimed its leads-table row though its system was down at start (O-6: "
        "it ends before the claim, as the withheld ending does)")
    assert d.budget.get("subagent_spawns") == 0, (
        f"{what}: l-00c spent a gather count though its system was down at start: {d.budget!r}")
    assert d.backend.rec.calls == [], (
        f"{what}: an adapter ran for a system down at start: {d.backend.rec.verbs}")
    assert d.rows_for(S.L3) == [], f"{what}: l-00c wrote queries rows: {d.rows_for(S.L3)}"
    assert d.run_state is not None, f"{what}: the run left no state to read the breaker from"
    assert d.run_state.breaker_failures("elastic") == 0, (
        f"{what}: the breaker was charged for a system down at start: {d.breaker!r}")
    assert d.breaker.get("total_failures", 0) == 0, (
        f"{what}: the run-wide failure count was charged: {d.breaker!r}")


def _assert_names_not_configured(d: S.Drive, control: S.Drive, what: str,
                                  *reason_tokens: str) -> None:
    """l-00c's ending (its correlation section) names the system and the CAUSE, 'not
    configured', and never the breaker's words; the check's REASON (the missing key) reaches MAIN
    somewhere in its opening message — O-3's workspace view carries it — and is neither required
    nor forbidden inside the correlation section (A2's sentences carry no fault text; O-6 asks
    only that the ending name the cause)."""
    body = _section(d)
    low = body.lower()
    assert _names_system(body, "elastic"), f"{what}: the ending does not name the system: {body!r}"
    assert "not configured" in low, (
        f"{what}: the ending does not name the cause 'not configured': {body!r}")
    said = [w for w in TRIPPED_WORDS if w in low]
    assert not said, f"{what}: the ending names the breaker's cause ({said}): {body!r}"
    for token in reason_tokens:
        assert token not in control.opening_message, (
            f"premise: the summary control's opening message already carries {token}")
        assert token in d.opening_message, (
            f"{what}: MAIN's opening message never names the reason ({token}) the system is down")


# =================================================================================================
# O-6 — the ending constant
# =================================================================================================

def test_o6_down_at_start_has_its_own_ending_constant() -> None:
    """The lead-zero vocabulary carries ONE new ending for a system down at run start, distinct from every ending A2 already lists (it is neither 'tripped breaker' nor 'every call failed')."""
    spec = importlib.import_module("defender.runtime.lead_zero._spec")
    others = {name: value for name, value in vars(spec).items()
              if name.startswith("ENDING_") and name != ENDING_NAME}
    assert {"ENDING_TRIPPED_BREAKER", "ENDING_EVERY_CALL_FAILED", "ENDING_WITHHELD"} <= set(
        others), f"premise: the A2 endings are not where they were: {sorted(others)}"
    value = getattr(spec, ENDING_NAME, None)
    assert isinstance(value, str), (
        f"lead_zero._spec has no {ENDING_NAME} (#1256 O-6: l-00c on a system down at start ends "
        f"with its own ending): {value!r}")
    assert value, f"{ENDING_NAME} is empty"
    assert value not in others.values(), (
        f"{ENDING_NAME} = {value!r} is another ending's value: "
        f"{[n for n, v in others.items() if v == value]}")


# =================================================================================================
# O-6 — l-00c on a system down at start, through the front door
# =================================================================================================

def test_o6_lead_on_an_unconfigured_system_ends_before_its_claim_naming_the_cause(
        tmp_path: Path) -> None:
    """l-00c whose system's settings miss a key its adapter requires is down at start: it ends before its claim and its gather count, names the cause 'not configured' in its ending (MAIN's correlation section) while the missing key reaches MAIN's opening message (O-3) — an ending that is not 'tripped breaker', 'every call failed' or 'withheld' — runs no adapter, charges no breaker, and the run goes on to report.md."""
    scene = _Scene(tmp_path)
    control = scene.control()
    withheld = _Scene(tmp_path, tenant_id="acme-withheld", table=S.TABLE_WITHHELD).run("withheld")
    tripped = scene.run("tb-reference", before=_pre_trip(),
                        leads={S.L3: [_q(1), S.text("FD1256-TB-NARRATION")]})
    ecf = scene.run("ecf-reference", backend=_fail_alerts(S.upstream_fault),
                    leads={S.L3: [_q(1), S.text("FD1256-ECF-NARRATION")]})
    # Elastic misses ELASTICSEARCH_URL (one of `elastic_adapter.REQUIRED_CONFIG_KEYS`); cmdb stays
    # complete, so gather keeps a usable system and O-8 does not refuse the run.
    unconfigured = _Scene(tmp_path, tenant_id="acme-down-url")
    _drop(unconfigured, "elastic", "ELASTICSEARCH_URL")
    down = unconfigured.run("down-at-start", main=S.closing_main_turns("inconclusive"),
                            **_down_lead())

    # The channels the 'never started' checks read can show a started lead (positive controls).
    assert control.has_sidecar(S.L3), "premise: the summary control's l-00c claimed no row"
    assert control.budget.get("subagent_spawns") == 1, (
        f"premise: the summary control's l-00c spent no gather count: {control.budget!r}")
    # The model O-6 names ('as the withheld ending does') meets every 'never started' check.
    _assert_never_started(withheld, "premise: the withheld reference")

    sentence = _named(down, control, "down at start (not configured)")
    for label, ref in (("tripped breaker", tripped), ("every call failed", ecf),
                       ("withheld", withheld)):
        assert sentence != _named(ref, control, f"{label} (reference)"), (
            f"l-00c on a system down at start is named with the {label!r} sentence")
        assert _section(down) != _section(ref), (
            f"MAIN's correlation section for a system down at start is the {label!r} one")
    _assert_names_not_configured(down, control, "down at start (not configured)",
                                 "ELASTICSEARCH_URL")
    _assert_never_started(down, "down at start (not configured)")
    # Never a run refusal: the run proceeds, MAIN runs, report.md is written.
    _assert_continued(down, "down at start (not configured)", requests=3)
    _assert_closed(down, "down at start (not configured)")


def test_o6_every_start_time_settings_fault_is_down_at_start(tmp_path: Path) -> None:
    """Whatever settings fault the adapter's check finds — no config.env at all, or the ES container key r1 showed `load_config` never checks — l-00c ends down at start, before its claim and count, naming 'not configured', with nothing run or charged."""
    scene = _Scene(tmp_path)
    control = scene.control()
    no_file = _Scene(tmp_path, tenant_id="acme-no-file", omit_systems=("elastic",))
    container = _Scene(tmp_path, tenant_id="acme-no-container")
    _drop(container, "elastic", "ELASTIC_ES_CONTAINER")

    for label, sc, tokens in (("no config.env", no_file, ()),
                              ("no ES container", container, ("ELASTIC_ES_CONTAINER",))):
        d = sc.run(label.replace(" ", "-").replace(".", ""), **_down_lead())
        _named(d, control, f"down at start ({label})")
        _assert_names_not_configured(d, control, f"down at start ({label})", *tokens)
        _assert_never_started(d, f"down at start ({label})")
        _assert_continued(d, f"down at start ({label})")


# --- adapter broken (O-5a's cause, the same ending) ----------------------------------------------

#: Not mirrored into the planted tree: nothing a run reads, and the first two are large.
_NOT_MIRRORED = frozenset({".venv", "__pycache__", "tests", "fixtures-e2e"})

#: An elastic adapter that cannot be imported, whose verb table still READS (the roster's cold
#: AST read), so the grant check at start accepts it and only the import fails.
_BROKEN_ELASTIC = f'''\
"""#1256 planted: an elastic adapter that cannot be imported (O-5a)."""
raise ImportError("{BROKEN_MARK}")
VERBS = {{"health-check": None, "query": None, "alerts": None, "esql": None}}
'''


def _tree_with_broken_elastic(root: Path) -> Path:
    """A defender tree the run is pointed at: every top-level entry of the checkout symlinked
    except `scripts/`, whose entries are symlinked except `adapters/`, copied for REAL (a roster
    file must resolve inside its directory) with `elastic_adapter.py` replaced by `_BROKEN_ELASTIC`.
    `<root>/repo/defender`, so `defender_dir.parent` is a repo root as the catalog expects."""
    import shutil

    tree = root / "repo" / "defender"
    tree.mkdir(parents=True)
    for entry in S.DEFENDER.iterdir():
        if entry.name in _NOT_MIRRORED or entry.name == "scripts":
            continue
        (tree / entry.name).symlink_to(entry)
    scripts = tree / "scripts"
    scripts.mkdir()
    for entry in (S.DEFENDER / "scripts").iterdir():
        if entry.name in _NOT_MIRRORED or entry.name == "adapters":
            continue
        (scripts / entry.name).symlink_to(entry)
    shutil.copytree(S.DEFENDER / "scripts" / "adapters", scripts / "adapters",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (scripts / "adapters" / "elastic_adapter.py").write_text(_BROKEN_ELASTIC, encoding="utf-8")
    return tree


def test_o6_lead_on_a_system_whose_adapter_is_broken_ends_down_at_start(tmp_path: Path) -> None:
    """A correlation system whose adapter cannot be imported is down at start (adapter broken): l-00c ends before its claim and count with an ending that names the system and is not the 'not configured' one, nor 'tripped breaker', 'every call failed' or 'withheld'; nothing runs or is charged; the run goes on."""
    # Every reference runs on the checkout's own tree (its elastic adapter intact), so none of
    # them is itself down at start. They are compared by MAIN's correlation section alone: the
    # planted tree's workspace map names another DEFENDER_DIR, so a whole-prose diff against a
    # checkout control would carry that path.
    scene = _Scene(tmp_path)
    control = scene.control()
    withheld = _Scene(tmp_path, tenant_id="acme-withheld", table=S.TABLE_WITHHELD).run("withheld")
    tripped = scene.run("tb-reference", before=_pre_trip(),
                        leads={S.L3: [_q(1), S.text("FD1256-TB-NARRATION")]})
    ecf = scene.run("ecf-reference", backend=_fail_alerts(S.upstream_fault),
                    leads={S.L3: [_q(1), S.text("FD1256-ECF-NARRATION")]})
    unconfigured = _Scene(tmp_path, tenant_id="acme-down-url")
    _drop(unconfigured, "elastic", "ELASTICSEARCH_URL")
    not_configured = unconfigured.run("not-configured", **_down_lead())
    # The broken adapter's calls would be answered (the injected registry serves them): a run that
    # dispatches the lead anyway is seen calling.
    tree = _tree_with_broken_elastic(tmp_path / "planted")
    broken = scene.run("adapter-broken", defender_dir=tree, backend=_backend(),
                       main=S.closing_main_turns("inconclusive"),
                       leads={S.L3: [_q(1), _q(2), S.text("FD1256-BROKEN-NARRATION")]})

    body = _section(broken)
    for label, ref in (("summary", control), ("tripped breaker", tripped),
                       ("every call failed", ecf), ("withheld", withheld),
                       ("not configured", not_configured)):
        assert body != _section(ref), (
            f"l-00c on a system whose adapter is broken gets the {label!r} correlation section "
            f"(the cause is not named): {body!r}")
    assert _names_system(body, "elastic"), f"the ending does not name the system: {body!r}"
    assert "not configured" not in body.lower(), (
        f"an adapter that cannot be imported is named 'not configured' — not its cause: {body!r}")
    assert S.DEFAULT_CORRELATION_SUMMARY not in body, "a lead summary stands in the section"
    leaked = S.host_paths_in(body, tmp_path, tree, scene.tenant.root, S.DEFENDER, S.REPO_ROOT)
    assert not leaked, f"the ending carries a host path: {leaked}"
    _assert_never_started(broken, "down at start (adapter broken)")
    _assert_continued(broken, "down at start (adapter broken)", requests=3)
    _assert_closed(broken, "down at start (adapter broken)")


# =================================================================================================
# O-8 — every granted system down at start: refused at start, naming each
# =================================================================================================

#: Gather reaches three systems by query verbs; the correlation lead holds elastic.alerts.
TABLE_THREE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
    list-hosts: {roles: [gather]}
  elastic:
    alerts: {roles: [gather, lead-zero-correlation]}
    health-check: {roles: [gather, lead-zero-correlation]}
    query: {roles: [gather]}
  identity:
    get-user: {roles: [gather]}
    health-check: {roles: [gather]}
"""

#: Gather reaches cmdb by its health check ALONE, and elastic by query verbs; the correlation lead
#: holds elastic.alerts. With elastic down, the one system up grants gather no query.
TABLE_CMDB_HEALTH_ONLY = """\
dispositions:
  cmdb:
    get-host: {roles: [], reason: "#1256 fixture: cmdb is granted its health check alone"}
    health-check: {roles: [gather]}
    list-hosts: {roles: [], reason: "#1256 fixture: cmdb is granted its health check alone"}
  elastic:
    alerts: {roles: [gather, lead-zero-correlation]}
    health-check: {roles: [gather, lead-zero-correlation]}
    query: {roles: [gather]}
"""


def _runs_entries(scene: _Scene) -> list[str]:
    base = scene.tenant.runs
    return sorted(p.name for p in base.iterdir()) if base.is_dir() else []


def _refusal_text(d: S.Drive, scene: _Scene) -> str:
    """The refusal `run.main` exited with, the data root spelled out of it (a host path could
    spell a system's name by accident)."""
    assert isinstance(d.refusal, str), (
        f"the run was not refused at start: rc={d.rc!r} raised={d.raised!r} "
        f"MAIN requests={d.main.requests} summary={d.summary!r}")
    assert d.refusal.strip(), "the refusal carries no text"
    return d.refusal.replace(str(scene.tenant.root), "<DATA_ROOT>")


def _assert_refused_before_anything(d: S.Drive, scene: _Scene, before: list[str],
                                    what: str) -> None:
    """Refused as the existing start refusals are: a non-zero exit carrying the text, before the
    run folder, the box, any model call or any adapter call."""
    assert d.rc not in (0, None), f"{what}: the refusal exited {d.rc!r}"
    assert d.main.requests == 0, f"{what}: MAIN was asked {d.main.requests} times before refusal"
    assert d.router.leads() == [], f"{what}: a gather model ran: {d.router.leads()}"
    assert d.backend.rec.calls == [], f"{what}: an adapter ran: {d.backend.rec.verbs}"
    assert d.lifecycle_calls == [], f"{what}: the run's lifecycle (box, driver) was started"
    assert _runs_entries(scene) == before, (
        f"{what}: the refused run left something under the runs base: {_runs_entries(scene)}")


def test_o8_every_granted_system_down_at_start_refuses_the_run_naming_each(
        tmp_path: Path) -> None:
    """A run whose every granted system fails its adapter's settings check is refused at start — before the run folder, any model call or any adapter call — and the refusal names each down system with its reason ('not configured', the missing key), never the breaker's words."""
    scene = _Scene(tmp_path, tenant_id="acme-all-down")
    _drop(scene, "cmdb", "CMDB_URL_BASE")
    _drop(scene, "elastic", "ELASTICSEARCH_URL")
    before = _runs_entries(scene)
    d = scene.run("all-down", **_down_lead())

    text = _refusal_text(d, scene)
    low = text.lower()
    for system, key in (("cmdb", "CMDB_URL_BASE"), ("elastic", "ELASTICSEARCH_URL")):
        assert _names_system(text, system), (
            f"the refusal does not name the down system {system}: {text!r}")
        assert key in text, f"the refusal does not name {system}'s reason ({key}): {text!r}"
    assert "not configured" in low, f"the refusal does not name the cause: {text!r}"
    said = [w for w in TRIPPED_WORDS if w in low]
    assert not said, f"the refusal names the breaker's cause ({said}): {text!r}"
    _assert_refused_before_anything(d, scene, before, "every granted system down")


def test_o8_a_system_up_with_only_its_health_check_granted_does_not_save_the_run(
        tmp_path: Path) -> None:
    """'Gather can query nothing', applied to the systems granted and up: with elastic down and cmdb up but granted only its health check (which reaches no data), the run is refused at start naming elastic and its reason. The same table with elastic configured runs."""
    configured = _Scene(tmp_path, tenant_id="acme-hc-up", table=TABLE_CMDB_HEALTH_ONLY)
    ran = configured.run("hc-elastic-up")
    _assert_continued(ran, "premise: the health-check-only table with elastic configured")

    scene = _Scene(tmp_path, tenant_id="acme-hc-down", table=TABLE_CMDB_HEALTH_ONLY)
    _drop(scene, "elastic", "ELASTICSEARCH_URL")
    before = _runs_entries(scene)
    d = scene.run("hc-elastic-down", **_down_lead())

    text = _refusal_text(d, scene)
    assert _names_system(text, "elastic"), f"the refusal does not name the down system: {text!r}"
    assert "ELASTICSEARCH_URL" in text, f"the refusal does not name elastic's reason: {text!r}"
    assert "not configured" in text.lower(), f"the refusal does not name the cause: {text!r}"
    _assert_refused_before_anything(d, scene, before, "only a health check up")


def test_o8_one_usable_system_among_several_down_runs(tmp_path: Path) -> None:
    """Control: with elastic and identity down at start and cmdb up (a query verb granted), the run is not refused — it proceeds, MAIN runs and report.md is written (#1107 O5 stands short of every system down)."""
    scene = _Scene(tmp_path, tenant_id="acme-one-up", table=TABLE_THREE)
    _drop(scene, "elastic", "ELASTICSEARCH_URL")
    _drop(scene, "identity", "IDENTITY_URL_BASE")
    d = scene.run("one-up", main=S.closing_main_turns("inconclusive"), **_down_lead())

    _assert_continued(d, "one usable system among several down", requests=3)
    _assert_closed(d, "one usable system")


def test_o8_gather_granted_no_query_verb_is_still_refused(tmp_path: Path) -> None:
    """Control: the existing refusal stands — a table granting gather no query verb, every system configured, is refused at start naming the table, before anything is spent."""
    scene = _Scene(tmp_path, tenant_id="acme-blank", table=T6.TABLE_BLANK)
    before = _runs_entries(scene)
    d = scene.run("blank", backend=_backend())

    text = _refusal_text(d, scene)
    assert "verb-grants.yaml" in text, f"the refusal does not name the table: {text!r}"
    _assert_refused_before_anything(d, scene, before, "no query verb granted")
