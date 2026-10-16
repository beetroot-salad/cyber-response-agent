"""#1256 slice C — a granted system down at run start, seen by lead zero (O-6) and by run start
(O-8).

The design (#1256 r3): each granted system's adapter judges, at run start, whether the run's
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
system granted nothing but its health check, though up, does not save the run. O-8 is a RUN-start
refusal only (D4): `tenant.py setup` adopts a tenant whose every system is down (setup judges
structure and grants; settings content may be filled in later), and its runs are refused. Two
arms discriminate HOW run start judges "down": one whose systems are down only for keys no
`load_config` reads (the adapters' declared checks, not a load_config/stored-fault pre-check),
one mixing a broken adapter with a not-configured one (a broken adapter is down too).

D5 (r4) — a `ConfigFault` escaping during l-00c (O-5b) still downs its system on the spot,
uncharged; a lead that has written a usable summary keeps it — a summary written beside the call
that escaped counts even when the lead's last turn is empty (D5 as written, confirmed in r4 review) — and
MAIN gets it with a host note naming the system and the cause (never the fault text, #1222 A2); a
lead that ends with no summary takes the `down_mid_lead` ending, told apart by its correlation
section.

HOW EACH IS SEEN. Every scenario goes through the production front door (`S.run_alert`: the real
`run.main`, the real driver behind `_ReplayLifecycle`), with the REAL adapters under the checkout
judging the planted tenant's settings (K2) — except where an adapter must be broken: those
arms point run start at a planted tree holding only the test's own adapters (`_planted_tree`),
the adapter-broken O-6 arm and one mixed O-8 arm through the driver's `defender_dir`, and the
other mixed O-8 arm through `run.main` handed the planted tree's roster (`run.main(roster=…)`,
the adapters roster the run reads) — so run.py's pre-check and the driver are each held to
judging a broken adapter down (see the mixed arms' docstrings). A system is made unusable the way an operator would:
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
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from defender._paths import adapters_under
from defender.runtime.verbs import read_roster
from defender.scripts import policy_cli
from defender.scripts import tenant as tenant_py
from defender.tests import _tenants1106 as T6
from defender.tests import _triplet_947 as T
from defender.tests._data_root_1078 import current_data_root
from defender.tests.alert_front_door_1222 import _spec1222 as S
from defender.tests.alert_front_door_1222.test_1222_correlation_endings import (
    _alert,
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
from defender.tests.e2e import _lead_zero_808 as LZ
from defender.tests.e2e import _replay_harness as RH
from defender.tests.tenant_1107_settings import _spec1107 as S7
from defender.tests.tenant_1120_piece1 import _spec1120 as H20

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
        # A run id is case-stable (lower case: `run.py --run-id`'s rule), so the label is too.
        d = sc.run(label.replace(" ", "-").replace(".", "").lower(), **_down_lead())
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

#: A minimal, well-formed cmdb adapter: the scene's one usable gather system (TABLE_A grants
#: gather its three verbs), declaring a check that needs nothing. Written here, never copied from
#: the checkout, and importing nothing from it — so loading it touches no `sys.path`.
_PLANTED_CMDB = '''\
"""#1256 planted: a minimal cmdb adapter whose settings check needs nothing. Every verb
records its call in `planted-calls.log` at the planted tree's root."""
from pathlib import Path


def _called(verb):
    with open(Path(__file__).parents[4] / "planted-calls.log", "a", encoding="utf-8") as log:
        print(f"cmdb.{verb}", file=log)


def check_settings(*_a, **_k):
    return None


def get_host(ctx, *, host: str) -> dict:
    _called("get-host")
    return {"host": host, "planted": True, "mark": "FD1256-PLANTED-CMDB-ANSWER"}


def list_hosts(ctx, *, role=None, criticality=None, owner=None) -> dict:
    _called("list-hosts")
    return {"hosts": [], "planted": True}


def health_check(ctx) -> dict:
    _called("health-check")
    return {"ok": True, "planted": True}


VERBS = {"get-host": get_host, "list-hosts": list_hosts, "health-check": health_check}
'''


#: Where a planted adapter's verbs record each call they run: `<root>/planted-calls.log`, beside
#: (not inside) the tree `_planted_tree(root, ...)` builds.
PLANTED_CALLS = "planted-calls.log"


def _planted_calls(root: Path) -> list[str]:
    log = root / PLANTED_CALLS
    return log.read_text(encoding="utf-8").split() if log.is_file() else []


def _planted_tree(root: Path, adapters: dict[str, str]) -> Path:
    """A defender tree a run is pointed at: every top-level entry of the checkout symlinked
    except `scripts/`, whose entries are symlinked except `adapters/` — a real folder holding ONLY
    the adapters written here (`adapters`: system -> source); no shipped adapter is copied (a copy
    that bootstraps `sys.path` would leak the planted tree into later imports).
    `<root>/repo/defender`, so `defender_dir.parent` is a repo root as the catalog expects."""
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
    folder = scripts / "adapters"
    folder.mkdir()
    for system, source in adapters.items():
        (folder / f"{system.replace('-', '_')}_adapter.py").write_text(source, encoding="utf-8")
    return tree


def _tree_with_broken_elastic(root: Path) -> Path:
    """`_planted_tree` with the well-formed `_PLANTED_CMDB` and the unimportable elastic."""
    return _planted_tree(root, {"cmdb": _PLANTED_CMDB, "elastic": _BROKEN_ELASTIC})


@pytest.fixture
def _import_state_restored(tmp_path: Path) -> Iterator[None]:
    """Belt and braces around a run pointed at a planted tree: `sys.path` restored and every
    module loaded from under `tmp_path` evicted, so nothing planted is importable by a later
    test in the same worker."""
    saved = list(sys.path)
    try:
        yield
    finally:
        sys.path[:] = saved
        root = str(tmp_path.resolve())
        for name, module in list(sys.modules.items()):
            where = getattr(module, "__file__", None)
            if where and str(Path(where).resolve()).startswith(root):
                del sys.modules[name]


@pytest.mark.usefixtures("_import_state_restored")
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
    # Run start judges the tree the run reads (`roster=`, as production's one DEFENDER_DIR):
    # the lifecycle hands run.py's judgement on to the driver (r4), so it must be this tree's.
    broken = scene.run("adapter-broken", defender_dir=tree, backend=_backend(),
                       roster=read_roster(adapters_under(tree)),
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


# --- a ConfigFault escaping the start check, met by l-00c itself (O-5b, DP3, DP4) ----------------

def test_o5b_l00c_call_time_config_fault_marks_its_system_not_configured_uncharged(
        tmp_path: Path) -> None:
    """Elastic passes the start check, so l-00c is dispatched; its first call raises ConfigFault (an escape the check missed). Elastic goes down as not configured on the spot, uncharged: the lead's later calls never run the verb, MAIN's correlation section names elastic and 'not configured' — never the breaker's words (DP4), never the fault's text (#1222 A2, kept by D5) — and the breaker holds nothing for elastic or the run (DP3).

    r4 (D5): a lead that wrote a usable summary keeps it, with a note naming the cause; one that ends with no summary takes the `down_mid_lead` ending. Here every call the lead made failed or was refused and it then wrote text: whether that text is a "usable summary" (A2's classifier says a lead whose every call failed has none) the amendment does not say, so which of the two this is stays unpinned — both name elastic and 'not configured' in the section. The two unambiguous arms are the D5 tests below."""
    scene = _Scene(tmp_path)
    d = scene.run("escaped-config-fault", backend=_fail_alerts(_config_fault),
                  leads={S.L3: [_q(1), _q(2), _q(3), S.text("FD1256-ESCAPE-NARRATION")]})

    assert d.router.dispatched(S.L3), (
        "premise: l-00c was not dispatched — elastic did not pass the start check")
    calls = d.backend.rec.calls
    assert len(calls) == 1, (
        f"after elastic's first call raised ConfigFault, {len(calls)} calls reached the verb "
        "(O-5b: the system is down from that call on; its later calls run no adapter)")
    body = _section(d)
    low = body.lower()
    assert _names_system(body, "elastic"), f"the ending does not name the system: {body!r}"
    assert "not configured" in low, (
        f"the ending does not name the cause 'not configured' (DP4): {body!r}")
    said = [w for w in TRIPPED_WORDS if w in low]
    assert not said, f"the ending names the breaker's cause ({said}) for a config fault: {body!r}"
    assert "config file not found" not in low, (
        f"the correlation section carries the fault's text (#1222 A2, D5): {body!r}")
    assert d.run_state is not None, "the run left no state to read the breaker from"
    assert d.run_state.breaker_failures("elastic") == 0, (
        f"the escaped ConfigFault was charged to elastic's breaker: {d.breaker!r}")
    assert d.breaker.get("total_failures", 0) == 0, (
        f"the escaped ConfigFault was charged to the run-wide count: {d.breaker!r}")


# --- D5 (r4): a summary written before the system went down is kept, with a note --------------

#: The key the escaped fault names: elastic's `config.env` is complete, so its start check passes
#: and only this call's adapter finds the key unset (O-5b). It is the FAULT TEXT that #1222 A2
#: keeps out of the correlation section (D5: "naming the cause, not the fault text").
ESCAPE_TOKEN = "ELASTIC_FD1256_ESCAPED_KEY"
#: What the lead writes as its summary after one served call and one escaped one.
D5_SUMMARY = ("FD1256-D5-SUMMARY window 2026-05-25T13:00Z..17:00Z anchored on alert_timestamp; "
              "1 alert scoped to office-ws-1, measured before elastic went down.")


def _escape() -> BaseException:
    """A call-time `ConfigFault` the start check did not raise (O-5b), worded as the adapters word
    one: the key it needs and that the tenant's settings do not configure the system."""
    return S.sym("scripts.adapters.faults", "ConfigFault")(
        f"{ESCAPE_TOKEN} is not set - this tenant's settings do not configure this system")


def test_d5_l00c_keeps_a_usable_summary_and_main_is_told_its_system_went_down(
        tmp_path: Path) -> None:
    """D5: l-00c's first call is served; it writes its summary and, in the same response, makes a second call, which escapes the start check (ConfigFault): elastic goes Down(NotConfigured) on the spot, uncharged, and a later call never reaches the verb. The lead's summary is usable (one call succeeded, the text is not empty: A2's classifier) and was written before the system went down — and, should the lead run on, it ends on the same text. MAIN's correlation section carries that summary, framed as the lead's own text, AND a host note — outside the frame — naming elastic and the cause 'not configured'; never the fault's text (A2 stands) and never the breaker's words (DP4). Rejected by D5: ending `down_mid_lead` and discarding the summary. Red at base, which delivers the summary with no note.

    The summary is written both beside the escaping call and as the lead's last text, so this arm holds whether an implementation stops the lead at the escape or lets it run to its own end. That a summary written beside the escaping call counts even when the lead's last turn is empty is the next arm's (D5 as written, confirmed in r4 review)."""
    scene = _Scene(tmp_path)
    written_then_escaped = S.Turn(text=D5_SUMMARY, tool_calls=_q(2).tool_calls)
    d = scene.run("d5-summary", backend=_backend(fault=T.Fault(raise_after=1), exc=_escape),
                  leads={S.L3: [_q(1), written_then_escaped, _q(3), S.text(D5_SUMMARY)]})

    assert d.router.dispatched(S.L3), (
        "premise: l-00c was not dispatched — elastic did not pass the start check")
    body = _section(d)
    framed = [b for b in S.outer_frames(body) if D5_SUMMARY in b]
    assert framed, (
        "the usable summary l-00c wrote is not framed in MAIN's correlation section (D5: it is "
        f"kept, not discarded for a `down_mid_lead` ending): {body!r}")
    note = S.harness_text(body)
    assert _names_system(note, "elastic"), (
        f"no host note beside the summary names elastic (D5: MAIN is told the system went down "
        f"during the lead): {note!r}")
    assert "not configured" in note.lower(), (
        f"the host note beside the summary does not name the cause 'not configured' (D5): "
        f"{note!r}")
    assert ESCAPE_TOKEN not in body, (
        f"the correlation section carries the escaped fault's text (D5, #1222 A2): {body!r}")
    said = [w for w in TRIPPED_WORDS if w in note.lower()]
    assert not said, f"the note names the breaker's cause ({said}) for a config fault: {note!r}"
    calls = d.backend.rec.calls
    assert len(calls) == 2, (
        f"{len(calls)} of l-00c's calls reached the verb; after its second escaped, elastic is "
        "down (O-5b) and its third must run no adapter")
    assert d.run_state is not None, "the run left no state to read the breaker from"
    assert d.run_state.breaker_failures("elastic") == 0, (
        f"the escaped ConfigFault was charged to elastic's breaker: {d.breaker!r}")
    assert d.breaker.get("total_failures", 0) == 0, (
        f"the escaped ConfigFault was charged to the run-wide count: {d.breaker!r}")


def test_d5_l00c_keeps_a_summary_written_beside_the_escape_though_its_last_turn_is_empty(
        tmp_path: Path) -> None:
    """D5, as written ("if the lead has written a usable summary, MAIN receives that summary"; its rejected alternative "discards evidence already gathered") and as confirmed in r4 review: a usable summary the lead wrote beside the call that escaped counts even when the lead's last turn is empty. l-00c's first call is served; its next response carries its summary AND a second call, which raises a ConfigFault the start check missed (O-5b); its last turn is empty. MAIN's correlation section carries that summary, framed as the lead's own text, and a host note outside the frame naming elastic and 'not configured' — not the `down_mid_lead` ending, which is for a lead that wrote no summary; never the fault's text (A2) or the breaker's words (DP4). Elastic is down from the escape, uncharged. Red at base, which names the lead's empty turn `dispatch_raised` and discards the summary."""
    scene = _Scene(tmp_path)
    written_then_escaped = S.Turn(text=D5_SUMMARY, tool_calls=_q(2).tool_calls)
    d = scene.run("d5-empty-end", backend=_backend(fault=T.Fault(raise_after=1), exc=_escape),
                  leads={S.L3: [_q(1), written_then_escaped, S.EMPTY_OUTPUT]})

    assert d.router.dispatched(S.L3), (
        "premise: l-00c was not dispatched — elastic did not pass the start check")
    calls = d.backend.rec.calls
    assert len(calls) == 2, (
        f"premise: {len(calls)} of l-00c's calls reached the verb — the first served, the second "
        "escaping")
    body = _section(d)
    framed = [b for b in S.outer_frames(body) if D5_SUMMARY in b]
    assert framed, (
        "the usable summary l-00c wrote beside the call that escaped is not framed in MAIN's "
        "correlation section because the lead's last turn was empty (D5: a lead that has written "
        f"a usable summary keeps it; the evidence already gathered is not discarded): {body!r}")
    note = S.harness_text(body)
    assert _names_system(note, "elastic"), (
        f"no host note beside the summary names elastic (D5): {note!r}")
    assert "not configured" in note.lower(), (
        f"the host note beside the summary does not name the cause 'not configured' (D5): "
        f"{note!r}")
    assert ESCAPE_TOKEN not in body, (
        f"the correlation section carries the escaped fault's text (D5, #1222 A2): {body!r}")
    said = [w for w in TRIPPED_WORDS if w in note.lower()]
    assert not said, f"the note names the breaker's cause ({said}) for a config fault: {note!r}"
    assert d.run_state is not None, "the run left no state to read the breaker from"
    assert d.run_state.breaker_failures("elastic") == 0, (
        f"the escaped ConfigFault was charged to elastic's breaker: {d.breaker!r}")
    assert d.breaker.get("total_failures", 0) == 0, (
        f"the escaped ConfigFault was charged to the run-wide count: {d.breaker!r}")


def test_d5_l00c_with_no_summary_after_its_system_went_down_ends_down_mid_lead(
        tmp_path: Path) -> None:
    """D5's other arm: l-00c's first call escapes the start check (ConfigFault), elastic goes down on the spot, uncharged, and the lead then writes nothing — it ends with no summary, which is the `down_mid_lead` ending: MAIN's correlation section names elastic and 'not configured', carries no framed lead output, never the fault's text or the breaker's words, and is none of the other endings' sections — 'empty output' (a lead that wrote nothing on a working system), 'every call failed', 'tripped breaker', or 'down at start' (O-6). The constant's name is not pinned (K4's one type-level pin is O-6's); the section is the observable. Red at base, whose sentence for this lead names no system.

    Read as D5 is written: an escape during the lead ends it `down_mid_lead` unless the lead has written a usable summary (the rejected alternative was `down_mid_lead` always), so the lead's empty answer after the escape — whether it stops the lead or is retried and fails — is no summary, and the ending is `down_mid_lead`, not another no-summary ending."""
    scene = _Scene(tmp_path)
    empty = scene.run("empty-reference", leads={S.L3: [S.EMPTY_OUTPUT]})
    ecf = scene.run("ecf-reference", backend=_fail_alerts(S.upstream_fault),
                    leads={S.L3: [_q(1), S.text("FD1256-ECF-NARRATION")]})
    tripped = scene.run("tb-reference", before=_pre_trip(),
                        leads={S.L3: [_q(1), S.text("FD1256-TB-NARRATION")]})
    unconfigured = _Scene(tmp_path, tenant_id="acme-down-url")
    _drop(unconfigured, "elastic", "ELASTICSEARCH_URL")
    at_start = unconfigured.run("down-at-start", **_down_lead())
    d = scene.run("d5-no-summary", backend=_fail_alerts(_escape),
                  leads={S.L3: [_q(1), S.EMPTY_OUTPUT]})

    body = _section(d)
    low = body.lower()
    assert _names_system(body, "elastic"), (
        f"l-00c ended with no summary after elastic went down, and its section does not name "
        f"elastic (D5: `down_mid_lead` names the cause): {body!r}")
    assert "not configured" in low, (
        f"the section does not name the cause 'not configured' (D5, DP4): {body!r}")
    assert ESCAPE_TOKEN not in body, (
        f"the correlation section carries the escaped fault's text (D5, #1222 A2): {body!r}")
    said = [w for w in TRIPPED_WORDS if w in low]
    assert not said, f"the section names the breaker's cause ({said}): {body!r}"
    assert S.outer_frames(body) == [], (
        f"the section frames lead output though the lead wrote none: {S.outer_frames(body)}")
    for label, ref in (("empty output", empty), ("every call failed", ecf),
                       ("tripped breaker", tripped), ("down at start", at_start)):
        assert body != _section(ref), (
            f"l-00c that ended with no summary after its system went down gets the {label!r} "
            f"section: {body!r}")
    assert len(d.backend.rec.calls) == 1, (
        f"{len(d.backend.rec.calls)} calls reached the verb; one escaped and the lead made one")
    assert d.run_state is not None, "the run left no state to read the breaker from"
    assert d.run_state.breaker_failures("elastic") == 0, (
        f"the escaped ConfigFault was charged to elastic's breaker: {d.breaker!r}")
    assert d.breaker.get("total_failures", 0) == 0, (
        f"the escaped ConfigFault was charged to the run-wide count: {d.breaker!r}")


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


def _runs_entries(tenant: S.Planted) -> list[str]:
    base = tenant.runs
    return sorted(p.name for p in base.iterdir()) if base.is_dir() else []


def _refusal_text(d: S.Drive, tenant: S.Planted) -> str:
    """The refusal `run.main` exited with, the data root spelled out of it (a host path could
    spell a system's name by accident)."""
    assert isinstance(d.refusal, str), (
        f"the run was not refused at start: rc={d.rc!r} raised={d.raised!r} "
        f"MAIN requests={d.main.requests} summary={d.summary!r}")
    assert d.refusal.strip(), "the refusal carries no text"
    return d.refusal.replace(str(tenant.root), "<DATA_ROOT>")


def _assert_refused_before_anything(d: S.Drive, tenant: S.Planted, before: list[str],
                                    what: str) -> None:
    """Refused as the existing start refusals are: a non-zero exit carrying the text, before the
    run folder, the box, any model call or any adapter call."""
    assert d.rc not in (0, None), f"{what}: the refusal exited {d.rc!r}"
    assert d.main.requests == 0, f"{what}: MAIN was asked {d.main.requests} times before refusal"
    assert d.router.leads() == [], f"{what}: a gather model ran: {d.router.leads()}"
    assert d.backend.rec.calls == [], f"{what}: an adapter ran: {d.backend.rec.verbs}"
    assert d.lifecycle_calls == [], f"{what}: the run's lifecycle (box, driver) was started"
    assert _runs_entries(tenant) == before, (
        f"{what}: the refused run left something under the runs base: {_runs_entries(tenant)}")


def _assert_names_each(text: str, downs: tuple[tuple[str, str], ...], what: str) -> None:
    """The refusal names every down system (as a word of its own) and its reason's token, and
    never the breaker's words."""
    for system, token in downs:
        assert _names_system(text, system), (
            f"{what}: the refusal does not name the down system {system}: {text!r}")
        assert token in text, f"{what}: the refusal does not name {system}'s reason ({token}): {text!r}"
    said = [w for w in TRIPPED_WORDS if w in text.lower()]
    assert not said, f"{what}: the refusal names the breaker's cause ({said}): {text!r}"


def test_o8_every_granted_system_down_at_start_refuses_the_run_naming_each(
        tmp_path: Path) -> None:
    """A run whose every granted system fails its adapter's settings check is refused at start — before the run folder, any model call or any adapter call — and the refusal names each down system with its reason ('not configured', the missing key), never the breaker's words."""
    scene = _Scene(tmp_path, tenant_id="acme-all-down")
    _drop(scene, "cmdb", "CMDB_URL_BASE")
    _drop(scene, "elastic", "ELASTICSEARCH_URL")
    before = _runs_entries(scene.tenant)
    d = scene.run("all-down", **_down_lead())

    text = _refusal_text(d, scene.tenant)
    _assert_names_each(text, (("cmdb", "CMDB_URL_BASE"), ("elastic", "ELASTICSEARCH_URL")),
                       "every granted system down")
    assert "not configured" in text.lower(), f"the refusal does not name the cause: {text!r}"
    _assert_refused_before_anything(d, scene.tenant, before, "every granted system down")


def test_o8_a_system_up_with_only_its_health_check_granted_does_not_save_the_run(
        tmp_path: Path) -> None:
    """'Gather can query nothing', applied to the systems granted and up: with elastic down and cmdb up but granted only its health check (which reaches no data), the run is refused at start naming elastic and its reason. The same table with elastic configured runs."""
    configured = _Scene(tmp_path, tenant_id="acme-hc-up", table=TABLE_CMDB_HEALTH_ONLY)
    ran = configured.run("hc-elastic-up")
    _assert_continued(ran, "premise: the health-check-only table with elastic configured")

    scene = _Scene(tmp_path, tenant_id="acme-hc-down", table=TABLE_CMDB_HEALTH_ONLY)
    _drop(scene, "elastic", "ELASTICSEARCH_URL")
    before = _runs_entries(scene.tenant)
    d = scene.run("hc-elastic-down", **_down_lead())

    text = _refusal_text(d, scene.tenant)
    assert _names_system(text, "elastic"), f"the refusal does not name the down system: {text!r}"
    assert "ELASTICSEARCH_URL" in text, f"the refusal does not name elastic's reason: {text!r}"
    assert "not configured" in text.lower(), f"the refusal does not name the cause: {text!r}"
    _assert_refused_before_anything(d, scene.tenant, before, "only a health check up")


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
    before = _runs_entries(scene.tenant)
    d = scene.run("blank", backend=_backend())

    text = _refusal_text(d, scene.tenant)
    assert "verb-grants.yaml" in text, f"the refusal does not name the table: {text!r}"
    _assert_refused_before_anything(d, scene.tenant, before, "no query verb granted")


# --- O-8, discriminating arms (each: refused naming each down system; one system repaired runs) -

def _drop_present(scene: _Scene, system: str, key: str) -> None:
    """`_drop`, after checking the key is there to drop (`drop_key` is silent on an absent key)."""
    before = S7.config_path(scene.tenant.knowledge, system).read_text(encoding="utf-8")
    assert any(ln.split("=", 1)[0].strip() == key for ln in before.splitlines()), (
        f"premise: {system}'s planted config.env carries no {key} to drop:\n{before}")
    _drop(scene, system, key)


def test_o8_all_down_through_settings_load_config_never_reads(tmp_path: Path) -> None:
    """Every granted system down for a key no `load_config` reads — cmdb misses only its docker context (the access method `access_context` checks), elastic only its ES container (`_es_container`) — is refused at start naming each with its key: the refusal is the adapters' declared checks, not a pre-check that runs `load_config` or reads stored faults. Repairing cmdb lets the same tenant run."""
    repaired = _Scene(tmp_path, tenant_id="acme-access-repaired")
    _drop_present(repaired, "elastic", "ELASTIC_ES_CONTAINER")
    ran = repaired.run("cmdb-repaired")
    _assert_continued(ran, "control: cmdb repaired, elastic still down")

    scene = _Scene(tmp_path, tenant_id="acme-access-down")
    _drop_present(scene, "cmdb", "CMDB_DOCKER_CONTEXT")
    _drop_present(scene, "elastic", "ELASTIC_ES_CONTAINER")
    before = _runs_entries(scene.tenant)
    d = scene.run("access-down", **_down_lead())

    text = _refusal_text(d, scene.tenant)
    _assert_names_each(text, (("cmdb", "CMDB_DOCKER_CONTEXT"),
                              ("elastic", "ELASTIC_ES_CONTAINER")), "down beyond load_config")
    assert "not configured" in text.lower(), f"the refusal does not name the cause: {text!r}"
    _assert_refused_before_anything(d, scene.tenant, before, "down beyond load_config")


#: What the planted cmdb's check raises: not a ConfigFault, so cmdb is Down(AdapterBroken).
CRASH_MARK = "FD1256-PLANTED-CHECK-CRASH"
#: The planted elastic's check reason: a ConfigFault, so elastic is Down(NotConfigured).
ELASTIC_PLANTED_KEY = "ELASTIC_FD1256_PLANTED_SETTING"

_CRASHING_CMDB = _PLANTED_CMDB.replace(
    "def check_settings(*_a, **_k):\n    return None",
    f"def check_settings(*_a, **_k):\n    raise RuntimeError({CRASH_MARK!r})")

#: A planted elastic whose declared check finds it not configured, with the real verbs'
#: signatures (the correlation lead's agreement check reads the declared `alerts`).
_NOT_CONFIGURED_ELASTIC = f'''\
"""#1256 planted: an elastic adapter whose settings check finds it not configured."""
from pathlib import Path

from defender.scripts.adapters.faults import ConfigFault


def _called(verb):
    with open(Path(__file__).parents[4] / "{PLANTED_CALLS}", "a", encoding="utf-8") as log:
        print(f"elastic.{{verb}}", file=log)


def check_settings(*_a, **_k):
    raise ConfigFault("{ELASTIC_PLANTED_KEY} is not set - this tenant does not configure it")


def _search(ctx, *, native_query: str, start=None, end=None, limit: int = 20, index=None,
            sort: str = "desc") -> dict:
    _called("search")
    return {{"hits": [], "planted": True}}


def esql(ctx, *, query: str) -> dict:
    _called("esql")
    return {{"values": [], "planted": True}}


def health_check(ctx) -> dict:
    _called("health-check")
    return {{"ok": True, "planted": True}}


VERBS = {{"health-check": health_check, "query": _search, "alerts": _search, "esql": esql}}
'''


#: MAIN dispatches one lead on cmdb; its gather agent asks cmdb who web-1 is, then summarises.
_CMDB_LEAD = ("gather", {"lead_id": "l-001", "system": "cmdb", "goal": "who is web-1",
                         "what_to_summarize": ["web-1's owner"]})
_CMDB_QUERY = ("query", {"system": "cmdb", "verb": "get-host", "params": {"host": "web-1"}})


def _drive_over(tree: Path, tenant: S.Planted, where: Path) -> tuple[Any, Any, BaseException | None]:
    """One fresh run through the REAL driver (`_replay_harness.drive`) over `tree` — the tree the
    run reads, whose adapters' declared checks judge each granted system (K2) — as `tenant`.
    No registry is injected: the run's verbs are `tree`'s adapters, as production's are the
    checkout's. Returns (MAIN's fake, the gather fake, what the run raised or None)."""
    run_dir = LZ.materialize_alert(where, LZ.alert_doc())
    main = RH.ReplayFn([RH.Turn(tool_calls=[_CMDB_LEAD]), RH.Turn(text="Investigation complete.")])
    gather = RH.ReplayFn([RH.Turn(tool_calls=[_CMDB_QUERY]),
                          RH.Turn(text="Summary: asked cmdb who web-1 is.")])
    try:
        RH.drive(run_dir, run_id=run_dir.name, main=main, gather=gather, defender_dir=tree,
                 tenant=tenant.accept())
    except (Exception, SystemExit) as raised:  # noqa: BLE001 — its type is not the contract (K4)
        return main, gather, raised
    return main, gather, None


@pytest.mark.usefixtures("_import_state_restored")
def test_o8_all_down_mixing_a_broken_adapter_with_a_not_configured_one(tmp_path: Path) -> None:
    """Every granted system down for two different causes — cmdb's adapter broken (its check raises something other than ConfigFault), elastic not configured — and the run does not start: the real driver, over the tree whose roster says so (K2), raises naming each system with its reason before MAIN's first request and before any gather or adapter call. A pre-check that counts only 'not configured' as down misses cmdb and lets the run start blind. With cmdb's adapter well formed (elastic still down) the same tenant's run proceeds. The exception's type is not pinned; its site is, by composition: the run.main arms require run.py to refuse before the lifecycle, the D4 test keeps the refusal out of the resolution that setup and `defender-policy` share, and this arm requires the driver itself to refuse an all-down start (the design's flow judges statuses there). The same mixed tenant through `run.main` (handed the planted roster) is `test_o8_all_down_mixing_a_broken_adapter_with_a_not_configured_one_through_run_main`: a run.py pre-check that ignores broken adapters is caught there (N1)."""
    tenant = S.plant_tenant("acme-mixed-down", alert_mapping=S.DEFAULT_MAPPING,
                            table=S.TABLE_ELASTIC)

    repaired_root = tmp_path / "repaired"
    repaired = _planted_tree(repaired_root,
                             {"cmdb": _PLANTED_CMDB, "elastic": _NOT_CONFIGURED_ELASTIC})
    main, gather, raised = _drive_over(repaired, tenant, tmp_path / "run-repaired")
    assert raised is None, (
        f"control: with cmdb's adapter well formed (elastic still down) the run raised {raised!r}")
    assert main.seen, "control: MAIN was never asked"
    assert "cmdb.get-host" in _planted_calls(repaired_root), (
        "premise: the control's gather call never reached the planted cmdb adapter "
        f"(calls: {_planted_calls(repaired_root)}; gather saw {len(gather.seen)} requests)")

    mixed_root = tmp_path / "mixed"
    mixed = _planted_tree(mixed_root, {"cmdb": _CRASHING_CMDB, "elastic": _NOT_CONFIGURED_ELASTIC})
    main, gather, raised = _drive_over(mixed, tenant, tmp_path / "run-mixed")
    assert raised is not None, (
        "the run started though cmdb's adapter is broken and elastic not configured — every "
        f"granted system down (#1256 O-8): MAIN asked {len(main.seen)} times, gather "
        f"{len(gather.seen)}, adapter calls {_planted_calls(mixed_root)}")
    text = str(raised).replace(str(tenant.root), "<DATA_ROOT>")
    _assert_names_each(text, (("cmdb", CRASH_MARK), ("elastic", ELASTIC_PLANTED_KEY)),
                       "broken + not configured")
    assert "not configured" in text.lower(), f"the refusal does not name elastic's cause: {text!r}"
    assert main.seen == [], f"MAIN was asked {len(main.seen)} times before the refusal"
    assert gather.seen == [], f"a gather agent was asked {len(gather.seen)} times before the refusal"
    assert _planted_calls(mixed_root) == [], (
        f"an adapter verb ran before the refusal: {_planted_calls(mixed_root)}")


@pytest.mark.usefixtures("_import_state_restored")
def test_o8_all_down_mixing_a_broken_adapter_with_a_not_configured_one_through_run_main(
        tmp_path: Path) -> None:
    """N1 (adversary A2): the mixed all-down tenant through the production front door. `run.main` handed the planted tree's roster (`roster=`: the adapters roster the run reads, the one whose declared checks judge each granted system at start, K2) — cmdb's adapter broken (its check crashes), elastic not configured — refuses the run at start, before the run folder, the lifecycle, any model call or any adapter call, naming each system with its reason. With cmdb's adapter well formed (elastic still down) the same tenant passes run start and reaches its lifecycle. A run.py pre-check that counts only 'not configured' as down (or that judges a roster other than the one the run reads) lets the mixed run reach the lifecycle, where only the driver would refuse it — after its run folder and box exist."""
    tenant = S.plant_tenant("acme-mixed-main", alert_mapping=S.DEFAULT_MAPPING,
                            table=S.TABLE_ELASTIC)

    repaired_root = tmp_path / "repaired"
    repaired = _planted_tree(repaired_root,
                             {"cmdb": _PLANTED_CMDB, "elastic": _NOT_CONFIGURED_ELASTIC})
    ran = S.run_alert(tmp_path / "run-repaired", alert=_alert(), tenant=tenant,
                      backend=_backend(), defender_dir=repaired,
                      roster=read_roster(adapters_under(repaired)))
    assert ran.refusal is None, (
        f"control: with cmdb's adapter well formed (elastic still down) run start refused: "
        f"{ran.refusal!r}")
    assert ran.lifecycle_calls, (
        f"control: the run with one usable system never reached its lifecycle "
        f"(rc={ran.rc!r}, raised={ran.raised!r})")

    mixed_root = tmp_path / "mixed"
    mixed = _planted_tree(mixed_root, {"cmdb": _CRASHING_CMDB, "elastic": _NOT_CONFIGURED_ELASTIC})
    before = _runs_entries(tenant)
    d = S.run_alert(tmp_path / "run-mixed", alert=_alert(), tenant=tenant, backend=_backend(),
                    defender_dir=mixed, roster=read_roster(adapters_under(mixed)))
    text = _refusal_text(d, tenant)
    _assert_names_each(text, (("cmdb", CRASH_MARK), ("elastic", ELASTIC_PLANTED_KEY)),
                       "broken + not configured, through run.main")
    assert "not configured" in text.lower(), f"the refusal does not name elastic's cause: {text!r}"
    _assert_refused_before_anything(d, tenant, before, "broken + not configured, through run.main")
    assert _planted_calls(mixed_root) == [], (
        f"an adapter verb ran before the refusal: {_planted_calls(mixed_root)}")


# --- O-8 x D4: a run-start refusal only — setup adopts the same tenant ----------------------------

def test_o8_d4_setup_adopts_an_all_down_tenant_whose_runs_are_refused(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """D4: the tenant-management commands judge a tenant's structure (folder rules, grants, lead-zero config), not whether its systems are usable — `tenant.py setup` adopts a tenant whose every granted system fails its settings check (exit 0, its row written) and `defender-policy show gather` over it answers (exit 0) — while a run of that same tenant through `run.main` is refused at start naming each system and its reason (O-8). Rejects O-8 placed in the tenant resolution those commands share with run start (the readiness function, `run_tenant_for` / `resolve_tenant`)."""
    tenant_id = "acme-d4"
    # The operator's folder, authored outside the data root: complete (K6) but for one key per
    # granted system.
    authored = S.plant_tenant(tenant_id, root=tmp_path / "authored",
                              alert_mapping=S.DEFAULT_MAPPING, table=S.TABLE_ELASTIC)
    S7.drop_key(authored.knowledge, "cmdb", "CMDB_URL_BASE")
    S7.drop_key(authored.knowledge, "elastic", "ELASTICSEARCH_URL")
    root = current_data_root()
    H20.place_knowledge(root, tenant_id, source=authored.knowledge)

    proc = H20.setup(tenant_py, root, tenant_id)
    H20.assert_clean(proc)
    assert H20.row_path(root, tenant_id).is_file(), (
        f"setup exited 0 but wrote no row for {tenant_id}:\n{H20.output(proc)}")

    # The operator's policy audit over the adopted tenant (`defender-policy show gather`).
    policy_run = tmp_path / "policy-run"
    (policy_run / "gather_raw").mkdir(parents=True)
    capsys.readouterr()
    try:
        rc = policy_cli.main(["show", "gather", "--run-dir", str(policy_run),
                              "--tenant", tenant_id])
    except SystemExit as refused:
        pytest.fail(f"defender-policy refused a tenant whose systems are down (D4: only a run "
                    f"refuses): {refused.code!r}")
    shown = capsys.readouterr().out
    assert rc == 0, f"defender-policy show gather exited {rc!r} over an all-down tenant:\n{shown}"
    assert shown.startswith("agent: gather"), f"defender-policy showed no gather policy:\n{shown}"

    tenant = S.Planted(root=root, tenant_id=tenant_id, knowledge=H20.knowledge_dir(root, tenant_id))
    before = _runs_entries(tenant)
    d = S.run_alert(tmp_path / "run", alert=_alert(), tenant=tenant, **_down_lead())
    text = _refusal_text(d, tenant)
    _assert_names_each(text, (("cmdb", "CMDB_URL_BASE"), ("elastic", "ELASTICSEARCH_URL")),
                       "an adopted all-down tenant")
    assert "not configured" in text.lower(), f"the refusal does not name the cause: {text!r}"
    _assert_refused_before_anything(d, tenant, before, "an adopted all-down tenant")
