from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import functools
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from defender._paths import adapters_under
from defender.runtime.verbs import read_roster
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.tenancy.alert_front_door_1222.test_1222_correlation_endings import (
    _alert,
    _backend,
    _fail_alerts,
    _q,
    _Scene,
)
from defender.tests.tenancy.alert_front_door_1222.test_1256_down_at_start import (  # noqa: F401 — the fixture is used by name
    _CMDB_LEAD,
    _CMDB_QUERY,
    _PLANTED_CMDB,
    BROKEN_MARK,
    PLANTED_CALLS,
    TABLE_THREE,
    _drop,
    _import_state_restored,
    _names_system,
    _planted_calls,
    _planted_tree,
    _tree_with_broken_elastic,
)
from defender.tests.e2e import _replay_harness as RH

#: The key the escaped fault names (its reason), seen nowhere else in the run.
LIVE_KEY = "ELASTIC_FD1256_LIVE_KEY"


def _escape() -> BaseException:
    """A call-time `ConfigFault` elastic's start check did not raise (O-5b): its `config.env` is
    complete, and this call's adapter finds a key it needs unset."""
    return S.sym("integrations.faults", "ConfigFault")(
        f"{LIVE_KEY} is not set - this tenant's settings do not configure this system")


def _down_lines(text: str, system: str, token: str) -> list[str]:
    """The lines of `text` naming `system` (as a word) as not configured with the reason's
    `token` beside it — how O-3's views show a down system (the reason on the system's line)."""
    return [ln for ln in text.splitlines()
            if _names_system(ln, system) and "not configured" in ln.lower() and token in ln]


def _outside_correlation(opening: str) -> str:
    """MAIN's opening message less its ONE correlation section: the correlation section names a
    lead-zero system's cause (D5, O-6) and never its reason, so the workspace view's status lines
    are read everywhere else."""
    head, body = S.correlation_section(opening)
    section = head + body
    assert opening.count(section) == 1, "the correlation section is not one contiguous span"
    return opening.replace(section, "")


def test_a_system_downed_during_lead_zero_is_shown_down_to_main_and_to_the_first_lead(
        tmp_path: Path) -> None:
    """r4 "one judgement per run": every surface reads the run state's current status when it is rendered. Elastic passes its start check, so l-00c is dispatched; its call raises a ConfigFault (O-5b) and elastic is Down(NotConfigured) from then on. MAIN's opening message — built after lead zero — shows elastic as not configured with the escaped fault's reason on its line (outside the correlation section, which names the cause only), and so does the system index of the first lead MAIN dispatches (on cmdb). A copy of the statuses taken at run start says elastic is up: red. Red at base, which has no statuses."""
    scene = _Scene(tmp_path)
    d = scene.run("live-status", backend=_fail_alerts(_escape),
                  main=[S.gather("l-001", "cmdb", goal="FD1256 who is web-1"), S.text(S.DONE)],
                  leads={S.L3: [_q(1), S.text("FD1256-LIVE-NARRATION")],
                         "l-001": [S.text("Summary: FD1256 measured cmdb.")]})

    assert d.router.dispatched(S.L3), (
        "premise: l-00c was not dispatched — elastic did not pass its start check")
    assert len(d.backend.rec.calls) == 1, (
        f"premise: l-00c's one elastic call did not reach the verb: {d.backend.rec.verbs}")
    assert d.router.dispatched("l-001"), (
        f"premise: MAIN's cmdb lead never ran (MAIN requests: {d.main.requests})")

    view = _outside_correlation(d.opening_message)
    assert _down_lines(view, "elastic", LIVE_KEY), (
        f"MAIN's opening view does not show elastic as not configured with its reason "
        f"({LIVE_KEY}) though lead zero downed it before the view was built (r4: surfaces read "
        f"the current status, not a copy taken at start):\n{view}")
    index = _index_of(d, "l-001")
    assert _down_lines(index, "elastic", LIVE_KEY), (
        f"the system index of the first lead MAIN dispatched does not show elastic as not "
        f"configured with its reason ({LIVE_KEY}) (r4):\n{index}")


def _index_of(d: S.Drive, lead_id: str) -> str:
    """What lead `lead_id` was shown at its start: its instructions and its first prompt (gather's
    system index is in one of them)."""
    return d.router.instructions(lead_id) + "\n" + d.router.first_prompt(lead_id)


#: The key cmdb's escaped fault names (its reason): no other text in the run carries it.
CMDB_LIVE_KEY = "FD1256_INVENTORY_LIVE_KEY"


def _cmdb_escape() -> BaseException:
    """A call-time `ConfigFault` cmdb's start check did not raise (O-5b)."""
    return S.sym("integrations.faults", "ConfigFault")(
        f"{CMDB_LIVE_KEY} is not set - this tenant's settings do not configure this system")


def test_a_system_downed_by_a_main_lead_is_shown_down_in_the_next_leads_index(
        tmp_path: Path) -> None:
    """r4: every surface reads the run state's current status when it is rendered — not a copy taken at start, nor one taken when MAIN's opening was built. Every system passes its start check and lead zero downs nothing. MAIN dispatches l-001 on cmdb, whose call raises a ConfigFault (O-5b): cmdb is Down(NotConfigured) from then on. MAIN then dispatches l-002 on elastic, and l-002's system index shows cmdb as not configured with the escaped fault's reason on its line. Non-vacuity: l-001's own index, rendered while cmdb was up, does not — so the index is read at each dispatch, not a list of every system ever down. Red at base, which has no statuses."""
    scene = _Scene(tmp_path, tenant_id=fixture_uuid("tenant:acme-live-later"))
    d = scene.run("live-later",
                  backend=_backend(fault=T.Fault(fail_on=("cmdb.get-host",)), exc=_cmdb_escape),
                  main=[S.gather("l-001", "cmdb", goal="FD1256 who is web-1"),
                        S.gather("l-002", "elastic", goal="FD1256 what else fired on web-1"),
                        S.text(S.DONE)],
                  leads={"l-001": [S.query("cmdb", "get-host", {"host": "web-1"}),
                                   S.text("Summary: FD1256 cmdb could not say.")],
                         "l-002": [S.text("Summary: FD1256 measured elastic.")]})

    assert "cmdb.get-host" in d.backend.rec.verbs, (
        f"premise: l-001's cmdb call never reached the verb: {d.backend.rec.verbs}")
    assert d.router.dispatched("l-002"), (
        f"premise: MAIN's elastic lead never ran (MAIN requests: {d.main.requests})")
    assert not _down_lines(_index_of(d, "l-001"), "cmdb", CMDB_LIVE_KEY), (
        "premise: l-001's index, rendered before cmdb's call escaped, already shows cmdb down "
        "with the reason its call had not yet raised")
    index = _index_of(d, "l-002")
    assert _down_lines(index, "cmdb", CMDB_LIVE_KEY), (
        f"the system index of the lead MAIN dispatched after cmdb went down does not show cmdb as "
        f"not configured with its reason ({CMDB_LIVE_KEY}) (r4: every surface reads the current "
        f"status when it is rendered, not a copy taken earlier):\n{index}")


class _ProbingMain(S.MainScript):
    """MAIN's double, probing the run before it answers each request: `probed[i]` is what
    `probe()` saw when request i+1 arrived — for request 2, the moment MAIN reads its first
    dispatch's answer."""

    __name__ = "_ProbingMain"

    def __init__(self, turns: list[S.Turn], probe: Any) -> None:
        super().__init__(turns)
        self._probe = probe
        self.probed: list[Any] = []

    def __call__(self, messages: Any, info: Any) -> Any:
        self.probed.append(self._probe())
        return super().__call__(messages, info)


#: The two goals one lead id is dispatched with: on the system under test, then on cmdb.
GOAL_FIRST = "FD1256-GOAL-FIRST measure the system under test"
GOAL_AGAIN = "FD1256-GOAL-AGAIN who is web-1 on cmdb"


def _claim_scene(scene: _Scene, label: str, system: str, *,
                 l00c: list[S.Turn] | None = None, **kw: Any) -> tuple[S.Drive, _ProbingMain]:
    """MAIN dispatches `l-001` on `system`, then `l-001` again on cmdb, then stops. The lead's
    conversation (whichever dispatch opens it) answers with one summary; `l00c` scripts lead
    zero (its default makes no call). The probe lists the leads-table rows of `l-001` under the
    scene's runs base (one run per scene)."""
    runs = location_path(scene.tenant.runs)

    def probe() -> list[str]:
        return sorted(str(p) for p in runs.glob("*/gather_raw/l-001.lead.json"))

    main = _ProbingMain([S.gather("l-001", system, goal=GOAL_FIRST),
                         S.gather("l-001", "cmdb", goal=GOAL_AGAIN), S.text(S.DONE)], probe)
    leads: dict[str, list[S.Turn]] = {"l-001": [S.text("Summary: FD1256 one lead.")]}
    if l00c is not None:
        leads[S.L3] = l00c
    d = scene.run(label, main=main, leads=leads, **kw)
    return d, main


def _first_answer(d: S.Drive) -> str:
    """What MAIN was answered for its first dispatch: the tool returns of its second request."""
    assert d.main.requests >= 2, f"MAIN was never asked after its first dispatch ({d.main.requests})"
    return "\n".join(d.main.seen[1].tool_returns)


def _assert_gate_before_claim(d: S.Drive, main: _ProbingMain, system: str, what: str, *,
                              said: tuple[str, ...] = ("not configured",),
                              unsaid: tuple[str, ...] = ()) -> None:
    """The refused dispatch left no lead record when MAIN read its refusal, did not consume the
    id (the second dispatch claimed it and ran on cmdb), and was refused for its system's down
    cause: the refusal names the system and carries each of `said` (the cause's words, or its
    reason), and none of `unsaid` (another cause's words, DP4)."""
    assert len(main.probed) >= 2, f"{what}: MAIN was never asked after its first dispatch"
    assert main.probed[1] == [], (
        f"{what}: the dispatch of l-001 to {system}, which is down, wrote a lead record before "
        f"MAIN read its refusal (r4: the down gate comes before the lead claim): {main.probed[1]}")
    assert d.has_sidecar("l-001"), (
        f"{what}: l-001 dispatched again on cmdb was never claimed: {_first_answer(d)!r}")
    goal = str(d.sidecar("l-001").get("goal"))
    assert GOAL_AGAIN in goal, (
        f"{what}: l-001's lead record is not the second dispatch's (the refused dispatch "
        f"consumed the id): goal={goal!r}")
    assert GOAL_FIRST not in goal, (
        f"{what}: l-001's lead record carries the refused dispatch's goal: {goal!r}")
    assert re.search(r"(?m)^system: cmdb$", d.router.dispatch_block("l-001")), (
        f"{what}: l-001's conversation is not the cmdb dispatch's:\n"
        f"{d.router.dispatch_block('l-001')}")
    answer = _first_answer(d)
    assert _names_system(answer, system), (
        f"{what}: the refusal MAIN got for its dispatch to {system} does not name it (O-4): "
        f"{answer!r}")
    missing = [w for w in said if w.lower() not in answer.lower()]
    assert not missing, (
        f"{what}: the refusal MAIN got for its dispatch to {system} does not carry {missing} — "
        f"its down cause (O-4): {answer!r}")
    wrong = [w for w in unsaid if w.lower() in answer.lower()]
    assert not wrong, (
        f"{what}: the refusal MAIN got for its dispatch to {system} names another cause "
        f"({wrong}) (DP4): {answer!r}")


def test_a_dispatch_to_a_system_down_at_start_claims_no_lead_id(tmp_path: Path) -> None:
    """r4: the down gate comes before the lead claim. Identity misses a key its adapter requires, so it is down at start; MAIN dispatches l-001 on it and is refused — and when MAIN reads that refusal no lead record for l-001 exists. The id is not consumed: MAIN's next dispatch of l-001, on cmdb, is claimed (its goal is the lead record's) and runs. Control, the same script with identity configured: the first dispatch's record is there when MAIN reads its answer, and the second dispatch of the claimed id is not (the lead record keeps the first goal) — so both channels can show a claim. Red at base, which has no down gate."""
    configured = _Scene(tmp_path, tenant_id=fixture_uuid("tenant:acme-claim-up"), table=TABLE_THREE)
    control, control_main = _claim_scene(configured, "claim-up", "identity")
    assert len(control_main.probed) >= 2, (
        f"control: MAIN was never asked after its first dispatch ({control_main.probed})")
    assert control_main.probed[1], (
        "control: with identity configured, its dispatch's lead record was not there when MAIN "
        f"read the answer (probed: {control_main.probed})")
    kept = str(control.sidecar("l-001").get("goal"))
    assert GOAL_FIRST in kept, (
        f"control: a claimed id was claimed again by the second dispatch: goal={kept!r}")

    scene = _Scene(tmp_path, tenant_id=fixture_uuid("tenant:acme-claim-down"), table=TABLE_THREE)
    _drop(scene, "identity", "IDENTITY_URL_BASE")
    d, main = _claim_scene(scene, "claim-down", "identity")
    _assert_gate_before_claim(d, main, "identity", "identity down at start")


def test_a_dispatch_to_a_system_downed_mid_run_claims_no_lead_id(tmp_path: Path) -> None:
    """r4: the same gate for a system that went down during the run. Elastic passes its start check; l-00c's call raises a ConfigFault (O-5b), so elastic is down before MAIN's first turn. MAIN dispatches l-001 on elastic and is refused with no lead record written by the time it reads the refusal, and the id stays free for its next dispatch, on cmdb. Red at base."""
    scene = _Scene(tmp_path, tenant_id=fixture_uuid("tenant:acme-claim-mid"))
    d, main = _claim_scene(scene, "claim-mid", "elastic", backend=_fail_alerts(_escape),
                           l00c=[_q(1), S.text("FD1256-MID-NARRATION")])
    assert d.router.dispatched(S.L3), (
        "premise: l-00c was not dispatched — elastic did not pass its start check")
    _assert_gate_before_claim(d, main, "elastic", "elastic downed during lead zero")


@pytest.mark.usefixtures("_import_state_restored")
def test_a_dispatch_to_a_system_whose_adapter_is_broken_claims_no_lead_id(tmp_path: Path) -> None:
    """r4: the same gate for the other down cause. The run reads a planted tree whose elastic adapter cannot be imported (`roster=`, so run start judges the roster the run reads): elastic is Down(AdapterBroken) from the start. MAIN dispatches l-001 on elastic and is refused — naming elastic and the adapter's reason, neither 'not configured' nor 'tripped' (O-5a, DP4), and no host path — with no lead record written by the time it reads the refusal; the id stays free for its next dispatch, on cmdb (the planted, well-formed one). Red at base, which has no down gate."""
    scene = _Scene(tmp_path, tenant_id=fixture_uuid("tenant:acme-claim-broken"))
    tree = _tree_with_broken_elastic(tmp_path / "planted")
    d, main = _claim_scene(scene, "claim-broken", "elastic", defender_dir=tree,
                           backend=_backend(), roster=read_roster(adapters_under(tree)))
    _assert_gate_before_claim(d, main, "elastic", "elastic's adapter broken at start",
                              said=(BROKEN_MARK,), unsaid=("not configured", "tripped"))
    leaked = S.host_paths_in(_first_answer(d), tmp_path, tmp_path.resolve(), tree,
                             scene.tenant.root, S.DEFENDER, S.REPO_ROOT)
    assert not leaked, f"the refusal MAIN got for its dispatch to elastic carries {leaked}"


#: Where the planted checks log each call they answer: `<root>/checks.log`, beside the tree.
CHECKS = "checks.log"
#: What a planted check raises when it is asked a second time in one run.
SECOND = "FD1256-SECOND-JUDGEMENT"

#: A settings check that logs each call and answers "usable" the first time it is asked, and
#: "not configured" every later time: a second judgement in the same run disagrees with the first.
_COUNTED_CHECK = '''\
def check_settings(*_a, **_k):
    log = Path(__file__).parents[3] / "{checks}"
    seen = log.read_text(encoding="utf-8").split() if log.is_file() else []
    with open(log, "a", encoding="utf-8") as out:
        print("{system}", file=out)
    if "{system}" in seen:
        from defender.integrations.faults import ConfigFault
        raise ConfigFault("{second}: {system} was judged a second time in one run")
    return None
'''


def _counted(system: str) -> str:
    return _COUNTED_CHECK.format(checks=CHECKS, system=system, second=SECOND)


_NO_CHECK = "def check_settings(*_a, **_k):\n    return None\n"

_COUNTED_CMDB = _PLANTED_CMDB.replace(_NO_CHECK, _counted("cmdb"))

#: A planted elastic with the real verbs' signatures (run.py's lead-zero agreement check reads the
#: checkout's declared `alerts`; the driver dispatches l-00c on this one).
_COUNTED_ELASTIC = f'''\
"""#1256 planted: an elastic adapter whose settings check counts its calls."""
from pathlib import Path


def _record_planted_call(verb):
    with open(Path(__file__).parents[3] / "{PLANTED_CALLS}", "a", encoding="utf-8") as log:
        print(f"elastic.{{verb}}", file=log)


{_counted("elastic")}

def _search(ctx, *, native_query: str, start=None, end=None, limit: int = 20, index=None,
            sort: str = "desc") -> dict:
    _record_planted_call("search")
    return {{"hits": [], "planted": True}}


def esql(ctx, *, query: str) -> dict:
    _record_planted_call("esql")
    return {{"values": [], "planted": True}}


def health_check(ctx) -> dict:
    _record_planted_call("health-check")
    return {{"ok": True, "planted": True}}


VERBS = {{"health-check": health_check, "query": _search, "alerts": _search, "esql": esql}}
'''


class _UnboxedStart:
    """The lifecycle's `start_box` seam: no container — the unboxed executor, as `drive` uses."""

    def __call__(self, *_a: Any, **_k: Any) -> Any:
        from defender import box as box_mod

        return box_mod.unboxed_executor()


def _run_main_over(tree: Path, tmp_path: Path, tenant: S.Planted, *, main: S.MainScript,
                   router: S.LeadRouter) -> dict[str, Any]:
    """`run.main` over `tree`: run start judges the roster it is handed (`roster=`, as N1's arm
    does), and the lifecycle is production's own, its tree swapped for `tree` (so the driver's
    roster is `tree`'s too), its box unboxed, its last step the real driver over the replay
    doubles (`investigate_as_handed`). Returns rc / raised / the refusal."""
    run_py = S.mod("run")
    final = RH.investigate_as_handed(main, router)
    investigate = functools.partial(run_py._drive_investigation, investigate=final)

    def lifecycle(**kw: Any) -> dict:
        kw["defender_dir"] = tree
        return run_py._run_investigation_lifecycle(
            **kw, investigate=investigate, start_box=_UnboxedStart(),
            stop_box=lambda *_a, **_k: None, scrub=lambda *_a, **_k: None)

    alert = S.operator_input(tmp_path)
    alert.parent.mkdir(parents=True, exist_ok=True)
    alert.write_bytes(S.alert_bytes(_alert()))
    argv = [str(alert), "--tenant", tenant.tenant_id, "--no-learn"]
    out: dict[str, Any] = {"rc": None, "raised": None, "refusal": None}
    from defender.tests.support.tenancy._launch_publish_p4 import in_process_publish

    try:
        out["rc"] = run_py.main(
            argv, lifecycle=lifecycle, preflight=lambda *_a, **_k: 0,
            visualize=lambda *_a, **_k: None, ticket_writer=S.NoTicket(),
            enqueue=lambda *_a, **_k: False, roster=read_roster(adapters_under(tree)),
            # #1108 P4 (OD14, O11): the in-process launch-time publish.
            publish=in_process_publish())
    except SystemExit as exit_:
        out["refusal"] = exit_.code
    except Exception as e:  # noqa: BLE001 — kept for the assertions to name
        out["raised"] = e
    return out


@pytest.mark.usefixtures("_import_state_restored")
def test_each_granted_system_is_judged_once_per_run_and_that_verdict_is_the_runs(
        tmp_path: Path) -> None:
    """r4 "one judgement per run": run.py judges the systems before the run folder exists and hands the result to the run; the driver judges only when started without one. Through `run.main` (handed the planted roster) and production's own lifecycle chain, each granted system's `check_settings` runs exactly once in the run. Each planted check answers "usable" the first time and "not configured" every later time, so a second judgement disagrees with run.py's — and run.py's verdict is the run's: the run is not refused or crashed after its folder exists, MAIN plays its whole script, the cmdb lead's call reaches the planted verb, and nothing MAIN or the lead is shown carries the second judgement. Red at base, where nothing calls a check."""
    assert _COUNTED_CMDB != _PLANTED_CMDB, "premise: the planted cmdb's check moved"
    root = tmp_path / "planted"
    tree = _planted_tree(root, {"cmdb": _COUNTED_CMDB, "elastic": _COUNTED_ELASTIC})
    tenant = S.plant_tenant(fixture_uuid("tenant:acme-judged-once"), alert_mapping=S.DEFAULT_MAPPING,
                            table=S.TABLE_ELASTIC)
    main = S.MainScript([S.Turn(tool_calls=(_CMDB_LEAD,)), S.text(S.DONE)])
    router = S.LeadRouter({"l-001": [S.Turn(tool_calls=(_CMDB_QUERY,)),
                                     S.text("Summary: FD1256 asked cmdb who web-1 is.")]})
    out = _run_main_over(tree, tmp_path / "run", tenant, main=main, router=router)

    log = root / CHECKS
    judged = Counter(log.read_text(encoding="utf-8").split()) if log.is_file() else Counter()
    assert judged == Counter({"cmdb": 1, "elastic": 1}), (
        f"each granted system's settings check must run exactly once per run (r4: run.py judges "
        f"once and hands the result to the run): {dict(judged)} (rc={out['rc']!r}, "
        f"raised={out['raised']!r}, refusal={out['refusal']!r})")
    assert out["raised"] is None, f"the run crashed under run.py's verdict (all usable): {out}"
    assert out["refusal"] is None, f"the run was refused though run.py found all usable: {out}"
    assert out["rc"] == 0, f"the run did not end cleanly under run.py's verdict: {out}"
    assert main.requests == 2, (
        f"MAIN played {main.requests} of its 2 turns — the run did not go on under run.py's "
        "verdict")
    assert "cmdb.get-host" in _planted_calls(root), (
        f"the cmdb lead's call never reached the planted verb (calls: {_planted_calls(root)}) — "
        "the run judged cmdb down after run.py found it usable")
    shown = [main.opening_message, router.instructions("l-001"), router.first_prompt("l-001")]
    assert not [t for t in shown if SECOND in t], (
        "a second, disagreeing judgement reached what MAIN or the lead was shown")
