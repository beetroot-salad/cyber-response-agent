from __future__ import annotations

import logging
import re
import shutil
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender._frontmatter import parse_frontmatter  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender.runtime import circuit_breaker  # noqa: E402
from defender.runtime.lead_zero import RESERVED_LEAD_IDS  # noqa: E402
from defender.integrations import (  # noqa: E402
    change_mgmt_adapter,
    cmdb_adapter,
    identity_adapter,
    threat_intel_adapter,
)
from defender.integrations.faults import ConfigFault, TransportFault  # noqa: E402
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as R  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S  # noqa: E402


#: Gather holds verbs on four stub systems; no row names `lead-zero-correlation`, so the lead is
#: withheld (a legal table, `_tenants1106.TABLE_B`'s shape) and MAIN's first request is the start.
TABLE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
  identity:
    get-user: {roles: [gather]}
    health-check: {roles: [gather]}
  change-mgmt:
    health-check: {roles: [gather]}
  threat-intel:
    health-check: {roles: [gather]}
    lookup: {roles: [gather]}
"""

#: Each granted verb's keyword params, as its real adapter declares them — the fake carries the
#: real signature, which is what the query tool validates a call against.
_VERB_PARAMS: dict[str, dict[str, tuple[str, ...]]] = {
    "cmdb": {"get-host": ("host",), "health-check": ()},
    "identity": {"get-user": ("user",), "health-check": ()},
    "change-mgmt": {"health-check": ()},
    "threat-intel": {"health-check": (), "lookup": ("value",)},
}

#: The real adapter verbs (`REAL` runs them). Over an unconfigured system each raises the
#: `ConfigFault` naming what its settings lack, before any docker child (C3).
_REAL: dict[tuple[str, str], Callable[..., Any]] = {
    ("cmdb", "get-host"): cmdb_adapter.get_host,
    ("cmdb", "health-check"): cmdb_adapter.health_check,
    ("identity", "get-user"): identity_adapter.get_user,
    ("identity", "health-check"): identity_adapter.health_check,
    ("change-mgmt", "health-check"): change_mgmt_adapter.health_check,
    ("threat-intel", "health-check"): threat_intel_adapter.health_check,
    ("threat-intel", "lookup"): threat_intel_adapter.lookup,
}

REAL = "real"
OK = "ok"


def _no_docker_context(folder: Path) -> None:
    # `access_context`'s key: read on every docker call, never by `load_config` — a check that
    # covers only `load_config` judges cmdb usable (O-5 / DP3).
    S.drop_key(folder, "cmdb", "CMDB_DOCKER_CONTEXT")


def _no_url_base(folder: Path) -> None:
    # `load_config`'s required-key check.
    S.drop_key(folder, "identity", "IDENTITY_URL_BASE")


def _no_settings_folder(folder: Path) -> None:
    # No `systems/change-mgmt/` at all: the record has no entry (`system_entry`'s "config file
    # not found: ... — this tenant's settings do not configure this system").
    shutil.rmtree(S.config_path(folder, "change-mgmt").parent)


#: How each system is made unusable, and the distinctive token of the reason its adapter gives
#: (three different `ConfigFault` sites, C3). Each token is matched case-insensitively.
UNCONFIGURE: dict[str, tuple[Callable[[Path], None], str]] = {
    "cmdb": (_no_docker_context, "CMDB_DOCKER_CONTEXT"),
    "identity": (_no_url_base, "IDENTITY_URL_BASE"),
    "change-mgmt": (_no_settings_folder, "not found"),
}

#: The issue's headline: three granted systems the tenant does not configure, one it does.
THREE_DOWN = ("cmdb", "identity", "change-mgmt")
CONFIGURED = "threat-intel"


def _plant(tmp_path: Path, marker: str, down: tuple[str, ...] = ()) -> Path:
    """A complete #1107 tenant under `tmp_path/tenants` granting `TABLE`, with each system in
    `down` made unusable by its real settings file (`UNCONFIGURE`). Returns the tenants root."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker=marker, table=TABLE)
    for system in down:
        UNCONFIGURE[system][0](folder)
    return root


def _token(system: str) -> str:
    return UNCONFIGURE[system][1]


def _verbs(rec: VerbRecorder, behaviour: Mapping[str, Any]) -> FakeVerbs:
    """A `FakeVerbs` over `TABLE`'s verbs. Each call is recorded as `"<system>.<verb>"`, then
    `behaviour["<system>.<verb>"]` (else `behaviour["<system>"]`) decides it: `REAL` runs the
    real adapter verb, `OK` answers canned success, and a callable is a factory for the
    exception to raise. The fake decides nothing about usability."""

    def serve(system: str, verb: str, ctx: Any, params: dict) -> Any:
        rec.record(f"{system}.{verb}", ctx, params)
        how = behaviour.get(f"{system}.{verb}", behaviour[system])
        if how == REAL:
            return _REAL[(system, verb)](ctx, **params)
        if how == OK:
            return {"system": system, "verb": verb, "answer": "ok"}
        raise how()

    def make(system: str, verb: str) -> Callable[..., Any]:
        params = _VERB_PARAMS[system][verb]

        def no_params(ctx: Any) -> Any:
            return serve(system, verb, ctx, {})

        def host_param(ctx: Any, *, host: str) -> Any:
            return serve(system, verb, ctx, {"host": host})

        def user_param(ctx: Any, *, user: str) -> Any:
            return serve(system, verb, ctx, {"user": user})

        def value_param(ctx: Any, *, value: str) -> Any:
            return serve(system, verb, ctx, {"value": value})

        by_params = {(): no_params, ("host",): host_param, ("user",): user_param,
                     ("value",): value_param}
        return by_params[params]

    return FakeVerbs({s: {v: make(s, v) for v in verbs} for s, verbs in _VERB_PARAMS.items()})


def _transport_fault() -> BaseException:
    """The transport's own fault for an unreachable system (the class a docker failure raises)."""
    return TransportFault("docker exec curl timed out after 10s")


def dispatch(lead_id: str, system: str) -> R.Turn:
    """MAIN's `gather` tool call for one lead."""
    return R.call("gather", lead_id=lead_id, system=system, goal=f"measure {system} for this lead",
                  what_to_summarize=[f"what {system} says"])


SUMMARY = R.text("Summary: measured the lead.")


@dataclass
class _Run:
    run_dir: Path
    main: R.MainScript
    router: R.LeadRouter
    rec: VerbRecorder
    summary: dict

    @property
    def state(self) -> Any:
        """The run's `RunState` (#1235), as `drive` hands it back."""
        return self.summary["run_state"]

    @property
    def breaker(self) -> dict:
        """The whole snapshot — for failure messages only; assertions read the public
        accessors, so an implementation that records a zero entry is not judged on layout."""
        return self.state.breaker_snapshot()

    @property
    def total_failures(self) -> int:
        return self.state.breaker_snapshot()["total_failures"]

    def failures(self, *systems: str) -> dict[str, int]:
        """`breaker_failures` for each of `systems`."""
        return {s: self.state.breaker_failures(s) for s in systems}

    @property
    def rows(self) -> list[dict]:
        """The queries table, without the harness-reserved leads' rows."""
        path = self.run_dir / "executed_queries.jsonl"
        rows = read_jsonl_rows(path) if path.is_file() else []
        return [r for r in rows if r.get("lead_id") not in RESERVED_LEAD_IDS]

    def rows_for(self, system: str) -> list[dict]:
        return [r for r in self.rows if r.get("system") == system]

    def calls_to(self, system: str) -> list[str]:
        """The verbs the fake for `system` was asked to run, in order."""
        return [v for v in self.rec.verbs if v.split(".", 1)[0] == system]

    def main_answer(self, turn: int) -> str:
        """What the host answered MAIN's scripted turn `turn` with."""
        return _answer_to(self.main.seen, turn, f"MAIN's turn {turn}")

    def lead_answer(self, lead: str, turn: int) -> str:
        """What the host answered `lead`'s scripted turn `turn` with."""
        return _answer_to(self.router.seen(lead), turn, f"{lead}'s turn {turn}")

    @property
    def report_disposition(self) -> str | None:
        path = self.run_dir / "report.md"
        if not path.is_file():
            return None
        meta, _body = parse_frontmatter(path.read_text(encoding="utf-8"))
        return meta.get("disposition")


def _answer_to(seen: list, turn: int, what: str) -> str:
    """The tool-return / retry-prompt parts that arrived with the request AFTER scripted turn
    `turn` — the host's answer to that turn's tool call(s). A multiset difference, so an answer
    identical to an earlier one still counts as new."""
    assert len(seen) > turn + 1, (
        f"{what}: the double was never asked again after it ({len(seen)} requests) — the run "
        "ended before answering it")
    before = Counter(p for p in seen[turn].parts if p[0] in ("tool-return", "retry-prompt"))
    after = Counter(p for p in seen[turn + 1].parts if p[0] in ("tool-return", "retry-prompt"))
    return "\n".join(text for (_kind, text) in (after - before).elements())


def _drive(tmp_path: Path, root: Path, *, main: Any, leads: Mapping[str, list],
           behaviour: Mapping[str, Any], run_id: str = "r1256") -> _Run:
    rec = VerbRecorder()
    script = main if isinstance(main, R.MainScript) else R.MainScript(main)
    router = R.LeadRouter(leads)
    run_dir = materialize(tmp_path / "replay", GOLDEN_AB3, run_id=run_id)
    summary = drive(run_dir, run_id=run_id, main=script, gather=router,
                    verbs=_verbs(rec, behaviour), tenant=S.tenant_folder_of(root))
    return _Run(run_dir=run_dir, main=script, router=router, rec=rec, summary=summary)


def _names(text: str, system: str) -> bool:
    """`text` names `system` as a word (case-sensitive: `cmdb`, never the `CMDB_` of a key, nor
    the `cmdb-<marker>` of a host name)."""
    return re.search(rf"(?<![\w-]){re.escape(system)}(?![\w-])", text) is not None


_NOT_CONFIGURED = re.compile(r"(?i)not configured")
_DONT_DISPATCH = re.compile(
    r"(?i)\b(?:do not|don't|never|must not|should not|not to)\s+(?:be\s+)?(?:re-?)?dispatch")
_VISIBILITY_GAP = re.compile(r"(?i)visibility gap")
#: The gap denied rather than named: "is not a visibility gap", "no visibility gap".
_GAP_DENIED = re.compile(r"(?i)\b(?:not|no|never|isn't)\b(?:\s+\w+){0,2}?\s+visibility gap")
#: `name` as the instruction ("name the missing evidence", "name it") ...
_NAME = re.compile(r"(?i)\bname\b")
#: ... and denied ("nothing to name", "no need to name", "do not name").
_NAME_DENIED = re.compile(
    r"(?i)\b(?:nothing to|no need to|do not|don't|never|not)\s+(?:\w+\s+)?name\b")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+|\n+")


def _down_lines(text: str, system: str, token: str) -> list[str]:
    """The lines of `text` that name `system` as not configured, with its reason's token."""
    return [ln for ln in text.splitlines()
            if _names(ln, system) and _NOT_CONFIGURED.search(ln) and token.lower() in ln.lower()]


def _shown_down(text: str, system: str) -> list[str]:
    """The lines of `text` that name `system` together with "not configured" (the control's
    complement: a configured system must have none)."""
    return [ln for ln in text.splitlines() if _names(ln, system) and _NOT_CONFIGURED.search(ln)]


def _sections_holding(text: str, lines: list[str]) -> list[str]:
    """The markdown sections (heading to next heading) of `text` that contain any of `lines`."""
    sections: list[list[str]] = [[]]
    for ln in text.splitlines():
        if ln.lstrip().startswith("#"):
            sections.append([])
        sections[-1].append(ln)
    wanted = set(lines)
    return ["\n".join(sec) for sec in sections if wanted & set(sec)]


def _told_not_to_dispatch(section: str) -> bool:
    """O-3's instruction, read for its POLARITY, not its vocabulary: `section` prohibits
    dispatching (the prohibition's object is `dispatch`), and some sentence of it calls the down
    system a visibility gap without denying it, with the instruction to name it in that sentence
    or the next — never "nothing to name"."""
    if not _DONT_DISPATCH.search(section):
        return False
    sentences = [x for x in _SENTENCE_END.split(section) if x.strip()]
    for i, sentence in enumerate(sentences):
        if not _VISIBILITY_GAP.search(sentence) or _GAP_DENIED.search(sentence):
            continue
        near = " ".join(sentences[i:i + 2])
        if _NAME.search(near) and not _NAME_DENIED.search(near):
            return True
    return False


#: Instructions `_told_not_to_dispatch` must accept: the shapes an implementation may well write.
_TELLS: tuple[str, ...] = (
    "Do not dispatch these systems: their calls are refused. Each is a visibility gap — name the "
    "missing evidence in a `ceiling_test` row and escalate if it blocks disposition.",
    "Do NOT dispatch gather leads to them; each is a visibility gap: name it in your "
    "ceiling_test row, and escalate if it blocks the disposition.",
    "Never dispatch a system listed here. Treat each as a visibility gap.\nName the missing "
    "evidence in a ceiling_test row.",
)
#: ... and must refuse: the opposite instruction in the same vocabulary (adversary A5's own
#: sentence), and each half of the instruction inverted on its own.
_INVERTED: tuple[str, ...] = (
    "Do not hesitate to dispatch these systems as you would any other: a refusal from one is not "
    "a visibility gap, so there is nothing to name — retry it later in the run.",
    "Do not hesitate to dispatch these systems: each is a visibility gap — name the missing "
    "evidence in a ceiling_test row.",
    "Do not dispatch these systems. A refusal from one is not a visibility gap, so there is "
    "nothing to name.",
    "Do not dispatch these systems. Each is a visibility gap, but there is no need to name it.",
)


def test_the_dispatch_instruction_matcher_reads_polarity():
    for text in _TELLS:
        assert _told_not_to_dispatch(text), f"control: the instruction is not recognised: {text!r}"
    for text in _INVERTED:
        assert not _told_not_to_dispatch(text), (
            f"the matcher accepts an instruction that tells the agent the opposite: {text!r}")


def _assert_not_configured_refusal(text: str, token: str, what: str) -> None:
    """O-4: the refusal names the system as not configured with its reason — never as a breaker
    trip, a count of infra failures, or the breaker's own vocabulary."""
    assert _NOT_CONFIGURED.search(text), f"{what}: the refusal never says 'not configured': {text!r}"
    assert token.lower() in text.lower(), \
        f"{what}: the refusal does not carry the check's reason ({token}): {text!r}"
    low = text.lower()
    assert "tripped" not in low, f"{what}: a not-configured refusal reads as a breaker trip: {text!r}"
    assert "infra failure" not in low, \
        f"{what}: a not-configured refusal names infra failures: {text!r}"
    assert re.search(r"\b\d+\s+infra", low) is None, \
        f"{what}: a not-configured refusal counts failures: {text!r}"


def test_a_system_down_at_start_is_refused_at_every_gate_without_running_its_adapter(tmp_path):
    root = _plant(tmp_path, "o1", down=("cmdb",))
    token = _token("cmdb")
    run = _drive(tmp_path, root, main=[
        dispatch("l-001", "threat-intel"),
        dispatch("l-002", "cmdb"),
        R.text(R.DONE),
    ], leads={
        "l-001": [R.query("cmdb", "get-host", {"host": "web-1"}),
                  R.query("threat-intel", "health-check"),
                  R.query("cmdb", "health-check"),
                  SUMMARY],
        "l-002": [R.query("cmdb", "health-check"), SUMMARY],
    }, behaviour={"cmdb": REAL, "identity": OK, "change-mgmt": OK, "threat-intel": OK})

    # The control: a call to a configured system runs, is recorded, and writes its row.
    assert run.calls_to("threat-intel") == ["threat-intel.health-check"], \
        f"control: the configured system's call must run: {run.rec.verbs}"
    assert [r.get("exit_code") for r in run.rows_for("threat-intel")] == [0], \
        f"control: the configured system's call must write its row: {run.rows}"

    assert run.calls_to("cmdb") == [], \
        f"a system down at start had its adapter run (O-1): {run.calls_to('cmdb')}"
    for turn, what in ((0, "cmdb.get-host, the lead's first call"),
                       (2, "cmdb.health-check, after a configured call")):
        _assert_not_configured_refusal(run.lead_answer("l-001", turn), token, what)

    _assert_not_configured_refusal(run.main_answer(1), token, "MAIN's dispatch to cmdb")
    assert not run.router.dispatched("l-002"), \
        "a dispatch to a system down at start ran a gather conversation (O-1)"

    assert run.rows_for("cmdb") == [], \
        f"a refused call to a system down at start wrote a query row: {run.rows_for('cmdb')}"
    assert run.state.breaker_failures("cmdb") == 0, \
        f"a system down at start was charged (O-2): {run.breaker}"
    assert run.total_failures == 0, f"the run was charged (O-2): {run.breaker}"


def test_the_agent_is_told_at_start_which_systems_are_not_configured_and_why(tmp_path):
    down = ("cmdb", "change-mgmt")
    root = _plant(tmp_path, "o3", down=down)
    run = _drive(tmp_path, root, main=[dispatch("l-001", CONFIGURED), R.text(R.DONE)], leads={
        "l-001": [R.list_verbs("cmdb"), R.list_verbs(CONFIGURED), SUMMARY],
    }, behaviour={"cmdb": REAL, "identity": OK, "change-mgmt": REAL, CONFIGURED: OK})

    opening = run.main.opening_message
    index = run.router.first_prompt("l-001")
    for system in down:
        token = _token(system)
        marked = _down_lines(opening, system, token)
        assert marked, (
            f"MAIN's opening message does not name {system} as not configured with its reason "
            f"({token}) on any line")
        told = any(_told_not_to_dispatch(sec) for sec in _sections_holding(opening, marked)) or any(
            _NOT_CONFIGURED.search(par) and _told_not_to_dispatch(par)
            for par in run.main.instructions.split("\n\n"))
        assert told, (
            "MAIN is not told, beside the systems it is shown down, not to dispatch them and to "
            f"name the visibility gap: {marked}")
        assert _down_lines(index, system, token), (
            f"gather's system index does not name {system} as not configured with its reason "
            f"({token}) on any line")
    assert _shown_down(opening, CONFIGURED) == [], \
        f"MAIN's opening message shows a configured system as down: {_shown_down(opening, CONFIGURED)}"
    assert _shown_down(index, CONFIGURED) == [], \
        f"gather's system index shows a configured system as down: {_shown_down(index, CONFIGURED)}"

    listed_down = run.lead_answer("l-001", 0)
    assert _names(listed_down, "cmdb"), f"list_verbs(cmdb) does not name cmdb: {listed_down!r}"
    assert _NOT_CONFIGURED.search(listed_down), \
        f"list_verbs(cmdb) does not say cmdb is not configured: {listed_down!r}"
    assert _token("cmdb").lower() in listed_down.lower(), \
        f"list_verbs(cmdb) does not carry the reason ({_token('cmdb')}): {listed_down!r}"

    listed_up = run.lead_answer("l-001", 1)
    assert "health-check" in listed_up, \
        f"control: list_verbs for a configured system lists its verbs: {listed_up!r}"
    assert not _NOT_CONFIGURED.search(listed_up), \
        f"list_verbs shows a configured system as not configured: {listed_up!r}"


def test_a_not_configured_reason_names_the_settings_pointer_never_the_host_path(
        tmp_path, data_root):
    folder = S.plant(data_root, marker="red", table=TABLE)
    S.config_path(folder, "change-mgmt").unlink()
    pointer = "settings/systems/change-mgmt/config.env"
    host_paths = {str(data_root), str(Path(data_root).resolve())}
    run = _drive(tmp_path, data_root, main=[
        dispatch("l-001", CONFIGURED),
        dispatch("l-002", "change-mgmt"),
        R.text(R.DONE),
    ], leads={
        "l-001": [R.list_verbs("change-mgmt"), R.query("change-mgmt", "health-check"), SUMMARY],
        "l-002": [R.query("change-mgmt", "health-check"), SUMMARY],
    }, behaviour={"cmdb": OK, "identity": OK, "change-mgmt": REAL, CONFIGURED: OK})

    opening = run.main.opening_message
    index = run.router.first_prompt("l-001")
    surfaces = {
        "MAIN's opening message": ("\n".join(_shown_down(opening, "change-mgmt")), opening),
        "gather's system index": ("\n".join(_shown_down(index, "change-mgmt")), index),
        "list_verbs(change-mgmt)": (run.lead_answer("l-001", 0),) * 2,
        "a query's refusal": (run.lead_answer("l-001", 1),) * 2,
        "MAIN's dispatch refusal": (run.main_answer(1),) * 2,
    }
    for what, (shown, whole) in surfaces.items():
        assert _NOT_CONFIGURED.search(shown), \
            f"{what} does not show change-mgmt as not configured: {shown!r}"
        assert pointer in shown, \
            f"{what} does not name the missing file by its settings pointer ({pointer}): {shown!r}"
        for host_path in host_paths:
            assert host_path not in whole, \
                f"{what} carries the host data root path (#1106): {host_path}"


def test_three_unconfigured_systems_never_charge_and_the_run_reaches_its_close(tmp_path):
    root = _plant(tmp_path, "o2", down=THREE_DOWN)
    run = _drive(tmp_path, root, main=[
        dispatch("l-001", "cmdb"),
        dispatch("l-002", "identity"),
        dispatch("l-003", "change-mgmt"),
        dispatch("l-004", CONFIGURED),
        *R.closing_main_turns(),
    ], leads={
        "l-001": [R.query("cmdb", "get-host", {"host": "web-1"}),
                  R.query("cmdb", "health-check"), SUMMARY],
        "l-002": [R.query("identity", "get-user", {"user": "dev.dana"}),
                  R.query("identity", "health-check"), SUMMARY],
        "l-003": [R.query("change-mgmt", "health-check"), SUMMARY],
        "l-004": [R.query("cmdb", "health-check"), R.query("identity", "health-check"),
                  R.query("change-mgmt", "health-check"), R.query(CONFIGURED, "health-check"),
                  SUMMARY],
    }, behaviour={"cmdb": REAL, "identity": REAL, "change-mgmt": REAL, CONFIGURED: OK})

    assert run.failures(*THREE_DOWN, CONFIGURED) == dict.fromkeys((*THREE_DOWN, CONFIGURED), 0), \
        f"a not-configured system's failure was charged (O-2): {run.breaker}"
    assert run.total_failures == 0, \
        f"a not-configured system's failure was charged to the run (O-2): {run.breaker}"
    assert run.summary.get("exit_reason") is None, \
        f"the run did not end normally (RunAborted?): {run.summary.get('exit_reason')!r}"
    assert run.summary.get("truncated_by") is None, \
        f"the run was cut short: {run.summary.get('truncated_by')!r}"
    assert run.report_disposition == "inconclusive", \
        f"the run never reached its close (report.md: {run.report_disposition!r})"

    for system in THREE_DOWN:
        assert run.calls_to(system) == [], \
            f"{system} is not configured but its adapter ran: {run.calls_to(system)}"
        assert run.rows_for(system) == [], \
            f"{system}: a refused call wrote a query row: {run.rows_for(system)}"
    assert run.calls_to(CONFIGURED) == [f"{CONFIGURED}.health-check"], \
        f"the configured system's call must run: {run.rec.verbs}"
    assert [r.get("exit_code") for r in run.rows_for(CONFIGURED)] == [0], \
        f"the configured system must answer: {run.rows}"


def test_only_failures_of_configured_systems_are_charged(tmp_path):
    root = _plant(tmp_path, "o2m", down=("cmdb", "identity"))
    run = _drive(tmp_path, root, main=[dispatch("l-001", CONFIGURED), R.text(R.DONE)], leads={
        "l-001": [R.query("cmdb", "get-host", {"host": "web-1"}), R.query("cmdb", "health-check"),
                  R.query("identity", "get-user", {"user": "dev.dana"}),
                  R.query("identity", "health-check"),
                  R.query("change-mgmt", "health-check"),
                  R.query(CONFIGURED, "health-check"),
                  R.query(CONFIGURED, "lookup", {"value": "203.0.113.9"}),
                  R.query("change-mgmt", "health-check"),
                  SUMMARY],
    }, behaviour={"cmdb": REAL, "identity": REAL, "change-mgmt": _transport_fault,
                  CONFIGURED: _transport_fault})

    assert run.failures("cmdb", "identity", "change-mgmt", CONFIGURED) == {
            "cmdb": 0, "identity": 0, "change-mgmt": 2, CONFIGURED: 2}, (
        "only the configured systems' failures may be charged, each one counted "
        f"(O-2): {run.breaker}")
    assert run.total_failures == 4, \
        f"the run total must count exactly the configured failures: {run.breaker}"
    assert run.summary.get("exit_reason") is None, \
        f"the run was aborted below the limit of configured failures: {run.summary!r}"
    for system in ("cmdb", "identity"):
        assert run.calls_to(system) == [], f"unconfigured {system}'s adapter ran: {run.rec.verbs}"
        assert run.rows_for(system) == [], f"a refused {system} call wrote a query row: {run.rows}"
    assert [r.get("exit_code") for r in run.rows_for("change-mgmt")] == [2, 2], \
        f"control: a configured system's failures are rows: {run.rows}"


def _drive_configured_outage(tmp_path: Path) -> _Run:
    """Every system configured; cmdb, identity and change-mgmt fail every call with the
    transport's fault. MAIN dispatches cmdb (2 failures: tripped), cmdb again (refused by the
    breaker), identity (2 more) and change-mgmt (the 5th: RunAborted), and would then close."""
    root = _plant(tmp_path, "ctl")
    return _drive(tmp_path, root, main=[
        dispatch("l-001", "cmdb"),
        dispatch("l-002", "cmdb"),
        dispatch("l-003", "identity"),
        dispatch("l-004", "change-mgmt"),
        *R.closing_main_turns(),
    ], leads={
        "l-001": [R.query("cmdb", "get-host", {"host": "web-1"}),
                  R.query("cmdb", "health-check"), SUMMARY],
        "l-002": [R.query("cmdb", "health-check"), SUMMARY],
        "l-003": [R.query("identity", "get-user", {"user": "dev.dana"}),
                  R.query("identity", "health-check"), SUMMARY],
        "l-004": [R.query("change-mgmt", "health-check"), SUMMARY],
    }, behaviour={"cmdb": _transport_fault, "identity": _transport_fault,
                  "change-mgmt": _transport_fault, CONFIGURED: OK})


def test_configured_systems_that_fail_still_trip_and_abort_the_run(tmp_path):
    limit = circuit_breaker.RUN_FAIL_KILL_LIMIT
    per_system = circuit_breaker.PER_SYSTEM_FAIL_LIMIT
    assert (per_system, limit) == (2, 5), \
        f"precondition: the script spends 2 + 2 + 1 failures: {(per_system, limit)}"
    run = _drive_configured_outage(tmp_path)

    assert run.failures("cmdb", "identity", "change-mgmt", CONFIGURED) == {
            "cmdb": 2, "identity": 2, "change-mgmt": 1, CONFIGURED: 0}, \
        f"each configured failure is charged to its system: {run.breaker}"
    assert run.total_failures == limit, f"the run total: {run.breaker}"
    assert circuit_breaker.is_tripped(run.state, "cmdb"), f"cmdb must trip: {run.breaker}"
    assert run.summary.get("exit_reason") == "RunAborted", \
        f"{limit} configured failures must abort the run: {run.summary!r}"
    assert run.report_disposition is None, "an aborted run reached its close"

    refused = run.main_answer(1)
    assert "tripped" in refused.lower(), \
        f"the second dispatch to a tripped system is refused as tripped: {refused!r}"
    assert f"{per_system} infra failures" in refused.lower(), \
        f"the tripped refusal names its count: {refused!r}"
    assert not run.router.dispatched("l-002"), "a dispatch to a tripped system ran"
    assert run.calls_to("cmdb") == ["cmdb.get-host", "cmdb.health-check"], \
        f"only the lead before the trip reached cmdb: {run.rec.verbs}"


def test_a_tripped_systems_refusal_names_its_count_not_configuration(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    run = _drive_configured_outage(tmp_path)

    refused = run.main_answer(1)
    assert "tripped" in refused.lower(), \
        f"precondition: MAIN's second cmdb dispatch was refused by the breaker: {refused!r}"
    assert f"{circuit_breaker.PER_SYSTEM_FAIL_LIMIT} infra failures" in refused.lower(), \
        f"a tripped system's refusal keeps its count: {refused!r}"
    assert not _NOT_CONFIGURED.search(refused), \
        f"a tripped system's refusal still names 'not configured' as a cause (DP2): {refused!r}"

    kills = [r.getMessage() for r in caplog.records if "run aborted" in r.getMessage().lower()]
    assert kills, "precondition: the run's abort is logged with its message"
    for message in kills:
        assert "unconfigured" not in message.lower(), \
            f"the run-kill message still blames configuration (DP2): {message!r}"
        assert not _NOT_CONFIGURED.search(message), \
            f"the run-kill message still names 'not configured' (DP2): {message!r}"


#: The reason an escaped call-time `ConfigFault` carries, and its distinctive token.
ESCAPED_TOKEN = "THREAT_INTEL_FEED_INDEX"


def _escaped_config_fault() -> BaseException:
    return ConfigFault(f"{ESCAPED_TOKEN} is not set — this key escaped the settings check")


def test_a_config_fault_at_call_time_marks_its_system_not_configured_uncharged(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    root = _plant(tmp_path, "o5b")
    run = _drive(tmp_path, root, main=[
        dispatch("l-001", "cmdb"),
        dispatch("l-002", CONFIGURED),
        R.text(R.DONE),
    ], leads={
        "l-001": [R.query(CONFIGURED, "health-check"),
                  R.query(CONFIGURED, "lookup", {"value": "203.0.113.9"}),
                  R.query("cmdb", "health-check"),
                  SUMMARY],
        "l-002": [R.query(CONFIGURED, "lookup", {"value": "198.51.100.7"}), SUMMARY],
    }, behaviour={"cmdb": OK, "identity": OK, "change-mgmt": OK,
                  f"{CONFIGURED}.health-check": _escaped_config_fault, CONFIGURED: OK})

    assert [r.get("exit_code") for r in run.rows_for("cmdb")] == [0], \
        f"control: the configured cmdb call runs and writes its row: {run.rows}"
    assert run.calls_to(CONFIGURED) == [f"{CONFIGURED}.health-check"], (
        "after a call-time ConfigFault the system must be down: no later call may run its "
        f"verb (O-5b): {run.calls_to(CONFIGURED)}")
    assert run.state.breaker_failures(CONFIGURED) == 0, \
        f"a call-time ConfigFault was charged to its system (O-5b): {run.breaker}"
    assert run.total_failures == 0, \
        f"a call-time ConfigFault was charged to the run (O-5b): {run.breaker}"

    _assert_not_configured_refusal(run.lead_answer("l-001", 1), ESCAPED_TOKEN,
                                   "the lead's next call after the escaped ConfigFault")
    assert [r for r in run.rows_for(CONFIGURED) if r.get("verb") == "lookup"] == [], \
        f"the refused call wrote a query row: {run.rows_for(CONFIGURED)}"

    _assert_not_configured_refusal(run.main_answer(1), ESCAPED_TOKEN,
                                   "MAIN's dispatch after the escaped ConfigFault")
    assert not run.router.dispatched("l-002"), \
        "a dispatch to a system marked not configured ran a gather conversation"

    defects = [r for r in caplog.records
               if r.levelno >= logging.ERROR and _names(r.getMessage(), CONFIGURED)]
    assert defects, (
        "the escaped ConfigFault was not logged as an adapter defect at ERROR or above naming "
        f"{CONFIGURED} (K3): {[(r.levelname, r.getMessage()) for r in caplog.records]}")


class _AtFirstRequest:
    """MAIN's double, noting how many log records existed when MAIN was first asked for a turn
    — everything logged before that is the run's start (the correlation lead is withheld)."""

    __name__ = "AtFirstRequest"

    def __init__(self, inner: R.MainScript, caplog: pytest.LogCaptureFixture) -> None:
        self.inner = inner
        self._caplog = caplog
        self.records_before: int | None = None

    def __call__(self, messages: Any, info: Any) -> Any:
        if self.records_before is None:
            self.records_before = len(self._caplog.records)
        return self.inner(messages, info)


def test_the_operator_log_names_each_down_system_and_why_at_start(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    root = _plant(tmp_path, "o7", down=THREE_DOWN)
    main = _AtFirstRequest(R.MainScript([R.text(R.DONE)]), caplog)
    rec = VerbRecorder()
    run_dir = materialize(tmp_path / "replay", GOLDEN_AB3, run_id="r1256-o7")
    drive(run_dir, run_id="r1256-o7", main=main, gather=R.LeadRouter(),
          verbs=_verbs(rec, {"cmdb": REAL, "identity": REAL, "change-mgmt": REAL, CONFIGURED: OK}),
          tenant=S.tenant_folder_of(root))

    assert main.records_before is not None, "MAIN was never asked for a turn"
    at_start = [r for r in caplog.records[:main.records_before] if r.levelno >= logging.WARNING]
    shown = [(r.levelname, r.getMessage()) for r in at_start]
    per_system: dict[str, logging.LogRecord] = {}
    for system in THREE_DOWN:
        token = _token(system)
        lines = [r for r in at_start
                 if _names(r.getMessage(), system) and token.lower() in r.getMessage().lower()]
        assert len(lines) == 1, (
            f"the start log must carry one line naming {system} and its reason ({token}) at "
            f"WARNING or above (O-7); found {len(lines)} among {shown}")
        per_system[system] = lines[0]
    assert len({id(r) for r in per_system.values()}) == len(THREE_DOWN), (
        f"O-7: one line PER down system — these systems share one record: {shown}")
    for system, record in per_system.items():
        others = [s for s in THREE_DOWN if s != system and _names(record.getMessage(), s)]
        assert others == [], (
            f"O-7: {system}'s start line also names {others} — one line per system: "
            f"{record.getMessage()!r}")
    assert [m for _lvl, m in shown if _names(m, CONFIGURED)] == [], \
        f"the start log names a configured system as if it were down: {shown}"
