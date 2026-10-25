"""Correlation dispatch: `l-00c` runs before MAIN on every tenant, and MAIN's opening message
carries its outcome."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
import re
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from typing import Any

from defender._io import read_jsonl_rows
from defender.run_repository import RunPaths
from defender.tests.support.storage import _session_store_705 as SS
from defender.tests.support.tenancy import _tenants1106 as T6
from defender.tests.support.runtime.state import _1255_snapshot as S1255
from defender.tests.support.runtime.state import _1255_view as V
from defender.tests.support.learning.branch._branch_947 import spec_at
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.e2e import _replay_harness as H
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S7

# Local helpers (work-arounds requested as shared machinery in 82-writer-correlation_dispatch.md)

#: A document every elastic search of `_resolving_backend` answers. At base it is what item 1
#: renders into the ancestor section (and what makes base dispatch `l-00c` at all on a Kibana
ANCESTOR_DOC_MARK = "ANCESTOR-DOC-S04-9c1e"


_TOKEN = re.compile(r"\{[A-Za-z_][A-Za-z0-9_.]*\}")


def _resolving_backend() -> S.Backend:
    """A backend whose elastic searches each answer one document (through the real
    `search_envelope`); every other verb answers an empty result."""
    def answer(system: str, verb: str, params: dict) -> Any:
        if system == "elastic" and verb in ("query", "alerts"):
            return S.envelope([{"@timestamp": "2026-05-25T15:20:00.000Z",
                                "message": ANCESTOR_DOC_MARK,
                                "host": {"name": "office-ws-1"}, "user": {"name": "dev.dana"}}],
                              index=params.get("index") or "logs-*")
        return {"system": system, "verb": verb, "result": []}
    return S.Backend(answer=answer)


class _AtFirstRequest(S.MainScript):
    """MAIN's double, plus what the run held at the moment MAIN's FIRST request arrived: the
    queries table, the backend calls, the leads rows and the gather summaries. `bind` is the
    `before=` hook that names the run folder (requested as a shared hook, see the frontier)."""

    def __init__(self, turns: Sequence[S.Turn], backend: S.Backend) -> None:
        super().__init__(list(turns))
        self._backend = backend
        self.run_dir: Path | None = None
        self.rows: list[dict] | None = None
        self.calls: list[Any] = []
        self.sidecars: set[str] = set()
        self.summaries: dict[str, str] = {}

    def bind(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)

    def __call__(self, messages: Any, info: Any) -> Any:
        if self.rows is None:
            assert self.run_dir is not None, "the `before=` hook never named the run folder"
            paths = RunPaths(self.run_dir)
            self.rows = (read_jsonl_rows(paths.executed_queries)
                         if paths.executed_queries.is_file() else [])
            self.calls = list(self._backend.rec.calls)
            raw = self.run_dir / "gather_raw"
            self.sidecars = ({p.name.removesuffix(".lead.json") for p in raw.glob("*.lead.json")}
                             if raw.is_dir() else set())
            for lead in self.sidecars:
                summary = Path(paths.gather_summary(lead))
                if summary.is_file():
                    self.summaries[lead] = summary.read_text(encoding="utf-8")
        return super().__call__(messages, info)


def _framed_with(text: str, marker: str) -> list[str]:
    return [body for body in S.outer_frames(text) if marker in body]


def _prose_lines(d: S.Drive, text: str) -> set[str]:
    """The non-blank host lines of `text` (frames removed), `d`'s run folder and id normalized."""
    assert d.run_dir is not None
    prose = S.normalize(S.harness_text(text), run_dir=d.run_dir, run_id=d.run_dir.name)
    return {ln.strip() for ln in prose.splitlines() if ln.strip()}


def _section_lines(d: S.Drive, head: str, body: str) -> set[str]:
    """A section's host lines, its heading included (an ending may sit in either)."""
    return _prose_lines(d, head + "\n" + body)


def _opening(d: S.Drive, *names: str) -> str:
    """MAIN's whole opening message — host prose AND framed text, since a note about the tenant
    could ride either — with frame salts, this run's folder, its id and `names` (tenant ids)
    replaced by placeholders: two runs compare equal exactly when MAIN was shown the same
    thing."""
    assert d.run_dir is not None
    text = S.normalize(d.opening_message, run_dir=d.run_dir, run_id=d.run_dir.name)
    for i, name in enumerate(names):
        text = text.replace(name, f"<NAME{i}>")
    return text


def _later_user_prompts(d: S.Drive) -> list[list[str]]:
    """The user-prompt parts of every MAIN request after the first."""
    return [seen.user_prompts for seen in d.main.seen[1:]]


def _assert_nothing_later(d: S.Drive, *needles: str) -> None:
    """Nothing about correlation arrives later in MAIN's session: every later request carries
    exactly the opening message as its user prompt, and no later host part names a needle
    outside it."""
    opening = d.opening_message
    for i, prompts in enumerate(_later_user_prompts(d), start=2):
        assert prompts == [opening], (
            f"MAIN's request {i} carries {len(prompts)} user prompt(s) — something besides the "
            "opening message was added to MAIN's session after its first request (A4 retires the "
            "late correlation entry)")
    for i, seen in enumerate(d.main.seen[1:], start=2):
        rest = "\n".join(t for k, t in seen.parts if t != opening)
        for needle in needles:
            assert needle not in rest, (
                f"MAIN's request {i} carries {needle!r} outside its opening message")


def _assert_summary_in_opening(d: S.Drive, marker: str) -> None:
    """The lead's summary sits framed in the one correlation section and nowhere else."""
    opening = d.opening_message
    framed = _framed_with(opening, marker)
    assert len(framed) == 1, (
        f"MAIN's opening message carries l-00c's summary in {len(framed)} frame(s); exactly one "
        "framed copy is the contract (A4: the lead finishes before the opening message is built)")
    assert marker not in S.harness_text(opening), (
        "l-00c's summary text also reaches MAIN's opening message outside its frame")
    _head, body = S.correlation_section(opening)
    assert _framed_with(body, marker), (
        "l-00c's framed summary is not in the section whose heading names l-00c")


def _run_with_turns(d: S.Drive) -> None:
    assert d.raised is None, f"the run raised {d.raised!r}"
    assert d.rc == 0, f"the run exited {d.rc!r} (refusal={d.refusal!r})"


def _tenant_elastic_configs(tenant_id: str, *, events: str, alerts: str,
                            url: str | None = None) -> dict[str, str]:
    """The tenant's COMPLETE config files (`T6.config_texts`: access method, docker context and
    both containers included), its elastic one carrying the index patterns given. `url=""`
    blanks `ELASTICSEARCH_URL` (a faulted SIEM config: elastic's own settings check fails, so
    since #1256 elastic is down from run start).

    Until #1256 this omitted `ELASTIC_ES_CONTAINER` so that a call the confinement gate admitted
    ended in the adapter's own call-time `ConfigFault`. Under #1256 that omission makes elastic
    down at start and no call reaches the gate, so the real adapter is now stopped short of real
    docker by `_docker_shim` instead."""
    texts = T6.config_texts(tenant_id, events_index=events, alerts_index=alerts)
    if url is not None:
        texts["elastic"] = re.sub(r'(?m)^ELASTICSEARCH_URL=.*$', f'ELASTICSEARCH_URL="{url}"',
                                  texts["elastic"])
    return texts


#: An Elasticsearch `_search` answer with no hits, as the docker-exec'd curl prints it (the body,
#: then curl's `-w` status line — `S7.answer`'s shape).
ES_NO_HITS = S7.answer(json.dumps({"hits": {"total": {"value": 0}, "hits": []}}))


def _docker_shim(where: Path, monkeypatch: Any) -> S7.DockerShim:
    """A recording `docker` first on the PATH the run's verbs fork with, answering every call
    with `ES_NO_HITS`. It replaces the docker CLI only — the real adapter's config reading,
    confinement and request building all run — so a call the gate admits ends here, observably
    (`.calls()`), and one it refuses never reaches it."""
    shim = S7.DockerShim(where, [ES_NO_HITS])
    monkeypatch.setenv("PATH", shim.path_value())
    return shim


def _registry_with_real_elastic(backend: S.Backend, *verbs: str) -> Any:
    """`backend`'s registry with the named elastic verbs replaced by the REAL adapter's."""
    reg = backend.registry()
    table = {system: dict(reg.verbs(system)) for system in reg.systems()}
    real = S.sym("integrations.elastic_adapter", "VERBS")
    for verb in verbs:
        table["elastic"][verb] = real[verb]
    return H.FakeVerbs(table)


def _data_stream_pattern(backing_index: str) -> str:
    """The data-stream pattern a backing index belongs to — the agent's mapping
    (`skills/elastic/execution.md`), done here by hand as the scripted agent does it."""
    m = re.fullmatch(r"\.ds-(.+)-[^-]+-\d{4}\.\d{2}\.\d{2}-\d+", backing_index)
    assert m, f"not a data-stream backing index: {backing_index!r}"
    return f"{m.group(1)}-*"


def _lead_tool_returns(d: S.Drive, lead: str) -> str:
    return "\n".join(t for seen in d.router.seen(lead) for t in seen.tool_returns)


def _session_rows(store: Any) -> list[tuple[str, str]]:
    return SS.sql(store, "SELECT session_id, agent_id FROM session ORDER BY rowid")


def _payloads(store: Any, session_id: str) -> list[str]:
    return [str(p) for (p,) in SS.sql(store, """
        SELECT p.payload FROM message m JOIN message_payload p ON p.message_id = m.id
        WHERE m.session_id = ? ORDER BY m.id""", (session_id,))]


# correlation_outcome_reaches_main / slim heading / o3 opening prompt

def test_opening_message_holds_one_correlation_section(tmp_path):
    marker = "CORR-SUMMARY-S04-ONE"
    planted = S.plant_tenant(fixture_uuid("tenant:acme"))
    told = S.run_alert(tmp_path / "summary", tenant=planted,
                       leads={S.L3: [S.text(f"{marker}: 2 scoped, 9 unscoped.")]})
    _run_with_turns(told)
    _assert_summary_in_opening(told, marker)
    _assert_nothing_later(told, marker)

    raised = S.run_alert(tmp_path / "raised", tenant=planted,
                         leads={S.L3: [S.text(f"{marker}: never sent")]},
                         lead_faults={S.L3: S.LeadFault(raise_on=1, exc=S.provider_refusal)})
    _run_with_turns(raised)
    opening = raised.opening_message
    assert marker not in opening, "a lead whose dispatch raised still had text framed for MAIN"
    head, body = S.correlation_section(opening)
    assert not S.outer_frames(body), (
        "the correlation section of a lead that produced nothing carries a frame — its ending "
        "is one host sentence outside any frame (A2)")
    ending = (_section_lines(raised, head, body)
              - _section_lines(told, *S.correlation_section(told.opening_message)))
    assert ending, (
        "the correlation section of a lead whose dispatch raised says nothing the summary run's "
        "does not — the ending is never named to MAIN (never neither)")
    assert "request refused by provider" not in opening, (
        "the provider's error text reached MAIN's opening message (the ending is a fixed sentence)")
    told_lines = _prose_lines(told, told.opening_message)
    assert not (ending & told_lines), (
        f"the summary run's opening message also carries the ending sentence {ending & told_lines}"
        " — never both")
    _assert_nothing_later(raised, *ending)



# O1, the timestamp gate, tenants without elastic, O2

def test_o1_non_elastic_tenant_gets_correlation_without_kibana_fields(tmp_path):
    marker = "CORR-O1-CMDB-5a"
    alert = S.generic_alert()
    assert not set(S.KIBANA_KEYS) & set(alert), "the O1 alert must carry no Kibana field"
    planted = S.plant_tenant(fixture_uuid("tenant:acme"), table=S.TABLE_NON_ELASTIC, omit_systems=("elastic",))
    d = S.run_alert(tmp_path, alert=alert, tenant=planted,
                    leads={S.L3: [S.query("cmdb", "list-hosts", {}),
                                  S.text(f"{marker}: 3 hosts share the role.")]})
    _run_with_turns(d)
    assert d.router.dispatched(S.L3), "l-00c was never dispatched on a non-Elastic tenant"
    assert d.has_sidecar(S.L3), "l-00c owns no leads row"
    rows = d.rows_for(S.L3)
    assert rows, "l-00c's query left no row"
    assert {r.get("system") for r in rows} == {"cmdb"}, rows
    assert [c.verb for c in d.backend.rec.calls] == ["cmdb.list-hosts"], d.backend.rec.verbs
    _assert_summary_in_opening(d, marker)



def test_correlation_dispatches_with_no_or_unparseable_timestamp(tmp_path):
    planted = S.plant_tenant(fixture_uuid("tenant:acme"))
    alerts = {
        "absent": S.generic_alert(),
        "unparseable": S.generic_alert(alert_timestamp="sometime last tuesday"),
        "parseable": S.generic_alert(alert_timestamp="2026-09-30T08:15:00Z"),
    }
    contracts: dict[str, tuple[str, str, str]] = {}
    for label, alert in alerts.items():
        d = S.run_alert(tmp_path / label, alert=alert, tenant=planted)
        _run_with_turns(d)
        assert d.router.dispatched(S.L3), f"[{label}] l-00c was not dispatched"
        assert d.has_sidecar(S.L3), f"[{label}] l-00c owns no leads row"
        assert d.run_dir is not None
        row = d.sidecar(S.L3)

        def norm(text: str, run_dir: Path = d.run_dir) -> str:
            return S.normalize(text, run_dir=run_dir, run_id=run_dir.name)

        contracts[label] = (norm(str(row.get("goal"))),
                            norm(json.dumps(row.get("what_to_summarize"))),
                            norm(d.router.dispatch_block(S.L3)))
    assert contracts["absent"] == contracts["parseable"], (
        "l-00c's contract differs when the alert carries no alert_timestamp")
    assert contracts["unparseable"] == contracts["parseable"], (
        "l-00c's contract differs when the alert's alert_timestamp does not parse")



# O3: nothing but l-00c before MAIN's first request

def test_o3_only_l00c_backend_calls_precede_mains_first_request(tmp_path):
    planted = S.plant_tenant(fixture_uuid("tenant:acme"), alert_mapping=S.DEFAULT_MAPPING)
    backend = _resolving_backend()
    corr_q = "host.name:office-ws-1 AND NOT rule.id:x"
    main = _AtFirstRequest([S.gather("l-001", "elastic", "measure the host"), S.text(S.DONE)],
                           backend)
    d = S.run_alert(tmp_path, alert=S.fixture_alert(), tenant=planted, backend=backend,
                    main=main, before=main.bind,
                    leads={S.L3: [S.query("elastic", "alerts", {"native_query": corr_q}),
                                  S.text("CORR-O3: 1 scoped.")],
                           "l-001": [S.query("elastic", "query", {"native_query": "l001:probe"}),
                                     S.text("L1-O3: measured.")]})
    _run_with_turns(d)
    assert main.rows is not None, "MAIN was never asked for a turn"
    before = {r.get("lead_id") for r in main.rows}
    assert before <= {S.L3}, (
        f"queries rows under {sorted(map(str, before - {S.L3}))} exist before MAIN's first request — only "
        "l-00c may call a backend before MAIN starts (O3)")
    assert len(main.calls) == len(main.rows), (
        f"{len(main.calls)} backend call(s) but {len(main.rows)} queries row(s) before MAIN's first "
        "request — a call reached the backend that no lead's row accounts for")
    # Controls: the snapshot channel sees l-00c's call, and attributes MAIN's lead's call later.
    assert [c.params.get("native_query") for c in main.calls] == [corr_q], (
        "l-00c's scripted call is not what reached the backend before MAIN's first request — the "
        "lead had not finished (A4) or the channel cannot see it")
    assert [r.get("lead_id") for r in d.rows if r not in main.rows] == ["l-001"]



def test_p013_mains_first_turn_dispatches_leads_while_correlat(tmp_path):
    arms: list[tuple[str, str, str, list[S.Turn]]] = [
        ("calls", "elastic", "query",
         [S.query("elastic", "alerts", {"native_query": "lead:l-00c n:0"}),
          S.query("elastic", "alerts", {"native_query": "lead:l-00c n:1"}),
          S.text("CORR-P013: done.")]),
        ("nocall", "elastic", "query", [S.text("CORR-P013: nothing to bind.")]),
        ("withheld", "identity", "get-user", []),
    ]
    for label, system, verb, corr in arms:
        table = S.TABLE_WITHHELD if label == "withheld" else S.TABLE_ELASTIC
        planted = S.plant_tenant(fixture_uuid(f"tenant:p013-{label}"), table=table, alert_mapping=S.DEFAULT_MAPPING)
        backend = _resolving_backend()

        def lead_turns(lead: str, n: int, system: str = system, verb: str = verb) -> list[S.Turn]:
            key = "native_query" if system == "elastic" else "user"
            return [*[S.query(system, verb, {key: f"lead:{lead} n:{i}"}) for i in range(n)],
                    S.text(f"{lead} measured.")]

        first = S.Turn(tool_calls=(
            ("gather", {"lead_id": "l-001", "system": system, "goal": "one",
                        "what_to_summarize": ["one"]}),
            ("gather", {"lead_id": "l-002", "system": system, "goal": "two",
                        "what_to_summarize": ["two"]})))
        main = _AtFirstRequest([first, S.text(S.DONE)], backend)
        leads = {"l-001": lead_turns("l-001", 2), "l-002": lead_turns("l-002", 2)}
        if corr:
            leads[S.L3] = corr
        d = S.run_alert(tmp_path / label, alert=S.fixture_alert(), tenant=planted,
                        backend=backend, main=main, before=main.bind,
                        leads=leads)
        _run_with_turns(d)
        assert main.rows is not None
        early = {r.get("lead_id") for r in main.rows}
        assert early <= {S.L3}, (
            f"[{label}] rows under {sorted(map(str, early - {S.L3}))} precede MAIN's first request")
        keys = [(r.get("lead_id"), r.get("seq")) for r in d.rows]
        assert len(keys) == len(set(keys)), f"[{label}] a (lead, seq) pair repeats: {keys}"
        for row in d.rows:
            bound = json.dumps(row.get("params"))
            assert f"lead:{row.get('lead_id')} " in bound, (
                f"[{label}] a row filed under {row.get('lead_id')} carries another lead's call: "
                f"{bound}")
        assert {r.get("lead_id") for r in d.rows} >= {"l-001", "l-002"}, (
            f"[{label}] MAIN's two leads left no rows — the arm proves nothing")



# l-000, O4 and the confinement survivals


def test_o4_agent_fetches_constituent_events_through_a_gather_lead(tmp_path):
    alert = S.fixture_alert()
    ancestors = alert["ancestor_events"]
    pattern = _data_stream_pattern(ancestors[0]["index"])
    patterns = ("logs-*", ".internal.alerts-security.alerts-default-*")
    planted = S.plant_tenant(fixture_uuid("tenant:acme"), alert_mapping=S.DEFAULT_MAPPING,
                             configs=_tenant_elastic_configs(fixture_uuid("tenant:acme"), events=patterns[0],
                                                             alerts=patterns[1]))
    confine = S.sym("integrations.confinement", "confine_index")
    ids = [a["id"] for a in ancestors]

    def answer(system: str, verb: str, params: dict) -> Any:
        if system == "elastic" and verb == "query" and "_id" in params["native_query"]:
            index = confine(params["index"], patterns)
            wanted = [i for i in ids if i in params["native_query"]]
            return S.envelope([{"@timestamp": "2026-05-25T15:22:40.000Z",
                                "message": f"constituent {i} DOCMARK"} for i in wanted],
                              index=index)
        return {"system": system, "verb": verb, "result": []}

    native = "_id: (" + " OR ".join(f'"{i}"' for i in ids) + ")"
    d = S.run_alert(tmp_path, alert=alert, tenant=planted, backend=S.Backend(answer=answer),
                    main=[S.gather("l-001", "elastic", "fetch the alert's constituent events"),
                          S.text(S.DONE)],
                    leads={"l-001": [S.query("elastic", "query",
                                             {"native_query": native, "index": pattern},
                                             query_id="elastic.doc-fetch-by-id"),
                                     S.text("L1-O4: all constituents fetched.")]})
    _run_with_turns(d)
    rows = d.rows_for("l-001")
    assert [r.get("exit_code") for r in rows] == [0], rows
    assert rows[0].get("params", {}).get("index") == pattern
    got = _lead_tool_returns(d, "l-001")
    for i in ids:
        assert f"constituent {i} DOCMARK" in got, f"the lead never got document {i} back"
    assert "L1-O4: all constituents fetched." in "\n".join(d.main.seen[1].tool_returns)


#: A table whose gather role reaches elastic and cmdb, and whose correlation holder sits on cmdb.
TABLE_ELASTIC_GATHER_CMDB_CORRELATION = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather, lead-zero-correlation]}
    list-hosts: {roles: [gather, lead-zero-correlation]}
  elastic:
    health-check: {roles: [gather]}
    query: {roles: [gather]}
"""


def _names_down_as_not_configured(text: str, system: str) -> list[str]:
    """Each line of `text` saying "not configured" (any case) whose own line or the one before
    it names `system` — how #1256 tells an agent a granted system is down from run start, read
    loosely on layout (the note may put the system on its own bullet line above the reason)."""
    lines = text.lower().splitlines()
    return [ln for i, ln in enumerate(lines) if "not configured" in ln
            and any(system in near for near in lines[max(i - 1, 0):i + 1])]


def _main_tool_returns(d: S.Drive) -> str:
    """Every tool result MAIN received after its first request (a dispatch's answer lands here)."""
    return "\n".join(t for seen in d.main.seen[1:] for t in seen.tool_returns)


def test_p134_tenants_siem_config_faulted_at_run_start(tmp_path, monkeypatch):
    patterns = ("logs-*", ".internal.alerts-security.alerts-default-*")
    leads = {S.L3: [S.query("cmdb", "list-hosts", {}), S.text("CORR-P134: 2 hosts.")],
             "l-001": [S.query("elastic", "query", {"native_query": "host.name:office-ws-1"}),
                       S.text("L1-P134: the SIEM answered.")]}
    main = [S.gather("l-001", "elastic", "measure the host"), S.text(S.DONE)]
    # An alert that names no signal index: the tenant's own SIEM config is the only place an
    # index could come from (base's item 1 read it here, and named its fault).
    alert = S.fixture_alert()
    alert.pop("signal_index")
    runs: dict[str, S.Drive] = {}
    shims: dict[str, S7.DockerShim] = {}
    for tenant_id, url in ((fixture_uuid("tenant:tfault1222"), ""), (fixture_uuid("tenant:tgood1222"), None)):
        planted = S.plant_tenant(
            tenant_id, alert_mapping=S.DEFAULT_MAPPING,
            table=TABLE_ELASTIC_GATHER_CMDB_CORRELATION, lead_zero=S.LEAD_ZERO_NON_ELASTIC,
            configs=_tenant_elastic_configs(tenant_id, events=patterns[0], alerts=patterns[1],
                                            url=url))
        shims[tenant_id] = _docker_shim(tmp_path / tenant_id / "docker", monkeypatch)
        backend = S.Backend()
        runs[tenant_id] = S.run_alert(tmp_path / tenant_id, alert=alert,
                                      tenant=planted, backend=backend,
                                      verbs=_registry_with_real_elastic(backend, "query"),
                                      main=main, leads=leads)
        _run_with_turns(runs[tenant_id])
    faulted, healthy = runs[fixture_uuid("tenant:tfault1222")], runs[fixture_uuid("tenant:tgood1222")]

    # O-3: MAIN's opening names elastic as not configured, with the check's reason (the key).
    opening = _opening(faulted, fixture_uuid("tenant:tfault1222"))
    assert _names_down_as_not_configured(opening, "elastic"), (
        "MAIN's opening message does not name elastic as not configured on a tenant whose "
        "elastic settings fail its check at run start (#1256 O-3)")
    assert "ELASTICSEARCH_URL" in opening, (
        "MAIN's opening message names elastic down without the check's reason (the blank key)")

    lead_saw = (_lead_tool_returns(faulted, "l-001") if faulted.router.dispatched("l-001")
                else "")
    refused = _main_tool_returns(faulted) + "\n" + lead_saw
    assert "not configured" in refused.lower(), (
        f"MAIN's elastic lead was not refused as not configured: {refused[:2000]}")
    assert "ELASTICSEARCH_URL" in refused, (
        f"the refusal does not name the check's reason (the blank key): {refused[:2000]}")
    assert "tripped" not in refused.lower(), (
        f"a not-configured system was refused as a tripped breaker: {refused[:2000]}")
    assert faulted.rows_for("l-001") == [], (
        f"the refused elastic lead wrote query rows — its call ran: {faulted.rows_for('l-001')}")
    assert not [r for r in faulted.rows if r.get("system") == "elastic"], faulted.rows
    # O-2: nothing is charged, per system or run-wide (read as failure counts, not as the
    # breaker's layout — where a not-configured status is kept is the implementer's).
    assert faulted.run_state.breaker_failures("elastic") == 0, faulted.breaker
    assert faulted.breaker.get("total_failures", 0) == 0, faulted.breaker

    # Correlation on cmdb (up) still runs and reaches MAIN.
    assert faulted.router.dispatched(S.L3), "l-00c on cmdb was not dispatched"
    assert {r.get("system") for r in faulted.rows_for(S.L3)} == {"cmdb"}, faulted.rows_for(S.L3)
    _assert_summary_in_opening(faulted, "CORR-P134")

    # Control: the healthy tenant's opening names no down elastic; its same lead runs through the
    # real verb to a row (one docker call); nothing it is told says "not configured".
    healthy_opening = _opening(healthy, fixture_uuid("tenant:tgood1222"))
    assert not _names_down_as_not_configured(healthy_opening, "elastic"), (
        f"a fully configured elastic is named not configured: "
        f"{_names_down_as_not_configured(healthy_opening, 'elastic')}")
    assert "ELASTICSEARCH_URL" not in healthy_opening
    assert [r.get("exit_code") for r in healthy.rows_for("l-001")] == [0], (
        healthy.rows_for("l-001"))
    assert len(shims[fixture_uuid("tenant:tgood1222")].calls()) == 1, shims[fixture_uuid("tenant:tgood1222")].calls()
    assert "not configured" not in _main_tool_returns(healthy).lower()
    assert "L1-P134: the SIEM answered." in _main_tool_returns(healthy)


# r1 / r2 — the opening message's slots, the sessions

def _canned_shim(argv: list[str], env: dict[str, str]) -> str | None:
    """ORIENT's three lookups answered with fixed corpus text (each carries a brace sequence)."""
    if argv[:1] == ["defender-lessons"] and "--tags" in argv:
        return "telemetry_source: auth-log, egress\nattack_phase: command-and-control\n"
    if argv[:1] == ["defender-lessons"]:
        return "lesson-s04-r1.md: R1-LESSON-HIT check the {cadence} before closing\n"
    if argv[:1] == ["defender-invlang"]:
        return "?beacon-cadence R1-VOCAB-HIT — {interval} fixed-period egress\n"
    return None


def test_r1_every_harness_slot_of_mains_opening_message_is_bound(tmp_path):
    marker = "R1-CORR-MARK"
    alert = S.generic_alert(rule={"id": "R-1001", "name": "Beacon",
                                  "description": "Beacon every {interval}s to {dest}"})
    shim = S.RecordingShim(real=_canned_shim)
    d = S.run_alert(tmp_path, alert=alert, tenant=S.plant_tenant(fixture_uuid("tenant:acme")),
                    orient_shim=shim,
                    leads={S.L3: [S.text(f"{marker}: window {{start}}..{{end}} on detected_at")]})
    _run_with_turns(d)
    assert shim.calls, "ORIENT never ran its lookups — the lessons and vocabulary slots are empty"
    opening = d.opening_message
    sections = S.raw_sections(opening)
    header = opening[:opening.find("\n#")] if "\n#" in opening else opening

    def section(pred: Callable[[str], bool], what: str) -> tuple[str, str]:
        found = [(h, b) for h, b in sections if pred(h)]
        assert found, f"MAIN's opening message has no {what} section: {[h for h, _ in sections]}"
        return found[0]

    heads = [h for h, _b in sections]
    at = next((i for i, h in enumerate(heads) if h.startswith("## Workspace")), None)
    assert at is not None, f"MAIN's opening message has no workspace section: {heads}"
    # The workspace map's own `## ` sub-sections run up to the invlang catalog that follows it.
    upto = next((i for i in range(at + 1, len(heads)) if heads[i].startswith("## invlang")),
                len(heads))
    holding = [h + b for h, b in sections if _framed_with(b, marker)]
    assert len(holding) == 1, f"the lead's summary sits in {len(holding)} sections"
    parts = {
        "header": header,
        "workspace": "\n".join(h + b for h, b in sections[at:upto]),
        "lessons": "".join(section(lambda h: h.startswith("## Lessons"), "lessons")),
        "vocabulary": "".join(section(lambda h: "vocabulary" in h.lower(), "vocabulary")),
        "l-00c heading": "".join(S.correlation_section(opening)),
        "correlation": holding[0],
    }
    for name, text in parts.items():
        prose = S.harness_text(text)
        assert prose.strip(), f"the {name} part of MAIN's opening message is empty"
        assert not _TOKEN.findall(prose), (
            f"the {name} part carries unsubstituted template token(s) {_TOKEN.findall(prose)}")
    # Data arrives as it was, and each filled slot shows its content.
    frames = S.outer_frames(opening)
    assert any("Beacon every {interval}s to {dest}" in f for f in frames), (
        "the raw alert block lost or rewrote the alert's brace sequence")
    assert any("window {start}..{end}" in f for f in _framed_with(opening, marker))
    assert any("R1-LESSON-HIT check the {cadence}" in f for f in S.outer_frames(parts["lessons"]))
    assert any("telemetry_source: auth-log" in f for f in S.outer_frames(parts["lessons"]))
    assert any("R1-VOCAB-HIT" in f for f in S.outer_frames(parts["vocabulary"]))
    assert "R-1001" in S.harness_text(parts["vocabulary"]), (
        "the vocabulary section does not name the signature it was looked up by")
    assert d.run_dir is not None
    # #1255 (design rev 4, P1 Outbound; O3): the workspace map names the run folder by its model
    # path, and never by its host folder.
    workspace = S.harness_text(parts["workspace"])
    assert V.MODEL_RUN in workspace, (
        f"the workspace section does not name this run's folder ({V.MODEL_RUN})")
    assert str(d.run_dir) not in workspace, (
        "the workspace section names this run's HOST folder, not its model path")


def test_r2_the_lead_session_and_mains_sessions_land_as_distinct_rows(tmp_path):
    marks = {S.L3: "R2-CORR-MARK", "l-001": "R2-L1-MARK", "l-002": "R2-L2-MARK"}
    sink: list = []
    first = S.Turn(tool_calls=tuple(
        ("gather", {"lead_id": lead, "system": "elastic", "goal": f"measure {lead}",
                    "what_to_summarize": ["one count"]}) for lead in ("l-001", "l-002")))
    d = S.run_alert(
        tmp_path, alert=S.fixture_alert(), backend=_resolving_backend(),
        tenant=S.plant_tenant(fixture_uuid("tenant:acme"), alert_mapping=S.DEFAULT_MAPPING),
        store_factory=S.store_factory(tmp_path / "db", sink=sink),
        main=[first, S.text(S.DONE)],
        leads={S.L3: [S.query("elastic", "alerts", {"native_query": "r2:corr"}),
                      S.text(f"{marks[S.L3]}: 1 scoped.")],
               "l-001": [S.query("elastic", "query", {"native_query": "r2:l001"}),
                         S.text(f"{marks['l-001']}: measured.")],
               "l-002": [S.query("elastic", "query", {"native_query": "r2:l002"}),
                         S.text(f"{marks['l-002']}: measured.")]})
    _run_with_turns(d)
    assert sink, "the run opened no store through the injected factory"
    store = sink[-1]
    rows = _session_rows(store)
    agents = [a for _s, a in rows]
    expected = ["main", f"gather:{S.L3}", "gather:l-001", "gather:l-002"]
    assert sorted(agents) == sorted(expected), f"session rows by agent: {agents}"
    assert len({s for s, _a in rows}) == len(rows), "two agents share a session id"
    by_agent = {a: _payloads(store, s) for s, a in rows}
    for agent, payloads in by_agent.items():
        assert payloads, f"{agent}'s session reads back empty"
    corr = "\n".join(by_agent[f"gather:{S.L3}"])
    assert "r2:corr" in corr, "l-00c's session does not read back its own round"
    assert not any(f"r2:{x}" in corr for x in ("l001", "l002")), (
        "l-00c's session holds a MAIN lead's rounds")
    assert "Begin the investigation" not in corr, "l-00c's session holds MAIN's opening message"
    main_rows = by_agent["main"]
    carrying = [i for i, p in enumerate(main_rows) if marks[S.L3] in p]
    assert carrying == [0], (
        f"l-00c's summary appears in MAIN's session rows {carrying} — it belongs to MAIN's opening "
        "message alone, with no injected correlation entry after it")
    for lead, other in (("l-001", "l002"), ("l-002", "l001")):
        text = "\n".join(by_agent[f"gather:{lead}"])
        assert f"r2:{lead.replace('-', '')}" in text, (
            f"{lead}'s session does not read back its own rounds")
        assert f"r2:{other}" not in text, f"{lead}'s session holds another lead's rounds"
        assert "r2:corr" not in text, f"{lead}'s session holds l-00c's rounds"



# The harness default (C01): p001, p186


# p012, p033, p173 — the outcome is in the opening message, whenever the run ends

def test_p012_run_ends_at_mains_first_answer_with_correlation(tmp_path):
    marker = "CORR-P012-31"
    backend = S.Backend()
    main = _AtFirstRequest([S.text(S.DONE)], backend)
    d = S.run_alert(tmp_path, tenant=S.plant_tenant(fixture_uuid("tenant:acme")), backend=backend, main=main,
                    before=main.bind,
                    leads={S.L3: [S.query("elastic", "alerts", {"native_query": "p012:corr"}),
                                  S.text(f"{marker}: 4 scoped.")]})
    _run_with_turns(d)
    assert d.main.requests == 1, "the scenario must end at MAIN's first answer"
    assert S.L3 in main.sidecars, "l-00c's leads row did not exist before MAIN's first request"
    assert [(r.get("lead_id"), r.get("exit_code")) for r in main.rows or []] == [(S.L3, 0)], (
        f"l-00c's query was not complete before MAIN's first request: {main.rows}")
    assert marker in main.summaries.get(S.L3, ""), (
        "l-00c's summary was not written before MAIN's first request")
    _assert_summary_in_opening(d, marker)
    assert d.run_dir is not None
    joined = S.sym("learning.judge.family", "leads_by_id")(d.run_dir)
    assert S.L3 in joined, "the judge's lead loader does not see l-00c"
    assert joined[S.L3].goal == d.sidecar(S.L3).get("goal")
    assert len(joined[S.L3].queries) == 1
    page = S.sym("presentation.visualize_run", "render_page")(_run_handle_1165(d.run_dir))
    assert S.L3 in page, "the run page does not show l-00c"


def test_p033_mains_first_request_retried_before_correlation_i(tmp_path):
    marker = "CORR-P033-RETRY"
    d = S.run_alert(tmp_path, alert=S.fixture_alert(), backend=_resolving_backend(),
                    tenant=S.plant_tenant(fixture_uuid("tenant:acme"), alert_mapping=S.DEFAULT_MAPPING),
                    main=[S.gather("not a lead id", "elastic", "bad id"), S.text(S.DONE)],
                    leads={S.L3: [S.text(f"{marker}: 3 scoped.")]})
    _run_with_turns(d)
    assert len(d.main.seen) >= 2, "MAIN made no second request"
    assert d.main.seen[1].of_kind("retry-prompt"), (
        "MAIN's second request is not a retry — the scenario does not exercise PR-15")
    retry = d.main.seen[1]
    assert retry.user_prompts == [d.opening_message], (
        "the retried first request does not resend exactly the opening message — something "
        f"arrived at the retry: {len(retry.user_prompts)} user prompt(s)")
    copies = sum(t.count(marker) for _k, t in retry.parts)
    assert copies == 1, (
        f"the retried request carries l-00c's summary {copies} time(s); exactly the one in the "
        "resent opening message is the contract")
    _assert_summary_in_opening(d, marker)



# The resume trio: p034, p037, p040

def _plant_sibling(source_dir: Path, sibling_dir: Path) -> Path:
    """A sibling's run folder holding the source run's alert (and its record once it has one) — the
    case input a resumed run starts from (`_branch_947.ALERT_DOC`'s reasoning)."""
    sibling_dir.mkdir(parents=True)
    for attr in ("alert", S.COINED["runpaths.record"]):
        src = getattr(RunPaths(source_dir), attr, None)
        if src is not None and Path(src).is_file():
            dst = Path(getattr(RunPaths(sibling_dir), attr))
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
    return sibling_dir


def _source_then_sibling(tmp_path: Path, *, planted: S.Planted, run_id: str,
                         corr: list[S.Turn], capture: tuple[str, str, dict],
                         sibling_turns: list[S.Turn],
                         before: Callable[[Path], None] | None = None,
                         ) -> tuple[S.Drive, S.Drive]:
    """A source run through `run.main` (production's default store), branched at MAIN's `echo`
    CALL after the document landed and the capturing lead returned, and a sibling resumed
    there. Before #1255 this branched at the append's tool RETURN, which D1 refuses; the
    `echo` is a tool-calling MAIN response (D1) that is not the gather turn (an arm re-runs a
    gather at its branch turn against its own backend), and it sits after `l-009`'s capture so
    the branch point holds a capture however the capture rule reads the source's table (cut at
    the snapshot or whole — the design does not say)."""
    golden = (H.GOLDEN / "investigation.md").read_text(encoding="utf-8")
    system, verb, params = capture
    src = S.run_alert(
        tmp_path / "source", alert=S.fixture_alert(), tenant=planted,
        backend=_resolving_backend(), before=before,
        main=[S.call("append_block", text=golden),
              S.gather("l-009", system, "capture one fact"), S.call("bash", command="echo held"),
              S.text(S.DONE)],
        leads={S.L3: corr, "l-009": [S.query(system, verb, params), S.text("L9 captured.")]})
    _run_with_turns(src)
    assert src.run_dir is not None
    store = S.sym("runtime.branch._spec", "open_source_store")(src.run_dir, source_run=_run_handle_1165(src.run_dir))
    ss = SS.store_mod()
    path = ss.path_row_ids(store, ss.main_session_id(store))
    point = S1255.tool_calling_responses(store)[2]  # the `echo` call
    assert S1255.calls_of(S1255.message_at(store, point))[0].tool_name == "bash", path
    spec = spec_at(store, src.run_dir, point)
    sibling_dir = _plant_sibling(src.run_dir, location_path(planted.runs) / fixture_uuid(f"{run_id}-sibling"))
    sib = S.new_drive(tmp_path / "sibling", tenant=planted, main=sibling_turns)
    S.drive_run(sib, sibling_dir, tenant=planted.accept(), resume=spec)
    return src, sib


#: An `:R` row citing l-00c against the golden's v-001 — accepted exactly when l-00c is declared.
CITE_L00C = (
    "```invlang\n"
    ":R attr_updates [resolved_by|target|key|value]\n"
    f"{S.L3}|v-001|attrs.correlated_alerts|2\n"
    "```\n")


def test_p040_resumed_sibling_of_a_post_change_source_cites_l0(tmp_path):
    arms = {
        "declared": (S.plant_tenant(fixture_uuid("tenant:decl"), alert_mapping=S.DEFAULT_MAPPING),
                     ("elastic", "query", {"native_query": "p040:capture"})),
        "undeclared": (S.plant_tenant(fixture_uuid("tenant:undecl"), table=S.TABLE_WITHHELD,
                                      alert_mapping=S.DEFAULT_MAPPING),
                       ("identity", "get-user", {"user": "dev.dana"})),
    }
    for label, (planted, capture) in arms.items():
        src, sib = _source_then_sibling(
            tmp_path / label, planted=planted, run_id=fixture_uuid(f"s04-p040-{label}"),
            corr=[S.text("CORR-P040: 1 scoped.")], capture=capture,
            sibling_turns=[S.call("append_block", text=CITE_L00C), S.text(S.DONE)])
        source_doc = src.investigation
        declares = re.search(rf"(?m)^{re.escape(S.L3)}\|", source_doc) is not None
        assert declares == (label == "declared"), (
            f"[{label}] the source document {'does not declare' if declares is False else 'declares'}"
            f" {S.L3} — the arm is not the condition it names")
        assert not sib.router.dispatched(S.L3), f"[{label}] the resumed sibling dispatched l-00c"
        assert sib.backend.rec.calls == [], f"[{label}] the resumed sibling called the backend"
        cited = f"{S.L3}|v-001|attrs.correlated_alerts|2" in sib.investigation
        assert cited == (label == "declared"), (
            f"[{label}] the sibling's citation of {S.L3} was "
            f"{'accepted' if cited else 'refused'}; it must be accepted exactly when the inherited "
            "document declares it")
        if label == "undeclared":
            told = "\n".join(t for seen in sib.main.seen[1:] for t in seen.tool_returns)
            assert S.L3 in told, "the refusal of the undeclared citation does not name l-00c"
