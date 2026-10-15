"""#1222 slice S04 — correlation dispatch: `l-00c` runs before MAIN on every tenant.

Every test is one demand of `spec-flow/specs/spec_graph_1222.yaml`, named by its `discharged_by`
and carrying its `seed_docstring`. The design (`.spec-flow/design.md` as amended — A4, A2, M1,
O1-O4, C01) deletes item 1 (the ancestor fetch): the correlation lead runs to its end before
MAIN's opening message is built, on every tenant and every alert, and that message carries its
outcome. THE SUITE IS WRITTEN BEFORE THE IMPLEMENTATION: at base `301f196c` correlation is gated
on item 1 and on `alert_timestamp`, and its summary is injected late (before MAIN's second
request), so most tests here are RED at base — each for the reason its demand names.

HOW THE OUTCOME IS FOUND (no literal is coined for it). The fixed ending sentences are not
spelled anywhere in the design, so no test asserts one. "The correlation section" is the one
`## ` section of MAIN's opening message whose heading names `l-00c` (the slim ORIENT heading that
survives M1 — `slim_heading_names_l00c_reserved`), read through the suite's one anchor
`S.correlation_section`; the lead's summary is found by a marker the
test scripted into `l-00c`'s answer, inside an untrusted frame; an ending is found as the host
prose one run's correlation section carries and a summary run's does not. "Up to MAIN's first
request" is a snapshot taken inside MAIN's double on its first call (`_AtFirstRequest`).

FAULTS. Model faults are `S.LeadFault` specs (PR-12). Backend refusals come from the REAL
`elastic_adapter` verbs (`confine_index` refuses before any transport; the tenant's config names
no `ELASTIC_ES_CONTAINER`, so a call the gate admits ends in the adapter's own `ConfigFault` before
any docker child: no network is reachable from this file). Admitted fetches are answered by the
shared `S.Backend` through the real `search_envelope`.
"""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

import json
import re
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from defender._io import read_jsonl_rows
from defender.run_repository import RunPaths
from defender.tests import _data_root_1078 as D
from defender.tests import _session_store_705 as SS
from defender.tests import _tenants1106 as T6
from defender.tests import _1255_snapshot as S1255
from defender.tests._branch_947 import spec_at
from defender.tests.alert_front_door_1222 import _spec1222 as S
from defender.tests.e2e import _replay_harness as H

# =================================================================================================
# Local helpers (work-arounds requested as shared machinery in 82-writer-correlation_dispatch.md)
# =================================================================================================

#: A document every elastic search of `_resolving_backend` answers. At base it is what item 1
#: renders into the ancestor section (and what makes base dispatch `l-00c` at all on a Kibana
#: alert); after the change no harness-built text may carry it.
ANCESTOR_DOC_MARK = "ANCESTOR-DOC-S04-9c1e"

#: The base ancestor heading, spelled here rather than imported: a removed symbol must never
#: break collection (D6), and the suite never asserts on it — it only names what base printed.
BASE_ANCESTOR_WORD = "ancestor"

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
    """The tenant's config files, its elastic one carrying the index patterns given and the
    access keys the real adapter checks (`ELASTIC_TRANSPORT`, `ELASTIC_DOCKER_CONTEXT`), and NO
    `ELASTIC_ES_CONTAINER` — so the real adapter reaches its confinement gate and, past it,
    ends in its own `ConfigFault` before any docker child could run. `url=""` blanks
    `ELASTICSEARCH_URL` (a faulted SIEM config)."""
    texts = T6.config_texts(tenant_id, events_index=events, alerts_index=alerts)
    elastic = texts["elastic"]
    if url is not None:
        elastic = re.sub(r'(?m)^ELASTICSEARCH_URL=.*$', f'ELASTICSEARCH_URL="{url}"', elastic)
    texts["elastic"] = (elastic + 'ELASTIC_TRANSPORT="docker-exec"\n'
                        'ELASTIC_DOCKER_CONTEXT="s04-no-such-context"\n')
    return texts


def _registry_with_real_elastic(backend: S.Backend, *verbs: str) -> Any:
    """`backend`'s registry with the named elastic verbs replaced by the REAL adapter's."""
    reg = backend.registry()
    table = {system: dict(reg.verbs(system)) for system in reg.systems()}
    real = S.sym("scripts.adapters.elastic_adapter", "VERBS")
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


# =================================================================================================
# correlation_outcome_reaches_main / slim heading / o3 opening prompt
# =================================================================================================

def test_opening_message_holds_one_correlation_section(tmp_path):
    """MAIN's opening message holds exactly one correlation section: the lead's framed summary when
    the lead produced a usable one, otherwise one fixed sentence naming its ending, outside the
    lead's frame — never both, never neither — and nothing about correlation arrives later in
    MAIN's session.

    Two runs of one non-Kibana alert on one tenant differ only in how l-00c answers: a summary
    (scripted marker) and a dispatch that raised (PR-12's provider refusal)."""
    marker = "CORR-SUMMARY-S04-ONE"
    planted = S.plant_tenant("acme")
    told = S.run_alert(tmp_path / "summary", tenant=planted, run_id="s04-one-summary",
                       leads={S.L3: [S.text(f"{marker}: 2 scoped, 9 unscoped.")]})
    _run_with_turns(told)
    _assert_summary_in_opening(told, marker)
    _assert_nothing_later(told, marker)

    raised = S.run_alert(tmp_path / "raised", tenant=planted, run_id="s04-one-raised",
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


def test_slim_heading_names_l00c_reserved(tmp_path):
    """The opening message's ORIENT heading tells MAIN that l-00c is harness-reserved and not to
    attach new work to it, and names no l-000.

    Observed on a run whose lead summarised and on one whose table withholds the lead."""
    for label, table in (("granted", S.TABLE_ELASTIC), ("withheld", S.TABLE_WITHHELD)):
        planted = S.plant_tenant(f"slim-{label}", table=table)
        d = S.run_alert(tmp_path / label, tenant=planted, run_id=f"s04-slim-{label}")
        _run_with_turns(d)
        opening = d.opening_message
        assert S.L0 not in opening, (
            f"[{label}] MAIN's opening message names {S.L0} — after the change it is an ordinary "
            "id and the heading names only l-00c as reserved")
        head, _body = S.correlation_section(opening)
        assert S.L3 in S.harness_text(head), f"[{label}] the l-00c heading is not host prose"


def test_o3_opening_prompt_carries_no_ancestor_section(tmp_path):
    """The opening message MAIN received carries no ancestor section — asserted on the message the
    model received, never on source.

    The Kibana fixture alert carries `ancestor_events`, and the backend answers every search with a
    marked document: base's item 1 fetched and rendered it. Positive control on the same message:
    the alert's own ancestor pointers DO reach MAIN, framed inside the raw alert block, and the
    slim heading names l-00c."""
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING)
    alert = S.fixture_alert()
    d = S.run_alert(tmp_path, alert=alert, tenant=planted, backend=_resolving_backend(),
                    run_id="s04-o3-prompt")
    _run_with_turns(d)
    opening = d.opening_message
    assert ANCESTOR_DOC_MARK not in opening, (
        "a document the harness fetched for the alert's ancestors reached MAIN's opening message")
    headings = [h for h, _b in S.sections(opening)]
    assert not [h for h in headings if BASE_ANCESTOR_WORD in h.lower()], (
        f"MAIN's opening message still opens an ancestor section: {headings}")
    # Positive control: the channel sees ancestor pointers when the ALERT carries them.
    pointer = alert["ancestor_events"][0]["id"]
    assert any(pointer in body for body in S.outer_frames(opening)), (
        "the alert's own ancestor_events pointers are missing from the raw alert block — the "
        "observation channel cannot see ancestor content at all, so the negative is vacuous")
    assert pointer not in S.harness_text(opening)
    S.correlation_section(opening)


# =================================================================================================
# O1, the timestamp gate, tenants without elastic, O2
# =================================================================================================

def test_o1_non_elastic_tenant_gets_correlation_without_kibana_fields(tmp_path):
    """A tenant whose lead-zero.yaml and grants name a non-Elastic system, over an alert carrying
    none of alert_id / signal_index / ancestor_events / alert_timestamp: l-00c's leads row exists,
    its queries ran on that system, and MAIN's opening message carries the lead's summary.

    The tenant's correlation template is the shipped, established `cmdb.list-all-hosts`, granted to
    the correlation holder alone on cmdb; the tenant has no elastic system at all."""
    marker = "CORR-O1-CMDB-5a"
    alert = S.generic_alert()
    assert not set(S.KIBANA_KEYS) & set(alert), "the O1 alert must carry no Kibana field"
    planted = S.plant_tenant("acme", table=S.TABLE_NON_ELASTIC, omit_systems=("elastic",))
    d = S.run_alert(tmp_path, alert=alert, tenant=planted, run_id="s04-o1",
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
    """An alert with no alert_timestamp, and one whose alert_timestamp does not parse, both get l-00c
    dispatched; neither the lead's dispatch nor its contract depends on a timestamp field.

    A third alert with a parseable alert_timestamp is the control: the lead's stored goal, its
    summary asks and its Dispatch block are the same text for all three."""
    planted = S.plant_tenant("acme")
    alerts = {
        "absent": S.generic_alert(),
        "unparseable": S.generic_alert(alert_timestamp="sometime last tuesday"),
        "parseable": S.generic_alert(alert_timestamp="2026-09-30T08:15:00Z"),
    }
    contracts: dict[str, tuple[str, str, str]] = {}
    for label, alert in alerts.items():
        d = S.run_alert(tmp_path / label, alert=alert, tenant=planted, run_id=f"s04-ts-{label}")
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


def test_tenant_without_elastic_folder_runs_to_close(tmp_path):
    """A tenant with no systems/elastic/ folder starts a run, dispatches its correlation lead and
    reaches report.md; the opening message carries no note about a missing Elastic system.

    The control is the same tenant shape with an elastic folder: the host says the same thing to
    MAIN in both opening messages."""
    marker = "CORR-NOELASTIC-77"
    leads = {S.L3: [S.query("cmdb", "list-hosts", {}), S.text(f"{marker}: nothing related.")]}
    bare = S.plant_tenant("tbare1222", table=S.TABLE_NON_ELASTIC, omit_systems=("elastic",))
    assert not (bare.settings / "systems" / "elastic").exists()
    d = S.run_alert(tmp_path / "bare", tenant=bare, run_id="s04-noelastic",
                    main=S.closing_main_turns(), leads=leads)
    _run_with_turns(d)
    assert d.router.dispatched(S.L3), "l-00c was not dispatched on a tenant without elastic"
    assert d.rows_for(S.L3), "l-00c's query left no row"
    report = d.report
    assert report is not None, "the run never reached report.md"
    assert "disposition:" in report, "report.md carries no disposition"
    _assert_summary_in_opening(d, marker)

    full = S.plant_tenant("tfull1222", table=S.TABLE_NON_ELASTIC)
    assert (full.settings / "systems" / "elastic").is_dir()
    ctl = S.run_alert(tmp_path / "full", tenant=full, run_id="s04-noelastic",
                      main=S.closing_main_turns(), leads=leads)
    _run_with_turns(ctl)
    assert _opening(d, bare.tenant_id) == _opening(ctl, full.tenant_id), (
        "MAIN's opening message differs between a tenant with an elastic folder and one without "
        "— the run start told MAIN something about the missing Elastic system")


def test_o2_kibana_fixture_alert_still_gets_its_correlation_summary(tmp_path):
    """Today's Kibana-projected fixture alert on the Elastic fixture tenant still gets l-00c
    dispatched and its summary into MAIN's opening message, whether or not the agent ever fetches
    ancestors.

    Every committed fixture alert, on the committed fixture tenant; for the first one MAIN also
    dispatches a lead that fetches the alert's constituent documents."""
    tenant = T6.fixture_tenant()
    root = D.current_data_root()
    planted = S.Planted(root=root, tenant_id=tenant.id, knowledge=root / tenant.id / "knowledge")
    for i, slug in enumerate(S.FIXTURE_SLUGS):
        marker = f"CORR-O2-{i}-e4"
        main = S.default_main_turns()
        if i == 0:
            main = [S.gather("l-001", "elastic", "fetch the alert's constituent events"),
                    S.text(S.DONE)]
        d = S.run_alert(tmp_path / slug, alert=S.fixture_alert(slug), tenant=planted,
                        run_id=f"s04-o2-{i}", main=main,
                        leads={S.L3: [S.text(f"{marker}: 1 scoped, 4 unscoped.")],
                               "l-001": [S.query("elastic", "query",
                                                 {"native_query": '_id: "AZ5fuw9rEmDJyXFcPn5t"',
                                                  "index": "logs-system.auth-*"}),
                                         S.text("L1-O2: one constituent fetched.")]})
        _run_with_turns(d)
        assert d.router.dispatched(S.L3), f"[{slug}] l-00c was not dispatched"
        _assert_summary_in_opening(d, marker)


# =================================================================================================
# O3: nothing but l-00c before MAIN's first request
# =================================================================================================

def test_o3_only_l00c_backend_calls_precede_mains_first_request(tmp_path):
    """Up to MAIN's first request the queries table and the verb registry record no backend call
    under any lead id other than l-00c.

    Snapshot inside MAIN's double on its first call, over the Kibana fixture alert (base's item 1
    ran here). Channel controls in the same run: l-00c's scripted call IS recorded in both
    channels by then, and MAIN's own lead's call is recorded afterwards under its own id."""
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING)
    backend = _resolving_backend()
    corr_q = "host.name:office-ws-1 AND NOT rule.id:x"
    main = _AtFirstRequest([S.gather("l-001", "elastic", "measure the host"), S.text(S.DONE)],
                           backend)
    d = S.run_alert(tmp_path, alert=S.fixture_alert(), tenant=planted, backend=backend,
                    main=main, before=main.bind, run_id="s04-o3-calls",
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
    """Before MAIN's first request, no queries row exists under any lead other than l-00c. l-00c's own
    rows may be absent (the lead was withheld, or issued no call). Each row names its own lead, and
    numbers are unique.

    MAIN's first turn dispatches two leads at once. Three tenants/scripts: l-00c calling twice,
    l-00c issuing no call, l-00c withheld by the table."""
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
        planted = S.plant_tenant(f"p013-{label}", table=table, alert_mapping=S.DEFAULT_MAPPING)
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
                        backend=backend, main=main, before=main.bind, run_id=f"s04-p013-{label}",
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


# =================================================================================================
# l-000, O4 and the confinement survivals
# =================================================================================================

def test_l000_is_claimed_like_any_lead_on_a_new_run(tmp_path):
    """On a new run MAIN can dispatch a lead with id l-000 and it is claimed like any other id.

    MAIN dispatches l-000 and l-001 in one turn; both are claimed by the same path and both
    summaries reach MAIN."""
    planted = S.plant_tenant("acme")
    first = S.Turn(tool_calls=(
        ("gather", {"lead_id": S.L0, "system": "elastic", "goal": "lead zero, ordinary",
                    "what_to_summarize": ["what the system says"]}),
        ("gather", {"lead_id": "l-001", "system": "elastic", "goal": "lead one, ordinary",
                    "what_to_summarize": ["what the system says"]})))
    d = S.run_alert(tmp_path, tenant=planted, run_id="s04-l000", main=[first, S.text(S.DONE)],
                    leads={S.L0: [S.query("elastic", "query", {"native_query": "l000:probe"}),
                                  S.text("L0-ORDINARY-SUMMARY")],
                           "l-001": [S.query("elastic", "query", {"native_query": "l001:probe"}),
                                     S.text("L1-ORDINARY-SUMMARY")]})
    _run_with_turns(d)
    assert d.router.dispatched(S.L0), (
        f"MAIN's {S.L0} never ran — the id is still reserved by the harness on a new run")
    zero, one = d.sidecar(S.L0), d.sidecar("l-001")
    assert zero.get("goal") == "lead zero, ordinary", zero
    assert set(zero) == set(one), (
        f"{S.L0}'s leads row is not shaped like any other lead's: {sorted(zero)} vs {sorted(one)}")
    assert [r.get("exit_code") for r in d.rows_for(S.L0)] == [0]
    returned = "\n".join(d.main.seen[1].tool_returns)
    assert "L0-ORDINARY-SUMMARY" in returned, f"{S.L0}'s summary never reached MAIN"
    assert "L1-ORDINARY-SUMMARY" in returned, "l-001's summary never reached MAIN"


def test_o4_agent_fetches_constituent_events_through_a_gather_lead(tmp_path):
    """MAIN dispatching an ordinary gather lead that binds elastic.doc-fetch-by-id with the
    data-stream pattern mapped from alert.json's ancestor_events gets the documents back.

    The fetch is answered through the real `search_envelope` after the real `confine_index` admits
    the bound index against the tenant's configured patterns."""
    alert = S.fixture_alert()
    ancestors = alert["ancestor_events"]
    pattern = _data_stream_pattern(ancestors[0]["index"])
    patterns = ("logs-*", ".internal.alerts-security.alerts-default-*")
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING,
                             configs=_tenant_elastic_configs("acme", events=patterns[0],
                                                             alerts=patterns[1]))
    confine = S.sym("scripts.adapters.confinement", "confine_index")
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
                    run_id="s04-o4-fetch",
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


def test_o4_backing_index_bound_verbatim_is_refused_naming_patterns(tmp_path):
    """Binding the alert's backing index verbatim gets the adapter's existing refusal, which names the
    configured patterns.

    The real elastic `query` verb. Control in the same lead: the data-stream pattern passes the
    same confinement gate and ends past it, on the missing container."""
    alert = S.fixture_alert()
    backing = alert["ancestor_events"][0]["index"]
    pattern = _data_stream_pattern(backing)
    patterns = ("logs-*", ".internal.alerts-security.alerts-default-*")
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING,
                             configs=_tenant_elastic_configs("acme", events=patterns[0],
                                                             alerts=patterns[1]))
    backend = S.Backend()
    native = f'_id: "{alert["ancestor_events"][0]["id"]}"'
    d = S.run_alert(tmp_path, alert=alert, tenant=planted, backend=backend,
                    verbs=_registry_with_real_elastic(backend, "query"), run_id="s04-o4-refuse",
                    main=[S.gather("l-001", "elastic", "fetch the alert's constituent events"),
                          S.text(S.DONE)],
                    leads={"l-001": [S.query("elastic", "query",
                                             {"native_query": native, "index": backing}),
                                     S.query("elastic", "query",
                                             {"native_query": native, "index": pattern}),
                                     S.text("L1-O4: refused once.")]})
    _run_with_turns(d)
    rows = d.rows_for("l-001")
    assert len(rows) == 2, rows
    refused, admitted = rows
    assert refused.get("exit_code") != 0, refused
    detail = str(refused.get("payload_digest"))
    for p in patterns:
        assert p in detail, f"the refusal of {backing!r} does not name the configured pattern {p!r}"
    seen = _lead_tool_returns(d, "l-001")
    assert all(p in seen for p in patterns), "the lead was not told which patterns are configured"
    # Control: the pattern is past the gate — what remains is the container the config omits.
    assert "ELASTIC_ES_CONTAINER" in str(admitted.get("payload_digest")), admitted
    assert not any(p in str(admitted.get("payload_digest")) for p in patterns), admitted


def test_p132_sequence_alert_whose_constituents_are_building_b(tmp_path):
    """O4 covers data-stream documents. Building-block alerts are fetched through the alerts-index
    pattern the existing confinement admits; no widening.

    A sequence alert whose ancestors are building-block alerts in the alerts index (PR-32's pattern
    pair). The lead's fetch through the configured alerts pattern returns them; the alias outside
    every pattern is refused by the real `alerts` verb, naming the patterns."""
    patterns = ("logs-*", ".internal.alerts-security.alerts-default-*")
    bb_index = ".internal.alerts-security.alerts-default-000001"
    alert = S.kibana_alert(ancestor_events=[
        {"id": "bb-0001", "type": "signal", "index": bb_index, "depth": 1},
        {"id": "bb-0002", "type": "signal", "index": bb_index, "depth": 1}])
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING,
                             configs=_tenant_elastic_configs("acme", events=patterns[0],
                                                             alerts=patterns[1]))
    confine = S.sym("scripts.adapters.confinement", "confine_index")

    def answer(system: str, verb: str, params: dict) -> Any:
        if system == "elastic" and verb == "query" and "bb-" in params["native_query"]:
            index = confine(params["index"], patterns)
            return S.envelope([{"@timestamp": "2026-05-25T15:22:40.000Z",
                                "message": f"building block {i} BBMARK"}
                               for i in ("bb-0001", "bb-0002")], index=index)
        return {"system": system, "verb": verb, "result": []}

    backend = S.Backend(answer=answer)
    native = '_id: ("bb-0001" OR "bb-0002")'
    d = S.run_alert(tmp_path, alert=alert, tenant=planted, backend=backend,
                    verbs=_registry_with_real_elastic(backend, "alerts"), run_id="s04-p132",
                    main=[S.gather("l-001", "elastic", "fetch the sequence's building blocks"),
                          S.text(S.DONE)],
                    leads={"l-001": [S.query("elastic", "query",
                                             {"native_query": native, "index": patterns[1]}),
                                     S.query("elastic", "alerts",
                                             {"native_query": native,
                                              "index": ".alerts-security.alerts-default"}),
                                     S.text("L1-P132: fetched.")]})
    _run_with_turns(d)
    fetched, widened = d.rows_for("l-001")
    assert fetched.get("exit_code") == 0, fetched
    got = _lead_tool_returns(d, "l-001")
    for block in ("bb-0001", "bb-0002"):
        assert f"building block {block} BBMARK" in got, f"the lead never got {block} back"
    assert widened.get("exit_code") != 0, (
        "an index outside every configured pattern was admitted — confinement was widened")
    assert all(p in str(widened.get("payload_digest")) for p in patterns), widened


def test_p133_ancestor_index_with_no_configured_pattern(tmp_path):
    """Binding an index no configured pattern covers gets the adapter's existing refusal naming the
    patterns. An id that has aged out returns an ordinary empty result.

    The real `query` verb refuses a cross-cluster index name; a fetch by an id the index no longer
    holds answers the real `search_envelope` with no hits (RJ-06), which the lead receives as an
    ordinary result, not a fault."""
    patterns = ("logs-*", ".internal.alerts-security.alerts-default-*")
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING,
                             configs=_tenant_elastic_configs("acme", events=patterns[0],
                                                             alerts=patterns[1]))
    backend = S.Backend()  # its `alerts` answers the real envelope with zero hits
    outside = "remote-cluster:logs-system.auth-*"
    d = S.run_alert(tmp_path, alert=S.fixture_alert(), tenant=planted, backend=backend,
                    verbs=_registry_with_real_elastic(backend, "query"), run_id="s04-p133",
                    main=[S.gather("l-001", "elastic", "fetch the constituents"), S.text(S.DONE)],
                    leads={"l-001": [S.query("elastic", "query",
                                             {"native_query": '_id: "gone-1"', "index": outside}),
                                     S.query("elastic", "alerts",
                                             {"native_query": '_id: "aged-out-1"',
                                              "index": patterns[1]}),
                                     S.text("L1-P133: refused, then empty.")]})
    _run_with_turns(d)
    refused, empty = d.rows_for("l-001")
    assert refused.get("exit_code") != 0, refused
    assert all(p in str(refused.get("payload_digest")) for p in patterns), refused
    assert empty.get("exit_code") == 0, f"an aged-out id became a fault: {empty}"
    returns = d.router.seen("l-001")[2].tool_returns
    assert any('"total": 0' in t or '"returned": 0' in t for t in returns), (
        f"the lead did not receive an ordinary empty result for the aged-out id: {returns}")


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


def test_p134_tenants_siem_config_faulted_at_run_start(tmp_path):
    """Nothing at run start names a faulted SIEM config. The first lead on that system fails with the
    adapter's configured error.

    Two tenants differ only in their elastic config (one blanks ELASTICSEARCH_URL); correlation
    runs on cmdb in both. The host says the same thing to MAIN in both opening messages; MAIN's
    elastic lead on the faulted tenant meets the real adapter's `ConfigFault`."""
    patterns = ("logs-*", ".internal.alerts-security.alerts-default-*")
    leads = {S.L3: [S.query("cmdb", "list-hosts", {}), S.text("CORR-P134: 2 hosts.")],
             "l-001": [S.query("elastic", "query", {"native_query": "host.name:office-ws-1"}),
                       S.text("L1-P134: the SIEM did not answer.")]}
    main = [S.gather("l-001", "elastic", "measure the host"), S.text(S.DONE)]
    # An alert that names no signal index: the tenant's own SIEM config is the only place an
    # index could come from (base's item 1 read it here, and named its fault).
    alert = S.fixture_alert()
    alert.pop("signal_index")
    runs: dict[str, S.Drive] = {}
    for tenant_id, url in (("tfault1222", ""), ("tgood1222", None)):
        planted = S.plant_tenant(
            tenant_id, alert_mapping=S.DEFAULT_MAPPING,
            table=TABLE_ELASTIC_GATHER_CMDB_CORRELATION, lead_zero=S.LEAD_ZERO_NON_ELASTIC,
            configs=_tenant_elastic_configs(tenant_id, events=patterns[0], alerts=patterns[1],
                                            url=url))
        backend = S.Backend()
        runs[tenant_id] = S.run_alert(tmp_path / tenant_id, alert=alert,
                                      tenant=planted, backend=backend,
                                      verbs=_registry_with_real_elastic(backend, "query"),
                                      run_id="s04-p134", main=main, leads=leads)
        _run_with_turns(runs[tenant_id])
    faulted, healthy = runs["tfault1222"], runs["tgood1222"]
    assert _opening(faulted, "tfault1222") == _opening(healthy, "tgood1222"), (
        "MAIN's opening message differs between a tenant whose SIEM config is faulted and one "
        "whose is not — something at run start named the faulted config")
    (row,) = faulted.rows_for("l-001")
    assert row.get("exit_code") != 0, row
    assert "ELASTICSEARCH_URL" in str(row.get("payload_digest")), (
        f"the elastic lead's failure does not name the faulted key: {row}")
    assert "ELASTICSEARCH_URL" in _lead_tool_returns(faulted, "l-001")
    # Control: the healthy tenant's same lead passes the config check (it ends past it).
    (ok,) = healthy.rows_for("l-001")
    assert "ELASTICSEARCH_URL" not in str(ok.get("payload_digest")), ok


def test_p135_tenant_with_no_siem_and_correlation_withheld(tmp_path):
    """The opening message says l-00c is harness-reserved and carries the withheld sentence. It says
    nothing about ancestors or a missing Elastic system.

    A tenant with no elastic folder whose table withholds the lead; the control is the same
    tenant with an elastic folder."""
    bare = S.plant_tenant("tbare1222", table=S.TABLE_WITHHELD, omit_systems=("elastic",))
    d = S.run_alert(tmp_path / "bare", tenant=bare, run_id="s04-p135")
    _run_with_turns(d)
    prose = S.harness_text(d.opening_message)
    assert BASE_ANCESTOR_WORD not in prose.lower(), (
        "MAIN's opening message on a tenant with no SIEM still speaks of ancestors")
    full = S.plant_tenant("tfull1222", table=S.TABLE_WITHHELD)
    ctl = S.run_alert(tmp_path / "full", tenant=full, run_id="s04-p135")
    _run_with_turns(ctl)
    assert _opening(d, bare.tenant_id) == _opening(ctl, full.tenant_id), (
        "the opening message on a tenant with no elastic folder differs from one with — it "
        "names the missing Elastic system")
    assert not d.router.dispatched(S.L3), "the table withholds l-00c, yet it ran"
    head, body = S.correlation_section(d.opening_message)
    assert "verb-grants.yaml" in S.harness_text(head + body), (
        "the withheld sentence does not name the table that withholds the lead")


# =================================================================================================
# r1 / r2 — the opening message's slots, the sessions
# =================================================================================================

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
    """On the opening message the model received (recorded by the replay fake, never read off
    source): every harness-built part -- the header, the workspace section, the lessons section,
    the vocabulary section, the l-00c heading and the one correlation section -- is present and
    carries no unsubstituted {...} token; a brace sequence inside alert-derived text (the raw alert
    block, a mapped summary, the lead's framed summary) is data and arrives as it was. With the
    lead-zero section gone, orientation's own sections and the raw alert block are all still
    present. Positive control: the same message with every slot filled shows each section's
    content."""
    marker = "R1-CORR-MARK"
    alert = S.generic_alert(rule={"id": "R-1001", "name": "Beacon",
                                  "description": "Beacon every {interval}s to {dest}"})
    shim = S.RecordingShim(real=_canned_shim)
    d = S.run_alert(tmp_path, alert=alert, tenant=S.plant_tenant("acme"), run_id="s04-r1",
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
    assert str(d.run_dir) in S.harness_text(parts["workspace"]), (
        "the workspace section does not name this run's folder")


def test_r2_the_lead_session_and_mains_sessions_land_as_distinct_rows(tmp_path):
    """Driving one run end to end into one session store -- l-00c's correlation lead first, then MAIN
    and two leads MAIN dispatches -- leaves one distinct session row per agent: the lead's session
    holds only the lead's rounds and its ending, MAIN's holds MAIN's turns and no injected
    correlation entry, and each MAIN lead's session reads back its own rounds. Bound at the run,
    the frame that fans the writers. Positive control: every session reads back non-empty, and
    MAIN's lead sessions are still written now that the injected entry is gone."""
    marks = {S.L3: "R2-CORR-MARK", "l-001": "R2-L1-MARK", "l-002": "R2-L2-MARK"}
    sink: list = []
    first = S.Turn(tool_calls=tuple(
        ("gather", {"lead_id": lead, "system": "elastic", "goal": f"measure {lead}",
                    "what_to_summarize": ["one count"]}) for lead in ("l-001", "l-002")))
    d = S.run_alert(
        tmp_path, alert=S.fixture_alert(), backend=_resolving_backend(),
        tenant=S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING), run_id="s04-r2",
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


# =================================================================================================
# The harness default (C01): p001, p186
# =================================================================================================

class _PlainGather(H.ReplayFn):
    """ONE gather script for every gather conversation of the run — a replay that scripts MAIN's
    lead only — which also records whose conversation each request was."""

    __name__ = "PlainGather"

    def __init__(self, turns: list[H.Turn]) -> None:
        super().__init__(turns)
        self.leads: list[str | None] = []

    def __call__(self, messages: Any, info: Any) -> Any:
        self.leads.append(S.dispatch_lead_id(messages))
        return super().__call__(messages, info)


def _harness_drive(tmp_path: Path, *, gather: Any, run_id: str,
                   sink: list) -> tuple[Path, H.ReplayFn]:
    """`_replay_harness.drive` itself (no `run.main`), over the golden sshd alert, on a tenant
    (named after the run) that grants the correlation lead; MAIN dispatches one lead, l-001."""
    planted = S.plant_tenant(run_id.replace("s04-", "t"), alert_mapping=S.DEFAULT_MAPPING)
    run_dir = H.materialize(tmp_path, H.GOLDEN, run_id=run_id)
    main = H.ReplayFn([
        H.Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                       "goal": "measure the host",
                                       "what_to_summarize": ["one count"]})]),
        H.Turn(text="Investigation complete.")])
    main.summary = H.drive(run_dir, run_id=run_id, main=main, gather=gather,
            verbs=_resolving_backend().registry(), tenant=planted.accept(),
            store_factory=S.store_factory(tmp_path / "db", sink=sink))
    return run_dir, main


def _unframed(text: str) -> str:
    bodies = S.outer_frames(text)
    assert len(bodies) == 1, f"a gather summary file is not one framed body: {text!r}"
    return bodies[0].strip()


def test_p001_incidental_replay_scripts_gather_for_mains_lead(tmp_path):
    """Under C01's default the replay gives l-00c its own scripted fake: MAIN's lead draws only MAIN's
    scripted gather turns, l-00c's canned summary issues no backend call and is usable (C38), and
    the replay's spawn, session and leads-row counts include l-00c's row and session while the
    queries rows hold none of l-00c's."""
    script = [H.Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                            "params": {"native_query": "p001:l001"}})]),
              H.Turn(text="P001-L1-SCRIPTED-SUMMARY")]
    gather = _PlainGather(script)
    sink: list = []
    run_dir, main = _harness_drive(tmp_path, gather=gather, run_id="s04-p001", sink=sink)
    assert gather.leads == ["l-001", "l-001"], (
        f"the replay's one gather script was drawn by {gather.leads} — MAIN's lead must draw "
        "exactly its own scripted turns, and l-00c its own fake (C01)")
    paths = RunPaths(run_dir)
    l1 = Path(paths.gather_summary("l-001"))
    assert l1.is_file(), "MAIN's lead left no gather summary"
    assert "P001-L1-SCRIPTED-SUMMARY" in l1.read_text(encoding="utf-8"), (
        "MAIN's lead did not summarise from its own scripted turns")
    corr_file = Path(paths.gather_summary(S.L3))
    assert corr_file.is_file(), "l-00c left no gather summary — it never ran under the default"
    canned = _unframed(corr_file.read_text(encoding="utf-8"))
    assert canned, "l-00c's default fake wrote an empty summary"
    assert "P001-L1-SCRIPTED-SUMMARY" not in canned, "l-00c summarised from MAIN's lead's script"
    assert any(canned in b for b in S.outer_frames(main.seen[0])), (
        "l-00c's canned summary is not framed in MAIN's opening message — under C38 a summary "
        "from a lead that issued no call is usable")
    rows = read_jsonl_rows(paths.executed_queries)
    assert [r for r in rows if r.get("lead_id") == S.L3] == [], "l-00c's default fake made a call"
    assert (run_dir / "gather_raw" / f"{S.L3}.lead.json").is_file(), "l-00c owns no leads row"
    budget = main.summary["run_state"].budget_snapshot()
    assert budget.get("subagent_spawns") == 2, (
        f"the spawn count {budget.get('subagent_spawns')} is not l-00c plus MAIN's one lead")
    agents = sorted(a for _s, a in _session_rows(sink[-1]))
    assert agents == sorted(["main", f"gather:{S.L3}", "gather:l-001"]), agents


def test_p186_replay_scripts_correlation_itself_or_shares_one_(tmp_path):
    """A replay that scripts the correlation lead gives l-00c that script; otherwise l-00c gets the
    default fake. MAIN's leads never draw l-00c's turns.

    Two replays through `_replay_harness.drive`: one passing a single gather script for MAIN's
    lead, one passing a router that scripts l-00c itself (the suite's `LeadRouter`)."""
    shared = _PlainGather([
        H.Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                      "params": {"native_query": "p186:l001"}})]),
        H.Turn(text="P186-SHARED-L1")])
    plain_dir, _main = _harness_drive(tmp_path / "shared", gather=shared, run_id="s04-p186-a",
                                      sink=[])
    assert shared.leads == ["l-001", "l-001"], (
        f"one gather script was drawn by {shared.leads}: l-00c took MAIN's lead's turns")
    default = Path(RunPaths(plain_dir).gather_summary(S.L3))
    assert default.is_file(), "l-00c never ran on the replay that does not script it"
    assert "P186-SHARED-L1" not in default.read_text(encoding="utf-8")

    router = S.LeadRouter({
        S.L3: [S.query("elastic", "alerts", {"native_query": "p186:corr"}),
               S.text("P186-SCRIPTED-CORR")],
        "l-001": [S.query("elastic", "query", {"native_query": "p186:l001"}),
                  S.text("P186-ROUTED-L1")]})
    routed_dir, routed_main = _harness_drive(tmp_path / "routed", gather=router,
                                             run_id="s04-p186-b", sink=[])
    assert router.requests(S.L3) == 2, "l-00c was not given the replay's own correlation script"
    corr = Path(RunPaths(routed_dir).gather_summary(S.L3)).read_text(encoding="utf-8")
    assert "P186-SCRIPTED-CORR" in corr
    rows = read_jsonl_rows(RunPaths(routed_dir).executed_queries)
    assert [r.get("params", {}).get("native_query") for r in rows
            if r.get("lead_id") == S.L3] == ["p186:corr"]
    assert router.requests("l-001") == 2
    assert any("P186-SCRIPTED-CORR" in b for b in S.outer_frames(routed_main.seen[0]))


# =================================================================================================
# p012, p033, p173 — the outcome is in the opening message, whenever the run ends
# =================================================================================================

def test_p012_run_ends_at_mains_first_answer_with_correlation(tmp_path):
    """l-00c's row, queries and summary are complete before MAIN's first request. A run that ends at
    MAIN's first answer still carries correlation's outcome in its opening message. The judge and
    the visualizer load it."""
    marker = "CORR-P012-31"
    backend = S.Backend()
    main = _AtFirstRequest([S.text(S.DONE)], backend)
    d = S.run_alert(tmp_path, tenant=S.plant_tenant("acme"), backend=backend, main=main,
                    before=main.bind, run_id="s04-p012",
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
    page = S.sym("scripts.visualize.visualize_run", "render_page")(_run_handle_1165(d.run_dir))
    assert S.L3 in page, "the run page does not show l-00c"


def test_p033_mains_first_request_retried_before_correlation_i(tmp_path):
    """Exactly one correlation section, in the opening message. A retried first request resends that
    message.

    MAIN's first answer calls `gather` with an invalid lead id, so the framework issues a retry
    request (PR-15); on base the late entry was injected at exactly that retry."""
    marker = "CORR-P033-RETRY"
    d = S.run_alert(tmp_path, alert=S.fixture_alert(), backend=_resolving_backend(),
                    tenant=S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING),
                    run_id="s04-p033",
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


def test_p173_run_request_count_now_includes_the_leads_request(tmp_path):
    """The run's request count is the total, the lead's requests included, as at base.

    The count is the run summary's; the wire log the run is priced from carries the lead's
    requests under its own agent id."""
    d = S.run_alert(tmp_path, tenant=S.plant_tenant("acme"), run_id="s04-p173",
                    leads={S.L3: [S.query("elastic", "alerts", {"native_query": "p173:corr"}),
                                  S.text("CORR-P173: 2 scoped.")]})
    _run_with_turns(d)
    lead_requests = d.router.requests(S.L3)
    assert lead_requests == 2, f"l-00c made {lead_requests} request(s); the scenario needs two"
    total = d.main.requests + sum(d.router.requests(lead) for lead in d.router.leads())
    assert d.summary is not None, "the run returned no summary"
    assert d.summary.get("requests") == total, (
        f"the run summary counts {d.summary.get('requests')} requests; MAIN made "
        f"{d.main.requests} and the leads {total - d.main.requests}")
    assert d.run_dir is not None
    wire = read_jsonl_rows(d.run_dir / "wire_logs" / "llm_requests.jsonl")
    lead_rows = [r for r in wire if r.get("agent_id") == f"gather:{S.L3}"
                 and r.get("kind") == "response"]
    assert len(lead_rows) == lead_requests, (
        "the wire log the run is priced from does not carry every l-00c request")


# =================================================================================================
# The resume trio: p034, p037, p040
# =================================================================================================

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
        tmp_path / "source", alert=S.fixture_alert(), tenant=planted, run_id=run_id,
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
    sibling_dir = _plant_sibling(src.run_dir, planted.runs / f"{run_id}-sibling")
    sib = S.new_drive(tmp_path / "sibling", tenant=planted, main=sibling_turns)
    S.drive_run(sib, sibling_dir, tenant=planted.accept(), resume=spec)
    return src, sib


def test_p034_sibling_branched_before_the_correlation_entry_la(tmp_path):
    """A sibling's inherited history holds the source run's correlation section. A resumed sibling
    dispatches no correlation.

    Branched early (PR-16: on base, before the late entry; #1255: at a tool-calling response
    after the capture, D1); the sibling is handed a verb registry and still issues nothing."""
    marker = "CORR-P034-INHERIT"
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING)
    src, sib = _source_then_sibling(
        tmp_path, planted=planted, run_id="s04-p034",
        corr=[S.text(f"{marker}: 2 scoped.")],
        capture=("elastic", "query", {"native_query": "p034:capture"}),
        sibling_turns=[S.text("Resumed and stopping.")])
    assert src.router.dispatched(S.L3), "the source run dispatched no correlation (control)"
    assert sib.main.seen, "the sibling never reached its model"
    inherited = sib.main.seen[0]
    framed = [b for t in inherited.user_prompts for b in _framed_with(t, marker)]
    assert len(framed) == 1, (
        f"the sibling's inherited history carries the source's correlation summary {len(framed)} "
        "time(s) — it must hold exactly the one in the source's opening message")
    assert not sib.router.dispatched(S.L3), "the resumed sibling dispatched l-00c again"
    assert sib.backend.rec.calls == [], (
        f"the resumed sibling reached the backend: {sib.backend.rec.verbs}")


def test_p037_ancestor_heading_asserts_a_claim_that_then_fails(tmp_path):
    """The opening message's correlation section matches the true outcome. A sibling resumed after it
    inherits that outcome.

    The true outcome here: l-00c's claim collides with a leads row an earlier attempt left (a real
    file planted before the driver starts). The control run, on the same tenant, summarises."""
    marker = "CORR-P037-NEVER"
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING)
    control = S.run_alert(tmp_path / "control", alert=S.fixture_alert(), tenant=planted,
                          backend=_resolving_backend(), run_id="s04-p037-control",
                          leads={S.L3: [S.text(f"{marker}: 2 scoped.")]})
    _run_with_turns(control)
    _assert_summary_in_opening(control, marker)

    def pre_claim(run_dir: Path) -> None:
        raw = run_dir / "gather_raw"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / f"{S.L3}.lead.json").write_text(json.dumps(
            {"goal": "an earlier attempt's correlation", "what_to_summarize": ["earlier"],
             "provenance": "harness"}), encoding="utf-8")

    src, sib = _source_then_sibling(
        tmp_path, planted=planted, run_id="s04-p037",
        corr=[S.text(f"{marker}: 2 scoped.")],
        capture=("elastic", "query", {"native_query": "p037:capture"}),
        sibling_turns=[S.text("Resumed and stopping.")], before=pre_claim)
    assert not src.router.dispatched(S.L3), "l-00c ran although its claim collided"
    opening = src.opening_message
    assert marker not in opening, "MAIN was shown a summary from a lead that never ran"
    head, body = S.correlation_section(opening)
    assert not S.outer_frames(body), "the collided lead's section carries a frame"
    ending = (_section_lines(src, head, body)
              - _section_lines(control, *S.correlation_section(control.opening_message)))
    assert ending, (
        "the opening message names no ending for a lead whose claim collided — it says what the "
        "summary run says, which is not the true outcome")
    assert src.run_dir is not None
    assert sib.main.seen, "the sibling never reached its model"
    inherited = S.normalize("\n".join(sib.main.seen[0].user_prompts), run_dir=src.run_dir,
                            run_id=src.run_dir.name)
    for line in ending:
        assert line in inherited, f"the resumed sibling did not inherit the ending {line!r}"
    assert not sib.router.dispatched(S.L3)


#: An `:R` row citing l-00c against the golden's v-001 — accepted exactly when l-00c is declared.
CITE_L00C = (
    "```invlang\n"
    ":R attr_updates [resolved_by|target|key|value]\n"
    f"{S.L3}|v-001|attrs.correlated_alerts|2\n"
    "```\n")


def test_p040_resumed_sibling_of_a_post_change_source_cites_l0(tmp_path):
    """A resumed sibling dispatches no correlation. Its validator accepts a citation of l-00c exactly
    when the inherited document declares it.

    Two sources: one whose l-00c ran (the harness declares it), one whose table withholds it. Each
    sibling appends the same block citing l-00c."""
    arms = {
        "declared": (S.plant_tenant("decl", alert_mapping=S.DEFAULT_MAPPING),
                     ("elastic", "query", {"native_query": "p040:capture"})),
        "undeclared": (S.plant_tenant("undecl", table=S.TABLE_WITHHELD,
                                      alert_mapping=S.DEFAULT_MAPPING),
                       ("identity", "get-user", {"user": "dev.dana"})),
    }
    for label, (planted, capture) in arms.items():
        src, sib = _source_then_sibling(
            tmp_path / label, planted=planted, run_id=f"s04-p040-{label}",
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
