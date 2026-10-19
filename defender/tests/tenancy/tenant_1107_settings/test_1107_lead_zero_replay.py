"""Replay-driven runs: record reaches the leads, resume re-resolves, grants via tenant config, settings path redacted."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import dataclasses
import inspect
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import run_tenant  # noqa: E402
from defender.integrations import (  # noqa: E402
    _stub_transport,
)
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root  # noqa: E402
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.e2e import _lead_zero_808 as LZ  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
)
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H  # noqa: E402
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S  # noqa: E402

pytestmark = pytest.mark.e2e


def _plant(tmp_path: Path, marker: str, **kw: Any) -> tuple[Path, Path, Any]:
    """A complete #1107 tenant `playground` under its own data root:
    (root, knowledge folder, accepted Tenant)."""
    root = tmp_path / f"tenants-{marker}"
    folder = S.plant(root, marker=marker, **kw)
    return root, folder, S.tenant_folder_of(root)


def _plant_at_data_root(marker: str, **kw: Any) -> tuple[Path, Path, Any]:
    """`_plant`, under THIS test's data root — the one an entry point (`run.main`, a resume)
    reads its tenants from (#1120: `DEFENDER_DATA_ROOT` alone, no flag). Replaces
    any knowledge folder already there. Returns (data root, knowledge folder, accepted Tenant)."""
    root = current_data_root()
    folder = S.plant(root, marker=marker, **kw)
    return root, folder, S.tenant_folder_of(root)


def _identity_worlds() -> list[dict]:
    """A family whose siblings assert facts about an identity record only — nothing in it
    names an Elastic corpus (#1224: a world is the facts it asserts)."""
    return [T.base_world(),
            T.world_doc("b", facts=[T.fact("f1", "web-1's owner is x", ("web-1",))]),
            T.world_doc("c", facts=[T.fact("f2", "web-1's owner is y", ("web-1",))])]


def _resume_argv(manifest: Path) -> list[str]:
    """The sibling's command line (#1105 PR 2, declared change 6: `--tenant T --episode <id>
    --world b`); its episode is opened by id under the tenant's `<T>/episodes/`
    (`_sibling_episode`)."""
    return H.sibling_argv(manifest, "b", "--tenant", S.PLAYGROUND_ID)


def _sibling_episode(tmp_path: Path, doc: dict, *, label: str) -> Path:
    """The episode a sibling opens by id (#1105 PR 2). #1187 (R1, R2, O9, declared changes 5
    and 6): at `<data root>/<playground>/episodes/<uuid>` — its tenant's, the id
    `fixture_uuid(label)` (so two scenes in one test are two episodes) — with no container
    record and no episodes variable; the launcher's RUNS step (`start_runs`, through
    `T.episode_view`) makes `runs/` and writes the arm roster the sibling reads its arm id from
    (O4b)."""
    from defender.episodes._episode_handle import Episode

    root = current_data_root()
    episode_id = fixture_uuid(f"1107-{label}")
    episode = T.episode(tmp_path, doc={**doc, "episode_id": episode_id}, episode_id=episode_id,
                        root=root / S.PLAYGROUND_ID / "episodes")
    with Episode.open(episode) as held:
        T.episode_view(held, tenant=S.tenant_folder_of(root)).close()
    return episode


def _jsonl_text(run_dir: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(run_dir.rglob("*.jsonl")))


class _QueryAnswers(ReplayFn):
    """`ReplayFn` that also keeps, per model request, the `query` tool's answers that arrived
    with it — the tool-return and retry-prompt parts of the request's last message, i.e. the
    host's answer to the previous turn's call, read off that request rather than diffed from the
    whole transcript (an answer worded like an earlier one still counts)."""

    __name__ = "_QueryAnswers"

    def __init__(self, turns: list[Turn]) -> None:
        super().__init__(turns)
        self.answers: list[str] = []

    def __call__(self, messages: Any, info: Any) -> Any:
        parts = getattr(messages[-1], "parts", ()) if messages else ()
        self.answers.append("\n".join(
            str(p.content) for p in parts
            if getattr(p, "part_kind", None) in ("tool-return", "retry-prompt")
            and getattr(p, "tool_name", None) == "query"))
        return super().__call__(messages, info)


# ---- both AgentDeps copies carry the record ------------------------------------------------------

def test_d_agentdeps_record(tmp_path):
    marker = "adeps1107"
    _root, _folder, tenant = _plant(tmp_path, marker)
    fields = {f.name for f in dataclasses.fields(S.mod("runtime.tools._deps").AgentDeps)}
    assert S.RECORD_FIELD in fields, sorted(fields)
    assert S.RETIRED_FIELD not in fields, sorted(fields)

    # Two runs: item 3 and a MAIN gather lead share the one gather model, so one run each.
    l3_query = 'user.name:"adeps-l3"'
    l3 = LZ.run(tmp_path / "lz-l3", run_id="adeps-l3", tenant=tenant,
                answer=LZ.answer_hits([LZ.hit(ts="2026-05-25T15:26:10.000Z"),
                                       LZ.hit(ts="2026-05-25T15:26:50.000Z")]),
                gather_turns=[
                    Turn(tool_calls=[("query", {"system": "elastic", "verb": "alerts",
                                                "params": {"native_query": l3_query}})]),
                    Turn(text=LZ.CORRELATION_SUMMARY),
                ])
    assert l3.has_sidecar(LZ.L3), "item 3 never dispatched the correlation lead"
    main_query = 'host.name:"adeps-main"'
    main = LZ.run(tmp_path / "lz-main", run_id="adeps-main", tenant=tenant,
                  alert=LZ.alert_doc(ancestors=[]),
                  main_turns=[
                      Turn(tool_calls=[("gather", {
                          "lead_id": "l-001", "system": "elastic",
                          "goal": "what else did this host do", "what_to_summarize": ["events"],
                      })]),
                      Turn(text="Investigation complete."),
                  ],
                  gather_turns=[
                      Turn(text=LZ.CORRELATION_SUMMARY),   # `l-00c` answers first (#1222)
                      Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                                  "params": {"native_query": main_query}})]),
                      Turn(text="Summary: the host's events."),
                  ])

    for lead, res, query in (("l3", l3, l3_query), ("main-gather", main, main_query)):
        calls = [c for c in res.rec.calls if c.params.get("native_query") == query]
        assert calls, f"the {lead} lead's verb was never called: {res.rec.verbs}"
        for call in calls:
            record = S.record_on(call.ctx)
            assert record.settings == tenant.settings, (lead, record.settings)
            assert record.systems["elastic"]["ELASTIC_ALERTS_INDEX"] == f"{marker}-alerts-*", (
                lead, record.systems["elastic"])
            assert record.systems["cmdb"]["CMDB_URL_BASE"] == f"http://cmdb-{marker}:8080", lead


# ---- a run whose Elastic part is bad completes ---------------------------------------------------


# ---- resumed runs re-resolve at their own start --------------------------------------------------

def test_s7_mf16_resume_reflects_its_own_start(tmp_path, data_root, monkeypatch):
    marker = "mf16"
    _base, source = H.tenant_source(data_root, S.PLAYGROUND_ID)
    root, folder, _tenant = _plant_at_data_root(marker)
    original = f"http://cmdb-{marker}:8080"
    edited = "http://cmdb-mf16-edited:8080"
    later = "http://cmdb-mf16-later:8080"

    first = S.RunRecorder(tmp_path / "runs" / "mf16-first")
    rc, refused = S.drive_run(S.run_argv(S.plant_alert(tmp_path / "in"), root), first,
                              visualize=first.visualize)
    assert refused is None, (rc, refused and H.refusal_text(refused))
    assert rc == 0, (rc, refused and H.refusal_text(refused))

    S.set_key(folder, "cmdb", "CMDB_URL_BASE", edited)
    S.mapping_path(folder).write_text(T1106.mapping_text(reporter="resolved"),
                                      encoding="utf-8")
    fresh = run_tenant.resolve_tenant(root, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                      dispatches_lead_zero=False)

    def edit_within(_run_dir: Path) -> None:
        S.set_key(folder, "cmdb", "CMDB_URL_BASE", later)
        S.mapping_path(folder).write_text(T1106.mapping_text(reporter="archived"),
                                          encoding="utf-8")

    episode = _sibling_episode(tmp_path, T.family_doc(source_run_dir=str(source),
                                                      worlds=_identity_worlds()),
                               label="mf16")
    sibling = S.RunRecorder(tmp_path / "sibling", before_lifecycle=edit_within)
    rc, refused = S.drive_run(_resume_argv(episode / "family.yaml"), sibling,
                              visualize=sibling.visualize)
    assert refused is None, (rc, refused and H.refusal_text(refused))
    assert rc == 0, (rc, refused and H.refusal_text(refused))

    before = first.lifecycle_calls[0]["tenant"]
    after = sibling.lifecycle_calls[0]["tenant"]
    assert before.systems["cmdb"]["CMDB_URL_BASE"] == original, before.systems["cmdb"]
    assert S.open_reporter(before.ticket_mapping) == "defender"
    assert after.systems["cmdb"]["CMDB_URL_BASE"] == edited, (
        "the resumed sibling did not re-resolve at its own start")
    assert after.systems["cmdb"] == fresh.systems["cmdb"]
    assert S.open_reporter(after.ticket_mapping) == "resolved"

    # Within the resumed run: the files moved on again, and the record did not.
    assert f'CMDB_URL_BASE="{later}"' in S.config_path(folder, "cmdb").read_text(encoding="utf-8")
    ctx = S.verb_context(after, sibling.run_dir_at, {"PATH": ""})
    assert _stub_transport.load_config(ctx, "cmdb", "CMDB")["URL_BASE"] == edited
    assert S.open_reporter(after.ticket_mapping) == "resolved"
    # N7: nothing copied the resolved values into the run or the episode.
    for where in (sibling.run_dir_at, episode):
        assert S.holders(where, edited) == [], (where, S.holders(where, edited))


# ---- the replay helper chain builds through the resolver -----------------------------------------


def test_d_grants_through_tenant_config(tmp_path):
    # rejected: a grants= override on the replay helper chain (_tenants1106.run_tenant, fixture_run_tenant, _replay_harness.drive, _lead_zero_808.run, test_1106_query_lane._run): fork F1, resolved by the human toward the design
    _root, _folder, tenant = _plant(tmp_path, "gb1107", table=T1106.TABLE_B)
    projected = T1106.run_grants(tenant.settings)
    resolved = run_tenant.resolve_run_tenant(tenant.settings, defender_dir=S.DEFENDER,
                                             dispatches_lead_zero=True)
    helper = T1106.run_tenant(tenant, defender_dir=S.DEFENDER, dispatches_lead_zero=True)

    rec = VerbRecorder()

    def get_user(ctx: Any, *, user: str = "dev.dana") -> dict:
        rec.record("get-user", ctx, {"user": user})
        return {"user": user}

    run_dir = LZ.materialize_alert(tmp_path / "replay", LZ.alert_doc(ancestors=[]))
    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "identity", "verb": "get-user",
                                    "params": {"user": "dev.dana"}})]),
        Turn(text="Summary: the user."),
    ])
    drive(run_dir, run_id="gb1107", tenant=tenant, gather=gather,
          main=ReplayFn([
              Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "identity",
                                           "goal": "who is this user",
                                           "what_to_summarize": ["the user's record"]})]),
              Turn(text="Investigation complete."),
          ]),
          verbs=FakeVerbs({"identity": {"get-user": get_user}}))

    record = S.record_on(rec.only().ctx)
    assert record.grants == projected, "the replay ran with grants other than its table's"
    assert helper.grants == projected
    assert record.correlation == resolved.correlation, (record.correlation, resolved.correlation)
    assert helper.correlation == resolved.correlation
    # TABLE_B grants gather identity and threat-intel and withholds cmdb: the lead's own
    # dispatch prompt is narrowed to exactly that.
    assert "- `identity`:" in gather.seen[0]
    assert "- `cmdb`:" not in gather.seen[0]
    for entry in (drive, T1106.run_tenant, LZ.run):
        assert S.GRANTS_KW not in inspect.signature(entry).parameters, (
            f"{entry.__module__}.{entry.__qualname__} still takes {S.GRANTS_KW}=")


# ---- the three SOC_PLAYGROUND_DOCKER_CONTEXT tests, migrated -------------------------------------


# ---- the settings-path redaction keys on the record ----------------------------------------------

def test_d_record_settings_redacted(tmp_path, monkeypatch):
    # CX8: the shim first on the PATH the run env inherits (no call here should reach docker).
    shim = S.DockerShim(tmp_path / "docker")
    monkeypatch.setenv("PATH", shim.path_value())
    root, _folder, tenant = _plant(tmp_path, "red1107")
    record = run_tenant.resolve_tenant(root, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                       dispatches_lead_zero=False)
    assert record.settings == tenant.settings, (record.settings, tenant.settings)
    given, resolved = str(record.settings), str(Path(record.settings).resolve())
    spellings = {given, resolved}

    raised: list[BaseException] = []

    # CX5: an adapter's ConfigFault names the file under the settings folder, worded as
    # load_config's own "config file not found: <path> — this tenant's settings do not configure
    # this system"; here it names the path both as given and as resolved.
    def get_host(ctx: Any, *, host: str = "web-1") -> dict:
        fault = S.config_fault()(
            f"config file not found: {given}/systems/cmdb/config.env — this tenant's settings "
            f"do not configure this system (resolved: {resolved}/systems/cmdb/config.env)")
        raised.append(fault)
        raise fault

    run_dir = LZ.materialize_alert(tmp_path / "replay", LZ.alert_doc(ancestors=[]))
    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "cmdb", "verb": "get-host",
                                    "params": {"host": "web-1"}})]),
        Turn(text="Summary: the host."),
    ])
    drive(run_dir, run_id="red1107", tenant=tenant, gather=gather,
          main=ReplayFn([
              Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "cmdb",
                                           "goal": "what is this host",
                                           "what_to_summarize": ["the host's record"]})]),
              Turn(text="Investigation complete."),
          ]),
          verbs=FakeVerbs({"cmdb": {"get-host": get_host}}))

    assert raised, "the cmdb verb raised no ConfigFault — there was nothing to redact"
    assert any(s in str(raised[0]) for s in spellings), (
        f"the fault names no settings path: {raised[0]!s}")
    after = "\n".join(gather.seen[1:])
    assert S.settings_pointer() in after, f"the fault reached the model unnamed:\n{after}"
    for surface, text in (("gather model", after), ("run-dir tables", _jsonl_text(run_dir))):
        for spelling in spellings:
            assert spelling not in text, f"the {surface} holds the host path {spelling}"
    assert shim.calls() == [], shim.calls()
