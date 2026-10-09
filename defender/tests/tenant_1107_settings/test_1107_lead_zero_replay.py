"""#1107 — lead-zero and the replay lane over the tenant settings record (slice E2).

Lead-zero's item 1 reads the run's record (`record.elastic`) rather than the tenant's files, and
reports an unconfigured or bad Elastic part through an explicit "unavailable" branch; both
`AgentDeps` copies (MAIN's and lead-zero's) carry the record to their leads; the replay helper
chain builds its `RunTenant` through `resolve_run_tenant` alone, its grants from the tenant
folder; a resumed run or sibling re-resolves at its own start; and the three tests that exported
`SOC_PLAYGROUND_DOCKER_CONTEXT` run on their fixture tenant's `config.env` instead.

Driven through the real entry points: the replay harness (`_replay_harness.drive`,
`_lead_zero_808.run`) with its `verbs=` / `tenant=` / `store_factory=` seams, and `run.main`
with `_spec1107.RunRecorder`'s seams. No test reaches the real `docker`: every transport call
runs in an env whose PATH starts with `_spec1107.DockerShim` or a test fixture's own shim.
"""
from __future__ import annotations

import dataclasses
import importlib
import inspect
import json
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import driver, run_tenant  # noqa: E402
from defender.scripts.adapters import (  # noqa: E402
    _stub_transport,
    elastic_adapter,
    host_state_adapter,
)
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender.tests._data_root_1078 import current_data_root  # noqa: E402
from defender.tests import _triplet_947 as T  # noqa: E402
from defender.tests.e2e import _lead_zero_808 as LZ  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
)
from defender.tests.tenant_1078_pass_a import _spec1078 as H  # noqa: E402
from defender.tests.tenant_1107_settings import _spec1107 as S  # noqa: E402

pytestmark = pytest.mark.e2e

#: Item 1's broad-except note at base (`_items._resolve_item1`) — the mechanism o9 rejects.
BROAD_EXCEPT_NOTE = "could not resolve this alert's signal_index"

#: `SOC_PLAYGROUND_DOCKER_CONTEXT`, the env key the three migrated tests exported (s60).
SOC_PLAYGROUND_CONTEXT_KEY = "SOC_PLAYGROUND_DOCKER_CONTEXT"


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


def _linked_root(tmp_path: Path, marker: str) -> tuple[Path, Path, Path]:
    """A tenant planted under a real root and reached through a SYMLINKED tenants root (a link
    to the root is admitted; `accept_tenant` refuses links only below the root). Returns
    (link root, real folder, the settings path as given through the link)."""
    real = tmp_path / f"tenants-{marker}-real"
    folder = S.plant(real, marker=marker)
    link = tmp_path / f"tenants-{marker}-link"
    link.symlink_to(real, target_is_directory=True)
    return link, folder, link / S.PLAYGROUND_ID / "knowledge" / "settings"


def _identity_worlds() -> list[dict]:
    """A family whose siblings assert facts about an identity record only — nothing in it
    names an Elastic corpus (#1224: a world is the facts it asserts)."""
    return [T.base_world(),
            T.world_doc("b", facts=[T.fact("f1", "web-1's owner is x", ("web-1",))]),
            T.world_doc("c", facts=[T.fact("f2", "web-1's owner is y", ("web-1",))])]


def _resume_argv(manifest: Path) -> list[str]:
    return H.resume_argv(manifest, "b", "--tenant", S.PLAYGROUND_ID)


def _jsonl_text(run_dir: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(run_dir.rglob("*.jsonl")))


def _fresh(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.mkdir(parents=True)
    return path


# ---- lead-zero item 1 reads the record ---------------------------------------------------------

def test_c_lead_zero_reads_record(tmp_path):
    """resolve_lead_zero takes the record, lead-zero's capture deps carry it, and item 1's
    alerts-index fallback reads record.elastic. With ELASTIC_ALERTS_INDEX edited in the file
    after the record is built, item 1's shell fetch still uses the value as built."""
    built, edited = "c1107-built-alerts-*", "c1107-edited-alerts-*"
    _root, folder, tenant = _plant(
        tmp_path, "c1107", configs=S.config_texts("c1107", alerts_index=built))
    in_file: list[str] = []

    # `drive()` builds the run's record BEFORE the driver starts, and `run_investigation` opens
    # the store (this factory) BEFORE `_opening_prompt` resolves item 1 — so the edit lands after
    # the record is built and before item 1 falls back to the alerts index.
    def edit_then_open(case_id: str, run_dir: Path) -> Any:
        S.set_key(folder, "elastic", "ELASTIC_ALERTS_INDEX", edited)
        in_file.append(S.config_path(folder, "elastic").read_text(encoding="utf-8"))
        return driver._default_store_factory(case_id, run_dir)

    res = LZ.run(tmp_path / "lz", run_id="c1107-lz", alert=LZ.alert_doc(signal_index=None),
                 answer=LZ.answer_hits([LZ.hit(ts="2026-05-25T15:22:00.000Z")]),
                 tenant=tenant, store_factory=edit_then_open)

    assert in_file, ("the edit never landed before item 1 ran — the scenario cannot tell the record from the "
        f"file: {in_file!r}")
    assert f'ELASTIC_ALERTS_INDEX="{edited}"' in in_file[0], ("the edit never landed before item 1 ran — the scenario cannot tell the record from the "
        f"file: {in_file!r}")
    assert res.shell_call.params["index"] == built, (
        f"item 1's shell fetch used {res.shell_call.params['index']!r}: it re-read the tenant's "
        f"config.env after the record was built instead of reading record.elastic ({built!r})")
    entry = S.mod("runtime.lead_zero").resolve_lead_zero
    assert S.RETIRED_FIELD not in inspect.signature(entry).parameters, (
        f"resolve_lead_zero still takes {S.RETIRED_FIELD}: {inspect.signature(entry)}")
    for call in res.rec.calls:
        record = S.record_on(call.ctx)
        assert record.settings == tenant.settings, (call.verb, record.settings)
        assert record.elastic.alerts_index == built, (
            f"lead-zero's {call.verb} call carried a record whose alerts index is "
            f"{record.elastic.alerts_index!r}, not the value as built")


def test_o9_lead_zero_unavailable_explicit(tmp_path):
    """With record.elastic None, and separately with it a ConfigFault, an alert that has no
    signal_index gets item 1 reported 'unavailable' through an explicit branch. The note names
    the cause, 'no elastic system configured' or 'elastic config is bad' (F11 resolved auto). No
    shell fetch is issued, nothing is raised into item 1's broad except, and the investigation
    continues (C10, CX4)."""
    # rejected: the broad `except Exception` in _resolve_item1 as the mechanism
    root_none, folder_none, tenant_none = _plant(tmp_path, "o9none")
    shutil.rmtree(S.config_path(folder_none, "elastic").parent)
    root_bad, folder_bad, tenant_bad = _plant(tmp_path, "o9bad")
    # d_elastic_view: ELASTIC_ES_CONTAINER is one of the all-or-nothing keys (no default, CX17).
    S.drop_key(folder_bad, "elastic", "ELASTIC_ES_CONTAINER")

    for arm, root, tenant, cause in (("none", root_none, tenant_none, S.NO_ELASTIC),
                                     ("bad", root_bad, tenant_bad, S.BAD_ELASTIC)):
        record = run_tenant.resolve_tenant(root, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                           dispatches_lead_zero=True)
        if arm == "none":
            assert record.elastic is None, (arm, record.elastic)
        else:
            assert isinstance(record.elastic, S.config_fault()), (arm, record.elastic)

        res = LZ.run(tmp_path / f"lz-{arm}", run_id=f"o9-{arm}",
                     alert=LZ.alert_doc(signal_index=None), tenant=tenant)
        section = res.section()
        assert LZ.UNAVAILABLE in section, f"[{arm}] item 1 was not reported unavailable:\n{section}"
        assert cause in section, f"[{arm}] the unavailable note does not name {cause!r}:\n{section}"
        # Nothing raised into the broad except: neither its own note nor the outer frame's repr
        # of a raised fault (`_unavailable(f"{e!r}")`) is what item 1 reports.
        assert BROAD_EXCEPT_NOTE not in section, f"[{arm}] the broad except answered:\n{section}"
        assert "ConfigFault(" not in section, f"[{arm}] a raised fault's repr reached the note"
        assert res.rec.calls == [], (
            f"[{arm}] item 1 issued backend calls with no alerts index to fetch from: "
            f"{[(c.verb, c.params) for c in res.rec.calls]}")
        assert len(res.main.seen) >= 2, f"[{arm}] the investigation stopped at item 1"


def test_s7_nf20_lead_zero_note_names_no_host_path(tmp_path):
    """Lead-zero item 1's "unavailable" note names the cause class ("no elastic system
    configured" / "elastic config is bad"); any fault text it carries passes the settings-path
    redaction, so message zero never holds the tenant's host settings path, as given or
    resolved, only SETTINGS_POINTER."""
    link_none, folder_none, given_none = _linked_root(tmp_path, "nf20none")
    shutil.rmtree(S.config_path(folder_none, "elastic").parent)
    link_bad, folder_bad, given_bad = _linked_root(tmp_path, "nf20bad")
    # The folder stays and its config.env goes: the fault that stands for it names the file —
    # by the settings pointer since #1156's review, never by its host path.
    S.config_path(folder_bad, "elastic").unlink()

    for arm, link, given, cause in (("none", link_none, given_none, S.NO_ELASTIC),
                                    ("bad", link_bad, given_bad, S.BAD_ELASTIC)):
        assert given.is_dir(), f"the settings path as given names no folder: {given}"
        resolved = given.resolve()
        assert str(given) != str(resolved), "the tenants root is not reached through a link"
        record = run_tenant.resolve_tenant(link, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                           dispatches_lead_zero=True)
        if arm == "bad":
            # The record's Elastic fault names the file, by the pointer and not the host path.
            fault_text = str(record.elastic)
            assert isinstance(record.elastic, S.config_fault()), (arm, record.elastic)
            assert S.settings_pointer() in fault_text, (
                f"the elastic fault does not name the file by the settings pointer: {fault_text!r}")
            for spelling in (str(resolved), str(given)):
                assert spelling not in fault_text, (
                    f"the elastic fault names the host settings path: {fault_text!r}")

        res = LZ.run(tmp_path / f"lz-{arm}", run_id=f"nf20-{arm}",
                     alert=LZ.alert_doc(signal_index=None), tenant=S.tenant_folder_of(link))
        assert cause in res.section(), f"[{arm}] message zero's note does not name {cause!r}"
        message_zero = res.message_zero
        for spelling in (given, resolved, link, link.resolve()):
            assert str(spelling) not in message_zero, (
                f"[{arm}] message zero holds the tenant's host path {spelling}")


# ---- both AgentDeps copies carry the record ------------------------------------------------------

def test_d_agentdeps_record(tmp_path):
    """AgentDeps carries the record instead of settings_dir, and both copies reach their leads.
    A verb called from a MAIN-dispatched gather lead (tools_gather's replace) sees the run's own
    record, and so does one called from lead-zero's L3 correlation lead (dispatch_correlation
    and _items' replace)."""
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
            assert record.elastic.alerts_index == f"{marker}-alerts-*", (lead, record.elastic)
            assert record.systems["cmdb"]["CMDB_URL_BASE"] == f"http://cmdb-{marker}:8080", lead


# ---- a run whose Elastic part is bad completes ---------------------------------------------------

def test_o5_missing_es_container_run_completes(tmp_path, monkeypatch, d9_tenant):
    """A tenant whose elastic config.env lacks ELASTIC_ES_CONTAINER resolves with record.elastic
    a ConfigFault, and its investigation runs to completion. Elastic calls fault with
    ConfigFault, and lead-zero's item 1 reports unavailable."""
    # CX8: the shim, first on the PATH the run env inherits, receives any docker call's argv.
    shim = S.DockerShim(tmp_path / "docker")
    monkeypatch.setenv("PATH", shim.path_value())
    root, folder, tenant = _plant_at_data_root("o5")
    S.drop_key(folder, "elastic", "ELASTIC_ES_CONTAINER")

    rec = S.RunRecorder(tmp_path / "runs" / "o5-run")
    rc, refused = S.drive_run(S.run_argv(S.plant_alert(tmp_path / "in"), root, tenant_id=d9_tenant),
                              rec, visualize=rec.visualize)
    assert refused is None, f"run.main refused the tenant: {H.refusal_text(refused)}"
    assert rc == 0, (rc, rec.order)
    assert rec.order.count("lifecycle") == 1, (rc, rec.order)
    record = rec.lifecycle_calls[0]["tenant"]
    assert isinstance(record.elastic, S.config_fault()), record.elastic

    ctx = S.verb_context(record, rec.run_dir_at, shim.env())
    with pytest.raises(S.config_fault()):
        elastic_adapter.query(ctx, native_query='host.name:"o5"')
    assert shim.calls() == [], f"an Elastic call reached docker: {shim.calls()}"

    res = LZ.run(tmp_path / "lz", run_id="o5-lz", alert=LZ.alert_doc(signal_index=None),
                 tenant=tenant)
    section = res.section()
    assert LZ.UNAVAILABLE in section, section
    assert S.BAD_ELASTIC in section, section
    assert len(res.main.seen) >= 2, "the investigation stopped at item 1"


# ---- resumed runs re-resolve at their own start --------------------------------------------------

def test_s7_mf16_resume_reflects_its_own_start(tmp_path, data_root):
    """A run or a sibling world resumed after its tenant's config.env and mapping.yaml were
    edited re-resolves at the resume's own start and addresses the edited values (N7: no
    snapshot file); within the resumed run the values then stay fixed (O2)."""
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
    S.mapping_path(folder).write_text(T1106.mapping_text(released_status="resolved"),
                                      encoding="utf-8")
    fresh = run_tenant.resolve_tenant(root, S.PLAYGROUND_ID, defender_dir=S.DEFENDER,
                                      dispatches_lead_zero=False)

    def edit_within(_run_dir: Path) -> None:
        S.set_key(folder, "cmdb", "CMDB_URL_BASE", later)
        S.mapping_path(folder).write_text(T1106.mapping_text(released_status="archived"),
                                          encoding="utf-8")

    episode = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(source),
                                                   worlds=_identity_worlds()),
                        episode_id=T.EPISODE_ID, root=tmp_path / "episodes")
    sibling = S.RunRecorder(tmp_path / "sibling", before_lifecycle=edit_within)
    rc, refused = S.drive_run(_resume_argv(episode / "family.yaml"), sibling,
                              visualize=sibling.visualize)
    assert refused is None, (rc, refused and H.refusal_text(refused))
    assert rc == 0, (rc, refused and H.refusal_text(refused))

    before = first.lifecycle_calls[0]["tenant"]
    after = sibling.lifecycle_calls[0]["tenant"]
    assert before.systems["cmdb"]["CMDB_URL_BASE"] == original, before.systems["cmdb"]
    assert S.released_status(before.ticket_mapping) == "closed"
    assert after.systems["cmdb"]["CMDB_URL_BASE"] == edited, (
        "the resumed sibling did not re-resolve at its own start")
    assert after.systems["cmdb"] == fresh.systems["cmdb"]
    assert S.released_status(after.ticket_mapping) == "resolved"

    # Within the resumed run: the files moved on again, and the record did not.
    assert f'CMDB_URL_BASE="{later}"' in S.config_path(folder, "cmdb").read_text(encoding="utf-8")
    ctx = S.verb_context(after, sibling.run_dir_at, {"PATH": ""})
    assert _stub_transport.load_config(ctx, "cmdb", "CMDB")["URL_BASE"] == edited
    assert S.released_status(after.ticket_mapping) == "resolved"
    # N7: nothing copied the resolved values into the run or the episode.
    for where in (sibling.run_dir_at, episode):
        assert S.holders(where, edited) == [], (where, S.holders(where, edited))


def test_s7_mf7e_old_manifest_resume_runs_elastic_down(tmp_path, data_root):
    """Resuming a sibling whose manifest records no corpus patterns over a tenant with no elastic
    folder, or a bad one, proceeds: record.elastic is None or a ConfigFault, the resumed
    sibling runs with its Elastic reads failing, and nothing refuses the investigation (O5).

    #1224: no manifest records patterns any more (`configured_patterns` is refused as
    pre-oracle), so the v2 manifest is this case's input, and the world-view guard the pre-#1224
    arm also drove went with cluster staging."""
    _base, source = H.tenant_source(data_root, S.PLAYGROUND_ID)
    shim = S.DockerShim(tmp_path / "docker")

    for arm in ("none", "bad"):
        _root, folder, _tenant = _plant_at_data_root(f"mf7e{arm}")
        if arm == "none":
            shutil.rmtree(S.config_path(folder, "elastic").parent)
        else:
            S.drop_key(folder, "elastic", "ELASTIC_ES_CONTAINER")
        doc = T.family_doc(source_run_dir=str(source), worlds=_identity_worlds())
        assert "configured_patterns" not in doc, sorted(doc)
        episode = T.episode(tmp_path, doc=doc, episode_id=T.EPISODE_ID,
                            root=tmp_path / f"episodes-{arm}")
        sibling = S.RunRecorder(tmp_path / f"sibling-{arm}")

        rc, refused = S.drive_run(_resume_argv(episode / "family.yaml"), sibling,
                                  visualize=sibling.visualize)
        assert refused is None, f"[{arm}] the resume was refused: {H.refusal_text(refused)}"
        assert rc == 0, (arm, rc, sibling.order)
        assert "lifecycle" in sibling.order, (arm, rc, sibling.order)
        record = sibling.lifecycle_calls[0]["tenant"]
        if arm == "none":
            assert record.elastic is None, (arm, record.elastic)
        else:
            assert isinstance(record.elastic, S.config_fault()), (arm, record.elastic)

        ctx = S.verb_context(record, sibling.run_dir_at, shim.env())
        with pytest.raises(S.config_fault()):
            elastic_adapter.query(ctx, native_query="event.action:ssh_login")
        assert shim.calls() == [], f"[{arm}] an Elastic read reached docker: {shim.calls()}"


# ---- the replay helper chain builds through the resolver -----------------------------------------

def test_d_replay_helper_through_resolver(tmp_path, monkeypatch):
    """tests/_tenants1106.run_tenant builds through run_tenant.resolve_run_tenant and nothing
    else (human, early-exit resolution 2). A replay-driven run's RunTenant is the one
    resolve_run_tenant builds for its tenant folder: the same systems, elastic, ticket_mapping,
    grants and correlation."""
    # G54 / test_1078_env.py:343-361: the harness builds with no data root and no runs base.
    H.set_data_root(monkeypatch, None)
    monkeypatch.delenv("DEFENDER_RUNS_BASE", raising=False)
    _root, _folder, tenant = _plant(tmp_path, "rh1107")
    # #1120: `resolve_run_tenant` is the readiness function (grants, correlation) over the
    # tenant's settings; the record builder over an accepted tenant, which run start's
    # `resolve_tenant` delegates to, is `run_tenant_for`.
    resolved = run_tenant.run_tenant_for(tenant, defender_dir=S.DEFENDER,
                                         dispatches_lead_zero=True)

    # "Nothing else": the one table resolve_run_tenant refuses (CX24: TABLE_BLANK, gather can
    # query nothing) is refused by the helper too — a helper assembling the pieces itself is not.
    _broot, _bfolder, blank = _plant(tmp_path, "rhblank", table=T1106.TABLE_BLANK)
    with pytest.raises(run_tenant.refusals()):
        run_tenant.resolve_run_tenant(blank.settings, defender_dir=S.DEFENDER,
                                      dispatches_lead_zero=False)
    with pytest.raises(run_tenant.refusals()):
        T1106.run_tenant(blank, defender_dir=S.DEFENDER, dispatches_lead_zero=False)

    run_dir = LZ.materialize_alert(tmp_path / "replay", LZ.alert_doc())
    rec = VerbRecorder()
    drive(run_dir, run_id="rh1107", tenant=tenant,
          main=ReplayFn([Turn(text="Investigation complete.")]),
          gather=ReplayFn([Turn(text=LZ.CORRELATION_SUMMARY)]),
          verbs=LZ.elastic_backend(rec, LZ.answer_hits([])))
    assert rec.calls, "lead-zero issued no verb call — the run's record was never observed"
    record = S.record_on(rec.calls[0].ctx)

    assert record.settings == tenant.settings
    assert record.systems == resolved.systems
    assert ([getattr(record.elastic, a) for a in S.ELASTIC_ATTRS]
            == [getattr(resolved.elastic, a) for a in S.ELASTIC_ATTRS])
    assert type(record.ticket_mapping) is type(resolved.ticket_mapping)
    assert S.released_status(record.ticket_mapping) == S.released_status(resolved.ticket_mapping)
    assert record.grants == resolved.grants
    assert record.correlation == resolved.correlation


def test_d_grants_through_tenant_config(tmp_path):
    """A scenario expresses its grants through its tenant folder's verb-grants.yaml. A replay
    over a planted TABLE_B tenant, given no grants argument, runs with the RunGrants that
    run_grants(tenant.settings) projects, and dispatches lead-zero under the correlation
    identity resolve_run_tenant checks. The grants the eight former injection sites handed in
    are exactly these (CX24)."""
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

def test_s60_soc_playground_tests_migrated(tmp_path):
    """The three tests that set SOC_PLAYGROUND_DOCKER_CONTEXT in an env mapping
    (test_encoding_contract_589.py:322, test_947_clock.py:260, _world_1007.py:607) complete
    correctly after being rewritten (d_tests_move_docker_context) to write
    <PREFIX>_DOCKER_CONTEXT into their fixture tenant's config.env instead -- the migration the
    clause records is itself exercised, not merely described."""
    tests_dir = S.DEFENDER / "tests"
    for name in ("test_encoding_contract_589.py", "test_947_clock.py", "_world_1007.py"):
        text = (tests_dir / name).read_text(encoding="utf-8")
        assert SOC_PLAYGROUND_CONTEXT_KEY not in text, (
            f"{name} still sets {SOC_PLAYGROUND_CONTEXT_KEY}")
        assert re.search(r"\b[A-Z][A-Z_]*_DOCKER_CONTEXT\b", text), (
            f"{name} writes no <PREFIX>_DOCKER_CONTEXT for its fixture tenant")

    # The migrated tests themselves, each in a fresh directory of its own (no nested pytest:
    # this process already holds the suite lock).
    enc589 = importlib.import_module("defender.tests.test_encoding_contract_589")
    clock947 = importlib.import_module("defender.tests.test_947_clock")
    world1007 = importlib.import_module("defender.tests._world_1007")
    enc589.test_a_vendor_byte_from_a_transport_is_replaced_not_raised(_fresh(tmp_path, "t589"))
    clock947.test_the_health_check_stamps_nothing_and_stays_that_way(_fresh(tmp_path, "t947"))
    # The 1007 test that drove this fixture (`test_1007_reachability`) went with the replay
    # review (#1224); its body is run here so the migrated fixture still completes a real read.
    _elastic_envelope_carries_no_incidental_fields(world1007, _fresh(tmp_path, "t1007"))

    # test_947_clock's fixture: its own docker shim logs every argv, so the context a call
    # names is observable — and it is the one the fixture tenant's config.env declares.
    where = _fresh(tmp_path, "ctx947")
    ctx = clock947.docker_ctx(where)
    assert SOC_PLAYGROUND_CONTEXT_KEY not in ctx.env, sorted(ctx.env)
    declared = S.record_on(ctx).systems["host-state"]["HOST_STATE_DOCKER_CONTEXT"]
    host_state_adapter.VERBS["health-check"](ctx)
    argvs = clock947.docker_calls(where)
    assert argvs, "the health-check made no docker call"
    assert {S.context_of(argv) for argv in argvs} == {declared}, (declared, argvs)

    # _world_1007's fixture: its shim answers without logging, so the record is what is read.
    ctx = world1007.elastic_ctx(_fresh(tmp_path, "ctx1007"))
    assert SOC_PLAYGROUND_CONTEXT_KEY not in ctx.env, sorted(ctx.env)
    assert S.record_on(ctx).systems["elastic"]["ELASTIC_DOCKER_CONTEXT"], (
        "the 1007 fixture tenant declares no elastic docker context")


def _elastic_envelope_carries_no_incidental_fields(world1007: Any, where: Path) -> None:
    """A REAL raw Elasticsearch response reaches the real `query` verb through `_world_1007`'s
    fixture tenant and docker shim, and the envelope carries only the documents' `_source`."""
    raw = world1007.RAW_ES_RESPONSE
    envelope = elastic_adapter.query(world1007.elastic_ctx(where, response=raw),
                                     native_query="event.action:ssh_login")
    assert set(envelope) == {"index", "total", "returned", "sort", "truncated", "hits"}, (
        sorted(envelope))
    rendered = json.dumps(envelope, sort_keys=True)
    for incidental in ("took", "_shards", "_id", "_score", "max_score"):
        assert incidental not in rendered, incidental
    assert envelope["hits"] == [h["_source"] for h in raw["hits"]["hits"]]


# ---- the settings-path redaction keys on the record ----------------------------------------------

def test_d_record_settings_redacted(tmp_path, monkeypatch):
    """record.settings is the tenant's settings folder path. A ConfigFault whose text names that
    path, either as given or resolved, reaches the model with the path replaced by
    SETTINGS_POINTER ("the tenant's settings/") (CX5)."""
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
