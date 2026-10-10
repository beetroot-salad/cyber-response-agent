"""#1107 — the branch launcher over the tenant settings record: the box-mounted tenants root
(MF-13), the Elastic view's values carried verbatim at resolve (NF-18), a sibling's pass-through
env (GR7) and its own record (N6/MF-17).

#1224 retired what the rest of this file guarded: the launcher no longer refuses a tenant for
its Elastic part (O1: any tenant branches — `live_oracle_1224`'s s_p036), and the corpus-pattern
check, the cluster probe, the write door and the foreign-view guard went with cluster staging.

Every launch drives the REAL `learning/branch/cli.main` over a source run planted at its tenant
location under this test's data root (`_spec1078.tenant_source`: runs-base record + stamp), whose
knowledge folder is then replaced by a COMPLETE #1107 tenant (`_spec1107.plant`).
#1120: the launcher reads the tenant from `DEFENDER_DATA_ROOT` alone — no flag names it.
Fakes enter only through the launcher's seams (`spawn`, `questioner`, `preflight`, `live_tree`).
The role preflight is a RECORDING TRIPWIRE answering 1: a launch that got past every check
knowable before spend reaches it and is refused there, so "the refusal came before any preflight
spend" is an observation (`calls == []`), and a control arm that reaches it (`calls == [None]`)
proves the refused arm was refused for its own reason.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from defender.learning.branch import cli
from defender.runtime import run_tenant
from defender.scripts.adapters import elastic_adapter
from defender._episode_handle import Episode
from defender.tests import _triplet_947 as T
from defender.tests.e2e import _lead_zero_808 as LZ
from defender.tests.tenant_1078_pass_a import _spec1078 as H
from defender.tests.tenant_1107_settings import _spec1107 as S

#: A tenant id nothing else on this box spells, so "the message names the tenant" is a finding
#: about the message and never about a default.
TID = "acme-t1107"
#: The config-shaped variables a developer's shell might carry. Cleared before every launch so a
#: value either side of an assertion is the one the test put there.
_CONFIG_VARS = ("ELASTIC_EVENTS_INDEX", "ELASTIC_ALERTS_INDEX", "ELASTICSEARCH_URL",
                "ELASTIC_SSL_VERIFY", "SOC_PLAYGROUND_ES_CONTAINER",
                "SOC_PLAYGROUND_KIBANA_CONTAINER", "SOC_PLAYGROUND_DOCKER_CONTEXT",
                "CMDB_URL_BASE", "DEFENDER_RUN_DIR", "DEFENDER_RUNS_BASE")


class _Preflight:
    """The role-model preflight seam, RECORDING and answering `rc` (1: the tripwire)."""

    def __init__(self, rc: int = 1) -> None:
        self.rc = rc
        self.calls: list[str | None] = []

    def __call__(self, model: str | None = None, *, branching: bool = False) -> int:
        self.calls.append(model)
        return self.rc


def _layout(tmp_path: Path, data_root: Path, monkeypatch, *,
            marker: str) -> tuple[Path, Path, Path, Path]:
    """A branchable source at TID's tenant location, TID's complete #1107 knowledge folder set
    up under `data_root` (this test's, the one the launcher reads), and a configured episodes
    root. Returns (src, data root, knowledge folder, episodes)."""
    for name in _CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    episodes = tmp_path / "episodes"
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(episodes))
    _base, src = H.tenant_source(data_root, TID)
    folder = S.plant(data_root, TID, marker=marker)
    return src, data_root, folder, episodes


def _seams(**over: Any) -> dict[str, Any]:
    """Every launcher seam faked; `questioner` holds no replies, so reaching it is an
    AssertionError out of the fake rather than a model call."""
    seams: dict[str, Any] = {
        "spawn": T.FakeSpawn(), "questioner": T.FakeAgent(), "live_tree": T.source_capture(),
        "preflight": _Preflight()}
    seams.update(over)
    return seams


def _launch(src: Path, root: Path, seams: dict[str, Any]) -> tuple[Any, BaseException | None]:
    """The REAL launcher over `src`, whose tenant is set up under `root` — this test's data root
    (#1120: the launcher reads it from `DEFENDER_DATA_ROOT`; no flag names it). Returns (rc, None)
    or (None, the SystemExit it refused with)."""
    S._require_data_root(root)
    argv = [str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", H.CONTINUATION]
    try:
        return cli.main(argv, **seams), None
    except SystemExit as refused:
        return None, refused


def _resolve(root: Path) -> Any:
    """The REAL acceptance frame over a planted root (C1)."""
    return run_tenant.resolve_tenant(
        Path(root), TID, defender_dir=S.DEFENDER, dispatches_lead_zero=False)


def _sans_paths(text: str, *paths: Path) -> str:
    """`text` with every spelling of `paths` removed — the source run and both tenant folders
    carry the tenant id as a path component, so "names the tenant" is read off what is left."""
    spelled = sorted({s for p in paths for s in (str(p), str(Path(p).resolve()))},
                     key=len, reverse=True)
    for s in spelled:
        text = text.replace(s, "<path>")
    return text


def _episode_dir(episodes: Path) -> Path:
    return episodes / cli.episode_id_for(T.SOURCE_RUN_ID, T.BRANCH_MESSAGE_ID)


# ---------------------------------------------------------------------------------------------
# MF-7a / MF-13 — an Elastic part with no docker-exec transport; a box-mounted tenants root.
# ---------------------------------------------------------------------------------------------

def test_s7_mf7a_elastic_without_docker_exec_is_a_fault(tmp_path, data_root, monkeypatch):
    """A tenant whose elastic config.env carries every listed Elastic key but no ELASTIC_TRANSPORT
    (or one other than docker-exec) has record.elastic a ConfigFault, and lead-zero's item 1
    reports unavailable naming the cause."""
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    _src, root, folder, _episodes = _layout(tmp_path, data_root, monkeypatch, marker="mf7a")

    # Positive control: the same complete file WITH `ELASTIC_TRANSPORT=docker-exec` is a view.
    assert isinstance(_resolve(root).elastic, S.record_type("ElasticSettings")), \
        "the complete file is not a view"
    for arm, edit in (("absent", lambda: S.drop_key(folder, "elastic", "ELASTIC_TRANSPORT")),
                      ("ssh", lambda: S.set_key(folder, "elastic", "ELASTIC_TRANSPORT", "ssh"))):
        edit()
        fault = _resolve(root).elastic
        assert isinstance(fault, S.config_fault()), \
            f"TRANSPORT {arm}: record.elastic is not a ConfigFault: {fault!r}"
        S.set_key(folder, "elastic", "ELASTIC_TRANSPORT", S.DOCKER_EXEC)

    # Lead-zero's item 1 over the same tenant, for an alert with no signal_index: the complete
    # tenant issues the shell fetch (the channel can see the difference) ...
    tenant_dir = S.tenant_folder_of(root, TID)
    ok = LZ.run(tmp_path / "lz-ok", alert=LZ.alert_doc(signal_index=None), tenant=tenant_dir)
    assert ok.rec.calls, "control: item 1 issued no backend call over the complete tenant"
    # ... and the one with no ELASTIC_TRANSPORT reports unavailable, issuing none. The note names
    # the cause (F11, auto: 'elastic config is bad') — the control's own section can say
    # "unavailable" too (the fetch found nothing), so the cause and the call count discriminate.
    S.drop_key(folder, "elastic", "ELASTIC_TRANSPORT")
    bad = LZ.run(tmp_path / "lz-bad", alert=LZ.alert_doc(signal_index=None), tenant=tenant_dir)
    assert bad.rec.calls == [], f"item 1 issued {len(bad.rec.calls)} backend call(s)"
    assert LZ.UNAVAILABLE in bad.section(), \
        f"item 1 did not report unavailable: {bad.section()[:600]!r}"
    assert S.BAD_ELASTIC in bad.section(), \
        f"item 1's note does not name the cause: {bad.section()[:600]!r}"


def test_s7_mf13_launcher_refuses_box_mounted_tenants_root(tmp_path, data_root, monkeypatch):
    """The branch launcher passes its box-mounted trees (the episodes base, and the runs base it
    resolves at cli.py:1374) to resolve_tenant as box_mounted: a tenants root inside either is
    refused at launch with LauncherRefused naming the tenant, before any episode dir exists and
    before any sibling starts."""
    # #1120: the tenants root is the data root (`DEFENDER_DATA_ROOT`, no flag), so "a tenants
    # root inside the episodes base" is a data root inside it — the tenant's settings half then
    # lies inside a tree the box mounts, which acceptance's step 7 refuses for the launcher's
    # `box_mounted`. The runs-base arm has no #1120 counterpart: the runs base is
    # `<data root>/<T>/runs`, derived from the data root, so a data root inside it is circular,
    # and acceptance itself (not the launcher) holds every tenant's own runs base.
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    src, outside, _folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="mf13")

    # Positive control: the same tenant under a root outside both trees passes every check
    # before spend.
    control = _seams()
    _launch(src, outside, control)
    assert control["preflight"].calls == [None], \
        "the control launch (tenants root outside both trees) never reached the role preflight"

    for arm, root in (("inside the episodes base", episodes / "tenants-in-episodes"),):
        root.mkdir(parents=True)
        H.set_data_root(monkeypatch, root)
        _base, src_in = H.tenant_source(root, TID)
        S.plant(root, TID, marker="mf13")
        resolved = run_tenant.resolve_tenant(root, TID, defender_dir=S.DEFENDER,
                                             dispatches_lead_zero=False)
        assert resolved.tenant_id == TID, f"{arm}: the resolver alone refuses this root"
        seams = _seams()
        rc, refused = _launch(src_in, root, seams)
        assert isinstance(refused, cli.LauncherRefused), \
            f"{arm}: the launcher accepted a box-mounted tenants root (rc={rc}, {refused!r})"
        text = H.refusal_text(refused)
        assert TID in _sans_paths(text, src, src_in, root / TID, outside / TID, data_root / TID), \
            f"{arm}: the refusal does not name the tenant: {text!r}"
        # The launcher's own episodes-base guard also refuses a base containing the data root;
        # the refusal observed here is acceptance's, over the launcher's `box_mounted`.
        assert "which a box mounts" in text, \
            f"{arm}: the refusal is not the box-mounted settings refusal: {text!r}"
        assert seams["preflight"].calls == [], f"{arm}: the role preflight was spent: {text!r}"
        assert seams["spawn"].launches == [], f"{arm}: a sibling started"
        assert seams["questioner"].prompts == [], f"{arm}: the questioner was asked"
        assert not _episode_dir(episodes).exists(), f"{arm}: an episode dir exists"


# ---------------------------------------------------------------------------------------------
# NF-18 — the Elastic view's values are carried verbatim at resolve.
# ---------------------------------------------------------------------------------------------

def test_s60_elastic_events_index_values_carried_forward(tmp_path, data_root, monkeypatch):
    """ELASTIC_EVENTS_INDEX is not validated beyond presence (NF-18): a plain (non-wildcard)
    pattern, a bare '*' and an upper-case/CHANGE-ME pattern are each carried verbatim into
    record.elastic at resolve, the part still a view (no resolve-time value validation). A VALID
    pattern exported under the same key does not reach the record."""
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    _src, root, folder, _episodes = _layout(tmp_path, data_root, monkeypatch, marker="s60e")
    view_type = S.record_type("ElasticSettings")

    for value in ("s60e-events", "*", "CHANGE-ME"):
        S.set_key(folder, "elastic", "ELASTIC_EVENTS_INDEX", value)
        if value == "CHANGE-ME":
            monkeypatch.setenv("ELASTIC_EVENTS_INDEX", "s60e-env-*")
        carried = _resolve(root).elastic
        assert isinstance(carried, view_type), f"{value!r} faulted the part: {carried!r}"
        assert carried.events_index == value, \
            f"{value!r} not carried verbatim: {carried.events_index!r}"


def test_s60_elastic_ssl_verify_values_pass_through(tmp_path, data_root, monkeypatch):
    """ELASTIC_SSL_VERIFY is not validated (F3/NF-18, presence-only): 'false', 'TRUE' (uppercase)
    and 'CHANGE-ME' are each carried into record.elastic as the raw string, with no rejection."""
    _src, root, folder, _episodes = _layout(tmp_path, data_root, monkeypatch, marker="ssl")
    for value in ("false", "TRUE", "CHANGE-ME"):
        S.set_key(folder, "elastic", "ELASTIC_SSL_VERIFY", value)
        carried = _resolve(root).elastic
        assert isinstance(carried, S.record_type("ElasticSettings")), \
            f"ELASTIC_SSL_VERIFY={value!r} faulted the part: {carried!r}"
        assert carried.ssl_verify == value, \
            f"ELASTIC_SSL_VERIFY={value!r} not carried as the raw string: {carried!r}"


# ---------------------------------------------------------------------------------------------
# GR7 / N6 — siblings: the launcher's pass-through env, and a sibling's own record.
# ---------------------------------------------------------------------------------------------

def test_s60_launch_one_env_is_passthrough(tmp_path, data_root, monkeypatch):
    """learning/branch/cli.py's launch_one closure passes os.environ to each sibling's spawn as a
    wholesale copy, with no per-key lookup or branch on any tenant-config-shaped name -- a sibling
    launch is unaffected by a config key exported in the launching process's environment, the same
    guarantee O1's other tests pin for the adapters."""
    for name in _CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    H.make_tenant(data_root, TID)
    S.plant(data_root, TID, marker="gr7")

    quiet_ep = T.episode(tmp_path / "quiet", root=tmp_path / "quiet" / "episodes")
    quiet = T.FakeSpawn()
    cli.start_family(Episode.open(quiet_ep), ["b"], spawn=quiet, tenant_id=TID)
    quiet_environ = dict(os.environ)

    exported = {"CMDB_URL_BASE": "http://gr7-env-cmdb.invalid:1",
                "ELASTIC_EVENTS_INDEX": "gr7env-events-*"}
    for key, value in exported.items():
        monkeypatch.setenv(key, value)
    loud_ep = T.episode(tmp_path / "loud", root=tmp_path / "loud" / "episodes")
    loud = T.FakeSpawn()
    cli.start_family(Episode.open(loud_ep), ["b"], spawn=loud, tenant_id=TID)
    loud_environ = dict(os.environ)

    assert len(quiet.launches) == 1, (quiet.launches, loud.launches)
    assert len(loud.launches) == 1, (quiet.launches, loud.launches)
    q, lo = quiet.launches[0], loud.launches[0]
    # Positive precondition: the exported config key WAS in what the sibling was handed.
    assert lo["env"].get("CMDB_URL_BASE") == exported["CMDB_URL_BASE"], \
        "the exported key is not in the sibling's env — the channel is blind"
    # A wholesale copy of the launching environment, nothing selected, dropped or added ...
    assert q["env"] == quiet_environ, "the quiet sibling's env is not os.environ copied whole"
    assert lo["env"] == loud_environ, "the loud sibling's env is not os.environ copied whole"
    # ... and the launch is otherwise unaffected by the exported key.
    assert [a.replace(str(loud_ep), "<ep>") for a in lo["argv"]] == \
        [a.replace(str(quiet_ep), "<ep>") for a in q["argv"]], (q["argv"], lo["argv"])
    assert lo["kw"] == q["kw"], (q["kw"], lo["kw"])


def test_s7_mf17_sibling_resolves_its_own_record(tmp_path, data_root, monkeypatch):
    """An elastic config.env edited between the launch and a sibling's start: the sibling builds
    its own record at its own start (N6), so an edit that makes its Elastic part bad makes that
    sibling's Elastic calls fault (O5) without refusing it."""
    shim = S.DockerShim(tmp_path / "docker")
    monkeypatch.setenv("PATH", shim.path_value())
    for name in _CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    _base, src = H.tenant_source(data_root, TID)
    root = data_root
    folder = S.plant(root, TID, marker="mf17")
    manifest = H.family_for(src, tmp_path / "episodes" / T.EPISODE_ID)
    # At launch the Elastic part was whole ...
    assert isinstance(_resolve(root).elastic, S.record_type("ElasticSettings")), \
        "the tenant's Elastic part was not whole at launch"
    # ... and is edited bad before the sibling starts.
    S.drop_key(folder, "elastic", "ELASTIC_ES_CONTAINER")

    rec = S.RunRecorder(tmp_path / "sibling-run")
    rc, refused = S.drive_run(
        H.resume_argv(manifest, "b", "--tenant", TID), rec,
        visualize=rec.visualize)

    assert refused is None, f"the sibling was refused: {H.refusal_text(refused)!r}"
    assert rc == 0, f"the sibling exited {rc} ({rec.order})"
    assert len(rec.lifecycle_calls) == 1, f"lifecycle ran {len(rec.lifecycle_calls)} times"
    record, world = rec.lifecycle_calls[0]["tenant"], rec.lifecycle_calls[0]["world"]
    assert world.label == "b", f"the sibling ran another world: {world!r}"
    assert isinstance(record.elastic, S.config_fault()), \
        f"the sibling's own record does not see the edit: {record.elastic!r}"
    # Its Elastic calls fault (O5).
    run_dir = tmp_path / "sibling-run"
    with pytest.raises(S.config_fault()):
        elastic_adapter.query(S.verb_context(record, run_dir, shim.env()), native_query="*")
    assert shim.calls() == [], f"a faulted Elastic call reached docker: {shim.calls()}"
