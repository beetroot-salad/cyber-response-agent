"""#1107 — the branch launcher over the tenant settings record: the Elastic view's values
carried verbatim at resolve (NF-18), a sibling's pass-through env (GR7) and its own record
(N6/MF-17).

#1187 (design rev 2, O9 and S-acc): `DEFENDER_EPISODES_BASE` is read by nothing, so MF-13's
"a data root inside the configured episodes base" has no configured base to sit inside;
`test_s7_mf13_launcher_refuses_box_mounted_tenants_root` was deleted (the graph says so) and
the launcher's box-mounted `<T>/episodes` is pinned by
`ids_1187/test_1187_roster_consumers.py::test_the_launcher_refuses_a_settings_half_inside_its_episodes_folder`.

#1224 retired what the rest of this file guarded: the launcher no longer refuses a tenant for
its Elastic part (O1: any tenant branches — `live_oracle_1224`'s s_p036), and the corpus-pattern
check, the cluster probe, the write door and the foreign-view guard went with cluster staging.

Every launch drives the REAL `learning/branch/cli.main` over a source run planted at its tenant
location under this test's data root (`_spec1078.tenant_source`: runs-base record + stamp), whose
knowledge folder is then replaced by a COMPLETE #1107 tenant (`_spec1107.plant`).
#1120: the launcher reads the tenant from `DEFENDER_DATA_ROOT` alone — no flag names it.
Fakes enter only through the launcher's seams (`spawn`, `questioner`, `preflight`, `live_tree`).
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


def _resolve(root: Path) -> Any:
    """The REAL acceptance frame over a planted root (C1)."""
    return run_tenant.resolve_tenant(
        Path(root), TID, defender_dir=S.DEFENDER, dispatches_lead_zero=False)


# ---------------------------------------------------------------------------------------------
# NF-18 — the Elastic view's values are carried verbatim at resolve.
# ---------------------------------------------------------------------------------------------

def test_s60_elastic_events_index_values_carried_forward(tmp_path, data_root, monkeypatch):
    """ELASTIC_EVENTS_INDEX is not validated beyond presence (NF-18): a plain (non-wildcard)
    pattern, a bare '*' and an upper-case/CHANGE-ME pattern are each carried verbatim into
    the tenant's systems["elastic"] at resolve (no resolve-time value validation). A VALID
    pattern exported under the same key does not reach the record."""
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    _src, root, folder, _episodes = _layout(tmp_path, data_root, monkeypatch, marker="s60e")

    for value in ("s60e-events", "*", "CHANGE-ME"):
        S.set_key(folder, "elastic", "ELASTIC_EVENTS_INDEX", value)
        if value == "CHANGE-ME":
            monkeypatch.setenv("ELASTIC_EVENTS_INDEX", "s60e-env-*")
        carried = _resolve(root).systems["elastic"]
        assert isinstance(carried, S.record_type("SystemConfig")), \
            f"{value!r} faulted the part: {carried!r}"
        assert carried["ELASTIC_EVENTS_INDEX"] == value, \
            f"{value!r} not carried verbatim: {carried['ELASTIC_EVENTS_INDEX']!r}"


def test_s60_elastic_ssl_verify_values_pass_through(tmp_path, data_root, monkeypatch):
    """ELASTIC_SSL_VERIFY is not validated (F3/NF-18, presence-only): 'false', 'TRUE' (uppercase)
    and 'CHANGE-ME' are each carried into the record's systems["elastic"] as the raw string, with no rejection."""
    _src, root, folder, _episodes = _layout(tmp_path, data_root, monkeypatch, marker="ssl")
    for value in ("false", "TRUE", "CHANGE-ME"):
        S.set_key(folder, "elastic", "ELASTIC_SSL_VERIFY", value)
        carried = _resolve(root).systems["elastic"]
        assert isinstance(carried, S.record_type("SystemConfig")), \
            f"ELASTIC_SSL_VERIFY={value!r} faulted the part: {carried!r}"
        assert carried["ELASTIC_SSL_VERIFY"] == value, \
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
    manifest = H.family_for(src)  # #1187: at `<root>/<T>/episodes/<uuid>`, RUNS reached
    # At launch the Elastic part was whole ...
    assert "ELASTIC_ES_CONTAINER" in _resolve(root).systems["elastic"], \
        "the tenant's Elastic part was not whole at launch"
    # ... and is edited bad before the sibling starts.
    S.drop_key(folder, "elastic", "ELASTIC_ES_CONTAINER")

    rec = S.RunRecorder(tmp_path / "sibling-run")
    rc, refused = S.drive_run(
        H.sibling_argv(manifest, "b", "--tenant", TID), rec,
        visualize=rec.visualize)

    assert refused is None, f"the sibling was refused: {H.refusal_text(refused)!r}"
    assert rc == 0, f"the sibling exited {rc} ({rec.order})"
    assert len(rec.lifecycle_calls) == 1, f"lifecycle ran {len(rec.lifecycle_calls)} times"
    record, world = rec.lifecycle_calls[0]["tenant"], rec.lifecycle_calls[0]["world"]
    assert world.label == "b", f"the sibling ran another world: {world!r}"
    assert "ELASTIC_ES_CONTAINER" not in record.systems["elastic"], \
        f"the sibling's own record does not see the edit: {record.systems['elastic']!r}"
    # Its Elastic calls fault (O5).
    run_dir = tmp_path / "sibling-run"
    with pytest.raises(S.config_fault()):
        elastic_adapter.query(S.verb_context(record, run_dir, shim.env()), native_query="*")
    assert shim.calls() == [], f"a faulted Elastic call reached docker: {shim.calls()}"
