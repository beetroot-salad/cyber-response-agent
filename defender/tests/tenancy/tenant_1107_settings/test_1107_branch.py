"""Branch launcher and tenant settings: box-mounted tenants-root refusal; a sibling resolves its own record."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from pathlib import Path
from typing import Any

import pytest

from defender.learning.branch import cli
from defender.runtime import run_tenant
from defender.integrations import elastic_adapter
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

#: A tenant id nothing else on this box spells, so "the message names the tenant" is a finding
#: about the message and never about a default.
TID = fixture_uuid("tenant:acme-t1107")
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
    """A branchable tenant source, complete settings, and its canonical episodes folder."""
    for name in _CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    episodes = data_root / TID / "episodes"
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
    # #1105 PR 2 (declared change 1): the tenant and the source run by id.
    argv = ["--tenant", src.parent.parent.name, src.name, str(T.BRANCH_MESSAGE_ID),
            *T.retired_continuation_argv()]
    try:
        return cli.main(argv, **seams), None
    except SystemExit as refused:
        return None, refused


def _resolve(root: Path) -> Any:
    """The REAL acceptance frame over a planted root (C1)."""
    return run_tenant.resolve_tenant(
        fixture_data_root(Path(root)), TID, defender_dir=S.DEFENDER, dispatches_lead_zero=False)


def _sans_paths(text: str, *paths: Path) -> str:
    """`text` with every spelling of `paths` removed — the source run and both tenant folders
    carry the tenant id as a path component, so "names the tenant" is read off what is left."""
    spelled = sorted({s for p in paths for s in (str(p), str(Path(p).resolve()))},
                     key=len, reverse=True)
    for s in spelled:
        text = text.replace(s, "<path>")
    return text


def test_s7_mf13_launcher_refuses_box_mounted_tenants_root(tmp_path, data_root, monkeypatch):
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    src, outside, _folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="mf13")

    # Positive control: the same tenant under a root outside both trees passes every check
    # before spend.
    control = _seams()
    _launch(src, outside, control)
    assert control["preflight"].calls == [None], \
        "the control launch (tenants root outside both trees) never reached the role preflight"

    episodes.symlink_to(_folder, target_is_directory=True)
    before = set(episodes.iterdir())
    resolved = run_tenant.resolve_tenant(fixture_data_root(outside), TID, defender_dir=S.DEFENDER,
                                         dispatches_lead_zero=False)
    assert resolved.tenant_id == TID, "the resolver alone refuses this root"
    seams = _seams()
    rc, refused = _launch(src, outside, seams)
    assert isinstance(refused, cli.LauncherRefused), \
        f"the launcher accepted box-mounted settings (rc={rc}, {refused!r})"
    text = H.refusal_text(refused)
    assert TID in _sans_paths(text, src, outside / TID, data_root / TID), \
        f"the refusal does not name the tenant: {text!r}"
    assert "which a box mounts" in text, \
        f"the refusal is not the box-mounted settings refusal: {text!r}"
    assert seams["preflight"].calls == [], f"the role preflight was spent: {text!r}"
    assert seams["spawn"].launches == [], "a sibling started"
    assert seams["questioner"].prompts == [], "the questioner was asked"
    assert set(episodes.iterdir()) == before, "the refused launch claimed an episode"


def test_s7_mf17_sibling_resolves_its_own_record(tmp_path, data_root, monkeypatch):
    shim = S.DockerShim(tmp_path / "docker")
    monkeypatch.setenv("PATH", shim.path_value())
    for name in _CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    _base, src = H.tenant_source(data_root, TID)
    root = data_root
    folder = S.plant(root, TID, marker="mf17")
    manifest = H.family_for(src)
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
