"""Acceptance answers a link loop or linked tenant folder with its own refusal, never a traceback.

A name chosen by a tenant repo reaches a refusal escaped, so it cannot forge a verdict line.

_io.stat_entries judges every directory entry without following it.

One rule for the tenant a request names.

The launcher refuses a bad tenant before its billable role preflight.

(`validate_scaffold` judging settings against an exported `DEFENDER_DIR` tree is retired: #1366 O11.)

Tenant refuses a construction without acceptance's token.
"""
from __future__ import annotations

import shutil
from pathlib import Path
import os
import stat

import pytest

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path
from defender import _paths
from defender.tenancy import _tenant
from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
from defender import _io
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.records._tenant_id import TenantRefused
from defender.cli.learning import branch as branch_entry
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.records._tenant_id import TenantId


def test_a_knowledge_folder_linked_to_itself_is_refused_by_name(tmp_path: Path) -> None:
    """`<T>/knowledge -> knowledge` (a one-link loop): refused naming the knowledge path.
    Control: the same row beside a real knowledge folder is accepted."""
    root = tmp_path / "data"
    H.adopted(root)
    knowledge = H.knowledge_dir(root)
    shutil.rmtree(knowledge)
    knowledge.symlink_to("knowledge")
    text = H.accept_refusal(_tenant, root)
    assert str(knowledge) in text, text

    knowledge.unlink()
    H.place_knowledge(root)
    assert H.accept(_tenant, root).knowledge == knowledge


def test_a_data_root_linked_to_itself_is_refused_by_name(tmp_path: Path) -> None:
    """A data root that is a self-loop: refused naming the root, before anything under it."""
    root = tmp_path / "data"
    root.symlink_to("data")
    text = H.accept_refusal(_tenant, root)
    assert str(root) in text, text


def test_check_folder_over_a_looped_folder_refuses_without_a_traceback(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    loop.symlink_to("loop")
    H.assert_refused(H.check(tenant_py, None, "--folder", str(loop)), "[tenant.py]", str(loop))
    refused = H.refusal(_tenant, _tenant.check_knowledge_folder, loop, tenant_id=None)
    assert str(loop) in str(refused), refused


def test_runs_linked_onto_knowledge_puts_settings_in_a_mounted_tree(tmp_path: Path) -> None:
    """`<T>/runs -> knowledge`: the settings half now lies inside the runs base a box mounts,
    so acceptance refuses it, naming the settings. Control: a real `runs/` is accepted."""
    root = tmp_path / "data"
    H.adopted(root)
    runs = H.tenant_folder(root) / "runs"
    shutil.rmtree(runs, ignore_errors=True)
    runs.symlink_to("knowledge")
    text = H.accept_refusal(_tenant, root)
    assert str(H.settings_dir(root)) in text, text

    runs.unlink()
    runs.mkdir()
    assert location_path(H.accept(_tenant, root).runs) == runs


def test_a_linked_settings_systems_folder_is_named_as_a_link(tmp_path: Path) -> None:
    """#1359: no required setting sits under `systems/` any more, so a linked `systems/` is
    refused by the link walk, not as the way to a missing required file. (#1366 O9: the tenant repo no longer
    carries `systems/`; a leftover one is still walked, so the test plants it.)"""
    root = tmp_path / "data"
    H.adopted(root)
    systems = H.settings_dir(root) / "systems"
    systems.mkdir(exist_ok=True)
    (systems / "leftover").mkdir(exist_ok=True)
    copy = tmp_path / "systems-copy"
    shutil.move(str(systems), copy)
    systems.symlink_to(copy, target_is_directory=True)
    text = H.accept_refusal(_tenant, root)
    assert f"{systems} is a link" in text, text
    assert "required settings file is missing" not in text, text


def test_a_tenant_folder_linked_into_the_checkout_is_refused_before_acceptance(
        tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    (root / H.TID).symlink_to(_paths.PATHS.defender_dir, target_is_directory=True)
    refused = H.refusal(_tenant, _tenant._TenantPaths, fixture_data_root(root), H.TID)
    assert "inside the checkout's defender/ tree" in str(refused), refused

    (root / H.TID).unlink()
    (root / H.TID).mkdir()
    assert location_path(_tenant._TenantPaths(fixture_data_root(root), H.TID).tenant_root) == root / H.TID


def test_a_nul_in_a_mounted_tree_path_is_a_refusal(tmp_path: Path) -> None:
    """A caller-handed path with a NUL cannot be resolved (`ValueError`, not `OSError`): it is
    the refusal naming the path, never an escaping `ValueError`."""
    root = tmp_path / "data"
    H.adopted(root)
    text = H.accept_refusal(_tenant, root, box_mounted=(Path("/tmp/a\0b"),))
    assert "could not be resolved" in text, text


@pytest.mark.parametrize("target", ["knowledge/agent", "knowledge/settings/systems",
                                    "knowledge/archive", "knowledge/.git"])
def test_runs_linked_into_a_knowledge_half_is_refused(tmp_path: Path, target: str) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    runs = H.tenant_folder(root) / "runs"
    shutil.rmtree(runs, ignore_errors=True)
    (H.tenant_folder(root) / target).mkdir(parents=True, exist_ok=True)
    runs.symlink_to(target)
    text = H.accept_refusal(_tenant, root)
    assert str(runs) in text, text
    assert "knowledge folder" in text, text


_FORGED = "\x1b[2K\r[tenant.py] all checks passed\n"


def _no_control_characters(text: str) -> None:
    assert not any(ord(c) < 0x20 or c == "\x7f" for c in text), repr(text)


def test_a_stray_top_level_name_is_shown_escaped(tmp_path: Path) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    (H.knowledge_dir(root) / _FORGED).write_text("", encoding="utf-8")
    text = H.accept_refusal(_tenant, root)
    _no_control_characters(text)
    assert repr(_FORGED) in text, text


@pytest.mark.parametrize("half", ["settings", "agent"])
def test_a_link_inside_a_half_is_named_escaped(tmp_path: Path, half: str) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    (H.knowledge_dir(root) / half / _FORGED).symlink_to("/etc/hostname")
    text = H.accept_refusal(_tenant, root)
    _no_control_characters(text)
    assert "is a link" in text, text


def test_each_entry_is_judged_as_itself(tmp_path: Path) -> None:
    """A file, a directory, a link and a FIFO (never opened, so it cannot block): each
    answers with its own kind. An absent directory answers absent; a linked one is refused."""
    d = tmp_path / "root" / "d"
    d.mkdir(parents=True)
    (d / "file").write_text("x", encoding="utf-8")
    (d / "sub").mkdir()
    (d / "link").symlink_to("file")
    os.mkfifo(d / "fifo")
    (tmp_path / "root" / "linked").symlink_to("d")
    with _io.bind(tmp_path / "root") as bound:
        got = _io.stat_entries(bound.under("d"))
        absent = _io.stat_entries(bound.under("nothing"))
        linked = _io.stat_entries(bound.under("linked"))
    assert got.stats is not None, got
    kinds = {name: stat.S_IFMT(st.st_mode) for name, st in got.stats.items()}
    assert kinds == {"file": stat.S_IFREG, "sub": stat.S_IFDIR, "link": stat.S_IFLNK,
                     "fifo": stat.S_IFIFO}, kinds
    assert absent.absent, absent
    assert absent.stats is None, absent
    assert linked.stats is None, linked
    assert linked.reason == _io.ALIAS_READ_REFUSAL, linked


def test_an_absent_or_malformed_request_is_refused() -> None:
    with pytest.raises(TenantRefused, match="no default tenant"):
        _tenant.requested_tenant_id(None)
    with pytest.raises(TenantRefused):
        _tenant.requested_tenant_id("../x")
    assert _tenant.requested_tenant_id(fixture_uuid("tenant:acme")) == fixture_uuid("tenant:acme")


def _no_tenant_root(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    root.mkdir()
    return root


def test_the_launcher_refuses_before_its_role_preflight(tmp_path: Path, monkeypatch) -> None:
    """A source under a data root holding no tenant is refused before the role preflight
    runs."""
    root = _no_tenant_root(tmp_path)
    monkeypatch.setenv(H.DATA_ROOT_ENV, str(root))
    calls: list[object] = []

    def recording_preflight(model: str | None = None) -> int:
        calls.append(model)
        return 0

    source = root / H.TID / "runs" / T.SOURCE_RUN_ID
    try:
        got: object = branch_entry.main(
            [str(source), str(T.BRANCH_MESSAGE_ID)],
            spawn=T.FakeSpawn(), preflight=recording_preflight)
    except SystemExit as refused:
        got = refused
    assert isinstance(got, BaseException) or got != 0, f"the launch was not refused: {got!r}"
    assert calls == [], f"the role preflight ran before the refusal: {calls}"


# Retired (#1366 O11, O9): `test_validate_scaffold_holds_settings_outside_the_tree_it_checks`. It asserted validate_scaffold's
# "config.env not checked" WARN for a data-root tenant whose settings sit inside the exported tree; the validator no longer reads
# a tenant's `config.env` (its input is connect's handoff folder, `tenant_1107_settings/test_validator.py`), so there is no
# data-root settings check to skip and no such WARN.


def test_a_forged_token_is_refused_by_the_guard(tmp_path: Path) -> None:
    """Every field supplied, `_token` a fresh object: `TenantRefused` naming acceptance."""
    with pytest.raises(TenantRefused, match="accept_tenant"):
        _tenant.Tenant(id=TenantId(fixture_uuid("tenant:acme")), data_root=tmp_path, _token=object())
