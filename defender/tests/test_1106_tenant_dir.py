"""#1106 — the tenant resolver: `tenant_dir(tenants_root, tenant_id) -> TenantDir` (O5, O4, D3).

ONE resolver maps (tenants root, tenant id) to the tenant's two halves, `settings/` (host-only:
the four settings kinds) and `agent/` (model-facing, mounted read-only into the box). It is the
one place a tenant id becomes a path, so it is where both escapes the design names are closed:

  * the ID — a path separator, `..`, a leading dot, or nothing at all is not a tenant id (O5);
  * the LINK — the tenant folder must resolve under the root, and each half must be a real
    directory resolving under `<root>/<id>/`, which is what catches `A/agent -> ../B/agent` and
    `A/agent -> ../settings`: both stay INSIDE the root, so a root-containment check alone
    passes them (O5).

and where D3's "fail loudly" lives: an absent tenant folder or an absent required settings file
(`verb-grants.yaml`, `lead-zero.yaml`, `systems/case-history/mapping.yaml`) is a
`TenantDirError` NAMING THE PATH, with no fallback to another tenant, the template, or the
checkout (O4).

Every fault here is a real one planted through the real primitive — real directories, real
symlinks, real missing files — and every refusal is paired with the well-formed tenant it
differs from by exactly that fault.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.tests import _tenants1106 as T


def _resolver():
    m = T.tenants()
    return m.tenant_dir, m.TenantDirError


def _refusal(root: Path, tenant_id: str) -> str:
    tenant_dir, error = _resolver()
    with pytest.raises(error) as caught:
        tenant_dir(root, tenant_id)
    return str(caught.value)


# ---- the positive control every refusal below is measured against -----------------------------

def test_a_well_formed_tenant_resolves_to_its_two_halves_under_root_and_id(tmp_path):
    """The control: a complete tenant resolves, and both halves are the RESOLVED paths under
    `<root>/<id>/` — resolved, because the box mounts `agent` by its resolved path (M6) and a
    reader's path is compared by it."""
    root = tmp_path / "tenants"
    T.plant_tenant(root, "acme")
    tenant_dir, _ = _resolver()
    td = tenant_dir(root, "acme")
    assert td.tenant_id == "acme"
    assert td.settings == (root / "acme" / "settings").resolve()
    assert td.agent == (root / "acme" / "agent").resolve()
    # Read THROUGH the resolved half: the file the table loader will open is the one planted.
    assert (td.settings / "verb-grants.yaml").read_text(encoding="utf-8") == T.TABLE_A


def test_the_tenant_dir_error_is_a_value_error():
    _, error = _resolver()
    assert issubclass(error, ValueError)


def test_the_required_settings_are_exactly_d3s_three_files():
    """D3: required AT START means these three. `config.env` is not among them — some
    adapters need none, and its absence stays the existing per-call `ConfigFault`."""
    assert set(T.tenants().REQUIRED_SETTINGS) == set(T.REQUIRED_FILES)


def test_a_tenant_without_any_config_env_still_resolves(tmp_path):
    """The other half of D3's list: a tenant whose systems carry no `config.env` at all is
    not refused at start (an MCP-path or config-less adapter is legal)."""
    root = tmp_path / "tenants"
    T.plant_tenant(root, "acme", configs={})
    tenant_dir, _ = _resolver()
    assert tenant_dir(root, "acme").settings == (root / "acme" / "settings").resolve()


# ---- O5: the id ----------------------------------------------------------------------------

@pytest.mark.parametrize("bad_id", ["../x", "a/b", ".hidden", "", "..", "."])
def test_an_id_that_is_not_a_single_plain_name_is_refused_naming_it(tmp_path, bad_id):
    """An id with a path separator, `..`, a leading dot, or no name at all is refused — and
    refused even when the place it would reach EXISTS and is a complete tenant, so the refusal
    is the id's grammar and not an accident of what is on disk. The positive control is the
    same plant reached by a plain id."""
    root = tmp_path / "tenants"
    root.mkdir(parents=True)
    # Make every one of these ids point at a complete tenant, if it were followed.
    T.plant_tenant(tmp_path, "x")                       # root/../x
    T.plant_tenant(root / "a", "b")                     # root/a/b
    T.plant_tenant(root, ".hidden")                     # root/.hidden
    T.plant_tenant(root, "acme")
    message = _refusal(root, bad_id)
    if bad_id:
        assert bad_id in message, message
    tenant_dir, _ = _resolver()
    assert tenant_dir(root, "acme").tenant_id == "acme"


def test_an_absolute_id_is_refused(tmp_path):
    """`Path(root) / "/elsewhere"` IS `/elsewhere` — the join discards the root entirely."""
    root = tmp_path / "tenants"
    elsewhere = T.plant_tenant(tmp_path / "outside", "evil")
    root.mkdir(parents=True)
    _refusal(root, str(elsewhere))


# ---- O5: the link --------------------------------------------------------------------------

def test_a_tenant_folder_symlinked_outside_the_root_is_refused_naming_it(tmp_path):
    """A COMPLETE tenant planted outside the root and linked in under a plain id: a resolver
    that checks only the id grammar follows the link and serves another tree's settings."""
    root = tmp_path / "tenants"
    root.mkdir(parents=True)
    outside = T.plant_tenant(tmp_path / "outside", "acme")
    (root / "acme").symlink_to(outside, target_is_directory=True)
    message = _refusal(root, "acme")
    assert str(root / "acme") in message or str(outside) in message, message
    # Control: the same tenant, really under the root.
    T.plant_tenant(tmp_path / "real", "acme")
    tenant_dir, _ = _resolver()
    assert tenant_dir(tmp_path / "real", "acme").settings == \
        (tmp_path / "real" / "acme" / "settings").resolve()


def test_an_agent_half_linked_to_a_sibling_tenants_agent_is_refused(tmp_path):
    """`A/agent -> ../B/agent` stays INSIDE the root, so root containment alone passes it —
    and the box would then mount B's agent half into A's run (O1)."""
    root = tmp_path / "tenants"
    a = T.plant_tenant(root, "acme")
    b = T.plant_tenant(root, "bravo")
    _swap_for_link(a / "agent", Path("..") / "bravo" / "agent")
    assert (a / "agent").resolve() == (b / "agent").resolve()
    message = _refusal(root, "acme")
    assert "agent" in message, message
    tenant_dir, _ = _resolver()
    assert tenant_dir(root, "bravo").agent == (b / "agent").resolve()


def test_an_agent_half_linked_to_its_own_settings_is_refused(tmp_path):
    """`A/agent -> ../settings` resolves under `<root>/A/` and still must be refused: the box
    mounts `agent/`, so this link would put every settings file into the box (O1, O5)."""
    root = tmp_path / "tenants"
    a = T.plant_tenant(root, "acme")
    _swap_for_link(a / "agent", Path("settings"))
    assert (a / "agent").resolve() == (a / "settings").resolve()
    message = _refusal(root, "acme")
    assert "agent" in message, message


def test_a_settings_half_linked_to_a_sibling_tenants_settings_is_refused(tmp_path):
    """The mirror image on the host-only half: `A/settings -> ../B/settings` would make every
    reader of tenant A read tenant B's permission table and connection settings (O2, O3)."""
    root = tmp_path / "tenants"
    a = T.plant_tenant(root, "acme")
    T.plant_tenant(root, "bravo", table=T.TABLE_B)
    _swap_for_link(a / "settings", Path("..") / "bravo" / "settings")
    assert (a / "settings").resolve() == (root / "bravo" / "settings").resolve()
    message = _refusal(root, "acme")
    assert "settings" in message, message


def _swap_for_link(half: Path, target: Path) -> None:
    """Replace a planted half with a relative symlink to `target` — the real primitive."""
    for p in sorted(half.rglob("*"), reverse=True):
        p.unlink() if p.is_file() or p.is_symlink() else p.rmdir()
    half.rmdir()
    os.symlink(target, half, target_is_directory=True)


# ---- O4 / D3: absence ------------------------------------------------------------------------

def test_a_missing_tenant_folder_is_refused_naming_its_path(tmp_path):
    """No fallback: another tenant beside it, and the committed checkout's own playground, are
    both there to fall back to, and neither may be used."""
    root = tmp_path / "tenants"
    T.plant_tenant(root, "acme")
    message = _refusal(root, "ghost")
    assert str(root / "ghost") in message, message


@pytest.mark.parametrize("missing", T.REQUIRED_FILES)
def test_each_missing_required_settings_file_is_refused_naming_its_path(tmp_path, missing):
    """Each of D3's three files, absent alone from an otherwise complete tenant, refuses — and
    the refusal names that file's full path, which is what an operator acts on."""
    root = tmp_path / "tenants"
    T.plant_tenant(root, "acme", omit=(missing,))
    message = _refusal(root, "acme")
    assert str(root / "acme" / "settings" / missing) in message or \
        str((root / "acme" / "settings").resolve() / missing) in message, message


@pytest.mark.parametrize("half", ["settings", "agent"])
def test_a_missing_half_is_refused_naming_it(tmp_path, half):
    """Both halves are required real directories (O5): a tenant with no `agent/` has nothing
    the box can mount, and one with no `settings/` has nothing a reader can read."""
    root = tmp_path / "tenants"
    tenant = T.plant_tenant(root, "acme")
    for p in sorted((tenant / half).rglob("*"), reverse=True):
        p.unlink() if p.is_file() else p.rmdir()
    (tenant / half).rmdir()
    message = _refusal(root, "acme")
    assert half in message, message


def test_a_required_file_that_is_a_directory_is_refused(tmp_path):
    """Present-by-name is not present: a directory squatting `verb-grants.yaml` is no table."""
    root = tmp_path / "tenants"
    T.plant_tenant(root, "acme", omit=("verb-grants.yaml",))
    (root / "acme" / "settings" / "verb-grants.yaml").mkdir()
    message = _refusal(root, "acme")
    assert "verb-grants.yaml" in message, message


# ---- D2: the root is an input, and its default belongs to the entry point ---------------------

def test_the_default_tenants_root_is_the_checkouts_knowledge_tenants(tmp_path):
    """The entry point's default: `<checkout>/knowledge/tenants`, computed from the root it is
    HANDED — so a worktree's entry point defaults to the worktree's copy (D2, N6) and nothing
    works out which checkout it is on."""
    m = T.tenants()
    assert m.default_tenants_root(tmp_path) == tmp_path / "knowledge" / "tenants"
    assert m.default_tenants_root(T.REPO_ROOT) == T.TENANTS_ROOT


def test_two_roots_holding_the_same_tenant_id_resolve_independently(tmp_path):
    """The root decides, and only the root: one id under two roots is two tenants. A resolver
    that cached by id, or consulted the checkout's `knowledge/tenants` first, answers both
    calls with one folder."""
    one = T.plant_tenant(tmp_path / "one", T.PLAYGROUND_ID, table=T.TABLE_A)
    two = T.plant_tenant(tmp_path / "two", T.PLAYGROUND_ID, table=T.TABLE_B)
    tenant_dir, _ = _resolver()
    a = tenant_dir(tmp_path / "one", T.PLAYGROUND_ID)
    b = tenant_dir(tmp_path / "two", T.PLAYGROUND_ID)
    assert a.settings == (one / "settings").resolve()
    assert b.settings == (two / "settings").resolve()
    assert (a.settings / "verb-grants.yaml").read_text(encoding="utf-8") == T.TABLE_A
    assert (b.settings / "verb-grants.yaml").read_text(encoding="utf-8") == T.TABLE_B
