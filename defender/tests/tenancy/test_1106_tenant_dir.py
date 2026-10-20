"""accept_tenant: a tenant id and its knowledge folder halves are accepted only as plain, unlinked directories under the data root."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import os
from pathlib import Path

import pytest

from defender.tests.support.tenancy import _tenants1106 as T


def _refused():
    return T.mod("tenancy._tenant").TenantRefused


def _refusal(root: Path, tenant_id: str) -> str:
    with pytest.raises(_refused()) as caught:
        T.accept(root, tenant_id)
    return str(caught.value)


# ---- the positive control every refusal below is measured against -----------------------------

def test_a_well_formed_tenant_resolves_to_its_two_halves_under_root_and_id(tmp_path):
    root = tmp_path / "tenants"
    knowledge = T.place_tenant(root, fixture_uuid("tenant:acme"))
    assert knowledge == root / fixture_uuid("tenant:acme") / "knowledge"
    td = T.accept(root, fixture_uuid("tenant:acme"))
    assert td.id == fixture_uuid("tenant:acme")
    assert td.settings == knowledge / "settings"
    assert td.agent == knowledge / "agent"
    assert td.settings.resolve() == (knowledge / "settings").resolve()
    assert td.agent.resolve() == (knowledge / "agent").resolve()
    # Read THROUGH the accepted half: the file the table loader will open is the one planted.
    assert (td.settings / "verb-grants.yaml").read_text(encoding="utf-8") == T.TABLE_A


def test_a_tenant_without_any_config_env_still_resolves(tmp_path):
    """The other half of D3's list: a tenant whose systems carry no `config.env` at all is
    not refused at start (an MCP-path or config-less adapter is legal)."""
    root = tmp_path / "tenants"
    knowledge = T.place_tenant(root, fixture_uuid("tenant:acme"), configs={})
    assert T.accept(root, fixture_uuid("tenant:acme")).settings == knowledge / "settings"


# ---- O5: the id ----------------------------------------------------------------------------

@pytest.mark.parametrize("bad_id", ["../x", "a/b", ".hidden", "", "..", ".", "Acme_Corp"])
def test_an_id_that_is_not_a_single_plain_name_is_refused_naming_it(tmp_path, bad_id):
    root = tmp_path / "tenants"
    root.mkdir(parents=True)
    # Make every one of these ids point at a complete tenant, if it were followed.
    T.place_tenant(tmp_path, "x")                       # root/../x
    T.place_tenant(root / "a", "b")                     # root/a/b
    T.place_tenant(root, ".hidden")                     # root/.hidden
    T.place_tenant(root, "Acme_Corp")                   # root/Acme_Corp
    T.place_tenant(root, fixture_uuid("tenant:acme"))
    message = _refusal(root, bad_id)
    if bad_id:
        assert bad_id in message, message
    assert T.accept(root, fixture_uuid("tenant:acme")).id == fixture_uuid("tenant:acme")


# ---- O5: the link --------------------------------------------------------------------------

def test_a_tenant_folder_symlinked_outside_the_root_is_refused_naming_it(tmp_path):
    root = tmp_path / "tenants"
    root.mkdir(parents=True)
    outside = T.place_tenant(tmp_path / "outside", fixture_uuid("tenant:acme")).parent
    (root / fixture_uuid("tenant:acme")).symlink_to(outside, target_is_directory=True)
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert str(root / fixture_uuid("tenant:acme")) in message or str(outside) in message, message
    # Control: the same tenant, really under the root.
    T.place_tenant(tmp_path / "real", fixture_uuid("tenant:acme"))
    assert T.accept(tmp_path / "real", fixture_uuid("tenant:acme")).settings == \
        tmp_path / "real" / fixture_uuid("tenant:acme") / "knowledge" / "settings"


def test_an_agent_half_linked_to_a_sibling_tenants_agent_is_refused(tmp_path):
    """`A/agent -> ../B/agent` stays INSIDE the root, so root containment alone passes it —
    and the box would then mount B's agent half into A's run (O1)."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, fixture_uuid("tenant:acme"))
    b = T.place_tenant(root, fixture_uuid("tenant:bravo"))
    _swap_for_link(a / "agent", Path("..") / ".." / fixture_uuid("tenant:bravo") / "knowledge" / "agent")
    assert (a / "agent").resolve() == (b / "agent").resolve()
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert "agent" in message, message
    assert T.accept(root, fixture_uuid("tenant:bravo")).agent == b / "agent"


def test_an_agent_half_linked_to_its_own_settings_is_refused(tmp_path):
    root = tmp_path / "tenants"
    a = T.place_tenant(root, fixture_uuid("tenant:acme"))
    _swap_for_link(a / "agent", Path("settings"))
    assert (a / "agent").resolve() == (a / "settings").resolve()
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert "agent" in message, message


def test_a_settings_half_linked_to_a_sibling_tenants_settings_is_refused(tmp_path):
    """The mirror image on the host-only half: `A/settings -> ../B/settings` would make every
    reader of tenant A read tenant B's permission table and connection settings (O2, O3)."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, fixture_uuid("tenant:acme"))
    b = T.place_tenant(root, fixture_uuid("tenant:bravo"), table=T.TABLE_B)
    _swap_for_link(a / "settings", Path("..") / ".." / fixture_uuid("tenant:bravo") / "knowledge" / "settings")
    assert (a / "settings").resolve() == (b / "settings").resolve()
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert "settings" in message, message


def test_a_tenant_folder_linked_to_a_sibling_tenant_inside_the_root_is_refused(tmp_path):
    root = tmp_path / "tenants"
    bravo = T.place_tenant(root, fixture_uuid("tenant:bravo"), table=T.TABLE_B)
    os.symlink(Path(fixture_uuid("tenant:bravo")), root / fixture_uuid("tenant:acme"), target_is_directory=True)
    assert (root / fixture_uuid("tenant:acme") / "knowledge").resolve() == bravo.resolve()
    assert (root / fixture_uuid("tenant:acme") / "knowledge" / "settings" / "verb-grants.yaml").read_text(
        encoding="utf-8") == T.TABLE_B, \
        "the link must be a working one for the refusal to mean anything"
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert fixture_uuid("tenant:acme") in message, message
    assert T.accept(root, fixture_uuid("tenant:bravo")).settings == bravo / "settings"


@pytest.mark.parametrize("target", [Path("settings") / "systems", Path("..")],
                         ids=["a-subfolder-of-its-own-settings", "its-own-tenant-folder"])
def test_an_agent_half_linked_inside_its_own_tenant_but_not_to_itself_is_refused(
        tmp_path, target):
    root = tmp_path / "tenants"
    knowledge = T.place_tenant(root, fixture_uuid("tenant:acme"))
    acme = knowledge.parent
    assert T.accept(root, fixture_uuid("tenant:acme")).agent == knowledge / "agent"
    _swap_for_link(knowledge / "agent", target)
    exposed = (knowledge / "agent").resolve()
    assert exposed.is_relative_to(acme.resolve())
    assert exposed != (knowledge / "settings").resolve()
    assert any(p.name == "config.env" for p in exposed.rglob("*")), \
        "the link must really expose settings files for the refusal to mean anything"
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert "agent" in message, message


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
    T.place_tenant(root, fixture_uuid("tenant:acme"))
    message = _refusal(root, fixture_uuid("tenant:ghost"))
    assert str(root / fixture_uuid("tenant:ghost")) in message, message


@pytest.mark.parametrize("missing", T.REQUIRED_FILES)
def test_each_missing_required_settings_file_is_refused_naming_its_path(tmp_path, missing):
    """Each of D3's three files, absent alone from an otherwise complete tenant, refuses — and
    the refusal names that file's full path, which is what an operator acts on."""
    root = tmp_path / "tenants"
    settings = T.place_tenant(root, fixture_uuid("tenant:acme"), omit=(missing,)) / "settings"
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert str(settings / missing) in message or \
        str(settings.resolve() / missing) in message, message


@pytest.mark.parametrize("half", ["settings", "agent"])
def test_a_missing_half_is_refused_naming_it(tmp_path, half):
    """Both halves are required real directories (O5): a tenant with no `agent/` has nothing
    the box can mount, and one with no `settings/` has nothing a reader can read."""
    root = tmp_path / "tenants"
    tenant = T.place_tenant(root, fixture_uuid("tenant:acme"))
    for p in sorted((tenant / half).rglob("*"), reverse=True):
        p.unlink() if p.is_file() else p.rmdir()
    (tenant / half).rmdir()
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert half in message, message


def test_a_required_file_that_is_a_directory_is_refused(tmp_path):
    """Present-by-name is not present: a directory squatting `verb-grants.yaml` is no table."""
    root = tmp_path / "tenants"
    knowledge = T.place_tenant(root, fixture_uuid("tenant:acme"), omit=("verb-grants.yaml",))
    (knowledge / "settings" / "verb-grants.yaml").mkdir()
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert "verb-grants.yaml" in message, message


@pytest.mark.parametrize("linked", T.REQUIRED_FILES)
def test_a_required_file_linked_to_another_tenants_copy_is_refused(tmp_path, linked):
    root = tmp_path / "tenants"
    a = T.place_tenant(root, fixture_uuid("tenant:acme"), table=T.TABLE_A)
    b = T.place_tenant(root, fixture_uuid("tenant:bravo"), table=T.TABLE_B)
    assert T.accept(root, fixture_uuid("tenant:acme")).id == fixture_uuid("tenant:acme")
    own = a / "settings" / linked
    theirs = b / "settings" / linked
    own.unlink()
    os.symlink(os.path.relpath(theirs, own.parent), own)
    assert own.is_file(), "the link must really read as a file for the refusal to mean anything"
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert str(own) in message, message


def test_a_linked_directory_on_the_way_to_a_required_file_is_refused(tmp_path):
    """`settings/systems -> bravo's settings/systems`: no required FILE is itself a link, but
    the mapping reached through it is bravo's."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, fixture_uuid("tenant:acme"))
    b = T.place_tenant(root, fixture_uuid("tenant:bravo"))
    systems = a / "settings" / "systems"
    _swap_for_link(systems, Path(os.path.relpath(b / "settings" / "systems", systems.parent)))
    assert (systems / "case-history" / "mapping.yaml").is_file(), \
        "the link must be a working one for the refusal to mean anything"
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert str(systems) in message, message


@pytest.mark.parametrize("linked", [
    "settings/systems/elastic/config.env",
    "settings/systems/elastic",
    "agent/.gitkeep",
])
def test_any_link_inside_a_tenant_folder_is_refused_not_only_the_required_files(
        tmp_path, linked):
    root = tmp_path / "tenants"
    a = T.place_tenant(root, fixture_uuid("tenant:acme"))
    b = T.place_tenant(root, fixture_uuid("tenant:bravo"))
    own = a / linked
    theirs = b / linked
    if own.is_dir():
        _swap_for_link(own, Path(os.path.relpath(theirs, own.parent)))
    else:
        if not own.exists():
            own.parent.mkdir(parents=True, exist_ok=True)
            theirs.parent.mkdir(parents=True, exist_ok=True)
            theirs.write_text("", encoding="utf-8")
        else:
            own.unlink()
        os.symlink(os.path.relpath(theirs, own.parent), own)
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert str(own) in message, message


def test_a_hard_linked_file_inside_a_tenant_folder_is_refused(tmp_path):
    """A hard link is a second name for another tenant's file with no link to see: refused
    all the same. Control: the tenant without it is accepted (above)."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, fixture_uuid("tenant:acme"))
    b = T.place_tenant(root, fixture_uuid("tenant:bravo"))
    own = a / "settings" / "systems" / "elastic" / "config.env"
    own.parent.mkdir(parents=True, exist_ok=True)
    if own.exists():
        own.unlink()
    theirs = b / "settings" / "verb-grants.yaml"
    os.link(theirs, own)
    message = _refusal(root, fixture_uuid("tenant:acme"))
    assert "hard link" in message, message
    assert str(own) in message, message


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 directory anyway")
def test_a_directory_the_link_check_cannot_read_is_refused_not_skipped(tmp_path):
    """Skipped silently, an unreadable directory would hide any link below it."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, fixture_uuid("tenant:acme"))
    hidden = a / "settings" / "systems" / "hidden"
    hidden.mkdir(parents=True)
    hidden.chmod(0)
    try:
        message = _refusal(root, fixture_uuid("tenant:acme"))
    finally:
        hidden.chmod(0o755)
    assert "could not be checked" in message, message


# ---- D2: the root is an input --------------------------------------------------------------
