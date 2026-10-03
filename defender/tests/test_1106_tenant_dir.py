"""#1106 — the tenant's knowledge folder, as `_tenant.accept_tenant` accepts it (O5, O4, D3).

#1120 removed the `tenant_dir` resolver; its refusals live in the ONE acceptance,
`accept_tenant(data_root, tenant_id, *, defender_dir) -> Tenant`, which maps (data root, tenant
id) to the tenant's two halves under `<root>/<id>/knowledge/`: `settings/` (host-only: the four
settings kinds) and `agent/` (model-facing, mounted read-only into the box). It is the one place
a tenant id becomes an accepted tenant, so it is where both escapes the design names are closed:

  * the ID — a path separator, `..`, a leading dot, or nothing at all is not a tenant id (O5);
  * the LINK — the knowledge folder must resolve to `<root>/<id>/knowledge`, and each half must
    be a real directory resolving under it, which is what catches `A/agent -> ../B/agent` and
    `A/agent -> ../settings`: both stay INSIDE the root, so a root-containment check alone
    passes them (O5).

and where D3's "fail loudly" lives: an absent tenant folder or an absent required settings file
(`verb-grants.yaml`, `lead-zero.yaml`, `systems/case-history/mapping.yaml`) is a
`TenantRefused` NAMING THE PATH, with no fallback to another tenant, the template, or the
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


def _refused():
    return T.mod("_tenant").TenantRefused


def _refusal(root: Path, tenant_id: str) -> str:
    with pytest.raises(_refused()) as caught:
        T.accept(root, tenant_id)
    return str(caught.value)


# ---- the positive control every refusal below is measured against -----------------------------

def test_a_well_formed_tenant_resolves_to_its_two_halves_under_root_and_id(tmp_path):
    """The control: a complete tenant is accepted, and both halves are the paths under
    `<root>/<id>/knowledge/` — the very folders planted (compared resolved too, because the box
    mounts `agent` by its resolved path (M6) and a reader's path is compared by it)."""
    root = tmp_path / "tenants"
    knowledge = T.place_tenant(root, "acme")
    assert knowledge == root / "acme" / "knowledge"
    td = T.accept(root, "acme")
    assert td.id == "acme"
    assert td.settings == knowledge / "settings"
    assert td.agent == knowledge / "agent"
    assert td.settings.resolve() == (knowledge / "settings").resolve()
    assert td.agent.resolve() == (knowledge / "agent").resolve()
    # Read THROUGH the accepted half: the file the table loader will open is the one planted.
    assert (td.settings / "verb-grants.yaml").read_text(encoding="utf-8") == T.TABLE_A


def test_the_tenant_dir_error_is_a_tenant_refusal(tmp_path):
    """The knowledge folder's refusal is one of the tenant refusals every entry catches
    (#1078's one refusal class) — and not a `ValueError`, which pydantic would wrap inside a
    validator. Observed on a real refusal of the folder (a missing required file), so the
    class asserted is the one `accept_tenant` raises."""
    root = tmp_path / "tenants"
    T.place_tenant(root, "acme", omit=("verb-grants.yaml",))
    with pytest.raises(Exception) as caught:  # noqa: PT011 — the class is what is asserted
        T.accept(root, "acme")
    assert isinstance(caught.value, _refused()), type(caught.value)
    assert not isinstance(caught.value, ValueError), type(caught.value)
    assert issubclass(_refused(), Exception)
    assert not issubclass(_refused(), ValueError)


def test_the_required_settings_are_exactly_d3s_three_files():
    """D3: required AT START means these three. `config.env` is not among them — some
    adapters need none, and its absence stays the existing per-call `ConfigFault`."""
    assert set(T.tenants().REQUIRED_SETTINGS) == set(T.REQUIRED_FILES)


def test_a_tenant_without_any_config_env_still_resolves(tmp_path):
    """The other half of D3's list: a tenant whose systems carry no `config.env` at all is
    not refused at start (an MCP-path or config-less adapter is legal)."""
    root = tmp_path / "tenants"
    knowledge = T.place_tenant(root, "acme", configs={})
    assert T.accept(root, "acme").settings == knowledge / "settings"


# ---- O5: the id ----------------------------------------------------------------------------

@pytest.mark.parametrize("bad_id", ["../x", "a/b", ".hidden", "", "..", ".", "Acme_Corp"])
def test_an_id_that_is_not_a_single_plain_name_is_refused_naming_it(tmp_path, bad_id):
    """An id with a path separator, `..`, a leading dot, no name at all, or anything else
    outside the one tenant-id grammar a run is held to (`Acme_Corp`) is refused — and
    refused even when the place it would reach EXISTS and is a complete tenant, so the refusal
    is the id's grammar and not an accident of what is on disk. The positive control is the
    same plant reached by a plain id."""
    root = tmp_path / "tenants"
    root.mkdir(parents=True)
    # Make every one of these ids point at a complete tenant, if it were followed.
    T.place_tenant(tmp_path, "x")                       # root/../x
    T.place_tenant(root / "a", "b")                     # root/a/b
    T.place_tenant(root, ".hidden")                     # root/.hidden
    T.place_tenant(root, "Acme_Corp")                   # root/Acme_Corp
    T.place_tenant(root, "acme")
    message = _refusal(root, bad_id)
    if bad_id:
        assert bad_id in message, message
    assert T.accept(root, "acme").id == "acme"


def test_an_absolute_id_is_refused(tmp_path):
    """`Path(root) / "/elsewhere"` IS `/elsewhere` — the join discards the root entirely."""
    root = tmp_path / "tenants"
    elsewhere = T.place_tenant(tmp_path / "outside", "evil").parent
    root.mkdir(parents=True)
    _refusal(root, str(elsewhere))


# ---- O5: the link --------------------------------------------------------------------------

def test_a_tenant_folder_symlinked_outside_the_root_is_refused_naming_it(tmp_path):
    """A COMPLETE tenant planted outside the root and linked in under a plain id: an
    acceptance that checks only the id grammar follows the link and serves another tree's
    settings."""
    root = tmp_path / "tenants"
    root.mkdir(parents=True)
    outside = T.place_tenant(tmp_path / "outside", "acme").parent
    (root / "acme").symlink_to(outside, target_is_directory=True)
    message = _refusal(root, "acme")
    assert str(root / "acme") in message or str(outside) in message, message
    # Control: the same tenant, really under the root.
    T.place_tenant(tmp_path / "real", "acme")
    assert T.accept(tmp_path / "real", "acme").settings == \
        tmp_path / "real" / "acme" / "knowledge" / "settings"


def test_an_agent_half_linked_to_a_sibling_tenants_agent_is_refused(tmp_path):
    """`A/agent -> ../B/agent` stays INSIDE the root, so root containment alone passes it —
    and the box would then mount B's agent half into A's run (O1)."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, "acme")
    b = T.place_tenant(root, "bravo")
    _swap_for_link(a / "agent", Path("..") / ".." / "bravo" / "knowledge" / "agent")
    assert (a / "agent").resolve() == (b / "agent").resolve()
    message = _refusal(root, "acme")
    assert "agent" in message, message
    assert T.accept(root, "bravo").agent == b / "agent"


def test_an_agent_half_linked_to_its_own_settings_is_refused(tmp_path):
    """`A/agent -> settings` resolves under A's own knowledge folder and still must be
    refused: the box mounts `agent/`, so this link would put every settings file into the box
    (O1, O5)."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, "acme")
    _swap_for_link(a / "agent", Path("settings"))
    assert (a / "agent").resolve() == (a / "settings").resolve()
    message = _refusal(root, "acme")
    assert "agent" in message, message


def test_a_settings_half_linked_to_a_sibling_tenants_settings_is_refused(tmp_path):
    """The mirror image on the host-only half: `A/settings -> ../B/settings` would make every
    reader of tenant A read tenant B's permission table and connection settings (O2, O3)."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, "acme")
    b = T.place_tenant(root, "bravo", table=T.TABLE_B)
    _swap_for_link(a / "settings", Path("..") / ".." / "bravo" / "knowledge" / "settings")
    assert (a / "settings").resolve() == (b / "settings").resolve()
    message = _refusal(root, "acme")
    assert "settings" in message, message


def test_a_tenant_folder_linked_to_a_sibling_tenant_inside_the_root_is_refused(tmp_path):
    """`root/acme -> bravo` stays INSIDE the root, so "the folder resolves under the root" is
    satisfied — and every reader of acme would read bravo's table, settings and agent half.
    The tenant folder must be THE folder `<root>/<id>`, not any folder under the root. The
    control is bravo itself, reached by its own id through the same root."""
    root = tmp_path / "tenants"
    bravo = T.place_tenant(root, "bravo", table=T.TABLE_B)
    os.symlink(Path("bravo"), root / "acme", target_is_directory=True)
    assert (root / "acme" / "knowledge").resolve() == bravo.resolve()
    assert (root / "acme" / "knowledge" / "settings" / "verb-grants.yaml").read_text(
        encoding="utf-8") == T.TABLE_B, \
        "the link must be a working one for the refusal to mean anything"
    message = _refusal(root, "acme")
    assert "acme" in message, message
    assert T.accept(root, "bravo").settings == bravo / "settings"


@pytest.mark.parametrize("target", [Path("settings") / "systems", Path("..")],
                         ids=["a-subfolder-of-its-own-settings", "its-own-tenant-folder"])
def test_an_agent_half_linked_inside_its_own_tenant_but_not_to_itself_is_refused(
        tmp_path, target):
    """Two links that stay under `<root>/<id>/` and are not `settings/` itself, so a check of
    "resolves under the tenant folder, and is not the settings half" passes both — yet each
    puts settings files into the box that mounts `agent/` (O1): `agent -> settings/systems`
    exposes every system's `config.env`, `agent -> ..` exposes the whole tenant. The control is
    the same tenant with a real `agent/` directory, which is accepted."""
    root = tmp_path / "tenants"
    knowledge = T.place_tenant(root, "acme")
    acme = knowledge.parent
    assert T.accept(root, "acme").agent == knowledge / "agent"
    _swap_for_link(knowledge / "agent", target)
    exposed = (knowledge / "agent").resolve()
    assert exposed.is_relative_to(acme.resolve())
    assert exposed != (knowledge / "settings").resolve()
    assert any(p.name == "config.env" for p in exposed.rglob("*")), \
        "the link must really expose settings files for the refusal to mean anything"
    message = _refusal(root, "acme")
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
    T.place_tenant(root, "acme")
    message = _refusal(root, "ghost")
    assert str(root / "ghost") in message, message


@pytest.mark.parametrize("missing", T.REQUIRED_FILES)
def test_each_missing_required_settings_file_is_refused_naming_its_path(tmp_path, missing):
    """Each of D3's three files, absent alone from an otherwise complete tenant, refuses — and
    the refusal names that file's full path, which is what an operator acts on."""
    root = tmp_path / "tenants"
    settings = T.place_tenant(root, "acme", omit=(missing,)) / "settings"
    message = _refusal(root, "acme")
    assert str(settings / missing) in message or \
        str(settings.resolve() / missing) in message, message


@pytest.mark.parametrize("half", ["settings", "agent"])
def test_a_missing_half_is_refused_naming_it(tmp_path, half):
    """Both halves are required real directories (O5): a tenant with no `agent/` has nothing
    the box can mount, and one with no `settings/` has nothing a reader can read."""
    root = tmp_path / "tenants"
    tenant = T.place_tenant(root, "acme")
    for p in sorted((tenant / half).rglob("*"), reverse=True):
        p.unlink() if p.is_file() else p.rmdir()
    (tenant / half).rmdir()
    message = _refusal(root, "acme")
    assert half in message, message


def test_a_required_file_that_is_a_directory_is_refused(tmp_path):
    """Present-by-name is not present: a directory squatting `verb-grants.yaml` is no table."""
    root = tmp_path / "tenants"
    knowledge = T.place_tenant(root, "acme", omit=("verb-grants.yaml",))
    (knowledge / "settings" / "verb-grants.yaml").mkdir()
    message = _refusal(root, "acme")
    assert "verb-grants.yaml" in message, message


@pytest.mark.parametrize("linked", T.REQUIRED_FILES)
def test_a_required_file_linked_to_another_tenants_copy_is_refused(tmp_path, linked):
    """The link rule reaches the FILES, not only the folder and its halves: a required file
    that is a link to tenant B's copy stays inside the root, reads cleanly, and would hand A
    B's grants (or lead-zero id, or released-status spelling). Paired with the control above:
    the same two tenants, differing only by the link."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, "acme", table=T.TABLE_A)
    b = T.place_tenant(root, "bravo", table=T.TABLE_B)
    assert T.accept(root, "acme").id == "acme"
    own = a / "settings" / linked
    theirs = b / "settings" / linked
    own.unlink()
    os.symlink(os.path.relpath(theirs, own.parent), own)
    assert own.is_file(), "the link must really read as a file for the refusal to mean anything"
    message = _refusal(root, "acme")
    assert str(own) in message, message


def test_a_linked_directory_on_the_way_to_a_required_file_is_refused(tmp_path):
    """`settings/systems -> bravo's settings/systems`: no required FILE is itself a link, but
    the mapping reached through it is bravo's."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, "acme")
    b = T.place_tenant(root, "bravo")
    systems = a / "settings" / "systems"
    _swap_for_link(systems, Path(os.path.relpath(b / "settings" / "systems", systems.parent)))
    assert (systems / "case-history" / "mapping.yaml").is_file(), \
        "the link must be a working one for the refusal to mean anything"
    message = _refusal(root, "acme")
    assert str(systems) in message, message


@pytest.mark.parametrize("linked", [
    "settings/systems/elastic/config.env",
    "settings/systems/elastic",
    "agent/.gitkeep",
])
def test_any_link_inside_a_tenant_folder_is_refused_not_only_the_required_files(
        tmp_path, linked):
    """The link rule covers the whole folder, not a list of files: a system's `config.env` (or
    its whole `systems/<sys>/` folder) linked to another tenant's copy hands this tenant that
    tenant's endpoints, and a link in `agent/` would hand the model another tenant's knowledge
    — all while staying inside the root. Control: the unlinked tenant is accepted (above)."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, "acme")
    b = T.place_tenant(root, "bravo")
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
    message = _refusal(root, "acme")
    assert str(own) in message, message


def test_a_hard_linked_file_inside_a_tenant_folder_is_refused(tmp_path):
    """A hard link is a second name for another tenant's file with no link to see: refused
    all the same. Control: the tenant without it is accepted (above)."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, "acme")
    b = T.place_tenant(root, "bravo")
    own = a / "settings" / "systems" / "elastic" / "config.env"
    own.parent.mkdir(parents=True, exist_ok=True)
    if own.exists():
        own.unlink()
    theirs = b / "settings" / "verb-grants.yaml"
    os.link(theirs, own)
    message = _refusal(root, "acme")
    assert "hard link" in message, message
    assert str(own) in message, message


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 directory anyway")
def test_a_directory_the_link_check_cannot_read_is_refused_not_skipped(tmp_path):
    """Skipped silently, an unreadable directory would hide any link below it."""
    root = tmp_path / "tenants"
    a = T.place_tenant(root, "acme")
    hidden = a / "settings" / "systems" / "hidden"
    hidden.mkdir(parents=True)
    hidden.chmod(0)
    try:
        message = _refusal(root, "acme")
    finally:
        hidden.chmod(0o755)
    assert "could not be checked" in message, message


# ---- D2: the root is an input --------------------------------------------------------------

def test_two_roots_holding_the_same_tenant_id_resolve_independently(tmp_path):
    """The root decides, and only the root: one id under two roots is two tenants. An
    acceptance that cached by id, or consulted the checkout's lab first, answers both calls
    with one folder."""
    one = T.place_tenant(tmp_path / "one", T.PLAYGROUND_ID, table=T.TABLE_A)
    two = T.place_tenant(tmp_path / "two", T.PLAYGROUND_ID, table=T.TABLE_B)
    a = T.accept(tmp_path / "one", T.PLAYGROUND_ID)
    b = T.accept(tmp_path / "two", T.PLAYGROUND_ID)
    assert a.settings == one / "settings"
    assert b.settings == two / "settings"
    assert (a.settings / "verb-grants.yaml").read_text(encoding="utf-8") == T.TABLE_A
    assert (b.settings / "verb-grants.yaml").read_text(encoding="utf-8") == T.TABLE_B
