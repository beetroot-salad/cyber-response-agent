"""#1120 piece 1 — D1: `accept_tenant`, the one acceptance function, and `Tenant`.

`accept_tenant(data_root, raw_id, *, defender_dir, box_mounted) -> Tenant` is driven directly
(it is the owner), over real trees built on disk under the test's own tmp data root. Its seven
checks run in order: the id grammar, the row, `knowledge/` a real unlinked directory, the two
halves plus `REQUIRED_SETTINGS`, the link walk over `settings/` and `agent/` only (skipping
`knowledge/.git`), `agent/.tenant-id`, and `settings` outside every mounted tree. Every
refusal is a `TenantRefused` naming the refused value. See `_spec1120.py` for the coined names.

# rejected: re-validation after acceptance — point-in-time by design (M3, human).
"""
from __future__ import annotations

import contextlib
import dataclasses
import os
import shutil
import stat
import threading
from pathlib import Path

import pytest

from defender import _tenant
from defender.scripts import tenant as tenant_py
from defender.tests import _spec1077 as S1077
from defender.tests.tenant_1120_piece1 import _spec1120 as H

# ======================================================================================
# Step 1 — the id grammar, before anything under the data root is named.
# ======================================================================================

#: O3's refused ids plus a control-character id (N16), with the gate's address tokens as the
#: pytest ids so a failure names the domain member it is about.
OFF_GRAMMAR_IDS = [
    pytest.param("../x", id="../x"),
    pytest.param("A", id="A"),
    pytest.param("a/b", id="a/b"),
    pytest.param("", id="empty"),
    pytest.param("a" * 64, id="64-chars"),
    pytest.param("1abc", id="1abc"),
    pytest.param("acme\n", id="trailing-newline"),
    pytest.param("ac\x1bme", id="control-chars"),
]


@pytest.mark.parametrize("raw_id", OFF_GRAMMAR_IDS)
def test_1120_accept_tenant_refuses_an_off_grammar_id_before_touching_the_root(
        tmp_path: Path, raw_id: str) -> None:
    """For each of '../x', 'A', 'a/b', '', a 64-character id, '1abc', 'acme' plus a newline and
    an id carrying a control character, accept_tenant raises TenantRefused naming the id. It
    does so before any path under the data root is named: a data root that does not exist
    yields the grammar refusal, not a missing-row one, and the refusal never names the data
    root. A control-character id is rendered escaped (repr-style) and bounded, never raw
    (N16). The positive control: a valid id over the same absent data root is refused for
    its missing row instead, naming the row's path."""
    root = tmp_path / "no-such-root"
    text = H.accept_refusal(_tenant, root, raw_id)
    # "Names" survives N16's bound: the escaped rendering's head is in the message.
    assert repr(raw_id)[:40] in text, (
        f"the grammar refusal does not name the refused id {raw_id!r} (repr-style): {text!r}")
    assert str(root) not in text, (
        f"the refusal for an off-grammar id names the data root — it looked under the root "
        f"before checking the grammar: {text!r}")
    if any(ord(c) < 0x20 for c in raw_id):
        assert not any(ord(c) < 0x20 for c in text), (
            f"a control character reached the refusal text raw: {text!r}")
    assert not root.exists(), "accepting a tenant created the data root"

    control = H.accept_refusal(_tenant, root, H.TID)
    assert str(H.row_path(root, H.TID)) in control, (
        f"a valid id over an absent root must be refused for its row, naming it: {control!r}")


# ======================================================================================
# Same-file helpers: the plants. Each one makes a REAL fault on disk.
# ======================================================================================

def _other_file(tmp_path: Path, name: str = "outside.txt") -> Path:
    """A regular file OUTSIDE the tenant — what a planted link would hand the tenant."""
    target = tmp_path / "elsewhere" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("not this tenant's bytes\n", encoding="utf-8")
    return target


def _plant_symlink(half: Path, tmp_path: Path) -> Path:
    link = half / "planted-link"
    link.symlink_to(_other_file(tmp_path))
    return link


def _plant_hardlink(half: Path, tmp_path: Path) -> Path:
    """A second name, outside the tenant, for a file INSIDE the half — the file's bytes may be
    another tenant's (st_nlink > 1)."""
    inside = half / "planted-hardlink.yaml"
    inside.write_text("shared: bytes\n", encoding="utf-8")
    outside = tmp_path / "elsewhere" / "second-name.yaml"
    outside.parent.mkdir(parents=True, exist_ok=True)
    os.link(inside, outside)
    return inside


def _accept_within(owner, root: Path, tenant_id: str = H.TID, *, seconds: float = 20.0,
                   fifo: Path | None = None, **kw) -> tuple[object, BaseException | None]:
    """`accept_tenant` in a worker thread with a deadline: a walk that OPENS a FIFO (or follows a
    cycle) blocks, and a blocked call must fail the test rather than hang the worker. On a
    deadline, the FIFO's write end is opened once to release the blocked reader."""
    box: dict[str, object] = {}

    def call() -> None:
        try:
            box["value"] = H.accept(owner, root, tenant_id, **kw)
        except BaseException as exc:  # noqa: BLE001 — handed back to the test thread as-is
            box["exc"] = exc

    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        if fifo is not None:
            with contextlib.suppress(OSError):
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail(f"accept_tenant did not return within {seconds}s — it opened a planted "
                    "special file or followed a link cycle instead of refusing it by lstat")
    return box.get("value"), box.get("exc")  # type: ignore[return-value]


# ======================================================================================
# #0 — the return-value contract.
# ======================================================================================

def test_1120_accept_tenant_returns_a_frozen_tenant_whose_members_are_its_layout(
        tmp_path: Path) -> None:
    """For a finished tenant under a tmp data root, accept_tenant(root, "acme", …) with the
    checkout's defender/ and the tenant's runs folder as the mounted trees returns a Tenant:
    its stored fields are exactly id, data_root and row; its id is the TenantId "acme"; its
    data_root is the root passed in; its row is the TenantRow require_tenant read, naming acme
    (N6 reading (a) — the row FILE's path is its own property, spelled row_path here, equal to
    <root>/acme/tenant.json). It is frozen: assigning any member raises. Its path members are
    exactly dir = <root>/acme, runs = dir/runs, sessions = dir/sessions, episodes =
    dir/episodes, learning = dir/learning, worktrees = learning/worktrees, knowledge =
    dir/knowledge, settings = knowledge/settings and agent = knowledge/agent, and none of runs,
    sessions, episodes or learning lies under knowledge. Accepting writes nothing: the root's
    census is byte-identical before and after. A relative data root is refused with
    TenantRefused naming it, never a bare ValueError; this is the response every entry point
    receives from accept_tenant (run.py included)."""
    root = tmp_path / "data"
    H.adopted(root)
    before = H.tree_census(root)
    tenant = H.accept(_tenant, root, H.TID, box_mounted=(H.tenant_folder(root) / "runs",))
    assert H.census_diff(before, H.tree_census(root)) == [], "accepting a tenant wrote"

    assert dataclasses.is_dataclass(tenant), f"Tenant is not a dataclass: {type(tenant)!r}"
    assert [f.name for f in dataclasses.fields(tenant)] == ["id", "data_root", "row"]
    assert tenant.id == H.TID
    assert isinstance(tenant.id, _tenant.TenantId)
    assert tenant.data_root == root
    assert isinstance(tenant.row, _tenant.TenantRow)
    assert tenant.row.tenant_id == H.TID
    assert getattr(tenant, H.ROW_PATH_PROPERTY) == root / H.TID / H.ROW_NAME
    with pytest.raises(AttributeError):
        tenant.id = H.OTHER  # type: ignore[misc]

    d = root / H.TID
    expected = {
        "dir": d, "runs": d / "runs", "sessions": d / "sessions", "episodes": d / "episodes",
        "learning": d / "learning", "worktrees": d / "learning" / "worktrees",
        "knowledge": d / "knowledge", "settings": d / "knowledge" / "settings",
        "agent": d / "knowledge" / "agent",
    }
    assert {name: getattr(tenant, name) for name in H.TENANT_PATH_PROPERTIES} == expected
    for name in ("runs", "sessions", "episodes", "learning"):
        assert not getattr(tenant, name).is_relative_to(tenant.knowledge), name

    relative = Path("relative") / "root"
    text = H.accept_refusal(_tenant, relative, H.TID)
    assert str(relative) in text, f"the relative-root refusal does not name it: {text!r}"


# ======================================================================================
# D1 — the seven checks run IN ORDER.
# ======================================================================================

def _off_grammar_and_no_row(root: Path, tmp_path: Path) -> tuple[str, str, str]:
    return "A", repr("A"), str(H.row_path(root, "A"))


def _no_row_and_no_knowledge(root: Path, tmp_path: Path) -> tuple[str, str, str]:
    (root / H.TID).mkdir(parents=True)
    return H.TID, str(H.row_path(root)), str(H.knowledge_dir(root))


def _knowledge_link_over_missing_settings(root: Path, tmp_path: Path) -> tuple[str, str, str]:
    H.plant_row(root)
    elsewhere = tmp_path / "linked-knowledge"
    (elsewhere / "agent").mkdir(parents=True)
    H.knowledge_dir(root).symlink_to(elsewhere, target_is_directory=True)
    return H.TID, str(H.knowledge_dir(root)), str(H.settings_dir(root))


def _missing_settings_and_agent_link(root: Path, tmp_path: Path) -> tuple[str, str, str]:
    H.adopted(root)
    shutil.rmtree(H.settings_dir(root))
    _plant_symlink(H.agent_dir(root), tmp_path)
    return H.TID, str(H.settings_dir(root)), "planted-link"


def _hardlink_and_wrong_tenant_id(root: Path, tmp_path: Path) -> tuple[str, str, str]:
    H.adopted(root, tenant_id_file=f"{H.OTHER}\n")
    inside = _plant_hardlink(H.settings_dir(root), tmp_path)
    return H.TID, str(inside), ".tenant-id"


def _wrong_tenant_id_and_mounted_settings(root: Path, tmp_path: Path) -> tuple[str, str, str]:
    H.adopted(root, tenant_id_file=f"{H.OTHER}\n")
    return H.TID, ".tenant-id", "\0never-in-a-message"


#: Each pair plants the faults of two ADJACENT checks; the refusal must be the EARLIER one's:
#: it names the first string and not the second. The last pair's second fault is `settings`
#: under a mounted tree (`box_mounted=(root,)`).
ADJACENT_PAIRS = [
    pytest.param(_off_grammar_and_no_row, id="grammar-before-row"),
    pytest.param(_no_row_and_no_knowledge, id="row-before-knowledge"),
    pytest.param(_knowledge_link_over_missing_settings, id="knowledge-before-halves"),
    pytest.param(_missing_settings_and_agent_link, id="halves-before-link-walk"),
    pytest.param(_hardlink_and_wrong_tenant_id, id="link-walk-before-tenant-id"),
    pytest.param(_wrong_tenant_id_and_mounted_settings, id="tenant-id-before-mounted-tree"),
]


@pytest.mark.parametrize("plant", ADJACENT_PAIRS)
def test_1120_accept_tenant_reports_the_earliest_failing_check(tmp_path: Path, plant) -> None:
    """For each adjacent pair of accept_tenant's seven checks, a tenant is planted that fails
    both, and the refusal names the EARLIER check's fault: an off-grammar id with no row — the
    grammar; no row and no knowledge/ — the row; knowledge/ a symlink with settings/ missing
    behind it — knowledge/; settings/ missing and a symlink in agent/ — the missing half; a
    hard link in settings/ and a mismatched agent/.tenant-id — the link; a mismatched
    .tenant-id with settings under a box_mounted path — the .tenant-id."""
    root = tmp_path / "data"
    raw_id, earlier, later = plant(root, tmp_path)
    text = H.accept_refusal(_tenant, root, raw_id, box_mounted=(root,))
    assert earlier in text, f"the refusal does not name the earlier check's fault {earlier!r}: {text!r}"
    assert later not in text, f"the refusal names the LATER check's fault {later!r}: {text!r}"


# ======================================================================================
# Step 2 — the row.
# ======================================================================================

def _row_absent(root: Path) -> None:
    return None


BAD_ROWS = [
    pytest.param(_row_absent, id="absent"),
    pytest.param(lambda root: H.plant_row(root, body="{not json"), id="corrupt"),
    pytest.param(lambda root: H.plant_row(root, body="[]\n"), id="corrupt-non-object"),
    pytest.param(lambda root: H.plant_row(root, row_tenant_id=H.OTHER), id="other-tenant"),
    pytest.param(lambda root: H.row_path(root).mkdir(parents=True), id="directory"),
    pytest.param(lambda root: H.plant_row(root, drop="created_at"), id="missing-created-at"),
]


@pytest.mark.parametrize("plant_bad_row", BAD_ROWS)
def test_1120_accept_tenant_refuses_an_absent_corrupt_or_foreign_row(
        tmp_path: Path, plant_bad_row) -> None:
    """With a complete knowledge/ in place, accept_tenant raises TenantRefused naming
    <root>/<id>/tenant.json when the tenant_row is absent, is not valid JSON, is a JSON
    non-object, names another tenant, is a directory standing at its name, or lacks
    created_at (J-PO2, executed: a missing created_at is a TenantRefused naming tenant.json,
    never a TypeError). The positive control, also J-PO2's: a row carrying an extra key a
    newer writer added is ACCEPTED, the key dropped (N18)."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    plant_bad_row(root)
    text = H.accept_refusal(_tenant, root)
    assert str(H.row_path(root)) in text, f"the refusal does not name the row: {text!r}"

    control = tmp_path / "control"
    H.place_knowledge(control)
    H.plant_row(control, extra={"added_by_a_newer_writer": "x"})
    tenant = H.accept(_tenant, control)
    assert tenant.row.tenant_id == H.TID


# ======================================================================================
# Step 3 — knowledge/ is a real, unlinked directory at <T>/knowledge.
# ======================================================================================

def _knowledge_absent(root: Path, tmp_path: Path) -> None:
    H.plant_row(root)


def _knowledge_symlink(root: Path, tmp_path: Path) -> None:
    H.plant_row(root)
    complete = H.place_knowledge(tmp_path / "other-place")
    H.knowledge_dir(root).symlink_to(complete, target_is_directory=True)


def _knowledge_file(root: Path, tmp_path: Path) -> None:
    H.plant_row(root)
    H.knowledge_dir(root).write_text("a file, not a folder\n", encoding="utf-8")


def _tenant_dir_symlink(root: Path, tmp_path: Path) -> None:
    """`<root>/acme` itself links to a complete tenant folder elsewhere: its row reads, but its
    knowledge/ does not resolve to `<root>/acme/knowledge`."""
    elsewhere = tmp_path / "elsewhere-tenant"
    H.adopted(elsewhere)
    root.mkdir(parents=True)
    (root / H.TID).symlink_to(elsewhere / H.TID, target_is_directory=True)


KNOWLEDGE_NOT_REAL = [
    pytest.param(_knowledge_absent, id="absent"),
    pytest.param(_knowledge_symlink, id="symlink"),
    pytest.param(_knowledge_file, id="file"),
    pytest.param(_tenant_dir_symlink, id="tenant-dir-symlink"),
]


@pytest.mark.parametrize("plant", KNOWLEDGE_NOT_REAL)
def test_1120_accept_tenant_refuses_a_knowledge_folder_that_is_not_a_real_unlinked_directory(
        tmp_path: Path, plant) -> None:
    """With a valid row, accept_tenant raises TenantRefused naming the knowledge path when
    <root>/<id>/knowledge is absent, is a symlink to a complete knowledge folder elsewhere
    (N13: an operator-placed symlinked knowledge/ is refused here), is a regular file, or when
    <root>/<id> itself is a symlink to a folder elsewhere so knowledge does not resolve to
    dir/knowledge. The absent cell's message also names the remedy — clone the tenant repo
    into it, then run tenant.py setup <id> (DC2, N12 re-read) — and every entry point passes
    it through verbatim. The positive control: the same row beside a real knowledge/ is
    accepted."""
    # rejected: sidecar symlink publishing (N13) — a symlinked knowledge/ is refused, never
    # followed to where it points.
    root = tmp_path / "data"
    plant(root, tmp_path)
    text = H.accept_refusal(_tenant, root)
    assert str(H.knowledge_dir(root)) in text, f"the refusal does not name knowledge/: {text!r}"
    if not H.knowledge_dir(root).exists() and not H.knowledge_dir(root).is_symlink():
        for remedy in ("clone", f"tenant.py setup {H.TID}"):
            assert remedy in text, (
                f"the absent-knowledge refusal carries no remedy ({remedy!r}): {text!r}")

    control = tmp_path / "control"
    H.adopted(control)
    assert H.accept(_tenant, control).knowledge == H.knowledge_dir(control)


# ======================================================================================
# Step 4 — the two halves and REQUIRED_SETTINGS.
# ======================================================================================

def _remove(rel: str):
    def plant(knowledge: Path, tmp_path: Path) -> Path:
        target = knowledge / rel
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        return target
    return plant


def _settings_symlink(knowledge: Path, tmp_path: Path) -> Path:
    real = tmp_path / "real-settings"
    shutil.move(str(knowledge / "settings"), real)
    (knowledge / "settings").symlink_to(real, target_is_directory=True)
    return knowledge / "settings"


def _required_is_directory(knowledge: Path, tmp_path: Path) -> Path:
    target = knowledge / "settings" / "lead-zero.yaml"
    target.unlink()
    target.mkdir()
    return target


MISSING_HALF_OR_SETTING = [
    pytest.param(_remove("settings"), id="settings_half:absent"),
    pytest.param(_remove("agent"), id="agent_half:absent"),
    pytest.param(_settings_symlink, id="settings_half:symlink"),
    *(pytest.param(_remove(f"settings/{rel}"), id=f"REQUIRED_SETTINGS:missing:{rel}")
      for rel in H.REQUIRED_SETTINGS),
    pytest.param(_required_is_directory, id="REQUIRED_SETTINGS:directory"),
]


@pytest.mark.parametrize("plant", MISSING_HALF_OR_SETTING)
def test_1120_accept_tenant_refuses_a_missing_half_or_required_settings_file(
        tmp_path: Path, plant) -> None:
    """accept_tenant raises TenantRefused naming the path when knowledge/settings/ is absent,
    when knowledge/agent/ is absent, when settings/ is a symlink to a real folder, when each
    REQUIRED_SETTINGS member (verb-grants.yaml, lead-zero.yaml,
    systems/case-history/mapping.yaml) is missing in turn, and when a REQUIRED_SETTINGS member
    is a directory. The positive control: a system's config.env being absent is NOT refused
    (some adapters need none; its absence stays the per-call ConfigFault)."""
    root = tmp_path / "data"
    folder = H.adopted(root)
    named = plant(folder / "knowledge", tmp_path)
    text = H.accept_refusal(_tenant, root)
    assert str(named) in text, f"the refusal does not name {named}: {text!r}"

    control = tmp_path / "control"
    H.adopted(control)
    (H.settings_dir(control) / "systems" / "cmdb" / "config.env").unlink()
    assert H.accept(_tenant, control).settings == H.settings_dir(control)


# ======================================================================================
# Step 5 — the link walk over settings/ and agent/ ONLY.
# ======================================================================================

LINKS_IN_HALVES = [
    pytest.param("settings", _plant_symlink, id="settings_half:symlink-inside"),
    pytest.param("settings", _plant_hardlink, id="settings_half:hardlink-inside"),
    pytest.param("agent", _plant_symlink, id="agent_half:symlink-inside"),
    pytest.param("agent", _plant_hardlink, id="agent_half:hardlink-inside"),
]


@pytest.mark.parametrize(("half", "plant"), LINKS_IN_HALVES)
def test_1120_accept_tenant_refuses_a_symlink_or_hard_link_inside_either_half(
        tmp_path: Path, half: str, plant) -> None:
    """A symlink planted in settings/ is refused, and so is a symlink in agent/, a second name
    for a settings/ file (a hard link, st_nlink > 1), and a hard link in agent/ — each with
    TenantRefused naming the planted entry, since a link can hand this tenant another's
    settings or knowledge. The positive control, through the same call: the same tenant with
    the plant removed is accepted."""
    # rejected: filesystem-portable hard-link detection (N11) — st_nlink > 1 is the rule.
    root = tmp_path / "data"
    H.adopted(root)
    planted = plant(H.knowledge_dir(root) / half, tmp_path)
    text = H.accept_refusal(_tenant, root)
    assert str(planted) in text, f"the refusal does not name the planted link: {text!r}"

    planted.unlink()
    assert H.accept(_tenant, root).id == H.TID


def _cloned_with_row(tmp_path: Path) -> Path:
    """DC2's canonical placement — a plain local clone into `<root>/acme/knowledge` — plus the
    row setup would write. Returns the data root."""
    root = tmp_path / "data"
    H.cloned_tenant(tmp_path, root)
    H.plant_row(root)
    return root


def _assert_hardlinked_objects(root: Path) -> None:
    """PO-b: the positive control is vacuous unless the clone really left a hard link to find."""
    linked = H.hardlinked_git_objects(H.knowledge_dir(root))
    assert linked, (
        "PRECONDITION FAILED (PO-b): no file under knowledge/.git/objects has st_nlink > 1 — "
        "this filesystem did not hard-link the local clone, so accepting it proves nothing")


def test_1120_accept_tenant_accepts_a_plain_local_clone_whose_git_objects_are_hard_linked(
        tmp_path: Path) -> None:
    """knowledge/ is a plain `git clone <local repo>` (no --no-hardlinks), so at least one file
    under knowledge/.git/objects has st_nlink > 1 (C3, C4; P-DC2-1 leg D). accept_tenant
    accepts it: the link walk skips knowledge/.git (U4's positive control, now the production
    shape under DC2). Today's tenant_dir refuses the same tree (C3)."""
    root = _cloned_with_row(tmp_path)
    _assert_hardlinked_objects(root)
    tenant = H.accept(_tenant, root)
    assert tenant.knowledge == H.knowledge_dir(root)


def _dot_github(knowledge: Path) -> Path:
    return knowledge / ".github"


def _dot_git(knowledge: Path) -> Path:
    return knowledge / ".git"


def test_1120_accept_tenant_walks_links_in_settings_and_agent_only(tmp_path: Path) -> None:
    """A symlink under knowledge/.github/ (outside both halves) and one under knowledge/.git/
    do not refuse the tenant: the walk covers settings/ and agent/ only and skips
    knowledge/.git. The same symlink moved into agent/ is refused, naming it. Only
    knowledge/.git is skipped (N15, reading (a)): a .git nested INSIDE a half is walked, and a
    link planted there is refused, naming it. The tree is a real clone committing
    agent/.tenant-id (a real repository, as check's committed-.tenant-id read expects — V11)
    and .github/ and .git are two of the names V12 admits at knowledge/'s top level."""
    # rejected: walking .git (a local clone's objects are hard links, C3/C4) or the whole
    # knowledge/ folder.
    root = _cloned_with_row(tmp_path)
    knowledge = H.knowledge_dir(root)
    for outside_the_halves in (_dot_github(knowledge), _dot_git(knowledge)):
        outside_the_halves.mkdir(exist_ok=True)
        _plant_symlink(outside_the_halves, tmp_path)
    assert H.accept(_tenant, root).id == H.TID, "a link outside the halves refused the tenant"

    moved = _plant_symlink(H.agent_dir(root), tmp_path)
    text = H.accept_refusal(_tenant, root)
    assert str(moved) in text, f"the link in agent/ was not refused by name: {text!r}"
    moved.unlink()

    nested = H.agent_dir(root) / "vendored" / ".git"
    nested.mkdir(parents=True)
    in_nested = _plant_symlink(nested, tmp_path)
    text = H.accept_refusal(_tenant, root)
    assert str(in_nested) in text, f"a link in a .git nested inside agent/ was skipped: {text!r}"


# ======================================================================================
# Step 6 — agent/.tenant-id.
# ======================================================================================

TENANT_ID_FILE_CELLS = [
    pytest.param(None, False, id="absent"),
    pytest.param(f"{H.OTHER}\n", False, id="other-id"),
    pytest.param("ac\x1bme\n", False, id="control-chars"),
    pytest.param(H.TID, True, id="matching"),
    pytest.param(f"{H.TID}\n", True, id="matching-with-newline"),
]


@pytest.mark.parametrize(("content", "accepted"), TENANT_ID_FILE_CELLS)
def test_1120_accept_tenant_refuses_an_agent_tenant_id_that_is_absent_or_names_another_tenant(
        tmp_path: Path, content: str | None, accepted: bool) -> None:
    """accept_tenant(root, "acme", …) raises TenantRefused naming knowledge/agent/.tenant-id
    when the file is absent, when it holds another tenant's id (the message also names that
    id, beta), and when it carries a control character (rendered escaped, never raw — N16).
    It returns a Tenant when the file holds acme, with or without a trailing newline. Under
    DC2 setup writes nothing into knowledge/, so an absent file is a folder-rule refusal."""
    root = tmp_path / "data"
    H.adopted(root, tenant_id_file=content)
    tid_file = H.knowledge_dir(root) / H.TENANT_ID_FILE
    if accepted:
        assert H.accept(_tenant, root).id == H.TID
        return
    text = H.accept_refusal(_tenant, root)
    assert str(tid_file) in text, f"the refusal does not name {tid_file}: {text!r}"
    if content is not None and content.startswith(H.OTHER):
        assert H.OTHER in text, f"the refusal does not name the id the file holds: {text!r}"
    assert not any(ord(c) < 0x20 for c in text), f"a control character reached the text: {text!r}"


# ======================================================================================
# V3 as WIDENED by V12 and V15 (human, §7-verify; replaces M9 5(i) under DC2, overriding NF7):
# knowledge/'s top level holds settings/, agent/, .github/, .git, archive/ (V15: A6's lab archive,
# outside both halves, never mounted), README.md, .gitignore and .gitattributes — nothing else.
# ======================================================================================

#: The eight names V12 and V15 admit at knowledge/'s top level (sorted as `iterdir` is compared).
ALLOWED_TOP_LEVEL = [".git", ".gitattributes", ".github", ".gitignore", "README.md", "agent",
                     "archive", "settings"]


def _dot_env(knowledge: Path) -> Path:
    entry = knowledge / ".env"
    entry.write_text("API_TOKEN=an-operator-secret\n", encoding="utf-8")
    return entry


def _secrets_dir(knowledge: Path) -> Path:
    entry = knowledge / "secrets"
    entry.mkdir()
    (entry / "token").write_text("an-operator-secret\n", encoding="utf-8")
    return entry


def _docs_dir(knowledge: Path) -> Path:
    entry = knowledge / "docs"
    entry.mkdir()
    (entry / "runbook.md").write_text("# how acme's analysts work\n", encoding="utf-8")
    return entry


EXTRA_TOP_LEVEL = [
    pytest.param(_dot_env, id="knowledge_dir:extra-top-level-entry:.env"),
    pytest.param(_secrets_dir, id="knowledge_dir:extra-top-level-entry:secrets"),
    pytest.param(_docs_dir, id="knowledge_dir:extra-top-level-entry:docs"),
]


def _clone_with_every_allowed_entry(tmp_path: Path, root: Path) -> Path:
    """A clone of a repo committing agent/.tenant-id, a .github/workflows file, a README.md, a
    .gitignore, a .gitattributes and a file under archive/ (A6's lessons-actor/, as the lab repo
    carries it — git keeps no empty directory) — every name V12 and V15 admit present at
    knowledge/'s top level."""
    src = tmp_path / "ci-src"
    shutil.copytree(H.FIXTURE, src, symlinks=True)
    H.write_tenant_id_file(src, H.TID, "id")
    workflow = src / ".github" / "workflows" / "tenant-ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("on: push\njobs: {}\n", encoding="utf-8")
    (src / "README.md").write_text("# acme's tenant repo\n", encoding="utf-8")
    (src / ".gitignore").write_text("*.swp\n", encoding="utf-8")
    (src / ".gitattributes").write_text("*.yaml text eol=lf\n", encoding="utf-8")
    archived = src / "archive" / "lessons-actor" / "README.md"
    archived.parent.mkdir(parents=True)
    archived.write_text("# retired actor lessons (A6)\n", encoding="utf-8")
    repo = H.repo_of(src, tmp_path / "ci-repo")
    return H.local_clone(repo, H.knowledge_dir(root))


@pytest.mark.parametrize("plant", EXTRA_TOP_LEVEL)
def test_1120_accept_tenant_refuses_a_knowledge_entry_outside_the_allow_list(
        tmp_path: Path, plant) -> None:
    """A top-level entry of knowledge/ outside the allow-list — settings/, agent/, .github/,
    .git, archive/, README.md, .gitignore and .gitattributes (V12 and V15, human, widening V3)
    — here a .env, a
    secrets/ folder or a docs/ folder, is refused naming the entry (the folder rules keep an
    operator's .env or secrets/ out of the data root; .tenant-id lives inside agent/).
    accept_tenant raises TenantRefused naming it; `tenant.py check acme` and `tenant.py check
    --folder <knowledge>` (a folder rule, so it needs no data root) exit 1 naming it; a row-less
    first `tenant.py setup acme` exits 1 naming it and writes nothing. The positive control: a
    clone whose top level is exactly the eight allow-listed names — README.md, .gitignore,
    .gitattributes and a file under archive/ committed among them — is accepted, and check
    --folder over it exits 0."""
    root = tmp_path / "data"
    H.adopted(root)
    entry = plant(H.knowledge_dir(root))
    text = H.accept_refusal(_tenant, root)
    assert str(entry) in text, f"the refusal does not name {entry}: {text!r}"
    H.assert_refused(H.check(tenant_py, root, H.TID), str(entry))
    H.assert_refused(H.check(tenant_py, None, "--folder", str(H.knowledge_dir(root))),
                     str(entry))

    H.row_path(root).unlink()
    before = H.tree_census(root)
    text = H.assert_refused(H.setup(tenant_py, root), str(entry))
    assert "the data root is not empty" not in text, (
        f"the refusal is the one-tenant guard's; it must admit the placed knowledge (MF1) and "
        f"the folder rule must refuse the entry:\n{text}")
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"

    control = tmp_path / "control"
    knowledge = _clone_with_every_allowed_entry(tmp_path, control)
    assert sorted(p.name for p in knowledge.iterdir()) == ALLOWED_TOP_LEVEL
    H.plant_row(control)
    assert H.accept(_tenant, control).id == H.TID
    H.assert_clean(H.check(tenant_py, None, "--folder", str(knowledge)))


def _tenant_id_directory(knowledge: Path) -> None:
    target = knowledge / H.TENANT_ID_FILE
    target.unlink()
    target.mkdir()


def _tenant_id_oversize(knowledge: Path) -> None:
    """A 16 MiB SPARSE file: a bounded read (at most 128 bytes) refuses it at once."""
    with open(knowledge / H.TENANT_ID_FILE, "wb") as fh:
        fh.write(b"acme\n")
        fh.truncate(16 * 1024 * 1024)


#: M8's byte rule, cell by cell: (id token, the file's bytes or a planter, accepted?).
BYTE_RULE_CELLS: list[tuple[str, object, bool]] = [
    ("trailing-newline", b"acme\n", True),
    ("crlf", b"acme\r\n", True),
    ("bom", b"\xef\xbb\xbfacme\n", False),
    ("trailing-space", b"acme \n", False),
    ("uppercase", b"ACME\n", False),
    ("extra-line", b"acme\nbeta\n", False),
    ("empty", b"", False),
    ("directory", _tenant_id_directory, False),
    ("invalid-utf8", b"acme\xff\n", False),
    ("oversize", _tenant_id_oversize, False),
]


def _plant_byte_cell(knowledge: Path, content: object) -> None:
    if callable(content):
        content(knowledge)
    else:
        (knowledge / H.TENANT_ID_FILE).write_bytes(content)  # type: ignore[arg-type]


def test_1120_accept_tenant_reads_the_tenant_id_file_bounded_and_admits_only_the_id_and_one_line_ending(
        tmp_path: Path) -> None:
    """accept_tenant and `tenant.py check <id>` accept agent/.tenant-id holding exactly the id
    plus at most one LF or CRLF, read bounded (at most 128 bytes), and refuse every other
    variant naming the file: a BOM, a trailing space, uppercase, a second line, an empty file,
    a directory at the name, invalid UTF-8, and an oversize file (refused unread). check
    <id> exits 0 on the accepted variants and 1 on the refused ones. The template and the
    fixture commit no .tenant-id (M8), and `tenant.py check --folder` grammar-checks the file
    only when present: --folder over knowledge/tenant-template exits 0, over a tmp copy of the
    fixture without the file exits 0, and over the same copy holding an off-grammar .tenant-id
    exits 1 naming it. DC2 drops setup writing the file: setup writes nothing into knowledge/."""
    misjudged: list[str] = []
    for token, content, accepted in BYTE_RULE_CELLS:
        root = tmp_path / token
        H.adopted(root)
        _plant_byte_cell(H.knowledge_dir(root), content)
        tid_file = str(H.knowledge_dir(root) / H.TENANT_ID_FILE)
        if accepted:
            H.accept(_tenant, root)
        else:
            text = H.accept_refusal(_tenant, root)
            if tid_file not in text:
                misjudged.append(f"accept_tenant[{token}] did not name {tid_file}: {text!r}")
        proc = H.check(tenant_py, root, H.TID)
        H.assert_ran(proc)
        want = 0 if accepted else 1
        if proc.returncode != want or (not accepted and tid_file not in H.output(proc)):
            misjudged.append(f"check {H.TID} [{token}] exited {proc.returncode}, want {want}:\n"
                             f"{H.output(proc)}")
    assert not misjudged, "\n".join(misjudged)

    assert not (H.TEMPLATE / H.TENANT_ID_FILE).exists(), "the template commits a .tenant-id"
    assert not (H.FIXTURE / H.TENANT_ID_FILE).exists(), "the fixture commits a .tenant-id"
    H.assert_clean(H.check(tenant_py, None, "--folder", str(H.TEMPLATE)))
    folder = tmp_path / "fixture-copy"
    shutil.copytree(H.FIXTURE, folder, symlinks=True)
    H.assert_clean(H.check(tenant_py, None, "--folder", str(folder)))
    (folder / H.TENANT_ID_FILE).write_bytes(b"ACME\n")
    H.assert_refused(H.check(tenant_py, None, "--folder", str(folder)),
                     str(folder / H.TENANT_ID_FILE))


# ======================================================================================
# Step 7 — settings outside every mounted tree.
# ======================================================================================

def test_1120_accept_tenant_refuses_settings_under_defender_dir_or_a_box_mounted_path(
        tmp_path: Path) -> None:
    """accept_tenant raises TenantRefused naming the settings path and the mounted tree in two
    cases: the defender_dir passed is a tmp tree that contains the data root, or box_mounted
    names a directory that contains tenant.settings (the settings half is host-only; a box
    mounts defender/ and the runs base). The positive control: the same tenant with
    defender_dir and box_mounted disjoint from it is accepted."""
    fake_defender = tmp_path / "fake-defender"
    root = fake_defender / "data"
    H.adopted(root)
    settings = str(H.settings_dir(root))

    text = H.accept_refusal(_tenant, root, defender_dir=fake_defender)
    assert settings in text, f"the defender_dir refusal does not name settings: {text!r}"
    assert str(fake_defender) in text, f"the refusal does not name the tree: {text!r}"

    mounted = H.knowledge_dir(root)
    text = H.accept_refusal(_tenant, root, box_mounted=(mounted,))
    assert settings in text, f"the box_mounted refusal does not name settings: {text!r}"
    assert str(mounted) in text, f"the refusal does not name the mounted tree: {text!r}"

    tenant = H.accept(_tenant, root, defender_dir=tmp_path / "another-defender",
                      box_mounted=(H.tenant_folder(root) / "runs",))
    assert tenant.settings == H.settings_dir(root)


def test_1120_accept_tenant_accepts_an_unversioned_knowledge_folder(tmp_path: Path) -> None:
    """A knowledge/ that is a plain folder (no .git) holding complete halves and a matching
    agent/.tenant-id is accepted (settled decision 9: an unversioned knowledge folder runs)."""
    root = tmp_path / "data"
    H.adopted(root)
    assert not (H.knowledge_dir(root) / ".git").exists()
    tenant = H.accept(_tenant, root)
    assert tenant.knowledge == H.knowledge_dir(root)
    assert tenant.agent == H.agent_dir(root)


# ======================================================================================
# M9's surviving rule and NF2's named refusal.
# ======================================================================================

def _fifo(where: Path) -> Path:
    path = where / "planted.fifo"
    os.mkfifo(path)
    return path


def _socket(where: Path) -> Path:
    path = where / "planted.sock"
    os.mknod(path, stat.S_IFSOCK | 0o600)
    return path


def _device(where: Path) -> Path:
    path = where / "planted.dev"
    try:
        os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(1, 3))
    except PermissionError:
        pytest.skip("creating a device node needs CAP_MKNOD; the fifo and socket cells cover "
                    "the rule on an unprivileged runner")
    return path


NON_REGULAR = [
    pytest.param("settings", _fifo, id="settings_half:non-regular-entry:fifo"),
    pytest.param("settings", _socket, id="settings_half:non-regular-entry:socket"),
    pytest.param("settings", _device, id="settings_half:non-regular-entry:device"),
    pytest.param("agent", _fifo, id="agent_half:non-regular-entry:fifo"),
    pytest.param("agent", _socket, id="agent_half:non-regular-entry:socket"),
]


@pytest.mark.parametrize(("half", "plant"), NON_REGULAR)
def test_1120_accept_tenant_refuses_a_fifo_socket_or_device_inside_either_half_without_opening_it(
        tmp_path: Path, half: str, plant) -> None:
    """A FIFO, socket or device inside settings/ or agent/ of an adopted knowledge/ is refused
    with TenantRefused naming it, without being opened (a FIFO opened for reading would block
    acceptance forever, which this test fails on a deadline). The positive control, through
    the same call: regular files and directories only — the same tenant with the entry
    removed — is accepted."""
    root = tmp_path / "data"
    H.adopted(root)
    planted = plant(H.knowledge_dir(root) / half)
    value, exc = _accept_within(_tenant, root, fifo=planted if planted.suffix == ".fifo" else None)
    assert isinstance(exc, _tenant.TenantRefused), (
        f"a {planted.suffix} in {half}/ was not refused as TenantRefused: {value!r} / {exc!r}")
    assert str(planted) in str(exc), f"the refusal does not name the entry: {exc}"

    planted.unlink()
    assert H.accept(_tenant, root).id == H.TID


def _unlistable_settings_dir(knowledge: Path) -> Path:
    target = knowledge / "settings" / "systems" / "cmdb"
    target.chmod(0)
    return target


def _unlistable_agent(knowledge: Path) -> Path:
    target = knowledge / "agent"
    target.chmod(0)
    return target


def _unreadable_tenant_id(knowledge: Path) -> Path:
    target = knowledge / H.TENANT_ID_FILE
    target.chmod(0)
    return target


UNREADABLE = [
    pytest.param(_unlistable_settings_dir, id="settings-dir-mode-000"),
    pytest.param(_unlistable_agent, id="agent-mode-000"),
    pytest.param(_unreadable_tenant_id, id="tenant-id-mode-000"),
]


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses mode bits; CI runs unprivileged")
@pytest.mark.parametrize("plant", UNREADABLE)
def test_1120_accept_tenant_names_an_unreadable_entry_as_a_refusal_never_a_traceback(
        tmp_path: Path, plant) -> None:
    """An OSError from any read accept_tenant performs — the link walk meeting an unlistable
    directory in settings/, an unlistable agent/, an unreadable agent/.tenant-id — is raised
    as TenantRefused naming the path and the errno (NF2), never an escaping OSError.
    `tenant.py setup` and `tenant.py check <id>` print it as `[tenant.py] …` and exit 1, never
    a traceback, and setup writes no row. There is no ownership rule (N11). The positive
    control: the same tree with the mode restored is accepted."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    target = plant(H.knowledge_dir(root))
    try:
        H.plant_row(root)
        text = H.accept_refusal(_tenant, root)
        assert str(target) in text, f"the refusal does not name the unreadable path: {text!r}"
        assert any(e in text for e in ("Permission denied", "EACCES", "Errno 13")), (
            f"the refusal does not name the errno: {text!r}")
        H.row_path(root).unlink()
        H.assert_refused(H.setup(tenant_py, root), "[tenant.py]", str(target))
        assert not H.row_path(root).exists(), "the refused setup wrote the row"
        H.plant_row(root)
        H.assert_refused(H.check(tenant_py, root, H.TID), "[tenant.py]", str(target))
    finally:
        target.chmod(0o755 if target.is_dir() else 0o644)
    assert H.accept(_tenant, root).id == H.TID


# ======================================================================================
# Settled premises (45-dispositions, "Settled (30)").
# ======================================================================================

def test_1120_s0_id_grammar_length_boundary(tmp_path: Path) -> None:
    """A 63-character id that matches the unchanged TenantId grammar passes accept_tenant's
    step 1 (a finished tenant under that id is accepted). A 64-character id is refused with
    TenantRefused naming it, before any path under the data root is named."""
    root = tmp_path / "data"
    longest = "a" * 63
    H.adopted(root, longest)
    assert H.accept(_tenant, root, longest).id == longest

    too_long = "a" * 64
    text = H.accept_refusal(_tenant, root, too_long)
    assert too_long[:40] in text, text
    assert str(root) not in text, text


def test_1120_s0_containment_string_prefix_near_miss(tmp_path: Path) -> None:
    """Step 7 does not refuse a box_mounted path or a defender_dir that only shares a string
    prefix with the settings path: a mounted `<root>/acme/knowledge/sett` or a defender tree
    at `<root>/acme/knowledge/setting` beside settings/, and a sibling data root `<tmp>/T-other`
    beside the data root `<tmp>/T`. Containment means path-component ancestry. The positive
    control: a true ancestor (the knowledge folder mounted, or the data root inside the
    defender tree) is refused. The two near-miss paths inside knowledge/ are named, never
    created: V12's allow-list refuses any other top-level entry of knowledge/, and step 7's
    containment is a path comparison, not a filesystem read."""
    root = tmp_path / "T"
    H.adopted(root)
    knowledge = H.knowledge_dir(root)
    near_mount, near_defender, sibling = (knowledge / "sett", knowledge / "setting",
                                          tmp_path / "T-other")
    sibling.mkdir()
    assert H.accept(_tenant, root, box_mounted=(near_mount, sibling)).id == H.TID
    assert H.accept(_tenant, root, defender_dir=near_defender).id == H.TID
    assert H.accept(_tenant, root, defender_dir=sibling).id == H.TID

    H.accept_refusal(_tenant, root, box_mounted=(knowledge,))
    H.accept_refusal(_tenant, root, defender_dir=tmp_path)


def test_1120_s5_link_walk_meets_a_symlink_cycle(tmp_path: Path) -> None:
    """A symlink inside agent/ points back at an ancestor of itself, forming a cycle. The walk
    never follows a directory link: the symlink forming the cycle is refused as a symlink in
    the half, by name, and accept_tenant returns (it does not hang)."""
    root = tmp_path / "data"
    H.adopted(root)
    loop = H.agent_dir(root) / "loop"
    loop.symlink_to(H.agent_dir(root), target_is_directory=True)
    value, exc = _accept_within(_tenant, root)
    assert isinstance(exc, _tenant.TenantRefused), f"the cycle was not refused: {value!r} {exc!r}"
    assert str(loop) in str(exc), f"the refusal does not name the cycle's link: {exc}"


def test_1120_s5_local_clone_positive_control_no_hard_link_to_find(tmp_path: Path) -> None:
    """U4's positive control builds the source repo and its plain local clone under one
    tmp_path. It asserts its precondition FIRST — at least one file under
    knowledge/.git/objects has st_nlink > 1 — and a failed precondition fails the test, never
    passing vacuously (PO-b). Only then does it assert acceptance."""
    root = _cloned_with_row(tmp_path)
    _assert_hardlinked_objects(root)
    assert H.accept(_tenant, root).knowledge == H.knowledge_dir(root)


def test_1120_s6_data_root_env_var_symlink_retargeted_mid_resolution(
        tmp_path: Path, monkeypatch) -> None:
    """DEFENDER_DATA_ROOT may itself be a symlink. resolve_data_root resolves it once per
    entry point; accept_tenant and everything after it use the resolved path, so retargeting
    the link afterwards does not change which tenant the process reads: the Tenant's
    data_root and settings stay under the first target."""
    first, second = tmp_path / "root-a", tmp_path / "root-b"
    H.adopted(first)
    H.adopted(second)
    link = tmp_path / "data-root-link"
    link.symlink_to(first, target_is_directory=True)
    monkeypatch.setenv(H.DATA_ROOT_ENV, str(link))
    resolved = _tenant.resolve_data_root()
    assert resolved == first.resolve()

    link.unlink()
    link.symlink_to(second, target_is_directory=True)
    tenant = H.accept(_tenant, resolved)
    assert tenant.data_root == first.resolve()
    assert tenant.settings == first.resolve() / H.TID / "knowledge" / "settings"


# ======================================================================================
# R7 (minted at phase E) — every reader of the row agrees with accept_tenant.
# ======================================================================================

ROW_CELLS = [
    pytest.param(_row_absent, False, id="absent"),
    pytest.param(lambda root: H.plant_row(root, body="{not json"), False, id="corrupt"),
    pytest.param(lambda root: H.plant_row(root, row_tenant_id=H.OTHER), False, id="other-tenant"),
    pytest.param(lambda root: H.row_path(root).mkdir(parents=True), False, id="directory"),
    pytest.param(lambda root: H.plant_row(root, drop="created_at"), False,
                 id="missing-created-at"),
    pytest.param(lambda root: H.plant_row(root, extra={"added_by_a_newer_writer": "x"}), True,
                 id="extra-key"),
]


def _cell_tree(root: Path, plant_row_cell) -> None:
    H.place_knowledge(root)
    plant_row_cell(root)


def _verdict(owner, fn, *args) -> str | None:
    """`None` when the reader accepts, else its refusal text — a TenantRefused, asserted."""
    try:
        fn(*args)
    except owner.TenantRefused as refused:
        return str(refused)
    return None


@pytest.mark.parametrize(("plant_row_cell", "accepted"), ROW_CELLS)
def test_1120_every_tenant_row_reader_refuses_what_accept_tenant_refuses(
        tmp_path: Path, plant_row_cell, accepted: bool) -> None:
    """Every reader of <root>/<id>/tenant.json reaches accept_tenant's verdict on each of its
    row cells — absent, corrupt, other-tenant, directory and missing-created-at refused, an
    extra key accepted — and every refusal names <root>/acme/tenant.json: accept_tenant,
    require_tenant, and tenant_of_run_dir (given the data root and a run dir under
    <root>/acme/runs whose runs-base record names acme; D1 re-signs it to take the root).
    The one-tenant guard refuse_foreign_data_root reads the row only for its presence and
    leaves its shape to acceptance (the row's own name exempt, pass-A J60; MF1 admits the
    placed knowledge beside a missing row), so it returns on every cell; `tenant.py setup`
    over each cell then refuses every present bad row naming tenant.json and leaves it
    byte-identical, stays silent over the extra-key row, and adopts the absent-row cell by
    writing the row."""
    verdicts: dict[str, str | None] = {}
    for reader in ("accept_tenant", "require_tenant", "tenant_of_run_dir"):
        root = tmp_path / reader
        _cell_tree(root, plant_row_cell)
        if reader == "accept_tenant":
            verdicts[reader] = _verdict(_tenant, H.accept, _tenant, root, H.TID)
        elif reader == "require_tenant":
            verdicts[reader] = _verdict(_tenant, _tenant.require_tenant, root,
                                        _tenant.TenantId(H.TID))
        else:
            runs = H.tenant_folder(root) / "runs"
            runs.mkdir(parents=True, exist_ok=True)
            S1077.plant_tenant_record(runs, tenant_id=H.TID)
            (runs / "r1").mkdir()
            verdicts[reader] = _verdict(_tenant, _tenant.tenant_of_run_dir, root, runs / "r1")
        row = str(H.row_path(root))
        if accepted:
            assert verdicts[reader] is None, f"{reader} refused an extra-key row: {verdicts[reader]}"
        else:
            assert verdicts[reader] is not None, f"{reader} accepted a bad row"
            assert row in verdicts[reader], (
                f"{reader} did not refuse this row naming {row}: {verdicts[reader]!r}")

    guarded = tmp_path / "guard"
    _cell_tree(guarded, plant_row_cell)
    assert _verdict(_tenant, _tenant.refuse_foreign_data_root, guarded,
                    _tenant.TenantId(H.TID)) is None, "the guard judged the row's shape"

    setup_root = tmp_path / "setup"
    _cell_tree(setup_root, plant_row_cell)
    row_existed = H.row_path(setup_root).exists()
    before = H.tree_census(setup_root)
    proc = H.setup(tenant_py, setup_root)
    if not row_existed:
        H.assert_clean(proc)
        assert H.row_path(setup_root).is_file(), "setup did not adopt the absent-row cell"
    elif accepted:
        H.assert_clean(proc)
        assert H.census_diff(before, H.tree_census(setup_root)) == []
    else:
        H.assert_refused(proc, str(H.row_path(setup_root)))
        assert H.census_diff(before, H.tree_census(setup_root)) == [], "setup rewrote a bad row"
