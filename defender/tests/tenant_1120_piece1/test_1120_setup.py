"""#1120 piece 1 — D7 `tenant.py setup <id>`: ADOPT the operator-placed knowledge folder.

DC2 (human, §7): setup never fetches. The operator clones the tenant's repo on the host into
`<root>/<id>/knowledge` (or places a plain folder there), then runs `tenant.py setup <id>`,
which runs the one-tenant guard (MF1 (a): a rowless `<id>/` may hold exactly the name
`knowledge`), then setup's rule as V18 (human) states it: the folder rules (links and special
files, `agent/.tenant-id` presence + match, the top-level allow-list, the settings files parse —
`mapping.yaml` included) plus RUN START'S OWN readiness function (V14, human, superseding V1's
and V10's rule lists: the grant table loads, gather holds a query verb, the lead-zero agreement —
setup refuses anything that would make a run refuse), then writes the row LAST (MF1 Q2,
rules-first) — so a refused setup writes nothing.
There is no `--from`, no copy, no staging, no rename and no git call, over a plain folder or a
clone (DC2; V11 keeps the committed-.tenant-id rule in `check`). The grant gap is `check`'s,
never setup's (DC1 as refined by V1: runs proceed over a gap, A1).

Driven as the operator runs it: a process against a data root the test owns. The exit status
and output are the observables, and "writes nothing" is a before/after census of the data root
(bytes, mtimes and modes), never a bare exit code, which a crash also satisfies.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from defender import _tenant
from defender import run as run_py
from defender.scripts import tenant as tenant_py
from defender.tests import _dispositions995 as D995
from defender.tests.tenant_1120_piece1 import _spec1120 as H

#: The remedy every "no knowledge folder" refusal carries (DC2, N12 re-read): clone the tenant
#: repo into the folder, then run setup again.
REMEDY_WORDS = ("clone", "tenant.py setup")


def _rowless_empty_own_folder(root: Path) -> None:
    (root / H.TID).mkdir(parents=True)


def _row_only_tenant(root: Path) -> None:
    H.plant_row(root, H.TID)


ABSENT_KNOWLEDGE = [
    pytest.param(lambda root: None, id="absent-data-root"),
    pytest.param(lambda root: root.mkdir(parents=True), id="empty-data-root"),
    pytest.param(_rowless_empty_own_folder, id="empty-rowless-own-folder"),
    pytest.param(_row_only_tenant, id="row-only-tenant"),
]


@pytest.mark.parametrize("plant", ABSENT_KNOWLEDGE)
def test_1120_setup_over_an_absent_knowledge_folder_exits_one_naming_it_and_the_remedy_and_writes_nothing(
        tmp_path: Path, plant) -> None:
    """`tenant.py setup acme` exits 1 naming <root>/acme/knowledge and the remedy (clone the
    tenant repo into it, then run tenant.py setup acme again) in three cases: an absent or
    empty data root, an empty rowless acme/ folder, and a row-only tenant. It writes nothing:
    no row, no directory, and an existing row stays byte-identical (rules-first, MF1 Q2).
    This supersedes pass-A's o10_fresh_root_writes_exactly_row exit 0 and J08's positive
    leg — presence of a row alone is never a successful setup."""
    root = tmp_path / "data"
    plant(root)
    before = H.tree_census(root)
    proc = H.setup(tenant_py, root)
    text = H.assert_refused(proc, str(H.knowledge_dir(root)))
    for word in REMEDY_WORDS:
        assert word in text, f"the refusal does not carry the remedy word {word!r}:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == [], (
        "the refused setup wrote into the data root")


# ======================================================================================
# Shared observations for this file.
# ======================================================================================

#: A verb the change-mgmt adapter declares (`change_mgmt_adapter.VERBS`) and the fixture's
#: table grants on one line — dropping that line leaves a GAP the census names as
#: `change-mgmt.get-change` (DC1: `check`'s finding, never setup's).
GAP_LINE = "    get-change:"
GAP_PAIR = "change-mgmt.get-change"


def _row_is_acme(root: Path) -> None:
    """Exactly one row under `root`, and it is valid JSON naming acme."""
    rows = sorted(Path(root).glob("*/tenant.json"))
    assert rows == [H.row_path(root)], f"the data root holds rows {rows}, not exactly acme's"
    doc = json.loads(H.row_path(root).read_text(encoding="utf-8"))
    assert doc.get("tenant_id") == H.TID, f"the row names {doc.get('tenant_id')!r}, not acme"


def _gap_table(settings: Path) -> None:
    """Drop one declared verb's row from a tenant's table (a real edit on disk)."""
    before = (Path(settings) / "verb-grants.yaml").read_text(encoding="utf-8")
    H.edit_table(settings, drop=(GAP_LINE,))
    after = (Path(settings) / "verb-grants.yaml").read_text(encoding="utf-8")
    assert after != before, "the gap edit changed nothing"
    assert GAP_LINE not in after, "the gap edit left the verb's row in place"


def _knowledge_census(root: Path) -> dict:
    return H.tree_census(H.knowledge_dir(root))


# ======================================================================================
# DC2 + MF1 (a): setup ADOPTS the placed folder — the row is its only write.
# ======================================================================================

def _plain_folder(tmp: Path, root: Path) -> Path:
    return H.place_knowledge(root)


def _local_clone(tmp: Path, root: Path) -> Path:
    knowledge = H.cloned_tenant(tmp, root)
    # The cell IS a hard-linked clone (C3/C4, P-DC2-1 leg D) — assert it, never assume it.
    assert H.hardlinked_git_objects(knowledge), (
        "precondition: the plain local clone left no hard-linked file under .git/objects — "
        "this cell would not be the local-clone-hardlinked-git member")
    return knowledge


PLACEMENTS = [
    pytest.param(_local_clone, id="local-clone-hardlinked-git"),
    pytest.param(_plain_folder, id="plain-folder"),
]


@pytest.mark.parametrize("place", PLACEMENTS)
def test_1120_setup_adopts_an_operator_placed_knowledge_folder_writing_only_the_row(
        tmp_path: Path, place) -> None:
    """Over a data root whose only entry is acme/knowledge, placed by the operator, `tenant.py
    setup acme` exits 0 and prints nothing. The root census gains exactly acme/tenant.json;
    every file under knowledge/ is byte- and mtime-identical, and `git status --porcelain` in
    the clone is empty; accept_tenant then succeeds over the tree. Two cells: a plain `git
    clone <local repo path>` of a repo committing agent/.tenant-id, whose .git objects are hard
    links, and a plain folder carrying .tenant-id. The one-tenant guard admits the placed
    knowledge in the rowless own folder (MF1 (a), P-DC2-1: at a1c65801 it refused it)."""
    # rejected: detecting an in-progress or interrupted clone (NF3) — setup judges the tree
    # as found; the docs say run setup after the clone exits 0.
    root = tmp_path / "data"
    knowledge = place(tmp_path, root)
    before = H.tree_census(root)
    proc = H.setup(tenant_py, root)
    text = H.assert_clean(proc)
    assert text == "", f"a successful adopt printed something:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == [f"added: {H.TID}/{H.ROW_NAME}"], (
        "setup's adopt wrote something other than exactly the row")
    _row_is_acme(root)
    if (knowledge / ".git").exists():
        assert H.git_status(knowledge) == "", "setup dirtied the operator's clone"
    tenant = H.accept(_tenant, root)
    assert tenant.id == H.TID


# ======================================================================================
# MF1 (a), NF6: the guard's rowless inner scan admits exactly the NAME `knowledge`.
# ======================================================================================

def _knowledge_dir_entry(root: Path, tmp: Path) -> None:
    H.knowledge_dir(root).mkdir(parents=True)


def _knowledge_symlink(root: Path, tmp: Path) -> None:
    elsewhere = tmp / "elsewhere-knowledge"
    elsewhere.mkdir()
    H.tenant_folder(root).mkdir(parents=True)
    H.knowledge_dir(root).symlink_to(elsewhere, target_is_directory=True)


def _knowledge_file(root: Path, tmp: Path) -> None:
    H.tenant_folder(root).mkdir(parents=True)
    H.knowledge_dir(root).write_text("not a folder\n", encoding="utf-8")


def _row_alias_beside_knowledge(root: Path, tmp: Path) -> None:
    # J60: an alias planted at the row's own name is the guarded write's to refuse, never the
    # guard's — the row's name stays exempt from the inner scan.
    H.knowledge_dir(root).mkdir(parents=True)
    H.row_path(root).symlink_to(tmp / "nowhere.json")


def _runs_beside_knowledge(root: Path, tmp: Path) -> None:
    H.knowledge_dir(root).mkdir(parents=True)
    (H.tenant_folder(root) / "runs").mkdir()


def _other_knowledge(root: Path, tmp: Path) -> None:
    H.knowledge_dir(root).mkdir(parents=True)
    H.knowledge_dir(root, H.OTHER).mkdir(parents=True)


GUARD_CELLS = [
    pytest.param(_knowledge_dir_entry, None, id="knowledge-directory"),
    pytest.param(_knowledge_symlink, None, id="knowledge-symlink"),
    pytest.param(_knowledge_file, None, id="knowledge-file"),
    pytest.param(_row_alias_beside_knowledge, None, id="row-name-exempt"),
    pytest.param(_runs_beside_knowledge, f"{H.TID}/runs", id="runs-beside-knowledge"),
    pytest.param(_other_knowledge, H.OTHER, id="other-knowledge"),
]


@pytest.mark.parametrize(("plant", "foreign"), GUARD_CELLS)
def test_1120_the_one_tenant_guard_admits_only_knowledge_beside_a_missing_row(
        tmp_path: Path, plant, foreign: str | None) -> None:
    """refuse_foreign_data_root(root, acme) returns over a rowless acme/ holding exactly
    knowledge, whether that entry is a directory, a symlink or a file: the guard admits the
    NAME, and acceptance judges the type (NF6). The row's own name stays exempt (pass-A J60).
    It refuses naming acme/runs when runs/ sits beside knowledge — the principle narrows from
    "anything setup did not make is foreign" to "anything the setup protocol did not sanction
    is foreign", never further — and refuses naming beta for beta/knowledge beside acme's (the
    outer scan is unchanged, N1). The admitted cells are the positive control of the refused
    ones."""
    root = tmp_path / "data"
    plant(root, tmp_path)
    before = H.tree_census(root)
    refused: BaseException | None = None
    try:
        _tenant.refuse_foreign_data_root(root, _tenant.TenantId(H.TID))
    except _tenant.TenantRefused as exc:
        refused = exc
    assert H.census_diff(before, H.tree_census(root)) == [], "the guard wrote into the root"
    if foreign is None:
        assert refused is None, (
            f"the one-tenant guard refused the operator-placed knowledge in a rowless own "
            f"folder (MF1 (a) admits exactly that name): {refused}")
    else:
        assert refused is not None, f"the guard admitted {foreign!r} beside the placed knowledge"
        text = str(refused)
        assert foreign in text, f"the guard's refusal does not name {foreign!r}: {text}"
        assert f"{H.TID}/knowledge" not in text, (
            f"the guard named the placed knowledge as foreign: {text}")


# ======================================================================================
# M8 under DC2: agent/.tenant-id is the only cross-tenant defence at setup.
# ======================================================================================

TENANT_ID_CELLS = [
    pytest.param(None, (), id="absent"),
    pytest.param(f"{H.OTHER}\n", (H.TID, H.OTHER), id="other-id"),
]


@pytest.mark.parametrize(("content", "also_named"), TENANT_ID_CELLS)
def test_1120_setup_refuses_a_placed_knowledge_folder_whose_tenant_id_is_absent_or_names_another_tenant(
        tmp_path: Path, content: str | None, also_named: tuple[str, ...]) -> None:
    """`setup acme` over an operator's clone exits 1 when agent/.tenant-id is absent, naming
    <root>/acme/knowledge/agent/.tenant-id, or names beta (the wrong tenant's repo was cloned —
    now the only cross-tenant defence at setup), naming the file, acme and beta. Either way
    setup writes nothing: no row, knowledge/ byte-identical, and `git status --porcelain` in
    the clone stays empty (setup never writes a .tenant-id into a clone). The positive
    control: the same repo committing .tenant-id = acme sets up with exit 0."""
    root = tmp_path / "data"
    knowledge = H.cloned_tenant(tmp_path / "bad", root, tenant_id_file=content)
    before = H.tree_census(root)
    proc = H.setup(tenant_py, root)
    H.assert_refused(proc, str(knowledge / H.TENANT_ID_FILE), *also_named)
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"
    assert not H.row_path(root).exists(), "a refused setup left a row (rules-first, MF1 Q2)"
    assert H.git_status(knowledge) == "", "setup wrote into the operator's clone"

    control = tmp_path / "control"
    H.cloned_tenant(tmp_path / "good", control)
    H.assert_clean(H.setup(tenant_py, control))
    _row_is_acme(control)


# ======================================================================================
# Re-runs (DC1, M2 dissolved): the folder rules always run; a clean re-run is silent.
# ======================================================================================

def test_1120_setup_over_a_finished_tenant_succeeds_and_writes_nothing(tmp_path: Path) -> None:
    """After a successful adopt (a finished tenant: its row plus the placed knowledge/), a
    second `setup acme` runs the folder rules, exits 0 with no output, and the whole data-root
    census is byte- and mtime-identical — it also carries pass-A's o10_rerun_no_second_row.
    DC1 cell: the same re-run after the tenant's verb-grants.yaml drops a declared verb still
    exits 0 silently and writes nothing, because a grant gap is never setup's finding, while
    `tenant.py check acme` exits 1 naming change-mgmt.get-change."""
    # rejected: re-cloning, re-copying or overwriting an existing knowledge/ (and, per N6,
    # pulling).
    root = tmp_path / "data"
    H.adopted(root)
    before = H.tree_census(root)
    text = H.assert_clean(H.setup(tenant_py, root))
    assert text == "", f"a clean re-run printed something:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == [], "a clean re-run wrote something"

    _gap_table(H.settings_dir(root))
    gapped = H.tree_census(root)
    text = H.assert_clean(H.setup(tenant_py, root))
    assert text == "", f"a re-run over a gapped table printed something (DC1):\n{text}"
    assert H.census_diff(gapped, H.tree_census(root)) == [], "the gapped re-run wrote something"
    H.assert_refused(H.check(tenant_py, root, H.TID), GAP_PAIR)


def _emptied(root: Path) -> str:
    knowledge = H.knowledge_dir(root)
    shutil.rmtree(knowledge)
    knowledge.mkdir()
    return str(knowledge)


def _dangling(root: Path) -> str:
    knowledge = H.knowledge_dir(root)
    shutil.rmtree(knowledge)
    knowledge.symlink_to(root.parent / "gone-knowledge", target_is_directory=True)
    return str(knowledge)


def _a_file(root: Path) -> str:
    knowledge = H.knowledge_dir(root)
    shutil.rmtree(knowledge)
    knowledge.write_text("knowledge used to be here\n", encoding="utf-8")
    return str(knowledge)


def _lost_settings(root: Path) -> str:
    settings = H.settings_dir(root)
    shutil.rmtree(settings)
    return str(settings)


REVERIFY_CELLS = [
    pytest.param(_emptied, id="empty"),
    pytest.param(_dangling, id="dangling-symlink"),
    pytest.param(_a_file, id="file"),
    pytest.param(_lost_settings, id="settings-absent"),
]


@pytest.mark.parametrize("damage", REVERIFY_CELLS)
def test_1120_setup_rerun_runs_the_folder_rules_and_names_a_knowledge_folder_that_no_longer_passes(
        tmp_path: Path, damage) -> None:
    """After a successful adopt, a re-run of `setup acme` runs the folder rules again —
    presence alone is not success — and exits 1 naming the offending path, writing nothing,
    when knowledge/ has since become empty, a dangling symlink, a regular file, or lost its
    settings/ half. A clean re-run is the positive control (exit 0). A grant gap is never
    setup's finding (DC1)."""
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(H.setup(tenant_py, root))
    named = damage(root)
    before = H.tree_census(root)
    H.assert_refused(H.setup(tenant_py, root), named)
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused re-run wrote something"


# ======================================================================================
# The one-tenant guard's outer scan, unchanged (N1): refused before any write.
# ======================================================================================

@pytest.mark.parametrize("with_row", [pytest.param(False, id="other-rowless"),
                                      pytest.param(True, id="other-with-row")])
def test_1120_setup_refuses_a_foreign_data_root_before_any_write_leaving_the_placed_knowledge_untouched(
        tmp_path: Path, with_row: bool) -> None:
    """`setup acme` over a data root holding beta/ (with or without a row) beside an
    operator-placed acme/knowledge exits 1 with the one-tenant guard's "the data root is not
    empty", naming beta; no row is written and acme/knowledge is byte-identical (the guard
    refuses after the operator's placement and never removes it). The positive control: the
    same root with beta/ removed adopts acme (exit 0) — so the refusal was beta's."""
    # rejected: a second tenant in one data root — the one-tenant guard is unchanged (N1,
    # decision 7); #1112 lifts it.
    root = tmp_path / "data"
    H.place_knowledge(root)
    if with_row:
        H.plant_row(root, H.OTHER)
    else:
        (root / H.OTHER).mkdir()
    before = H.tree_census(root)
    H.assert_refused(H.setup(tenant_py, root), "the data root is not empty", H.OTHER)
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"

    shutil.rmtree(root / H.OTHER)
    H.assert_clean(H.setup(tenant_py, root))
    _row_is_acme(root)


# ======================================================================================
# DC1 as REFINED by V1, V10 and V14 and STATED by V18 (human, §7-verify; overturning NF1): setup =
# run start's own readiness function (the grant table loads, gather holds a query verb, the
# lead-zero agreement — whatever would make a run refuse) + the folder rules (links and special
# files, .tenant-id presence + match, the top-level allow-list, the settings files parse —
# mapping.yaml included); the census is check's. (Was, before V1: "setup = acceptance + the
# settings tables load".)
# ======================================================================================

def test_1120_setup_refuses_a_placed_folder_that_fails_acceptance_and_leaves_grant_gaps_to_check(
        tmp_path: Path) -> None:
    """Setup runs the folder rules (V18: accept_tenant's checks plus the settings files'
    parse, mapping.yaml included) plus run start's own readiness function (V14: the grant table
    loads, gather holds a query verb, the lead-zero agreement — its cells pinned in
    test_1120_check.py), never the grant census (DC1: a gap does not stop runs, A1).
    An adopted knowledge/ lacking
    settings/lead-zero.yaml makes `setup acme` exit 1 naming that path and write nothing
    (knowledge/ byte-identical, no row — rules-first); so does a verb-grants.yaml that does
    not parse, naming it. DC1 FLIPS the gap: a verb-grants.yaml omitting a declared verb makes
    setup exit 0 with the row written, while `tenant.py check acme` exits 1 naming
    change-mgmt.get-change."""
    missing = tmp_path / "missing"
    H.place_knowledge(missing)
    lead_zero = H.settings_dir(missing) / "lead-zero.yaml"
    lead_zero.unlink()
    before = H.tree_census(missing)
    H.assert_refused(H.setup(tenant_py, missing), str(lead_zero))
    assert H.census_diff(before, H.tree_census(missing)) == [], "the refused setup wrote something"

    torn = tmp_path / "torn"
    H.place_knowledge(torn)
    table = H.settings_dir(torn) / "verb-grants.yaml"
    table.write_text("dispositions:\n  cmdb: [unclosed\n", encoding="utf-8")
    before = H.tree_census(torn)
    H.assert_refused(H.setup(tenant_py, torn), str(table))
    assert H.census_diff(before, H.tree_census(torn)) == [], "the refused setup wrote something"

    gapped = tmp_path / "gapped"
    H.place_knowledge(gapped)
    _gap_table(H.settings_dir(gapped))
    H.assert_clean(H.setup(tenant_py, gapped))
    _row_is_acme(gapped)
    H.assert_refused(H.check(tenant_py, gapped, H.TID), GAP_PAIR)


# ======================================================================================
# V5 (92 #3; MF1 Q2 rules-first, NF6): a FIRST, row-less setup applies every folder rule
# acceptance applies — the guard admits the NAME knowledge, acceptance judges what it is.
# ======================================================================================

def _outside_file(tmp: Path) -> Path:
    target = tmp / "elsewhere" / "not-this-tenants.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("not this tenant's bytes\n", encoding="utf-8")
    return target


def _first_knowledge_symlink(root: Path, tmp: Path) -> Path:
    """The operator cloned elsewhere and symlinked the clone in (47 P3): the target is a
    complete, valid knowledge folder, so only the link itself can be the refusal."""
    real = H.place_knowledge(tmp / "clone-elsewhere")
    link = H.knowledge_dir(root)
    link.parent.mkdir(parents=True)
    link.symlink_to(real, target_is_directory=True)
    return link


def _first_knowledge_file(root: Path, tmp: Path) -> Path:
    path = H.knowledge_dir(root)
    path.parent.mkdir(parents=True)
    path.write_text("knowledge is not a folder\n", encoding="utf-8")
    return path


def _first_symlink_in_settings(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    link = H.settings_dir(root) / "planted-link.yaml"
    link.symlink_to(_outside_file(tmp))
    return link


def _first_hardlink_in_agent(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    inside = H.agent_dir(root) / "planted-hardlink.md"
    inside.write_text("shared bytes\n", encoding="utf-8")
    second = tmp / "elsewhere" / "second-name.md"
    second.parent.mkdir(parents=True, exist_ok=True)
    os.link(inside, second)
    return inside


def _first_fifo_in_settings(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    fifo = H.settings_dir(root) / "planted.fifo"
    os.mkfifo(fifo)
    return fifo


def _first_unparseable_lead_zero(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    path = H.settings_dir(root) / "lead-zero.yaml"
    path.write_text("correlation_template: [unclosed\n", encoding="utf-8")
    return path


def _first_unparseable_mapping(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    path = H.settings_dir(root) / "systems" / "case-history" / "mapping.yaml"
    path.write_text("fields: {unclosed: [\n", encoding="utf-8")
    return path


FIRST_RUN_FAULTS = [
    pytest.param(_first_knowledge_symlink, id="knowledge_dir:symlink"),
    pytest.param(_first_knowledge_file, id="knowledge_dir:file"),
    pytest.param(_first_symlink_in_settings, id="settings_half:symlink-inside"),
    pytest.param(_first_hardlink_in_agent, id="agent_half:hardlink-inside"),
    pytest.param(_first_fifo_in_settings, id="settings_half:non-regular-entry:fifo"),
    pytest.param(_first_unparseable_lead_zero, id="tables-load:lead-zero.yaml"),
    pytest.param(_first_unparseable_mapping, id="tables-load:mapping.yaml"),
]


@pytest.mark.parametrize("plant", FIRST_RUN_FAULTS)
def test_1120_a_first_setup_applies_every_folder_rule_before_it_writes_the_row(
        tmp_path: Path, plant) -> None:
    """Over a data root holding only an operator-placed acme/knowledge and no row, `tenant.py
    setup acme` exits 1 naming the offending path, writes no row and leaves the data-root
    census unchanged, when knowledge/ is a symlink (to an otherwise valid folder) or a regular
    file, when settings/ holds a symlink, when agent/ holds a hard link, when settings/ holds a
    FIFO (refused without being opened — setup does not block on it), and when lead-zero.yaml
    or systems/case-history/mapping.yaml does not parse. The refusal is acceptance's (or the
    settings-files-parse folder rule's — V18 keeps it: run start's readiness function never reads
    mapping.yaml), never the one-tenant guard's: MF1 admits the NAME knowledge in a
    row-less own folder (NF6), so "a refused setup writes nothing" and "setup never produces a
    tenant accept_tenant refuses" hold on the first run as on a re-run (MF1 Q2, N7). The
    positive control: the fixture placed as-is sets up with exit 0 and writes the row."""
    root = tmp_path / "data"
    named = plant(root, tmp_path)
    assert not H.row_path(root).exists(), "precondition: this is a first, row-less setup"
    before = H.tree_census(root)
    try:
        proc = H.setup(tenant_py, root)
    except subprocess.TimeoutExpired:
        pytest.fail(f"setup blocked on {named} instead of refusing it (a FIFO opened for reading)")
    text = H.assert_refused(proc, str(named))
    assert "the data root is not empty" not in text, (
        f"the refusal is the one-tenant guard's; it must admit the placed knowledge (MF1) and "
        f"the folder rule must refuse {named}:\n{text}")
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused first setup wrote"
    assert not H.row_path(root).exists(), "a refused first setup left a row (MF1 Q2)"

    control = tmp_path / "control"
    H.place_knowledge(control)
    H.assert_clean(H.setup(tenant_py, control))
    _row_is_acme(control)


# ======================================================================================
# The guarded lane: the row is setup's ONLY write, and setup makes no tree operation.
# ======================================================================================

#: Run a script under a Python audit hook that records every tree operation and every
#: process spawn it makes (PEP 578 events) — the observation of what setup DOES, not only of
#: its net effect: a copy made and then removed, or a staged folder renamed into place,
#: leaves the same final census as no copy at all.
_AUDIT_RUNNER = '''\
import json, os, runpy, sys
_fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
_WATCH = ("os.rename", "os.link", "os.symlink", "os.remove", "os.rmdir", "os.system",
          "subprocess.Popen", "os.posix_spawn", "os.exec", "os.spawn", "os.fork")
def _hook(event, args):
    if event in _WATCH or event.startswith("shutil."):
        os.write(_fd, (json.dumps([event, [repr(a) for a in args]]) + "\\n").encode())
sys.addaudithook(_hook)
_script = sys.argv[2]
sys.argv = [_script, *sys.argv[3:]]
runpy.run_path(_script, run_name="__main__")
'''


def _audited_setup(tmp: Path, root: Path) -> tuple[object, list[list]]:
    runner = tmp / "audit_runner.py"
    runner.write_text(_AUDIT_RUNNER, encoding="utf-8")
    log = tmp / "audit.jsonl"
    proc = H.run_script(runner, str(log), str(H.script_of(tenant_py)), "setup", H.TID,
                        root=root, PYTHONDONTWRITEBYTECODE="1")
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] \
        if log.exists() else []
    return proc, events


def _placed_plain_folder(tmp: Path, root: Path) -> None:
    H.place_knowledge(root)


def _placed_clone_with_uncommitted_tenant_id(tmp: Path, root: Path) -> None:
    """A clone whose .tenant-id matches but is untracked: a setup that asked git anything
    would either spawn it (seen by the hook) or refuse (V11 moves that rule to check)."""
    H.clone_with_uncommitted_tenant_id(tmp / "src", root, "untracked")


@pytest.mark.parametrize("place", [
    pytest.param(_placed_plain_folder, id="plain-folder"),
    pytest.param(_placed_clone_with_uncommitted_tenant_id, id="clone-uncommitted-tenant-id"),
])
def test_1120_setup_adopts_by_writing_only_the_row_through_the_guarded_lane(
        tmp_path: Path, place) -> None:
    """The census diff after a first adopt is exactly +acme/tenant.json; no file under
    knowledge/ changes its bytes, mtime or mode. setup performs no copy, rename, tree removal,
    symlink or git call — no subprocess at all — observed by an audit hook on the setup
    process itself, so a staged copy renamed into place cannot hide behind a clean final
    census. That holds over a plain folder and over a git clone whose agent/.tenant-id is
    untracked (DC2's "no git calls"; V11: the committed-.tenant-id rule is check's, so setup
    exits 0 there). Its one write is the row, through create_tenant's guarded lane
    (write_guarded in create mode: an unnamed file linked to the row's name, or one exclusive
    open), which also carries pass-A's o10_fresh_root_writes_exactly_row."""
    root = tmp_path / "data"
    place(tmp_path, root)
    before = H.tree_census(root)
    knowledge_before = _knowledge_census(root)
    proc, events = _audited_setup(tmp_path, root)
    H.assert_clean(proc)
    assert H.census_diff(before, H.tree_census(root)) == [f"added: {H.TID}/{H.ROW_NAME}"]
    assert H.census_diff(knowledge_before, _knowledge_census(root)) == []
    tree_ops = [e for e in events if e[0] != "os.link"]
    assert tree_ops == [], (
        "setup made a tree operation or spawned a process (DC2: no copy, rename, rmtree or "
        f"git call):\n{json.dumps(tree_ops, indent=1)}")
    # The create lane links an unnamed file to the row's NAME (relative to the tenant
    # folder's fd): each link's destination argument must name the row.
    links = [e for e in events if e[0] == "os.link"]
    assert all(H.ROW_NAME in e[1][1] for e in links), (
        f"setup linked something other than the row: {links}")


# ======================================================================================
# N1's residual: two first setups racing one placed knowledge/.
# ======================================================================================

def test_1120_two_concurrent_first_setups_leave_one_row_and_one_refusal_naming_it(
        tmp_path: Path) -> None:
    """Two concurrent first `setup acme` runs over one operator-placed knowledge/ leave exactly
    one tenant.json, valid and naming acme, and knowledge/ byte-identical. Every run exits 0
    or 1, at least one exits 0, and a run that exits 1 names the row ("already exists",
    create_tenant's create-exclusive write). No lock is taken. Which of the two outcomes the
    loser takes is not pinned: rules-first, a loser that sees the winner's row takes the
    silent re-run path (exit 0), one that races the create is refused naming the row."""
    # rejected: a foreign tenant created mid-setup (N1).
    root = tmp_path / "data"
    H.place_knowledge(root)
    knowledge_before = _knowledge_census(root)
    argv = [sys.executable, str(H.script_of(tenant_py)), "setup", H.TID]
    env = H.tenant_env(root)
    procs = [subprocess.Popen(argv, env=env, cwd=str(H.REPO_ROOT), stdout=subprocess.PIPE,  # noqa: S603
                              stderr=subprocess.STDOUT, text=True) for _ in range(2)]
    results = [(p.wait(timeout=180), p.stdout.read() if p.stdout else "") for p in procs]
    for p in procs:
        if p.stdout:
            p.stdout.close()
    for rc, text in results:
        assert "Traceback (most recent call last)" not in text, f"a setup crashed:\n{text}"
        assert rc in (0, 1), f"a racing setup exited {rc}:\n{text}"
        if rc == 1:
            assert str(H.row_path(root)) in text, (
                f"the racing loser's refusal does not name the row:\n{text}")
            assert "already exists" in text, f"the loser's refusal is not the create race:\n{text}"
    assert any(rc == 0 for rc, _ in results), f"neither racing setup succeeded: {results}"
    _row_is_acme(root)
    assert H.census_diff(knowledge_before, _knowledge_census(root)) == []


# ======================================================================================
# N12 (pulled up, dissolved by DC2): a pass-A tenant meeting piece 1.
# ======================================================================================

def _pass_a_tenant(root: Path) -> None:
    """A pass-A tenant: its row and a runs base with records, and no knowledge/."""
    H.plant_row(root)
    runs = H.tenant_folder(root) / "runs"
    (runs / "r1").mkdir(parents=True)
    (runs / "_tenant.json").write_text(json.dumps({
        "tenant_id": H.TID, "base_world_id": "0" * 32,
        "created_at": "2026-09-26T00:00:00+00:00"}) + "\n", encoding="utf-8")
    (runs / "r1" / "report.md").write_text("disposition: benign\n", encoding="utf-8")


def _row_and_runs(root: Path) -> dict:
    census = H.tree_census(root)
    return {k: v for k, v in census.items()
            if k == f"{H.TID}/{H.ROW_NAME}" or k.startswith(f"{H.TID}/runs")}


def test_1120_setup_over_a_pass_a_tenant_names_the_missing_knowledge_then_adopts_a_placed_clone_leaving_runs_byte_identical(
        tmp_path: Path) -> None:
    """A pass-A tenant — a row plus runs/ with records, and no knowledge/. `setup acme` exits
    1 naming <root>/acme/knowledge and the remedy (clone the tenant repo into it, then run
    tenant.py setup acme again); the row and runs/ are byte-identical. After the operator
    places a clone, `setup acme` exits 0 with the row and runs/ still byte-identical (the
    row-then-clone order a1c65801's guard already admits, P-DC2-1 leg B)."""
    root = tmp_path / "data"
    _pass_a_tenant(root)
    before = H.tree_census(root)
    text = H.assert_refused(H.setup(tenant_py, root), str(H.knowledge_dir(root)))
    for word in REMEDY_WORDS:
        assert word in text, f"the refusal does not carry the remedy word {word!r}:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"

    kept = _row_and_runs(root)
    H.cloned_tenant(tmp_path, root)
    H.assert_clean(H.setup(tenant_py, root))
    assert _row_and_runs(root) == kept, "adopting the clone changed the row or runs/"


# ======================================================================================
# O11a survives TenantPaths' absorption (M4: the private layout class keeps it).
# ======================================================================================

def test_1120_a_data_root_inside_the_checkouts_defender_tree_is_still_refused(
        tmp_path: Path) -> None:
    """`tenant.py setup acme` (no --from) with DEFENDER_DATA_ROOT inside the RUNNING checkout's
    defender/ tree and an adopted acme/knowledge placed there exits 1 through `[tenant.py]`,
    naming the defender/ tree; no row is written and knowledge/ is byte-identical — the guard
    refuses AFTER the operator's placement and never removes it. The refusal is O11a's (or
    acceptance's containment step), never the one-tenant guard's, which admits the placed
    knowledge. The positive control: <checkout>/.defender-data, outside defender/, with an
    adopted knowledge/ exits 0 (pass-A o11a_positive_control, re-bound). The running checkout
    here is a tmp COPY of this one, so the real worktree is never written into."""
    checkout = H.tmp_checkout(tmp_path / "checkout")
    script = checkout / H.script_of(tenant_py).relative_to(H.REPO_ROOT)
    root = checkout / "defender" / "tenant-data"
    H.place_knowledge(root)
    before = H.tree_census(root)
    text = H.assert_refused(H.run_script(script, "setup", H.TID, root=root),
                            "[tenant.py]", str(checkout / "defender"))
    assert "not empty" not in text, (
        f"the refusal is the one-tenant guard's, not O11a's — the guard must admit the placed "
        f"knowledge (MF1 (a)):\n{text}")
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"

    allowed = checkout / ".defender-data"
    H.place_knowledge(allowed)
    H.assert_clean(H.run_script(script, "setup", H.TID, root=allowed))
    _row_is_acme(allowed)


# ======================================================================================
# Settled premises (45), rewritten under DC2 where 47 says so.
# ======================================================================================

def test_1120_s1_git_executable_absent_for_setup(tmp_path: Path) -> None:
    """INVERTED by DC2 (N9 dissolved): with no git on PATH (the runtime image, or a host
    without git), `setup acme` over an operator-placed knowledge/ exits 0 and writes the row,
    because setup makes no git subprocess call (was: exit 1 naming the git failure)."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    bare_path = tmp_path / "bin-without-git"
    bare_path.mkdir()
    probe = subprocess.run(  # noqa: S603 — the test's own interpreter
        [sys.executable, "-c", "import shutil, sys; sys.exit(shutil.which('git') is not None)"],
        env=H.tenant_env(root, PATH=str(bare_path)), capture_output=True, text=True, check=False)
    assert probe.returncode == 0, "precondition: git is still reachable on the reduced PATH"
    H.assert_clean(H.setup(tenant_py, root, PATH=str(bare_path)))
    _row_is_acme(root)


@pytest.mark.skipif(os.geteuid() == 0, reason="uid 0 bypasses mode bits; CI runs non-root")
def test_1120_s2_data_root_parent_not_writable(tmp_path: Path) -> None:
    """The clone has already created <root>/acme/, so setup's first write is the row into it.
    When that folder is not writable by setup's user (mode 0555), setup exits 1 naming
    <root>/acme/tenant.json and the permission error; knowledge/ is untouched and no row
    exists. Exercised with a real mode fault; skipped as root, which bypasses mode bits."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    before = _knowledge_census(root)
    folder = H.tenant_folder(root)
    folder.chmod(0o555)
    try:
        text = H.assert_refused(H.setup(tenant_py, root), str(H.row_path(root)))
        assert "ermission" in text, f"the refusal does not name the permission error:\n{text}"
    finally:
        folder.chmod(0o755)
    assert not H.row_path(root).exists()
    assert H.census_diff(before, _knowledge_census(root)) == []


def test_1120_s12_setup_resumes_row_only_no_partial_no_knowledge(tmp_path: Path) -> None:
    """A row-only tenant (acme/tenant.json and nothing else under acme/: an earlier setup
    wrote the row and no knowledge was ever placed). `setup acme` exits 1 naming
    <root>/acme/knowledge and the remedy, the row byte-identical. Once the operator places a
    clone, `setup acme` exits 0 with the row byte-identical and no second row (the row-then-
    clone order today's guard admits, P-DC2-1 leg B; also carries pass-A
    o10_rerun_no_second_row)."""
    root = tmp_path / "data"
    H.plant_row(root)
    before = H.tree_census(root)
    text = H.assert_refused(H.setup(tenant_py, root), str(H.knowledge_dir(root)))
    for word in REMEDY_WORDS:
        assert word in text, f"the refusal does not carry the remedy word {word!r}:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == []

    row_before = H.row_path(root).read_bytes()
    H.cloned_tenant(tmp_path, root)
    H.assert_clean(H.setup(tenant_py, root))
    assert H.row_path(root).read_bytes() == row_before, "the adopt re-created the row"
    _row_is_acme(root)


def _lost_and_found(root: Path) -> str:
    (root / "lost+found").mkdir()
    return "lost+found"


def _nfs_silly_rename(root: Path) -> str:
    (root / ".nfs000000000000abcd00000001").write_bytes(b"\0")
    return ".nfs000000000000abcd00000001"


def _orphan_partial(root: Path) -> str:
    (root / ".knowledge.partial" / "settings").mkdir(parents=True)
    return ".knowledge.partial"


DEBRIS = [
    pytest.param(_lost_and_found, id="lost+found"),
    pytest.param(_nfs_silly_rename, id="nfs-silly-rename"),
    pytest.param(_orphan_partial, id="orphan-knowledge-partial"),
]


@pytest.mark.parametrize("plant", DEBRIS)
def test_1120_s12_refuse_foreign_data_root_meets_filesystem_debris(tmp_path: Path, plant) -> None:
    """The one-tenant guard's outer scan is unchanged (N1): any top-level entry other than the
    id's own folder — an ext-style lost+found/, an NFS silly-rename .nfs* file, a
    .knowledge.partial orphaned by a deleted tenant — beside an operator-placed acme/knowledge
    makes `setup acme` refuse, naming the entry, before any write. The positive control: with
    the debris removed the same root adopts acme (exit 0)."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    entry = plant(root)
    before = H.tree_census(root)
    H.assert_refused(H.setup(tenant_py, root), entry)
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"

    target = root / entry
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    H.assert_clean(H.setup(tenant_py, root))
    _row_is_acme(root)


# ======================================================================================
# D9 / H2: THE helper a test uses to get a tenant — the fixture adopted into a tmp root.
# ======================================================================================

def test_1120_a_tmp_data_root_set_up_from_the_fixture_carries_the_lab_grant(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The helper that replaces the checkout default root copies knowledge/tenant-fixture into
    <tmp root>/<id>/knowledge, writes agent/.tenant-id = <id> plus a newline into the COPY (the
    fixture commits none, M8), and runs `tenant.py setup <id>` (exit 0). run.main with
    --tenant <id> against that data root then resolves a RunTenant whose gather grant equals
    GATHER_CENSUS and whose correlation template is elastic.correlate-alerts-by-entity, read
    from the data root's copy. The copy shares no inode with the fixture, and mutating it
    never changes the fixture (M9 item 4). One helper serves this and the pass-A re-plumb."""
    root = tmp_path / "data"
    fixture_before = H.tree_census(H.FIXTURE)
    H.adopt_fixture(tenant_py, root)
    knowledge = H.knowledge_dir(root)
    assert (knowledge / H.TENANT_ID_FILE).read_bytes() == f"{H.TID}\n".encode()
    fixture_inodes = {(p.lstat().st_dev, p.lstat().st_ino)
                      for p in H.FIXTURE.rglob("*") if p.is_file()}
    copy_inodes = {(p.lstat().st_dev, p.lstat().st_ino)
                   for p in knowledge.rglob("*") if p.is_file()}
    assert not fixture_inodes & copy_inodes, "the tenant's copy shares an inode with the fixture"

    monkeypatch.setenv(H.DATA_ROOT_ENV, str(root))
    rec = H.RunRecorder(tmp_path / "run")
    rc, exc = H.drive_run(run_py, [str(H.plant_alert(tmp_path / "in")), "--tenant", H.TID], rec)
    assert exc is None, f"run.main refused the adopted fixture: {H.exit_text(exc)}"
    assert rc == 0
    run_tenant = rec.lifecycle_calls[0]["tenant"]
    assert Path(run_tenant.settings).resolve() == H.settings_dir(root).resolve()
    assert {(s, v) for s, v, *_ in run_tenant.grants.gather.entries} == set(D995.GATHER_CENSUS)
    assert run_tenant.correlation is not None
    assert run_tenant.correlation.template_id == H.FIXTURE_CORRELATION_TEMPLATE

    (H.settings_dir(root) / "verb-grants.yaml").write_text("mutated\n", encoding="utf-8")
    assert H.tree_census(H.FIXTURE) == fixture_before, "mutating the copy changed the fixture"
