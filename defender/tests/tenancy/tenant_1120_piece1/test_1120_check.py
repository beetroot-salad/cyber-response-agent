"""D7/O8 `tenant.py check <id> | --folder <path>`: the tenant's own checks."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender.tenancy import _tenant
from defender.runtime import verb_dispositions
from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

#: A system only a tmp checkout declares, and the one verb its adapter declares (A3).
EXTRA_SYSTEM = "extra"
EXTRA_PAIR = "extra.verb"
EXTRA_ADAPTER = 'VERBS = {"verb": None}\n'

BROKEN_SYSTEM = H.BROKEN_SYSTEM
BROKEN_ADAPTER = H.BROKEN_ADAPTER

#: The retired learning-state knob; #1186 commands must ignore it even when overlapping.
OVERLAP_ENV = H.LEARNING_STATE_ENV

#: #1159: what `check` says when the census cannot be taken — the folder's table went unjudged
CENSUS_NOT_TAKEN = "was not checked against the running checkout's adapters"

#: The census's own causes (#1159 O1), each naming the side that failed: this machine's git,
GIT_ABSENT_CAUSE = "git is not available on PATH on this machine"
GIT_UNRUNNABLE_CAUSE = "git cannot be run on this machine"
ADAPTER_CAUSE = "have an adapter the cold verb reader saw no verb in"


def _copy_script(checkout: Path) -> Path:
    """The tmp checkout's OWN `tenant.py` — the copy of the file `tenant_py` runs from."""
    return checkout / H.script_of(tenant_py).resolve().relative_to(H.REPO_ROOT)


def _folder(tmp_path: Path, name: str, *, source: Path = H.FIXTURE,
            tenant_id_file: str | bytes | None = None) -> Path:
    """A tenant repo's working folder (`settings/` + `agent/`), copied from `source` — what
    `check --folder` is pointed at in tenant CI. No `.tenant-id` unless asked (M8)."""
    folder = tmp_path / name
    shutil.copytree(source, folder, symlinks=True)
    H.write_tenant_id_file(folder, H.TID, tenant_id_file)
    return folder


def _table(settings: Path) -> dict[str, Any]:
    doc = yaml.safe_load((settings / "verb-grants.yaml").read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{settings} holds no verb-grants mapping"
    assert isinstance(doc.get("dispositions"), dict), f"{settings}'s table has no dispositions"
    return doc


def _write_table(settings: Path, doc: dict[str, Any]) -> None:
    (settings / "verb-grants.yaml").write_text(
        yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _check_id(root: Path, *extra: str, **kw: Any):
    """`tenant.py check acme` against `root`."""
    return H.check(tenant_py, root, H.TID, *extra, **kw)


def _check_folder(folder: Path, **kw: Any):
    """`tenant.py check --folder <folder>` with `DEFENDER_DATA_ROOT` unset."""
    return H.check(tenant_py, None, "--folder", str(folder), **kw)


def _unparseable_mapping(folder: Path) -> Path:
    """Break `folder`'s case-history mapping.yaml so it does not parse — a finding about the
    folder that needs no census. Returns the file."""
    mapping = folder / "settings" / "systems" / "case-history" / "mapping.yaml"
    mapping.write_text("fields: {unclosed: [\n", encoding="utf-8")
    return mapping


def _census_blind_line(proc: subprocess.CompletedProcess, *, folder: Path, cause: str,
                       names: tuple[str, ...] = (), also: tuple[str, ...] = ()) -> tuple[str, str]:
    """#1159: `proc` is a `check` over `folder` whose census could not be taken."""
    text = H.assert_refused(proc, CENSUS_NOT_TAKEN, *also)
    lines = [ln for ln in text.splitlines() if CENSUS_NOT_TAKEN in ln]
    assert len(lines) == 1, f"the census line is not printed exactly once:\n{text}"
    line = lines[0]
    table = verb_dispositions.dispositions_path(folder / "settings")
    assert str(table) in line or str(table.resolve()) in line, (
        f"the census line does not name the table it left unchecked, {table}:\n{line}")
    framing = line.index(CENSUS_NOT_TAKEN)
    for said in (cause, *names):
        assert said in line[framing:], (
            f"the census line does not give {said!r} after its framing (#1159 O1):\n{line}")
    return text, line


@pytest.fixture(scope="module")
def extra_checkout(tmp_path_factory) -> Path:
    """A copy of this checkout whose adapters declare one more system, `extra` (read-only
    once built; shared by the tests about which tree the census is taken from)."""
    checkout = H.tmp_checkout(tmp_path_factory.mktemp("extra") / "checkout")
    H.add_adapter(checkout, EXTRA_SYSTEM, EXTRA_ADAPTER)
    return checkout


def test_1120_check_exits_zero_over_a_clean_tenant_and_a_clean_folder(tmp_path: Path) -> None:
    """`tenant.py check acme` over a finished tenant built from the fixture under a tmp data root exits 0."""
    root = tmp_path / "data"
    H.adopted(root)
    before = H.tree_census(root)
    H.assert_clean(_check_id(root))
    assert H.census_diff(before, H.tree_census(root)) == [], "check wrote into the data root"

    for folder in (H.FIXTURE, H.TEMPLATE):
        assert not (folder / H.TENANT_ID_FILE).exists(), f"{folder} commits a .tenant-id (M8)"
        committed = H.tree_census(folder)
        H.assert_clean(_check_folder(folder))
        assert H.census_diff(committed, H.tree_census(folder)) == [], f"check wrote into {folder}"


def _missing_required_setting(knowledge: Path) -> str:
    target = knowledge / "settings" / "systems" / "case-history" / "mapping.yaml"
    target.unlink()
    return str(target)


def _symlink_in_settings(knowledge: Path) -> str:
    link = knowledge / "settings" / "planted-grants-link.yaml"
    link.symlink_to(knowledge / "settings" / "verb-grants.yaml")
    return "planted-grants-link.yaml"


def _mismatched_tenant_id(knowledge: Path) -> str:
    H.write_tenant_id_file(knowledge, H.TID, f"{H.OTHER}\n")
    return ".tenant-id"


ACCEPTANCE_FAILURES = [
    pytest.param(_missing_required_setting, id="REQUIRED_SETTINGS-missing"),
    pytest.param(_symlink_in_settings, id="settings-symlink-inside"),
    pytest.param(_mismatched_tenant_id, id="tenant_id_file-other-id"),
]


@pytest.mark.parametrize("plant", ACCEPTANCE_FAILURES)
def test_1120_check_refuses_a_tenant_that_fails_acceptance_naming_the_file(
        tmp_path: Path, plant) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(_check_id(root))
    named = plant(H.knowledge_dir(root))
    before = H.tree_census(root)
    text = H.assert_refused(_check_id(root), named)
    assert "[tenant.py]" in text, f"the refusal is not tenant.py's own surface:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == [], "check wrote into the data root"
    H.assert_verbatim(text, H.accept_refusal(_tenant, root, H.TID), entry="tenant.py check")


def test_1120_check_refuses_every_grant_gap_in_both_directions_naming_each(
        tmp_path: Path) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(_check_id(root))
    settings = H.settings_dir(root)
    doc = _table(settings)
    rows = doc["dispositions"]
    del rows["change-mgmt"]["get-change"]
    del rows["threat-intel"]["list-indicators"]
    rows["cmdb"]["no-such-verb"] = {"roles": ["gather"]}
    rows["no-such-system"] = {"health-check": {"roles": ["gather"]}}
    _write_table(settings, doc)
    H.assert_refused(_check_id(root), "change-mgmt.get-change", "threat-intel.list-indicators",
                     "cmdb.no-such-verb", "no-such-system")


def test_1120_check_exits_non_zero_naming_an_adapter_module_that_fails_to_import(
        tmp_path: Path) -> None:
    checkout = H.tmp_checkout(tmp_path / "checkout")
    folder = _folder(tmp_path, "tenant")
    script = _copy_script(checkout)
    H.assert_clean(H.run_script(script, "check", "--folder", str(folder), root=None))
    H.add_adapter(checkout, BROKEN_SYSTEM, BROKEN_ADAPTER)
    blind = {"folder": folder, "cause": ADAPTER_CAUSE,
             "names": (BROKEN_SYSTEM, str(checkout.resolve()))}
    _census_blind_line(H.run_script(script, "check", "--folder", str(folder), root=None), **blind)
    _unparseable_mapping(folder)
    # A mapping that does not parse is refused by the one tenant check (#1222 A5) in acceptance,
    # before any census: a fixed reason naming the file, no host path.
    H.assert_refused(H.run_script(script, "check", "--folder", str(folder), root=None),
                     "systems/case-history/mapping.yaml")


def test_1120_s6_defender_dir_env_names_another_tree(
        tmp_path: Path, extra_checkout: Path) -> None:
    copy_defender = extra_checkout / "defender"
    root = copy_defender / f"data-{tmp_path.name}"
    H.adopted(root)
    text = H.assert_clean(_check_id(root, DEFENDER_DIR=str(copy_defender)))
    assert EXTRA_PAIR not in text, f"check took its census from DEFENDER_DIR:\n{text}"

    script = _copy_script(extra_checkout)
    H.assert_refused(H.run_script(script, "check", H.TID, root=root), str(copy_defender))
    H.assert_refused(
        H.run_script(script, "check", "--folder", str(_folder(tmp_path, "tenant")), root=None),
        EXTRA_PAIR)


def _no_agent_half(folder: Path) -> str:
    shutil.rmtree(folder / "agent")
    return str(folder / "agent")


def _no_required_setting(folder: Path) -> str:
    (folder / "settings" / "lead-zero.yaml").unlink()
    return str(folder / "settings" / "lead-zero.yaml")


def _link_in_settings(folder: Path) -> str:
    (folder / "settings" / "planted-settings-link").symlink_to(folder / "settings" / "systems")
    return "planted-settings-link"


def _link_in_agent(folder: Path) -> str:
    (folder / "agent" / "planted-agent-link").symlink_to(folder / "settings" / "lead-zero.yaml")
    return "planted-agent-link"


def _off_grammar_tenant_id(folder: Path) -> str:
    H.write_tenant_id_file(folder, H.TID, "Not An Id\n")
    return ".tenant-id"


def _grant_gap(folder: Path) -> str:
    doc = _table(folder / "settings")
    del doc["dispositions"]["host-state"]["passwd"]
    _write_table(folder / "settings", doc)
    return "host-state.passwd"


def _write_lead_zero(settings: Path, template: str) -> None:
    (settings / "lead-zero.yaml").write_text(f"correlation_template: {template}\n",
                                             encoding="utf-8")


#: A lead-zero template the running checkout's catalog lacks (92 #1 executed it through
ABSENT_TEMPLATE = "elastic.no-such-template"


def _lead_zero_disagreement(folder: Path) -> tuple[str, str]:
    _write_lead_zero(folder / "settings", ABSENT_TEMPLATE)
    return ("lead-zero.yaml", ABSENT_TEMPLATE)


FOLDER_FAULTS = [
    pytest.param(_no_agent_half, id="agent_half-absent"),
    pytest.param(_no_required_setting, id="REQUIRED_SETTINGS-missing"),
    pytest.param(_link_in_settings, id="settings_half-symlink-inside"),
    pytest.param(_link_in_agent, id="agent_half-symlink-inside"),
    pytest.param(_off_grammar_tenant_id, id="tenant_id_file-off-grammar"),
    pytest.param(_grant_gap, id="grant_census-undecided"),
    pytest.param(_lead_zero_disagreement, id="grant_census-lead-zero-disagreement"),
]


@pytest.mark.parametrize("plant", FOLDER_FAULTS)
def test_1120_check_folder_runs_every_rule_that_needs_no_data_root(
        tmp_path: Path, plant) -> None:
    folder = _folder(tmp_path, "tenant")
    H.assert_clean(_check_folder(folder))
    named = plant(folder)
    H.assert_refused(_check_folder(folder), *(named if isinstance(named, tuple) else (named,)))


def test_1120_s6_check_folder_reached_through_symlink_or_bind_mount(tmp_path: Path) -> None:
    checkout = H.tmp_checkout(tmp_path / "checkout")
    script = _copy_script(checkout)
    inside = checkout / "defender" / "tenant-under-review"
    shutil.copytree(H.FIXTURE, inside, symlinks=True)
    via_link = tmp_path / "review-link"
    via_link.symlink_to(inside, target_is_directory=True)
    H.assert_clean(H.run_script(script, "check", "--folder", str(via_link), root=None))

    root = tmp_path / "data"
    H.adopted(root)
    into_root = tmp_path / "root-link"
    into_root.symlink_to(H.knowledge_dir(root), target_is_directory=True)
    H.assert_clean(_check_folder(into_root))

    (inside / "settings" / "lead-zero.yaml").unlink()
    H.assert_refused(
        H.run_script(script, "check", "--folder", str(via_link), root=None), "lead-zero.yaml")


LEAD_ZERO_DISAGREEMENTS = [
    pytest.param(ABSENT_TEMPLATE, id="template-absent-from-catalog"),
    # `elastic.detection-alerts` binds `esql`; the table grants the lead `elastic.alerts`.
    pytest.param("elastic.detection-alerts", id="template-pair-disagrees"),
]


@pytest.mark.parametrize("template", LEAD_ZERO_DISAGREEMENTS)
def test_1120_setup_and_check_refuse_a_lead_zero_table_that_disagrees_with_the_running_catalog(
        tmp_path: Path, template: str) -> None:
    first = tmp_path / "first"
    knowledge = H.place_knowledge(first)
    _write_lead_zero(knowledge / "settings", template)
    before = H.tree_census(first)
    text = H.assert_refused(H.setup(tenant_py, first), "lead-zero.yaml", template)
    assert "the data root is not empty" not in text, (
        f"the refusal is the one-tenant guard's; it must admit the placed knowledge (MF1) and "
        f"the lead-zero agreement must refuse it:\n{text}")
    assert H.census_diff(before, H.tree_census(first)) == [], "the refused setup wrote something"
    assert not location_path(H.row_path)(first).exists(), "a refused first setup left a row (MF1 Q2)"

    rerun = tmp_path / "rerun"
    H.place_knowledge(rerun)
    H.assert_clean(H.setup(tenant_py, rerun))
    _write_lead_zero(H.settings_dir(rerun), template)
    before = H.tree_census(rerun)
    H.assert_refused(H.setup(tenant_py, rerun), "lead-zero.yaml", template)
    assert H.census_diff(before, H.tree_census(rerun)) == [], "the refused re-run wrote something"
    H.assert_refused(_check_id(rerun), "lead-zero.yaml", template)


def test_1120_s9_check_over_a_grant_table_repeats_a_top_level_key(tmp_path: Path) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(_check_id(root))
    table = H.settings_dir(root) / "verb-grants.yaml"
    table.write_text(table.read_text(encoding="utf-8")
                     + "\n  cmdb:\n    get-host: {roles: [gather]}\n", encoding="utf-8")
    H.assert_refused(_check_id(root), "verb-grants.yaml", "cmdb")


def test_1120_s9_check_over_a_grant_table_that_fails_to_parse_as_yaml(tmp_path: Path) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(_check_id(root))
    table = H.settings_dir(root) / "verb-grants.yaml"
    text = table.read_text(encoding="utf-8")
    table.write_text(text.replace("  cmdb:", "<<<<<<< HEAD\n  cmdb:", 1), encoding="utf-8")
    H.assert_refused(_check_id(root), "verb-grants.yaml")


def test_1120_s9_check_over_grant_table_verb_filed_under_wrong_real_system(
        tmp_path: Path) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(_check_id(root))
    settings = H.settings_dir(root)
    doc = _table(settings)
    rows = doc["dispositions"]
    rows["cmdb"]["list-authorized-hosts"] = rows["identity"].pop("list-authorized-hosts")
    _write_table(settings, doc)
    H.assert_refused(_check_id(root), "cmdb.list-authorized-hosts",
                     "identity.list-authorized-hosts")


def test_1186_tenant_commands_ignore_the_retired_learning_overlap(
        tmp_path: Path) -> None:
    git_identity = dict(H.GIT_IDENTITY)
    unset = tuple(k for k in os.environ if k.startswith("GIT_")) + (OVERLAP_ENV,)

    first = tmp_path / "scaffolded"
    first.mkdir()
    H.assert_clean(H.tenant_py(tenant_py, "scaffold", H.TID, str(first), root=None,
                               unset=unset, **git_identity))
    H.assert_clean(_check_folder(first, unset=unset))

    root = tmp_path / "data"
    H.adopted(root)
    overlap = {OVERLAP_ENV: str(root / "learning-state")}
    second = tmp_path / "scaffolded-under-overlap"
    second.mkdir()
    H.assert_clean(H.tenant_py(tenant_py, "scaffold", H.TID, str(second), root=root,
                               unset=unset, **git_identity, **overlap))
    H.assert_clean(H.check(tenant_py, root, "--folder", str(second), **overlap))

    before = H.tree_census(root)
    H.assert_clean(_check_id(root, **overlap))
    assert H.tree_census(root) == before, "check wrote into the tenant"
    H.assert_clean(H.setup(tenant_py, root, **overlap))
    assert H.census_diff(before, H.tree_census(root)) == [f"added: {H.TID}/learning"]
    assert list((H.tenant_folder(root) / "learning").iterdir()) == []
    initialized = H.tree_census(root)
    H.assert_clean(H.setup(tenant_py, root, **overlap))
    assert H.tree_census(root) == initialized, "setup rewrote initialized state"


def test_1120_check_with_both_or_neither_selector_is_a_usage_error(tmp_path: Path) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    folder = _folder(tmp_path, "tenant")
    H.assert_clean(_check_id(root))
    H.assert_clean(_check_folder(folder))
    before = H.tree_census(root)
    for argv in ((H.TID, "--folder", str(folder)), ()):
        proc = H.check(tenant_py, root, *argv)
        H.assert_ran(proc)
        assert proc.returncode == 2, (
            f"`check {' '.join(argv)}` exited {proc.returncode}, not 2 (usage):\n{H.output(proc)}")
    assert H.census_diff(before, H.tree_census(root)) == [], "a usage error wrote"


def _withhold_all(settings: Path) -> None:
    """The table as the TEMPLATE ships it: every declared pair decided, each `roles: []`
    with its reason — all withheld (the committed template's own verb-grants.yaml)."""
    shutil.copyfile(H.TEMPLATE / "settings" / "verb-grants.yaml", settings / "verb-grants.yaml")


# rejected: an all-withheld table as a finding (M6, human).
def test_1120_check_does_not_report_an_all_withheld_table_as_a_finding(tmp_path: Path) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    _withhold_all(H.settings_dir(root))
    folder = _folder(tmp_path, "tenant")
    _withhold_all(folder / "settings")
    H.assert_clean(_check_id(root))
    H.assert_clean(_check_folder(folder))

    doc = _table(folder / "settings")
    del doc["dispositions"]["threat-intel"]["list-indicators"]
    _write_table(folder / "settings", doc)
    H.assert_refused(_check_folder(folder), "threat-intel.list-indicators")


def test_1120_setup_refuses_an_all_withheld_table_that_check_accepts(tmp_path: Path) -> None:
    """A verb-grants.yaml that decides every declared pair and withholds every one (the table the
    template ships) grants gather nothing, so require_gather_query refuses every run of the tenant."""
    first = tmp_path / "first"
    knowledge = H.place_knowledge(first)
    _withhold_all(knowledge / "settings")
    table = knowledge / "settings" / "verb-grants.yaml"
    before = H.tree_census(first)
    text = H.assert_refused(H.setup(tenant_py, first), str(table))
    assert "the data root is not empty" not in text, (
        f"the refusal is the one-tenant guard's; it must admit the placed knowledge (MF1) and "
        f"setup must refuse the table no run can start with:\n{text}")
    assert H.census_diff(before, H.tree_census(first)) == [], "the refused setup wrote something"
    assert not location_path(H.row_path)(first).exists(), "a refused first setup left a row (MF1 Q2)"

    rerun = tmp_path / "rerun"
    H.place_knowledge(rerun)
    H.assert_clean(H.setup(tenant_py, rerun))
    _withhold_all(H.settings_dir(rerun))
    before = H.tree_census(rerun)
    H.assert_refused(H.setup(tenant_py, rerun), str(H.settings_dir(rerun) / "verb-grants.yaml"))
    assert H.census_diff(before, H.tree_census(rerun)) == [], "the refused re-run wrote something"
    H.assert_clean(_check_id(rerun))


def _gather_health_checks_only(settings: Path) -> None:
    """The template's table with every `health-check` row granted to gather and every other row still
    withheld: total (no gap), lead-zero clean and not all-withheld, yet gather holds no query verb,
    so require_gather_query refuses every run (92r2 #1, executed)."""
    doc = yaml.safe_load(
        (H.TEMPLATE / "settings" / "verb-grants.yaml").read_text(encoding="utf-8"))
    granted = 0
    for verbs in doc["dispositions"].values():
        for verb, row in verbs.items():
            if verb == "health-check":
                verbs[verb] = {"roles": ["gather"]}
                granted += 1
            else:
                assert row.get("roles") == [], f"precondition: the template grants {verb}"
    assert granted, "precondition: the template declares no health-check row"
    _write_table(settings, doc)


def test_1120_setup_refuses_a_health_check_only_gather_grant_that_check_accepts(
        tmp_path: Path) -> None:
    first = tmp_path / "first"
    knowledge = H.place_knowledge(first)
    _gather_health_checks_only(knowledge / "settings")
    table = knowledge / "settings" / "verb-grants.yaml"
    before = H.tree_census(first)
    text = H.assert_refused(H.setup(tenant_py, first), str(table))
    assert "the data root is not empty" not in text, (
        f"the refusal is the one-tenant guard's; it must admit the placed knowledge (MF1) and "
        f"setup must refuse the table no run can start with:\n{text}")
    assert H.census_diff(before, H.tree_census(first)) == [], "the refused setup wrote something"
    assert not location_path(H.row_path)(first).exists(), "a refused first setup left a row (MF1 Q2)"

    rerun = tmp_path / "rerun"
    H.place_knowledge(rerun)
    H.assert_clean(H.setup(tenant_py, rerun))
    _gather_health_checks_only(H.settings_dir(rerun))
    before = H.tree_census(rerun)
    H.assert_refused(H.setup(tenant_py, rerun), str(H.settings_dir(rerun) / "verb-grants.yaml"))
    assert H.census_diff(before, H.tree_census(rerun)) == [], "the refused re-run wrote something"
    H.assert_clean(_check_id(rerun))
    H.assert_clean(_check_folder(H.knowledge_dir(rerun)))


def _decoy_repo(tmp_path: Path) -> Path:
    """A repo whose HEAD DOES commit agent/.tenant-id = acme — what an exported GIT_DIR would point
    check's git read at (J-PO1, executed: an exported GIT_DIR decides the repository whatever `cwd=`
    says)."""
    src = tmp_path / "decoy-src"
    shutil.copytree(H.FIXTURE, src, symlinks=True)
    H.write_tenant_id_file(src, H.TID, "id")
    return H.repo_of(src, tmp_path / "decoy")


@pytest.mark.parametrize("how", [
    pytest.param("untracked", id="tenant_id_file:untracked-in-clone"),
    pytest.param("staged", id="tenant_id_file:staged-in-clone"),
    pytest.param("overwritten", id="tenant_id_file:modified-in-clone"),
])
def test_1120_check_refuses_a_clones_tenant_id_that_its_repo_does_not_commit(
        tmp_path: Path, how: str) -> None:
    root = tmp_path / "data"
    knowledge = H.clone_with_uncommitted_tenant_id(tmp_path / "src", root, how)
    named = H.TENANT_ID_FILE.as_posix()
    assert (knowledge / H.TENANT_ID_FILE).read_bytes() == f"{H.TID}\n".encode(), (
        "precondition: the bytes must match")
    status = H.git_status(knowledge)
    assert named in status, f"precondition: the clone's .tenant-id is not uncommitted:\n{status!r}"

    H.assert_clean(H.setup(tenant_py, root))
    assert location_path(H.row_path)(root).is_file(), "setup refused a matching .tenant-id (V11: no git rule)"
    assert H.accept(_tenant, root).id == H.TID

    H.assert_refused(_check_id(root), named)
    decoy = _decoy_repo(tmp_path)
    H.assert_refused(_check_id(root, GIT_DIR=str(decoy / ".git")), named)
    H.assert_refused(_check_folder(knowledge), named)
    assert H.git_status(knowledge) == status, "check changed the clone's git state"

    committed = tmp_path / "committed"
    clean_clone = H.cloned_tenant(tmp_path / "committed-src", committed)
    H.plant_row(committed)
    H.assert_clean(_check_id(committed))
    H.assert_clean(_check_folder(clean_clone))
    H.assert_clean(_check_folder(_folder(tmp_path, "plain", tenant_id_file="id")))


#: A uid other than this process's, for a clone git refuses as "dubious ownership".
OTHER_UID = 1000

#: A fault is `(tmp_path, knowledge) -> (env for the faulted run, a pattern for git's reason,
GitFault = Callable[[Path, Path], tuple[dict[str, str], str, Callable[[], None]]]


def _git_probe(knowledge: Path, **env: str) -> subprocess.CompletedProcess:
    """`git rev-parse` over the clone, in the environment the operator command inherits."""
    return subprocess.run(  # noqa: S603 — fixed argv
        ["git", "-C", str(knowledge), "rev-parse", "--is-inside-work-tree"],
        env=H.tenant_env(None, **env), capture_output=True, text=True, check=False, timeout=60)


def _git_absent(tmp_path: Path, _knowledge: Path):
    """No git on PATH (a host without git; the runtime image ships none)."""
    bare = tmp_path / "bin-without-git"
    bare.mkdir()
    probe = subprocess.run(  # noqa: S603 — the test's own interpreter
        [sys.executable, "-c", "import shutil, sys; sys.exit(shutil.which('git') is not None)"],
        env=H.tenant_env(None, PATH=str(bare)), capture_output=True, text=True, check=False)
    assert probe.returncode == 0, "precondition: git is still reachable on the reduced PATH"
    # git the executable, never a `.git` path (`knowledge/.git`, `.git/config`).
    return {"PATH": str(bare)}, r"(?<![.\w/])git(?![\w/])", lambda: None


def _git_unrunnable(tmp_path: Path, _knowledge: Path):
    """The only `git` on PATH is a file nobody may execute: starting it raises PermissionError, not
    FileNotFoundError (#1159 review: it crashed `check` with a traceback)."""
    bin_dir = tmp_path / "bin-with-unrunnable-git"
    bin_dir.mkdir()
    (bin_dir / "git").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (bin_dir / "git").chmod(0o644)
    probe = subprocess.run(  # noqa: S603 — the test's own interpreter
        [sys.executable, "-c", "import subprocess\ntry:\n    subprocess.run(['git'])\n"
         "except PermissionError:\n    raise SystemExit(0)\nraise SystemExit(1)"],
        env=H.tenant_env(None, PATH=str(bin_dir)), capture_output=True, text=True, check=False)
    assert probe.returncode == 0, (
        f"precondition: starting git on the reduced PATH does not raise PermissionError:\n"
        f"{probe.stdout}{probe.stderr}")
    return {"PATH": str(bin_dir)}, re.escape("git cannot be run"), lambda: None


def _chown_tree(top: Path, uid: int) -> None:
    os.lchown(top, uid, uid)
    for parent, dirs, files in os.walk(top):
        for name in (*dirs, *files):
            os.lchown(os.path.join(parent, name), uid, uid)


def _owned_by_another_uid(_tmp_path: Path, knowledge: Path):
    """The clone owned by another uid (an operator's host clone read by a root process — C14's
    daemon-mapped data root): git refuses it as dubious ownership, rc 128 (92r2 #3, executed)."""
    _chown_tree(knowledge, OTHER_UID)
    probe = _git_probe(knowledge)
    said = (f"precondition: git answers over a clone owned by uid {OTHER_UID} (a "
            f"safe.directory covers it?):\n{probe.stdout}{probe.stderr}")
    assert probe.returncode != 0, said
    assert "dubious ownership" in probe.stderr, said
    return {}, re.escape("dubious ownership"), lambda: _chown_tree(knowledge, os.geteuid())


def _unreadable_git_config(_tmp_path: Path, knowledge: Path):
    """The clone's .git/config does not parse: every git command over it fails, rc 128."""
    config = knowledge / ".git" / "config"
    saved = config.read_bytes()
    config.write_text("[core\n\tbroken\n", encoding="utf-8")
    probe = _git_probe(knowledge)
    said = f"precondition: git reads the broken config:\n{probe.stdout}{probe.stderr}"
    assert probe.returncode != 0, said
    assert "bad config" in probe.stderr, said
    return {}, re.escape("bad config"), lambda: config.write_bytes(saved)


def _without(text: str, *spans: str) -> str:
    for span in spans:
        text = text.replace(span, "<>")
    return text


GIT_CANNOT_ANSWER: list[Any] = [
    pytest.param(_git_absent, id="git:absent"),
    pytest.param(_git_unrunnable, id="git:not-executable"),
    pytest.param(_owned_by_another_uid, id="git:dubious-ownership", marks=pytest.mark.skipif(
        os.geteuid() != 0,
        reason="a clone owned by another uid needs root to chown; CI runs non-root")),
    pytest.param(_unreadable_git_config, id="git:read-error"),
]


@pytest.mark.parametrize("fault", GIT_CANNOT_ANSWER)
def test_1120_check_fails_closed_when_git_cannot_say_the_tenant_id_is_committed(
        tmp_path: Path, fault: GitFault) -> None:
    root = tmp_path / "data"
    knowledge = H.cloned_tenant(tmp_path / "src", root)
    H.plant_row(root)
    # O5: this setup re-run starts from a fully provisioned tenant.
    (H.tenant_folder(root) / "learning").mkdir()
    env, reason, repair = fault(tmp_path, knowledge)
    try:
        for proc in (_check_id(root, **env), _check_folder(knowledge, **env)):
            text = H.assert_refused(proc, H.CANNOT_VERIFY_TENANT_ID)
            assert re.search(reason, _without(text, str(tmp_path), H.CANNOT_VERIFY_TENANT_ID)), (
                f"check does not give git's reason (/{reason}/) for not answering:\n{text}")
        before = H.tree_census(root)
        H.assert_clean(H.setup(tenant_py, root, **env))
        assert H.census_diff(before, H.tree_census(root)) == [], "setup's re-run wrote something"
    finally:
        repair()
    H.assert_clean(_check_id(root))
    H.assert_clean(_check_folder(knowledge))


#: The two ways this machine's git fails the census, each with the census's cause and V16's
GIT_FAILS: list[Any] = [
    pytest.param(_git_absent, GIT_ABSENT_CAUSE, "git is not available on PATH", id="git:absent"),
    pytest.param(_git_unrunnable, GIT_UNRUNNABLE_CAUSE, "git cannot be run",
                 id="git:not-executable"),
]


@pytest.mark.parametrize(("fault", "cause", "unverified_reason"), GIT_FAILS)
def test_1159_check_says_this_machines_git_failed_and_exits_1(
        tmp_path: Path, fault: GitFault, cause: str, unverified_reason: str) -> None:
    """#1159 O2 (V16): when this machine's git fails, `check` over a tenant whose knowledge is
    a git work tree says, on its own line, that the committed `.tenant-id` cannot be verified
    and gives git's reason, and exits 1; a plain folder is exempt from that rule.

    #1108 P4 (design gap I, respelled): this case also pinned that the GRANT CENSUS goes blind
    with git (#1159 O1's census line naming `cause`). The census read git only for the
    checkout's committed system markers — the product tree's system skills, which P4 deletes
    (O-U5): the census is the adapters, read cold, and no longer starts git. That half pinned a
    mechanism P4 removes and is dropped (`cause` is kept in the parameters for the record); the
    census's own blind line stays pinned by the adapter cases above (`ADAPTER_CAUSE`). V16's
    half still reads git and is kept whole. What stays of the census half is its converse: the
    census is git-free, so neither command's output carries the census-not-taken line or either
    of the census's git causes."""
    folder = _folder(tmp_path, "tenant")
    root = tmp_path / "data"
    knowledge = H.cloned_tenant(tmp_path / "src", root)
    H.plant_row(root)
    env, _reason, _repair = fault(tmp_path, knowledge)

    def assert_census_taken(text: str) -> None:
        assert CENSUS_NOT_TAKEN not in text, (
            f"#1108 P4: the census is git-free, yet it went blind with git ({cause!r}):\n{text}")
        # The census causes end "... on this machine"; V16's own reason (`unverified_reason`)
        # is their prefix without it, so V16's line does not match these needles.
        for git_cause in (GIT_ABSENT_CAUSE, GIT_UNRUNNABLE_CAUSE):
            assert git_cause not in text, (
                f"#1108 P4: the census is git-free, yet the output gives a git cause "
                f"({git_cause!r}):\n{text}")

    text = H.output(_check_folder(folder, **env))
    assert H.CANNOT_VERIFY_TENANT_ID not in text, (
        f"a plain folder (no git work tree) is exempt from the committed-.tenant-id rule:\n{text}")
    assert_census_taken(text)

    for proc in (_check_folder(knowledge, **env), _check_id(root, **env)):
        text = H.assert_refused(proc, H.CANNOT_VERIFY_TENANT_ID)
        assert_census_taken(text)
        unverified = [ln for ln in text.splitlines() if H.CANNOT_VERIFY_TENANT_ID in ln]
        assert len(unverified) == 1, f"V16's line is not printed once (#1159 O2):\n{text}"
        assert CENSUS_NOT_TAKEN not in unverified[0], (
            f"V16's line is not its own line beside the census line (#1159 O2):\n{text}")
        assert unverified_reason in unverified[0], (
            f"V16's line does not give git's reason ({unverified_reason!r}):\n{text}")

    H.assert_clean(_check_folder(folder))
