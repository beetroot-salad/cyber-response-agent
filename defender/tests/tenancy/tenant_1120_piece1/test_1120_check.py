"""`tenant.py check <id> | --folder <path>`: the tenant's own checks."""
from __future__ import annotations


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
from defender.systems import verb_dispositions
from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

#: A system only a tmp checkout declares, and the one verb its adapter declares.
EXTRA_SYSTEM = "extra"
EXTRA_PAIR = "extra.verb"
EXTRA_ADAPTER = 'VERBS = {"verb": None}\n'

BROKEN_SYSTEM = H.BROKEN_SYSTEM
BROKEN_ADAPTER = H.BROKEN_ADAPTER

#: The retired learning-state knob; #1186 commands must ignore it even when overlapping.
OVERLAP_ENV = H.LEARNING_STATE_ENV

#: What `check` says when the census cannot be taken and the folder's table goes unjudged (#1159).
CENSUS_NOT_TAKEN = "was not checked against the running checkout's adapters"

#: The census's own causes, each naming the side that failed: this machine's git or an adapter.
GIT_ABSENT_CAUSE = "git is not available on PATH on this machine"
GIT_UNRUNNABLE_CAUSE = "git cannot be run on this machine"
ADAPTER_CAUSE = "have an adapter the cold verb reader saw no verb in"


def _copy_script(checkout: Path) -> Path:
    """The tmp checkout's own `tenant.py` — the copy of the file `tenant_py` runs from."""
    return checkout / H.script_of(tenant_py).resolve().relative_to(H.REPO_ROOT)


def _folder(tmp_path: Path, name: str, *, tenant_id_file: str | bytes | None = None) -> Path:
    """A tenant repo's working folder (`settings/` + `agent/`), copied from the fixture — what
    `check --folder` is pointed at in tenant CI. No `.tenant-id` unless asked."""
    folder = tmp_path / name
    shutil.copytree(H.FIXTURE, folder, symlinks=True)
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
    """Break `folder`'s case-record.yaml (#1359) so it does not parse — a finding about the
    folder that needs no census. Returns the file."""
    mapping = folder / "settings" / "case-record.yaml"
    mapping.write_text("system: [unclosed\n", encoding="utf-8")
    return mapping


def _census_blind_line(proc: subprocess.CompletedProcess, *, folder: Path, cause: str,
                       names: tuple[str, ...] = (), also: tuple[str, ...] = ()) -> tuple[str, str]:
    """Assert `proc`, a `check` over `folder`, printed the census-not-taken line once, naming
    the table, then `cause` and `names`."""
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
            f"the census line does not give {said!r} after its framing:\n{line}")
    return text, line


@pytest.fixture(scope="module")
def extra_checkout(tmp_path_factory) -> Path:
    """A copy of this checkout whose adapters declare one more system, `extra` (read-only
    once built; shared by the tests about which tree the census is taken from)."""
    checkout = H.tmp_checkout(tmp_path_factory.mktemp("extra") / "checkout")
    H.add_adapter(checkout, EXTRA_SYSTEM, EXTRA_ADAPTER)
    return checkout


def test_1120_check_exits_zero_over_a_clean_tenant_and_a_clean_folder(tmp_path: Path) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    before = H.tree_census(root)
    H.assert_clean(_check_id(root))
    assert H.census_diff(before, H.tree_census(root)) == [], "check wrote into the data root"

    for folder in (H.FIXTURE, H.TEMPLATE):
        assert not (folder / H.TENANT_ID_FILE).exists(), f"{folder} commits a .tenant-id"
        committed = H.tree_census(folder)
        H.assert_clean(_check_folder(folder))
        assert H.census_diff(committed, H.tree_census(folder)) == [], f"check wrote into {folder}"


def _missing_required_setting(knowledge: Path) -> str:
    target = knowledge / "settings" / "lead-zero.yaml"  # #1359: the case mapping is no longer required
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
    # A case-record file that does not parse is a finding naming it (#1359 r4), census or not.
    H.assert_refused(H.run_script(script, "check", "--folder", str(folder), root=None),
                     "settings/case-record.yaml")


def test_1120_s6_defender_dir_env_names_another_tree(
        tmp_path: Path, extra_checkout: Path) -> None:
    copy_defender = extra_checkout / "defender"
    root = copy_defender / f"data-{tmp_path.name}"
    H.adopted(root)
    text = H.assert_clean(_check_id(root, DEFENDER_DIR=str(copy_defender)))
    assert EXTRA_PAIR not in text, f"check took its census from DEFENDER_DIR:\n{text}"

    script = _copy_script(extra_checkout)
    H.assert_refused(H.checkout_tenant_py(extra_checkout, "check", H.TID, root=root), str(copy_defender))
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


#: A lead-zero template the running checkout's catalog lacks.
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
def test_1120_check_refuses_a_lead_zero_table_that_disagrees_with_the_running_catalog(
        tmp_path: Path, template: str) -> None:
    first = tmp_path / "first"
    knowledge = H.place_knowledge(first)
    _write_lead_zero(knowledge / "settings", template)
    before = H.tree_census(first)
    H.assert_refused(_check_id(first), "lead-zero.yaml", template)
    assert H.census_diff(before, H.tree_census(first)) == [], "the refused check wrote something"

    rerun = tmp_path / "rerun"
    H.place_knowledge(rerun)
    H.assert_clean(_check_id(rerun))
    _write_lead_zero(H.settings_dir(rerun), template)
    before = H.tree_census(rerun)
    H.assert_refused(_check_id(rerun), "lead-zero.yaml", template)
    assert H.census_diff(before, H.tree_census(rerun)) == [], "the refused re-check wrote something"


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
    root = tmp_path / "data"
    H.adopted(root)
    overlap = {OVERLAP_ENV: str(root / "learning-state")}
    folder = _folder(tmp_path, "tenant")
    H.assert_clean(H.check(tenant_py, root, "--folder", str(folder), **overlap))

    before = H.tree_census(root)
    H.assert_clean(_check_id(root, **overlap))
    assert H.tree_census(root) == before, "check wrote into the tenant"
    assert not (H.tenant_folder(root) / "learning").exists(), "check created learning state"


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
    """The template's own table: every declared pair decided and withheld (`roles: []`)."""
    shutil.copyfile(H.TEMPLATE / "settings" / "verb-grants.yaml", settings / "verb-grants.yaml")


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


def _gather_health_checks_only(settings: Path) -> None:
    """The template's table with every `health-check` row granted to gather and every other row still
    withheld: total (no gap), lead-zero clean and not all-withheld, yet gather holds no query verb,
    so require_gather_query refuses every run."""
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


@pytest.mark.parametrize("plant", [
    pytest.param(_withhold_all, id="all-withheld"),
    pytest.param(_gather_health_checks_only, id="health-checks-only"),
])
def test_1120_check_accepts_a_table_granting_gather_no_query_verb(
        tmp_path: Path, plant: Callable[[Path], None]) -> None:
    """A table granting gather no query verb (the template's all-withheld one, or one granting
    only `health-check`) fails `require_gather_query` for every run, yet `check` does not report it
    (the refusal at `setup` retired with `setup`, F-12)."""
    rerun = tmp_path / "rerun"
    H.place_knowledge(rerun)
    H.assert_clean(_check_id(rerun))
    plant(H.settings_dir(rerun))
    before = H.tree_census(rerun)
    H.assert_clean(_check_id(rerun))
    H.assert_clean(_check_folder(H.knowledge_dir(rerun)))
    assert H.census_diff(before, H.tree_census(rerun)) == [], "check wrote into the tenant"


def _decoy_repo(tmp_path: Path) -> Path:
    """A repo whose HEAD does commit the right agent/.tenant-id, for an exported GIT_DIR to point
    check's git read at (an exported GIT_DIR overrides `cwd=`)."""
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

    assert H.accept(_tenant, root).id == H.TID

    H.assert_refused(_check_id(root), named)
    decoy = _decoy_repo(tmp_path)
    H.assert_refused(_check_id(root, GIT_DIR=str(decoy / ".git")), named)
    H.assert_refused(_check_folder(knowledge), named)
    assert H.git_status(knowledge) == status, "check changed the clone's git state"

    committed = tmp_path / "committed"
    clean_clone = H.cloned_tenant(tmp_path / "committed-src", committed)
    H.assert_clean(_check_id(committed))
    H.assert_clean(_check_folder(clean_clone))
    H.assert_clean(_check_folder(_folder(tmp_path, "plain", tenant_id_file="id")))


#: A uid other than this process's, for a clone git refuses as "dubious ownership".
OTHER_UID = 1000

#: A fault is `(tmp_path, knowledge) -> (env for the faulted run, git's reason pattern, a repair)`.
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
    FileNotFoundError (#1159)."""
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
    """The clone owned by another uid (a host clone read by a root process): git refuses it as
    dubious ownership, rc 128."""
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
    env, reason, repair = fault(tmp_path, knowledge)
    try:
        for proc in (_check_id(root, **env), _check_folder(knowledge, **env)):
            text = H.assert_refused(proc, H.CANNOT_VERIFY_TENANT_ID)
            assert re.search(reason, _without(text, str(tmp_path), H.CANNOT_VERIFY_TENANT_ID)), (
                f"check does not give git's reason (/{reason}/) for not answering:\n{text}")
    finally:
        repair()
    H.assert_clean(_check_id(root))
    H.assert_clean(_check_folder(knowledge))


#: The two ways this machine's git fails, each with the census's cause and the unverified-id reason.
GIT_FAILS: list[Any] = [
    pytest.param(_git_absent, GIT_ABSENT_CAUSE, "git is not available on PATH", id="git:absent"),
    pytest.param(_git_unrunnable, GIT_UNRUNNABLE_CAUSE, "git cannot be run",
                 id="git:not-executable"),
]


@pytest.mark.parametrize(("fault", "cause", "unverified_reason"), GIT_FAILS)
def test_1159_check_says_this_machines_git_failed_and_exits_1(
        tmp_path: Path, fault: GitFault, cause: str, unverified_reason: str) -> None:
    """When this machine's git fails, `check` over a git work tree says on its own line that
    the committed `.tenant-id` cannot be verified, with git's reason, and exits 1; a plain folder
    is exempt. The census reads adapters cold, so no output carries the census-not-taken line or
    a census git cause."""
    folder = _folder(tmp_path, "tenant")
    root = tmp_path / "data"
    knowledge = H.cloned_tenant(tmp_path / "src", root)
    env, _reason, _repair = fault(tmp_path, knowledge)

    def assert_census_taken(text: str) -> None:
        assert CENSUS_NOT_TAKEN not in text, (
            f"the git-free census was not taken when git failed ({cause!r}):\n{text}")
        # The census causes end "... on this machine"; `unverified_reason` is their prefix
        # without it, so the unverified-id line does not match these needles.
        for git_cause in (GIT_ABSENT_CAUSE, GIT_UNRUNNABLE_CAUSE):
            assert git_cause not in text, (
                f"the git-free census reports a git cause ({git_cause!r}):\n{text}")

    text = H.output(_check_folder(folder, **env))
    assert H.CANNOT_VERIFY_TENANT_ID not in text, (
        f"a plain folder (no git work tree) is exempt from the committed-.tenant-id rule:\n{text}")
    assert_census_taken(text)

    for proc in (_check_folder(knowledge, **env), _check_id(root, **env)):
        text = H.assert_refused(proc, H.CANNOT_VERIFY_TENANT_ID)
        assert_census_taken(text)
        unverified = [ln for ln in text.splitlines() if H.CANNOT_VERIFY_TENANT_ID in ln]
        assert len(unverified) == 1, f"the unverified-id line is not printed once:\n{text}"
        assert CENSUS_NOT_TAKEN not in unverified[0], (
            f"the unverified-id line is not separate from the census line:\n{text}")
        assert unverified_reason in unverified[0], (
            f"the unverified-id line does not give git's reason ({unverified_reason!r}):\n{text}")

    H.assert_clean(_check_folder(folder))


# ---------------------------------------------------------------- #1390: the tacit-knowledge registry

TACIT = "tacit-knowledge"
TACIT_REGISTRY_REL = ("agent", "skills", TACIT, "registry.yaml")
#: Declares verbs the cold reader can see, and claims the platform's reserved name.
RESERVED_ADAPTER = 'VERBS = {"lookup": None, "health-check": None}\n'


def _without_tacit_rows(folder: Path, *verbs: str) -> None:
    """Delete the `tacit-knowledge` rows named (the whole system when none are left)."""
    settings = folder / "settings"
    doc = _table(settings)
    rows = doc["dispositions"][TACIT]
    for verb in verbs:
        del rows[verb]
    if not rows:
        del doc["dispositions"][TACIT]
    _write_table(settings, doc)


def _withhold_tacit(folder: Path, *verbs: str) -> None:
    """Keep the `tacit-knowledge` rows named, granted to no role, with a reason."""
    settings = folder / "settings"
    doc = _table(settings)
    for verb in verbs:
        doc["dispositions"][TACIT][verb] = {"roles": [], "reason": "this tenant keeps no sanctions"}
    _write_table(settings, doc)


def _cli_check(agent: Path, *extra: str) -> tuple[int, str]:
    """`tacit_cli check` over the registry under the agent root `agent`, as a human would see it."""
    import io
    from contextlib import redirect_stderr, redirect_stdout

    from defender.cli import tacit_cli

    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(out):
        rc = tacit_cli.main(["check", "--defender-dir", str(agent), *extra])
    return rc, out.getvalue()


def _cli_failures(agent: Path) -> list[str]:
    """What `tacit_cli check` prints as a failure for this registry: the text after each `[✗]`
    marker, without the DROPPED label. Exits 1 by premise."""
    rc, said = _cli_check(agent)
    assert rc == 1, f"premise: the CLI fails this registry:\n{said}"
    texts = [ln.split("[✗]", 1)[1].strip().removeprefix("DROPPED — ")
             for ln in said.splitlines() if "[✗]" in ln]
    assert texts, f"premise: the CLI printed a failure:\n{said}"
    return texts


def _registry_faults() -> dict[str, tuple]:
    """Registries `tenant check` must fail on: a dropped entry, and a file refused whole."""
    from defender.tests.support.shared.contracts import _tacit983 as scene

    return {
        "dropped-entry": (scene.registry_entry(id="tk-1390-200-days", added_at="2026-03-01",
                                               review_by="2026-09-17"),),
        "refused-whole": (),
    }


def _plant_registry_fault(folder: Path, kind: str) -> None:
    from defender.tests.support.shared.contracts import _tacit983 as scene

    entries = _registry_faults()[kind]
    if kind == "refused-whole":
        path = folder.joinpath(*TACIT_REGISTRY_REL)
        path.write_text("sanctions:\n  - id: tk-misfiled\n", encoding="utf-8")
        return
    scene.write_registry(folder / "agent", *entries)


@pytest.mark.parametrize("kind", ["dropped-entry", "refused-whole"])
def test_1390_check_folder_fails_on_what_the_authors_cli_fails_on_with_the_clis_words(
        tmp_path: Path, kind: str) -> None:
    """A registry with a dropped entry or refused whole fails `check --folder`, and the output carries each reason the author's CLI prints for the same file. O7, A8."""
    H.assert_clean(_check_folder(_folder(tmp_path, "control")))
    folder = _folder(tmp_path, "tenant")
    _plant_registry_fault(folder, kind)

    text = H.assert_refused(_check_folder(folder), TACIT)

    for reason in _cli_failures(folder / "agent"):
        assert reason in text, f"`check` does not carry the CLI's reason {reason!r}:\n{text}"


def test_1390_check_does_not_fail_on_what_only_the_calendar_changed(tmp_path: Path) -> None:
    """An entry past its `review_by` (a note in the author's CLI, never a failure there) leaves `check --folder` at exit 0. A8."""
    from defender.tests.support.shared.contracts import _tacit983 as scene

    folder = _folder(tmp_path, "tenant")
    scene.write_registry(folder / "agent", scene.registry_entry(
        added_at="2025-11-01", review_by="2026-01-01"))
    rc, said = _cli_check(folder / "agent", "--as-of", "2026-11-05")
    assert (rc, "EXPIRED" in said) == (0, True), (
        f"premise: the author's CLI only notes an expired entry:\n{said}")

    H.assert_clean(_check_folder(folder))


def test_1390_check_still_reports_a_broken_registry_when_the_grant_table_does_not_load(
        tmp_path: Path) -> None:
    """A grant table that fails to parse and a registry with a dropped entry are both reported by one `check --folder`. A8."""
    folder = _folder(tmp_path, "tenant")
    _plant_registry_fault(folder, "dropped-entry")
    table = folder / "settings" / "verb-grants.yaml"
    text = table.read_text(encoding="utf-8")
    table.write_text(text.replace("  cmdb:", "<<<<<<< HEAD\n  cmdb:", 1), encoding="utf-8")

    out = H.assert_refused(_check_folder(folder), "verb-grants.yaml", TACIT)

    for reason in _cli_failures(folder / "agent"):
        assert reason in out, f"the registry's reason {reason!r} is lost behind the table:\n{out}"


def test_1390_a_tenant_with_no_registry_file_is_clean(tmp_path: Path) -> None:
    """A tenant whose repo holds no registry file at all passes `check --folder` with the registry rows still granted. P4."""
    folder = _folder(tmp_path, "tenant")
    folder.joinpath(*TACIT_REGISTRY_REL).unlink()

    H.assert_clean(_check_folder(folder))


@pytest.mark.parametrize("how", [
    "rows-deleted", "lookup-withheld", "both-rows-withheld", "lookup-row-deleted", "health-check-row-deleted"])
def test_1390_a_registry_the_grant_table_does_not_reach_is_no_finding(tmp_path: Path, how: str) -> None:
    """With the registry file present and `lookup` unreached by the table (any row, or all, deleted or `roles: []`), `check --folder` exits 0 with no tacit line. H7, O10, A3."""
    control = H.assert_clean(_check_folder(_folder(tmp_path, "control")))
    assert "registry.yaml" not in control, "positive control: a granted lookup draws no warning"
    folder = _folder(tmp_path, "tenant")
    assert folder.joinpath(*TACIT_REGISTRY_REL).is_file(), "premise: the registry file is kept"
    if how == "rows-deleted":
        _without_tacit_rows(folder, "lookup", "health-check")
    elif how == "lookup-row-deleted":
        _without_tacit_rows(folder, "lookup")
    elif how == "health-check-row-deleted":
        _without_tacit_rows(folder, "health-check")
    elif how == "lookup-withheld":
        _withhold_tacit(folder, "lookup")
    else:
        _withhold_tacit(folder, "lookup", "health-check")

    out = H.assert_clean(_check_folder(folder))

    assert TACIT not in out, f"check reported on a system the tenant chose not to grant:\n{out}"
    assert folder.joinpath(*TACIT_REGISTRY_REL).is_file(), "the file was kept through the check"


def test_1390_a_broken_registry_fails_check_even_when_the_grant_table_does_not_reach_it(
        tmp_path: Path) -> None:
    """A dropped entry fails `check --folder` with the tacit rows deleted too: the check judges the file, not the grant. A10."""
    folder = _folder(tmp_path, "tenant")
    _plant_registry_fault(folder, "dropped-entry")
    _without_tacit_rows(folder, "lookup", "health-check")

    text = H.assert_refused(_check_folder(folder), TACIT)

    for reason in _cli_failures(folder / "agent"):
        assert reason in text, f"`check` does not carry the CLI's reason {reason!r}:\n{text}"


def test_1390_check_names_a_reserved_adapter_name_with_its_reason_and_keeps_the_other_adapters(
        tmp_path: Path) -> None:
    """An adapter file named for `tacit-knowledge` shows up in `check`'s census output with the reserved-name reason, not as an anomalous name, and the census of the other adapters is still taken. A5."""
    checkout = H.tmp_checkout(tmp_path / "checkout")
    folder = _folder(tmp_path, "tenant")
    script = _copy_script(checkout)
    H.assert_clean(H.run_script(script, "check", "--folder", str(folder), root=None))

    H.add_adapter(checkout, TACIT, RESERVED_ADAPTER)
    out = H.assert_refused(H.run_script(script, "check", "--folder", str(folder), root=None), TACIT)

    assert TACIT in out, f"the refusal is not named with its reason:\n{out}"
    assert "reserved" in out, f"the refusal is not named with its reason:\n{out}"
    assert "anomalous adapter name" not in out, f"the refusal reads as a malformed name:\n{out}"
    assert CENSUS_NOT_TAKEN not in out, f"the other adapters' census was lost:\n{out}"


def test_1390_check_still_judges_the_tacit_rows_that_are_present(tmp_path: Path) -> None:
    """A row for a verb the registry does not declare is a phantom finding, and a `roles: []` row with no reason is a finding; a reasoned withheld row is clean. H4, A3."""
    folder = _folder(tmp_path, "control")
    _withhold_tacit(folder, "lookup", "health-check")
    H.assert_clean(_check_folder(folder))

    phantom = _folder(tmp_path, "phantom")
    doc = _table(phantom / "settings")
    doc["dispositions"][TACIT]["wipe"] = {"roles": ["gather"]}
    _write_table(phantom / "settings", doc)
    H.assert_refused(_check_folder(phantom), f"{TACIT}.wipe")

    bare = _folder(tmp_path, "unreasoned")
    doc = _table(bare / "settings")
    doc["dispositions"][TACIT]["lookup"] = {"roles": []}
    _write_table(bare / "settings", doc)
    H.assert_refused(_check_folder(bare), f"{TACIT}.lookup", "reason")


@pytest.mark.parametrize("kind", ["dropped-entry", "refused-whole"])
def test_1390_plain_check_by_tenant_id_fails_on_a_broken_registry_too(tmp_path: Path, kind: str) -> None:
    """`tenant check <id>` over a placed tenant (not `--folder`) fails on a dropped entry or a refused file, and is clean without one. O7, A10."""
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(_check_id(root))
    _plant_registry_fault(H.knowledge_dir(root), kind)

    text = H.assert_refused(_check_id(root), TACIT)

    for reason in _cli_failures(H.agent_dir(root)):
        assert reason in text, f"`check <id>` does not carry the CLI's reason {reason!r}:\n{text}"


def test_1390_plain_check_by_tenant_id_names_a_reserved_adapter_name_with_its_reason(tmp_path: Path) -> None:
    """With a reserved-name adapter in the checkout, `tenant check <id>` fails naming `tacit-knowledge` and the reserved reason, not an anomalous name. A11."""
    checkout = H.tmp_checkout(tmp_path / "checkout")
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(H.checkout_tenant_py(checkout, "check", H.TID, root=root))

    H.add_adapter(checkout, TACIT, RESERVED_ADAPTER)
    out = H.assert_refused(H.checkout_tenant_py(checkout, "check", H.TID, root=root), TACIT)

    assert "reserved" in out, f"the refusal gives no reason:\n{out}"
    assert "anomalous adapter name" not in out, f"the refusal reads as a malformed name:\n{out}"


def _non_regular(path: Path, kind: str) -> None:
    path.unlink()
    if kind == "directory":
        path.mkdir()
    elif kind == "dangling-symlink":
        path.symlink_to("nowhere-1390.yaml")
    else:
        path.symlink_to(path.name)


@pytest.mark.parametrize("kind", ["directory", "dangling-symlink", "symlink-loop"])
def test_1390_check_folder_fails_a_non_regular_thing_at_the_registry_path_with_the_clis_words(
        tmp_path: Path, kind: str) -> None:
    """A directory, a dangling symlink or a symlink loop at the registry path is not an absent registry: `check --folder` fails naming tacit-knowledge with the reason the author's CLI prints (exit 1). P4."""
    folder = _folder(tmp_path, "tenant")
    _non_regular(folder.joinpath(*TACIT_REGISTRY_REL), kind)

    text = H.assert_refused(_check_folder(folder), TACIT)

    for reason in _cli_failures(folder / "agent"):
        assert reason in text, f"`check` does not carry the CLI's reason {reason!r}:\n{text}"
