"""#1120 piece 1 — D7/O8 `tenant.py check <id> | --folder <path>`: the tenant's own checks.

`check` runs acceptance (`accept_tenant`, stopping at its first refusal), the grant census in
BOTH directions (every declared verb decided, every decided verb declared) against the RUNNING
checkout's adapters (A3), the lead-zero agreement against the running catalog, "the
settings tables load" (M6, human), and — over a clone, or a `--folder` that is a git work tree —
that agent/.tenant-id is what the repo commits (V11, human: check's rule, never acceptance's or
setup's), failing closed when git cannot answer (V16). An all-withheld or a health-check-only
table is not a finding (M6), though setup refuses both: setup runs run start's own readiness
function (V14, superseding V1's and V10's rule lists) beside the folder rules (V18). `--folder`
runs every rule that needs no data root: it never resolves `DEFENDER_DATA_ROOT`, never applies the
`defender_dir`/`box_mounted` containment (that belongs to a process that mounts), and
grammar-checks `agent/.tenant-id` only when present (M8). Exit status (N17): 0 clean, 1 a
finding or a refusal, 2 a usage error (`<id>` and `--folder` are mutually exclusive, exactly one
required). A finding prints through `[tenant.py] …`, never a traceback. A census the running
checkout cannot take is still a finding, exit 1 (#1159 O2), and its line names that checkout
as the side that failed and the checked folder as not at fault (#1159 O1).

Driven as the operator runs it, as a process. The tests about WHICH tree the census comes from
run the command out of a tmp COPY of this checkout (`_spec1120.tmp_checkout`) carrying one more
(or one broken) adapter — the real worktree is never written into. At base a1c65801 `tenant.py`
has only `setup`, so every `check` is argparse's usage error (exit 2): each test pins exit 1 or
0 together with the finding it names, never a bare "non-zero".
"""
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

from defender import _tenant, _tenant_census
from defender import run as run_py
from defender.runtime import verb_dispositions
from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H

#: A system only a tmp checkout declares, and the one verb its adapter declares (A3).
EXTRA_SYSTEM = "extra"
EXTRA_PAIR = "extra.verb"
EXTRA_ADAPTER = 'VERBS = {"verb": None}\n'

#: An adapter whose source the cold roster read cannot parse (M6: a non-zero exit naming it).
BROKEN_SYSTEM = "broken"
BROKEN_ADAPTER = "VERBS = {\n    'verb': (\n"

#: The learning-state knob whose overlap with the data root `resolve_data_root` refuses.
OVERLAP_ENV = H.LEARNING_STATE_ENV

#: #1159 O1's "nothing in the checked folder is at fault", in any reasonable phrasing: a
#: negation, the folder (or tenant) and "fault"/"blame" inside ONE clause — no `;`, `:` or line
#: break between them — so "the checkout is not at fault; fix the folder" never passes for it.
#: Neither `CensusUnavailable` text, nor any finding about the folder itself, matches it.
NOT_THE_FOLDERS_FAULT = re.compile(
    r"\b(?:not|nothing|no|never)\b[^;:\n]{0,80}?\b(?:folder|tenant)\b[^;:\n]{0,80}?\b(?:fault|blame)"
    r"|\b(?:folder|tenant)\b[^;:\n]{0,80}?\b(?:not|never|isn't)\b[^;:\n]{0,40}?\b(?:fault|blame)"
    r"|\b(?:not|no)\b[^;:\n]{0,20}?\b(?:fault|blame)\b[^;:\n]{0,40}?\b(?:folder|tenant)\b",
    re.IGNORECASE)


# ======================================================================================
# Same-file helpers.
# ======================================================================================

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


def _census_unavailable(checkout: Path, monkeypatch: pytest.MonkeyPatch, **env: str) -> str:
    """What the census's owner says when it cannot be taken over the code at `checkout` (a
    checkout root) in the environment `env`: `take_census`'s own `CensusUnavailable` text — the
    cause #1159 O1 keeps verbatim on check's census line (the oracle, as `_run_start_refusal`
    is setup's)."""
    with monkeypatch.context() as scoped:
        for key, value in env.items():
            scoped.setenv(key, value)
        with pytest.raises(_tenant_census.CensusUnavailable) as blind:
            _tenant_census.take_census(checkout / "defender", checkout)
    return str(blind.value)


def _census_blind_line(proc: subprocess.CompletedProcess, *, checkout: Path, cause: str,
                       folder: Path, also: tuple[str, ...] = ()) -> tuple[str, str]:
    """#1159: `proc` is a `check` over `folder` whose census the running code at `checkout`
    could not take. It exits EXACTLY 1 (O2) naming each of `also`, and exactly one line carries
    the owner's `cause` verbatim (O1). THAT line — never the whole output — names `checkout`'s
    root (the root itself, not a tree under it, and not the folder) and says, without the exit
    code, that the running product checkout failed and nothing in the checked folder is at
    fault. Returns `(output, the census line)`."""
    text = H.assert_refused(proc, cause, *also)
    lines = [ln for ln in text.splitlines() if cause in ln]
    assert len(lines) == 1, f"the census cause {cause!r} is not on exactly one line:\n{text}"
    line = lines[0]
    rest = line.replace(cause, "<cause>")
    root = str(checkout.resolve())
    assert re.search(re.escape(root) + r"(?![\w/])", rest), (
        f"the census line does not name the running checkout {root} — the side that failed "
        f"(#1159 O1):\n{line}")
    for named in {str(folder), str(folder.resolve())}:
        assert named not in line, (
            f"the census line names the checked folder {named}; the census is the running "
            f"checkout's, and the folder is not the side that failed (#1159 O1):\n{line}")
    words = rest.replace(root, "<root>")
    assert re.search(r"\bcheckout\b", words, re.IGNORECASE), (
        f"the census line does not say the running product CHECKOUT failed (#1159 O1):\n{line}")
    assert NOT_THE_FOLDERS_FAULT.search(words), (
        f"the census line does not say nothing in the checked folder is at fault "
        f"(#1159 O1):\n{line}")
    return text, line


@pytest.fixture(scope="module")
def extra_checkout(tmp_path_factory) -> Path:
    """A copy of this checkout whose adapters declare one more system, `extra` (read-only
    once built; shared by the tests about which tree the census is taken from)."""
    checkout = H.tmp_checkout(tmp_path_factory.mktemp("extra") / "checkout")
    H.add_adapter(checkout, EXTRA_SYSTEM, EXTRA_ADAPTER)
    return checkout


# ======================================================================================
# The clean cases, and the acceptance half.
# ======================================================================================

def test_1120_check_exits_zero_over_a_clean_tenant_and_a_clean_folder(tmp_path: Path) -> None:
    """`tenant.py check acme` over a finished tenant built from the fixture under a tmp data
    root exits 0. So does `tenant.py check --folder knowledge/tenant-fixture`, and so does
    `--folder knowledge/tenant-template` (M8: the template carries no .tenant-id and --folder
    does not require one), both run with DEFENDER_DATA_ROOT unset. Both committed folders are
    read in place and left byte-identical."""
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
    """For a tenant with a missing REQUIRED_SETTINGS file, a symlink planted in settings/, or an
    agent/.tenant-id naming another tenant, `tenant.py check acme` exits 1 (N17) and prints
    accept_tenant's own refusal verbatim, which names the offending file. It writes nothing.
    The positive control: the same tenant before the plant is checked clean."""
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(_check_id(root))
    named = plant(H.knowledge_dir(root))
    before = H.tree_census(root)
    text = H.assert_refused(_check_id(root), named)
    assert "[tenant.py]" in text, f"the refusal is not tenant.py's own surface:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == [], "check wrote into the data root"
    H.assert_verbatim(text, H.accept_refusal(_tenant, root, H.TID), entry="tenant.py check")


# ======================================================================================
# The grant census, both directions, against the running checkout.
# ======================================================================================

def test_1120_check_refuses_every_grant_gap_in_both_directions_naming_each(
        tmp_path: Path) -> None:
    """A tenant's verb-grants.yaml has three faults: it omits two declared verbs on different
    systems (change-mgmt.get-change and threat-intel.list-indicators: undecided), it adds a row
    for cmdb.no-such-verb (a phantom verb) and it adds a whole no-such-system block (a phantom
    system). `tenant.py check acme` exits 1 and names all four findings, not just the first
    (N17). Today the loader accepts the phantom rows and grants them (K4). The positive
    control: the unedited table is checked clean."""
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


def test_1120_check_takes_the_census_from_the_code_it_runs(
        tmp_path: Path, extra_checkout: Path) -> None:
    """The census is taken from the running code (A3), never from the tenant: run out of a tmp
    copy of the checkout whose adapters declare one more verb (extra.verb), `tenant.py check
    --folder` over a copy of the fixture exits 1 naming extra.verb as undecided, while this
    checkout's own `check --folder` over the SAME folder, whose census has no such verb, exits
    0."""
    folder = _folder(tmp_path, "tenant")
    H.assert_clean(_check_folder(folder))
    H.assert_refused(
        H.run_script(_copy_script(extra_checkout), "check", "--folder", str(folder), root=None),
        EXTRA_PAIR)


def test_1120_check_exits_non_zero_naming_an_adapter_module_that_fails_to_import(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An adapter module the census cannot read (a source that does not parse) makes `tenant.py
    check` exit EXACTLY 1 naming the module's system, never 0 over a census that silently lacks
    it (M6; #1159 O2: a census-blind check is a finding, exit 1, no other code). Run out of a
    tmp copy of the checkout holding broken_adapter.py, over a sound folder. The census line
    says which side failed without the exit code (#1159 O1): it names the tmp COPY's root (the
    running checkout, whose path is neither the cwd the command starts in nor the folder's) and
    not the folder, says nothing in the checked folder is at fault, and carries the owner's
    `CensusUnavailable` text verbatim. The positive control: the same copy without that module
    checks the same folder clean."""
    checkout = H.tmp_checkout(tmp_path / "checkout")
    folder = _folder(tmp_path, "tenant")
    script = _copy_script(checkout)
    H.assert_clean(H.run_script(script, "check", "--folder", str(folder), root=None))
    H.add_adapter(checkout, BROKEN_SYSTEM, BROKEN_ADAPTER)
    cause = _census_unavailable(checkout, monkeypatch)
    assert BROKEN_SYSTEM in cause, f"precondition: the owner's cause names no {BROKEN_SYSTEM}"
    _census_blind_line(H.run_script(script, "check", "--folder", str(folder), root=None),
                       checkout=checkout, cause=cause, folder=folder, also=(BROKEN_SYSTEM,))


def test_1120_s6_defender_dir_env_names_another_tree(
        tmp_path: Path, extra_checkout: Path) -> None:
    """`check`'s census and every containment check use the running process's own checkout
    (its module location), not an exported DEFENDER_DIR. With DEFENDER_DIR naming a tmp copy
    of the checkout that declares one more verb (extra.verb) and whose defender/ tree holds
    the data root, this checkout's `tenant.py check acme` exits 0: no extra.verb finding, and
    no mounted-tree refusal. The control: the copy's own `check` does take its own tree — over
    the same data root it refuses (the settings sit inside ITS defender/ tree), and over the
    fixture folder it names extra.verb."""
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


# ======================================================================================
# Folder mode.
# ======================================================================================

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
#: `correlation_dispatch`: REFUSED, "resolves to no established template").
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
    """`tenant.py check --folder <path>` refuses a folder with a missing half, a missing
    REQUIRED_SETTINGS file, a link in either half, an off-grammar agent/.tenant-id, a grant
    gap, or a lead-zero.yaml naming a template the running catalog lacks (M6 (b): the lead-zero
    agreement is a folder rule tenant CI reports, V4): exit 1, naming each (the lead-zero cell
    names lead-zero.yaml and the template). It needs no DEFENDER_DATA_ROOT (every leg runs with
    the variable unset), and it does not require .tenant-id to exist (M8): the positive
    control, the same folder before the plant and without any .tenant-id, exits 0."""
    folder = _folder(tmp_path, "tenant")
    H.assert_clean(_check_folder(folder))
    named = plant(folder)
    H.assert_refused(_check_folder(folder), *(named if isinstance(named, tuple) else (named,)))


def test_1120_s6_check_folder_reached_through_symlink_or_bind_mount(tmp_path: Path) -> None:
    """Folder mode runs its content rules over the folder it is given and applies no
    defender_dir or box_mounted containment wherever that folder resolves, because containment
    belongs to a process that mounts (step 7). A folder reached through a symlink whose target
    lies inside the running checkout's defender/ tree (run out of a tmp copy of the checkout,
    the folder planted inside the COPY's tree), and one reached through a symlink into a data
    root's <T>/knowledge, are each checked clean (exit 0). The control: a content fault
    planted behind the same link (a missing lead-zero.yaml) is reported, naming the file."""
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


# ======================================================================================
# The lead-zero agreement: check's finding (M6) AND setup's refusal (V1, human, overturning NF1:
# setup refuses anything that would make a run refuse, and every fresh run dispatches lead
# zero). A grant gap still passes setup (runs proceed with it, A1).
# ======================================================================================

LEAD_ZERO_DISAGREEMENTS = [
    pytest.param(ABSENT_TEMPLATE, id="template-absent-from-catalog"),
    # `elastic.detection-alerts` binds `esql`; the table grants the lead `elastic.alerts`.
    pytest.param("elastic.detection-alerts", id="template-pair-disagrees"),
]


@pytest.mark.parametrize("template", LEAD_ZERO_DISAGREEMENTS)
def test_1120_setup_and_check_refuse_a_lead_zero_table_that_disagrees_with_the_running_catalog(
        tmp_path: Path, template: str) -> None:
    """A lead-zero.yaml naming a template the running checkout's catalog lacks, or one whose
    (system, verb) pair disagrees with the pair the table grants the correlation lead, stops
    every fresh run of the tenant (run.py dispatches lead zero on each; correlation_dispatch
    refuses both cells — 92 #1, executed). So (V1, human, overturning NF1) a FIRST `tenant.py
    setup acme` over a placed knowledge/ carrying it exits 1 naming lead-zero.yaml and the
    template, writing nothing (no row — rules-first); a RE-RUN over a finished tenant whose
    lead-zero.yaml has since become it exits 1 the same way, writing nothing; and `tenant.py
    check acme` exits 1 naming lead-zero.yaml and the template (M6). The positive control: the
    same placed folder with the fixture's own lead-zero.yaml sets up with exit 0. A grant gap
    still passes setup (d7_setup_rerun_is_silent_and_writes_nothing,
    d7_setup_runs_acceptance_and_check)."""
    first = tmp_path / "first"
    knowledge = H.place_knowledge(first)
    _write_lead_zero(knowledge / "settings", template)
    before = H.tree_census(first)
    text = H.assert_refused(H.setup(tenant_py, first), "lead-zero.yaml", template)
    assert "the data root is not empty" not in text, (
        f"the refusal is the one-tenant guard's; it must admit the placed knowledge (MF1) and "
        f"the lead-zero agreement must refuse it:\n{text}")
    assert H.census_diff(before, H.tree_census(first)) == [], "the refused setup wrote something"
    assert not H.row_path(first).exists(), "a refused first setup left a row (MF1 Q2)"

    rerun = tmp_path / "rerun"
    H.place_knowledge(rerun)
    H.assert_clean(H.setup(tenant_py, rerun))
    _write_lead_zero(H.settings_dir(rerun), template)
    before = H.tree_census(rerun)
    H.assert_refused(H.setup(tenant_py, rerun), "lead-zero.yaml", template)
    assert H.census_diff(before, H.tree_census(rerun)) == [], "the refused re-run wrote something"
    H.assert_refused(_check_id(rerun), "lead-zero.yaml", template)


# ======================================================================================
# The table loads (malformed = a named finding, never a traceback).
# ======================================================================================

def test_1120_s9_check_over_a_grant_table_repeats_a_top_level_key(tmp_path: Path) -> None:
    """The tenant's verb-grants.yaml, as text, repeats a key at the same nesting level (a
    second `cmdb:` block under dispositions, a copy-paste): `tenant.py check acme` exits 1
    naming verb-grants.yaml and the repeated key, never a traceback (PO-h). The positive
    control: the table before the edit is checked clean."""
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(_check_id(root))
    table = H.settings_dir(root) / "verb-grants.yaml"
    table.write_text(table.read_text(encoding="utf-8")
                     + "\n  cmdb:\n    get-host: {roles: [gather]}\n", encoding="utf-8")
    H.assert_refused(_check_id(root), "verb-grants.yaml", "cmdb")


def test_1120_s9_check_over_a_grant_table_that_fails_to_parse_as_yaml(tmp_path: Path) -> None:
    """The tenant's verb-grants.yaml is present and readable but is not valid YAML (a
    merge-conflict marker left in place): `tenant.py check acme` exits 1 naming verb-grants.yaml
    as unparseable, in its per-rule idiom, never a traceback. The positive control: the table
    before the edit is checked clean."""
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(_check_id(root))
    table = H.settings_dir(root) / "verb-grants.yaml"
    text = table.read_text(encoding="utf-8")
    table.write_text(text.replace("  cmdb:", "<<<<<<< HEAD\n  cmdb:", 1), encoding="utf-8")
    H.assert_refused(_check_id(root), "verb-grants.yaml")


def test_1120_s9_check_over_grant_table_verb_filed_under_wrong_real_system(
        tmp_path: Path) -> None:
    """A row names a genuinely declared verb but files it under a system other than the one
    that declares it: identity's list-authorized-hosts (declared by identity's adapter alone)
    moved under cmdb and dropped from identity. `tenant.py check acme` exits 1 reporting both
    the phantom pair cmdb.list-authorized-hosts and the undecided real pair
    identity.list-authorized-hosts — the census keys on (system, verb) pairs (PO-k). The
    positive control: the table before the move is checked clean."""
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


def test_1120_s9_check_run_twice_in_immediate_succession(tmp_path: Path) -> None:
    """`tenant.py check acme` over a clean tenant, run and then run again immediately with
    nothing else touching the data root: both runs exit 0 and give identical output, and check
    writes nothing, so the data root's census (bytes, mtimes, modes) is identical before and
    after both."""
    root = tmp_path / "data"
    H.adopted(root)
    before = H.tree_census(root)
    first, second = _check_id(root), _check_id(root)
    H.assert_clean(first)
    H.assert_clean(second)
    assert (first.returncode, first.stdout, first.stderr) == (
        second.returncode, second.stdout, second.stderr), "two checks of one tree disagree"
    assert H.census_diff(before, H.tree_census(root)) == [], "check wrote into the data root"


# ======================================================================================
# No data root for scaffold and check --folder (N10); the usage error (N17); M6's all-withheld.
# ======================================================================================

def test_1120_scaffold_and_check_folder_run_with_no_data_root_and_ignore_the_learning_overlap(
        tmp_path: Path) -> None:
    """`tenant.py scaffold acme <empty dir>` and `tenant.py check --folder <that dir>` never
    resolve the data root (N10): both exit 0 with DEFENDER_DATA_ROOT unset, and both exit 0
    again with DEFENDER_LEARNING_STATE_DIR overlapping a set data root. `tenant.py check acme`
    and `tenant.py setup acme` do resolve it, and inherit the learning-state-overlap refusal as
    run.py does: under the same overlap each exits 1 naming DEFENDER_LEARNING_STATE_DIR and
    writes nothing."""
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
    H.assert_refused(_check_id(root, **overlap), OVERLAP_ENV)
    H.assert_refused(H.setup(tenant_py, root, **overlap), OVERLAP_ENV)
    assert H.census_diff(before, H.tree_census(root)) == [], "a refused command wrote"


def test_1120_check_with_both_or_neither_selector_is_a_usage_error(tmp_path: Path) -> None:
    """`<id>` and `--folder` are mutually exclusive and exactly one is required (N17):
    `tenant.py check acme --folder <dir>` and a bare `tenant.py check` each exit 2 (a usage
    error, not a finding) and read or write nothing under the data root. The control carries
    the discrimination: each selector alone, `check acme` over a clean tenant and
    `check --folder` over a clean folder, is no usage error — each exits 0."""
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
    """A table that decides every declared pair and withholds every one (roles empty, each
    with a reason) is not a finding (M6): `tenant.py check acme` over a tenant carrying it,
    and `tenant.py check --folder` over a folder carrying it, both exit 0. The control: the
    same table with one pair (threat-intel.list-indicators) deleted exits 1 naming it — the
    census still runs over a withheld table."""
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


# ======================================================================================
# V10 (human, §7-verify round 2; extends V1 over M6): setup asks "can it run?", check asks "is
# it well-formed?". An all-withheld table grants gather nothing, so every run refuses it.
# ======================================================================================

def test_1120_setup_refuses_an_all_withheld_table_that_check_accepts(tmp_path: Path) -> None:
    """A verb-grants.yaml that decides every declared pair and withholds every one (the table
    the template ships) grants gather nothing, so require_gather_query refuses every run of
    the tenant. Setup refuses it (V10, human: setup refuses anything that would make a run
    refuse): a FIRST `tenant.py setup acme` over a placed knowledge/ carrying it exits 1 naming
    settings/verb-grants.yaml, writing nothing (no row; the refusal is not the one-tenant
    guard's), and a RE-RUN over a finished tenant whose table has since become it exits 1
    naming it, writing nothing. Check does not (M6 stands): `tenant.py check acme` over that
    same finished tenant exits 0. The positive control: the fixture's own table sets up."""
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
    assert not H.row_path(first).exists(), "a refused first setup left a row (MF1 Q2)"

    rerun = tmp_path / "rerun"
    H.place_knowledge(rerun)
    H.assert_clean(H.setup(tenant_py, rerun))
    _withhold_all(H.settings_dir(rerun))
    before = H.tree_census(rerun)
    H.assert_refused(H.setup(tenant_py, rerun), str(H.settings_dir(rerun) / "verb-grants.yaml"))
    assert H.census_diff(before, H.tree_census(rerun)) == [], "the refused re-run wrote something"
    H.assert_clean(_check_id(rerun))


# ======================================================================================
# V14 (human, §7-verify round 3; SUPERSEDES V1's and V10's rule lists): setup calls run start's
# own readiness function (`H.RUN_READINESS`), so any run-start refusal is setup's refusal, named
# (beside the folder rules — the settings files' parse, mapping.yaml included — V18 keeps).
# V1's lead-zero cells and V10's all-withheld cell above stay; this adds 92r2 #1's executed case
# and the words-for-words parity with run start. That setup REACHES the function (not a copy of
# its rules) is test_1120_censuses.py's census.
# ======================================================================================

def _gather_health_checks_only(settings: Path) -> None:
    """The template's table with every `health-check` row granted to gather and every other row
    still withheld: total (no gap), lead-zero clean and not all-withheld, yet gather holds no
    query verb, so require_gather_query refuses every run (92r2 #1, executed)."""
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


def _run_start_refusal(settings: Path) -> str:
    """What run start says about `settings`' table: the production `require_gather_query` over
    the production `run_grants` — the owner's own words, the oracle both entries must carry."""
    grants = verb_dispositions.run_grants(settings)
    with pytest.raises(verb_dispositions.DispositionError) as refused:
        verb_dispositions.require_gather_query(grants)
    return str(refused.value)


def test_1120_setup_refuses_a_health_check_only_gather_grant_that_check_accepts(
        tmp_path: Path) -> None:
    """The template's verb-grants.yaml with its health-check rows granted to gather: every
    declared pair decided, lead-zero clean, not all-withheld — yet gather holds no query verb,
    so require_gather_query refuses every run (92r2 #1, executed). Setup refuses it (V14, human:
    setup calls run start's own readiness function): a FIRST `tenant.py setup acme` over a placed
    knowledge/ carrying it exits 1 naming settings/verb-grants.yaml, writing nothing (no row;
    the refusal is not the one-tenant guard's), and a RE-RUN over a finished tenant whose table
    has since become it exits 1 naming it, writing nothing. Check does not (M6: well-formed):
    `tenant.py check acme` over that same finished tenant, and `check --folder` over its
    knowledge/, exit 0."""
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
    assert not H.row_path(first).exists(), "a refused first setup left a row (MF1 Q2)"

    rerun = tmp_path / "rerun"
    H.place_knowledge(rerun)
    H.assert_clean(H.setup(tenant_py, rerun))
    _gather_health_checks_only(H.settings_dir(rerun))
    before = H.tree_census(rerun)
    H.assert_refused(H.setup(tenant_py, rerun), str(H.settings_dir(rerun) / "verb-grants.yaml"))
    assert H.census_diff(before, H.tree_census(rerun)) == [], "the refused re-run wrote something"
    H.assert_clean(_check_id(rerun))
    H.assert_clean(_check_folder(H.knowledge_dir(rerun)))


RUN_START_REFUSED_TABLES = [
    pytest.param(_gather_health_checks_only, id="grant_census:health-check-only"),
    pytest.param(_withhold_all, id="grant_census:all-withheld"),
]


@pytest.mark.parametrize("table", RUN_START_REFUSED_TABLES)
def test_1120_setup_refuses_what_run_start_refuses_in_run_starts_own_words(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, table: Callable[[Path], None]) -> None:
    """Parity (V14: "any run-start refusal is setup's refusal, named"). Over one finished tenant
    whose table gather can query nothing through (health-check only, or all withheld), the
    production require_gather_query's message over the production run_grants is the oracle:
    `tenant.py setup acme` exits 1 carrying that message verbatim and writes nothing, and the
    REAL run.main (its seams recording) refuses the same tenant carrying the same message
    verbatim, before its preflight, materialize or lifecycle is reached. The lead-zero half of
    the readiness function is V1's cells; that setup reaches the function itself is the
    census's."""
    root = tmp_path / "data"
    H.adopted(root)
    settings = H.settings_dir(root)
    table(settings)
    owner = _run_start_refusal(settings)
    assert str(settings / "verb-grants.yaml") in owner, f"precondition: {owner!r}"

    before = H.tree_census(root)
    text = H.assert_refused(H.setup(tenant_py, root), str(settings / "verb-grants.yaml"))
    assert owner in text, (
        f"setup's refusal is not run start's, word for word (V14).\n  run start's readiness "
        f"says: {owner!r}\n  setup said: {text!r}")
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"

    monkeypatch.setenv(H.DATA_ROOT_ENV, str(root))
    rec = H.RunRecorder(tmp_path / "run")
    rc, exc = H.drive_run(run_py, [str(H.plant_alert(tmp_path / "in")), "--tenant", H.TID], rec)
    assert exc is not None, f"run.main started a run gather can query nothing in (rc {rc})"
    assert owner in H.exit_text(exc), (
        f"run.main's refusal does not carry its readiness function's words: "
        f"{H.exit_text(exc)!r}")
    assert not rec.spent, f"run.main spent a seam before refusing: {rec.order}"


# ======================================================================================
# V11 (human, §7-verify round 2; RELOCATES V2): "a clone's agent/.tenant-id must be committed"
# is check's rule — `check <id>` over a clone, `check --folder` over a git work tree — never
# acceptance's or setup's, which make no git call and check presence + match only (M8).
# ======================================================================================

def _decoy_repo(tmp_path: Path) -> Path:
    """A repo whose HEAD DOES commit agent/.tenant-id = acme — what an exported GIT_DIR would
    point check's git read at (J-PO1, executed: an exported GIT_DIR decides the repository
    whatever `cwd=` says)."""
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
    """knowledge/ is a git clone whose agent/.tenant-id holds exactly acme plus a newline, but
    its repo's HEAD does not commit that content: never added, added and never committed, or
    the repo commits beta's id (the wrong tenant's repo was cloned) and the operator
    overwrote it with acme's. Acceptance and setup check presence + match only and make no git
    call (V11): a row-less first `tenant.py setup acme` exits 0 and writes the row, and
    accept_tenant returns a Tenant. `tenant.py check acme` exits 1 naming agent/.tenant-id (D4's
    rule, now check's) — also with GIT_DIR exported at a repo that DOES commit acme, so the
    answer is the clone's own repo's (J-PO1); `tenant.py check --folder <knowledge>` over the
    clone, a git work tree as in tenant CI, exits 1 naming it. Neither stages, commits or edits
    anything in the clone: `git status --porcelain` is what it was. The positive controls: a
    clone committing acme's id checks clean both ways, and a plain folder carrying the same file
    (not a git work tree) checks clean with --folder."""
    root = tmp_path / "data"
    knowledge = H.clone_with_uncommitted_tenant_id(tmp_path / "src", root, how)
    named = H.TENANT_ID_FILE.as_posix()
    assert (knowledge / H.TENANT_ID_FILE).read_bytes() == f"{H.TID}\n".encode(), (
        "precondition: the bytes must match")
    status = H.git_status(knowledge)
    assert named in status, f"precondition: the clone's .tenant-id is not uncommitted:\n{status!r}"

    H.assert_clean(H.setup(tenant_py, root))
    assert H.row_path(root).is_file(), "setup refused a matching .tenant-id (V11: no git rule)"
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


# ======================================================================================
# V16 (human, §7-verify round 3, on 92r2 #3): when check's committed-.tenant-id git read cannot
# answer about a SOUND clone — git absent, git refusing the clone as dubious ownership, any git
# error — check exits 1 naming "cannot verify .tenant-id is committed" and git's reason. It never
# skips the rule. Setup makes no git call (V11), so its re-run over the same clone passes.
# ======================================================================================

#: A uid other than this process's, for a clone git refuses as "dubious ownership".
OTHER_UID = 1000

#: A fault is `(tmp_path, knowledge) -> (env for the faulted run, a pattern for git's reason,
#: repair)`.
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
    pytest.param(_owned_by_another_uid, id="git:dubious-ownership", marks=pytest.mark.skipif(
        os.geteuid() != 0,
        reason="a clone owned by another uid needs root to chown; CI runs non-root")),
    pytest.param(_unreadable_git_config, id="git:read-error"),
]


@pytest.mark.parametrize("fault", GIT_CANNOT_ANSWER)
def test_1120_check_fails_closed_when_git_cannot_say_the_tenant_id_is_committed(
        tmp_path: Path, fault: GitFault) -> None:
    """A SOUND finished tenant — knowledge/ a clone whose repo commits agent/.tenant-id = acme —
    while git cannot answer about it: no git on PATH; the clone owned by another uid, which git
    refuses as dubious ownership (built with chown, so it runs only as root and is skipped in
    CI); or a .git/config git cannot parse. `tenant.py check acme` and `tenant.py check
    --folder <knowledge>` each exit 1 naming "cannot verify .tenant-id is committed" and git's
    reason (git, dubious ownership, bad config) — V16, human: never a skip, never exit 0. A
    re-run of `tenant.py setup acme` in the same state exits 0 and writes nothing (setup makes no
    git call, V11). The positive control: the fault repaired, both checks exit 0."""
    root = tmp_path / "data"
    knowledge = H.cloned_tenant(tmp_path / "src", root)
    H.plant_row(root)
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


# ======================================================================================
# #1159 (human, 2026-10-03): a census the RUNNING checkout cannot take stays a finding — exit
# EXACTLY 1, every other finding still printed (O2, as V16's "cannot verify" is) — but its line
# says which side failed (O1): the running checkout's root, nothing in the checked folder at
# fault, then `CensusUnavailable`'s own text verbatim. The claim is the census line's alone: no
# finding about the folder carries it, nor V16's line, whose cause can lie on either side. The
# broken-adapter cell is test_1120_check_exits_non_zero_naming_an_adapter_module_that_fails_to_import.
# ======================================================================================

def test_1159_check_without_git_names_the_running_checkout_and_exits_1(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no git on PATH the running checkout cannot take the grant census (its marker half
    is a committed-tree read). Over a SOUND plain folder, `tenant.py check --folder` exits
    exactly 1 with the census line alone (#1159 K1: a plain folder is exempt from V16). Over a
    SOUND clone committing acme's id (K2), `check --folder <knowledge>` and `check acme` each
    exit exactly 1 printing BOTH the census line and V16's "cannot verify .tenant-id is
    committed: git is not available on PATH" line (O2), and V16's line does not carry the
    not-at-fault claim. Every census line names this checkout's root (the one `tenant.py` runs
    from), not the folder, says nothing in the checked folder is at fault, and carries the
    owner's "cannot resolve the declared systems: git is not available on PATH (…)" verbatim
    (O1). The positive control: git back on PATH, all three checks exit 0 printing nothing."""
    folder = _folder(tmp_path, "tenant")
    root = tmp_path / "data"
    knowledge = H.cloned_tenant(tmp_path / "src", root)
    H.plant_row(root)
    env, _reason, _repair = _git_absent(tmp_path, knowledge)
    cause = _census_unavailable(H.REPO_ROOT, monkeypatch, **env)
    assert "git is not available on PATH" in cause, f"precondition: the census's cause: {cause!r}"

    text, _line = _census_blind_line(
        _check_folder(folder, **env), checkout=H.REPO_ROOT, cause=cause, folder=folder)
    assert H.CANNOT_VERIFY_TENANT_ID not in text, (
        f"a plain folder (no git work tree) is exempt from the committed-.tenant-id rule:\n{text}")

    for proc in (_check_folder(knowledge, **env), _check_id(root, **env)):
        text, _line = _census_blind_line(proc, checkout=H.REPO_ROOT, cause=cause,
                                         folder=knowledge, also=(H.CANNOT_VERIFY_TENANT_ID,))
        unverified = [ln for ln in text.splitlines() if H.CANNOT_VERIFY_TENANT_ID in ln]
        assert len(unverified) == 1, f"V16's line is not printed once (#1159 O2):\n{text}"
        assert cause not in unverified[0], (
            f"V16's line is not its own line beside the census line (#1159 O2):\n{text}")
        assert "git is not available on PATH" in unverified[0], (
            f"V16's line no longer gives git's reason:\n{text}")
        assert not NOT_THE_FOLDERS_FAULT.search(unverified[0]), (
            f"V16's line claims the folder is not at fault; its cause can lie on either side "
            f"(#1159 non-obligation):\n{text}")

    for proc in (_check_folder(folder), _check_folder(knowledge), _check_id(root)):
        text = H.assert_clean(proc)
        assert "[tenant.py]" not in text, f"a clean check printed a finding:\n{text}"


def test_1159_only_the_census_blind_line_says_the_folder_is_not_at_fault(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The not-at-fault claim names the census line's side and is never pasted onto a finding
    about the folder. A folder genuinely at fault — its table leaves host-state.passwd undecided
    and its case-history mapping.yaml does not parse — checked with the census taken: exit 1
    naming both, and no line says the folder is not at fault. The same folder with no git on
    PATH (census blind): exit exactly 1, the mapping.yaml finding still printed beside the
    census line (#1159 O2), and the census line is the ONLY line carrying the claim (O1). The
    positive control: the folder before the faults checks clean."""
    folder = _folder(tmp_path, "tenant")
    H.assert_clean(_check_folder(folder))
    gap = _grant_gap(folder)
    mapping = folder / "settings" / "systems" / "case-history" / "mapping.yaml"
    mapping.write_text("fields: {unclosed: [\n", encoding="utf-8")

    text = H.assert_refused(_check_folder(folder), gap, str(mapping))
    claimed = [ln for ln in text.splitlines() if NOT_THE_FOLDERS_FAULT.search(ln)]
    assert claimed == [], f"a finding ABOUT the folder says the folder is not at fault:\n{text}"

    env, _reason, _repair = _git_absent(tmp_path, folder)
    cause = _census_unavailable(H.REPO_ROOT, monkeypatch, **env)
    text, line = _census_blind_line(_check_folder(folder, **env), checkout=H.REPO_ROOT,
                                    cause=cause, folder=folder, also=(str(mapping),))
    claimed = [ln for ln in text.splitlines() if NOT_THE_FOLDERS_FAULT.search(ln)]
    assert claimed == [line], (
        f"the not-at-fault claim is not the census line's alone (#1159 O1):\n{text}")
