"""#1120 piece 1 — D1/D2: the operator commands and the settings loaders read the DATA ROOT's copy.

After piece 1 a tenant's settings live under `<data root>/<T>/knowledge/settings/`, and every
operator command that takes `--tenant` (`policy_cli gather`, `validate_scaffold`) resolves the data root once and accepts its tenant through
`accept_tenant` — never through the checkout's `knowledge/tenants/`, and never from a root
derived off `$DEFENDER_DIR` (C11). A refusal is `accept_tenant`'s `TenantRefused`, surfaced in
each command's own idiom (M7: `validate_scaffold` is advisory and prints it as a WARN), never a
traceback. The settings loaders that survive the move unchanged take the folder as a parameter,
so each is handed the ACCEPTED tenant's `settings` and must read the file there (R7).

The checkout's lab is retired (human, PR #1157: #1158 folded in), so the scenarios that ask
"which copy was read" use the id `playground` in the data root with settings that DIFFER from
the committed fixture's (the lab's frozen copy): a gather grant, a `config.env` marker, a
missing config key, and assert nothing under the checkout's `knowledge/` was reported.
Commands with no argv parameter (`validate_scaffold`, the census lint) run as processes;
`policy_cli`, `run.main` and the launcher are driven in-process through their own seams.
`ticket_adapter` is no operator command: #1107 removed its command line (fork
TICKET-ADAPTER-CLI-REMOVED-BY-1107), so the legs that drove it are gone. See `_spec1120.py`
for the coined names.
"""
from __future__ import annotations

import functools
import shutil
from pathlib import Path
from typing import Any

import pytest

from defender import _tenant
from defender import run as run_py
from defender.learning.branch import cli as branch_cli
from defender.learning.branch import staging
from defender.learning.branch.estate.stagers import elastic as elastic_stager
from defender.runtime import box as box_mod
from defender.runtime import box_codec, lead_zero_config, verb_dispositions
from defender.runtime.verbs import VerbContext
from defender.scripts import policy_cli
from defender.scripts import tenant as tenant_py
from defender.scripts.adapters import _stub_transport, elastic_adapter
from defender.scripts.case_history import case_ticket
from defender.skills.connect import validate_scaffold
from defender.tests import _tenants1106 as T1106
from defender.tests import _triplet_947 as T947
from defender.tests.tenant_1078_pass_a import _spec1078 as H78
from defender.tests.tenant_1120_piece1 import _spec1120 as H

#: The census lint, a repo script outside `defender/` (driven by path).
CENSUS_LINT = H.REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"

#: A table that loads but grants gather no query verb — a table that DIFFERS from the fixture's
#: (the fixture grants gather dozens of query verbs), so a command that builds gather's grant from
#: it is refused naming it, and one that read a checkout copy would not be.
HEALTH_CHECK_ONLY_TABLE = "dispositions:\n  cmdb:\n    health-check: {roles: [gather]}\n"

#: A `verb-grants.yaml` that is not YAML (an unclosed flow mapping) — the unloadable table.
UNPARSEABLE_TABLE = "dispositions:\n  cmdb:\n    health-check: {roles: [gather]\n"

#: The fixture's withheld `cmdb.list-roles` row; the loader test's data-root
#: table grants it instead, so a grant for it can only have come from the data-root copy.
CMDB_LIST_ROLES_WITHHELD = (
    '    list-roles:\n      roles: []\n'
    '      reason: "in the registry, exercised by no template and no run (c18/#632)"\n')

#: The row `validate_scaffold` prints once it has checked a clean `config.env`.
CONFIG_CHECKED = "config.env carries no inline secrets"

#: The WARN / FAIL glyphs `validate_scaffold.Report` prints each row with.
WARN_ROW, FAIL_ROW = "[!]", "[✗]"


# ======================================================================================
# Same-file helpers.
# ======================================================================================

def _ticket_config(settings: Path) -> Path:
    return settings / "systems" / "ticket" / "config.env"


def _mark_ticket_config(settings: Path, marker_key: str, *, drop_timeout: bool) -> Path:
    """Give a tenant's ticket `config.env` an inline-secret MARKER line (a key
    `validate_scaffold` FAILs by name) and, with `drop_timeout`, lose the required
    `TICKET_TIMEOUT_SEC`."""
    path = _ticket_config(settings)
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines(keepends=True)
             if not (drop_timeout and ln.startswith("TICKET_TIMEOUT_SEC"))]
    path.write_text("".join(lines) + f'{marker_key}="inline-marker-{marker_key.lower()}"\n',
                    encoding="utf-8")
    return path


def _other_tree(tmp_path: Path, tenant_id: str, marker_key: str) -> Path:
    """Another checkout's `defender/` whose `knowledge/tenants/<tenant_id>` holds a COMPLETE
    tenant folder carrying `marker_key` in its ticket config — what a command would find if it
    derived its tenants root from an exported `$DEFENDER_DIR`. Returns its `defender/`."""
    other = tmp_path / "other-checkout"
    (other / "defender").mkdir(parents=True)
    folder = other / "knowledge" / "tenants" / tenant_id
    shutil.copytree(H.FIXTURE, folder)
    _mark_ticket_config(folder / "settings", marker_key, drop_timeout=True)
    return other / "defender"


def _validate_scaffold(root: Path | None, tenant_id: str, **kw: Any) -> Any:
    """`validate_scaffold.py ticket --tenant <id>`, as the operator runs it."""
    return H.run_script(H.script_of(validate_scaffold), "ticket", "--tenant", tenant_id,
                        root=root, **kw)


def _rows(text: str, glyph: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith(glyph)]


def _policy_gather(tmp_path: Path, tenant_id: str) -> tuple[int | None, str]:
    """`defender-policy show gather --tenant <id>` in-process: `(exit status, None-or-text)`
    — a `sys.exit(msg)` refusal comes back as `(None, msg)`."""
    try:
        return policy_cli.main(
            ["show", "gather", "--run-dir", str(tmp_path / "policy-run"), "--tenant",
             tenant_id]), ""
    except SystemExit as refused:
        return None, H.exit_text(refused)


def _census_lint(repo: Path) -> Any:
    return H.run_script(CENSUS_LINT, "--root", str(repo), root=None)


# ======================================================================================
# D1 — the operator commands read the data root's tenant.
# ======================================================================================

def test_1120_operator_commands_read_the_data_root_tenants_settings_not_the_checkouts(
        data_root: Path, tmp_path: Path, capsys) -> None:
    """The lab is retired (human, PR #1157: #1158 folded in); the checkout's knowledge/
    holds only the template and the fixture, a complete copy of the lab's settings. Under
    DEFENDER_DATA_ROOT the tenant playground has knowledge/settings that differ: a
    verb-grants.yaml granting gather only a health-check, and a systems/ticket/config.env
    carrying a distinct marker key and lacking TICKET_TIMEOUT_SEC. In that setup policy_cli
    gather --tenant playground builds gather's grant from the data-root table (refused naming
    <root>/playground/knowledge/settings/verb-grants.yaml, where the fixture's table would build a
    policy; with the fixture's table put back it builds one); and validate_scaffold ticket --tenant playground checks the data-root config.env (it
    FAILs the data-root marker key). None of them reads the checkout's knowledge/, and none
    derives a root from DEFENDER_DIR: with DEFENDER_DIR exported naming another tree that holds
    its own playground folder, the other tree's marker is never reported."""
    tid = "playground"
    H.adopted(data_root, tid)
    settings = H.settings_dir(data_root, tid)
    (settings / "verb-grants.yaml").write_text(HEALTH_CHECK_ONLY_TABLE, encoding="utf-8")
    _mark_ticket_config(settings, "TICKET_SPEC1120_DATA_ROOT_TOKEN", drop_timeout=True)
    other_defender = _other_tree(tmp_path, tid, "TICKET_SPEC1120_OTHER_TREE_TOKEN")
    table = settings / "verb-grants.yaml"

    # policy_cli: the data-root table decides gather's grant.
    rc, text = _policy_gather(tmp_path, tid)
    assert rc is None, "policy_cli built gather's policy from a table that grants it no query"
    assert str(table) in text, f"policy_cli's refusal does not name the data-root table:\n{text}"
    assert str(H.KNOWLEDGE_ROOT) not in text, f"policy_cli read the checkout's knowledge/:\n{text}"
    shutil.copyfile(H.FIXTURE / "settings" / "verb-grants.yaml", table)
    rc, text = _policy_gather(tmp_path, tid)
    assert rc == 0, f"policy_cli refused the data-root tenant's granting table: {text}"
    assert "agent: gather" in capsys.readouterr().out

    for defender_dir_env in ({}, {"DEFENDER_DIR": str(other_defender)}):
        unset = ("DEFENDER_DIR",) if not defender_dir_env else ()
        # validate_scaffold: the data-root config.env is the one checked.
        out = H.output(_validate_scaffold(data_root, tid, unset=unset, **defender_dir_env))
        assert "Traceback (most recent call last)" not in out, out
        assert any("TICKET_SPEC1120_DATA_ROOT_TOKEN" in row for row in _rows(out, FAIL_ROW)), (
            f"validate_scaffold did not check the data-root config.env ({defender_dir_env}):"
            f"\n{out}")
        assert "OTHER_TREE" not in out, out
        assert str(H.KNOWLEDGE_ROOT) not in out, out


def test_1120_validate_scaffold_and_the_census_lint_surface_tenant_refused_without_a_traceback(
        data_root: Path, tmp_path: Path) -> None:
    """validate_scaffold and the census lint catch TenantRefused (not only the removed
    TenantDirError) and surface its message in their own idiom, never a traceback. For a tenant
    whose knowledge/ is a symlink to a complete folder elsewhere, validate_scaffold ticket
    --tenant acme prints accept_tenant's refusal verbatim as a WARN and skips the tenant's
    config check (M7). The census lint, over a tmp repo whose knowledge/tenant-fixture/agent/
    holds a symlink, exits non-zero naming the fixture folder and the link. Positive controls:
    with the real folder in place, validate_scaffold checks that config.env; the lint over the
    unplanted repo exits 0. (ticket_adapter's leg is gone with its command line, #1107.)"""
    elsewhere = tmp_path / "elsewhere" / "knowledge"
    shutil.copytree(H.FIXTURE, elsewhere)
    H.write_tenant_id_file(elsewhere, H.TID, "id")
    _mark_ticket_config(elsewhere / "settings", "TICKET_SPEC1120_CONTROL_TOKEN",
                        drop_timeout=True)
    H.plant_row(data_root)
    link = H.knowledge_dir(data_root)
    link.symlink_to(elsewhere, target_is_directory=True)
    owner = H.accept_refusal(_tenant, data_root, H.TID)

    scaffold = _validate_scaffold(data_root, H.TID)
    H.assert_ran(scaffold)
    warned = _rows(H.output(scaffold), WARN_ROW)
    assert any(owner in row for row in warned), (
        f"validate_scaffold did not print accept_tenant's refusal as a WARN:\n"
        f"{H.output(scaffold)}")
    assert not any(owner in row for row in _rows(H.output(scaffold), FAIL_ROW))
    assert "TICKET_SPEC1120_CONTROL_TOKEN" not in H.output(scaffold), (
        "validate_scaffold checked the config of a tenant acceptance refused")

    # The positive control: the same folder, placed for real.
    link.unlink()
    shutil.move(str(elsewhere), str(link))
    scaffold = _validate_scaffold(data_root, H.TID)
    H.assert_ran(scaffold)
    assert "TICKET_SPEC1120_CONTROL_TOKEN" in H.output(scaffold), H.output(scaffold)

    # The census lint over a tmp repo whose fixture folder acceptance's folder rules refuse.
    repo = H.tmp_checkout(tmp_path / "repo")
    lint = _census_lint(repo)
    H.assert_ran(lint)
    assert lint.returncode == 0, f"the census lint refuses the clean checkout:\n{H.output(lint)}"
    agent_link = repo / "knowledge" / "tenant-fixture" / "agent" / "spec1120-link.md"
    outside = tmp_path / "outside" / "not-the-fixtures.md"
    outside.parent.mkdir()
    outside.write_text("not the fixture's bytes\n", encoding="utf-8")
    agent_link.symlink_to(outside)
    lint = _census_lint(repo)
    H.assert_ran(lint)
    assert lint.returncode != 0, f"the census lint passed a fixture with a link:\n{H.output(lint)}"
    assert "tenant-fixture" in H.output(lint), H.output(lint)
    assert "spec1120-link.md" in H.output(lint), H.output(lint)


def test_1120_s6_validate_scaffold_env_mutation_persists_across_calls(
        data_root: Path, tmp_path: Path) -> None:
    """validate_scaffold sets DEFENDER_DIR by setdefault, so a value from a first call may
    persist into a second (modelled here by exporting DEFENDER_DIR, naming another tree that
    holds its own acme and beta folders, into two successive calls). The tenant and settings
    each call validates still come only from DEFENDER_DATA_ROOT and that call's own --tenant,
    never from DEFENDER_DIR (C11): the first call, over a data root holding acme, checks
    acme's data-root config.env; the second, over another data root holding beta, checks
    beta's — and neither reports a marker of the DEFENDER_DIR tree's copies."""
    roots = {H.TID: data_root, H.OTHER: tmp_path / "second-data-root"}
    other_defender = _other_tree(tmp_path, H.TID, "TICKET_SPEC1120_OTHER_ACME_TOKEN")
    beta_folder = other_defender.parent / "knowledge" / "tenants" / H.OTHER
    shutil.copytree(H.FIXTURE, beta_folder)
    _mark_ticket_config(beta_folder / "settings", "TICKET_SPEC1120_OTHER_BETA_TOKEN",
                        drop_timeout=True)
    for tid, root in roots.items():
        H.adopted(root, tid)
        _mark_ticket_config(H.settings_dir(root, tid), f"TICKET_SPEC1120_ROOT_{tid.upper()}_TOKEN",
                            drop_timeout=False)

    for tid, root in roots.items():
        out = H.output(_validate_scaffold(root, tid, DEFENDER_DIR=str(other_defender)))
        assert "Traceback (most recent call last)" not in out, out
        fails = _rows(out, FAIL_ROW)
        assert any(f"TICKET_SPEC1120_ROOT_{tid.upper()}_TOKEN" in row for row in fails), (
            f"validate_scaffold --tenant {tid} did not check {tid}'s data-root config.env:\n{out}")
        assert "_OTHER_" not in out, (
            f"validate_scaffold --tenant {tid} read a tenant folder under DEFENDER_DIR's tree:\n"
            f"{out}")
        other_tid = next(t for t in roots if t != tid)
        assert f"ROOT_{other_tid.upper()}_TOKEN" not in out, out


def test_1120_s6_operator_tools_in_a_shell_without_the_data_root(
        data_root: Path, tmp_path: Path, monkeypatch) -> None:
    """With DEFENDER_DATA_ROOT unset, validate_scaffold --tenant and policy_cli gather --tenant
    each report resolve_data_root's refusal naming the variable. Neither falls back to the
    checkout — the id used, playground, is the lab's own. policy_cli exits non-zero; validate_scaffold is advisory (M7): it prints the refusal as
    a WARN, never a FAIL, and checks no config.env. The positive controls: with the data root
    set, validate_scaffold checks the tenant's config.env and policy_cli builds the policy."""
    tid = "playground"
    H.adopted(data_root, tid)

    scaffold = _validate_scaffold(None, tid)
    H.assert_ran(scaffold)
    out = H.output(scaffold)
    assert any(H.DATA_ROOT_ENV in row for row in _rows(out, WARN_ROW)), (
        f"validate_scaffold did not WARN naming {H.DATA_ROOT_ENV}:\n{out}")
    assert not any(H.DATA_ROOT_ENV in row for row in _rows(out, FAIL_ROW)), out
    assert CONFIG_CHECKED not in out, (
        f"validate_scaffold checked a config.env without a data root:\n{out}")
    monkeypatch.delenv(H.DATA_ROOT_ENV, raising=False)
    rc, text = _policy_gather(tmp_path, tid)
    assert rc is None, f"policy_cli gather built a policy without a data root: {rc}"
    assert H.DATA_ROOT_ENV in text, (
        f"policy_cli gather did not refuse naming {H.DATA_ROOT_ENV}: {text!r}")

    scaffold = _validate_scaffold(data_root, tid)
    H.assert_ran(scaffold)
    assert CONFIG_CHECKED in H.output(scaffold), H.output(scaffold)
    monkeypatch.setenv(H.DATA_ROOT_ENV, str(data_root))
    rc, text = _policy_gather(tmp_path, tid)
    assert rc == 0, f"policy_cli refused a tenant under a set data root: {text}"


# ======================================================================================
# D7/M6 — an unloadable grant table: check and every table-loading consumer refuse it.
# ======================================================================================

class _SpawnRecorder:
    """The launcher's `spawn=` seam: records, never spawns."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple, dict]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> int:
        self.calls.append((args, kwargs))
        return 0


def _launcher_source(root: Path) -> Path:
    """A finished, branchable source run at `<root>/acme/runs/<id>`, its runs-base record
    naming acme (pass-A's source-run builder, at a tenant location)."""
    base = root / H.TID / "runs"
    H78.plant_record(base, H.TID)
    return H78.source_run(base)


def _launch(source: Path) -> BaseException | int:
    """The REAL branch launcher over `source`, with no `--tenants-root` (piece 1 removes it),
    the role preflight neutralised and the spawn recorded."""
    spawn = _SpawnRecorder()
    try:
        return branch_cli.main(
            [str(source), str(T947.BRANCH_MESSAGE_ID), "--continuation-prompt",
             "Continue from here."], spawn=spawn, preflight=T947.no_preflight)
    except SystemExit as refused:
        return refused
    finally:
        assert spawn.calls == [], "the launcher spawned a sibling over an unloadable table"


def test_1120_check_and_every_table_loading_consumer_refuse_an_unloadable_grant_table(
        data_root: Path, tmp_path: Path, capsys) -> None:
    """A tenant whose settings/verb-grants.yaml does not parse as YAML: tenant.py check acme
    exits 1 naming verb-grants.yaml (M6: a malformed table is a named finding, never a
    traceback). run.main (before anything is spent), the branch launcher, policy_cli gather
    and tenant.py setup (NF1: "the settings tables load") each refuse naming the file, and
    setup writes nothing. validate_scaffold never loads the table and accepts the tenant: it
    proceeds past acceptance to its own work and does not mention verb-grants.yaml. (held_out takes no tenant and generate_case is removed — human, PR
    #1157.)"""
    # rejected: an all-withheld table as a finding (M6, human).
    H.adopted(data_root)
    table = H.settings_dir(data_root) / "verb-grants.yaml"
    table.write_text(UNPARSEABLE_TABLE, encoding="utf-8")
    _mark_ticket_config(H.settings_dir(data_root), "TICKET_SPEC1120_UNLOADABLE_TOKEN",
                        drop_timeout=True)

    H.assert_refused(H.check(tenant_py, data_root, H.TID), "verb-grants.yaml")

    rec = H.RunRecorder(tmp_path / "run")
    rc, exc = H.drive_run(run_py, [str(H.plant_alert(tmp_path / "in")), "--tenant", H.TID],
                          rec)
    assert rc is None, f"run.main ran over an unloadable table: rc={rc}"
    assert str(table) in H.exit_text(exc), (
        f"run.main did not refuse the unloadable table naming it: {H.exit_text(exc)!r}")
    assert not rec.spent, f"run.main spent before refusing the table: {rec.order}"

    launched = _launch(_launcher_source(data_root))
    assert isinstance(launched, SystemExit), f"the launcher did not refuse: {launched!r}"
    assert str(table) in H.exit_text(launched), (
        f"the launcher did not refuse the unloadable table naming it: {launched!r}")

    rc, text = _policy_gather(tmp_path, H.TID)
    assert rc is None, f"policy_cli built gather's policy over an unloadable table: {rc}"
    assert str(table) in text, f"policy_cli did not refuse naming the table: {text!r}"

    setup_root = tmp_path / "setup-root"
    H.place_knowledge(setup_root)
    (H.settings_dir(setup_root) / "verb-grants.yaml").write_text(UNPARSEABLE_TABLE,
                                                                 encoding="utf-8")
    before = H.tree_census(setup_root)
    H.assert_refused(H.setup(tenant_py, setup_root), "verb-grants.yaml")
    assert H.census_diff(before, H.tree_census(setup_root)) == [], "the refused setup wrote"

    # The consumer that never loads the table accepts the tenant.
    capsys.readouterr()
    out = H.output(_validate_scaffold(data_root, H.TID))
    assert "TICKET_SPEC1120_UNLOADABLE_TOKEN" in out, (
        f"validate_scaffold did not check the tenant's config:\n{out}")
    assert "verb-grants.yaml" not in out, out


# ======================================================================================
# D2 / O1 — the box: the tenant's agent half from under the data root, never its settings.
# ======================================================================================

def _mount_specs(argv: list[str]) -> list[dict[str, str]]:
    """Every `--mount` of a `docker run` argv as its key/value fields."""
    specs = []
    for flag, value in zip(argv, argv[1:], strict=False):
        if flag == "--mount":
            specs.append(dict(field.partition("=")[::2] for field in value.split(",")))
    return specs


def _exposes(source: Path, forbidden: Path) -> bool:
    """A bind of `source` shows `forbidden` inside the box: it is `forbidden` or an ancestor."""
    source, forbidden = source.resolve(), forbidden.resolve()
    return source == forbidden or source in forbidden.parents


def test_1120_the_run_box_mounts_the_tenants_agent_half_from_under_the_data_root_and_never_settings(
        data_root: Path, tmp_path: Path) -> None:
    """run.py calls start_box with the accepted tenant's agent half,
    <root>/acme/knowledge/agent (the tenant's knowledge a local git clone here, so its .git
    exists). The docker run argv composed for that call binds that source read-only at
    /tenant/agent, the target that stays in piece 1 (RF5), and no mount source equals, or is an
    ancestor of, the tenant's settings/, its knowledge/.git, or its knowledge/ folder."""
    H.cloned_tenant(tmp_path, data_root)
    H.plant_row(data_root)
    started: list[tuple[tuple, dict]] = []

    def start_box(*args: Any, **kwargs: Any) -> Any:
        started.append((args, kwargs))
        return box_mod.unboxed_executor()

    lifecycle = functools.partial(
        run_py._run_investigation_lifecycle,
        investigate=lambda **_kw: {"output": "spec1120", "requests": 0,
                                    "truncated_by": None},
        start_box=start_box, stop_box=lambda *a, **k: None, scrub=lambda tree: None)
    rec = H.RunRecorder(tmp_path / "run")
    try:
        rc = run_py.main([str(H.plant_alert(tmp_path / "in")), "--tenant", H.TID, "--no-learn"],
                         **{**rec.seams(), "lifecycle": lifecycle})
    except SystemExit as refused:
        pytest.fail(f"run.main refused a finished tenant: {H.exit_text(refused)}")
    assert rc == 0
    assert len(started) == 1, started
    agent = Path(started[0][1]["tenant_agent"])
    assert agent.resolve() == H.agent_dir(data_root).resolve(), (
        f"start_box was handed {agent}, not the data root's {H.agent_dir(data_root)}")

    argv = box_mod._create_argv(
        "defender-run-spec1120", tmp_path / "run", H.DEFENDER,
        box_mod.DEFAULT_SPEC, (), tenant_agent=agent).argv
    mounts = _mount_specs(argv)
    agent_mounts = [m for m in mounts if m.get("target") == str(box_mod.TENANT_AGENT_TARGET)]
    assert len(agent_mounts) == 1, mounts
    assert Path(agent_mounts[0]["source"]).resolve() == H.agent_dir(data_root).resolve()
    assert "readonly" in agent_mounts[0], agent_mounts
    for m in mounts:
        for forbidden in (H.settings_dir(data_root), H.knowledge_dir(data_root) / ".git",
                          H.knowledge_dir(data_root)):
            assert not _exposes(Path(m["source"]), forbidden), (
                f"the bind of {m['source']} exposes {forbidden} inside the box")
    # The control on the same predicate: the agent bind does expose the agent half.
    assert _exposes(Path(agent_mounts[0]["source"]), H.agent_dir(data_root))


def test_1120_an_agent_half_off_every_shared_mount_is_refused_naming_the_data_root_not_the_tenants_root(
        tmp_path: Path) -> None:
    """When the driver shares paths with the docker daemon (docker-outside-of-Docker, C46) and
    the tenant's agent half, <root>/acme/knowledge/agent, lies on none of them while the run
    dir and the defender dir do, composing the box's docker run refuses with BoxFault naming
    the agent half — and its remedy names DEFENDER_DATA_ROOT and never "the tenants root",
    which piece 1 removes (F13's refusal-wording consequence, V7). Reading of the remedy: the
    agent half now lives under the data root, beside the run dir whose remedy is already "Set
    DEFENDER_DATA_ROOT to a path", so moving it means moving the data root. The positive
    control: the same tenant with its data root under the shared mount composes (no refusal),
    so the refusal was the agent half's coverage."""
    shared = tmp_path / "shared"
    mounts = ((shared, tmp_path / "daemon-side"), (H.DEFENDER, H.DEFENDER))
    off_mount = tmp_path / "data"
    agent = H.agent_dir(off_mount)
    with pytest.raises(box_mod.BoxFault) as refused:
        box_mod._create_argv("defender-run-spec1120", shared / "run", H.DEFENDER,
                             box_mod.DEFAULT_SPEC, mounts, tenant_agent=agent)
    text = str(refused.value)
    assert str(agent) in text, f"the refusal does not name the agent half {agent}:\n{text}"
    assert "tenants root" not in text, (
        f"the remedy still names the tenants root piece 1 removes:\n{text}")
    assert H.DATA_ROOT_ENV in text, (
        f"the remedy does not tell the operator to move {H.DATA_ROOT_ENV}, under which the "
        f"agent half now lives:\n{text}")

    on_mount = shared / "data"
    box_mod._create_argv("defender-run-spec1120", shared / "run", H.DEFENDER,
                         box_mod.DEFAULT_SPEC, mounts, tenant_agent=H.agent_dir(on_mount))


def test_1120_no_tenant_or_data_root_key_enters_the_box_env(tmp_path: Path) -> None:
    """No key of BOX_ENV_ALLOWLIST names the tenant or the data root: no DEFENDER_DATA_ROOT and
    no key containing TENANT (C13 — a child learns its tenant from --tenant and the data root
    from its own environment, never from the box). The box env rendered from a request env
    that carries DEFENDER_DATA_ROOT and a tenant key drops both, and the docker run argv's
    --env keys are the allowlist's. The positive control: the allowlist carries DEFENDER_DIR,
    and the rendered env keeps it."""
    allow = box_codec.BOX_ENV_ALLOWLIST
    assert "DEFENDER_DIR" in allow
    assert H.DATA_ROOT_ENV not in allow, allow
    assert not [k for k in allow if "TENANT" in k.upper()], allow

    request = {H.DATA_ROOT_ENV: str(tmp_path / "data"), "DEFENDER_TENANT": H.TID,
               "DEFENDER_DIR": "/request/defender"}
    rendered = box_mod._render_env(request, tmp_path / "work")
    assert H.DATA_ROOT_ENV not in rendered, rendered
    assert "DEFENDER_TENANT" not in rendered, rendered
    assert "DEFENDER_DIR" in rendered, rendered

    argv = box_mod._create_argv(
        "defender-run-spec1120", tmp_path / "run", H.DEFENDER,
        box_mod.DEFAULT_SPEC, ()).argv
    env_keys = {v.partition("=")[0] for f, v in zip(argv, argv[1:], strict=False) if f == "--env"}
    assert env_keys == set(allow), env_keys


# ======================================================================================
# R7 — the settings loaders that survive the move read the ACCEPTED tenant's settings.
# ======================================================================================

def test_1120_every_settings_loader_reads_the_accepted_tenants_settings(
        data_root: Path, tmp_path: Path, monkeypatch) -> None:
    """Every settings-half loader that survives the move unchanged is handed the accepted
    Tenant's settings folder, <root>/acme/knowledge/settings, and reads the file there — never
    a checkout copy: verb_dispositions.run_grants (the data-root table's extra
    cmdb.list-roles grant) and dispositions_path; lead_zero_config.lead_zero_config_path;
    case_ticket._mapping_path; and validate_scaffold.check_config (it FAILs the data-root
    marker key). The system configs are read once, into the run's tenant record (#1107), from
    that same folder: elastic_adapter.load_config (the data-root cluster marker) and
    _stub_transport.load_config (the data-root ticket marker) for a VerbContext carrying the
    record; the elastic stager's configured_patterns over the record's Elastic view (the
    data-root index markers); staging.write_door_from_env over staging.host_context (the
    data-root cluster marker as the door's base URL). A loader that resolves anywhere else is
    the R7 escape this pins."""
    for key in ("ELASTICSEARCH_URL", "ELASTIC_SSL_VERIFY", "ELASTIC_EVENTS_INDEX",
                "ELASTIC_ALERTS_INDEX", "TICKET_URL_BASE", "TICKET_BASTION_HOST",
                "TICKET_TIMEOUT_SEC", "TICKET_KEY_PATTERN"):
        monkeypatch.delenv(key, raising=False)
    H.adopted(data_root)
    expected = H.settings_dir(data_root)
    table = expected / "verb-grants.yaml"
    text = table.read_text(encoding="utf-8")
    assert CMDB_LIST_ROLES_WITHHELD in text, "the fixture no longer withholds cmdb.list-roles"
    table.write_text(text.replace(CMDB_LIST_ROLES_WITHHELD,
                                  "    list-roles: {roles: [gather]}\n", 1), encoding="utf-8")
    elastic = expected / "systems" / "elastic" / "config.env"
    elastic.write_text(
        'ELASTICSEARCH_URL="https://spec1120-acme-cluster:9200"\n'
        'ELASTIC_EVENTS_INDEX="spec1120-acme-events-*"\n'
        'ELASTIC_ALERTS_INDEX="spec1120-acme-alerts-*"\n'
        'ELASTIC_SSL_VERIFY="false"\n'
        'KIBANA_URL="http://spec1120-acme-kibana:5601"\n'
        'ELASTIC_TRANSPORT="docker-exec"\n'
        'ELASTIC_DOCKER_CONTEXT="spec1120-acme-context"\n'
        'ELASTIC_ES_CONTAINER="spec1120-acme-es"\n'
        'ELASTIC_KIBANA_CONTAINER="spec1120-acme-kibana"\n', encoding="utf-8")
    _mark_ticket_config(expected, "TICKET_SPEC1120_LOADER_TOKEN", drop_timeout=False)
    ticket = _ticket_config(expected)
    ticket.write_text(ticket.read_text(encoding="utf-8").replace(
        "http://ticket-server:8080", "http://spec1120-acme-ticket:8080"), encoding="utf-8")

    tenant = H.accept(_tenant, data_root)
    settings = tenant.settings
    assert Path(settings) == expected, f"the accepted tenant's settings are {settings}"

    grants = verb_dispositions.run_grants(settings)
    assert Path(grants.path) == expected / "verb-grants.yaml"
    assert ("cmdb", "list-roles") in {(s, v) for s, v, *_ in grants.gather.entries}, (
        "run_grants did not read the data-root table (the fixture withholds cmdb.list-roles)")
    assert verb_dispositions.dispositions_path(settings) == expected / "verb-grants.yaml"
    assert lead_zero_config.lead_zero_config_path(settings) == expected / "lead-zero.yaml"
    assert case_ticket._mapping_path(settings) == (
        expected / "systems" / "case-history" / "mapping.yaml")
    record = T1106.run_tenant(tenant)
    ctx = VerbContext(defender_dir=H.DEFENDER, run_dir=tmp_path / "run", env={}, tenant=record)
    assert elastic_adapter.load_config(ctx)[
        "ELASTICSEARCH_URL"] == "https://spec1120-acme-cluster:9200"
    loaded = _stub_transport.load_config(ctx, "ticket", "TICKET")
    assert loaded["URL_BASE"] == "http://spec1120-acme-ticket:8080", loaded

    assert elastic_stager.configured_patterns(record.elastic) == (
        "spec1120-acme-events-*", "spec1120-acme-alerts-*")
    door = staging.write_door_from_env(staging.host_context(record, {}))
    assert door.base_url == "https://spec1120-acme-cluster:9200", door

    report = validate_scaffold.Report()
    validate_scaffold.check_config(report, Path(settings), "ticket")
    assert any(status == "FAIL" and "TICKET_SPEC1120_LOADER_TOKEN" in msg
               for status, msg in report.rows), report.rows
