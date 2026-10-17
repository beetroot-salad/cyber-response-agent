"""D1/D2: the operator commands and the settings loaders read the DATA ROOT's copy."""
from __future__ import annotations

import functools
import shutil
from pathlib import Path
from typing import Any

import pytest

from defender import _tenant
from defender import run as run_py
from defender.learning.branch import cli as branch_cli
from defender.runtime import box as box_mod
from defender.runtime import box_codec
from defender.scripts import policy_cli
from defender.scripts import tenant as tenant_py
from defender.skills.connect import validate_scaffold
from defender.tests._alert_plant import plant_alert as plant_alert_with_record
from defender.tests import _triplet_947 as T947
from defender.tests.tenant_1078_pass_a import _spec1078 as H78
from defender.tests.tenant_1120_piece1 import _spec1120 as H

#: The census lint, a repo script outside `defender/` (driven by path).
CENSUS_LINT = H.REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"

#: A table that loads but grants gather no query verb — a table that DIFFERS from the fixture's
HEALTH_CHECK_ONLY_TABLE = "dispositions:\n  cmdb:\n    health-check: {roles: [gather]}\n"

#: A `verb-grants.yaml` that is not YAML (an unclosed flow mapping) — the unloadable table.
UNPARSEABLE_TABLE = "dispositions:\n  cmdb:\n    health-check: {roles: [gather]\n"


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
    """Give a tenant's ticket `config.env` an inline-secret MARKER line (a key `validate_scaffold`
    FAILs by name) and, with `drop_timeout`, lose the required `TICKET_TIMEOUT_SEC`."""
    path = _ticket_config(settings)
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines(keepends=True)
             if not (drop_timeout and ln.startswith("TICKET_TIMEOUT_SEC"))]
    path.write_text("".join(lines) + f'{marker_key}="inline-marker-{marker_key.lower()}"\n',
                    encoding="utf-8")
    return path


def _other_tree(tmp_path: Path, tenant_id: str, marker_key: str) -> Path:
    """Another checkout's `defender/` whose `knowledge/tenants/<tenant_id>` holds a COMPLETE tenant
    folder carrying `marker_key` in its ticket config — what a command would find if it derived its
    tenants root from an exported `$DEFENDER_DIR`."""
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
    """The lab is retired (human, PR #1157: #1158 folded in); the checkout's knowledge/ holds only the
    template and the fixture, a complete copy of the lab's settings."""
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
    """validate_scaffold and the census lint catch TenantRefused (not only the removed TenantDirError)
    and surface its message in their own idiom, never a traceback."""
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


def test_1120_s6_operator_tools_in_a_shell_without_the_data_root(
        data_root: Path, tmp_path: Path, monkeypatch) -> None:
    """With DEFENDER_DATA_ROOT unset, validate_scaffold --tenant and policy_cli gather --tenant each
    report resolve_data_root's refusal naming the variable."""
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
    """The REAL branch launcher over `source`, with no `--tenants-root` (piece 1 removes it), the role
    preflight neutralised and the spawn recorded."""
    spawn = _SpawnRecorder()
    try:
        return branch_cli.main(
            ["--tenant", source.parent.parent.name, source.name,
             str(T947.BRANCH_MESSAGE_ID), "--continuation-prompt", "Continue from here."],
            spawn=spawn, preflight=T947.no_preflight)
    except SystemExit as refused:
        return refused
    finally:
        assert spawn.calls == [], "the launcher spawned a sibling over an unloadable table"


def test_1120_check_and_every_table_loading_consumer_refuse_an_unloadable_grant_table(
        data_root: Path, tmp_path: Path, capsys) -> None:
    """A tenant whose settings/verb-grants.yaml does not parse as YAML: tenant.py check acme exits 1
    naming verb-grants.yaml (M6: a malformed table is a named finding, never a traceback)."""
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
    """run.py calls start_box with the accepted tenant's agent half, <root>/acme/knowledge/agent (the
    tenant's knowledge a local git clone here, so its .git exists)."""
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
        start_box=start_box, stop_box=lambda *a, **k: None, scrub=lambda tree, **kw: None)
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
    agent_mounts = [m for m in mounts if m.get("target") == str(agent)]
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
    """When the driver shares paths with the docker daemon (docker-outside-of-Docker, C46) and the
    tenant's agent half, <root>/acme/knowledge/agent, lies on none of them while the run dir and the
    defender dir do, composing the box's docker run refuses with BoxFault naming the agent half —
    and its remedy names DEFENDER_DATA_ROOT and never "the tenants root", which piece 1 removes
    (F13's refusal-wording consequence, V7)."""
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
    plant_alert_with_record(shared / "run", {})
    box_mod._create_argv("defender-run-spec1120", shared / "run", H.DEFENDER,
                         box_mod.DEFAULT_SPEC, mounts, tenant_agent=H.agent_dir(on_mount))


def test_1120_no_tenant_or_data_root_key_enters_the_box_env(tmp_path: Path) -> None:
    """No key of BOX_ENV_ALLOWLIST names the tenant or the data root: no DEFENDER_DATA_ROOT and no key
    containing TENANT (C13 — a child learns its tenant from --tenant and the data root from its own
    environment, never from the box)."""
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

    plant_alert_with_record(tmp_path / "run", {})
    argv = box_mod._create_argv(
        "defender-run-spec1120", tmp_path / "run", H.DEFENDER,
        box_mod.DEFAULT_SPEC, ()).argv
    env_keys = {v.partition("=")[0] for f, v in zip(argv, argv[1:], strict=False) if f == "--env"}
    assert env_keys == set(allow) - {"DEFENDER_AGENT_DIR"}, env_keys
    assert "DEFENDER_AGENT_DIR" not in env_keys


# ======================================================================================
# R7 — the settings loaders that survive the move read the ACCEPTED tenant's settings.
# ======================================================================================

