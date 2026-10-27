"""#1108 P4 run start, parent side: what `run.main` does with the launch-time publish's outcome,
which export it copies, and what it stamps.

Entry: the real `run.main` with the real `materialize` (resolve the export, copy it, stamp the
run), a recording `lifecycle` that snapshots the run's tenant and copy while live, and the
`publish=` seam returning the child's report line. The tenant is `_s_b_support.run_tenant`: the
fixture with revision marks in one lesson and one settings file.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import (
    current_commit,
    export_dir,
    git,
    published_tenant,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        yield t


def _under(path: Path, root: Path) -> bool:
    return Path(path).resolve().is_relative_to(Path(root).resolve())


# --- O11 + O-B: the run reads one export, through its own copy ---------------------------------

def test_o11_o_b_an_unpinned_launch_publishes_once_and_the_run_reads_settings_and_knowledge_from_its_copy_of_current(
        tenant, tmp_path):
    """The run's `agent/` and `settings/` come from its copy under `<T>/run-knowledge/<run_id>/`,
    byte-equal to the export `current` names, and the settings it resolves are that export's."""
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit))

    assert out.reached, f"the run never reached its lifecycle: {out.text()}"
    assert out.rc == 0, out.text()
    assert len(out.publish_calls) == 1, f"the launch published {len(out.publish_calls)} times"
    seen = out.seen[0]
    copy_root = B.copy_root(tenant, seen.run_dir)
    assert _under(seen.agent, copy_root), (
        f"the run's agent half {seen.agent} is not its run copy under {copy_root}")
    assert _under(seen.settings, copy_root), (
        f"the run's settings half {seen.settings} is not its run copy under {copy_root}")
    # `<T>/run-knowledge/<run_id>/{owner, settings/, stage/{agent/, <token>}}`.
    assert Path(seen.agent).resolve() == (copy_root / "stage" / "agent").resolve(), (
        f"the run's agent half is not the copy's `stage/agent/`: {seen.agent}")
    assert Path(seen.settings).resolve() == (copy_root / "settings").resolve(), (
        f"the run's settings half is not the copy's `settings/` (beside `stage/`): "
        f"{seen.settings}")
    assert seen.agent_files == B.export_half(tenant, tenant.commit, "agent"), (
        "the run copy's agent/ is not byte-equal to the export `current` names")
    assert seen.settings_files == B.export_half(tenant, tenant.commit, "settings")
    cmdb = seen.kw["tenant"].systems["cmdb"]
    assert cmdb.get(B.MARK_KEY) == B.SEEDED_MARK, (
        f"the run resolved cmdb's settings from somewhere other than the copied export: "
        f"{dict(cmdb) if hasattr(cmdb, 'keys') else cmdb!r}")


def test_o_b_the_stamp_is_the_export_copied_never_the_clones_head(tenant, tmp_path):
    """The clone moved past `current` with an unpublished local commit; the run reads, resolves
    and stamps the export `current` names, nothing of the clone."""
    clone = B.clone_dir(tenant)
    (clone / B.LESSON).write_text(B.lesson_text(B.CLONE_ONLY_MARK), encoding="utf-8")
    (clone / B.CMDB_ENV).write_text(B.cmdb_env(B.CLONE_ONLY_MARK), encoding="utf-8")
    git(clone, "commit", "-am", "local, never published")
    head = git(clone, "rev-parse", "HEAD")
    assert head != tenant.commit
    assert current_commit(tenant.tenant) == tenant.commit

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit))

    assert out.reached, out.text()
    seen = out.seen[0]
    assert B.CLONE_ONLY_MARK not in seen.agent_files[B.LESSON_REL].decode(), (
        "the run read the clone's HEAD, not the export")
    assert B.SEEDED_MARK in seen.agent_files[B.LESSON_REL].decode()
    assert seen.kw["tenant"].systems["cmdb"].get(B.MARK_KEY) == B.SEEDED_MARK
    assert B.stamped_commit(out.stamp_after) == {"commit": tenant.commit}, (
        f"the run's knowledge stamp is not the export it copied ({tenant.commit}); the "
        f"clone's HEAD is {head}: {B.stamped_commit(out.stamp_after)!r}")
    assert B.knowledge_source(out)["commit"] == tenant.commit


def _gitfile_nowhere(clone: Path) -> None:
    shutil.rmtree(clone / ".git")
    (clone / ".git").write_text("gitdir: /nonexistent/1108-p4/broken-clone.git\n", encoding="utf-8")


def _git_removed(clone: Path) -> None:
    shutil.rmtree(clone / ".git")


def _uncommitted_edit(clone: Path) -> None:
    (clone / B.LESSON).write_text(B.lesson_text(B.CLONE_ONLY_MARK), encoding="utf-8")
    (clone / B.CMDB_ENV).write_text(B.cmdb_env(B.CLONE_ONLY_MARK), encoding="utf-8")


# Behavioural complement to the census: the run never reads the clone's working tree.
def _working_tree_removed(clone: Path) -> None:
    for half in ("agent", "settings"):
        shutil.rmtree(clone / half)


@pytest.mark.parametrize("breakage", [_gitfile_nowhere, _git_removed, _uncommitted_edit,
                                      _working_tree_removed],
                         ids=["gitfile-pointing-nowhere", "dot-git-removed", "uncommitted-edit",
                              "working-tree-removed"])
def test_o_b_a_broken_tenant_clone_does_not_stop_the_run_or_reach_its_stamp(
        tenant, tmp_path, breakage):
    """Run start never reads the clone: a broken `.git`, an uncommitted edit, or a working tree
    gone altogether (git objects kept) each leave the run starting on `current`'s export, with
    its bytes and its commit stamped."""
    clone = B.clone_dir(tenant)
    breakage(clone)
    assert current_commit(tenant.tenant) == tenant.commit

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit))

    assert out.reached, f"a broken clone stopped the run: {out.text()}"
    assert out.rc == 0, out.text()
    seen = out.seen[0]
    assert seen.agent_files == B.export_half(tenant, tenant.commit, "agent"), (
        "the run's agent half is not the export `current` names")
    assert seen.settings_files == B.export_half(tenant, tenant.commit, "settings")
    assert B.CLONE_ONLY_MARK not in seen.agent_files[B.LESSON_REL].decode(), (
        "the run read the clone's working tree")
    assert seen.kw["tenant"].systems["cmdb"].get(B.MARK_KEY) == B.SEEDED_MARK
    assert B.stamped_commit(out.stamp_after) == {"commit": tenant.commit}, (
        f"the stamp is not the export copied ({tenant.commit}): "
        f"{B.stamped_commit(out.stamp_after)!r}")
    source = B.knowledge_source(out)
    assert (source["kind"], source["commit"]) == ("fresh", tenant.commit), source


# --- O-STALE: the run record and continuing on a snapshot -------------------------------------

@pytest.mark.parametrize("report", ["fresh", "stale:transient", "stale:operator"])
def test_o_stale_every_publish_outcome_with_a_snapshot_runs_and_records_its_knowledge_source(
        tenant, tmp_path, report):
    """Fresh and both stale kinds run to the end on `current`; the host record names the kind,
    the commit copied and (stale) the stale kind and the child's reason. No box-readable file
    (the run dir, the copy's `stage/`) holds the raw reason while the run is live, nor any
    run-dir file after it but the saved run page, an operator surface written after the box
    stops (OD21)."""
    reason = "issuer unreachable: s-b reason text 4c1e"
    line = (B.fresh(tenant.commit) if report == "fresh"
            else B.stale(report.split(":")[1], reason))

    def box_readable_hits(seen: B.Seen) -> dict[str, list[str]]:
        return {"run dir": B.files_holding(seen.run_dir, reason),
                "stage": B.files_holding(B.copy_stage(tenant, seen.run_dir), reason)}

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: line, during=box_readable_hits)

    assert out.reached, out.text()
    assert out.rc == 0, (
        f"a {report} launch with a snapshot must run: {out.text()}")
    source = B.knowledge_source(out)
    assert source.get("commit") == tenant.commit, source
    assert out.seen[0].during == {"run dir": [], "stage": []}, (
        f"the raw publish reason is in a box-readable file: {out.seen[0].during}")
    # Only the saved run page may show the raw reason (OD21).
    after = [rel for rel in B.files_holding(out.run_dir, reason) if rel != "runtime.html"]
    assert after == [], (
        f"the raw publish reason was written into a run-dir file other than the saved "
        f"page after the lifecycle: {after}")
    if report == "fresh":
        assert source.get("kind") == "fresh", source
        assert source.get("stale_kind") is None, source
    else:
        assert source.get("kind") == "stale", source
        assert source.get("stale_kind") == report.split(":")[1], source
        assert isinstance(source.get("reason"), str), source
        assert reason in source["reason"], (
            f"the host record does not carry the child's reason ({reason!r}): {source}")
        # Positive control for the box-readable scan: the same text IS in the host file.
        assert reason in B.host_record_path(out.run_dir).read_text(encoding="utf-8")


def test_a_mismatch_a_copied_commit_descending_from_the_reported_one_is_fresh_at_the_copy(
        tenant, tmp_path):
    """The child reports `fresh <S>` but `current` has since fast-forwarded to a descendant M
    (another launch's publish): the run copies M and records fresh at M, keeping the reported S
    in any other field. Every writer of `current` fast-forwards it under the tenant lock, so the
    copy descends from the reported commit by construction; the run has no git to check it."""
    merged = tenant.merge(B.MERGE_FILES)
    tenant.publish()
    assert current_commit(tenant.tenant) == merged
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit))

    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert B.MERGED_MARK in out.seen[0].agent_files[B.LESSON_REL].decode()
    assert B.stamped_commit(out.stamp_after) == {"commit": merged}
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("commit")) == ("fresh", merged), source
    others = B.flat_values({k: v for k, v in source.items() if k != "commit"})
    assert any(tenant.commit in str(v) for v in others), (
        f"the record does not keep the child's reported commit {tenant.commit}: "
        f"{source}")


def test_o_stale_knowledge_source_is_informational_in_branch_preflights_stamp_table():
    """The run record's `knowledge_source` is classed `informational` (recorded, never compared)
    in branch preflight's stamp table."""
    from defender.learning.branch import preflight

    assert preflight.STAMP_FIELD_CLASSES.get("knowledge_source") == "informational", (
        preflight.STAMP_FIELD_CLASSES)


# --- O-A / misconfiguration: refusals before message 0 ----------------------------------------

@pytest.mark.parametrize("kind", ["transient", "operator"])
def test_o_a_no_current_and_a_failed_publish_refuses_before_message_zero(tenant, tmp_path, kind):
    """With no `current` there is no snapshot to fall back on, so a stale outcome refuses the
    run before its lifecycle (no box, no model)."""
    pointer = export_dir(tenant.tenant, tenant.commit).parent / "current"
    pointer.unlink()
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.stale(kind, "forge down"))

    assert not out.reached, "a run with no snapshot and a failed publish reached its box"
    assert out.rc not in (0, None) or out.refusal is not None, out.text()
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"


def test_o_a_control_the_same_stale_outcome_with_a_current_runs(tenant, tmp_path):
    """Positive control for the no-`current` refusal: same outcome, `current` present."""
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.stale("transient", "forge down"))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()


def test_o9_a_misconfigured_publish_refuses_the_run_even_with_a_snapshot(tenant, tmp_path):
    """Misconfiguration refuses the run before any model call, naming why: unlike a stale
    outcome, a snapshot does not save it."""
    reason = "the tenant row names no forge binding (S-B-MISCONFIG-REASON)"
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.misconfigured(reason))

    assert not out.reached, "a misconfigured launch reached its box"
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
    assert out.refusal is not None, out.text()
    assert "S-B-MISCONFIG-REASON" in out.refusal, out.text()


# --- O-PIN: a pinned launch -------------------------------------------------------------------

def test_o_pin_a_pinned_launch_reads_that_export_skips_publish_and_records_pinned(
        tenant, tmp_path):
    """With a merge published (`current` and the clone's HEAD both at it), a launch pinned to
    the seeded commit reads that export, never calls `publish`, and stamps and records it as
    pinned."""
    merged = tenant.merge(B.MERGE_FILES)
    tenant.publish()
    assert current_commit(tenant.tenant) == merged
    assert git(B.clone_dir(tenant), "rev-parse", "HEAD") == merged

    def must_not_publish(*a: Any, **k: Any) -> str:
        raise AssertionError("O-PIN: a pinned launch ran the launch-time publish")

    out = B.launch(tenant, tmp_path, publish=must_not_publish,
                   argv_extra=("--knowledge-commit", tenant.commit))

    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert out.publish_calls == []
    seen = out.seen[0]
    assert seen.agent_files == B.export_half(tenant, tenant.commit, "agent")
    assert seen.kw["tenant"].systems["cmdb"].get(B.MARK_KEY) == B.SEEDED_MARK
    assert B.stamped_commit(out.stamp_after) == {"commit": tenant.commit}, (
        "a pinned run's stamp is not the pinned export (it read the clone's HEAD?)")
    source = B.knowledge_source(out)
    assert source.get("kind") == "pinned", source
    assert source.get("commit") == tenant.commit, source
    assert source.get("stale_kind") is None, source


def test_o_pin_a_pin_to_a_commit_with_no_export_refuses_before_message_zero(tenant, tmp_path):
    """The run process has no git and cannot materialise, so a pin naming a commit with no
    export (merged on origin, never exported) refuses before the box. Control: the pinned
    launch above."""
    merged = tenant.merge(B.MERGE_FILES)
    assert not export_dir(tenant.tenant, merged).exists()
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   argv_extra=("--knowledge-commit", merged))
    assert not out.reached, "a pin to an unexported commit reached the box"
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
    assert out.refusal is not None, out.text()
    assert "usage:" not in out.refusal, f"argparse refused the flag, not the run: {out.refusal}"
    assert merged[:7] in out.refusal, out.text()
    _no_copy_left(tenant)


# --- O2: lead-zero templates from the copy's catalog ------------------------------------------

def test_o2_lead_zero_templates_come_from_the_run_copys_catalog_not_the_product_tree(
        tmp_path, data_root):
    """An export without the lead-zero template its settings name refuses the run at start,
    naming the template: there is no fallback catalog. Control: every other test here."""
    with published_tenant(tmp_path / "forge", root=data_root,
                          files={**B.SEED_FILES, B.CORRELATE_PATH: None}) as t:
        out = B.launch(t, tmp_path, publish=lambda *a, **k: B.fresh(t.commit))
    assert not out.reached, (
        "the run started although its own export has no lead-zero template")
    assert out.refusal is not None, out.text()
    assert B.CORRELATE_ID in out.refusal, out.text()
    _no_copy_left(t)


# --- O8 parent half ---------------------------------------------------------------------------

def test_o8_the_run_process_hands_the_publish_child_identifiers_only_and_holds_no_login(
        tenant, tmp_path):
    """The publish seam is handed only the tenant id and data root, and the run process's
    environment carries no issuer-named variable."""
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit))
    assert out.reached, out.text()
    ((args, kwargs),) = out.publish_calls
    leaves = B.flat_values([args, kwargs])
    spelled = sorted(str(location_path(leaf)) for leaf in leaves
                     if not isinstance(leaf, str) or leaf not in kwargs)
    assert spelled == sorted([tenant.tenant_id, str(Path(tenant.data_root))]), (
        f"the run process handed the publish child more (or less) than the tenant id and the "
        f"data root: {args!r} {kwargs!r}")
    assert not [k for k in out.seen[0].environ if B.ISSUER_ENV.search(k)], (
        "issuer material in the run process's environment")


def test_o8_operator_issuer_variables_never_reach_the_runs_environment(tenant, tmp_path,
                                                                       monkeypatch):
    """An operator shell exported `BAO_TOKEN`/`VAULT_TOKEN`: the environment run start builds
    for its host lanes (`run_env`, seen through the ticket writer) carries neither. Control: an
    ordinary variable passes."""
    monkeypatch.setenv("BAO_TOKEN", "s-b-operator-bao-token-77e1")
    monkeypatch.setenv("VAULT_TOKEN", "s-b-operator-vault-token-91a4")
    monkeypatch.setenv("S_B_ORDINARY", "s-b-ordinary-value")
    envs: list[dict] = []

    class Writer:
        def open_case_ticket(self, *_a: Any, env: Any, **_k: Any) -> None:
            envs.append(dict(env))

        def record_case_ticket(self, *_a: Any, env: Any, **_k: Any) -> None:
            envs.append(dict(env))

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   argv_extra=("--update-ticket",), ticket_writer=Writer())
    assert out.reached, out.text()
    assert envs, "the ticket writer was never handed the run's environment"
    assert all(env.get("S_B_ORDINARY") == "s-b-ordinary-value" for env in envs), "control"
    assert B.leaks(("s-b-operator-bao-token-77e1", "s-b-operator-vault-token-91a4"),
                   run_env=envs) == [], "operator issuer material reached the run's env"
    assert [k for env in envs for k in env if B.ISSUER_ENV.search(k)] == []


def _no_copy_left(t: Any) -> None:
    """Nothing of a run is left under `<T>/run-knowledge/` after it ended."""
    copies = B.run_copies(t)
    left = sorted(os.listdir(copies)) if copies.is_dir() else []
    assert left == [], f"a run copy outlived its run: {left}"


@pytest.mark.parametrize("seam", ["ticket_writer", "visualize"])
def test_r_s4_a_raise_after_the_lifecycle_still_removes_the_run_copy(tenant, tmp_path, seam):
    """A post-lifecycle step (the ticket write-back, the page) raises; the run copy is removed
    anyway (`finally`)."""
    class Boom(Exception):
        pass

    def boom(*_a: Any, **_k: Any) -> None:
        raise Boom(seam)

    class Writer:
        def open_case_ticket(self, *_a: Any, **_k: Any) -> None:
            pass

        record_case_ticket = staticmethod(boom)

    seams = ({"ticket_writer": Writer()} if seam == "ticket_writer" else {"visualize": boom})
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   argv_extra=("--update-ticket",) if seam == "ticket_writer" else (), **seams)
    assert out.reached, out.text()
    assert isinstance(out.raised, Boom), out.text()
    _no_copy_left(tenant)


@pytest.mark.parametrize("value", ["../current", "current", "SHORT"])
def test_o_pin_knowledge_commit_accepts_only_a_full_commit_id(tenant, tmp_path, value):
    """`--knowledge-commit` names an export by its full commit id; `../current`,
    `current` and a short id are refused before the box (never resolved as a path)."""
    pin = tenant.commit[:7] if value == "SHORT" else value
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   argv_extra=("--knowledge-commit", pin))
    assert not out.reached, f"--knowledge-commit {pin!r} reached the box"
    assert out.raised is None, out.text()
    assert out.refusal is not None, out.text()
    assert "unrecognized arguments" not in out.refusal, (
        f"argparse does not know --knowledge-commit: {out.refusal}")
    _no_copy_left(tenant)
