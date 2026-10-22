"""#1108 P4 slice S-B — run start, parent side: what `run.main` does with the launch-time
publish's outcome, which export it copies, and what it stamps.

Entry: the REAL `run.main` with the REAL `materialize` (run start resolves the export, copies
it, stamps the run), a recording `lifecycle` that snapshots the run's tenant and copy while the
run is live, and the `publish=` seam (design O11) returning the child's report line. The
tenant is S0's fixture tenant published for real (`_s_b_support.run_tenant`: plus the lead-zero
template the fixture settings name, and revision marks in one lesson and one settings file).

Obligations: O11 (`publish=` seam), O-B for runs (one export commit for settings, knowledge and
stamp; never the clone's HEAD), O-STALE (run record `knowledge_source`; a stale outcome never
stops a run with a snapshot), O-A (no `current` + failed publish refuses before message 0),
O-PIN (`--knowledge-commit` uses that export and skips publish), O9/misconfiguration (refuses),
O2 (lead-zero templates from the copy's catalog), O8 parent half (the run process hands the
child identifiers only and holds no login material).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

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
    """O11/O-B: `run.main(publish=...)` calls the seam once, then the run's tenant hands the run
    `agent/` and `settings/` from `<T>/run-knowledge/<run_id>/`, byte-equal to the export
    `current` names, and the settings the run resolved (a system's config) are that export's."""
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit))

    assert out.reached, f"the run never reached its lifecycle: {out.text()}"
    assert out.rc == 0, out.text()
    assert len(out.publish_calls) == 1, f"the launch published {len(out.publish_calls)} times"
    seen = out.seen[0]
    copy_root = B.run_copies(tenant) / seen.run_dir.name
    assert _under(seen.agent, copy_root), (
        f"O-B: the run's agent half {seen.agent} is not its run copy under {copy_root}")
    assert _under(seen.settings, copy_root), (
        f"O-B: the run's settings half {seen.settings} is not its run copy under {copy_root}")
    assert seen.agent_files == B.export_half(tenant, tenant.commit, "agent"), (
        "O2/O-B: the run copy's agent/ is not byte-equal to the export `current` names")
    assert seen.settings_files == B.export_half(tenant, tenant.commit, "settings")
    cmdb = seen.kw["tenant"].systems["cmdb"]
    assert cmdb.get(B.MARK_KEY) == B.SEEDED_MARK, (
        f"O-B: the run resolved cmdb's settings from somewhere other than the copied export: "
        f"{dict(cmdb) if hasattr(cmdb, 'keys') else cmdb!r}")


def test_o_b_the_stamp_is_the_export_copied_never_the_clones_head(tenant, tmp_path):
    """O-B: the clone has moved past `current` (an unpublished local commit changing the lesson
    and a settings file); the run reads, resolves and stamps the export `current` names, and
    reads nothing of the clone's HEAD or working tree."""
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
        "O-B: the run read the clone's HEAD, not the export")
    assert B.SEEDED_MARK in seen.agent_files[B.LESSON_REL].decode()
    assert seen.kw["tenant"].systems["cmdb"].get(B.MARK_KEY) == B.SEEDED_MARK
    assert B.stamped_commit(out.stamp_after) == {"commit": tenant.commit}, (
        f"O-B: the run's knowledge stamp is not the export it copied ({tenant.commit}); the "
        f"clone's HEAD is {head}: {B.stamped_commit(out.stamp_after)!r}")
    assert B.knowledge_source(out.stamp_after)["commit"] == tenant.commit


# --- O-STALE: the run record and continuing on a snapshot -------------------------------------

@pytest.mark.parametrize("report", ["fresh", "stale:transient", "stale:operator"])
def test_o_stale_every_publish_outcome_with_a_snapshot_runs_and_records_its_knowledge_source(
        tenant, tmp_path, report):
    """O-STALE: fresh and both stale kinds each run to the end on `current`; the run record's
    `knowledge_source` names the kind, the commit actually copied, and (stale) a reason and
    the stale kind (orchestrator decision: `stale_kind` mirrors the API, null unless stale)."""
    reason = "issuer unreachable: s-b reason text"
    line = (B.fresh(tenant.commit) if report == "fresh"
            else B.stale(report.split(":")[1], reason))
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: line)

    assert out.reached, out.text()
    assert out.rc == 0, (
        f"O-STALE: a {report} launch with a snapshot must run (both stale kinds keep the run "
        f"going): {out.text()}")
    source = B.knowledge_source(out.stamp_after)
    assert source.get("commit") == tenant.commit, source
    if report == "fresh":
        assert source.get("kind") == "fresh", source
        assert source.get("stale_kind") is None, source
    else:
        assert source.get("kind") == "stale", source
        assert source.get("stale_kind") == report.split(":")[1], source
        assert isinstance(source.get("reason"), str), source
        assert source["reason"].strip(), (
            f"O-STALE: a stale record must say why: {source}")


def test_o_stale_the_commit_recorded_is_the_export_copied_even_when_the_child_reports_another(
        tenant, tmp_path):
    """O-STALE: `commit` is the export actually copied. The child reports `fresh <M>` (M merged
    on origin) while `current` still names the seeded commit; the run copies and records the
    seeded commit. (Where the mismatch itself is recorded is a reported gap: not asserted.)"""
    merged = tenant.merge(B.MERGE_FILES)
    assert merged != tenant.commit
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(merged))

    assert out.reached, out.text()
    assert B.SEEDED_MARK in out.seen[0].agent_files[B.LESSON_REL].decode()
    assert B.knowledge_source(out.stamp_after)["commit"] == tenant.commit
    assert B.stamped_commit(out.stamp_after) == {"commit": tenant.commit}


def test_o_stale_knowledge_source_is_informational_in_branch_preflights_stamp_table():
    """O-STALE: the run record's `knowledge_source` is classed `informational` (recorded, never
    compared) in branch preflight's stamp table."""
    from defender.learning.branch import preflight

    assert preflight.STAMP_FIELD_CLASSES.get("knowledge_source") == "informational", (
        preflight.STAMP_FIELD_CLASSES)


# --- O-A / misconfiguration: refusals before message 0 ----------------------------------------

@pytest.mark.parametrize("kind", ["transient", "operator"])
def test_o_a_no_current_and_a_failed_publish_refuses_before_message_zero(tenant, tmp_path, kind):
    """O-A: with no `current` there is no snapshot to fall back on, so a stale outcome refuses
    the run before its lifecycle (no box, no model)."""
    pointer = export_dir(tenant.tenant, tenant.commit).parent / "current"
    pointer.unlink()
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.stale(kind, "forge down"))

    assert not out.reached, "O-A: a run with no snapshot and a failed publish reached its box"
    assert out.rc not in (0, None) or out.refusal is not None, out.text()
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"


def test_o_a_control_the_same_stale_outcome_with_a_current_runs(tenant, tmp_path):
    """Positive control for the no-`current` refusal: same outcome, `current` present."""
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.stale("transient", "forge down"))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()


def test_o9_a_misconfigured_publish_refuses_the_run_even_with_a_snapshot(tenant, tmp_path):
    """O9/O-STALE: misconfiguration (no issuer config file / no forge binding) refuses the run
    before any model call, naming why — unlike a stale outcome, a snapshot does not save it."""
    reason = "the tenant row names no forge binding (S-B-MISCONFIG-REASON)"
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.misconfigured(reason))

    assert not out.reached, "O9: a misconfigured launch reached its box"
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
    assert out.refusal is not None, out.text()
    assert "S-B-MISCONFIG-REASON" in out.refusal, out.text()


# --- O-PIN: a pinned launch -------------------------------------------------------------------

def test_o_pin_a_pinned_launch_reads_that_export_skips_publish_and_records_pinned(
        tenant, tmp_path):
    """O-PIN/O-B: after a merge is published (`current` and clone HEAD both = M), a launch
    pinned to the seeded commit S reads S's export, never calls `publish`, stamps S and records
    `knowledge_source: {kind: pinned, commit: S}`."""
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
        "O-B: a pinned run's stamp is not the pinned export (it read the clone's HEAD?)")
    source = B.knowledge_source(out.stamp_after)
    assert source.get("kind") == "pinned", source
    assert source.get("commit") == tenant.commit, source
    assert source.get("stale_kind") is None, source


def test_o_pin_a_pin_to_a_commit_with_no_export_refuses_before_message_zero(tenant, tmp_path):
    """O-PIN/P-3: the run process has no git, so it cannot materialise; a pin naming a commit
    with no export (here a commit merged on origin, never exported) refuses before the box.
    Control: `test_o_pin_a_pinned_launch_reads_that_export...` (an exported pin runs)."""
    merged = tenant.merge(B.MERGE_FILES)
    assert not export_dir(tenant.tenant, merged).exists()
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   argv_extra=("--knowledge-commit", merged))
    assert not out.reached, "a pin to an unexported commit reached the box"
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
    assert out.refusal is not None, out.text()
    assert merged[:7] in out.refusal, out.text()


# --- O2: lead-zero templates from the copy's catalog ------------------------------------------

def test_o2_lead_zero_templates_come_from_the_run_copys_catalog_not_the_product_tree(
        tmp_path, data_root):
    """O2 (P4-C3): the fixture settings name `elastic.correlate-alerts-by-entity`, which the
    product catalog holds. An export WITHOUT it refuses the run at start naming the template —
    the run did not fall back to the product's. (Control: every other test here, whose export
    carries it, runs.)"""
    with published_tenant(tmp_path / "forge", root=data_root,
                          files={**B.SEED_FILES, B.CORRELATE_PATH: None}) as t:
        out = B.launch(t, tmp_path, publish=lambda *a, **k: B.fresh(t.commit))
    assert not out.reached, (
        "O2: the run started although its own export has no lead-zero template — it read the "
        "product catalog")
    assert out.refusal is not None, out.text()
    assert B.CORRELATE_ID in out.refusal, out.text()


# --- O8 parent half ---------------------------------------------------------------------------

def test_o8_the_run_process_hands_the_publish_child_identifiers_only_and_holds_no_login(
        tenant, tmp_path):
    """O8: the run process passes the publish child nothing but identifiers (tenant id, data
    root) — no client, identity, token, config bytes or secret — and neither its environment
    nor what it hands the run carries issuer material."""
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit))
    assert out.reached, out.text()
    ((args, kwargs),) = out.publish_calls
    leaves = B.flat_values([args, kwargs])
    assert any(str(leaf) == tenant.tenant_id for leaf in leaves), (
        f"the child was not told which tenant to publish: {args!r} {kwargs!r}")
    odd = [leaf for leaf in leaves if not isinstance(leaf, (str, os.PathLike, int, type(None)))
           and type(leaf).__name__ not in ("DataRoot", "TenantId")]
    assert odd == [], f"O8: the run process handed the publish child objects: {odd!r}"
    assert not [k for k in out.seen[0].environ if B.ISSUER_ENV.search(k)], (
        "P-4/O8: issuer material in the run process's environment")
