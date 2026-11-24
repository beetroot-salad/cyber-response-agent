"""#1108 P4 run start, parent side, as #1618 leaves it: what `run.main` does with the fetch child's line, which commit
the run reads (through its own copy) and what it stamps.

Entry: the real `run.main` with the real `materialize` (fetch into an owned folder, rename it into the run copy, stamp
the run), a recording `lifecycle` that snapshots the run's tenant and copy while live, and the `fetch=` seam
(`B.fetching`: the product's in-process fetch of the tenant's served Forgejo remote; `B.refusing`: a refusal line). The
tenant is `_s_b_support.run_tenant`: the fixture with revision marks in one lesson and one settings file (a plain file
beside the grants: a system's settings are records, not a folder, R10).

Retired here (#1618 design "Retired promises"), each with its successor:
- O-B "the stamp is the export copied, never the clone's HEAD" and "a broken tenant clone does not stop the run" (K8: no
  clone, no exports, no `current`): `knowledge_1618/test_run_start_1618.py::test_a1_*` (the stamp is the commit the
  run's own fetch saw) and `::test_a14_*` (no clone, exports, current or lock after the upgrade);
- O-STALE "every publish outcome with a snapshot runs and records its knowledge source" (stale kinds), O-A's control
  "the same stale outcome with a `current` runs" and O9 "a misconfigured publish refuses even with a snapshot" (K9 stale
  retired, D3 no stale fallback, D11 misconfigured gone): `test_o_a_a_refused_fetch_refuses_before_message_zero` below;
  the fresh arm survives in `test_o11_*` below (the host record says fresh at the commit read);
- "a copied commit descending from the reported one is fresh at the copy" (the export `current` could fast-forward
  past the child's report; there is no `current` now): `knowledge_1618/test_run_start_1618.py::test_a1_*`.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

pytestmark = pytest.mark.e2e


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        yield t


def _under(path: Path, root: Path) -> bool:
    return Path(path).resolve().is_relative_to(Path(root).resolve())


# --- O11 + O-B: the run reads one commit, through its own copy -------------------------------------------------------

def test_o11_o_b_an_unpinned_launch_fetches_once_and_the_run_reads_settings_and_knowledge_from_its_copy_of_main(
        tenant, tmp_path):
    """The run's `agent/` and `settings/` come from its copy under `<T>/run-knowledge/<run_id>/`, byte-equal to `main`
    on the tenant's Forgejo remote, and the settings it resolves are that commit's; the host record says fresh at it."""
    fetch = B.fetching(tenant)
    out = B.launch(tenant, tmp_path, fetch=fetch)

    assert out.reached, f"the run never reached its lifecycle: {out.text()}"
    assert out.rc == 0, out.text()
    assert len(fetch.calls) == 1, f"the launch fetched {len(fetch.calls)} times"
    assert fetch.lines == [f"ok {tenant.commit}"], fetch.lines
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
    assert seen.agent_files == B.committed_half(tenant, tenant.commit, "agent"), (
        "the run copy's agent/ is not byte-equal to main's on the remote")
    assert seen.settings_files == B.committed_half(tenant, tenant.commit, "settings")
    # A system's settings are the tenant's records (R10, DC7), not a folder; what the run still resolves from the
    # settings half are its grants, read from this very copy.
    assert B.mark_text(B.SEEDED_MARK) == B.settings_read(seen), (
        "the run's settings half is not the revision main names")
    assert B.stamped_commit(out.stamp_after) == {"commit": tenant.commit}, B.stamped_commit(out.stamp_after)
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("commit"), source.get("stale_kind")) == ("fresh", tenant.commit, None), source


def test_o_stale_knowledge_source_is_informational_in_branch_preflights_stamp_table():
    """The run record's `knowledge_source` is classed `informational` (recorded, never compared)
    in branch preflight's stamp table."""
    from defender.learning.branch import preflight

    assert preflight.STAMP_FIELD_CLASSES.get("knowledge_source") == "informational", (
        preflight.STAMP_FIELD_CLASSES)


# --- O-A: a refused fetch refuses before message 0 (D3: no stale fallback) -------------------------------------------

@pytest.mark.parametrize("word", ["transient", "lasting"])
def test_o_a_a_refused_fetch_refuses_before_message_zero(tenant, tmp_path, word):
    """There is no snapshot to fall back on (#1618 D3; was: "with no `current`"), so a refused fetch, of either class,
    refuses the run before its lifecycle (no box, no model), by a refusal naming the child's reason, not a crash, and
    leaves no run copy. Control: the same tenant with a fetch that answers `ok` runs."""
    reason = f"S-B-FETCH-REFUSED-{word}"
    out = B.launch(tenant, tmp_path, fetch=B.refusing(word, reason))

    assert not out.reached, "a run whose fetch was refused reached its box"
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
    assert out.rc not in (0, None) or out.refusal is not None, out.text()
    assert reason in (out.refusal or ""), out.text()
    _no_copy_left(tenant)
    assert B.launch(tenant, tmp_path / "control", fetch=B.fetching(tenant)).reached, "control: an ok fetch runs"


# --- O-PIN: a pinned launch -------------------------------------------------------------------

def test_o_pin_a_pinned_launch_reads_that_commit_and_records_pinned(tenant, tmp_path):
    """With a merge on `main`, a launch pinned to the seeded commit asks the fetch for that commit by id (not `main`),
    reads its bytes, and stamps and records it as pinned. (#1618: the fetch is asked for the pin, A8; was "reads that
    export and skips publish".)"""
    merged = tenant.merge(B.MERGE_FILES)
    assert tenant.origin_main() == merged
    fetch = B.fetching(tenant)
    out = B.launch(tenant, tmp_path, fetch=fetch, argv_extra=("--knowledge-commit", tenant.commit))

    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert [kw.get("commit") for _a, kw in fetch.calls] == [tenant.commit], fetch.calls
    seen = out.seen[0]
    assert seen.agent_files == B.committed_half(tenant, tenant.commit, "agent")
    assert B.settings_read(seen) == B.mark_text(B.SEEDED_MARK)
    assert B.stamped_commit(out.stamp_after) == {"commit": tenant.commit}, (
        "a pinned run's stamp is not the pinned commit (it read main?)")
    source = B.knowledge_source(out)
    assert source.get("kind") == "pinned", source
    assert source.get("commit") == tenant.commit, source
    assert source.get("stale_kind") is None, source


def test_o_pin_a_pin_to_a_commit_forgejo_does_not_serve_refuses_before_message_zero(tenant, tmp_path):
    """A pin naming a full commit id the remote does not hold refuses before the box, naming the commit, by the
    run's refusal (not argparse's). Control: the pinned launch above. (#1618: was "a commit with no export".)"""
    absent = "0123456789abcdef0123456789abcdef01234567"
    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant), argv_extra=("--knowledge-commit", absent))
    assert not out.reached, "a pin to a commit Forgejo does not serve reached the box"
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
    assert out.refusal is not None, out.text()
    assert "usage:" not in out.refusal, f"argparse refused the flag, not the run: {out.refusal}"
    assert absent[:7] in out.refusal, out.text()
    _no_copy_left(tenant)


# --- O2, as #1503 left it: the step-zero lead needs no saved query --------------------------

def test_o2_a_commit_without_a_saved_correlation_query_still_starts(tmp_path, data_root):
    """The step-zero lead binds no saved query (#1503), so knowledge whose catalog lacks the
    correlation query starts as any other does."""
    with published_tenant(tmp_path / "forge", root=data_root,
                          files={**B.SEED_FILES, B.CORRELATE_PATH: None}) as t:
        out = B.launch(t, tmp_path, fetch=B.fetching(t))
    assert out.reached, out.text()
    assert out.refusal is None, out.text()


# --- O8 parent half ---------------------------------------------------------------------------

def test_o8_the_run_process_hands_the_fetch_child_identifiers_only_and_holds_no_login(tenant, tmp_path):
    """The fetch seam is handed only the tenant id, the owned empty folder it fills (under `<T>/run-knowledge/`, D5)
    and the data root, with no commit for an unpinned run; the run process's environment carries no issuer-named
    variable. (#1618 flow 1: the destination folder is the one value added to the publish child's identifiers.)"""
    fetch = B.fetching(tenant)
    out = B.launch(tenant, tmp_path, fetch=fetch)
    assert out.reached, out.text()
    ((args, kwargs),) = fetch.calls
    assert kwargs.get("commit") is None, kwargs
    rest = {k: v for k, v in kwargs.items() if k != "commit"}
    leaves = B.flat_values([args, rest])
    spelled = sorted(str(location_path(leaf)) for leaf in leaves
                     if not isinstance(leaf, str) or leaf not in rest)
    [dest] = [leaf for leaf in spelled if leaf not in (tenant.tenant_id, str(Path(tenant.data_root)))]
    assert sorted(spelled) == sorted([tenant.tenant_id, str(Path(tenant.data_root)), dest]), (
        f"the run process handed the fetch child more (or less) than the tenant id, its folder and the data root: "
        f"{args!r} {kwargs!r}")
    assert _under(Path(dest), B.run_copies(tenant)), f"the fetch's folder is not the run's own, under <T>: {dest}"
    assert not [k for k in out.seen[0].environ if B.ISSUER_ENV.search(k)], (
        "issuer material in the run process's environment")


def _no_copy_left(t: Any) -> None:
    """Nothing of a run is left under `<T>/run-knowledge/` after it ended."""
    copies = B.run_copies(t)
    left = sorted(os.listdir(copies)) if copies.is_dir() else []
    assert left == [], f"a run copy outlived its run: {left}"


def test_r_s4_a_raise_after_the_lifecycle_still_removes_the_run_copy(tenant, tmp_path):
    """A post-lifecycle step (the page) raises; the run copy is removed anyway (`finally`). The ticket write-back
    is no longer a step of the operator run (#1471 W7), so the page is the one post-lifecycle step left."""
    class Boom(Exception):
        pass

    def boom(*_a: Any, **_k: Any) -> None:
        raise Boom("visualize")

    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant), visualize=boom)
    assert out.reached, out.text()
    assert isinstance(out.raised, Boom), out.text()
    _no_copy_left(tenant)


@pytest.mark.parametrize("value", ["../current", "current", "SHORT"])
def test_o_pin_knowledge_commit_accepts_only_a_full_commit_id(tenant, tmp_path, value):
    """`--knowledge-commit` names a commit by its full id; `../current`, `current` and a short id are refused before the
    box (never resolved as a path) and before any fetch."""
    pin = tenant.commit[:7] if value == "SHORT" else value
    fetch = B.fetching(tenant)
    out = B.launch(tenant, tmp_path, fetch=fetch, argv_extra=("--knowledge-commit", pin))
    assert not out.reached, f"--knowledge-commit {pin!r} reached the box"
    assert out.raised is None, out.text()
    assert out.refusal is not None, out.text()
    assert "unrecognized arguments" not in out.refusal, (
        f"argparse does not know --knowledge-commit: {out.refusal}")
    assert fetch.calls == [], f"a malformed pin was handed to the fetch: {fetch.calls}"
    _no_copy_left(tenant)
