"""#1108 P4 run-copy and run-start edge cases, each a wrong-but-green production variant: per-copy tokens, the
host knowledge-source record, and the host secret file's location.

Real `run.main` over the fetch seam (`B.fetching`, #1618 flow 1). Retired with `copy_for_run` (#1618 flow 1: the
caller makes an owned empty folder, the fetch child fills it, the caller renames it into place, D5), each with its
successor in `knowledge_1618/test_run_start_1618.py`: "a second copy for a run id whose owner lives is refused" and "a
dead owner's copy at the run id is replaced" (`::test_a5_a_dead_owners_folder_at_the_run_id_is_never_replaced_*`: the
rename refuses onto any existing folder, so a dead owner's is no longer replaced), and "a copy build cut off mid-write
already names its owner" (`::test_1618_k7_the_run_copy_holds_its_owner_record_at_the_instant_it_is_renamed_into_place`
and `::test_a4_*`: the temporary carries its owner in its name from its first instant).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender.tenancy import run_knowledge
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge
from defender.tests.tenancy.tenant_1108_p4.test_run_copy import (
    _mount_sources,
    boxed_only,  # noqa: F401, F811 — fixture
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        yield t


# --- each run copy's token is its own ---------------------------------------------------------

def test_r6_every_run_copy_stages_its_own_unpredictable_token(tenant, tmp_path):
    """Three runs of one tenant: each copy's `stage/<token>` is its own, at least 128 bits of hex. (#1618: read while
    each run is live, through `run.main`, as `copy_for_run` is gone.)"""
    def token(seen: B.Seen) -> str:
        return (B.copy_stage(tenant, seen.run_dir) / run_knowledge.STAGE_TOKEN).read_text(encoding="utf-8").strip()

    tokens = []
    for n in range(3):
        out = B.launch(tenant, tmp_path / f"run-{n}", fetch=B.fetching(tenant), during=token)
        assert out.reached, out.text()
        tokens.append(out.seen[0].during)
    assert len(set(tokens)) == 3, f"run copies share a token: {tokens}"
    assert all(len(t) >= 32 for t in tokens), tokens


# --- the host knowledge-source record is written before the box -------------------------------

def test_r6_the_host_knowledge_source_record_exists_when_the_lifecycle_starts(tenant, tmp_path):
    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant),
                   during=lambda seen: B.read_host_record(seen.run_dir))
    assert out.rc == 0, out.text()
    record = out.seen[0].during
    assert isinstance(record, dict), "no host record when the run's lifecycle started"
    assert record["kind"] == "fresh"
    assert record["commit"] == tenant.commit


def test_r6_a_run_that_cannot_write_its_host_knowledge_record_does_not_start(tenant, tmp_path):
    """The record is the run's only host-held knowledge source: a run that cannot write it does
    not start. The run dir is built by the real `materialize`; a wrapper then puts a directory
    where the record must go (after materialize cleared any stale sidecar)."""
    from defender import run as run_py

    def materialize_then_block(*a: Any, **k: Any):
        run = run_py._materialize_run(*a, **k)
        B.host_record_path(Path(run.run_dir)).mkdir()
        return run

    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant), materialize=materialize_then_block)
    assert not out.reached, f"the run started without its knowledge record: {out.text()}"
    assert out.refusal, out.text()
    assert "knowledge record" in out.refusal, out.text()


# --- the host secret file a generation records lies under no box mount source ------------------

def test_r6_the_host_secret_file_location_lies_under_no_box_mount_source(tenant, tmp_path,
                                                                        boxed_only):  # noqa: F811 — fixture
    """The host secret file the tenant's live generation records (#1214: the AppRole secret id, one file per
    tenant outside the tenant folder) is under no box mount source."""
    secret = bind_forge(tenant)["generations"][0]["host_secret_file"]
    sources = _mount_sources(tenant, tmp_path)
    assert not T.exposes(sources, secret), f"a box mount exposes the host secret file {secret}"
