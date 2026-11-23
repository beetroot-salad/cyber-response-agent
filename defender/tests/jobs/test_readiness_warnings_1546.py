# ruff: noqa: PT018
"""#1546 A-O7 (r9, one release): the readiness check warns, host-side, of a tenant whose evidence key is missing
(`evidence_key_missing`) and stays `ready`; the kind is declared in the container's record vocabulary and the API's. A tenant
without a retention row no longer exists (D16), so there is no `retention_unset`. The warning is read off the finished
`host_requests.result` row (the worker's end over the helper's staged facts), not a host file (D5, A-O2).

Pinned (missing): the helper takes a seam `evidence_keys` (an object with `exists(tenant_id) -> bool`) that answers whether the
tenant's `evidence-<T>` key is in the secret store. Whether the helper or the worker merges the warning is not pinned: the
row is what is observed."""
from __future__ import annotations

import asyncio
import contextlib
import io
import sys
import uuid
from typing import Any, get_args

import pytest

from defender.tests.support.jobs._job_helper import ContainerStandIn, drive_helper, make_signer
from defender.tests.support.jobs._readiness1471 import Readied, entry_of, readiness_scene
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and uses prctl(PR_SET_PDEATHSIG), Linux only")]

KIND = "evidence_key_missing"


def test_both_warning_kind_lists_declare_the_evidence_key_warning_and_not_the_retired_retention_one():
    """`evidence_key_missing` is in the container record's kinds (`records/job_lane.py`) and the API's `WarningKind`;
    `retention_unset` is in neither (D16). (A-O7)"""
    from defender.api import models
    from defender.records import job_lane

    for kinds in (set(job_lane.READINESS_WARNING_KINDS), set(get_args(models.WarningKind))):
        assert KIND in kinds and "retention_unset" not in kinds


class _Keys:
    def __init__(self, present: bool) -> None:
        self.present, self.asked = present, []

    def exists(self, tenant_id: str) -> bool:
        self.asked.append(tenant_id)
        return self.present


def _check(scene: Any, keys: _Keys) -> tuple[Readied, dict[str, Any]]:
    """One readiness check over the scene (as `readiness()` runs it) with the `evidence_keys` seam handed to the helper, for a
    planted host request claimed under the scene's token; then the worker's end of it. Returns the run and the request's row."""
    from defender.tests.support.jobs._ending1546 import end_row
    from defender.tests.support.jobs._helper_evidence1546 import plant
    from defender.tests.support.jobs._jobs1342 import job_store

    planted = plant(scene, "readiness")
    rid = planted.owner
    done = Readied(scene, rid, None, ContainerStandIn(), "")  # type: ignore[arg-type]
    stand_in = ContainerStandIn()
    stand_in.job = entry_of(scene, rid, done)
    done.docker = stand_in
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        done.ran = drive_helper(scene, scene.argv("readiness", rid), docker=stand_in, signer=make_signer(),
                                evidence_keys=keys)
    done.err = err.getvalue()

    async def end() -> None:
        async with job_store(scene.dsn) as store:
            await end_row(store, scene.dsn, kind="readiness", tenant=scene.tenant, owner=rid, token=planted.claim, by="exited")

    asyncio.run(end())
    [(row,)] = execute(scene.dsn, "SELECT result FROM jobs.host_requests WHERE id = %s", (rid,))
    return done, row


def test_the_check_warns_of_a_missing_evidence_key_on_the_request_row_and_stays_ready(tmp_path, monkeypatch, migrated_database):
    """Two checks of one tenant, its evidence key present and then missing: both read `ready` on their finished `host_requests`
    rows; the missing key adds exactly one warning with a sentence to what the check reports with the key (the systems check's
    own warnings stay, #1471 R4); each asked for the tenant's own key. (A-O7)"""
    from collections import Counter
    from dataclasses import replace

    from defender.box import CLAIM_ENV

    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        kinds = {}
        for present in (True, False):
            keys = _Keys(present)
            done, result = _check(scene, keys)
            assert isinstance(result, dict) and result["outcome"] == "ready", (result, done.said())
            assert keys.asked == [scene.tenant], "the key check was not asked for the tenant's key"
            kinds[present] = [w["kind"] for w in result["warnings"]]
            for warning in result["warnings"]:
                assert warning["sentence"].strip(), warning
            scene = replace(scene, claim=uuid.uuid4().hex)  # the next check is another request under its own claim
            monkeypatch.setenv(CLAIM_ENV, scene.claim)
        assert KIND not in kinds[True], kinds
        assert Counter(kinds[False]) == Counter(kinds[True]) + Counter([KIND]), kinds
