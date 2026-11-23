# ruff: noqa: PT018
"""#1546 A-O7 (r9, one release): the readiness check warns, host-side, of a tenant whose evidence key is missing
(`evidence_key_missing`) and stays `ready`; the kind is declared in the container's record vocabulary and the API's. A tenant
without a retention row no longer exists (D16), so there is no `retention_unset`. The warning is read off the finished
`host_requests.result` row (the worker's end over the helper's staged facts), not a host file (D5, A-O2).

The helper's `evidence_keys` seam is the tenant's key login (an `evidence.EvidenceKeys` over an AppRole holding the lifecycle's
policy for `evidence-<T>`, as `_helper_evidence1546.evidence_login` makes it): the check is observed against a REAL OpenBao,
whose transit key `evidence-<T>` is there or not. Whether the helper or the worker merges the warning is not pinned: the row
is what is observed."""
from __future__ import annotations

import asyncio
import contextlib
import io
import sys
import uuid
from typing import Any, get_args

import pytest

from defender.tests.support.jobs._job_helper import ContainerStandIn, drive_helper, make_signer
from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.jobs._readiness1471 import SECOND_TENANT, Readied, entry_of, readiness_scene
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.postgres, pytest.mark.garage, pytest.mark.openbao, pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and uses prctl(PR_SET_PDEATHSIG), Linux only")]

KIND = "evidence_key_missing"


def test_both_warning_kind_lists_declare_the_evidence_key_warning_and_not_the_retired_retention_one():
    """`evidence_key_missing` is in the container record's kinds (`records/job_lane.py`) and the API's `WarningKind`;
    `retention_unset` is in neither (D16). (A-O7)"""
    from defender.api import models
    from defender.records import job_lane

    for kinds in (set(job_lane.READINESS_WARNING_KINDS), set(get_args(models.WarningKind))):
        assert KIND in kinds and "retention_unset" not in kinds


def _seams(scene: Any, bao: Any, store: Any) -> dict[str, Any]:
    """The seams a helper is configured with (an unconfigured store or key login is refused at setup, r8): the real store, and
    the scene tenant's key login. Nothing here makes the tenant's key: a case makes it, or leaves it missing."""
    from defender.tests.support.jobs._helper_evidence1546 import evidence_login, evidence_module

    evidence = evidence_module()
    return {"evidence": evidence.BlobStore(endpoint=store.endpoint, bucket=store.bucket, access_key=store.access_key,
                                           secret_key=store.secret_key, region=store.region),
            "evidence_keys": evidence.EvidenceKeys(addr=bao.addr, **evidence_login(bao, scene.tenant))}


def _check(scene: Any, seams: dict[str, Any]) -> tuple[Readied, dict[str, Any]]:
    """One readiness check over the scene (as `readiness()` runs it) with the key-login and store `seams` handed to the helper, for
    a planted host request claimed under the scene's token; then the worker's end of it. Returns the run and the request's row."""
    from defender.tests.support.jobs._ending1546 import end_row
    from defender.tests.support.jobs._helper_evidence1546 import plant
    from defender.tests.support.jobs._jobs1342 import job_store

    planted = plant(scene, "readiness")
    rid = planted.owner
    done = Readied(scene, rid, None, ContainerStandIn(), "", token=planted.claim)  # type: ignore[arg-type]
    stand_in = ContainerStandIn()
    stand_in.job = entry_of(scene, rid, done)
    done.docker = stand_in
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        done.ran = drive_helper(scene, scene.argv("readiness", rid), docker=stand_in, signer=make_signer(), **seams)
    done.err = err.getvalue()

    async def end() -> None:
        async with job_store(scene.dsn) as store:
            await end_row(store, scene.dsn, kind="readiness", tenant=scene.tenant, owner=rid, token=planted.claim, by="exited")

    asyncio.run(end())
    [(row,)] = execute(scene.dsn, "SELECT result FROM jobs.host_requests WHERE id = %s", (rid,))
    return done, row


def test_the_check_warns_of_a_missing_evidence_key_on_the_request_row_and_stays_ready(
        tmp_path, monkeypatch, migrated_database, openbao, garage, evidence_keys):  # noqa: F811 — the imported fixtures
    """Three checks of one tenant against a real OpenBao: its evidence key missing while another tenant's exists, then its own key
    made. All read `ready` on their finished `host_requests` rows; the missing key adds exactly one warning with a sentence to
    what the check reports with the key (the systems check's own warnings stay, #1471 R4), and another tenant's key does not
    answer for this tenant's. (A-O7)"""
    from collections import Counter
    from dataclasses import replace

    from defender.box import CLAIM_ENV

    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        kinds = {}
        for phase in ("missing", "present"):
            if phase == "missing":
                evidence_keys.make(SECOND_TENANT)  # another tenant's key: the control that the check asks for this tenant's own
            else:
                evidence_keys.make(scene.tenant)
            done, result = _check(scene, _seams(scene, openbao, garage))
            assert isinstance(result, dict) and result["outcome"] == "ready", (result, done.said())
            kinds[phase] = [w["kind"] for w in result["warnings"]]
            for warning in result["warnings"]:
                assert warning["sentence"].strip(), warning
            scene = replace(scene, claim=uuid.uuid4().hex)  # the next check is another request under its own claim
            monkeypatch.setenv(CLAIM_ENV, scene.claim)
        assert KIND not in kinds["present"], kinds
        assert Counter(kinds["missing"]) == Counter(kinds["present"]) + Counter([KIND]), kinds
