"""#1546 A-O7 rollout (release 1): the readiness check warns, host-side, of a tenant with no retention row
(`retention_unset`) and of a tenant whose evidence key is missing (`evidence_key_missing`); neither refuses the check; both
kinds are declared in the container's record vocabulary and the API's.

Pinned (missing): the helper writes the final `ready` record with these warnings among the container's; the helper takes a
seam `evidence_keys` (an object with `exists(tenant_id) -> bool`) that answers whether the tenant's `evidence-<T>` key is in
the secret store. FORCED CHOICE: whether the helper or the worker merges them (the contract observes the record the helper
leaves, `<runs>/<id>.readiness.json`)."""
from __future__ import annotations

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

NEW_KINDS = {"retention_unset", "evidence_key_missing"}


def test_both_warning_kind_lists_declare_the_two_rollout_warnings():
    """`retention_unset` and `evidence_key_missing` are in the container record's kinds (`records/job_lane.py`) and the
    API's `WarningKind`. (A-O7 rollout)"""
    from defender.api import models
    from defender.records import job_lane

    assert set(job_lane.READINESS_WARNING_KINDS) >= NEW_KINDS
    assert set(get_args(models.WarningKind)) >= NEW_KINDS


class _Keys:
    def __init__(self, present: bool) -> None:
        self.present, self.asked = present, []

    def exists(self, tenant_id: str) -> bool:
        self.asked.append(tenant_id)
        return self.present


def _check(scene: Any, keys: _Keys) -> Readied:
    """One readiness check over the scene (as `readiness()` runs it) with the `evidence_keys` seam handed to the helper."""
    rid = str(uuid.uuid4())
    done = Readied(scene, rid, None, ContainerStandIn(), "")  # type: ignore[arg-type]
    stand_in = ContainerStandIn()
    stand_in.job = entry_of(scene, rid, done)
    done.docker = stand_in
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        done.ran = drive_helper(scene, scene.argv("readiness", rid), docker=stand_in, signer=make_signer(),
                                evidence_keys=keys)
    done.err = err.getvalue()
    return done


def _kinds(done: Readied) -> list[str]:
    record = done.result()
    assert record["outcome"] == "ready", done.said()
    return [w["kind"] for w in record["warnings"]]


@pytest.mark.parametrize(("retention", "key_present", "expected"), [
    (False, True, {"retention_unset"}),
    (True, False, {"evidence_key_missing"}),
    (False, False, NEW_KINDS),
    (True, True, set()),
])
def test_the_check_warns_of_each_missing_piece_and_stays_ready(tmp_path, monkeypatch, migrated_database, retention,
                                                               key_present, expected):
    """A tenant lacking its retention row and/or its evidence key reads `ready` with exactly the matching rollout
    warnings, each with a sentence; with both present neither is raised. (A-O7 rollout)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        if retention:
            execute(migrated_database, "INSERT INTO tenancy.evidence_retention (tenant_id, investigation_days, learning_days) "
                                       "VALUES (%s, 90, 90)", (scene.tenant,))
        keys = _Keys(key_present)
        done = _check(scene, keys)
        kinds = _kinds(done)
        assert NEW_KINDS & set(kinds) == expected, done.said()
        assert len(kinds) == len(set(kinds)), "a warning kind was raised twice"
        for warning in done.result()["warnings"]:
            assert warning["sentence"].strip(), warning
        assert keys.asked == [scene.tenant], "the key check was not asked for the tenant's key"
