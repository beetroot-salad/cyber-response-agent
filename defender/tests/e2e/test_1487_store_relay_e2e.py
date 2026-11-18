"""#1487 sketch (design r1, O8): the store relay seen from inside a real post-step job container. NOT RUN HERE: like
`test_job_box_boundary_e2e.py` it needs a native docker daemon with the levered runtime and the job image; CI runs it.

The real helper (`job_host.main`, the real docker) starts a post-step container whose command is a probe: it holds no
database address, login or route, and through the helper's store relay it lists its own tenant's work and not
another's. The finding it reads was handed in by a learning job and made claimable by the worker's end write; here the
host side seeds it with the store's own verb (the chain through a worker is `tests/jobs/test_1487_*`)."""
from __future__ import annotations

import json
import uuid

import pytest

from defender.tests.e2e.test_job_box_boundary_e2e import requires_box
from defender.tests.support.jobs._job_helper import OTHER_TENANT, drive_helper, ensure_job_network, helper_scene
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import call, finding
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

pytestmark = [pytest.mark.e2e, pytest.mark.box, pytest.mark.postgres, requires_box]

PROBE = r'''
import json, os, sys
out, tenant, other = sys.argv[1], sys.argv[2], sys.argv[3]
seen = {"env": dict(os.environ)}
try:
    try:
        import psycopg
        psycopg.connect("", connect_timeout=5).close()
        seen["db"] = "connected"
    except Exception as e:
        seen["db"] = f"<{type(e).__name__}>"
    from defender.learning.branch.container import JobContainer
    store = JobContainer.in_environ().store()
    seen["own"] = [i.key for i in store.work(tenant)]
    seen["asked_other"] = [i.key for i in store.work(other)]
except BaseException:
    import traceback
    seen["error"] = traceback.format_exc()
finally:
    json.dump(seen, open(out, "w"))
'''


def test_o8_o3_from_inside_a_post_step_no_database_is_held_and_the_own_tenants_work_is_reachable_through_the_helper(
        tmp_path, monkeypatch, migrated_database):  # noqa: F811
    """(O8; #1170 O3 rewritten) not run here."""
    from defender.box import run_docker
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    with helper_scene(tmp_path, monkeypatch, migrated_database) as scene:
        register_tenant(scene.dsn, OTHER_TENANT)
        call(scene.dsn, "publish_findings", scene.tenant, "run-own", [finding("own/w/0/0")], kind="finding")
        call(scene.dsn, "publish_findings", OTHER_TENANT, "run-other", [finding("other/w/0/0")], kind="finding")
        out = scene.root / scene.tenant / f"probe-{uuid.uuid4().hex[:8]}.json"
        monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")
        ensure_job_network(run_docker)
        ran = drive_helper(scene, scene.argv("post-step", None), docker=run_docker, signer=A.MarkedSigner(),
                           command=["python3", "-c", PROBE, str(out), scene.tenant, OTHER_TENANT])
        assert ran.raised is None, ran.raised
        seen = json.loads(out.read_text(encoding="utf-8"))

    assert "error" not in seen, seen["error"]
    assert seen["db"] != "connected"
    assert not any(scene.dsn in v or "postgresql://" in v for v in seen["env"].values())
    assert seen["own"] == ["own/w/0/0"], "control: the tenant's own work is reachable through the helper"
    assert seen["asked_other"] == ["own/w/0/0"], "another tenant's work was reached"
