"""#1546 "Done when": one investigation through the real worker lane with the real per-job helper over a real docker
(`runsc-job` where boxes run under runsc), the real renderer, and Garage + OpenBao; only the allowlisted mounts reach the
container, and nothing of the job is left on the host afterwards. NOT RUN HERE (no native docker with the job runtime,
no runsc): CI's `test` job (gVisor installed, job image built, Postgres, OpenBao and Garage started) runs it.

What CI verifies (and only CI): (1) the job container starts under the `runsc-job` runtime with the root and the read-only
`.job-inputs` bind (G18); (2) its `docker run` mounts are exactly the allowlist (A-O9); (3) the job's evidence objects are
in the store under the claim's key, SSE-C with a key unwrapped from the row's wrapped key, bytes matching the recorded
digest, the page equal to the real renderer's output over the same run (A-O3, A-O8); (4) the row ends `complete` from
staged rows; (5) root, inputs and spool of the claim are gone (A-O1). NOT verified by it: a real model run (the job is the
protocol script `_job_container1546.py`, so the replay driver is not in the container), the alias probe at `/tmp` (G18's
other half: `test_box_boundary_e2e`/`test_scrub_lifecycle` own it), cross-tenant refusals (slice SB).

Seam picks, all in `support/jobs/_job_container1546.py`/here: the helper's store configuration env `DEFENDER_EVIDENCE_*`
(the design does not name it) and the verbs `outcome`, `page`, `evidence.put`."""
from __future__ import annotations

import io
import json
import os
import stat
import sys
import tarfile
from pathlib import Path

import pytest

from defender.box import BoxSpec
from defender.tests.support.evidence._evidence1546 import evidence_keys, garage, new_sse_key  # noqa: F401 — fixtures
from defender.tests.support.jobs._evidence_flows1546 import INPUTS, ROOTS, SPOOL, accepted, claim_of, owner, sha
from defender.tests.support.jobs._job_helper import ensure_job_network, no_proxy_records
from defender.tests.support.jobs._jobs1342 import StandInContainers, an_alert, job_store, make_worker, register_tenant
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood

_NO_DAEMON = not daemon_reachable()
_RUNTIME = BoxSpec.from_env(os.environ).runtime
requires_job_runtime = pytest.mark.skipif(
    _NO_DAEMON or (is_dood() and dood_anchor() is None)
    or (_RUNTIME == "runsc" and "runsc-job" not in docker_runtimes()) or _RUNTIME not in docker_runtimes(),
    reason="needs a native docker daemon with the box runtime and, under runsc, the runsc-job runtime (CI)")

pytestmark = [pytest.mark.anyio, pytest.mark.e2e, pytest.mark.box, pytest.mark.postgres, pytest.mark.openbao,
              pytest.mark.garage, requires_job_runtime]

HELPER_CHILD = Path(__file__).resolve().parents[1] / "support" / "jobs" / "_helper_child1546.py"
SHIM = """#!/bin/sh
printf '%s\\n' "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@")" >> "$DOCKER_LOG"
exec "$DOCKER_REAL" "$@"
"""


def _bind_sources(argv: list[str]) -> list[dict]:
    from defender.tests.support.jobs._job_helper import parse_mounts

    return parse_mounts(argv)


async def test_a_replayed_investigation_ends_complete_with_only_allowlisted_mounts_and_nothing_left(  # noqa: PLR0915 — one flow
        migrated_database, tmp_path, monkeypatch, openbao, garage, evidence_keys):  # noqa: F811
    """Queue -> worker -> real helper -> real container -> store -> `decide`/`apply`: `complete`, bundle and page promoted
    and readable from the store by their digests, the page the real renderer's, the binds the allowlist, the claim's root,
    inputs and spool gone. (Done when 1; A-O1, A-O3, A-O8, A-O9)"""
    import shutil

    from defender.presentation import visualize_run
    from defender.tests.support.shared.contracts._spec1077 import fixture_run
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = Path(os.environ.get("TMPDIR", "/tmp")) / f"j1546{os.getpid()}"
    root.mkdir()
    try:
        golden = Path(__file__).resolve().parents[1] / "fixtures" / "e2e" / "golden-v2sshd"
        oracle = tmp_path / "oracle-run"
        shutil.copytree(golden, oracle)
        expected_page = visualize_run.render_page(fixture_run(oracle)).encode("utf-8")
        real = shutil.which("docker")
        (tmp_path / "bin").mkdir()
        shim = tmp_path / "bin" / "docker"
        shim.write_text(SHIM, encoding="utf-8")
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
        log = tmp_path / "docker.log"
        monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("DOCKER_REAL", real)
        monkeypatch.setenv("DOCKER_LOG", str(log))
        monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
        monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
        for name, value in {"ENDPOINT": garage.endpoint, "BUCKET": garage.bucket, "ACCESS_KEY": garage.access_key,
                            "SECRET_KEY": garage.secret_key, "REGION": garage.region}.items():
            monkeypatch.setenv(f"DEFENDER_EVIDENCE_{name}", value)
        from defender.box import run_docker

        ensure_job_network(run_docker)

        with B.run_tenant(tmp_path, root) as t:
            register_tenant(migrated_database, t.tenant_id, data_root=root, records=no_proxy_records())
            (root / t.tenant_id / "runs").mkdir(exist_ok=True)
            evidence_keys.make(t.tenant_id)
            garage.tenant_prefix(t.tenant_id)

            def child(launch) -> list[str]:
                from defender.worker import run_argv

                helper = run_argv(launch)  # [python, -m, defender.job_host, --kind, investigation, <rest>]
                return [sys.executable, str(HELPER_CHILD), t.commit, *helper[helper.index("--job"):]]

            async with job_store(migrated_database) as store:
                alert = await an_alert(store, t.tenant_id)
                inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
                inv_id = inv.investigation_id
                worker = make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers"))
                await worker.drain()

            dsn = migrated_database
            assert owner(dsn, "investigations", inv_id, "stage", "disposition", "scrub", "evidence_state") == (
                "completed", "benign", "clean", "complete")
            token = claim_of(dsn, "investigation", inv_id)
            assert token
            assert accepted(dsn, token) == ["bundle", "page/runtime.html"]

            # the store: encrypted by the row's wrapped key, bytes matching the row's digest, the page the renderer's
            prefix = f"t/{t.tenant_id}/investigation/{inv_id}/{token}/"
            assert garage.list(prefix) == [prefix + "bundle", prefix + "page/runtime.html"], garage.list(prefix)
            rows = {o: (h, w) for o, h, w in execute(
                dsn, "SELECT object, sha256, wrapped_key FROM jobs.uploads WHERE token = %s", (token,))}
            fetched = {}
            for name, (digest, wrapped) in rows.items():
                key = evidence_keys.unwrap(t.tenant_id, wrapped)
                assert garage.get(prefix + name).status_code in (400, 403), "an unkeyed read of the object was served"
                body = garage.get(prefix + name, sse_key=key).content
                assert sha(body) == digest
                fetched[name] = body
            assert fetched["page/runtime.html"] == expected_page
            with tarfile.open(fileobj=io.BytesIO(fetched["bundle"]), mode="r:gz") as bundle_tar:
                members = bundle_tar.getnames()
            assert any(n.endswith("probe.json") for n in members), members
            probe_member = next(n for n in members if n.endswith("probe.json"))
            with tarfile.open(fileobj=io.BytesIO(fetched["bundle"]), mode="r:gz") as bundle_tar:
                probe = json.load(bundle_tar.extractfile(probe_member))

            # the daemon's view of the job container's binds: the allowlist, no tenant folder, no other claim
            runs = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            (run,) = [c for c in runs if c[:1] == ["run"] and "--init" in c]
            if _RUNTIME == "runsc":
                assert run[run.index("--runtime") + 1] == "runsc-job", run
            mounts = _bind_sources(["docker", *run])
            tenant_folder = root / t.tenant_id
            sources = {m["source"]: m for m in mounts}
            own_root, own_inputs = str(root / ROOTS / token), str(root / INPUTS / token)
            assert sources[own_root]["target"] == own_root, mounts
            assert not sources[own_root]["readonly"], mounts
            assert sources[own_inputs]["readonly"], mounts
            for m in mounts:
                assert not Path(m["source"]).is_relative_to(tenant_folder), f"a bind names the tenant folder: {m}"
                rel = Path(m["source"]).relative_to(root) if Path(m["source"]).is_relative_to(root) else None
                assert rel is None or not rel.parts[0].startswith(".job-") or token in rel.parts, f"another claim: {m}"
            assert probe["outside_tenant_folder"].startswith("<"), probe
            assert not probe["lists_.job-roots"], probe
            assert not probe["lists_.job-spool"], probe

            # nothing of the job is left on the host (asserted here, keyed by the claim's token)
            for base in (ROOTS, INPUTS, SPOOL, ".job-sockets", ".job-scratch"):
                assert not (root / base / token).exists(), f"{base}/<claim> outlived the job"
    finally:
        shutil.rmtree(root, ignore_errors=True)
