"""#1546 "Done when": one investigation through the real worker lane with the real per-job helper over a real docker
(`runsc-job` where boxes run under runsc), the REAL investigation entry's replay driver in the job container, the real
renderer, and Garage + OpenBao; only the allowlisted mounts reach the container, and nothing of the job is left on the host.
NOT RUN HERE (no native docker with the job runtime, no runsc): CI's `test` job (gVisor installed, job image and the test-only
replay layer built, Postgres, OpenBao and Garage started) runs it, and there a missing runtime or image FAILS it.

The container runs `_job_entry1342.py replay-container` (production post-run end: its own `page` fact, its own bundle and page
puts through the helper) from `tooling/testing/Dockerfile.job-replay`, the job image plus pytest that the replay harness
imports. What CI verifies: (1) the job container starts under `runsc-job` with the root and the read-only `.job-inputs` bind;
(2) its `docker run` mounts are exactly the allowlist (A-O9); (3) the job's evidence objects are in the store under the claim's
key, SSE-C with a key unwrapped from the row's wrapped key, bytes matching the recorded digest, the page equal to the renderer's
output computed HERE from the run held in the job's own bundle, not the job's call (A-O3, A-O8); (4) the row ends `complete`
from staged rows; (5) root, inputs and spool of the claim are gone (A-O1). NOT verified by it: a real model run (a replay
model), the alias probe at `/tmp`, cross-tenant refusals (slice SB).

Seam picks (store env, verbs, record shapes): `support/evidence/_facts1546.py`."""
from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from defender.box import BoxSpec
from defender.box._docker import CLAIM_LABEL
from defender.tests.e2e._replay_harness import committed_record, golden_disposition
from defender.tests.support.evidence._evidence1546 import evidence_keys, garage, new_sse_key  # noqa: F401 — fixtures
from defender.tests.support.evidence._facts1546 import RUN_PAGE, evidence_env
from defender.tests.support.jobs._evidence_flows1546 import INPUTS, ROOTS, SPOOL, accepted, claim_of, owner, sha
from defender.tests.support.jobs._job_helper import ensure_job_network, no_proxy_records
from defender.tests.support.jobs._jobs1342 import StandInContainers, an_alert, job_store, make_worker, register_tenant
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood

#: The test-only layer over the job image (`tooling/testing/Dockerfile.job-replay`), built by CI's `test` job.
REPLAY_IMAGE = os.environ.get("DEFENDER_JOB_REPLAY_IMAGE", "defender-job-replay:latest")
_RUNTIME = BoxSpec.from_env(os.environ).runtime
_ON_CI = bool(os.environ.get("CI"))


def _missing() -> str | None:
    """What this machine lacks for a real job container, or None. Off CI that skips the test; on CI it fails it."""
    if not daemon_reachable():
        return "no reachable docker daemon"
    if is_dood() and dood_anchor() is None:
        return "docker-outside-of-docker with no bind anchor"
    runtimes = docker_runtimes()
    if _RUNTIME not in runtimes or (_RUNTIME == "runsc" and "runsc-job" not in runtimes):
        return f"the daemon lacks the box runtime {_RUNTIME!r} (and `runsc-job` under runsc): {sorted(runtimes)}"
    if subprocess.run(["docker", "image", "inspect", REPLAY_IMAGE], capture_output=True, check=False).returncode != 0:
        return f"the test-only image {REPLAY_IMAGE} is not built (docker build -f tooling/testing/Dockerfile.job-replay)"
    return None


@pytest.fixture
def real_job_container():
    """Skip off CI; FAIL on CI (done-when 1 must never pass by skipping), and there the runtime must be runsc."""
    lacking = _missing()
    if lacking is not None:
        if _ON_CI:
            pytest.fail(f"CI must run the real job container, and it cannot: {lacking}")
        pytest.skip(lacking)
    if _ON_CI:
        assert _RUNTIME == "runsc", f"CI runs the job under gVisor, not {_RUNTIME!r}"


pytestmark = [pytest.mark.anyio, pytest.mark.e2e, pytest.mark.box, pytest.mark.postgres, pytest.mark.openbao,
              pytest.mark.garage]

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "e2e" / "golden-v2sshd"
HELPER_CHILD = Path(__file__).resolve().parents[1] / "support" / "jobs" / "_helper_child1546.py"
SHIM = """#!/bin/sh
printf '%s\\n' "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@")" >> "$DOCKER_LOG"
exec "$DOCKER_REAL" "$@"
"""


def _bind_sources(argv: list[str]) -> list[dict]:
    from defender.tests.support.jobs._job_helper import parse_mounts

    return parse_mounts(argv)


async def test_a_replayed_investigation_ends_complete_with_only_allowlisted_mounts_and_nothing_left(  # noqa: PLR0915 — one flow
        migrated_database, tmp_path, monkeypatch, openbao, garage, evidence_keys, real_job_container):  # noqa: F811
    """Queue -> worker -> real helper -> real container -> store -> `decide`/`apply`: `complete`, bundle and page promoted
    and readable from the store by their digests, the page the renderer's output over the run in the job's own bundle, the
    entry's own puts, `runsc-job`, the binds the allowlist, nothing left. (Done when 1; A-O1, A-O3, A-O8, A-O9)"""
    import shutil

    from defender.presentation import visualize_run
    from defender.tests.support.shared.contracts._spec1077 import fixture_run
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = Path(os.environ.get("TMPDIR", "/tmp")) / f"j1546{os.getpid()}"
    root.mkdir()
    try:
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
        monkeypatch.setenv("DEFENDER_JOB_IMAGE", REPLAY_IMAGE)
        for name, value in evidence_env(garage).items():
            monkeypatch.setenv(name, value)
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
                alert = await an_alert(store, t.tenant_id, raw=(GOLDEN / "alert.json").read_bytes())
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
            # the page is the renderer's output over the run the job's own bundle holds, computed here (not the job's call)
            unpacked = tmp_path / "unpacked"
            with tarfile.open(fileobj=io.BytesIO(fetched["bundle"]), mode="r:gz") as bundle_tar:
                bundle_tar.extractall(unpacked, filter="data")
            [held] = [p for p in unpacked.rglob(inv_id) if p.is_dir() and p.parent.name == "runs"]
            assert committed_record(held).disposition == golden_disposition(GOLDEN), "the bundle's run is not the replay's"
            expected_page = visualize_run.render_page(fixture_run(held)).encode("utf-8")
            assert fetched[RUN_PAGE] == expected_page
            assert expected_page.lstrip().lower().startswith(b"<!doctype html"), "premise: a real page"

            # the daemon's view of the job container's binds: the allowlist, no tenant folder, no other claim
            runs = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            (run,) = [c for c in runs if c[:1] == ["run"] and "--init" in c]
            assert run[run.index("--runtime") + 1] == ("runsc-job" if _RUNTIME == "runsc" else _RUNTIME), run
            assert REPLAY_IMAGE in run, "the job did not start from the test-only replay image"
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

            # nothing of the job is left on the host (asserted here, keyed by the claim's token)
            for base in (ROOTS, INPUTS, SPOOL, ".job-sockets", ".job-scratch"):
                assert not (root / base / token).exists(), f"{base}/<claim> outlived the job"
            left = subprocess.run(["docker", "ps", "-aq", "--filter", f"label={CLAIM_LABEL}={token}"], capture_output=True,
                                  text=True, check=True).stdout.split()
            assert left == [], f"a container of the claim outlived the job: {left}"
    finally:
        shutil.rmtree(root, ignore_errors=True)
