"""#1170 sketch (test_o3 rewritten for #1487 O8c): what a real job container can reach, observed from inside it. NOT RUN HERE: they need a native docker
daemon with the levered runtime (gVisor `runsc`) and skip in this devcontainer (docker-outside-of-Docker); CI runs them.
They also need the job container's image, which the design does not yet say where comes from (dev, CI, prod).

The real helper (`job_host.main`, the real docker) starts the container with a probe as its command (`command=`, a
sketch seam) in place of the kind's entry; the probe writes what it saw into its own tenant folder, read here.

#1546 (A-O9, design r9 "Mounts are an allowlist"; A-O1): an investigation container is bound its claim's own root
(`.job-roots/<claim>/`, its `DEFENDER_DATA_ROOT`), never the tenant's host folder, and the root is gone once the job ends. So
the tenant folder the probe calls its own is `<job root>/<T>/`: the host plants the own canary there once the helper has
made the root (at the container's `docker run`, `_Recorded.popen`) and keeps the probe's `probe.json` the moment the
container has exited, before the helper removes the root (`_Kept`). A canary in the tenant's host folder is now one the
container must not read, beside the other tenant's."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

from defender import job_host
from defender.box import BoxSpec
from defender.tests.support.jobs._job_helper import CANARY, OTHER_TENANT, drive_helper, ensure_job_network, helper_scene
from defender.tests.support.jobs._helper_evidence1546 import job_root  # the claim's own root: the container's data root (#1546 A-O9)
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood

_NO_DAEMON = not daemon_reachable()
_DOOD = (not _NO_DAEMON) and is_dood()
_RUNTIME = BoxSpec.from_env(os.environ).runtime
requires_box = pytest.mark.skipif(
    _NO_DAEMON or (_DOOD and dood_anchor() is None) or ((not _NO_DAEMON) and _RUNTIME not in docker_runtimes()),
    reason="needs a native docker daemon with the levered runtime (as `test_box_boundary_e2e.requires_box`)")

pytestmark = [pytest.mark.e2e, pytest.mark.box, pytest.mark.postgres, pytest.mark.openbao, pytest.mark.garage, requires_box]

#: The own canary's bytes and file name, planted in the job's own tenant folder (`<job root>/<T>/`).
OWN = "OWN-1170"
OWN_CANARY = "own-canary"
#: A canary in the tenant's HOST folder (`<data root>/<T>/`), which no investigation container binds (A-O9).
HOST_CANARY = "HOST-1546"
#: The probe's observations, in the job's own tenant folder (`<job root>/<T>/probe.json`), kept by the host on exit.
OUT = "probe.json"

#: Runs inside the job container (product code mounted read-only, so `defender` imports). Writes probe.json into its own
#: tenant folder under its `DEFENDER_DATA_ROOT` (the claim's root, #1546 A-O9).
PROBE = r'''
import json, os, shutil, subprocess, sys
tenant, other, host, viz, inv, secrets = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6:]
mine = os.path.join(os.environ["DEFENDER_DATA_ROOT"], tenant)
out, own = os.path.join(mine, "probe.json"), os.path.join(mine, "own-canary")
seen = {"env": dict(os.environ), "own_folder": mine}
try:
    def reads(p):
        try:
            return open(p, encoding="utf-8").read()
        except OSError as e:
            return f"<{type(e).__name__}>"
    seen["other_canary"] = reads(other)
    seen["host_canary"] = reads(host)
    seen["own_canary"] = reads(own)
    seen["secrets"] = [reads(p) for p in secrets]
    def writes(p):
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write("x")
            return True
        except OSError:
            return False
    from defender import job_host
    # `defender` is a namespace package (no `__file__`); a module of it names the tree: <root>/defender/job_host/__init__.py (job_host is a package)
    code = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(job_host.__file__))))
    seen["code_root"] = code
    seen["code_env_files"] = [n for n in os.listdir(code) + os.listdir(os.path.join(code, "defender")) if n.startswith(".env")]
    seen["code_writable"] = writes(os.path.join(code, "defender", "written-by-job"))
    seen["own_writable"] = writes(own + ".w")
    seen["viz_canary"] = reads(os.path.join(viz, "canary"))
    seen["viz_writable"] = writes(os.path.join(viz, "written-by-job"))
    seen["docker_sock"] = os.path.exists("/var/run/docker.sock")
    try:
        rc = subprocess.run(["docker", "ps"], capture_output=True, timeout=30).returncode
        seen["docker_ps"] = rc
    except OSError as e:
        seen["docker_ps"] = f"<{type(e).__name__}>"
    try:
        import psycopg
        psycopg.connect("", connect_timeout=5).close()
        seen["db"] = "connected"
    except Exception as e:
        seen["db"] = f"<{type(e).__name__}>"
    sock = os.environ[job_host.SOCKET_ENV]
    try:
        h = job_host.ask(sock, "box.start", kind="shell", id=inv)["handle"]
        from defender.execution import bash_exec, box_codec
        frame = box_codec.encode_request(bash_exec.parse("echo box-ok"))
        answer = job_host.ask(sock, "box.exec", handle=h, frame=frame)
        seen["shell"] = [answer.get("result"), box_codec.decode_response(answer["frame"]).out.decode()]
    except Exception as e:
        seen["shell"] = f"<{type(e).__name__}: {e}>"
except BaseException:
    import traceback
    seen["error"] = traceback.format_exc()
finally:
    json.dump(seen, open(out, "w"))
'''


def _is_job_run(argv: list[str]) -> bool:
    """The job container's attached `docker run` (a box is created, not run with `--init`)."""
    return argv[:2] == ["docker", "run"] and "--init" in argv


class _Kept:
    """The job container's process, as the helper polls it: the first time it is seen ended (`poll`, `wait` or
    `communicate`), the probe's file is copied out of the job's root, which the helper removes after (A-O1)."""

    def __init__(self, proc, keep) -> None:  # noqa: ANN001 — a Popen and a callable
        self._proc, self._keep = proc, keep

    def _seen(self, answer):  # noqa: ANN001, ANN202
        if self._proc.returncode is not None:
            self._keep()
        return answer

    def poll(self):  # noqa: ANN201
        return self._seen(self._proc.poll())

    def wait(self, *a, **kw):  # noqa: ANN002, ANN003, ANN201
        return self._seen(self._proc.wait(*a, **kw))

    def communicate(self, *a, **kw):  # noqa: ANN002, ANN003, ANN201
        return self._seen(self._proc.communicate(*a, **kw))

    def __getattr__(self, name):  # noqa: ANN001, ANN204
        return getattr(self._proc, name)


class _Recorded:
    """The real docker, recording each argv it is asked (the attached `docker run` of the job container included). With
    `own_folder` and `kept`: at the job container's `docker run` (the helper has made the claim's root by then) the own
    canary is planted in `own_folder`, and the probe's file there is copied to `kept` once the container has exited."""

    def __init__(self, own_folder: Path | None = None, kept: Path | None = None) -> None:
        self.calls: list[list[str]] = []
        self.own_folder, self.kept = own_folder, kept
        self.planted = False

    def __call__(self, argv, **kw):  # noqa: ANN001 — DockerFn
        from defender.box import run_docker

        self.calls.append(list(argv))
        return run_docker(argv, **kw)

    def popen(self, argv, **kw):  # noqa: ANN001, ANN201 — the seam's own
        from defender.box import run_docker

        self.calls.append(list(argv))
        if self.own_folder is None or not _is_job_run(list(argv)):
            return run_docker.popen(argv, **kw)
        assert self.own_folder.is_dir(), f"premise: the helper made the job's own tenant folder before its container: {self.own_folder}"
        (self.own_folder / OWN_CANARY).write_text(OWN, encoding="utf-8")
        self.planted = True
        return _Kept(run_docker.popen(argv, **kw), self._keep)

    def _keep(self) -> None:
        found = self.own_folder / OUT if self.own_folder is not None else None
        if self.kept is not None and found is not None and not self.kept.exists() and found.is_file():
            self.kept.write_bytes(found.read_bytes())


@pytest.fixture
def probed(tmp_path, monkeypatch, migrated_database):  # noqa: F811
    """One real job container of the scene's tenant, run with the probe; what it saw."""
    from defender.box import run_docker
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    with helper_scene(tmp_path, monkeypatch, migrated_database) as scene:
        inv = str(uuid.uuid4())
        scene.plant(inv)
        # The tenant's host folder: a canary the container must not read (no bind names it, A-O9).
        host = scene.root / scene.tenant / "host-canary"
        host.write_text(HOST_CANARY, encoding="utf-8")
        own_folder = job_root(scene) / scene.tenant  # the job's own tenant folder: the helper makes it at setup
        out = Path(tmp_path) / "probe-kept.json"
        # The publish folder (A10) is one host folder outside every tenant and the data root, holding a canary. It is
        # in the helper's own environment (the dev run page) and must not be in the job's.
        viz = Path(tmp_path) / "published-pages"
        viz.mkdir()
        (viz / "canary").write_text(CANARY, encoding="utf-8")
        monkeypatch.setenv("DEFENDER_RUN_VISUALIZATIONS_DIR", str(viz))
        monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")
        ensure_job_network(run_docker)
        command = ["python3", "-c", PROBE, scene.tenant,
                   str(scene.root / OTHER_TENANT / "canary"), str(host), str(viz), inv, *map(str, scene.secrets)]
        docker = _Recorded(own_folder, out)
        ran = drive_helper(scene, scene.argv("investigation", inv), docker=docker, signer=A.MarkedSigner(),
                           command=command)
        assert ran.raised is None, ran.raised
        assert docker.planted, f"premise: the helper started the job container (rc {ran.rc}): {docker.calls}"
        assert out.is_file(), f"the probe left no {OUT} in the job's own tenant folder {own_folder} (rc {ran.rc})"
        seen = json.loads(out.read_text(encoding="utf-8"))
        assert not job_root(scene).exists(), "premise (A-O1): the job's root is gone after the job"
        # What the helper asked docker (#1469 S2: the job container's runtime), beside what the probe saw.
        seen["host_docker_calls"] = docker.calls
        assert "error" not in seen, f"the probe crashed inside the container: {seen['error']}"
        yield scene, seen, viz


def test_o1_from_inside_another_tenants_canary_is_unreadable_and_its_own_folder_is(probed):
    """(O1; #1546 A-O9) not run here. Its own folder is the job's own root's tenant folder; another tenant's canary and the
    tenant's host folder (no bind names it) are unreadable."""
    scene, seen, _viz = probed
    assert Path(seen["own_folder"]) == job_root(scene) / scene.tenant, (
        "the container's own folder is not under the claim's own root", seen["own_folder"])
    assert seen["env"].get("DEFENDER_DATA_ROOT") == str(job_root(scene)), seen["env"].get("DEFENDER_DATA_ROOT")
    assert seen["own_canary"] == OWN, "control: the job's own folder is readable"
    assert seen["other_canary"].startswith("<"), seen["other_canary"]
    assert CANARY not in seen["other_canary"]
    assert seen["host_canary"].startswith("<"), ("the tenant's host folder was readable from inside (A-O9)", seen["host_canary"])
    assert HOST_CANARY not in seen["host_canary"]


def test_o2_from_inside_docker_is_unreachable_and_a_shell_box_still_runs(probed):
    """(O2) not run here."""
    _scene, seen, _viz = probed
    assert seen["docker_sock"] is False
    assert seen["docker_ps"] != 0
    assert seen["shell"] == ["ok", "box-ok\n"], f"control: a shell box command through the socket ran: {seen['shell']}"


def test_s2_under_runsc_boxes_the_job_container_runs_on_runsc_job_and_reaches_its_socket(probed):
    """The job container starts under `runsc-job` when boxes run under `runsc`, and its shell box through the socket
    runs (o2's control). (#1469 S2)"""
    _scene, seen, _viz = probed
    if _RUNTIME != "runsc":
        pytest.skip("boxes here run under runc: the job runs under runc too (the hermetic S2 test)")
    (run,) = [c for c in seen["host_docker_calls"] if c[:2] == ["docker", "run"] and "--init" in c]
    assert run[run.index("--runtime") + 1] == "runsc-job", run
    assert seen["shell"] == ["ok", "box-ok\n"], seen["shell"]


@pytest.fixture
def post_step_reach(tmp_path, monkeypatch, migrated_database):  # noqa: F811
    """A real post-step container of the scene's tenant (the one kind that gets the tick's store) running the reach program, over batches the host seeded; what it saw."""
    from defender.box import run_docker
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.support.jobs import _real_containers1487 as R
    from defender.tests.support.jobs._jobs1342 import register_tenant
    from defender.tests.support.learning.core._store1278 import batches

    R.compiled()
    with helper_scene(tmp_path, monkeypatch, migrated_database) as scene:
        register_tenant(scene.dsn, OTHER_TENANT)
        seeded = R.seed_reach(scene.dsn, scene.tenant, OTHER_TENANT)
        R.prepare(scene.root, scene.tenant, scene.dsn, ids=seeded.ids)
        monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")
        ensure_job_network(run_docker)

        def state() -> dict:
            every = batches(scene.dsn, scene.tenant) + batches(scene.dsn, OTHER_TENANT)
            return {str(b.id): (b.phase, b.outcome, b.token, b.lease_owner, b.reason) for b in every}

        before = state()
        ran = drive_helper(scene, scene.argv("post-step", None), docker=run_docker, signer=A.MarkedSigner(),
                           command=["python3", "-c", R.REACH, scene.tenant])
        assert ran.raised is None, ran.raised
        yield scene, seeded, R.observed(scene.root, scene.tenant, "reach"), before, state()


def test_o3_from_inside_no_database_address_or_login_is_held_and_the_helper_reaches_only_the_own_tenants_and_lanes(
        post_step_reach):
    """(O8c; #1170 O3 rewritten) no database held; own work reachable; another tenant's batch unseen; another lane's lapsed batch not taken over, its working batch not parked or ended."""
    from defender.tests.support.jobs import _real_containers1487 as R

    scene, seeded, seen, before, after = post_step_reach
    ids = seeded.ids
    assert R.host_can_dial(scene.dsn), "control: the address the container dials is live from the host"
    assert R.database_held(seen, scene.dsn) == []
    assert ["finding", seeded.own_finding] in seen["own_work"], "control: the tenant's own work is reachable through the helper"
    assert ids["other_working"] not in seen["listed"], "another tenant's batch was listed"
    assert not any(k.startswith("other-a/") for _kind, k in seen["own_work"]), "another tenant's work was listed"
    calls = seen["calls"]
    assert calls["own_lapsed_take_over"] == {"returned": "Held"}, "control: the own lane's lapsed batch can be taken over"
    refused = {name: call for name, call in calls.items() if name != "own_lapsed_take_over"}
    assert refused == {name: {"raised": "ForeignBatch"} for name in refused}, refused
    for name in ("lead_lapsed", "feedback_working", "other_working"):
        assert after[ids[name]] == before[ids[name]], f"{name} was changed"
    assert after[ids["author_lapsed"]] != before[ids["author_lapsed"]], "control: the taken-over batch changed"


def test_o4_from_inside_no_sign_login_openbao_login_or_forge_secret_is_readable(probed):
    """(O4) not run here."""
    _scene, seen, _viz = probed
    assert all(s.startswith("<") for s in seen["secrets"]), seen["secrets"]
    assert not {"VAULT_ADDR", "VAULT_TOKEN", "BAO_ADDR", "BAO_TOKEN"} & set(seen["env"])


def test_a7_the_code_mounted_is_the_code_tree_the_helper_runs_from_read_only_at_the_same_path_with_no_env_file(probed):
    """(A7, O1) not run here. The helper knows its code only as the tree it runs from (the worker starts it with that
    tree, its code copy, as the working directory: `worker/__main__.py` `child_cwd=copy`, `_start.refresh_code_copy`), so
    the code the job imports is the tree `defender` itself is imported from here, at the same path; the job cannot write
    into it; it holds no `.env*`. That the tree a worker's helper runs from is the worker's code copy rests on the worker's
    `child_cwd` (nothing in the helper names the copy); no path of the copy (`.defender-code`) is assumed here."""
    scene, seen, _viz = probed
    assert Path(seen["code_root"]) == Path(job_host.__file__).resolve().parents[2]
    assert seen["code_writable"] is False
    assert seen["code_env_files"] == []
    assert seen["own_writable"] is True, "control: the job's own folder is writable"


def test_a10_the_shared_publish_folder_is_not_visible_from_inside(probed):
    """(A10) not run here. `DEFENDER_RUN_VISUALIZATIONS_DIR` names a host folder shared by every tenant: it is
    neither readable nor writable from the job container. Control: the job's own folder is (#1546: its own root)."""
    _scene, seen, _viz = probed
    assert seen["viz_canary"].startswith("<"), seen["viz_canary"]
    assert CANARY not in seen["viz_canary"]
    assert seen["viz_writable"] is False
    assert seen["own_writable"] is True, "control: the job's own folder is writable"


def test_o4_from_inside_no_environment_name_or_value_carries_a_login_or_secret_file(probed):
    """(O4, A8, A10) not run here. Nothing in the environment names an OpenBao/forge/sign login or holds a secret-file path
    or its content; the publish folder's setting (the helper's own environment holds it) is not handed in; control: the
    deployment setting A8 hands in is there."""
    scene, seen, _viz = probed
    env = seen["env"]
    assert not [k for k in env if any(w in k.upper() for w in ("BAO", "VAULT", "APPROLE", "SIGN_LOGIN", "FORGE_SECRET"))]
    values = " ".join(v for v in env.values() if isinstance(v, str))
    assert not any(str(p) in values for p in scene.secrets)
    assert "DEFENDER_RUN_VISUALIZATIONS_DIR" not in env, "the cross-tenant publish folder's setting reached the job (A10)"
    assert env.get("DEFENDER_DEPLOYMENT") == "dev", "control: A8 passes the deployment setting"
