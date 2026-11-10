"""#1170 sketch: what a real job container can reach, observed from inside it. NOT RUN HERE: they need a native docker
daemon with the levered runtime (gVisor `runsc`) and skip in this devcontainer (docker-outside-of-Docker); CI runs them.
They also need the job container's image, which the design does not yet say where comes from (dev, CI, prod).

The real helper (`job_host.main`, the real docker) starts the container with a probe as its command (`command=`, a
sketch seam) in place of the kind's entry; the probe writes what it saw into its own tenant folder, read here."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

import defender
from defender.box import BoxSpec
from defender.tests.support.jobs._job_helper import CANARY, OTHER_TENANT, drive_helper, helper_scene
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood

_NO_DAEMON = not daemon_reachable()
_DOOD = (not _NO_DAEMON) and is_dood()
_RUNTIME = BoxSpec.from_env(os.environ).runtime
requires_box = pytest.mark.skipif(
    _NO_DAEMON or (_DOOD and dood_anchor() is None) or ((not _NO_DAEMON) and _RUNTIME not in docker_runtimes()),
    reason="needs a native docker daemon with the levered runtime (as `test_box_boundary_e2e.requires_box`)")

pytestmark = [pytest.mark.e2e, pytest.mark.box, pytest.mark.postgres, requires_box]

#: Runs inside the job container (product code mounted read-only, so `defender` imports). Writes probe.json.
PROBE = r'''
import json, os, shutil, subprocess, sys
out, other, own, viz, inv, secrets = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6:]
seen = {"env": dict(os.environ)}
def reads(p):
    try:
        return open(p, encoding="utf-8").read()
    except OSError as e:
        return f"<{type(e).__name__}>"
seen["other_canary"] = reads(other)
seen["own_canary"] = reads(own)
seen["secrets"] = [reads(p) for p in secrets]
def writes(p):
    try:
        with open(p, "w", encoding="utf-8") as f:
            f.write("x")
        return True
    except OSError:
        return False
import defender
code = os.path.dirname(os.path.dirname(os.path.abspath(defender.__file__)))
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
from defender import job_host
sock = os.environ[job_host.SOCKET_ENV]
try:
    h = job_host.ask(sock, "box.start", kind="shell", id=inv)["handle"]
    from defender.execution import bash_exec, box_codec
    frame = box_codec.encode_request(bash_exec.parse("echo box-ok"))
    answer = job_host.ask(sock, "box.exec", handle=h, frame=frame)
    seen["shell"] = [answer.get("result"), box_codec.decode_response(answer["frame"]).out.decode()]
except Exception as e:
    seen["shell"] = f"<{type(e).__name__}: {e}>"
json.dump(seen, open(out, "w"))
'''


@pytest.fixture
def probed(tmp_path, monkeypatch, migrated_database):  # noqa: F811
    """One real job container of the scene's tenant, run with the probe; what it saw."""
    from defender.box import run_docker
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    with helper_scene(tmp_path, monkeypatch, migrated_database) as scene:
        inv = str(uuid.uuid4())
        scene.plant(inv)
        own = scene.root / scene.tenant / "own-canary"
        own.write_text("OWN-1170", encoding="utf-8")
        out = scene.root / scene.tenant / "probe.json"
        # The publish folder (A10) is one host folder outside every tenant and the data root, holding a canary. It is
        # in the helper's own environment (the dev run page) and must not be in the job's.
        viz = Path(tmp_path) / "published-pages"
        viz.mkdir()
        (viz / "canary").write_text(CANARY, encoding="utf-8")
        monkeypatch.setenv("DEFENDER_RUN_VISUALIZATIONS_DIR", str(viz))
        monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")
        command = ["python3", "-c", PROBE, str(out),
                   str(scene.root / OTHER_TENANT / "canary"), str(own), str(viz), inv, *map(str, scene.secrets)]
        ran = drive_helper(scene, scene.argv("investigation", inv), docker=run_docker, signer=A.MarkedSigner(),
                           command=command)
        assert ran.raised is None, ran.raised
        yield scene, json.loads(out.read_text(encoding="utf-8")), viz


def test_o1_from_inside_another_tenants_canary_is_unreadable_and_its_own_folder_is(probed):
    """(O1) not run here."""
    _scene, seen, _viz = probed
    assert seen["own_canary"] == "OWN-1170", "control: the tenant's own folder is readable"
    assert seen["other_canary"].startswith("<"), seen["other_canary"]
    assert CANARY not in seen["other_canary"]


def test_o2_from_inside_docker_is_unreachable_and_a_shell_box_still_runs(probed):
    """(O2) not run here."""
    _scene, seen, _viz = probed
    assert seen["docker_sock"] is False
    assert seen["docker_ps"] != 0
    assert seen["shell"] == ["ok", "box-ok\n"], f"control: a shell box command through the socket ran: {seen['shell']}"


def test_o3_from_inside_no_database_login_is_held_and_a_connect_fails(probed):
    """(O3) not run here."""
    scene, seen, _viz = probed
    assert seen["db"] != "connected"
    assert not any(scene.dsn in v or "postgresql://" in v for v in seen["env"].values())


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
    assert Path(seen["code_root"]) == Path(defender.__file__).resolve().parents[1]
    assert seen["code_writable"] is False
    assert seen["code_env_files"] == []
    assert seen["own_writable"] is True, "control: the tenant's own folder is writable"


def test_a10_the_shared_publish_folder_is_not_visible_from_inside(probed):
    """(A10) not run here. `DEFENDER_RUN_VISUALIZATIONS_DIR` names a host folder shared by every tenant: it is
    neither readable nor writable from the job container. Control: the tenant's own folder is."""
    _scene, seen, _viz = probed
    assert seen["viz_canary"].startswith("<"), seen["viz_canary"]
    assert CANARY not in seen["viz_canary"]
    assert seen["viz_writable"] is False
    assert seen["own_writable"] is True, "control: the tenant's own folder is writable"


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
