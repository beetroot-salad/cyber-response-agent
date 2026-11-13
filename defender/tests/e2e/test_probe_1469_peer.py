"""#1469 throwaway probe (never merged): what the job socket's peer check sees under real runsc.

A real helper starts a real job container (runtime from BoxSpec, runsc in CI). The probe inside connects once, then
waits. While it waits, the host connects to the same socket from a process outside the container. Every peer check
the helper makes is recorded: the pid SO_PEERCRED named, what that process is on the host, the container's process set
and the raw docker answers it was built from. Printed as JSON; nothing is asserted."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from defender.job_host import _server
from defender.job_host._container import container_processes
from defender.tests.e2e.test_job_box_boundary_e2e import pytestmark  # noqa: F401 — same skip and markers
from defender.tests.support.jobs._job_helper import drive_helper, helper_scene
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

PROBE = r'''
import json, os, sys, time
from defender import job_host
out, go = sys.argv[1], sys.argv[2]
sock = os.environ[job_host.SOCKET_ENV]
seen = {"sock": sock, "inside_pid": os.getpid()}
try:
    seen["inside"] = sorted(job_host.ask(sock, "launch"))
except Exception as e:
    seen["inside"] = f"<{type(e).__name__}: {e}>"
json.dump(seen, open(out, "w"))
deadline = time.time() + 120
while not os.path.exists(go) and time.time() < deadline:
    time.sleep(0.2)
'''

FOREIGN = r'''
import json, sys
from defender import job_host
try:
    print(json.dumps({"ok": sorted(job_host.ask(sys.argv[1], "launch"))}))
except Exception as e:
    print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
'''


def _proc(pid: int) -> dict:
    def read(name: str) -> str:
        try:
            return Path(f"/proc/{pid}/{name}").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")[:300]
        except OSError as e:
            return f"<{type(e).__name__}>"
    stat = read("stat")
    return {"pid": pid, "cmdline": read("cmdline"), "comm": read("comm").strip(),
            "ppid": stat[stat.rfind(")") + 2:].split()[1] if ")" in stat else stat}


def test_probe_1469_what_the_peer_check_sees(tmp_path, monkeypatch, migrated_database):  # noqa: F811
    from defender.box import run_docker
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    checks: list[dict] = []
    original = _server.Server._peer_ok

    def recording(self, pid: int) -> bool:
        session = self._session
        inspect = subprocess.run(["docker", "inspect", "-f", "{{.State.Pid}} {{.HostConfig.Runtime}}",
                                  session.container], capture_output=True, text=True)
        top = subprocess.run(["docker", "top", session.container, "-o", "pid,ppid,comm"],
                             capture_output=True, text=True)
        members = container_processes(session)
        verdict = original(self, pid)
        checks.append({"peer": _proc(pid), "verdict": verdict, "helper_pid": os.getpid(),
                       "inspect": inspect.stdout.strip() or inspect.stderr.strip(),
                       "top": top.stdout.strip() or top.stderr.strip(),
                       "set_size": len(members), "set_has_host_pid_1": 1 in members,
                       "set_has_helper": os.getpid() in members,
                       "set": [_proc(p) for p in sorted(members)[:40]]})
        return verdict

    monkeypatch.setattr(_server.Server, "_peer_ok", recording)
    result: dict = {}
    with helper_scene(tmp_path, monkeypatch, migrated_database) as scene:
        inv = str(uuid.uuid4())
        scene.plant(inv)
        out = scene.root / scene.tenant / "probe.json"
        go = scene.root / scene.tenant / "probe.go"

        def host_side() -> None:
            deadline = time.time() + 180
            while not out.exists() and time.time() < deadline:
                time.sleep(0.2)
            try:
                inside = json.loads(out.read_text(encoding="utf-8"))
                result["inside"] = inside
                repo = Path(__file__).resolve().parents[3]
                foreign = subprocess.run([sys.executable, "-c", FOREIGN, inside["sock"]], capture_output=True,
                                         text=True, timeout=60, cwd=repo,
                                         env={**os.environ, "PYTHONPATH": str(repo)})
                result["foreign"] = foreign.stdout.strip() or foreign.stderr.strip()[-2000:]
            except Exception as e:  # noqa: BLE001 — a probe records everything
                result["host_side_error"] = f"{type(e).__name__}: {e}"
            finally:
                go.write_text("go", encoding="utf-8")

        watcher = threading.Thread(target=host_side, daemon=True)
        watcher.start()
        ran = drive_helper(scene, scene.argv("investigation", inv), docker=run_docker, signer=A.MarkedSigner(),
                           command=["python3", "-c", PROBE, str(out), str(go)])
        watcher.join(timeout=30)
        result["helper_rc"], result["helper_raised"] = ran.rc, repr(ran.raised)
    result["checks"] = checks
    print("\n=== PROBE-1469 BEGIN ===\n" + json.dumps(result, indent=1) + "\n=== PROBE-1469 END ===")
