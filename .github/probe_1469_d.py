"""#1469 probe D (throwaway): cost and outcome of a box-check container per runtime, with box confinement flags."""
import json, os, socket, subprocess, sys, tempfile, threading, time

PROFILE = os.path.abspath("defender/box/seccomp/alias-deny.json")
IMAGE = "python:3.11-slim"
CONNECT = ("import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect('/chk/s'); s.sendall(b'x'); print('CHECK:connected')\n"
           "except OSError as e:\n print('CHECK:refused', e.errno, e.strerror)\n")

def flags(rt, user):
    f = ["--runtime", rt, "--network", "none", "--read-only", "--pull=never", "--security-opt", f"seccomp={PROFILE}",
         "--ulimit", "fsize=1048576:1048576", "--ulimit", "core=0:0", "--memory", "2g", "--memory-swap", "2g",
         "--cpus", "2", "--pids-limit", "256", "--tmpfs", "/tmp:rw,noexec,nosuid,mode=1777,size=64m"]
    return f + (["--user", user] if user else [])

def one(rt, user):
    d = tempfile.mkdtemp(dir=os.environ.get("RUNNER_TEMP", "/tmp")); os.chmod(d, 0o777)
    path = os.path.join(d, "s"); srv = socket.socket(socket.AF_UNIX); srv.bind(path); os.chmod(path, 0o777); srv.listen(4)
    accepts = []
    def acc():
        srv.settimeout(30)
        try:
            c, _ = srv.accept(); accepts.append(c.recv(1))
        except OSError: pass
    t = threading.Thread(target=acc, daemon=True); t.start()
    t0 = time.monotonic()
    p = subprocess.run(["docker", "run", "--rm", *flags(rt, user), "--mount", f"type=bind,source={d},target=/chk",
                        IMAGE, "python3", "-c", CONNECT], capture_output=True, text=True, timeout=120)
    dt = round(time.monotonic() - t0, 2); t.join(2); srv.close()
    return {"rt": rt, "user": user, "secs": dt, "rc": p.returncode, "out": p.stdout.strip(), "err": p.stderr.strip()[-300:],
            "accepted": bool(accepts)}

subprocess.run(["docker", "pull", "-q", IMAGE], check=True)
res = []
for user in (None, "65534:65534"):
    for rt in ("runc", "runsc", "runsc-plain"):
        for _ in range(4 if user is None else 1):
            res.append(one(rt, user))
print("=== PROBE-D BEGIN ===\n" + json.dumps(res, indent=1) + "\n=== PROBE-D END ===")
info = subprocess.run(["docker", "info", "--format", "{{json .Runtimes}}"], capture_output=True, text=True).stdout
print("RUNTIMES", info)
print("ID", subprocess.run(["docker", "info", "--format", "{{.ID}}"], capture_output=True, text=True).stdout)
