---
title: runsc spawner-host go/no-go — the OS-sandbox isolate is deployable
status: done
groups: defender, runtime, sandbox, security
---

**GO.** `runsc run` succeeds on the playground VPS with every capability the
gVisor-isolate design needs — a read-only bind, a read-write bind, a
bind-mounted host unix socket (`--host-uds=open`), and `--network=none` with a
loopback-only netstack. This clears the one *existential* unknown in
[`defender/docs/runtime-sandbox-design.md`](../../defender/docs/runtime-sandbox-design.md):
the isolate is deployable on the intended v1 host, so #549 (Agent Vault) and the
Phase-1 build (#550) can proceed on top of it.

Spike for **#548** (OS-sandbox rollout #540, Phase 0). Throwaway — this note +
the evidence below are the deliverable; no production code was written.

## What was asked

The design runs each untrusted investigation inside a per-alert gVisor (`runsc`)
isolate whose only route off-box is a host-side broker over a bind-mounted unix
socket. `runsc` needs privilege to *build* that box (create namespaces + mount
the rootfs = `CAP_SYS_ADMIN`), and our container envs deny it: rootless runsc
rides the unprivileged user namespaces we've observed `EPERM` on, and default
runsc wants root. The same evidence standard that rejected bubblewrap applies —
**see a real `runsc run` succeed** before treating the isolate as deployable.

## The two hosts

- **Devcontainer — observed no-go.** Both privilege doors are shut here:
  `unshare --user` → `EPERM` (rootless dead) *and* `unshare --net`/`--mount`
  **as root** → `EPERM` (default-root dead — no `CAP_SYS_ADMIN`; `Seccomp: 2`;
  AppArmor `docker-default`). The host *kernel* is permissive
  (`unprivileged_userns_clone=1`), so the block is the container's
  seccomp/AppArmor/cap layer, not the kernel. No local docker daemon, no runsc,
  no `/dev/kvm`. → **local runsc iteration needs the devcontainer relaunched
  `--privileged`** (or `--cap-add=SYS_ADMIN --security-opt seccomp=unconfined
  --security-opt apparmor=unconfined`).
- **Playground VPS — the go.** A throwaway `--privileged` container on the VPS
  (`docker --context soc-playground`) restores the capability, and `runsc`
  builds its box. This mirrors the intended v1 spawner host without bouncing the
  live playground stack (unlike registering runsc as a daemon runtime, which
  needs a `dockerd` restart).

## Evidence (observed 2026-07-09)

Host: playground VPS, kernel `6.8.0-71-generic`, 8 CPUs, ~32 GB.
runsc `release-20260706.0` (go1.26.3), platform **systrap** (no KVM required —
and none present, confirming the no-KVM claim).

Command (all four knobs):

```
runsc --host-uds=open --network=none --platform=systrap --ignore-cgroups \
      run --bundle /work/bundle full        # exit 0
```

| Design need | Observed | ✓ |
|---|---|---|
| runsc runs at all | trivial bundle → `HELLO-FROM-GVISOR-SANDBOX`, exit 0 | ✅ |
| it's really gVisor | guest `uname` = `Linux runsc 4.19.0-gvisor … x86_64` (Sentry serviced it) | ✅ |
| **ro bind** | read `hello-from-ro-bind` OK; write → `Read-only file system` | ✅ |
| **rw bind** | guest write OK, **host sees `guest-wrote-this`** on the bind → *the writable mount IS the artifact exit* | ✅ |
| **`--host-uds=open`** | guest connected to the bind-mounted host socket, got the echo back (`UDS-REPLY: ping-from-guest`) → the broker channel | ✅ |
| **`--network=none` loopback netstack** | guest has **only `lo`** (127.0.0.1/8, ::1), routes loopback-only, external ping unreachable | ✅ |
| startup latency | **~0.08–0.11 s** per create+run+teardown (`/bin/true`, systrap) | ✅ |

## Caveats (carry into the build)

- **Privilege stays on the trusted side — but it is not "spent".** The outer
  container needs `--privileged`; the guest ran uid 0 with a **reduced cap set**
  (`chown, dac_override, dac_read_search, fowner, fsetid, sys_ptrace` — from the
  boot log), never `CAP_SYS_ADMIN`. The model-driven code inside gets none of it.
  **Amended 2026-07-17:** the original wording ("the spawner spends the privilege
  once to build the box") is wrong and was load-bearing. Privilege is not spent —
  the `--privileged` container persists for its lifetime, and **the Sentry runs
  inside it**. That matters because gVisor's security model has two layers: the
  Sentry services guest syscalls (layer one), *and the Sentry itself is confined
  by a host seccomp-bpf filter plus namespaces* (layer two), which is what makes a
  Sentry compromise survivable rather than fatal. A privileged outer container does
  not disable layer two — the Sentry applies its own filter — but it makes the far
  side of that filter much richer: host devices, `CAP_SYS_ADMIN` in the bounding
  set, largely unmasked `/proc` and `/sys`.
- **The proven path was not the intended path — now both are proven.** This spike
  proved *nested* runsc inside a privileged container. The design's
  `ContainerRunner` assumes `docker run --runtime=runsc` against the host daemon.
  **That path was cleared separately on 2026-07-17 — see below.** The nested result
  stands as history; the daemon path is the one to build on.

## The daemon path — GO (observed 2026-07-17)

`docker run --runtime=runsc` against the host daemon works, needs **no privileged
container**, and leaves the Sentry confined. This is the path `ContainerRunner`
should target.

Host: throwaway `cx33`/fsn1 (Ubuntu 24.04, fresh — *not* the playground box, which
was left untouched), Docker 29.6.2, runsc `release-20260714.0` installed from the
gVisor apt repo. `runsc install` writes `/etc/docker/daemon.json`; `systemctl
restart docker` registers it. Teardown: `hcloud server delete runsc-daemon-spike`.

| Design need | Observed | ✓ |
|---|---|---|
| registers as a daemon runtime | `docker info` → `"runsc": {"path": "/usr/bin/runsc"}` | ✅ |
| it's really gVisor | guest `uname` = `4.19.0-gvisor` | ✅ |
| **ro bind** | read OK; write → `Read-only file system` | ✅ |
| **rw bind** | guest write OK, **host sees it** — the artifact exit | ✅ |
| **`--network=none`** | guest has only `lo`; outbound → blocked | ✅ |
| **`--ignore-cgroups` unnecessary** | default `false`, every run above succeeded | ✅ |
| startup latency | **~0.30–0.37 s** per `docker run --rm` (vs ~0.08–0.11 s for bare `runsc run`) — the docker layer costs ~0.2 s, noise against a per-run box | ✅ |

**The layer-two evidence — the point of the exercise.** gVisor's second layer (the
Sentry is itself confined, so a Sentry compromise is not automatically host access)
was asserted in this design and never checked. On the daemon path it holds, and it
is now *observed*:

```
runsc-sandbox (the Sentry)
  └─ parent: containerd-shim-runc-v2
       └─ parent: /sbin/init (PID 1)      ← a host process; no privileged container in the chain

Seccomp:         2      (SECCOMP_MODE_FILTER)
Seccomp_filters: 1
NoNewPrivs:      1
CapEff:  000000000008001f = chown, dac_override, dac_read_search, fowner, fsetid, sys_ptrace
         → no CAP_SYS_ADMIN
(host root shell, for contrast: CapEff 000001ffffffffff, Seccomp 0)
```

So on this path the privilege genuinely *is* on the trusted side: dockerd (root)
builds the box, and the Sentry that faces model-written bash runs seccomp-filtered
with six capabilities and no `CAP_SYS_ADMIN`. That is the claim the nested path
could not make, and it is why the daemon path is not a packaging preference.

**Still unproven, and the bigger risk: compatibility.** Everything above uses a
stock `alpine` rootfs. Nobody has run *gather's actual bash* inside the box. The
sharp edge is that the bash gate's flag grammars were tuned against the runtime
container's GNU binaries specifically (the dev box ships ugrep) — a box with a
different rootfs shifts that alignment **silently**. Also unchecked: whether
anything on the bash lane needs to write under a read-only `defender_dir`
(`__pycache__` when `defender-sql` runs from it), and whether our real mount list
exposes anything the `alpine` probe wouldn't reveal.
- **`--ignore-cgroups`** was needed to sidestep cgroup friction in the *nested*
  container. Likely unnecessary when the spawner is root directly on the host —
  confirm when testing the prod-faithful `docker run --runtime=runsc` daemon
  path (that path is the real `ContainerRunner` integration, not this spike).
- **Socket lifecycle.** The broker socket must exist *before* `runsc run`, or FS
  setup aborts (`opening /work/broker/broker.sock: no such file or directory`).
  Matches the design lifecycle: broker opens its socket, *then* spawns the
  isolate, and serves for the isolate's lifetime.
- **seccomp.** runsc ignores the OCI `linux.seccomp` profile (Sentry services
  syscalls itself) — on runsc the absent network *is* the enforcement; a
  `socket(AF_INET)`-deny belt exists only on the `runc` fallback.
- gVisor config from the boot log: `Directfs: true`, `Overlay: root:self`,
  `FileAccess: exclusive`.

## Fallbacks (not needed — recorded per acceptance)

Had this been a no-go: `runc` for playground/dev (weakest, any host), a
different spawner host, or a Firecracker/Kata microVM (needs `/dev/kvm`, absent
here). The architecture doesn't move — the runtime is an OCI knob.

## Reproduction

Throwaway privileged container on the VPS; install runsc; `runsc run` a busybox
bundle with a ro bind, rw bind, a socat unix-socket echo server bind-mounted in,
and `--network=none`. Full script transcript is in the #548 session; the load-
bearing invocation is the command above. Teardown: `docker --context
soc-playground rm -f runsc-spike`.
