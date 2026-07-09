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

- **Privilege stays on the trusted side.** The outer container needs
  `--privileged`; the guest ran uid 0 with a **reduced cap set** (`chown,
  dac_override, dac_read_search, fowner, fsetid, sys_ptrace` — from the boot
  log), never `CAP_SYS_ADMIN`. So the spawner (run.py / worker / broker) spends
  the privilege once to build the box; the model-driven code inside gets none.
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
