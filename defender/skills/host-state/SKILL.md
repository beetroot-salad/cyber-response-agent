---
name: defender-host-state
description: Host live-state system reference — point-in-time host observations (process tree, /etc/passwd, authorized_keys, file hashes, packages) via docker exec in the v2 playground. The runtime view, paired with policy views (cmdb / identity) for divergence detection.
---

Host live-state is **not an HTTP service** — each verb wraps a single
`docker --context soc-playground exec <host> <command>` against the
target role container. Observations are point-in-time and
non-replayable; two calls seconds apart on volatile state (processes,
sockets) can legitimately disagree. Every text response carries an
explicit `captured_at` UTC timestamp; the agent must not
cross-time-window observations from different captures. In a run
resumed from a branch point, `captured_at` is that branch point's
moment rather than the wall clock — the observation describes the
world the run is reasoning in, and two runs forked from one point
agree on it.

This file is split by audience. **Visibility surface** is read by
the defender, the author skill, and the actor-reviewer judge.
**Execution** is read only by code paths that dispatch queries.

## Visibility surface

### available_queries

| Verb | Measurement |
|---|---|
| `container-inspect` | Container name + image (daemon `docker inspect`) — keyed on a container id, not a host name |
| `proc-tree` | Process forest for a host (`ps -eo pid,ppid,user,stat,etime,cmd --forest`) |
| `passwd` | `/etc/passwd` entries for a host — UNIX-level account presence |
| `authorized-keys` | `~/.ssh/authorized_keys` for a host, per user (defaults to root) |
| `fim-checksum` | SHA-256 of a single absolute path on a host |
| `package-list` | Installed `dpkg` packages (name + version) for a host |

### gaps

- **Point-in-time only.** No history; the host doesn't keep
  per-second snapshots. `proc-tree` at T+0 and T+10 can show
  different processes for legitimate reasons (cron firing, shells
  ending). Do not treat divergence between two captures as evidence
  of tampering without other signal.
- **Volatile-state captures are flaky.** Processes can exit between
  the `ps` command starting and the row materialising. The
  observation is best-effort, not transactional.
- **No `/proc` introspection past `ps`.** Open FDs, sockets,
  capability sets — not exposed. Adding those is a future
  workstream.
- **`package-list` assumes Debian-family (`dpkg`).** All v2 hosts
  today are Ubuntu base, so `dpkg-query` works everywhere. A
  future RPM-family host would silently return rc≠0.
- **`fim-checksum` is single-file only.** No bulk scan / no recursion
  / no comparison against a known-good. The hash is just the
  current bytes; comparing against expectation is the caller's job.
- **No process-ancestry-with-binary-path.** `ps cmd` returns the
  command line, which can be rewritten by a process. Match against
  ELF path via `proc-tree` + a follow-up only if the discrimination
  is load-bearing.

### read_guidance

- **`captured_at` is mandatory in any cross-source reasoning.** If
  a host-state observation will be paired with an Elastic event,
  the event timestamp and `captured_at` must both be on record.
- **`/etc/passwd` divergence from the identity stub is a join-bug
  signal.** A user in `passwd` but not in identity's
  `authorized_hosts`, or vice versa, indicates seeding drift —
  surface the divergence, don't assume either source is correct.
- **`authorized_keys` may be absent** — the file does not exist for
  users with no remote-key auth configured. The adapter returns an
  empty key list, not an error, in that case.
- **Empty `proc-tree` rows are still real.** Daemons that exit
  during the capture get dropped silently; do not infer absence of
  a service from a single capture without re-running.
- **The host runs the **role container**, not the VPS host.**
  `proc-tree web-1` shows processes inside `web-1`'s container
  namespace, not anything from the Hetzner host. Cross-container
  ancestry is invisible.

### when_to_use

- **Use to ground a hypothesis about live host state** —
  authorized-keys after a `v2-falco-authorized-keys-modification`
  alert; proc-tree after a `living-off-the-land` alert.
- **Use for runtime divergence checks** — does `getent passwd
  <user>` on the host agree with identity's
  `authorized_hosts` for that host?
- **Use for FIM-style binary verification** — `fim-checksum` on
  `/etc/passwd` or a service binary, compared against expectation.

### when_not_to_use

- **Not for "what happened" — only "what is now."** Past events
  live in Elastic; host-state is purely the current snapshot.
- **Not for `host.role` / criticality / owner.** That's cmdb.
- **Not for "is this user authorized."** That's the identity stub;
  `/etc/passwd` is only the materialized side.
- **Not for trace reproducibility.** Captures are non-replayable;
  use Elastic's retained event streams for any "go back and check
  again" question.

## Execution

Verb surface, connectivity, config, and exit codes live in
`execution.md` — read by gather only.
