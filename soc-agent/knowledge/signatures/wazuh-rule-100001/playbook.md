---
signature_id: wazuh-rule-100001
last_updated: 2026-04-08
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: Terminal shell in container (100001)

> **Note on the hypothesis catalog below:** the current shape conflates
> observable primitives with outcome stories — `?operator-debug` and
> `?ci-cd-pipeline` share all the same primitives, `?image-startup` and
> `?healthcheck-or-probe` differ only in cadence, etc. Worker-mode validation
> confirmed this catalog over-escalates because the leads cannot
> discriminate the entries. A primitives + archetypes + trust-anchors
> redesign is tracked in `docs/design-v3-hypothesis-archetype-rewrite.md`
> and will replace this section.

## Hypothesis Catalog

### ?operator-debug
An authorized operator opened a shell into the container via `docker exec`,
`kubectl exec`, or an equivalent runtime primitive for debugging or
maintenance.

**Typical profile:** Parent process is a container runtime exec primitive
(`runc`, `containerd-shim`, `docker-exec`); user is a real human account or
matches an operator service account; correlates in time with a deploy,
incident, or ticketed maintenance.

### ?ci-cd-pipeline
A build, test, or deploy pipeline executed a shell command inside the
container as part of an automated workflow.

**Typical profile:** Container name or image is a CI/build image; shell
invocation is short-lived and non-interactive; recurring on a predictable
cadence.

### ?image-startup
The container's own entrypoint or init script invokes a shell as part of
normal startup. The shell is spawned **inside** the container's process tree,
not via a runtime exec primitive.

**Typical profile:** Shell event happens within seconds of container start;
`proc.pname` is the container's init/entrypoint binary (e.g., `node`,
`python3`, `java`, a custom launcher) — **not** `runc` /
`containerd-shim` / `docker-exec` / `crio`; the same image fires this event
once per container start and not in between.

**Discriminator vs `?healthcheck-or-probe`:** parent is an in-container
process, and the event happens at container start, not on a recurring
schedule.

### ?healthcheck-or-probe
A liveness/readiness/exec-probe configured on the container invokes a shell
to run a small script (e.g., `sh -c "curl localhost:8080/health"`). The
orchestrator runs the probe by exec-ing into the container, so the shell is
spawned by the runtime, not by the container's own process tree.

**Typical profile:** Recurring at a fixed interval matching the configured
probe period; identical `proc.cmdline` on every occurrence; `proc.pname` is
a runtime exec primitive (`runc`, `containerd-shim`, `docker-exec`, `crio`);
shell terminates within milliseconds.

**Discriminator vs `?image-startup`:** parent is a runtime exec primitive
(the probe came from outside the container's process tree), and the event
recurs on a strict schedule.

**Discriminator vs `?operator-debug`:** identical recurring `cmdline` on a
strict schedule, vs. ad-hoc operator commands at irregular times.

### ?adversary-post-exploit
An attacker who reached code execution inside the container spawned an
interactive shell for follow-on activity.

**Typical profile:** Parent process is an application binary (web server,
database, language runtime); shell command line indicates interactivity
(`bash -i`, `sh -i`); may correlate with other Falco events from the same
container (sensitive file read, network redirect, dropped binary).

---

## Lead List

### shell-context
**Query:** Inspect the Falco event fields for this alert: `proc.name`,
`proc.pname`, `proc.cmdline`, `user.name`, `container.name`,
`container.image.repository`.

**Discriminates:** All hypotheses — the parent process and command line are
the strongest single signals.

| Hypothesis | Prediction |
|------------|------------|
| ?operator-debug | Parent is `runc` / `containerd-shim` / `docker-exec`; cmdline is plain `bash`/`sh` (no `-c`), interactive flags possible |
| ?ci-cd-pipeline | Parent is a runtime exec primitive; cmdline is `sh -c "..."` or `bash -c "..."` with a scripted command, non-interactive |
| ?image-startup | Parent is the container's init/entrypoint binary (not a runtime exec primitive); happens at container start |
| ?healthcheck-or-probe | Parent is a runtime exec primitive; cmdline is a short fixed `sh -c "..."` matching the configured probe |
| ?adversary-post-exploit | Parent is an application binary (nginx, java, python, node, ...); cmdline shows `-i`, pipes, or redirects to a socket |

### container-baseline
**Query:** Other 100001 events from the same `container.image` (and ideally
`container.name`) over the last 7-30 days. Has this image been observed
spawning shells before? At what cadence?

**Discriminates:** Routine vs anomalous behaviour for this workload.

| Hypothesis | Prediction |
|------------|------------|
| ?operator-debug | Sporadic prior events tied to operator activity windows |
| ?ci-cd-pipeline | Regular cadence matching pipeline schedule |
| ?image-startup | Event fires once per container start, not in between |
| ?healthcheck-or-probe | Strictly periodic, matching the configured probe interval, with identical cmdline |
| ?adversary-post-exploit | No prior events for this image, or sudden change in pattern |

### correlated-falco-events
**Query:** Other Falco-derived alerts (rules 100000-100099) from the same
`container.id` in a ±15 minute window — especially 100002 (network
redirect), 100006 (sensitive file read), 100007 (drop-and-exec), and 100008
(log clearing).

**Discriminates:** Whether the shell is isolated or part of a chain.

| Hypothesis | Prediction |
|------------|------------|
| ?operator-debug | No correlated suspicious events, or only operator-driven follow-ups |
| ?ci-cd-pipeline | No correlated suspicious events |
| ?image-startup | No correlated suspicious events |
| ?adversary-post-exploit | One or more correlated rules in the same container window |

> **Host-context queries** ("other alerts on this agent in last 24h",
> "is this a repeat or part of a pattern") are handled by the
> ticket-context subagent at CONTEXTUALIZE — its findings are already in
> the investigation context by the time leads run. Don't re-execute those
> queries here; reference the ticket-context output instead.

> **Container runtime privileges** (privileged flag, Docker socket mount,
> host network/PID) are scoping evidence that informs severity and the
> Privilege axis of risk indicators. Gather them as scoping evidence when
> the primitive pattern looks adversarial; not a separate diagnostic lead.

---

## Start With

**`shell-context`** — the parent process and command line are the most
diagnostic single signal. A shell whose parent is `runc` is a very different
situation from a shell whose parent is `nginx` or `java`.

Follow with `container-baseline` to determine whether this is normal behaviour
for the image, then `correlated-falco-events` if any doubt remains.

---

## Auto-Close Criteria

All must be true:
1. Exactly one hypothesis remains with `++` support
2. The adversary-post-exploit hypothesis has `--` refutation
3. A matching precedent exists in `precedents/`
4. No correlated Falco events from the same container in the surrounding window
5. `confidence` is `high`

## Escalation Criteria

Escalate immediately if ANY:
- Shell command line indicates a networked shell (pipes to `/dev/tcp`,
  redirects to a socket fd) — this is unambiguously adversarial
- Correlated 100002, 100006, 100007, or 100008 event from the same container
  within the surrounding window
- Container is privileged, mounts the Docker socket, or runs with host
  network / host PID **and** the primitive pattern doesn't match a known
  benign archetype for this image
- Parent is an application binary **and** this image has no prior history
  of shells from that parent **and** no operator/CI/deploy activity
  explains the timing
- Container image has never previously fired this rule and the operator
  hypothesis cannot be confirmed
- No hypothesis reaches `++` after pursuing all leads
- A field a lead depends on (`proc.pname`, `proc.cmdline`, `container.image`,
  etc.) is missing from the alert and cannot be retrieved — do not guess

> **Removed:** "parent is an application binary → escalate" as a hard
> standalone trigger. Real apps shell out routinely (build/deploy hooks,
> `subprocess.run`, ImageMagick/ffmpeg wrappers, log rotation) and the
> trigger as written produced too many false escalations. App-spawned
> shells now require corroboration from the abnormality axis before
> escalating.

## Scope

Investigation covers the alerting Falco event, other Falco events from the
same `container.id` in a ±15 minute window, and other alerts from the same
agent in the last 24 hours. Do not expand beyond the originating host
without escalating.
