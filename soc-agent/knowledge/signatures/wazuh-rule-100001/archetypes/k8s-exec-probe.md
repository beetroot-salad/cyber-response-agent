---
archetype: k8s-exec-probe
signature_id: wazuh-rule-100001
required_anchors:
  - workload-manifest
precedents: []
---

# Kubernetes Exec Probe

## Story

A Kubernetes liveness, readiness, or startup probe of `exec` type ran
on its configured cadence. The kubelet exec'd into the container to
run the probe command — typically a small `sh -c "..."` invoking a
health endpoint via `curl`, checking the existence of a file, or
returning the output of a status command. The shell appears as a
child of `runc` / `containerd-shim` / `crio`, and the cmdline is the
**exact same short scripted command on every invocation**.

The cadence is strictly periodic, matching the probe's
`periodSeconds` configuration (commonly 5s, 10s, or 30s). Jitter is
minimal. The shell terminates within milliseconds. Hundreds or
thousands of identical events from the same `container.id` over the
workload's lifetime are the norm — this is the highest-volume benign
archetype for this signature.

What takes an alert *out* of this archetype is a probe-shaped event
that doesn't match the workload's declared probe — a different
cmdline, a different cadence, or a sudden change. A probe whose
command silently changed is either a deploy (in which case the new
shape should match the new pod spec) or a sign that something else is
piggybacking on the probe pattern to hide periodic activity.

This is benign **only when the workload manifest actually declares an
exec probe whose command matches what we observed**. Without that
confirmation, a probe-shaped event is just one of several
periodic-runtime-exec patterns and could be a cron-like backdoor
mimicking a probe.

## Trust Anchors

### `workload-manifest`

**Question:** does the Kubernetes pod spec for this `container.name`
declare a liveness, readiness, or startup probe of `exec` type whose
command matches the observed `proc.cmdline`, with `periodSeconds`
matching the observed cadence?

**Confirmation:** the anchor returns a probe definition whose command
and period both match the observation. Mismatch on either the command
or the period is a refutation, not a confirmation — a probe that's
declared but runs a different command is more suspicious than no
declared probe at all.

## Precedents

None yet.
