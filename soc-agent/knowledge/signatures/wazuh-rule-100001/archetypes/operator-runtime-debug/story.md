---
archetype: operator-runtime-debug
signature_id: wazuh-rule-100001
required_anchors:
  - oncall-schedule
  - change-windows
---

# Operator Runtime Debug — Story

An authorized operator opened an interactive shell into the container
via a container runtime exec primitive (`docker exec`, `kubectl exec`,
`crictl exec`, or equivalent) for ad-hoc debugging or troubleshooting.
The shell appears as a child of `runc` / `containerd-shim` /
`docker-exec` / `crictl` / `crio` — the runtime injected it into the
container's namespace from outside the container's own process tree.
The cmdline is interactive: a bare shell name (`bash`, `sh`, `zsh`),
a shell with `-i`, or no `-c` argument at all.

The operator's session is bounded by the troubleshooting scope. They
exec in, perform diagnostic commands relevant to the issue at hand
(process listing, configuration checks, log tail, restart of a stuck
service), and exit. They do **not** read user personal data, dump
credentials, exfiltrate files, or pivot to other workloads — those
actions take the event out of this archetype, even when performed by
an otherwise authorized operator.

The cadence is irregular and ad-hoc, not periodic. A shell that recurs
at strict intervals with an identical cmdline is `k8s-exec-probe`, not
this.

This is routine activity in environments where operators retain
prod-touch authority. It is benign **only when the operator was
authorized to be touching this workload at this time**, which is what
the trust anchors confirm. Without anchor confirmation, this is
observationally indistinguishable from an attacker who has acquired
operator credentials and is exec'ing into a container the same way an
operator would.
