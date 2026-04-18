---
archetype: ci-pipeline-exec
signature_id: wazuh-rule-100001
required_anchors:
  - deploy-runs
---

# CI/CD Pipeline Exec — Story

A continuous-integration or continuous-deployment job exec'd into the
container to run a scripted command — typically a build step, a
database migration, a health check during a rolling deploy, or a
post-deploy smoke test. The shell appears as a child of `runc` /
`containerd-shim` / `docker-exec` / `crictl` (the runtime injected it
from outside the container's process tree, the same way an operator
exec works), but the cmdline is **not** interactive: it is
`sh -c "..."` or `bash -c "..."` carrying a scripted command, and the
process exits as soon as the command completes.

The cadence is regular and predictable. CI exec invocations cluster
around deploy windows, scheduled pipeline runs, or rollout
verification, and they recur with similar shape from the same
identity — typically a build agent service account, never an
interactive operator.

The pipeline's command is bounded by the job's purpose. Migrations
touch only their own schemas; smoke tests hit only their own
endpoints; build steps operate on the build's working directory.
Pipeline jobs that read user data, dump credentials, or shell into
arbitrary parts of the container are out of this archetype — that is
either a misconfigured pipeline (still worth escalating) or a
compromised one.

This is benign **only when a real CI/CD run actually correlates in
time** with the alert. Without that correlation, the activity is
indistinguishable from an attacker abusing a CI service account or
exec'ing into the container under a CI-shaped identity.
