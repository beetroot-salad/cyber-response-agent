# k3s spike (#1509)

This is the go/no-go spike for the deployment design's k3s choice (`defender/docs/decisions/vps-compose-deployment.md`,
work item 1). It is throwaway tooling: nothing in the product imports it.

`run-all.sh` builds a one-node k3d cluster with two gVisor runtime classes, runs every probe, writes
`out/run-all-<date>.txt`, and deletes the cluster. Set `KEEP=1` to keep the cluster.

## Run it

In the dev container:

```sh
start-jobs-docker                       # the dev container's own Docker daemon
K3D=/path/to/k3d sh tooling/spikes/k3s-1509/run-all.sh
```

Requirements:

- k3d v5.8.3, which pulls `rancher/k3s:v1.33.9-k3s1`.
- `runsc`, `containerd-shim-runsc-v1` and the `gvisor-bin` sidecar folder under `/usr/bin`, as the devcontainer
  installs them. This gVisor release (`release-20261109.0`) refuses every sandbox without `gvisor-bin`.

A run takes about five minutes. It leaves the k3s and k3d helper images in the daemon (`rancher/k3s:v1.33.9-k3s1`,
`ghcr.io/k3d-io/k3d-tools`) and `busybox:1.36.1` inside the node.

## What each probe checks

| Probe | Checks |
|---|---|
| 1 | `gvisor-job` gives a pod a normal network; `gvisor-box` (handler config `network = "none"`) gives it loopback only. |
| 2 | Deny-by-default NetworkPolicy, first with no policy (the controls), then under policy. Targets: the proxy by pod address and by Service, a worker, another job, the node's own kubelet, API server port and a NodePort (by node address and by pod gateway), the API server Service, cluster DNS, cloud metadata, and an outside address. Also checks that workers accept the proxy only. |
| 3 | Two gVisor pods sharing a generic ephemeral local-path volume see each other's writes. |
| 4 | A `ValidatingAdmissionPolicy` (`m/05-launcher.yaml`) refuses every change to the job and box templates (`gen-admission.py`), with Pod Security "restricted" on and off, using the launcher's own token. It also covers what the launcher's role allows and refuses. |
| 5 | Box pod create-to-ready time, first exec, and delete. |
| 6 | The job's volume is deleted with its job pod, and a box that still mounts it holds it until the box goes. |

Not covered: the CI runner; several nodes; a k3s server restart; real file deletion on the shared volume (the
probe moves files instead); a real cloud metadata endpoint.

## Result, 2026-11-14 (dev leg)

Every probe passes. Box create-to-ready had a median of 0.97 s to 1.95 s across runs on a loaded desktop machine.
The design changes the run found are recorded on #1509 and in the design document's claim B-G7.
