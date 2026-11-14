#!/bin/sh
# #1509 spike, end to end: create the cluster, run every probe, write out/, delete the cluster (KEEP=1 keeps it).
# Needs: k3d on PATH or $K3D; Docker at $DOCKER_HOST (dev: the jobs daemon, start-jobs-docker); runsc, its shim and
# its gvisor-bin folder under /usr/bin, as the devcontainer installs them.
set -u
S=$(cd "$(dirname "$0")" && pwd); export S; export DOCKER_HOST=${DOCKER_HOST:-unix:///var/run/docker-jobs.sock}
N=k3d-spike1509-server-0; K="docker exec -i $N kubectl"; export K
mkdir -p "$S/out"; OUT=${OUT:-$S/out/run-all-$(date +%F).txt}
sec(){ echo; echo "## $1"; }
{
sec "versions"; "${K3D:-k3d}" version; runsc --version | head -1; docker version --format 'docker {{.Server.Version}}'
sec "cluster"; sh "$S/up.sh" 2>&1 | tail -1
if ! docker inspect "$N" >/dev/null 2>&1; then echo "SETUP FAILED: the cluster was not created; no probe ran"; exit 3; fi
sleep 20; $K get nodes -o wide | awk '{print $1,$2,$5,$NF}'
$K apply -f - < "$S/m/01-runtime.yaml" >/dev/null; $K apply -f - < "$S/m/02-targets.yaml" >/dev/null
$K wait --for=condition=Ready pod --all -n jobs --timeout=180s >/dev/null; $K wait --for=condition=Ready pod --all -n control --timeout=180s >/dev/null
sec "probe 1: gVisor runtime classes (interfaces and routes)"
for p in p-job p-box p-runc; do echo "-- $p"; $K -n jobs exec $p -- sh -c 'dmesg 2>/dev/null | head -1; ip -o link | cut -d" " -f2 | tr "\n" " "; echo; ip route'; done
ip(){ $K get pod -n "$1" "$2" -o jsonpath='{.status.podIP}'; }
ENV="PROXY_POD=$(ip control proxy) PROXY_SVC=$($K -n control get svc proxy -o jsonpath='{.spec.clusterIP}') WORKER_POD=$(ip control worker) PEER_POD=$(ip jobs peer-job)"
ENV="$ENV GW=$($K get node $N -o jsonpath='{.spec.podCIDR}' | sed 's|0/24|1|') NODE_IP=$($K get node $N -o jsonpath='{.status.addresses[0].address}')"
ENV="$ENV API_SVC=$($K get svc kubernetes -o jsonpath='{.spec.clusterIP}') DNS_SVC=$($K -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')"
ENV="$ENV COREDNS_POD=$($K -n kube-system get pod -l k8s-app=kube-dns -o jsonpath='{.items[0].status.podIP}')"
echo "addresses: $ENV"
net(){ { echo "export $ENV"; cat "$S/probe-net.sh"; } | $K -n jobs exec -i "$1" -- sh; }
sec "probe 2a: network, job pod, NO policy (controls)"; net p-job
$K apply -f - < "$S/m/03-netpol.yaml" >/dev/null; sleep 8
sec "probe 2b: network, job pod, deny-all + job->proxy"; net p-job
sec "probe 2c: network, runc pod in jobs ns, deny-all"; net p-runc
sec "probe 2d: network, box pod (gvisor-box + deny-all)"; net p-box
sec "probe 2e: worker ingress"; $K -n control run other --image=busybox:1.36.1 --restart=Never -- sleep 600 >/dev/null; $K -n control wait --for=condition=Ready pod/other --timeout=60s >/dev/null
W=$(ip control worker)
echo "proxy->worker: $($K -n control exec proxy -- sh -c "nc -w3 $W 8080 </dev/null && echo OPEN || echo CLOSED")"
echo "other control pod->worker: $($K -n control exec other -- sh -c "nc -w3 $W 8080 </dev/null && echo OPEN || echo CLOSED")"
sec "probe 3: shared volume"
$K apply -f - < "$S/m/04-vol.yaml" >/dev/null; $K -n jobs wait --for=condition=Ready pod/vjob --timeout=120s >/dev/null
$K apply -f - < "$S/m/04-vbox.yaml" >/dev/null; $K -n jobs wait --for=condition=Ready pod/vbox --timeout=120s >/dev/null
sh "$S/probe-volume.sh"
sec "probe 4: admission (PSA restricted on + policy)"
$K apply -f - < "$S/m/05-launcher.yaml" >/dev/null; $K label ns jobs pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null 2>&1
T=$($K -n control create token launcher --duration=1h)
L="docker exec -i $N kubectl --kubeconfig=/dev/null --server=https://127.0.0.1:6443 --insecure-skip-tls-verify --token=$T"; export L
echo "launcher is: $($L auth whoami -o jsonpath='{.status.userInfo.username}')"
$L -n jobs create secret generic pass-c9 --from-literal=pass=x >/dev/null
python3 "$S/gen-admission.py" > "$S/out/04-cases.jsonl"; sh "$S/run-admission.sh"
sec "probe 4: admission (PSA off, policy alone)"
$K label ns jobs pod-security.kubernetes.io/enforce- >/dev/null; sh "$S/run-admission.sh"; $K label ns jobs pod-security.kubernetes.io/enforce=restricted >/dev/null 2>&1
$K -n jobs wait --for=condition=Ready pod/t-job pod/t-box --timeout=90s >/dev/null
sec "probe 4: the admitted job pod"
$K -n jobs exec t-job -- sh -c 'cat /etc/resolv.conf; nslookup -timeout=3 kubernetes.default.svc.cluster.local >/dev/null 2>&1 && echo RESOLVES || echo NO-RESOLVE; ls /pass; id; ls /var/run/secrets 2>&1 | head -1'
echo "proxy from t-job: $($K -n jobs exec t-job -- sh -c "nc -w3 $($K -n control get svc proxy -o jsonpath='{.spec.clusterIP}') 8080 </dev/null && echo OPEN || echo CLOSED")"
eph(){ $K -n jobs debug t-job --image=busybox:1.36.1 --profile=restricted -- true 2>&1 | grep -v Warning | tail -1 | cut -c1-200
  echo "ephemeral containers on t-job now: [$($K -n jobs get pod t-job -o jsonpath='{.spec.ephemeralContainers[*].name}')]"; }
sec "probe 4: admin adds an ephemeral container (PSA on)"; eph
sec "probe 4: admin adds an ephemeral container (PSA off, policy alone)"
$K label ns jobs pod-security.kubernetes.io/enforce- >/dev/null; eph; $K label ns jobs pod-security.kubernetes.io/enforce=restricted >/dev/null 2>&1
sec "probe 4: admin relabels a job pod"; $K -n jobs label pod t-job extra=1 2>&1 | grep -o "denied request: .*" | head -1
sec "probe 4b: launcher rights"; sh "$S/probe-rbac.sh"
sec "probe 5: box timing"; sh "$S/probe-timing.sh"
sec "probe 6: volume lifetime"; sh "$S/probe-volume-life.sh"
} 2>&1 | tee "$OUT"
grep -q "^SETUP FAILED" "$OUT" && exit 3
[ "${KEEP:-0}" = 1 ] || "${K3D:-k3d}" cluster delete spike1509 >/dev/null 2>&1
echo; python3 "$S/verdict.py" "$OUT"
