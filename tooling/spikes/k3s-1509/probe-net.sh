#!/bin/sh
# Runs inside a pod; the addresses come from run-all.sh, which looks them up. One line per target: OPEN or CLOSED.
t() { if nc -w 3 "$2" "$3" </dev/null >/dev/null 2>&1; then echo "OPEN   $1"; else echo "CLOSED $1"; fi; }
t proxy-pod          "$PROXY_POD" 8080
t proxy-service      "$PROXY_SVC" 8080
t worker-pod         "$WORKER_POD" 8080
t peer-job-pod       "$PEER_POD" 8080
t node-gw-kubelet    "$GW" 10250
t node-gw-apiserver  "$GW" 6443
t node-gw-nodeport   "$GW" 30080
t node-ip-kubelet    "$NODE_IP" 10250
t node-ip-apiserver  "$NODE_IP" 6443
t node-ip-nodeport   "$NODE_IP" 30080
t apiserver-service  "$API_SVC" 443
t kube-dns-tcp       "$DNS_SVC" 53
t coredns-pod-tcp    "$COREDNS_POD" 53
t metadata           169.254.169.254 80
t outside            1.1.1.1 443
if nslookup -timeout=3 kubernetes.default.svc.cluster.local "$DNS_SVC" >/dev/null 2>&1; then echo "OPEN   dns-udp-resolve"; else echo "CLOSED dns-udp-resolve"; fi
