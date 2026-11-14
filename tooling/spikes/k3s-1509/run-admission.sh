#!/bin/sh
# Submits every case in out/04-cases.jsonl as the launcher's service account. BASE cases are really created; every
# mutation is a server-side dry run, which runs validating admission (the policy and Pod Security) without storing it.
# Prints: verdict, case, and who refused it (VAP = our policy, PSA = Pod Security, API = built-in validation).
S=${S:-$(dirname "$0")}; N=k3d-spike1509-server-0
T=$(docker exec $N kubectl -n control create token launcher --duration=1h)
L(){ docker exec -i $N kubectl --kubeconfig=/dev/null --server=https://127.0.0.1:6443 --insecure-skip-tls-verify --token="$T" "$@"; }
docker exec $N kubectl -n jobs delete pod t-job t-box --ignore-not-found --wait >/dev/null 2>&1
python3 - "$S/out/04-cases.jsonl" "$S/m" > $S/out/04-split.txt <<'PY'
import json,sys
for i,l in enumerate(open(sys.argv[1])):
    d=json.loads(l); open(f"{sys.argv[2]}/case{i:02d}.json","w").write(json.dumps(d["pod"])); print(i,d["case"])
PY
while read i c; do f=$S/m/case$(printf %02d $i).json
  if [ "$c" = BASE ]; then out=$(L create -f - < $f 2>&1); else out=$(L create --dry-run=server -f - < $f 2>&1); fi
  if echo "$out" | grep -q created; then r=ADMITTED; else r=REFUSED; fi
  why=$(printf '%s\n' "$out" | python3 -c '
import sys,re
s=sys.stdin.read()
m=re.search(r"denied request: (.*)",s) or None
if m: print("VAP:",m.group(1)[:130]); sys.exit()
m=re.search(r"violates PodSecurity [^:]*: (.*)",s)
if m: print("PSA:",m.group(1)[:130]); sys.exit()
m=re.search(r"((Invalid|Required) value.*)",s)
if m: print("API:",m.group(1)[:130]); sys.exit()
print(s.strip()[:130] if "created" not in s else "")')
  printf '%-9s %-22s %s\n' "$r" "$c" "$why"; done < $S/out/04-split.txt
