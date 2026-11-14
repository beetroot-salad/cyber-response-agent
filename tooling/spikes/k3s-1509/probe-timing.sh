#!/bin/sh
# Box pod create -> Ready, first exec, delete; N runs as the launcher (image already pulled). Needs: $L, $S.
N=${RUNS:-12}
for i in $(seq 1 $N); do
  python3 -c "import json;p=json.load(open('$S/m/case01.json'));p['metadata']['name']='tb-$i';print(json.dumps(p))" > $S/m/tb.json
  t0=$(date +%s%N); $L create -f - < $S/m/tb.json >/dev/null; $L -n jobs wait --for=condition=Ready pod/tb-$i --timeout=60s >/dev/null; t1=$(date +%s%N)
  $L -n jobs exec tb-$i -- true; t2=$(date +%s%N)
  $L -n jobs delete pod tb-$i --wait >/dev/null; t3=$(date +%s%N)
  echo "run $i create->ready_ms=$(( (t1-t0)/1000000 )) first_exec_ms=$(( (t2-t1)/1000000 )) delete_ms=$(( (t3-t2)/1000000 ))"
done > $S/out/05-timing.raw
cat $S/out/05-timing.raw
awk '{split($3,a,"=");print a[2]}' $S/out/05-timing.raw | sort -n | awk '{v[NR]=$1} END{print "create->ready ms: min",v[1],"median",(v[int((NR+1)/2)]+v[int(NR/2)+1])/2,"max",v[NR]}'
rm -f $S/m/tb.json $S/out/05-timing.raw
