#!/bin/bash
# Round 2: wait for the held-out family → 25 judge calls in 5 batches → grade every ungraded trial 4 at a time → final table.
cd /workspace/experiments/judge-context-921
FAM=family/A-F2-t1/family.yaml
while pgrep -f "^python3 make_family.py" >/dev/null; do sleep 10; done
if [ ! -f "$FAM" ]; then echo "[drive2] FAILED: questioner produced no family"; tail -5 family/A-F2-t1.log; exit 1; fi
echo "[drive2] family ready $(date -u +%H:%M:%S)"
wait_judges() { while pgrep -f "^python3 run_judge.py" >/dev/null; do sleep 15; done; }
for t in 0 1 2 3 4; do
  for arm in current proposed proposed+correlate; do (nohup python3 run_judge.py --arm "$arm" --fixture A-F2-t1 --trial $t > "results/run-$arm-A-F2-t1-t$t.log" 2>&1 &); done
  for fx in fresh-alert-input A-F1-t3; do (nohup python3 run_judge.py --arm proposed+correlate --fixture $fx --trial $t > "results/run-proposed+correlate-$fx-t$t.log" 2>&1 &); done
  sleep 5; wait_judges; echo "[drive2] judge batch t$t done $(date -u +%H:%M:%S)"
done
# grade everything ungraded, 4 at a time
mapfile -t TODO < <(for d in runs/*/*/t*; do [ -f "$d/reply.yaml" ] && [ ! -f "$d/grade.json" ] && echo "$d"; done)
echo "[drive2] grading ${#TODO[@]} replies"
i=0
for d in "${TODO[@]}"; do
  arm=$(basename "$(dirname "$(dirname "$d")")"); fx=$(basename "$(dirname "$d")"); tr=${d##*/t}
  (nohup python3 grade.py --arm "$arm" --fixture "$fx" --trial "$tr" > "results/grade-$arm-$fx-t$tr.log" 2>&1 &)
  i=$((i+1)); if [ $((i % 4)) -eq 0 ]; then sleep 5; while pgrep -f "^python3 grade.py" >/dev/null; do sleep 15; done; echo "[drive2] graded $i/${#TODO[@]} $(date -u +%H:%M:%S)"; fi
done
sleep 5; while pgrep -f "^python3 grade.py" >/dev/null; do sleep 15; done
python3 analyze.py final_round2.md > /dev/null; echo "[drive2] final table written $(date -u +%H:%M:%S)"
