#!/bin/bash
# Unattended remainder: wait for t2+t3 judges → launch t4 judges → grade t2+t3 (4 at a time) → wait t4 → grade t4 → final table.
cd /workspace/experiments/judge-context-921
wait_judges() { while pgrep -f "^python3 run_judge.py" >/dev/null; do sleep 15; done; }
wait_graders() { while pgrep -f "^python3 grade.py" >/dev/null; do sleep 15; done; }
grade_trial() { for arm in current proposed; do for fx in fresh-alert-input A-F1-t3; do (nohup python3 grade.py --arm $arm --fixture $fx --trial $1 > results/grade-$arm-$fx-t$1.log 2>&1 &); done; done; wait_graders; }
wait_judges
echo "[drive] t2+t3 judges done $(date -u +%H:%M:%S)"
for arm in current proposed; do for fx in fresh-alert-input A-F1-t3; do (nohup python3 run_judge.py --arm $arm --fixture $fx --trial 4 > results/run-$arm-$fx-t4.log 2>&1 &); done; done
grade_trial 2; echo "[drive] t2 graded $(date -u +%H:%M:%S)"
grade_trial 3; echo "[drive] t3 graded $(date -u +%H:%M:%S)"
wait_judges; echo "[drive] t4 judges done $(date -u +%H:%M:%S)"
grade_trial 4; echo "[drive] t4 graded $(date -u +%H:%M:%S)"
python3 analyze.py final.md > /dev/null; echo "[drive] final table written"
grep -h "" results/grade-*-t[234].log
