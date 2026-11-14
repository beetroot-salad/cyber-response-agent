#!/bin/sh
# The job's ephemeral claim is deleted with the job pod; a box still mounting it holds it until the box goes. Needs: $K.
echo "claims before: $($K -n jobs get pvc -o custom-columns=N:.metadata.name --no-headers | tr '\n' ' ')"
$K -n jobs delete pod vjob --wait=false >/dev/null; sleep 15
echo "vjob deleted, vbox still mounts vjob-work: $($K -n jobs get pvc vjob-work -o jsonpath='{.metadata.deletionTimestamp} {.status.phase}' 2>&1)"
echo "box still reads: $($K -n jobs exec vbox -- cat /work/d/y)"
$K -n jobs delete pod vbox --wait >/dev/null; sleep 10
echo "after box deleted: $($K -n jobs get pvc vjob-work 2>&1 | tail -1)"
$K -n jobs delete pod t-job t-box --ignore-not-found --wait >/dev/null; sleep 25
echo "after t-job deleted: $($K -n jobs get pvc t-job-work 2>&1 | tail -1)"
echo "PersistentVolumes left: $($K get pv --no-headers 2>/dev/null | wc -l)"
