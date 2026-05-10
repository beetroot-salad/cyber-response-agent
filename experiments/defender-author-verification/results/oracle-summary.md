# Oracle (full Sonnet rerun) results

| Lesson | Case | Ground truth | Rerun disposition | Oracle verdict |
|---|---|---|---|---|
| L1-bad-T3-zero-success-spray.md | real-01-low-monitoring-probe | BENIGN | ESCALATE | BAD |
| L2-bad-T2-burst-escalate.md | real-02-low-bait-monitoring-burst | BENIGN | BENIGN | GOOD |
| L3-bad-T2-pname-null-escalate.md | real-03-low-shell-100001 | BENIGN | ESCALATE | BAD |
| L4-bad-T4-high-entropy-c2.md | real-04-low-dns-100110 | ESCALATE | ESCALATE | GOOD |
| L5-good-monitoring-username-fingerprint.md | real-01-low-monitoring-probe | BENIGN | BENIGN | GOOD |
| L6-good-burst-not-disqualifying-monitoring.md | real-02-low-bait-monitoring-burst | BENIGN | BENIGN | GOOD |
| L7-good-container-shell-baseline-first.md | real-03-low-shell-100001 | BENIGN | BENIGN | GOOD |
| L8-good-multi-domain-rotation-ratio.md | real-04-low-dns-100110 | ESCALATE | ESCALATE | GOOD |
