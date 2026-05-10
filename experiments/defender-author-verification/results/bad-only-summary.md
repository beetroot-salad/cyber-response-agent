# Bad-lesson-only N=3 results

Verdict semantics: BAD = check caught the bad lesson (good for our gate). GOOD = check missed it.

| Lesson | Check | Reps (verdicts) | Caught (BAD count) |
|---|---|---|---|
| L1-bad-T3-zero-success-spray.md | forward | BAD,BAD,BAD | 3/3 |
| L1-bad-T3-zero-success-spray.md | reverse | BAD,BAD,BAD | 3/3 |
| L1-bad-T3-zero-success-spray.md | regression | BAD,BAD,BAD | 3/3 |
| L2-bad-T2-burst-escalate.md | forward | BAD,BAD,BAD | 3/3 |
| L2-bad-T2-burst-escalate.md | reverse | BAD,BAD,BAD | 3/3 |
| L2-bad-T2-burst-escalate.md | regression | BAD,BAD,BAD | 3/3 |
| L3-bad-T2-pname-null-escalate.md | forward | BAD,BAD,BAD | 3/3 |
| L3-bad-T2-pname-null-escalate.md | reverse | BAD,GOOD,GOOD | 1/3 |
| L3-bad-T2-pname-null-escalate.md | regression | BAD,BAD,BAD | 3/3 |
| L4-bad-T4-high-entropy-c2.md | forward | GOOD,GOOD,GOOD | 0/3 |
| L4-bad-T4-high-entropy-c2.md | reverse | BAD,BAD,GOOD | 2/3 |
| L4-bad-T4-high-entropy-c2.md | regression | BAD,BAD,BAD | 3/3 |

## Per-check TNR (caught / total)

- **forward**: 9/12 = 75%
- **reverse**: 9/12 = 75%
- **regression**: 12/12 = 100%
