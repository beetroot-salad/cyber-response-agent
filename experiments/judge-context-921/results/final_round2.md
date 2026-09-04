| arm | fixture | n | recall/3 (mean) | R1 | R2 | R3 | unmatched true | unmatched false | dup | grounded | tok in | tok out |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| current | A-F1-t3 | 5 | 0.3 | 0.0 | 0.0 | 0.3 | 0.4 | 2.8 | 0.0 | 0.96 | 3612.4 | 4793.2 |
| current | A-F2-t1 | 5 | 0.3 | 0.0 | 0.0 | 0.3 | 1.8 | 0.2 | 0.4 | 0.98 | 3226.6 | 2121.0 |
| current | fresh-alert-input | 5 | 0.2 | 0.0 | 0.1 | 0.1 | 0.0 | 2.0 | 0.2 | 0.97 | 2678.2 | 2836.0 |
| proposed | A-F1-t3 | 5 | 1.7 | 0.8 | 0.0 | 0.9 | 3.0 | 0.2 | 0.0 | 1.0 | 16008.8 | 6560.4 |
| proposed | A-F2-t1 | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 3.0 | 0.2 | 0.2 | 1.0 | 12204.6 | 3406.0 |
| proposed | fresh-alert-input | 5 | 2.2 | 0.8 | 0.8 | 0.6 | 1.0 | 0.0 | 0.0 | 1.0 | 20293.4 | 6676.8 |
| proposed+correlate | A-F1-t3 | 5 | 2.3 | 1.0 | 0.4 | 0.9 | 3.2 | 0.0 | 0.2 | 1.0 | 32191.0 | 10753.2 |
| proposed+correlate | A-F2-t1 | 5 | 0.9 | 0.8 | 0.0 | 0.1 | 2.8 | 0.6 | 0.2 | 1.0 | 24582.6 | 7608.0 |
| proposed+correlate | fresh-alert-input | 5 | 2.8 | 0.8 | 1.0 | 1.0 | 2.4 | 0.2 | 0.0 | 1.0 | 10234.4 | 9493.2 |

Per-trial:
- current/A-F1-t3/t0: recall=1.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 1.0} um_true=1 um_false=2 dup=0 grounded=0.93
- current/A-F1-t3/t1: recall=0.5 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.5} um_true=0 um_false=3 dup=0 grounded=1.0
- current/A-F1-t3/t2: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=0 um_false=3 dup=0 grounded=1.0
- current/A-F1-t3/t3: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=0 um_false=3 dup=0 grounded=0.89
- current/A-F1-t3/t4: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=1 um_false=3 dup=0 grounded=1.0
- current/A-F2-t1/t0: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=3 um_false=0 dup=0 grounded=1.0
- current/A-F2-t1/t1: recall=0.5 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.5} um_true=2 um_false=0 dup=0 grounded=1.0
- current/A-F2-t1/t2: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=2 um_false=0 dup=0 grounded=1.0
- current/A-F2-t1/t3: recall=0.5 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.5} um_true=1 um_false=1 dup=1 grounded=1.0
- current/A-F2-t1/t4: recall=0.5 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.5} um_true=1 um_false=0 dup=1 grounded=0.9
- current/fresh-alert-input/t0: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=0 um_false=1 dup=1 grounded=1.0
- current/fresh-alert-input/t1: recall=0.5 R={'R1': 0.0, 'R2': 0.5, 'R3': 0.0} um_true=0 um_false=1 dup=0 grounded=1.0
- current/fresh-alert-input/t2: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=0 um_false=3 dup=0 grounded=1.0
- current/fresh-alert-input/t3: recall=0.5 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.5} um_true=0 um_false=2 dup=0 grounded=0.875
- current/fresh-alert-input/t4: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=0 um_false=3 dup=0 grounded=1.0
- proposed/A-F1-t3/t0: recall=1.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 1.0} um_true=4 um_false=0 dup=0 grounded=1.0
- proposed/A-F1-t3/t1: recall=2.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 1.0} um_true=2 um_false=1 dup=0 grounded=1.0
- proposed/A-F1-t3/t2: recall=2.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 1.0} um_true=4 um_false=0 dup=0 grounded=1.0
- proposed/A-F1-t3/t3: recall=2.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 1.0} um_true=3 um_false=0 dup=0 grounded=1.0
- proposed/A-F1-t3/t4: recall=1.5 R={'R1': 1.0, 'R2': 0.0, 'R3': 0.5} um_true=2 um_false=0 dup=0 grounded=1.0
- proposed/A-F2-t1/t0: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=3 um_false=1 dup=0 grounded=1.0
- proposed/A-F2-t1/t1: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=2 um_false=0 dup=0 grounded=1.0
- proposed/A-F2-t1/t2: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=3 um_false=0 dup=1 grounded=1.0
- proposed/A-F2-t1/t3: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=4 um_false=0 dup=0 grounded=1.0
- proposed/A-F2-t1/t4: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=3 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t0: recall=2.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 1.0} um_true=2 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t1: recall=1.5 R={'R1': 0.0, 'R2': 1.0, 'R3': 0.5} um_true=1 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t2: recall=2.5 R={'R1': 1.0, 'R2': 1.0, 'R3': 0.5} um_true=1 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t3: recall=2.5 R={'R1': 1.0, 'R2': 1.0, 'R3': 0.5} um_true=1 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t4: recall=2.5 R={'R1': 1.0, 'R2': 1.0, 'R3': 0.5} um_true=0 um_false=0 dup=0 grounded=1.0
- proposed+correlate/A-F1-t3/t0: recall=2.5 R={'R1': 1.0, 'R2': 0.5, 'R3': 1.0} um_true=2 um_false=0 dup=0 grounded=1.0
- proposed+correlate/A-F1-t3/t1: recall=2.5 R={'R1': 1.0, 'R2': 0.5, 'R3': 1.0} um_true=3 um_false=0 dup=0 grounded=1.0
- proposed+correlate/A-F1-t3/t2: recall=2.5 R={'R1': 1.0, 'R2': 0.5, 'R3': 1.0} um_true=2 um_false=0 dup=1 grounded=1.0
- proposed+correlate/A-F1-t3/t3: recall=2.5 R={'R1': 1.0, 'R2': 0.5, 'R3': 1.0} um_true=5 um_false=0 dup=0 grounded=1.0
- proposed+correlate/A-F1-t3/t4: recall=1.5 R={'R1': 1.0, 'R2': 0.0, 'R3': 0.5} um_true=4 um_false=0 dup=0 grounded=1.0
- proposed+correlate/A-F2-t1/t0: recall=1.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 0.0} um_true=3 um_false=1 dup=0 grounded=1.0
- proposed+correlate/A-F2-t1/t1: recall=1.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 0.0} um_true=1 um_false=1 dup=1 grounded=1.0
- proposed+correlate/A-F2-t1/t2: recall=0.5 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.5} um_true=2 um_false=1 dup=0 grounded=1.0
- proposed+correlate/A-F2-t1/t3: recall=1.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 0.0} um_true=4 um_false=0 dup=0 grounded=1.0
- proposed+correlate/A-F2-t1/t4: recall=1.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 0.0} um_true=4 um_false=0 dup=0 grounded=1.0
- proposed+correlate/fresh-alert-input/t0: recall=2.0 R={'R1': 0.0, 'R2': 1.0, 'R3': 1.0} um_true=2 um_false=1 dup=0 grounded=1.0
- proposed+correlate/fresh-alert-input/t1: recall=3.0 R={'R1': 1.0, 'R2': 1.0, 'R3': 1.0} um_true=3 um_false=0 dup=0 grounded=1.0
- proposed+correlate/fresh-alert-input/t2: recall=3.0 R={'R1': 1.0, 'R2': 1.0, 'R3': 1.0} um_true=1 um_false=0 dup=0 grounded=1.0
- proposed+correlate/fresh-alert-input/t3: recall=3.0 R={'R1': 1.0, 'R2': 1.0, 'R3': 1.0} um_true=3 um_false=0 dup=0 grounded=1.0
- proposed+correlate/fresh-alert-input/t4: recall=3.0 R={'R1': 1.0, 'R2': 1.0, 'R3': 1.0} um_true=3 um_false=0 dup=0 grounded=1.0

## Round 2 decision (2026-09-03; 45 replies graded in total, grader spend $116)

Arms: `current` (spine), `proposed` (spine + four joined views), `proposed+correlate` (same context;
judge prompt adds a mandatory correlation / scope / derivation pass emitted before findings, generic
wording, no entity or system names). Fixtures: the two tuned ones plus the held-out
authorized-keys trial `A-F2-t1`, whose reference was written blind before any arm ran on it.

| fixture | arm | recall/3 | join-type ref | true extra | false extra |
|---|---|---|---|---|---|
| fresh-alert-input | current | 0.2 | R2 0.1 | 0.0 | 2.0 |
| fresh-alert-input | proposed | 2.2 | R2 0.8 | 1.0 | 0.0 |
| fresh-alert-input | proposed+correlate | **2.8** | R2 1.0, R3 1.0 | 2.4 | 0.2 |
| A-F1-t3 | current | 0.3 | A2 0.0 | 0.4 | 2.8 |
| A-F1-t3 | proposed | 1.7 | A2 0.0 | 3.0 | 0.2 |
| A-F1-t3 | proposed+correlate | **2.3** | A2 0.4, A1 1.0 | 3.2 | 0.0 |
| A-F2-t1 (held-out) | current | 0.3 | B1 0.0 | 1.8 | 0.2 |
| A-F2-t1 (held-out) | proposed | 0.0 | B1 0.0 | 3.0 | 0.2 |
| A-F2-t1 (held-out) | proposed+correlate | **0.9** | B1 0.8 | 2.8 | 0.6 |

**The correlation prompt generalizes in direction.** On all three fixtures it beats the same context
without it, and the class it was meant to move — a fact present in a payload and lost before the
belief trace, or held by two leads that nothing joined — moved on the held-out alert too: B1 (the
alerted writes' parent-process split, carried by the summary and collapsed by the document) went from
0/5 to 4/5. On the tuned fixtures the cadence break went 0/5 → 5/5 (fresh R3), the 7-day window
0/5 → 5/5 (A1), the db-1 join 0/5 → 2/5 (A2). False findings did not rise (0.0–0.2, except 0.6 on
the held-out, all of them the same observability finding — see grader note).

**Against the pre-registered rule it falls short on one count.** The rule asked for the db-1 join on
the malicious trial at ≥ 3/5; it reached 2/5. Reachable, still not reliable. The mechanical
boundary diff remains the candidate for reliability; it is no longer the first thing to build.

**The held-out alert says the reference is the weaker oracle there.** Recall against my three
findings is ≤ 0.9 for every arm, yet the grader — verifying against the artifacts — counts 2.8–3.0
true findings per reply in both proposed arms (1.8 for current). All ten proposed-arm replies
converge on a decision-discipline defect I did not rank: both authz contracts resolved to their
`escalate` branch and the run closed benign by forking a contract-free hypothesis. That is a real
root cause of that close, arguably ahead of my B3. Two of my three held-out findings — the
initiating session never queried (B2) and the persistence check impossible and unrecorded (B3) —
were found by no arm in 15 replies. The "never asked" class is the residual gap of every arm.

**Grader note.** The "errored queries archived as 0-byte payloads" finding was graded `true` on the
tuned fixtures (where the reference lists it) and `false` on the held-out (reason: harness-owned,
nothing rests on the missing bytes). Same finding, opposite verdicts, driven by whether the
reference mentioned it. It accounts for the whole 0.6 false rate on the held-out correlate arm.

**Output budget held.** Correlate replies: 7.5–10.8K output tokens, strict-YAML parseable in all 15
(the prompt's "quote any scalar with a colon" rule), 134–200 s per call.
