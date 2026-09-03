| arm | fixture | n | recall/3 (mean) | R1 | R2 | R3 | unmatched true | unmatched false | dup | grounded | tok in | tok out |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| current | A-F1-t3 | 2 | 0.75 | 0.0 | 0.0 | 0.75 | 0.5 | 2.5 | 0.0 | 0.97 | 9029.5 | 6691.0 |
| current | fresh-alert-input | 2 | 0.25 | 0.0 | 0.25 | 0.0 | 0.0 | 1.0 | 0.5 | 1.0 | 6694.0 | 626.5 |
| proposed | A-F1-t3 | 2 | 1.5 | 0.5 | 0.0 | 1.0 | 3.0 | 0.5 | 0.0 | 1.0 | 40020.5 | 6527.0 |
| proposed | fresh-alert-input | 2 | 1.75 | 0.5 | 0.5 | 0.75 | 1.5 | 0.0 | 0.0 | 1.0 | 25366.5 | 4790.0 |

Per-trial:
- current/A-F1-t3/t0: recall=1.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 1.0} um_true=1 um_false=2 dup=0 grounded=0.93
- current/A-F1-t3/t1: recall=0.5 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.5} um_true=0 um_false=3 dup=0 grounded=1.0
- current/fresh-alert-input/t0: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=0 um_false=1 dup=1 grounded=1.0
- current/fresh-alert-input/t1: recall=0.5 R={'R1': 0.0, 'R2': 0.5, 'R3': 0.0} um_true=0 um_false=1 dup=0 grounded=1.0
- proposed/A-F1-t3/t0: recall=1.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 1.0} um_true=4 um_false=0 dup=0 grounded=1.0
- proposed/A-F1-t3/t1: recall=2.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 1.0} um_true=2 um_false=1 dup=0 grounded=1.0
- proposed/fresh-alert-input/t0: recall=2.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 1.0} um_true=2 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t1: recall=1.5 R={'R1': 0.0, 'R2': 1.0, 'R3': 0.5} um_true=1 um_false=0 dup=0 grounded=1.0

## Mid-run decision (8 of 20 graded, 2026-09-02)

CONTINUE, variable unchanged. Direction is unambiguous on both fixtures: `proposed` recall 1.5–1.75/3
vs `current` 0.25–0.75/3; true unmatched 1.5–3.0 vs 0–0.5; false unmatched 0–0.5 vs 1.0–2.5; all
pointers grounded in both arms. `proposed` is below the 2.5/3 win bar because R2/A2 (the db-1 join)
surfaced in 1 of 4 draws and R1/A1 in 2 of 4 — reachable, not reliable. Not adjusting the view
mid-run; the entity-index view is the follow-up ablation, not a change to this experiment.

Two things the grader surfaced that are findings about the CURRENT context, not about the judge:
- On the malicious fixture both `current` draws read the sibling worlds' injected facts
  (sre.oncall, bash parent, null container) as truths about world A; t1 declared
  `corpus-contradiction`. The manifest without payloads invites the confusion.
- `current` replies restate the run's own close narrative as findings (all `false`/`duplicate`).

Grader agreement with the hand score on t0: identical on R1/R2; R3 `hit` where I had `partial`
on current/A-F1-t3 (the grader credited the close-phase mechanism without the l-007 link).
Grader cost ≈ $2–3.2 per reply at xhigh, 65–145 s.
