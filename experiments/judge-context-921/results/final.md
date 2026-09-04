| arm | fixture | n | recall/3 (mean) | R1 | R2 | R3 | unmatched true | unmatched false | dup | grounded | tok in | tok out |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| current | A-F1-t3 | 5 | 0.3 | 0.0 | 0.0 | 0.3 | 0.4 | 2.8 | 0.0 | 0.96 | 3612.4 | 4793.2 |
| current | fresh-alert-input | 5 | 0.2 | 0.0 | 0.1 | 0.1 | 0.0 | 2.0 | 0.2 | 0.97 | 2678.2 | 2836.0 |
| proposed | A-F1-t3 | 5 | 1.7 | 0.8 | 0.0 | 0.9 | 3.0 | 0.2 | 0.0 | 1.0 | 16008.8 | 6560.4 |
| proposed | fresh-alert-input | 5 | 2.2 | 0.8 | 0.8 | 0.6 | 1.0 | 0.0 | 0.0 | 1.0 | 20293.4 | 6676.8 |

Per-trial:
- current/A-F1-t3/t0: recall=1.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 1.0} um_true=1 um_false=2 dup=0 grounded=0.93
- current/A-F1-t3/t1: recall=0.5 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.5} um_true=0 um_false=3 dup=0 grounded=1.0
- current/A-F1-t3/t2: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=0 um_false=3 dup=0 grounded=1.0
- current/A-F1-t3/t3: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=0 um_false=3 dup=0 grounded=0.89
- current/A-F1-t3/t4: recall=0.0 R={'R1': 0.0, 'R2': 0.0, 'R3': 0.0} um_true=1 um_false=3 dup=0 grounded=1.0
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
- proposed/fresh-alert-input/t0: recall=2.0 R={'R1': 1.0, 'R2': 0.0, 'R3': 1.0} um_true=2 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t1: recall=1.5 R={'R1': 0.0, 'R2': 1.0, 'R3': 0.5} um_true=1 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t2: recall=2.5 R={'R1': 1.0, 'R2': 1.0, 'R3': 0.5} um_true=1 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t3: recall=2.5 R={'R1': 1.0, 'R2': 1.0, 'R3': 0.5} um_true=1 um_false=0 dup=0 grounded=1.0
- proposed/fresh-alert-input/t4: recall=2.5 R={'R1': 1.0, 'R2': 1.0, 'R3': 0.5} um_true=0 um_false=0 dup=0 grounded=1.0

## Decision (N=5 per arm per fixture, 20 replies, all graded by Fable 5.1 xhigh; grader spend $50.82)

Against the pre-registered criteria: **neither "proposed wins" nor "current retained" fires.**
`proposed` reaches 2.2/3 (fresh) and 1.7/3 (malicious), under the 2.5 bar on both; `current`
is at 0.2 and 0.3 with 2.0–2.8 false findings per reply, so it is not retained either. The
pre-registered reading is "inconclusive against the bar → ablate", and the direction is not in
doubt: on every axis, on both fixtures, the joined views beat the spine by a wide margin
(recall +1.4 to +2.0 of 3; true unmatched 1.0–3.0 vs 0.0–0.4; false unmatched 0.0–0.2 vs
2.0–2.8; every proposed pointer grounded).

### What the misses say (this is the design input for #921)

1. **The db-1 join (R2/A2) is a cross-lead entity join, and the per-lead chain does not make it.**
   Fresh fixture: 4/5 hits — there the l-006 SUMMARY says "container … is named db-1" beside
   the CMDB inventory. Malicious fixture: 0/5 — there the name db-1 exists only in the l-007/0
   payload and in query params (host=db-1); the l-007 summary is one line ("hit request
   limit"), and the document never writes the name. The judge finds what a summary states and
   not what only a payload holds. → Fifth view for the follow-up: an ENTITY INDEX (host / user /
   ip / container → every payload, summary, param and document row naming it, with the
   summary/document absence marked).
2. **The 7-day-window finding (A1) surfaced 4/5 only via the sibling spread**, never from the
   coverage view, which lists index patterns but not time windows. → Coverage rows need the
   window (and scope key) beside the pattern.
3. **The eight-day pre-alert silence (R3a) was never noticed in 10 proposed replies**; R3 hits came
   from the empty error payloads and the dropped baseline rows. A cadence break is a derived
   fact over a payload, not a row in it; either the judge computes it or a view does.
4. **`current` confabulates from the manifest.** 5/5 malicious-fixture replies under `current`
   treated the sibling worlds' injected facts (actor sre.oncall, bash parent, null container) as
   truths about world A; two declared `corpus-contradiction`. A judge grading world A must be
   handed the counterfactuals marked as such, or not at all.

### Findings outside the question, recorded for their owners

- Questioner (#947): shown query rows without payload text or summaries (5.2K tokens), it
  authored a discriminator the run's own l-001 payload already answered and two worlds that
  contradict that payload; reply fenced in ```yaml with prose before it (parser refuses);
  world ids with `-` (identity gate refuses); `overlay.elastic` as a list (schema wants a mapping).
- Archive: error rows persist 0-byte payload files — the 404 behind an authz verdict exists only
  in a summary; leaked `</parameter></invoke>` markup in a run's investigation.md.
- K3 as judge: unquoted colons in YAML scalars in 7/20 replies (lenient parser added to checks).

### Cost
Judge (K3, medium): current ≈ 3–9K tokens in (cache hits after t0), proposed ≈ 16–80K in;
≈ 2 min per call. Grader (Fable 5.1, xhigh): $1.9–3.3 and 65–145 s per reply.
