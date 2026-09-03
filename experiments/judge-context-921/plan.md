# Judge input context — does the joined view find the root cause? (#921)

## Question

**Engineering** — given one finished investigation and its family discriminator, does a
judge (Kimi K3) fed the four joined views produce the three root-cause findings a human
reader produced, where a judge fed the "spine is already written" context (the issue's
premise: investigation document + report + queries table + discriminator) does not?

The reference is the human examination of `20260830T100154Z-fresh-alert-input`
(this session, 2026-09-02), written before any judge output existed:

| Ref | Finding | Bucket | Evidence a hit must name |
|---|---|---|---|
| R1 | Never established who ran the burst: no SSH auth-index or process-parent query; "automated" inferred from sub-ms timing. Sibling trials that asked found an accepted root SSH from a public IP 10s before, or the container startup script. Lesson prescribing the auth-log query was loaded 3×. | lead-set | auth log / `logs-system.auth-*` / sshd / process parent as *unqueried* |
| R2 | Right systems, wrong asset: CMDB queried for `soc-playground` (the Docker host); the returned inventory contains `db-1`; loop 2 identifies the container as `db-1`; no lead goes back. The ceiling "unregistered in every governance system" is false — db-1 is prod, owner team.data, change window sat 04-06 UTC, one sudo account (not root). | lead-quality | `db-1` present in CMDB / wrong scope / never reconciled |
| R3 | Claims not traceable to bytes: l-002 summary says "no record" over a payload containing db-1; l-005 summary says "every 1–3 days" over a payload where all sudo stops Aug 17/22 then 8 days of silence; resolutions cite edges that paraphrase summaries; error rows have empty payload files (the 404 exists only in a summary). | analyze-discipline | summary vs payload discrepancy, or the pre-alert silence, or empty error payloads |

Meta-fact the judge should surface as context, not as a finding: the same alert has 16
trials on disk with 5 distinct dispositions (benign 8, inconclusive 4, malicious 2,
false-positive 1, unresolved 1).

## Variants

One variable: **what the judge is shown**. Same model (`kimi-k3` via Fireworks), same
effort, same judge prompt (`variants/judge.md`), same output schema, same family manifest.

### current (regression) — `variants/contexts.py::render_current`

The issue's premise, verbatim: "the reviewer's context is not a new artifact to design".

```
1. family.yaml            (questioner output: base story, discriminator, worlds)
2. investigation.md       (the whole document, invlang blocks and prose)
3. report.md
4. executed_queries.jsonl (as recorded: lead_id, seq, system, verb, query_id, params, status)
5. alert.json
```

### proposed — `variants/contexts.py::render_proposed`

Everything in `current`, plus the four joined views, rendered by the host (no model call):

```
6. PER-LEAD CHAIN, one section per lead, keyed on lead id then edge id:
     goal + what_to_summarize            (gather_raw/<lead>.lead.json)
     each query: params + raw payload    (executed_queries row + gather_raw/<lead>/<seq>.json,
                                          payload truncated at 6 KB per row, error rows shown
                                          as "payload file EMPTY (error_class=…)")
     the summary the main agent received (gather_summaries/<lead>.md)
     edges / vertices / attr_updates / authz rows citing this lead   (companion parser)
     resolutions whose supporting_edges cite those edges              (companion parser)
7. COVERAGE: per system → set of (verb, index/template, scope key) this run issued;
     the discriminator's holding_system + envelope marked touched/untouched;
     the UNION of (system, verb, index/template) issued by the 15 sibling trials of the
     same alert, with the count of trials that issued each — "what was askable".
8. LESSONS LOADED: name, load timestamp(s), and the lesson body (lessons/<name>.md).
9. TRIAL SPREAD: for each of the 16 trials of this alert: disposition,
     termination.category, one-line summary, systems touched.
```

Diff is additive on purpose: if `proposed` wins, a follow-up ablates views 6–9 one at a time.

## Fixtures

- `fixtures/fresh-alert-input` → `/workspace/.defender-runs/20260830T100154Z-fresh-alert-input`
  — the examined run; reference R1–R3 above. Exercises all three buckets and the
  summary-vs-payload cut.
- `fixtures/A-F1-t3` → `/workspace/.defender-runs/ic986-A-F1-off-hours-sudo-t3` — same alert,
  closed **malicious** on the SSH finding. Guards against `proposed` merely pattern-matching
  the first fixture. **Its reference is written by the same examination method BEFORE any
  trial runs on it**, and after validation on fixture 1 (so the method is not tuned to it).
- Family: ONE questioner run over the fresh run at **branch message 32** (the request
  carrying loop 1's three gather returns — the analogue of the 08-16 experiment's message 59).
  Produced by `make_family.py` → `family/family.yaml`, validated through `parse_family`.
  Both fixtures share this family (same alert; the discriminator is about the case).
  Questioner model = repo default (`kimi-k3`). Sibling worlds are NOT run — no ΔO/verdict
  difference exists in this experiment; the discriminator is what the judge grades against.

Shape-current: runs are from 2026-08-30 on the current invlang schema (companion parses
with 0 warnings); the family manifest is #947's shipped schema.

## Trials

Validation: 1 per variant per fixture (4 calls). I hand-score every validation reply
against R1–R3, run the grader on them to check it agrees, and check the `proposed` context
renders within K3's window.
Scale-up: **N = 5 per arm per fixture** (20 calls). Mid-run analysis at 2/5.
Analysis script: `experiments/judge-context-921/analyze.py`, written before scale-up.

Cost ceiling: `proposed` context ≈ 50–60K tokens → ≈ $0.20/call in, ~$0.05 out; whole
run under $15.

## Scoring (an LLM grader, with mechanical checks as its context)

The judge returns YAML: `findings: [{bucket, claim, root_cause, evidence: [pointers]}]`
plus `episode_outcome` and `noise_floor_note`.

`grade.py` runs per reply, in two steps:

1. **Mechanical checks** (`checks.py`): regex hits per reference finding over
   `claim`+`root_cause`+`evidence` (patterns frozen before scale-up); per pointer, whether it
   names a file/row that exists in the fixture; the judge's bucket per finding. These are
   handed to the grader as context, never as the verdict.
2. **The grader** — Claude Fable 5.1 at `--effort xhigh`, headless via
   `claude -p --model claude-fable-5-1 --output-format json --tools ""`, blind to the arm.
   It is given the reference table (R1–R3 with evidence), the judge's reply, the mechanical
   checks, and the fixture's ground facts (the db-1 CMDB row, the query table, the
   sibling-trial query union) so it can verify an unmatched finding rather than guess. It
   returns JSON: per reference finding `hit | partial | miss` with a one-line reason; per
   unmatched finding `true | false | duplicate` with a reason; and `grounded_pointer_share`.

`analyze.py` aggregates per (arm, fixture): mean recall (hit=1, partial=0.5) with n; mean
true-unmatched and false-unmatched per reply with n; grounded share; tokens in/out.
Rank by per-occurrence mean, n shown as support. I spot-audit the grader on the four
validation replies before scale-up; the reference was written by me, which is the
circularity in this design and it is stated rather than hidden.

## Decision criteria

- **proposed wins** if, on both fixtures, mean recall ≥ 2.5/3 with ≥ 80 % of pointers
  grounded, AND the audited false-finding rate is no higher than `current`'s.
- **current retained** if `current` already reaches mean recall ≥ 2/3 (the spine suffices
  and the views are cost), OR `proposed` buys its recall with a false-finding rate above
  `current`'s by more than one finding per reply (the views make it confabulate).
- **inconclusive** if recall differs by < 0.5 with overlapping spreads → ablate views one
  at a time before deciding anything.

## Layout

```
experiments/judge-context-921/
  plan.md
  variants/judge.md                 # shared judge prompt + output schema
  variants/contexts.py              # renders arm `current` and arm `proposed`
  family/                           # questioner episode: family.yaml + traces
  make_family.py                    # standalone questioner call at message 32
  run_judge.py                      # one call: --arm --fixture --trial → runs/…
  fixtures/                         # pointer files + reference.md per fixture
  runs/<arm>/<fixture>/t<N>/        # prompt.md, reply.yaml, trace.jsonl
  checks.py                         # mechanical checks handed to the grader
  grade.py                          # claude -p grader (Fable 5.1, xhigh), blind to arm
  analyze.py                        # written before scale-up
  results/                          # validation.md, midrun.md, final.md
```
