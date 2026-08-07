# The review gate between #797 and #796

> **Both halves have landed.** The gate dispatches three blind lenses and a composer; the
> interim posture below — `REVIEW_ROLES` empty, every confident close failing closed on
> `NO_REVIEWER` — is history, and `NO_REVIEWER` is gone with it. The document is kept because
> the rules are what outlive both changes; the prose below is written from where each rule
> waited, and this note is what carries it forward.
>
> Two entries need updating in place. **Rule 16** is no longer unwitnessed:
> `test_796_gate_arms.py::test_moving_the_generic_subagent_deadline_does_not_move_the_reviews`
> re-pins the separation. **Rule 17** has its raiser again — `ReviewStages.stage()` raises
> `UnboundReviewStage` for a bundle built without a run dir, and the gate takes it through the
> ordinary stage-fault arm.
>
> The three rules under "code survives but the witness does not" are witnessed again: their
> vulture-baseline entries are retired now that lenses call them.
>
> **Rules 9 and 13 came back with the reviewer, and both fired.** Rule 9's second path did not
> exist — `_write_trace_row` always wrote the framed reply as its own literal line, which was
> harmless only while no stage answered; the composer answers with a JSON OBJECT by contract,
> so every close left a round-less row in the trace. It now rides inside the row's value when
> any of its lines parses as an object — asked of `_io.parse_jsonl_row`, the same predicate
> every trace reader applies, so the writer's raw-line choice cannot drift from what the
> reader skips. Rule 13's "exactly one pass" no longer holds either: a challenged close comes
> back and reviews again, so BOTH numbers `_fail` used to write as zero are parameters now —
> the trace round is `ReviewState.turns`, and so is the `turns_used` the verdict carries into
> the review record.
>
> The fresh-salt rule under "code survives but the witness does not" was half-held: the salt
> was minted per call and read by nothing, so the record a lens reads went in UNFRAMED. The
> projection is now rendered against that salt.

#797 retired the live write-time gate's three review stages — the **challenger**, the
**coherence checker** and the **projection stage** — and everything that existed only to
serve them. #796 lands the blind lenses and the composer that replace them.

**Between the two, the gate had no reviewer** — `challenge_gate.REVIEW_ROLES` was empty and
every confident close took the fail-closed arm, with `NO_REVIEWER` as its detail. That window
is closed: `REVIEW_ROLES` names the three lenses and the composer, and `NO_REVIEWER` is
deleted. What survives the window is the ARM, and the rule it carries — a gate that cannot
review must not let a confident finding through, and committing one silently would be
indistinguishable from a review that ran and found nothing. Its witness is
`test_797_retirement.py::test_797_a_confident_close_fails_closed_when_no_stage_is_bound`,
which now drives it through an unbound bundle: `forced-inconclusive`, cause "the challenge
review did not complete", `failure_kind: error`, detail from `UnboundReviewStage`.

`inconclusive` closes are unaffected — they bypass the gate, as they always did.

## What #796 must not re-derive

The retired code carried rules the gate learned the hard way. Each one below is either
carried by a live test after #797, or it is not — and where it is not, this is the note the
acceptance criterion asks for. **Nothing here is a suggestion; each row is a defect the gate
already shipped once.**

### Rules with a live carrier after #797

| Rule | Where it lives now |
|---|---|
| **Record first, report second**, both attempted, the fault held until both writes are tried; terminality follows the REPORT, not both. | `close_tool._commit`; driven by the e2e replays and `test_797_retirement.py` |
| `report.md` carries **host-owned vocabulary only** — a stage's prose reaches the numbered record and never the report, because the report rides verbatim into the judge's prompt and out through the ticket bridge. | `close_tool.render_report` / `_record_dict`; `test_797_retirement.py` |
| The raised request ceiling is **read from the bounds the run was handed**, both terms, never restated. | `challenge_gate.raised_request_limit`; `test_replay_error_paths` |
| A confident close that cannot be reviewed **fails closed**, and says the MACHINERY failed rather than the evidence. | `test_797_retirement.py`, `test_replay_skeleton` |

### Rules whose CODE survives but whose witness does not

These three were stated in code that #797 kept and no test then reached, because their only
callers were the retired stages — which is why `_call_stage`, `_fresh_stage_request`,
`bind_review_role` and `_make_live_stage` sat in the vulture baseline rather than being
deleted. **#796 gave all three callers again and the baseline entries are retired**; the rows
below name where each rule now lives.

| Rule | Code that holds it |
|---|---|
| A review role holds **no read grant and no bash grant at all** — not narrowed roots, zero. At write time its run dir IS the investigation's dir, and both grant surfaces admit that unconditionally ahead of any narrowing, so a role that could read or run bash could always reach the live working document. | `review_roles._DENY_REASON` (the roles it was attached to are gone; #796's carry it again) |
| **Fresh salt per stage call**, never the investigation's. A role that reads attacker-influenced payloads must not hold the delimiter of the frame its own output returns inside. | `challenge_gate._fresh_stage_request`, `review_roles.bind_review_role` |
| **A deadline and a raise are different failure kinds**, told apart at the invocation point rather than by a branch downstream that can drift. | `challenge_gate._call_stage` |

### Rules with NO live carrier — #796 owns them

Each of these is stated as the rule, not as the deleted code, because #796's shapes differ.

1. **No fail-open read of a stage reply.** `_read_coherence` returned `True`/`False`/`None`;
   the bare `"INCOHERENT" not in text.upper()` it replaced read every non-answering reply —
   an empty string, a refusal, a stray JSON blob, a timeout's leftover detail — as the
   permissive value, and a confident disposition then committed on a counter-story nothing
   had judged. **A reply that answers neither way has not completed.** Applies verbatim to a
   lens reading the composer cannot use.

2. **Unreadable is not a quality finding.** A reply the gate never parsed says nothing about
   the reasoning behind it. Folding "would not parse" into "answered inside its contract and
   the content was unusable" inflates the apparent quality-failure rate. #797 retired the
   `incoherent` kind because its producer is gone; if #796 mints a quality signal for a lens
   or the composer, it must stay apart from `unreadable`.

3. **A closed tag vocabulary is checked, not assumed.** `_parse_projection_reply` refused a
   row whose tag was outside `PROJECTION_TAGS`. Unchecked, an unknown or misspelt tag was
   invisible to all three classifier buckets, fell through to the "everything confirmed" arm
   and committed `forced-inconclusive` with **no failure kind** — the review's own breakage
   recorded as a finding about the evidence. Any enum #796 dispatches on owes the same check.

4. **The invented-identifier guard.** `_unexecuted_leads` refused an identifier the host
   never sent out. Unbounded, a hallucinated (or foreign-run) id flowed into the
   discriminating set and was handed back to the investigator as a lead to go investigate —
   the forced turn's economy inverted, with the gate charging the investigation for a
   hallucination. #796's `ask.target` is the same hazard: it is host-validated against the
   parsed companion, and a ref that does not resolve takes the `unreadable` arm.

5. **Readable-and-empty keeps its own arm.** The routing is on whether the output could be
   READ, never on how many rows it carried. A valid, readable, zero-row reply is a real
   finding. Collapsing it into the unreadable arm loses the finding; collapsing the unreadable
   arm into it records a broken review as evidence.

6. **Selection by declared header, never by column position.** `_declared_lead_columns` read
   the `:L findings` block's column names in the order the DOCUMENT declares them. The
   investigator authors that table and nothing validates its column order, so reading by fixed
   position makes the guarantee a convention the document's own author controls: reorder two
   columns and the wrong values go through silently. Any projection #796 builds over the
   companion inherits this — and #796 already says each projection has exactly one definition
   against the **parsed** companion rather than tag prefixes over raw text.

7. **`:L findings`, not the `:L` prefix.** invlang gives every lead its own `:L` sub-blocks
   (`:L l-001.lead_preds`, the routing rules), and `:L findings` is the sole site that
   declares a lead. Matching the prefix harvested the sub-block rows too and read them through
   the findings table's column positions, fabricating id/name/target triples — which the
   invented-identifier guard then failed the whole review closed on. Prefix matching over
   invlang tags is the bug, not the tag list.

8. **Every early-ended round marks every role's trace incomplete.** Otherwise the stages that
   never ran leave traces reading as if their round had completed.
   `challenge_gate._mark_traces_incomplete` survives and reads `REVIEW_ROLES`, so #796 gets
   this by filling the roster — but only if it fills the roster rather than restating the
   names at the call sites, which is how the shipped version drifted.

9. **A raw reply that is itself valid JSON must not be written as its own trace line.** It
   would stand as a round-less JSONL row and corrupt the trace's row structure. A framed reply
   goes on its own literal line only when it cannot parse as JSON; otherwise it rides inside
   the row's JSON value. `_write_trace_row` survives with both paths.

10. **An affordance that shells out does not belong in a live prompt builder.**
    `_no_closed_tickets` existed because the real closed-ticket lister shells out to a ticket
    CLI — fine for the offline actor's once-per-run cost, wrong inside the gate's own stage
    deadline. Any corpus #796 inlines (the composer's lessons corpus) pays this at every
    close.

11. **"Nobody asked" and "we asked and there were none" must render identically**, and neither
    as a claim. An empty sample was omitted entirely rather than sent as an empty list,
    because an empty menu reads to a model as "there are none" — a claim the sampler never
    made.

12. **A second ask is not a retry.** The refinement round carried the reply that failed and
    the gap that was named. Re-sending the identical prompt made the budget a coin flip and
    made the rounds-consumed count mean nothing. #796 has **one pass and no second ask**, so
    the rule is subsumed by construction — and `GRACE_BOUND`, `Bounds.grace_rounds`,
    `GateVerdict.rounds_used` and the record's `rounds_consumed` went with it. If a repeat is
    ever reintroduced, this rule and the "round is a parameter, not a hardcoded zero" rule
    below both come back.

13. **The round is a parameter, not a hardcoded zero.** `_fail` hardcoded round 0 on every arm
    it served, so a run that had spent a refinement before faulting persisted a record saying
    it had spent none. Retired with the rounds themselves (see 12) — `_fail` no longer takes a
    round. **This is the one rule #797 dropped rather than kept**, and it is only safe because
    there is exactly one pass.

14. **A decline and an unparseable reply are different facts.** The challenger's deliberate
    decline left the confident disposition STANDING and named no failure kind; an unparseable
    reply overrode it and named `unreadable`. Merging them inflated the apparent failure rate.
    #796's composer cannot decline, so `CAUSE_NO_STORY` is retired — but if any lens is given
    a "cannot answer" reply shape, it is a decline and it is not a failure.

15. **Order the checks so a retryable fault stays retryable.** The coherence verdict was acted
    on BEFORE the projection was read. Requiring the rows first turned a round the grace budget
    existed to retry into a terminal `unreadable`, and made the terminal quality arm reachable
    only when a DIFFERENT stage answered cleanly. #796 reads four lens replies before the
    composer runs; the ordering question is the same one.

16. **The review's deadline is its own env var.** `DEFENDER_REVIEW_STAGE_TIMEOUT_SECONDS`
    matches the offline pipeline's `subagent_timeout()` default IN VALUE only; the two must
    not move together. The test that pinned that
    (`test_moving_the_generic_subagent_deadline_does_not_move_the_reviews`) went with the
    #774 suite. `stage_timeout()` and `REVIEW_TIMEOUT_ENV` survive unchanged, but the
    separation is currently unwitnessed — #796 should re-pin it, since a reviewer that runs
    four lenses concurrently is exactly when someone will reach for the generic knob.

17. **An unbound stage raises; it does not substitute the source tree for the missing run
    dir.** That substitution put each stage's live trace inside the repo checkout and anchored
    the review roles' compiled policies on the source tree instead of the run they were
    judging. `review_roles.UnboundReviewStage` survives as the exception with nothing raising
    it — #796's stage factory is what raises it again.

## What #797 did NOT touch

Turn accounting, the overlap rule (`ReviewState.raised_leads` then; #796 rekeyed it to
`raised_asks` on `ask.target`), the forced-turn cap, and everything in the offline learning
loop.
`directions_for`, `ticket_seeds` and `mitre_corpus` stay — the learning loop is their other
consumer; only the gate's use of them went.
