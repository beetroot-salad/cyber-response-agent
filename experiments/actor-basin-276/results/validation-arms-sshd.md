# Validation pass 2 — sshd anchor (benign, dev.gabe). Outcomes & honest read.

Direction-signal pass over `fixtures/sshd-gabe-live/` (frozen **benign/medium**: dev.gabe fat-finger,
3 fails + success on jump-box-1 from 172.18.0.25, credited as "user retry"). Seed pinned across arms.
**This time the human-mimicry lesson IS retrieval-relevant** (`alert_rule_ids: rule-v2-sshd-success-
after-failures`, derived key matches), so armA/armB **actually retire** `ssh-brute-force-timing-mimicry`
(moved out of the live corpus during the actor call, git-restored after — verified clean).

## Outcomes — the verdict moved for the first time

| arm | actor.md | lesson | outcome |
|---|---|---|---|
| arm0-baseline | current | **present** | **caught** |
| armA-reframe | reframed | retired | **survived** |
| armB-whitebox | reframed + white-box | retired | **survived** |

## What actually caught arm0 (correcting my pre-run prediction)

I predicted arm0 would be caught on a **timing mismatch** (the lesson prescribes 8–20s "human" gaps;
the real fat-finger is sub-3s / ~9.7s total). **That prediction was wrong.** The judge's cadence finding
on arm0 actually ruled the timing **dual-consistent** — *"this cadence is equally consistent with a
credential-stuffing tool that introduces small randomized delays… carries near-zero likelihood-ratio
weight"* — i.e. the timing did **not** refute the story.

arm0 was caught on a **self-generated artifact**: its PAM-backdoor persistence required a *verification
login* ("after confirming the PAM module authenticates correctly in a second test SSH… the actor
truncates auth.log"). That second `Accepted password for dev.gabe` is shipped to Elastic before any
log truncation — a durable, checkable event. The judge grounded it: *"[actual] 0 occurrences of a second
Accepted password for dev.gabe in any post-alert window"* → refuted → **caught**. The story's own
verification step produced an event the real telemetry contradicts.

armA/armB **survived** because their load-bearing harm sits in the **post-auth process/filesystem
envelope** (PAM module drop + `/etc/pam.d/sshd` write *inside the interactive session*) that the
auth-focused lead set never queries — and they did **not** stage a separate checkable verification login.
armB additionally exploited a grounded gap: the **absence of the session-open event** (the white-box
actuals show dev.ethan/dev.dana produce a full session lifecycle; dev.gabe's was unobserved).

## Honest attribution — suggestive, not proven

- **The outcome flipped, and both retired arms moved the bypass locus** from the auth surface (where
  arm0 self-refuted) to the analysis's coverage gap (post-auth execution). That 2-vs-1 pattern is
  consistent with the #276 thesis: *stop investing in mimicking the auth telemetry; target the analysis
  gap.*
- **But it is N=1 per arm with a shared seed.** arm0's fatal step (the verification login) is not
  obviously *caused* by the timing lesson — the lesson is about cadence/session, not backdoor testing.
  It may be a stochastic story-construction difference (arm0 happened to include a self-refuting test
  login; the retired arms happened not to). Clean attribution needs multiple seeds per arm (the planned
  N=6). Call this a **strong direction signal**, not validation.
- The reframe did **not** eliminate human-timing framing — armA still claims "tens-of-seconds to low
  minutes" gaps. What changed is *where the load-bearing bypass sits*, not whether the actor mentions
  human timing.

## Bonus: even the caught arm produced the target finding

arm0 (caught) still emitted a clean **likelihood-ratio / dual-consistency** finding —
`analyze-discipline: "failure cadence treated as benign discriminator when dual-consistent"` — flagging
that the defender over-weighted the 0.68–2.58s cadence as benign without comparing against the 7-day
baseline distribution (l-002 was available, unused). That's a genuine **FP-risk lesson for the defender**,
independent of the actor outcome. And the misprediction finding (the verification login is a durable
trace) is a real **realizability lesson for the actor**.

## Cross-anchor synthesis (falco + sshd)

- **falco anchor** (winnable automation basin, lesson irrelevant): all 3 survived; differences were
  quality only (armA sharpest dual-consistency finding; armB more grounded but noisier findings).
- **sshd anchor** (human basin, lesson relevant & mis-calibrated): the lesson-present baseline was
  **caught**, both retired arms **survived**. The reframe/retirement's clearest value shows up exactly
  where the stale lesson is in play — consistent with #276, pending replication at N>1.
- **White-box**, both anchors: never changed the outcome vs the blind reframe (armA) — it adds grounding
  refinement (here: the session-open-absence exploit), not a verdict change. Reinforces "keep the actor
  blind in production; white-box is an offline diagnostic."

## Housekeeping
Lesson restored (git clean, present at end). Runner: `run_arms_sshd.py`. Artifacts: `runs-sshd/<arm>/`.
N=1/arm, low-effort judge — direction signals, not measurements.
