# Design check as a from-scratch redesign: replay on #1366

## Question
Engineering. Does the reframed design check (PR #1527) give a verdict on the design's shape and
propose a redesign grounded in the sketch's and spike's tensions, without losing the gaps the
current check catches?

## Variants
One variable per comparison. The PR changed two prompts, so they are compared separately.

### Primary: the design check (`variants/{current,proposed}-review.md`, section "Design check")
- current: "does the design say enough, consistently enough, to write a thorough contract
  against?"; keep a spike finding only if it names the design choice it conflicts with; return
  findings grouped by decision.
- proposed: (1) collect tensions inside the design and between design and code (read the spike's
  diff); harness defects and test upkeep go to a trailing author list; (2) redesign from scratch
  so the tensions never arise, keeping the promises; (3) compare, leading with whether the
  current shape holds.

Both arms read the same design, sketch and spike. Only the charge differs.

### Secondary: the spike's friction log (`variants/{current,proposed}-authoring.md`, "Spike")
- proposed adds: where the code pulled toward another shape; harness defects and stale tests in a
  separate trailing list.
- The regression for this one is free: the original run's `spike-log.md` was written under the
  current charge. Compared by reading, not scored.

## Fixture
#1366, "System and case records as versioned DB records", merged as PR #1473.
- Input: design r6 folded (`.worktrees/1366-contract-repair-1/.contract-first/design.md`), grounding
  base `e451f1de7`. Copied into `fixtures/`.
- Why it's load-bearing: the original design check returned eight items (DC1–DC8) and the owner
  approved DC1–DC5. After that, the design changed shape twice: tenant admins write records
  through the API (#1083 amendment, 2026-11-11), and operator commands were removed (#1470,
  2026-11-14). The original DC8 was "operator command surface: flows the design implies but does
  not state", a gap sitting where the later reshaping happened.
- Ground truth (given only to the judge): DC1–DC5 as approved, and the two later amendments. The
  later amendments may have come from product direction rather than anything visible in code,
  so anticipating them is a bonus signal, not a criterion.
- Sketch and spike diffs from the original run are gone; only `spike-log.md` survives. So both
  are regenerated.

## Trials
1. Regenerate the shared inputs once, in a detached worktree at `e451f1de7`:
   - sketch: Opus, medium effort, current sketch charge (unchanged by the PR);
   - spike: Sonnet, medium effort, **proposed** spike charge. Its extra fields are additive. The
     current-check arm reading a richer log biases toward current, which is the conservative
     direction.
   - Postgres container as in the original run. Every pytest call through `defender-pytest`.
2. Validation: one design check per arm (Opus, high effort) on those inputs.
3. Scale-up: 2 more checks per arm (N=3 per arm) on the same inputs, only if validation is
   well-formed. Checks are cheap next to the spike; the spike is not repeated.

Contamination guard, for every agent:
- no `gh` or network, no reads outside its worktree (other worktrees hold #1366's later
  records), no `git log` past the base;
- the project cache as of the base commit (0 lines about #1366; today's has 12, including the
  spike's own findings);
- no code map: the surviving one was written after the check. Workers read the code themselves;
- briefed from the files in `variants/`, never through the slash command (the installed plugin is
  a stale copy).
Transcripts are grepped for `gh `, `issues/1366` and `.worktrees/1366` afterwards; a
contaminated trial is discarded.

Prerequisites: a fresh Postgres container for this run (`pg1366r`; other sessions' containers are
not reused); the worktree at the base needs its own working interpreter, checked before the sketch.
Cost: the spike is the expensive step (the original #1366 run was large: 883 tests at the end).

## Scoring (`analyze.py` written before scale-up)
Mechanical, per check output:
- does it open with a verdict on the shape (holds / reshape)?
- number of findings, and how many in the findings section are about tests or harness upkeep;
- for each redesign item: does it cite at least two tensions it removes, and does it name a
  changed promise as a choice for the human?

Blind judge (Opus, high effort, a fresh agent per trial pair, arm labels randomised), given the
ground truth:
- which of DC1, DC3 and DC4 (the confirmed misfit, collision and contradiction) each output
  catches, by substance, not by wording;
- whether a redesign is grounded in cited evidence or speculative;
- whether either output moves toward the later shape (who writes records; the operator surface);
- pairwise preference: which would a design owner rather receive, and why.

## Decision criteria
The judge can't be truly blind (the proposed layout gives the arm away), so the human reads the
first pair side by side before any scale-up. The question is whether the reframing they expected
shows up at all.

If proposed says "the shape holds" in every trial, the result is **inconclusive**: the fixture
didn't exercise the reframing.

- **proposed wins** if, in at least 2 of 3 trials, it proposes a reshape that the judge rates
  grounded (removes two or more cited tensions), catches at least as many of DC1/DC3/DC4 as current
  does in the same trial, and the judge and the human prefer it. Opening with a verdict and keeping
  test upkeep out show only that the charge was followed; they are checked, not counted as a win.
- **current retained** if proposed misses one of DC1/DC3/DC4 that current catches in 2 or more
  trials, or its redesigns are mostly ungrounded, or it changes a promise without flagging it.
- **inconclusive** otherwise. A redesign that both arms make, or neither, says nothing about the
  charge.

## Optional smoke test first: #1161
Its design, sketch, spike diff and log are all on disk, so a check-only replay costs two Opus runs
and no spike. It is not held out: the rewrite was shaped on it, so the proposed charge's #1161
cache line is stripped for that run. A smoke test before #1366, not a replacement.

## Layout
experiments/design-check-redesign/
  plan.md
  variants/   current-*.md (origin/main), proposed-*.md (PR #1527)
  fixtures/   design-r6.md, original spike-log.md, ground-truth.md (judge only)
  runs/       sketch/, spike/, check-{current,proposed}-{1..3}.md, transcripts
  analyze.py
  results/
