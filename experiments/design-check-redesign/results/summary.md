# Where this experiment stands

Plan: `plan.md` (#1366 replay, not yet run). What ran instead, on #1161 piece 1, one trial each:

| Run | Instructions | Output | Result |
|---|---|---|---|
| `runs/1161/check-current.md` | write-tests design check before PR #1527 | 8 findings, "not ready" | baseline |
| `runs/1161/check-proposed.md` | first rewrite: redesign from scratch, still in write-tests | "shape holds", 4 sign-in shapes tried, 15 findings | `1161-smoke.md`: no catch lost; dropped readiness; harness list grew to ~60 lines |
| `runs/1161-v2/review.md` | moved into discuss-issue, returns a proposed design | "shape does not hold for sign-in", 4 decisions | `1161-v2-criteria.md`: 4 of 5 criteria pass (too long); recommends the sign-in shape the smoke run rejected for session theft, without weighing that risk |

Not yet run: the final instructions in PR #1527, where the review explains problems by cause and
offers shapes as options with trade-offs, weighed against the threat model, instead of a verdict.

Caveats: #1161 is not held out (the rewrite was shaped on it); the sketch was copied from the
live worktree and includes edits made after the original check; one trial per variant.
