# clerk-996-live — the #996 port against the live stack

## Question

**Engineering** — does moving row authorship off MAIN onto a cheap clerk lower the cost of a
real investigation without degrading the investigation it produces?

The cost thesis is arithmetic and worth stating so the run can refute it: the clerk's model
bills at `$0.15 / $0.50` per million (in/out) against MAIN's `$1.40 / $4.40` — about 9× cheaper
on both sides — and the invlang grammar (~11k tokens) leaves MAIN's orientation, where it was
re-sent on every single MAIN request. So the port should move token volume from an expensive
model to a cheap one AND shrink the expensive model's per-request prefix.

What could make that fail to show up: the clerk spends up to six calls per `record` and `record`
is MAIN's most-called verb, so a clerk that retries a lot can eat the saving. That is the thing
this experiment is actually measuring.

## Variants

One variable: **who writes the invlang rows**. It cannot be split smaller — the roster change,
the orientation change and the clerk role are one mechanism, and any two of them alone leave a
runtime that cannot write its own document. The variable in its smallest honest statement:

```
current (origin/main)                    proposed (spec/996-clerk)
─────────────────────                    ────────────────────────
MAIN roster:  append_block, fix_row      MAIN roster:  record
MAIN prompt:  + invlang grammar (~11k)   MAIN prompt:  no grammar (catalog kept)
rows authored by: MAIN (glm-5.2)         rows authored by: clerk (glm-5.3-flash)
                                         + clerk_trace.jsonl per record call
```

### current (regression arm)
`origin/main` @ `7817e386`. MAIN authors `:V`/`:E`/`:R`/`:T` blocks directly through
`append_block`, repairs with `fix_row`, and carries the grammar in every request.

### proposed
`spec/996-clerk`. MAIN calls `record(text)` with prose; the clerk compiles it.

**Both arms must be committed before any trial runs.** `provenance.json` stamps the commit and
whether the tree was dirty; a dirty-tree run is not a result anyone can reproduce, and this
branch currently carries ~1000 lines of uncommitted work.

## Fixtures

The labelled held-out set (`defender/fixtures/held-out/`) contains **only a README** in this
checkout, so `evals/held_out.py` — the north-star disposition metric — has nothing to score.
That is a real limit on this experiment and is why the quality criteria below are proxies
rather than the primary metric. Anything stronger needs the labelled set restored first.

- `defender/fixtures/v2-sshd-success-after-failures/alert.json` — the simplest shape: one host,
  one identity, a brute-force-then-success question. Exercises the ordinary prose→rows path with
  few leads. This is the validation fixture.
- `defender/fixtures/v2-cross-tier-ssh-pivot/alert.json` — multi-hop, multiple vertices and
  edges, several leads. Exercises the row volume the clerk has to carry, and the loop close.
- `defender/fixtures/v2-falco-suspicious-network-tool/alert.json` — process/behaviour shaped
  rather than identity shaped; exercises a different slot vocabulary and a likelier `??`.

All three are shape-current: they are the v2 fixtures the current `playground-v2` stack serves.

## Trials

**Validation: 1 per variant per fixture = 6 runs.** Purpose is to confirm the experiment is
well-formed — both arms complete, produce a parseable `report.md`, and emit the wire-log and
trace rows the analysis reads. Not to compare anything.

**Scale-up: N=5 per variant per fixture = 30 runs**, only if validation is clean. Mid-run
analysis after the first 8 (~27%): re-run `analyze.py`, decide continue / abort / adjust.

`analyze.py` is written **before** scale-up, not after. Metrics, all read from the run dir:

| Metric | Source | Why |
|---|---|---|
| total cost, per role | `wire_logs/llm_requests.jsonl` × `scripts/pricing.py` | the headline |
| MAIN input tokens/request | same | isolates the orientation saving from the clerk's spend |
| clerk calls per `record` | `wire_logs/clerk_trace.jsonl` `rounds`+`repair_rounds` | the cost thesis's own risk |
| refusals per record | `clerk_trace.jsonl` `refusals` | a clerk that cannot satisfy the validator |
| gaps per record | `clerk_trace.jsonl` `gaps` | prose the clerk could not ground |
| wall clock | `budget.json` / result events | the clerk adds a serial call per record |
| disposition | `report.md` frontmatter | agreement between arms, not correctness |
| document validity | `validate_companion` over `investigation.md` | a document that would not re-write |
| rows + fences landed | `scan_fences` / companion projection | did the record get RICHER or thinner |

## Decision criteria

**Proposed wins** if, over the scale-up:
- median total cost per run is **≥20% below** the current arm, AND
- every proposed run produces a parseable `report.md` with a disposition in the enum, AND
- `validate_companion` is clean on every proposed `investigation.md`, AND
- dispositions agree with the current arm on ≥ the same fixtures (no fixture where current is
  right-shaped and proposed is not), AND
- landed row count is not materially lower — the port must not buy its saving by recording less.

**Current is retained** if any of:
- cost is within ±10% (the port adds a role and a failure mode; parity is not worth it), OR
- any proposed run fails to close, or force-closes `unresolved` where current closed cleanly, OR
- clerk calls per `record` average >2 (the six-call budget is being spent, which is where the
  arithmetic saving goes), OR
- the proposed document lands materially fewer grounded rows for the same evidence.

**Abort early** if validation shows either arm cannot complete a run against the live stack —
that is an infrastructure result, not a comparison.

## Layout

```
experiments/clerk-996-live/
  plan.md            # this file
  variants/          # the two commit shas, and the env each arm runs under
  fixtures/          # pointers to defender/fixtures/v2-*
  runs/              # run ids: live-996-old-<fixture>-<n>, live-996-new-<fixture>-<n>
  analyze.py         # written before scale-up
  results/           # mid-run + final
```

Run-id convention follows the existing `live-867-old` / `live-867-new` precedent in
`$DEFENDER_RUNS_BASE`.

## Blocked on two things before any of this runs

1. **Levering up bills real money.** `infra/bin/up.sh` restores a CCX33 in `nbg1` at ~€74/mo
   gross, prorated — a few euros for an afternoon, but Hetzner bills for existence, not uptime,
   so the server must be levered back down (`infra/bin/down.sh`) or it keeps billing. Model
   spend is on top: ~30 scale-up runs against `glm-5.2` + `kimi-k2.6` + `kimi-k3`. Needs an
   explicit go-ahead, and someone has to own remembering the lever-down.

2. **The terraform state is not in this worktree.** `terraform.tfstate`, `terraform.tfvars` and
   `image.auto.tfvars` are gitignored and live in `/workspace/infra/`. This session is
   worktree-isolated at `/workspace/.claude/worktrees/996-clerk`. Running `bin/up.sh` from here
   would see empty state, no pinned snapshot and no SSH pubkey — and would create a **second,
   fresh** server rather than restoring snapshot `426757757`, which is exactly the
   duplicate-billing trap `infra/CLAUDE.md` warns about. The lever has to be pulled from
   `/workspace/infra`, by someone whose session may operate there.

Current stack state, for the record: no `hcloud_server` in state (firewall and SSH keys only),
and `/workspace/.ssh/config` parks the alias on `soc-playground.invalid` — the server is down
and the alias is failing closed, which is what `down.sh` leaves behind.
