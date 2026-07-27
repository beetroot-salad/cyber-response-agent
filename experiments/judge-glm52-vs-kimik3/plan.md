# Judge model A/B — GLM 5.2 vs Kimi K3

## Question

**Engineering** — should the judge stage move off GLM 5.2 onto Kimi K3, and what does that
cost? The judge is the loop's ground truth (`judge_equivalence.py:5` — its `outcome` drives
FN/FP accounting and its `defender_findings` become the lessons the author trains on), so it
is the highest-leverage stage to upgrade and the one where a regression is most expensive.

Two sub-questions, deliberately separated because the harness answers only the second:

1. **Cost** — GLM 5.2 vs K3 per judge invocation, at real token counts.
2. **Quality direction** — is K3's verdict *better*, not merely *different*.

## The metric problem (read before interpreting any output)

`run_judge_ab.py` scores **agreement with the reference**, and `render_report` prints
"NOT yet equivalent" whenever there are `caught↔survived` / `refuted↔survived` flips. That
gate was built for the Sonnet→GLM migration — a cost-down move where *no behaviour change*
was success. It is the wrong gate here: if K3 is genuinely the stronger reasoner it should
disagree with GLM 5.2 precisely on the hard cases, and this harness scores that as failure.
Zero flips would mean the port bought nothing.

So the run is restructured as **three-way agreement against a trusted third reference**
rather than head-to-head:

```
reference  = claude-sonnet-4-6  (the harness's shipped --ref-model default; the originally
                                 proven judge, displaced by GLM on cost, not on quality)
candidate A = glm-5.2      @ medium   (incumbent — the regression arm)
candidate B = kimi-k3      @ medium   (proposed)
```

Whichever candidate agrees *more* with Sonnet — on `outcome_match` and on the flip axis — is
the better judge. This reuses the harness exactly as designed (agreement-with-a-trusted-
reference) and needs no new truth oracle, which `judge_equivalence.py:29` is explicit does
not exist for a synthetic encounter.

Sonnet 4.6 is a defensible-but-imperfect adjudicator: it is the proven incumbent, not
ground truth. If the two candidates split close to the noise floor, escalate the
adjudicator to `claude-opus-5` over the same frozen set rather than calling the result.

## Variants

One variable changes: the judge model. Effort held at `medium` (the current
`JUDGE_EFFORT` / `BENIGN_JUDGE_EFFORT` default) for both arms.

### current (regression arm)

```
--ref-model claude-sonnet-4-6 --ref-effort low
--cand-model glm-5.2 --cand-effort medium
```

### proposed

```
--ref-model claude-sonnet-4-6 --ref-effort low
--cand-model kimi-k3 --cand-effort medium
```

### Enabling changes (not part of the measured variable)

`kimi-k3` is reachable — `accounts/fireworks/models/kimi-k3` returns HTTP 200 under the
repo's `FIREWORKS_API_KEY` — but is absent from the alias map and the pricing table. Both
need a one-line addition before the run:

```diff
 # defender/runtime/providers/__init__.py
         "kimi-k2.6": "accounts/fireworks/models/kimi-k2p6",
         "kimi-k2p6": "accounts/fireworks/models/kimi-k2p6",
+        "kimi-k3":   "accounts/fireworks/models/kimi-k3",
```

```diff
 # defender/scripts/pricing.py
     "kimi-k2.6":         {"in": 0.6, "out":  3.0, "cache_w": 0.60, "cache_r": 0.60},
+    "kimi-k3":           {"in": 3.0, "out": 15.0, "cache_w": 3.00, "cache_r": 0.30},

 def model_key(model: str) -> str:
+    if "kimi-k3" in m:
+        return "kimi-k3"
     if "kimi" in m:
         return "kimi-k2.6"
```

The `kimi-k3` branch **must precede** the `kimi` branch or every K3 run bills at K2.6's
$0.60/$3.00 and the cost answer is wrong by ~5×.

> **The K3 price is not yet confirmed.** Fireworks' `/v1/models` omits K3 entirely (returns
> 6 curated models), and their two web surfaces disagree: the model library lists a 1M-context
> "Kimi K3 (New)" at $3.00/$15.00 and a 262k "Kimi K3" at $0.95/$4.00 — the latter byte-identical
> to K2.6's row, which is what a page-template artifact looks like. The table above uses the
> conservative $3/$15. `analyze.py` reports cost under **both** hypotheses from the same token
> counts; the billing dashboard after the run settles it.

## Fixtures

Fresh alerts from the live playground-v2 lab, per your instruction — the existing
`experiments/actor-basin-276/runs/*` snapshots carry `actor_story.md` +
`projected_telemetry.yaml` but predate the current judge wiring and are not shape-current.

Production procedure (once, then frozen):

1. `infra/bin/up.sh` — restore the Hetzner CCX33 from the latest lever-down snapshot
   (~€74/mo gross while up; **Hetzner bills for existence, not uptime** — only `bin/down.sh`
   stops the bill, per `infra/CLAUDE.md`).
2. `defender/run.py` against the live lab per fresh alert → run dir.
3. LEARN each once → `actor_story.md` + `projected_telemetry.yaml` (the judge inputs;
   `build_judge_invocation` is a pure function of them).
4. Snapshot each into `fixtures/case-NNN/` as `{meta.json, run_dir/, actor_story.md,
   projected_telemetry.yaml}`.

**One alert is not enough.** `outcome_match` over n=1 is 0% or 100% — it cannot be compared
to a self-consistency floor, so the run would be uninterpretable. The judge is also two
stages, not one: `ADVERSARIAL_WIRING` and `BENIGN_WIRING` (`directions.py:39-43`) drive FN
and FP accounting respectively and are separately configured. Proposed set:

| case | direction | exercises |
|---|---|---|
| 001–004 | adversarial | FN axis — `caught↔survived`; the flip axis that gates the port |
| 005–008 | benign | FP axis — `refuted↔survived`; guards against a stronger reasoner over-calling |

8 cases, balanced across both directions. Fewer than 4 per direction and the flip count is
noise.

## Trials

**Validation pass:** 1 case per direction (2 cases), all three configs, to confirm the
wiring works end-to-end — K3 parses under the judge's structured-output contract
(`cand_parse_failure_rate` is a first-class metric precisely because a new model can fail
here), the alias resolves, traces land, `analyze.py` runs.

**Scale-up:** N=8 cases × 3 configs. The driver runs the reference **twice** (`ref-a`,
`ref-b`) to establish the self-consistency floor, so a single invocation is 3 passes over
the case set; two invocations (one per candidate) = 6 passes, of which 2 are a redundant
Sonnet rep. At 8 cases that is 48 judge calls — cheap enough to accept the redundancy
rather than fork the driver.

Below the ≥10-trials-per-arm threshold that mandates mid-run batching, but the validation
pass serves the same function: stop and read it before committing the remaining 6 cases.

**Analysis script:** `experiments/judge-glm52-vs-kimik3/analyze.py`, written before
scale-up. Walks `runs/*/judge_trace.jsonl` for per-config token usage, applies
`defender.scripts.pricing.usage_cost` under both K3 price hypotheses, and emits: cost per
judge invocation per arm, `outcome_match` vs the Sonnet reference per arm, flip lists, and
`findings_agreement`. Ranking by per-occurrence mean with `n` shown as support.

## Decision criteria

**Port the judge to K3 if:**
- K3's `outcome_match` against the Sonnet reference **exceeds** GLM 5.2's, by more than the
  same-config self-consistency floor's margin — i.e. the gap is larger than the judge's own
  stochastic noise; **and**
- K3's flip list against Sonnet is a **subset** of GLM's, or smaller — it is not introducing
  new disagreement on the FN/FP axis; **and**
- `cand_parse_failure_rate` is 0% — a judge that fails the structured-output contract
  poisons labels regardless of reasoning quality; **and**
- `cand_punt_rate` is not above GLM's — a stronger model that punts more is worse here.

**Retain GLM 5.2 if:**
- the two candidates' `outcome_match` differ by less than the noise floor — K3 is not
  measurably a better judge, and at $3/$15 it is a 2.1×/3.4× cost increase for nothing; **or**
- K3 shows any parse failures; **or**
- K3 flips cases *away* from Sonnet that GLM 5.2 gets right.

**Cost is reported, not gating.** The judge is 2 calls per cycle against a per-lead oracle
at concurrency 8, so even the $3/$15 hypothesis is a small absolute delta — but it is
reported per-invocation and per-cycle so the trade is explicit. If the $0.95/$4.00 SKU is
real, K3 is *cheaper than GLM 5.2 on input* and the cost argument disappears entirely.

**Escalation:** if `outcome_match` splits within the floor, re-run the adjudicator as
`claude-opus-5` over the same frozen set before deciding.

## Layout

```
experiments/judge-glm52-vs-kimik3/
  plan.md          # this file
  variants/        # resolved judge-settings JSON per arm
  fixtures/        # case-001..008 frozen snapshots
  runs/            # per-config judge output + traces
  analyze.py       # written before scale-up
  results/         # validation + final analysis
```

## Open items before launch

1. **VPS lever-up is billable and not auto-reversed** — `bin/up.sh` starts a ~€74/mo meter
   that only `bin/down.sh` stops. Confirm before I run it, and confirm who levers down.
2. **8 cases, or fewer?** More alerts = more lab time and more metered calls. 8 is my floor
   for an interpretable flip count; say if you want it tighter and I will state the reduced
   confidence rather than pretend the number holds.
3. **Adjudicator** — Sonnet 4.6 as shipped default, or go straight to `claude-opus-5` for a
   stronger reference at higher per-case cost.

---

## Decisions taken (supersede the sections above)

- **Scale: n=2, validation only** — 1 adversarial + 1 benign fresh alert. No statistical
  claim; the run proves the wiring (K3 parses under the judge's structured-output contract,
  alias resolves, traces land) and yields real token counts for the cost answer.
- **Adjudication: Opus via Claude Code headless**, not an in-harness reference arm. The
  harness runs `--ref-model glm-5.2 --cand-model kimi-k3` (giving GLM's self-consistency
  floor, outcome_match, flips, findings_agreement, parse-failure rate); Opus then reads the
  paired verdict text and judges which reasoning is better. At n=2 this is strictly more
  informative than `outcome_match`, which can only be 0%, 50% or 100%.

### Status

| Step | State |
|---|---|
| `kimi-k3` alias → `accounts/fireworks/models/kimi-k3` | **done**, verified |
| `pricing.py` k3 entry + precedence before generic `kimi` | **done**, verified incl. `fireworks:` passthrough |
| VPS lever-up | **blocked** — see below |
| Fresh alerts → frozen cases | blocked on lever-up |
| Judge A/B run | blocked on fixtures |
| Opus headless adjudication | blocked on run |

### Lever-up blocker

`infra/bin/up.sh` cannot run as-is. Four gaps, three trivially recoverable, one needing a
decision:

1. **No terraform state** (`terraform.tfstate` gitignored, absent everywhere on disk) while
   `soc-playground-edge` (fw 10874072), `soc-playground-admin` (key 111179323) and
   `soc-playground-devcontainer` (key 111179518) all exist in Hetzner → `apply` would hit
   three name collisions. Fix: `terraform import` ×3.
2. **`terraform.tfvars` missing** — `ssh_public_key` and `ssh_source_cidrs` have no defaults.
   Recoverable: the 9 `/32` SSH CIDRs are readable off the live firewall, the admin pubkey
   off the Hetzner key.
3. **`/workspace/.ssh/devcontainer_ed25519.pub` missing** — `devcontainer_ssh_public_key_path`
   defaults to it and `file()` will error. Recoverable from Hetzner key 111179518.
4. **The only SSH private key on disk does not match either configured key.**
   `/workspace/.ssh/soc-playground` fingerprints to `65:1c:50:...:ce:e3` =
   `claude-soc-playground-1` (113740850), which is **not declared in the terraform config**.
   `server.tf` attaches only `hcloud_ssh_key.main` + `.devcontainer` — private halves we do
   not hold. `ssh_keys` is create-time-only, so this cannot be fixed after boot without
   recreating the server.

**Nothing billable was created.** Both failure paths fail closed: unset required vars abort
`apply` before any resource, and the server depends on the colliding keys/firewall so those
error first.
