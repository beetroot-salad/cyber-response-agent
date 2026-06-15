# Production arm-A variance study + discipline levers

**Question.** With arm A shipped (reframed `actor.md`, `ssh-brute-force-timing-mimicry`
retired), how consistent is the blind actor across repeated runs on one pinned input,
and what variance lives in the load-bearing dimensions (technique scope, grounding,
leakage)? Then: do three targeted prompt fixes reduce it?

**Method.** `run_variance.py` over `fixtures/sshd-gabe-live`, N=4, seed pinned to
`0x5EED5588` so archetype (`external`) and the 12-technique MITRE menu are identical
across runs (`runs-variance/pinned-{archetype,menu}.txt`) — the only divergence is model
sampling. Two passes, varied by checking out a different `actor.md` commit:

- **baseline** — arm A, reframe only (`a13ca0c`); full actor→oracle→judge (outcomes).
- **revised** — arm A + levers 1–3 (`bcdc2c2`); actor-only (story-level discipline).

N=4, single menu — a **direction signal, not a measurement**. Run on the subscription
credential (the configured `ANTHROPIC_API_KEY` was out of credit at the time).

## Baseline findings (reframe only)

| run | techniques | bytes | outcome |
|---|---|---|---|
| 1 | 9 | 7118 | survived |
| 2 | 5 | 5612 | survived |
| 3 | 10 | 7602 | survived |
| 4 | 9 | 8125 | **caught** |

**Convergent (good):** all four chose the same load-bearing spine — T1195.002 supply-chain
implant on the dev host `172.18.0.25` → harvest `dev.gabe`'s password → SSH to `jump-box-1`
producing the failure→success alert → post-auth work → encrypted C2. All four correctly
matched the **human basin** (failures paced tens-of-seconds-to-a-minute apart, realistic
session) with the stale timing lesson removed — none anchored to its old "8–20s" prior.
Grounding was clean (real IPs/accounts/timestamps; placeholders for ungrounded entities).

**The outcome-deciding variance was elaborateness → ungrounded collateral on queried
surfaces.** run4 (caught) was refuted not on its persistence act but on collateral the
blind actor guessed wrong about (`runs-variance/baseline/run4/judge_findings.yaml`):

- **port-443 tunnel** claimed to "blend into HTTPS baseline" — actual Zeek for jump-box-1
  showed only ports 9200 and 22, *zero* 443; the tunnel would be the only one, maximally
  conspicuous.
- **sudo under `dev.gabe`** claimed to blend with `svc.config-mgmt` — the sudo log held 49
  events, all `sre.alice`, *no* `dev.*` account; any `dev.gabe` sudo entry stands out.

run1 also put PAM on the watched host yet survived — it didn't commit those checkable
baseline-composition claims. So the lever is: **the more techniques, the more collateral
claims a blind actor must invent, the higher the catch rate.** The grounded judge (the #275
zipper) did exactly its job here — every catch citation is a real payload.

Two systematic discipline gaps (low variance, present in most/all runs): defender-surface
**leakage in Section 2** ("the 7-day baseline query shows…", "the sudo-commands lead never
scopes to dev.gabe") despite the abstract prohibition at `actor.md` line 7; and
self-refuting **already-captured log trims** (concede Elastic has the events, trim the
on-host log anyway).

## Levers (shipped in `bcdc2c2`, each as instruction + grounded example)

1. **Minimal technique spine** (mitre_menu rule) — minimum subset that produces the alerted
   artifact; every extra technique is a refutation surface.
2. **No ungrounded baseline-composition claims** (fact-fidelity) — "443 is normal here" /
   "this account routinely sudos" are grounded facts the judge checks, not free stealth.
3. **Section-2 anti-leakage example** (Bypass spec) — bad→good example naming the exact
   leak pattern, since the line-7 rule wasn't biting in the Bypass section.

## Revised findings (arm A + levers), before → after

| dimension | baseline | revised | effect |
|---|---|---|---|
| technique count per run | 9 / 5 / 10 / 9 | **4 / 2 / 3 / 3** | mean 8.25→3, spread 5→2 |
| ungrounded baseline-composition claims | 4 | **0** | eliminated |
| Section-2 *named-lead* leakage | 3 | **1** | named leaks gone; mild generic residual |

Stories stayed **coherent, not degenerate**: every revised run kept the T1195.002
initial-access spine, grounded its entities, and matched the human basin; run1 still reached
4 techniques where warranted (not flooring to the minimum). No revised run reproduced run4's
watched-host collateral pattern.

**Lever 3 is partial.** The loud named-lead leaks are gone, but a milder generic framing
persists (run1: "every inspection layer the defender queries for this alert class"; a couple
"the lead sequence does not query that envelope" phrasings). Closing it would need a sharper
rule than the example added.

## Caveats / open

- **No revised outcomes** — actor-only pass, so "tighter discipline" is shown, not "higher
  survival." The run4 logic implies minimal-spine should survive at least as well; confirm
  with a judged A/B.
- N=4, one pinned menu/archetype — direction signal. A controlled multi-seed A/B (baseline
  vs revised, both judged) is the proper validation.
- Lever 2's watched-host sub-case (where persistence lives) is better encoded as a
  `lessons-environment` fact ("jump-box-1 is Falco/auth-monitored; the dev tier is not")
  than in `actor.md` — the substrate-gap encoding #296 recommended.

## Reproduce

```bash
# baseline (reframe only): git checkout a13ca0c -- defender/learning/actor.md
env -u ANTHROPIC_API_KEY python3 experiments/actor-basin-276/run_variance.py baseline
# revised (arm A + levers): on bcdc2c2 / current
env -u ANTHROPIC_API_KEY python3 experiments/actor-basin-276/run_variance.py revised --actor-only
```
