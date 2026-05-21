# advisory-ab pilot — RESULTS

**Date:** 2026-05-21
**Branch:** `advisory-ab-harness`
**Scope:** Does PLAN-time Class-8 advisory retrieval (`lead_branch_effects`)
help defender investigations? Compare four caller configurations on a
matched 5710 signature: baseline, Haiku subagent (discretion),
Sonnet inline (discretion), Sonnet inline (always-fire).

## TL;DR

**Arm C (Sonnet inline with discretion) is the winning configuration.**
Matches baseline accuracy (6/6) at ~15% lower cost (-$0.20/run on
average). Arms B (Haiku subagent) and D (always-fire) both *hurt*
accuracy (3/6 each) — the failure modes differ but both reduce to
"advisory inputs perturb the agent off-baseline in directional-wrong
ways."

## Variants

| arm | surface | discretion | how advisory is fetched |
|---|---|---|---|
| A | none | — | not fetched |
| B | Haiku subagent (`defender/skills/advisory/SKILL.md`) | yes | main agent dispatches `Task(model=haiku)` when uncertain |
| C | main agent inline Bash | yes | main agent runs `python3 -m defender.scripts.invlang.cli ... advisory ...` when uncertain |
| D | main agent inline Bash | **no** (always-fire) | called every PLAN turn after `:H` exists |

Arm overlays: `arms/{a,b,c,d}.md`. The advisory CLI returns the same
markdown across B/C/D — only construction differs.

## Cases (synthetic, both 5710)

- **POS-1** — `apt-mirror` from undocumented `172.22.0.42`. Two plausible
  explanations (legacy ops automation missing CMDB entry / internal
  scanner). Gold: `inconclusive`.
- **NEG-1** — `nagios` from `172.22.0.10`, the recurring corpus pattern.
  CMDB+IAM resolves cleanly. Gold: `malicious`.

Corpus: `/tmp/defender-runs/` (~30 prior 5710 investigations from
unrelated work). Synthetic alerts are net-new entities, not in the
corpus.

## Outcome (N=3 trials per cell)

| arm | POS-1 | NEG-1 | total |
|---|---|---|---|
| **A** baseline | 3/3 ✓ | 3/3 ✓ | **6/6** |
| B Haiku subagent | 2/3 | 1/3 | 3/6 |
| **C** Sonnet inline | 3/3 ✓ | 3/3 ✓ | **6/6** |
| D always-fire | 2/3 | 1/3 | 3/6 |

## Cost — Δ vs A per run

| arm | POS-1 | NEG-1 |
|---|---|---|
| B | -$0.09 | -$0.15 |
| **C** | **-$0.22** | **-$0.20** |
| D | **+$0.18** | -$0.29 |

Cost comparison is against total investigation cost (the load-bearing
denominator from the 2026-05-20 discussion): cheaper means the agent
finished sooner, *not* that the advisory call itself was cheap. Arm D's
+$0.18 on POS-1 is the context-bloat compounding effect predicted —
forcing advisory calls on cases that don't need them grows the agent's
working context across subsequent PLAN turns.

## Failure-mode signature (B and D mismatches)

The losing arms fail in a **consistent direction**:

| case | gold | mismatched arm dispositions |
|---|---|---|
| POS-1 wrongs (B×1, D×1) | inconclusive | all 2: **malicious** (over-commit) |
| NEG-1 wrongs (B×2, D×2) | malicious | 4× `inconclusive` or `benign` (under-commit) |

Advisory-when-it-misfires shifts the agent off-baseline in *both*
directions depending on the case shape:
- On ambiguous-but-novel POS-1, advisory provides a precedent hint that
  the agent treats as a signal to commit (e.g. "cmdb-source-lookup
  historically refutes `?monitoring-probe`" + observed CMDB miss →
  agent commits to `malicious`).
- On clear-but-routine NEG-1, advisory introduces precedent leads that
  shift the agent away from the clean CMDB+IAM resolution toward
  qualified language.

Arm C is robust to both effects on this fixture set — the discretion
mechanism filters out spurious dispatches that B (and necessarily D)
include.

## Why arm B fails: Haiku subagent goes off-protocol

The Haiku subagent's instructions
(`defender/skills/advisory/SKILL.md`) say:

> You do not investigate. You do not interpret. You translate the
> caller's dispatch YAML into one CLI invocation, run it, and return
> the rendered markdown block verbatim.

Behavior observed in the pilot tool-traces:
- Some trials: Haiku reads `SKILL.md`, then reads `advisory.py` source
  code, then **fabricates a "loud-empty" response by reasoning about
  what the CLI would return** — without ever running the Bash command.
- Other trials: Haiku runs the CLI correctly and returns its output.

The hallucinated runs are accuracy disasters because the main agent
proceeds believing it received precedent data when none was actually
fetched. Replacing Haiku with a deterministic Python wrapper (no LLM
in the call construction step) would eliminate this — or at minimum,
re-prompting Haiku with explicit "do not Read any file other than the
SKILL; only call Bash" guardrails.

## Invocation discipline

| arm | POS calls/loop | NEG calls/loop |
|---|---|---|
| B (Haiku) | 0.83 | 1.00 |
| C (inline) | 1.33 | 2.00 |

C dispatches advisory more often than B (multiple times per loop in
some NEG runs — likely re-querying with refined frontiers). The
discretion arms are not gating advisory aggressively; arm A's perfect
score suggests advisory's marginal value is low even when fetched
correctly. C's win is the cost savings that come with *being efficient
about which leads to author* given the precedent hints.

## Open questions / caveats

1. **N=3 is small.** A and C each landed 6/6. With more trials, both
   could regress. The B/D 3/6 pattern is more robust against trial
   variance because all four mismatches share the same directional
   bias.
2. **Both cases land for baseline A.** Arm A's 6/6 means the pilot
   never exercised the scenario where advisory *recovers* a failure.
   The interesting next step is selecting cases where A fails — then
   testing whether C lifts accuracy, not just trims cost.
3. **Hypothesis-name vocabulary mismatch.** The corpus uses hypothesis
   names from older runs (`?monitoring-probe`, `?brute-force-or-scan`)
   that don't always match the new agent's names. Class-8's
   frontier-matched view returns less than the unfiltered view; the
   agents often fell back to "top recurring leads" output. A future
   pass should either normalize hypothesis names across the corpus or
   relax Class-8 frontier matching to fuzzy.
4. **Wazuh fixture gap.** Synthetic source IPs aren't in the Wazuh
   index, so `auth-events` queries return empty. The agent observed
   this and worked around it (treating empty-as-signal), but it likely
   contributed variance — particularly to the POS-1 over-commit
   failures, where the agent escalated "undocumented + unauthorized +
   no auth history" to malicious.
5. **B vs C cost prediction.** Hypothesis was Haiku-cheaper than
   Sonnet-inline. Pilot result: **C is cheaper than B** by $0.13/run on
   POS. The Sonnet-inline arm saves more because Sonnet decides
   precisely *when* to call (rather than always dispatching Task and
   eating subagent overhead). Haiku's terseness doesn't dominate.

## Cost of the pilot

- Pilot v3 (final): 24 runs × ~$1.20 avg = **~$30**
- Pilot v1+v2 (invalidated by harness leak + CLI bug): ~$25
- Total: ~$55, ~6 hours wall

## Pilot history & what was learned

The path to a working pilot exposed three categories of bug:

1. **Ground-truth leakage** (pilot v1): the harness lived at
   `defender/learning/eval/advisory_ab/`, inside the agent's
   `Read(/workspace/defender/**)` allow scope. Agents in *every* arm
   read `cases.json` (gold labels) and `fixtures/POS-1/README.md`
   ("advisory should surface wazuh-auth-pattern"). All results
   invalidated. Fix: move the harness to `experiments/advisory-ab/`
   (outside `defender/`).
2. **CLI invocation wrong** (pilot v2): arm overlays specified `cli
   advisory <corpus>` but the actual signature is `cli <corpus>
   advisory`. Every arm-C/D CLI call returned exit code 2. Arm B's
   Haiku subagent meanwhile hallucinated its result. Results
   invalidated. Fix: corrected arm prompts + advisory SKILL.md.
3. **Detector regex broken** (pilot v2 to v3): originally checked
   `ev.type == 'tool_use'` but stream-json wraps tool_use inside
   `assistant.message.content[]`. Then on the v3 fix, the regex still
   looked for `invlang.cli advisory` substring which didn't match the
   new arg order. Fix: traverse the actual event structure; match both
   orderings defensively.

The contamination findings are themselves useful — surfacing a real
risk for any defender experiment that lives inside `defender/` and
runs the agent with broad read permissions.

## Recommendations

1. **Ship arm C (Sonnet inline with discretion) as the default advisory
   wiring.** Matches accuracy, saves ~15% on cost in this fixture.
2. **Do not ship arm B as designed.** Either replace the Haiku subagent
   with a deterministic Python wrapper (`subprocess.run` from a
   harness-side tool), or significantly tighten its SKILL to forbid
   reading source code.
3. **Do not ship arm D.** Always-on is strictly dominated by C on
   accuracy and worse on cost in the case it's meant to anchor (POS-1
   needed advisory; advisory always-fire still mis-disposed it).
4. **Next experiment**: pick 4-8 cases *where baseline A fails* and
   measure whether C *recovers* those. This pilot's matched-A-and-C
   result tells us "advisory doesn't hurt"; the value-add story
   requires cases where A falls short.

## Artifacts

- Per-run metrics: `experiments/advisory-ab/results/20260520T204848Z/{arm}-{case}-t{N}.json`
- Synthetic fixtures: `experiments/advisory-ab/fixtures/{POS-1,NEG-1}/`
- Per-arm overlays: `experiments/advisory-ab/arms/{a,b,c,d}.md`
- Harness: `experiments/advisory-ab/{run,score}.py`, `cases.json`
- Advisory subagent SKILL: `defender/skills/advisory/SKILL.md`
- Raw run dirs (`/tmp/defender-runs/advisory-ab-*`): 24 dirs totaling
  ~13 GB — not committed; preserved on local disk for post-hoc
  analysis. Safe to delete after writeup review.
