# Ground truth — HYPOTHESIZE output for fixture alert

Hand-written reference shape for scoring arm outputs. Cut under the
**one-hop / lean-predictions** discipline of `docs/investigation-language.md`
§Hypothesis and `soc-agent/skills/investigate/SKILL.md` §HYPOTHESIZE. Do **not**
inherit the narrative shapes used by the current rule-5710 playbook —
those are the upstream defect this re-cut is correcting.

## Fixture recap

- Alert: wazuh-rule-5710, single attempt, 2026-04-18T14:22:17Z.
- Source: `10.30.18.42` (internal RFC1918, not in any sanctioned registry as far as CONTEXTUALIZE sees).
- Target: `app-web-07` (`10.30.12.88`).
- Attempted username: `root`.
- Ticket-context window shows no prior 5710 from this srcip in 4h, no 5501/5715 on target in 4h.
- Archetype scan: all four rule-5710 archetypes scored **weak** against this alert.

Anchor edge from prologue: `e-attempted-auth-01` — `attempted_auth` from `v-src-ip-10.30.18.42` to `v-dst-host-app-web-07`, identity `v-attempted-user-root`, outcome failed.

## Upstream enumeration (the one-hop parent step)

The anchor we attach upstream of is `v-src-ip-10.30.18.42` (the source endpoint), via the proposed edge `runs_on` (the parent process runs on that endpoint and originated the attempt). We vary the parent process's classification. Keep each hypothesis to **one predicted attribute** on that parent vertex.

Plausible classifications covering automated / human-authorized / human-unauthorized / adversarial:

| # | Name | Parent vertex classification | Coverage bucket |
|---|---|---|---|
| h-001 | `?sanctioned-automation` | `process, classification: sanctioned-automation` | automated (merges sanctioned-monitoring + scheduled-automation until evidence forces the split) |
| h-002 | `?operator-shell` | `process, classification: interactive-shell` | human-authorized (interactive) |
| h-003 | `?automation-misfire` | `process, classification: automation-with-stale-credential` | human-authorized (misconfig) |
| h-004 | `?adversary-controlled-source` | `process, classification: adversary-controlled` | adversarial (parent-origin) |

Plus a second-anchor adversarial hypothesis attached to a **hypothetical future edge**, per SKILL.md §HYPOTHESIZE Adversarial rule:

| # | Name | Attached to | Proposed edge | Coverage bucket |
|---|---|---|---|---|
| h-005 | `?compromise-followup` | hypothetical `e-future-success` in `[T, T+60s]` from `v-src-ip-10.30.18.42` to `v-dst-host-app-web-07` | `authenticated_as` (session → identity) | adversarial (downstream-success) |

**Why five and not three.** At HYPOTHESIZE time the discriminating question space has one axis on "what kind of upstream process drove this" (h-001/2/3/4) and an independent axis on "regardless of upstream, did a success follow the attempt" (h-005). These are orthogonal frontiers — h-005 can be live alongside any of h-001..h-004 and predicts a distinct observable. Merging h-005 into h-004 ("?adversary-controlled-followup") would be the narrative umbrella failure mode.

**Why not enumerate wordlist-vs-stuffing / monitoring-vs-scheduled at loop 1.** Those are sub-classifications of h-001 and h-004 respectively. The decomposition happens through `h-{parent}-{ordinal}` inside a lead's `new_hypotheses` once evidence confirms the parent — not upfront. Pre-decomposing them at loop 1 is exactly the discipline violation SKILL.md §Refinement calls out.

## Reference shape (lean, one-hop)

### h-001 `?sanctioned-automation`
- `attached_to_vertex`: `v-src-ip-10.30.18.42`
- `proposed_edge.relation`: `runs_on` (process → endpoint)
- `proposed_edge.parent_vertex`: `{type: process, classification: sanctioned-automation}`
- `predictions`:
  - p1: the `(srcip, srcuser, target) = (10.30.18.42, root, app-web-07)` triple is registered in some sanctioned-automation registry (approved-monitoring-sources OR scheduled-jobs) with an anchor result `confirmed`.
- `refutation_shape`:
  - r1: both sanctioned registries return `no match` for the triple.

### h-002 `?operator-shell`
- `attached_to_vertex`: `v-src-ip-10.30.18.42`
- `proposed_edge.relation`: `runs_on`
- `proposed_edge.parent_vertex`: `{type: process, classification: interactive-shell}`
- `predictions`:
  - p1: an authenticated interactive `session` vertex exists on `10.30.18.42` with an `authenticated_as → identity{kind: user}` edge active at T₀ − 60s to T₀.
- `refutation_shape`:
  - r1: no interactive session on 10.30.18.42 in the preceding 5-minute window.

### h-003 `?automation-misfire`
- `attached_to_vertex`: `v-src-ip-10.30.18.42`
- `proposed_edge.relation`: `runs_on`
- `proposed_edge.parent_vertex`: `{type: process, classification: automation-with-stale-credential}`
- `predictions`:
  - p1: a second `attempted_auth` edge from `10.30.18.42` to `app-web-07` appears in `[T₀, T₀ + 5min]` with a *different* `srcuser` that resolves to an authentication-success (the retry after the misfire).
- `refutation_shape`:
  - r1: the forward 5-minute window shows no follow-up auth event from this srcip, or only further `root` attempts with no username variation.

### h-004 `?adversary-controlled-source`
- `attached_to_vertex`: `v-src-ip-10.30.18.42`
- `proposed_edge.relation`: `runs_on`
- `proposed_edge.parent_vertex`: `{type: process, classification: adversary-controlled}`
- `predictions`:
  - p1: the upstream process has no sanctioning edge — neither registry membership (h-001's anchor) nor a preceding authenticated interactive session on 10.30.18.42 (h-002's preceding-session).
- `refutation_shape`:
  - r1: either h-001's registry match is confirmed, or h-002's preceding-session observation is confirmed. (This is the structural "defined by negation of siblings" shape — acceptable because the sanctioning-edge predicate is a single attribute of the parent vertex.)
- `concerns`:
  - defined by negation of h-001 and h-002; requires explicit confirmation of both negations to reach `--`, not just failure to observe one.

### h-005 `?compromise-followup` (future-edge adversarial)
- `attached_to_vertex`: a hypothetical edge `e-future-success` proposed upstream of the *target* endpoint in the forward window.
- `proposed_edge.relation`: `authenticated_as` (session → identity)
- `proposed_edge.parent_vertex`: `{type: session, classification: authenticated-session-from-source}`
- `predictions`:
  - p1: a rule-5501 or rule-5715 event with `srcip=10.30.18.42` on `app-web-07` appears in `[T₀, T₀ + 60s]`.
- `refutation_shape`:
  - r1: no success event from this srcip on this target in the forward 60-second window.

## Lead selection (ground truth)

**Dispatch mode: composite.** Same entity (`v-src-ip-10.30.18.42`) and same anchor time window. One dispatched subagent runs two leads side-by-side and returns a single evidence bundle:

- **`source-classification`** — queries the sanctioning registries (approved-monitoring-sources, scheduled-jobs) for the `(10.30.18.42, root, app-web-07)` triple. Directly tests h-001 p1. Refutation of h-001 is load-bearing for h-004.
- **`authentication-history`** — windowed query over `[T₀ − 5min, T₀ + 5min]` covering both directions. Tests h-002 p1 (preceding interactive session), h-003 p1 (forward retry with different user), h-005 p1 (forward 5501/5715).

**Why not single-lead.** No single measurement partitions all five hypotheses:
- `source-classification` alone partitions {h-001, ¬h-001} but leaves h-002/3/4/5 unresolved.
- `authentication-history` alone partitions {h-002, h-003, h-005} but cannot confirm sanctioning (the sanctioning registry is not in the auth-event stream).
- Together they discriminate the full set.

**Why not primary-plus-deferred.** h-005 must be tested regardless of h-001 outcome — the worst-case adversarial hypothesis cannot wait on a conditional branch. Running both now is not wasteful; each informs its own distinct frontier.

## Pitfalls (alert-specific, one per hypothesis)

- **h-001**: `root` is explicitly outside the sentinel list that the monitoring-probe archetype registry indexes; even if some wildcard entry covers the triple, confirm the registry truly authorizes `root` as the attempted username for this target — a loose "internal IP is in the registry somehow" read is insufficient for `++`.
- **h-002**: the absence of a *visible* interactive session ≠ absence of a session — shell-session audit coverage on 10.30.18.42 must be independently confirmed (data-source-debug) before treating the preceding-session refutation as load-bearing.
- **h-003**: `root` is not a plausible typo for a real username. The retry-with-different-user prediction is weak on its own; a confirmed forward-window success with a real operator username is needed to reach `+`, and even then it does not explain why `root` was attempted first.
- **h-004**: negation-defined hypotheses are easy to mistake as "confirmed by default" when siblings come back weak. Do not grade h-004 `+` or `++` until both the sanctioning-registry refutation and the preceding-session refutation are explicit — a partial-coverage auth-history query (e.g., missing shell-session stream) caps h-004 at null.
- **h-005**: the 4-hour backward-look from ticket-context does not substitute for the forward 60-second window. A missed forward success is the highest-severity failure mode for this alert; the forward query must be explicit and time-bounded, not inferred from "no recent successes."

## What is NOT in the ground truth

- No narrative classifications ("monitoring-probe", "brute-force campaign", "lateral movement from compromised host") — those are archetype labels or multi-hop stories, not one-hop parent classifications.
- No `?credential-guessing` seed from the current playbook — that name packs volume, wordlist-membership, and adversarial intent into a single label; its load-bearing content is covered by h-004 (upstream adversarial) and h-005 (forward success).
- No hypothesis conjunctions ("internal-source AND wordlist-username") — each claim should belong to exactly one hypothesis's single predicted attribute.
- No third+ prediction on any hypothesis.

## Scoring rubric for arm outputs

| Criterion | Weight | Pass condition |
|---|---|---|
| Each hypothesis names `attached_to_vertex` + proposed-edge relation + parent-vertex classification | high | structural match |
| ≤ 2 predictions per hypothesis, single attribute per prediction | high | count + single-attribute check |
| Classification coverage spans automated / human-authorized / human-unauthorized / upstream-adversarial / downstream-adversarial | high | at least one hypothesis per bucket |
| Adversarial hypothesis on a future edge (h-005 shape) present | high | present / absent |
| Refutation shape stated and observable | medium | present per hypothesis |
| Lead selection discriminates all live hypotheses (single / composite justified) | medium | composite expected given h-005 is orthogonal |
| Per-hypothesis alert-specific pitfall | medium | present per hypothesis |
| No narrative umbrellas, no multi-hop ancestry packed into a label | high | zero violations |
| Sub-classifications (monitoring-vs-scheduled, wordlist-vs-stuffing) are **not** pre-decomposed at loop 1 | medium | zero violations |

An arm output that matches h-001/2/3/4/5 structurally (even with different names, as long as one-hop shape + leanness + coverage hold) is a pass. An arm that re-emits the playbook's narrative seeds verbatim fails the "no narrative umbrellas" criterion regardless of polish.
