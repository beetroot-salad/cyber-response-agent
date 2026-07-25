# Oracle telemetry fidelity — sanity check results

**Date:** 2026-07-25 · **Env:** playground-v2 levered up from snapshot `409583061`
(2026-07-17) on a fresh Hetzner ccx33.
**Verdict: the oracle is directionally sound — not off.** 7/9 leads agree on
category; both event leads are grounded field-for-field with zero wrong concrete
values; all six state/lookup leads are correctly empty; no false suppression.
The two divergences share one explainable, disposition-neutral cause.

## What was compared

The oracle is normally *counterfactual* — the actor's story never happened, so
there is nothing to check it against. This test removes that obstacle by feeding
the production oracle a **true** story (an attack we actually fired) with every
other input held at production shape. A divergence is therefore oracle
translation error, not story error.

- **Attack (ground truth):** `ssh-brute-force-canary`, seed 42 —
  `office-ws-1` (172.18.0.15) → `canary-1` (172.18.0.9), 8 bursts of root
  password guesses over ~3 min (07:45:35–07:48:39Z). Manifest:
  `fixtures/attack-meta.json`. It produced 96 sshd failures and fired
  `v2-sshd-failed-auth-burst`.
- **Alert → defender run:** the real alert (`fixtures/alert.json`) run through
  `defender/run.py` (glm-5.2), yielding **9 leads across 5 sources**
  (elastic sshd-auth, elastic zeek, cmdb, identity, threat-intel, change-mgmt).
  Disposition: `malicious` (correct).
- **Oracle:** the unmodified production path
  (`invoke_oracle(run_dir, ground_truth_story, …, oracle_fn=_run_oracle_pydantic)`)
  over those 9 leads — same prompt, model, effort, per-lead user-message
  assembly, and scrubbed sample skeleton as production. Output:
  `runs/oracle_projection.yaml`.
- **Baseline recovery:** the oracle emits a *signed diff over baseline*; actuals
  are `baseline + delta`. The distinguishing rows were confirmed absent from
  three shape-matched control windows (same clock, prior Saturdays + a pre-attack
  window today), so `+event` is earned, not baseline coincidence.

## Scorecard (`results/scorecard.txt`)

Scored at the **per-query grain** (where the 4-way category is well-defined)
then aggregated to the lead as the strongest of its queries
(`+event > +noise > 0`). Full per-query breakdown: `results/scorecard.txt`.

| lead | source | predicted | actual (agg) | lead shape | |
|---|---|---|---|---|---|
| l-001 | elastic sshd-auth | `+event` | `+event` | heterogeneous | ✅ |
| l-002 | elastic sshd-auth | `0` | `+event` | heterogeneous | ➖ diverge |
| l-003 | cmdb | `0` | `0` | uniform | ✅ |
| l-004 | elastic zeek | `+event` | `+event` | heterogeneous | ✅ |
| l-005 | threat-intel | `0` | `0` | uniform | ✅ |
| l-006 | elastic sshd-auth | `+noise` | `+event` | heterogeneous | ➖ diverge |
| l-007 | cmdb | `0` | `0` | uniform | ✅ |
| l-008 | identity | `0` | `0` | uniform | ✅ |
| l-009 | change-mgmt | `0` | `0` | uniform | ✅ |

**Category agreement: 7/9.** ("Heterogeneous" = the lead's queries do not all
fall in one category; see the divergence analysis below.)

### Distinguishability (earns the `+event` calls)

canary-1 failures from 172.18.0.15: **attack window = 96**, C1-today-pre = 0,
C2 (−14d) = 0, C3 (−21d) = 0. The l-004 zeek pair 172.18.0.15→172.18.0.9:22 =
96 docs in-window (48 `zeek.connection` + 48 `zeek.ssh`), 0 in control.

### Field grounding on the event leads — zero wrong concrete values

- **l-001** (`+event`): `source.ip=172.18.0.15` ✓, `user.name=root` ✓,
  `host.name=canary-1` ✓, `event.outcome=failure` ✓,
  `sample_message="Failed password for root from 172.18.0.15 port <port> ssh2"` ✓
  (matches the real OpenSSH line). Counts / exact times / port were
  `<placeholders>` — the story didn't state them, so per the prompt they are
  *unknown*, not wrong.
- **l-004** (`+event`): `source.ip=172.18.0.15` ✓, `destination.ip=172.18.0.9` ✓
  (correctly canary-1, not the source), `destination.port=22` ✓,
  `data_stream.dataset=zeek.ssh` ✓ (48 such docs exist in-window). SSH
  client/server versions and the exact time were placeholders.

Every concrete value the oracle committed to is correct. No `<suppressed:…>`
was emitted anywhere, and no actual stream went dark — so the prompt's
most-dangerous error (turning silence into a false detection) did not occur.

## The two divergences — neither is a wrong assertion

First, the distinction that matters. The oracle could err two ways:
**a wrong assertion** (predict a false entity, invent an event, or emit
`<suppressed:…>` on a live stream — the dangerous errors), or
**a category disagreement** (the 4-way bucket is off). **Zero wrong assertions
occurred.** Both divergences are category disagreements, and both are on leads
the per-query breakdown flags as **heterogeneous** — the lead bundles queries
that genuinely fall in *different* categories, so no single lead-level label the
oracle emits can be fully "right."

### What the per-query view shows

Four of the nine leads are heterogeneous (l-001, l-002, l-004, l-006). The
oracle got **two of the four** exactly right (l-001, l-004) and diverged on the
other two — and the difference is not whether it *saw* the failure burst (it did:
it emits the burst on l-001 and the connection on l-004). The difference is the
**lead's framing** (`what_to_summarize`), which the oracle scopes its output to:

| lead | framing | oracle emitted | why |
|---|---|---|---|
| l-001 | "extract the **failures**" | `+event` ✅ | framing *is* the burst |
| l-004 | "**identify** the host / its conns" | `+event` ✅ | neutral framing → emits the distinguishable connection |
| l-002 | "did any login **succeed**?" | `0` ➖ | framing presupposes a success that didn't happen → Example A → `[]` |
| l-006 | "establish the source's **baseline**" | `+noise` ➖ | framing says *baseline* → emits the source's routine, not the burst |

So the behavior is coherent, not blind: the oracle emits the attack delta under
leads whose *purpose* is that delta (or is neutral), and declines to re-emit it
under a lead whose stated purpose is a different question. Concretely:

- **l-002** — `seq0` (success-after-failure alert) truly returned **0 rows**;
  `seq1` (the wide sshd-auth template) carries the failure burst. The oracle
  answered the lead's actual question ("any success?" → no → `[]`) — textbook
  Example A — and did not re-surface the failures that `seq1`'s envelope
  incidentally includes.
- **l-006** — 7 queries, all filtering `source.ip=172.18.0.15`: three pre-attack
  windows (empty — the source *was* silent on canary), one all-time query
  showing the source's **routine** logins to web-1/web-2 (real baseline noise),
  and three attack-window queries carrying the **burst**. The lead simultaneously
  earns `0`, `+noise`, *and* `+event`. The oracle picked `+noise`.

Neither divergence loses the attack: the burst is already emitted, correctly and
distinguishably, on l-001 and l-004, and the per-lead projections are **pooled**
before the judge consumes them — so a redundant omission under a second lead has
no downstream effect on disposition.

### A note on the scoring itself (honesty about the measurement)

Whether l-002/l-006's "actual" is `+event` is a *scoring choice*, not a fact
handed down: it depends on scoring the lead's envelope literally rather than by
its stated intent. An earlier lead-grain version of `analyze.py` even mislabeled
l-006 as `0` — a heuristic artifact (its attack rows are grouped by
`host.name/auth_method`, dropping the `source.ip` column the heuristic keyed on).
Moving to per-query scoring fixed that and made the heterogeneity explicit. The
weakest part of this measurement is exactly these two labels; the strongest
(l-001/l-004 field grounding, the six `0` state leads) is not in doubt.

## Verdict against the pre-registered criteria

- **Sound (met):** category agreement on 7/9 ≥ 3, *including* the primary
  `+event` lead (l-001), **and** zero wrong concrete field values on the
  `+event` leads. ✅
- **Materially off (not triggered):** primary event lead not missed; no false
  `−noise`; zero wrong concrete fields.
- **Inconclusive (not triggered):** all three control windows agree (0/0/0), so
  the baseline recovery is not in doubt.

## Caveats / scope

- **One attack, one run, one disposition class** (malicious brute-force). This
  says the oracle is not *grossly* off on a clear, high-signal `+event` case with
  many `0` state leads around it. It does **not** exercise `−noise` suppression
  (no stream-blinding attack) or a stealthy `+noise` case where the malice hides
  in baseline-shaped events — the harder calls. A fuller calibration would fire a
  suppression attack and a low-and-slow benign-shaped one.
- **glm-5.2 at effort=none** — the committed oracle config. A different model/effort
  is not characterized here.
- **Aggregate ES|QL leads** return `STATS` rows, not documents, so per-query
  category is judged by whether the in-window failure/connection delta is present
  in the predicted direction — not by document-level equality.
- **Category is scored per-query, then aggregated per-lead** (`+event > +noise >
  0`). This is the well-defined grain; a lead-level label is inherently lossy for
  a heterogeneous lead (see the divergence analysis). `analyze.py` runs offline
  from the captured payloads; `--live` re-measures the control windows when the
  env is up.
- The defender run was **unsandboxed** (`DEFENDER_ALLOW_UNSANDBOXED=1`) because the
  devcontainer's host-path mapping breaks the box's source==target bind mounts.
  This affects only the agent's freeform bash lane, not the typed `query` tool or
  the leads/telemetry the oracle consumed.

## Reproduce

```
# env levered up; detection rules installed; attack fired (see attack-meta.json)
python3 experiments/oracle-telemetry-fidelity/extract_alert.py \
    v2-sshd-failed-auth-burst 2026-07-25T07:40:00Z fixtures/alert.json
DEFENDER_ALLOW_UNSANDBOXED=1 python3 defender/run.py fixtures/alert.json \
    --run-id oracle-fidelity-1 --no-learn
python3 experiments/oracle-telemetry-fidelity/run_oracle.py \
    /tmp/defender-runs/oracle-fidelity-1 fixtures/ground_truth_story.md \
    runs/oracle_projection.yaml /abs/runs/oracle_learning_dir
python3 experiments/oracle-telemetry-fidelity/analyze.py \
    runs/oracle_projection.yaml /tmp/defender-runs/oracle-fidelity-1
```
