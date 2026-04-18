## CONTEXTUALIZE

**Alert:** 1776137449.1265639 — wazuh-rule-5710 (sshd: Attempt to login using a non-existent user)
**Source entity:** 172.22.0.10 (srcip) — monitoring-host container per `environment/context/ip-ranges.md`
**Target entity:** target-endpoint (172.22.0.2, agent.id=002)
**Key observables:**
- `data.srcuser` = `sensu` — matches monitoring-pattern sentinel list in `identity-patterns.md`
- `data.srcip` = `172.22.0.10` — classified `internal monitoring host` in `ip-ranges.md`
- `data.srcport` = 42202
- `agent.name` = `target-endpoint`
- `timestamp` = 2026-04-14T03:30:49.588Z
- `rule.firedtimes` = 7 (rule-level counter, NOT per-source attempt count — needs real auth-history lookup per playbook Screen design)
**Playbook hypotheses:** ?legitimate-automation, ?authentication-mistake, ?credential-guessing, ?compromise-followup (adversarial, always active)
**Available leads:** source-classification, username-classification, authentication-history, recent-alert-correlation, source-reputation, process-lineage, ad-hoc
**Archetype matches:** monitoring-probe (strong — internal monitoring host + sentinel username `sensu` + single target; caveat firedtimes=7 needs cadence verification); service-account-rotation (weak — username mismatch); credential-stuffing / external-bruteforce (disqualified — internal source)
**Data environment:** host_query + wazuh both READY per preflight. No degraded leads.
**Ticket-context:** no prior investigations for this signature, no fast-resolve candidates; situation = first-seen 5710 on this host. (Subagent's narrative about firedtimes=7 is speculative — must be verified via real authentication-history query.)

## SCREEN

**Result:** no_match
**Leads run:**
- source-classification: 172.22.0.10 → internal-monitoring-host (ip-ranges.md)
- username-classification: `sensu` → monitoring-pattern (identity-patterns.md)
- approved-monitoring-sources anchor: (172.22.0.10, sensu, target-endpoint) triple listed approved per approved-monitoring-sources.md, BUT cadence mismatch (see below)
- authentication-history (5 min preceding alert): **6 prior 5710 events from 172.22.0.10** — 5× `sensu` + 1× `monitorprobe` — all against target-endpoint
- authentication-history (60 sec after alert): **0 successful SSH logins** (rule 5501/5715) from 172.22.0.10
**Outcome:** falling through to HYPOTHESIZE — `attempt_count_5min` required exactly 1 (the alert itself), observed 6. Burst pattern disqualifies monitoring-probe fast-path despite the approved (srcip, srcuser, target) triple. Per `approved-monitoring-sources.md` failure-modes: "source approved but burst volume observed → refutation; escalate as 'approved source, unexpected volume'". Successful-login-after check is satisfied (none observed), but the compromise-followup window needs one more forward check before being fully cleared.
