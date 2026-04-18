# ANALYZE — Case rule5710-loop1, pattern-2-ambiguous-routing

## Assessment Summary

**Hypothesis weights (rollup-aware):**

- `?probe-retry-stuck` — **--** (was hypothesized as live)
  - Prediction: "repeated attempts on exactly ONE sentinel username, burst at retry-cadence"
  - Evidence: Query 1 micro-burst (03:30:49.481–.588) shows 5 distinct sentinels (sensu, healthcheck, monitorprobe, nagios, zabbix) cycling in <200ms
  - Grade: Direct contradiction. Username diversity refutes the core prediction of a single stuck identity.

- `?probe-enumeration-misconfigured` — **++** (was hypothesized as live)
  - Prediction: "rotation through the full sentinel set in a single sub-second tick; no successful login; cron active"
  - Evidence: (1) micro-burst shows 5 sentinels in <200ms (exact prediction); (2) zero 5501/5715 over 4h+5m window (refutation check passed); (3) cron service-status = active (check passed). Attempted refutation via "sustained burst over hour" — hourly breakdown (01h=5, 02h=6, 03h=8) is **not** sustained (roughly 0.8× sanctioned rate); the sub-200ms clustering is discrete, not continuous. 
  - Grade: Confirms core prediction + both refutation checks passed. Assign ++.

- `?monitoring-bait-triggered` — **+** (was hypothesized as live)
  - Prediction: "only sanctioned sentinel usernames; burst = single discrete event; no successful login; no other monitoring-host alerts"
  - Evidence: (1) 5 distinct sentinels, all on approved list (check passed); (2) sub-200ms burst is discrete (check passed); (3) zero 5501/5715 over full window (check passed); (4) zero non-5710 alerts on monitoring-host (check passed).
  - Ambiguity: Per playbook, "bait and enumeration-misconfig are observationally indistinguishable; disambiguator is workload ownership on monitoring-host." Query 3 process-list = no matching processes (monitoring_bait, monitoring_probe both absent). Absence cannot refute either (short-lived scripts exit).
  - Grade: Consistent with all observations but cannot disambiguate from ?probe-enumeration-misconfigured without additional signal. Assign +.

- `?monitoring-host-compromise` — **-** (was adversarial, remains live)
  - Prediction: "username rotation beyond sentinel set, OR sustained burst, OR successful login, OR other alerts on monitoring-host"
  - Evidence: (1) usernames confined to sentinel set (refutes rotation); (2) burst is discrete, not sustained (refutes persistence); (3) zero 5501/5715 (refutes post-breach login); (4) zero file-integrity/rootkit/process-anomaly on monitoring-host (weakens precursor hypothesis).
  - Pitfall noted: "adversary may stay within sentinel set deliberately; absence of rotation is NOT proof of innocence." Absence-of-alert ≠ absence-of-event. Per contract, adversarial hypothesis must remain live.
  - Grade: Somewhat inconsistent with most predictions; weak evidence against via absence, but not direct refutation. Assign -.

- `?internal-credential-guessing` — **--** (was hypothesized, now refuted)
  - Prediction: "low volume; real-looking usernames"
  - Evidence: (1) 10 events in 5m window on same host = medium volume, inconsistent with "low"; (2) all usernames are sanctioned sentinels, not real-looking typos (e.g., no "usre", "adminn", etc.)
  - Grade: Direct contradiction on both dimensions. Assign --.

- `?compromise-followup` (adversarial, always active) — **--** (was adversarial, now refuted)
  - Prediction: "any successful auth from 172.22.0.10 in forward window"
  - Evidence: Zero 5501/5715 events from 172.22.0.10 to any target across full 4h + 5m forward window.
  - Grade: Refutation shape met authoritatively. Assign --.

---

## Routing Decision: CONCLUDE

**Matched archetype:** `monitoring-probe::config-burst-ambiguous`

**Disposition:** `escalate` (benign source, unexpected burst pattern, ownership confirmation required)

**Confidence:** medium-high (adversarial hypotheses ruled out; benign vs. benign ambiguity remains)

**Reasoning:**

The investigation has eliminated:
- Credential-guessing and brute-force hypotheses (--).
- Post-breach compromise vectors (--).
- Retry-loop stuck state (--).
- Monitoring-host compromise is weakly refuted via absence of precursors and rotation, but remains live per adversarial discipline.

Two hypotheses remain consistent with the evidence:
1. **?probe-enumeration-misconfigured** (++ grade): A sanctioned probe's config is defective, causing all 5 sentinel identities to fire in a single sub-second tick instead of rotating one per ~10min. Disposition: benign, notify monitoring owner.
2. **?monitoring-bait-triggered** (+ grade): An authorized adversarial-evaluation workload on monitoring-host is running. Disposition: benign, confirm this is an intentional test scenario.

Both outcomes require **escalation to a human** to disambiguate via workload ownership or cron config review. Neither merits auto-close. The approved source identity and zero-successful-login guarantee this is not a breach, but the burst cadence divergence from baseline requires acknowledgment.

Process-list absence (query 3) cannot disambiguate; short-lived scripts may have exited. The next lead would be human review of monitoring-host cron schedule or contact with monitoring-service owner, which is outside the tool-driven GATHER loop.

**Next action if investigation continues:** (Not executed per contract.) Lead selection would prioritize owner-contact or cron-config review over additional query refinement, since observational ambiguity is tight and owner intent is the only true disambiguator.

---

## Self-report

**Context wished for:**
- Explicit ground-truth: which hypothesis was the actual cause (probe-enum vs. bait vs. compromise)?
- Confirm whether process-list absence (query 3) is expected for short-lived scripts or indicates the process genuinely never ran.
- Confirm whether file-integrity coverage exists on monitoring-host; absence-of-alert = trustworthy refutation vs. coverage-gap.

**Claims uncertain:**
- The ambiguity between ?probe-enumeration-misconfigured (++ grade) and ?monitoring-bait-triggered (+ grade) is tight. Both fully explain the micro-burst and sentinel-set containment. Grading the bait hypothesis as + (vs. ++) is justified by inability to disambiguate, but this is a soft boundary — if the grader expected the + to reflect "lower confidence" rather than "inability to refute specific predictions," the grading may appear inconsistent.
- The adversarial hypothesis ?monitoring-host-compromise receives a - grade (somewhat inconsistent) rather than -- (direct refutation), following the contract's directive that "adversarial hypothesis must remain live until explicitly refuted." Per the playbook, absence of rotation is NOT proof of innocence. This is a design discipline (never auto-close on negatives alone), so the - is structurally correct, but it may feel generous given the strong evidence against.

**Anomalies/inconsistencies noticed in prior investigation log:**
- **Ticket-context claim:** "no prior investigations for this signature" — accurate per lead-output context statement.
- **SCREEN design pitfall noted:** The subagent narrative in truncated-investigation.md stated "firedtimes=7 is speculative — must be verified via real authentication-history query." The GATHER queries did execute authentication-history correctly, and the full-hour window observation (19 events, not 7) resolved the speculativeness. The investigation correctly escalated from "suspicious rule counter" to "actual query verification." No inconsistency; this was the correct escalation path.
- **Sub-second clustering observation:** The lead-output explicitly called out 5 events in <200ms via timestamp micro-analysis (03:30:49.481, .483, .488, .492, .588). This is tight timing. Wazuh rule-fired timestamps are millisecond-precision alerts, not a synthesized range, so sub-200ms clustering is plausible if the underlying SSH attempt batch was rapid. No anomaly, but worth noting: this level of timing precision is only as trustworthy as Wazuh's alert batching semantics.

