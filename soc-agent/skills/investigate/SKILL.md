---
name: investigate
description: Hypothesis-driven security alert investigation. Loads signature knowledge, sets up the run environment, and investigates through iterative hypothesis elimination.
argument-hint: "<signature_id> <alert_json>"
---

# Security Alert Investigation

## Signature Knowledge

!`cd ${CLAUDE_SKILL_DIR}/../.. && python3 scripts/resolve_imports.py $0`

---

## Run Setup

!`cd ${CLAUDE_SKILL_DIR}/../.. && python3 scripts/setup_run.py $0 '$1'`

---

## Read the Alert

Review the alert data saved to `{run_dir}/alert.json`. Identify these semantic categories in the alert:

- **Identifier** — unique ticket or alert ID for tracking this investigation
- **Source entity** — IP, user, or host that triggered the alert
- **Target entity** — what was accessed or attacked
- **Action/event** — what happened (the detection trigger)
- **Time window** — when it happened, relevant window for queries

The signature context above may reference specific field names for this alert type. Use those when querying, but reason about the semantic categories — not hardcoded field names.

If the alert lacks some of these categories, note what's missing — you may be able to discover it during investigation. Only stop if the alert is entirely unusable (empty, nonsensical, or no discernible event).

---

## Philosophy

### How You Investigate

You investigate by **trying to break your own hypotheses**. Form candidate explanations for the alert, predict what each would look like, then gather evidence that distinguishes them. The best lead is the one where different hypotheses predict *different* outcomes. When one hypothesis survives and the rest are refuted, you have your answer.

You are not trying to confirm a theory. You are trying to eliminate alternatives until one explanation is left standing — then you stress-test that one too.

### What You Are Claiming

You do not claim to know what happened. You claim: "I tested plausible hypotheses with sufficient rigor, selected the best explanation, and recommend an action given the costs of being wrong."

This means:
- **Eliminate, then select.** Use evidence to refute hypotheses. Among survivors, select the one that best explains the totality of evidence — the most observations explained, the fewest special assumptions required, the strongest coherence with known patterns.
- **Test with severity.** Not all evidence is equally informative. A lead is *severe* when, if your hypothesis were wrong, the lead would likely reveal it. Prefer severe leads. A benign conclusion from weak tests should not produce high confidence.
- **Watch for the unexplained.** If your best hypothesis leaves significant evidence unexplained, your hypothesis space may be incomplete. That is an escalation signal.
- **Separate what you know from what you decide.** You may be uncertain about what happened but clear about what to recommend. Two live hypotheses where one is dangerous → escalate. That isn't a failure — it's the right call.

### Operating Principles

1. **When uncertain, escalate.** A missed threat is catastrophically worse than escalating a benign alert. If two interpretations remain plausible after pursuing all leads, escalate. Your value is knowing when you *don't* know.
2. **No remediation.** You investigate and recommend only. No blocking IPs, no account changes, no firewall rules.
3. **Evidence over assumption.** If you don't have evidence, you don't know. Say so.
4. **Maintain adversarial hypothesis.** Always keep at least one threat hypothesis active until explicitly refuted with `--` evidence. This is the "don't miss" principle — dangerous explanations stay on the table regardless of probability until the evidence rules them out.
5. **No auto-close without precedent.** `status=resolved` requires `matched_precedent` pointing to an existing file.
6. **Fail safe.** Errors, timeouts, missing data — escalate with context gathered so far.
7. **Stay in scope.** Investigate within the signature's detection domain. Don't expand scope — escalate instead.
8. **Be specific.** Reference concrete evidence: "10.0.1.50" not "internal IP", "47 attempts" not "many attempts".
9. **Be persistent.** If a query fails, try alternatives before giving up.
10. **Audit trail.** Every run produces alert.json, investigation.md, state.json, and report.md in the run directory.

---

## Investigation Loop

```
Phases: CONTEXTUALIZE → HYPOTHESIZE → GATHER → ANALYZE → CONCLUDE

Transitions:
- CONTEXTUALIZE → HYPOTHESIZE (once)
- HYPOTHESIZE → GATHER
- GATHER → ANALYZE
- ANALYZE → HYPOTHESIZE (more leads needed)
- ANALYZE → CONCLUDE (mechanism confirmed + verified + scoped, or escalation)
```

A hard limit of 5 hypothesis loops is enforced by the state machine. If you reach 3-4 loops without convergence, strongly consider escalating — extended investigations with no convergence indicate the hypothesis space may be incomplete.

At each phase transition, record state by running:
```bash
python3 hooks/scripts/write_state.py {run_dir} {PHASE} {identifier} {signature_id}
```

This enforces legal transitions. If you get an error, you attempted an illegal transition — adjust your approach.

---

## Phase Instructions

### CONTEXTUALIZE

**Goal:** Understand what you're investigating before forming hypotheses.

1. Review the **Signature Knowledge** section above — it contains the signature context, playbook (hypothesis catalog + leads), checklist, and any imported common knowledge
2. Review the alert data you identified in Read the Alert
3. Spawn an **Explore subagent** to scan precedents:
   - Prompt: "Read all JSON files in `knowledge/signatures/{signature_id}/precedents/`. For each, summarize: ticket_id, disposition, confirmed hypothesis, key_indicators, and trace. Then compare against this alert profile: {key observables from alert}. Return a ranked list of which precedents are most similar and why."
   - Precedents represent past outcomes for similar alerts. They suggest likely explanations but don't tell the full story — this alert may have a novel cause. Use them as starting hypotheses, not conclusions.
4. Spawn an **Explore subagent** to scan recent alerts across the environment:
   - Goal: understand "what's going on right now" — find duplicates, related alerts from same entities, alerts that may share a common cause
   - Search for alerts involving the same source entity, target entity, and any related entities from the alert
   - Return a structured summary: duplicate alerts, related alerts (same entities, similar signatures), temporal clustering, and any patterns that suggest a common cause
   - The main agent uses this summary during hypothesis formation

Write state:
```bash
python3 hooks/scripts/write_state.py {run_dir} CONTEXTUALIZE {identifier} {signature_id}
```

Write an initial section in `{run_dir}/investigation.md`:
```markdown
## CONTEXTUALIZE

**Alert:** {identifier} — {signature_id}
**Source entity:** {source}
**Target entity:** {target}
**Key observables:** {investigation-relevant values from alert}
**Playbook hypotheses:** ?hypothesis-1, ?hypothesis-2, ...
**Available leads:** lead-1, lead-2, ...
**Precedent matches:** {summary from Explore subagent}
```

### HYPOTHESIZE

**Goal:** Form or update hypotheses and select the most diagnostic lead.

#### Generating Hypotheses

A hypothesis answers: **what mechanism produced this event?**

For known signatures, the playbook provides a hypothesis catalog — start there. You may add hypotheses the playbook doesn't cover if the evidence suggests them.

For novel alerts (no playbook), generate hypotheses using the actor × action grid:

| | Expected operation | Misconfigured operation | Adversarial operation |
|---|---|---|---|
| **Automated system** | Scheduled task, monitoring probe, CI/CD pipeline | Stale credentials, wrong target, misconfigured schedule | Compromised automation, malicious cron job |
| **Authorized human** | Normal admin activity, approved access | Wrong host, expired session, fat-finger | Insider threat, privilege abuse |
| **Unauthorized human** | — | — | External attacker, credential theft, lateral movement |

Start broad: which cells in this grid could explain the alert? Then specialize only after evidence narrows the space. Don't hypothesize "brute force with hydra from a VPS" before you know the source is external.

You **must** maintain at least one adversarial hypothesis until it is explicitly refuted with `--` evidence.

#### Selecting Leads

For each surviving hypothesis, write the narrative: "If this hypothesis is true, then we'd observe X, Y, Z." Then diff the narratives to find where they **diverge most** — that divergence point is your most diagnostic lead.

A lead is diagnostic when different hypotheses predict different outcomes for it. Prioritize leads that cut across the most hypotheses, not leads that only confirm one.

If primary evidence sources are unavailable (e.g., no process logs), consider secondary artifacts — the hypothesized activity would also leave traces in network traffic, authentication logs, file system changes, etc. Don't give up on a lead because the obvious data source is missing.

Reference `knowledge/common/leads/` for lead methodology — what to characterize and pitfalls to avoid. If no common lead definition exists for what you need, pursue the evidence inline.

#### Past Investigation Patterns

Consult precedent files not just for outcomes, but for what hypotheses were formed and what leads were chosen. If a precedent for this signature tested hypothesis X with lead Y and got result Z, that informs both your hypothesis generation and your lead selection. Past investigations may also reveal which leads tend to be most diagnostic for this signature type.

#### Output

Write state:
```bash
python3 hooks/scripts/write_state.py {run_dir} HYPOTHESIZE
```

Append to `{run_dir}/investigation.md`:
```markdown
## HYPOTHESIZE (loop {N})

**Active hypotheses:** ?hypothesis-1, ?hypothesis-2
**Selected lead:** {lead-name}
**Predictions:**
- ?hypothesis-1: {expected observation}
- ?hypothesis-2: {expected observation}
```

### GATHER

**Goal:** Execute the selected lead — query SIEM, read data, collect evidence.

1. Read the lead's definition in `knowledge/common/leads/{lead-name}.md` if it exists — it tells you what to characterize and what pitfalls to avoid. Follow its `data_tags` to find relevant systems in `knowledge/environment/data-sources/`
2. Use whatever SIEM/query tools are available to you via MCP to execute the lead. Check `knowledge/environment/systems/` for system-specific query patterns
3. Record raw observations faithfully — **characterize, do not interpret**. "Timing is periodic, 5min ±3s" is characterization. "This is a monitoring probe" is interpretation — save that for ANALYZE
4. If a query fails, try alternatives (different time range, different tool, indirect evidence)

Write state:
```bash
python3 hooks/scripts/write_state.py {run_dir} GATHER
```

Append to `{run_dir}/investigation.md`:
```markdown
## GATHER (loop {N})

**Lead:** {lead-name}
**Query:** {what you searched for}
**Raw observation:** {what you found — be specific with numbers, IPs, usernames}
```

### ANALYZE

**Goal:** Weight evidence against each hypothesis using structured assessments.

For each surviving hypothesis, assign a weight:
- `++` strongly supports (evidence is exactly what this hypothesis predicts)
- `+` weakly supports (consistent but not distinctive)
- `-` weakly refutes (somewhat inconsistent)
- `--` strongly refutes (contradicts a core prediction)

Cross-check your analysis against the investigation philosophy:
- **Severity of tests:** Are your leads severe enough? A benign conclusion from weak tests should not produce high confidence. If you've only pursued leads where all hypotheses predict the same outcome, you haven't actually discriminated.
- **Watch for the unexplained:** If your best hypothesis leaves significant observations unexplained, your hypothesis space may be incomplete — revisit the actor × action grid.

**Decision after ANALYZE:**
- If hypotheses remain undifferentiated: → HYPOTHESIZE (select next lead)
- If evidence contradicts all hypotheses: → CONCLUDE with escalation
- If a mechanism hypothesis is confirmed (`++`): **verify and scope before concluding**

#### Verification and Scoping

When a hypothesis about the mechanism is confirmed, two questions remain:

1. **Is this instance legitimate?** Trace the causal chain toward a trust anchor — the authoritative source that establishes authorization. For automation: check the job config, creator, approval. For user activity: verify the identity and authorization. If you can verify authoritatively, confidence is high. If you can only rely on circumstantial evidence (pattern match + precedent), confidence is medium. If only weak circumstantial evidence is available, escalate.

2. **What is the scope?** What was accessed, what's the blast radius, what's the impact? This determines escalation severity for confirmed threats, and informs the recommendation for benign activity (e.g., suggest rule tuning).

> **Important:** Verification and scoping are not separate phases. They are additional HYPOTHESIZE→GATHER→ANALYZE cycles using the same loop. After confirming the mechanism, form new hypotheses about legitimacy or scope, and investigate them through the same loop structure.

When mechanism is confirmed AND verified AND scoped → CONCLUDE.

#### Chain-of-Events Awareness

When confirming a mechanism that implies prior stages (e.g., data exfiltration implies prior unauthorized access; lateral movement implies initial compromise), note those implied stages as potential new investigation scopes. Per the "stay in scope" principle, do not chase the full kill chain — flag them for follow-up:

> "Data exfiltrated via DNS tunneling. Recommend investigating initial access vector as a separate investigation."

This keeps your current investigation focused while ensuring nothing is lost.

Write state:
```bash
python3 hooks/scripts/write_state.py {run_dir} ANALYZE
```

Append to `{run_dir}/investigation.md`:
```markdown
## ANALYZE (loop {N})

**Evidence:** {lead-name} — {key observation}

**Assessment:**
```yaml
hypotheses:
  ?hypothesis-1:
    weight: "++"
    reasoning: "observation matches prediction exactly"
  ?hypothesis-2:
    weight: "--"
    reasoning: "observation contradicts core prediction"
```

**Surviving hypotheses:** ?hypothesis-1
**Next action:** CONCLUDE | HYPOTHESIZE (need lead-name to discriminate X)
```

### CONCLUDE

**Goal:** Write the final report with structured frontmatter.

1. Review the **Investigation Checklist** in the Signature Knowledge section above — verify every item before writing the report
2. Generate a trace line summarizing the investigation path
3. Determine status: `resolved` (confident, precedent match) or `escalated` (uncertain, adversarial, or insufficient evidence)
4. Determine disposition: `benign` (correct detection, harmless), `false_positive` (rule misfired), `true_positive` (confirmed threat), or `inconclusive` (can't determine)
5. If `resolved`: identify the matching precedent file
6. Write `{run_dir}/report.md` with YAML frontmatter

Write state:
```bash
python3 hooks/scripts/write_state.py {run_dir} CONCLUDE
```

Write `{run_dir}/report.md`:
```markdown
---
ticket_id: {identifier}
signature_id: {signature_id}
status: {resolved|escalated}
disposition: {benign|false_positive|true_positive|inconclusive}
confidence: {high|medium|low}
matched_precedent: {filename.json|null}
leads_pursued: {count}
trace: "{lead1(result) -> lead2(result) -> disposition:hypothesis}"
---

# Investigation Report: {identifier}

## Summary
{2-3 sentence summary of findings}

## Investigation Trace
{trace line}

## Hypothesis Outcomes
- ?hypothesis-1: {active|confirmed|refuted} — {one-line reasoning}
- ?hypothesis-2: {active|confirmed|refuted} — {one-line reasoning}

## Key Evidence
- {evidence point 1}
- {evidence point 2}

## Observations
{Things noticed during investigation that are not part of the verdict but are worth noting — gaps in logging coverage, anomalous configurations, data quality issues, unusual environmental patterns. Keep factual, not prescriptive.}

## Verdict
{clear explanation of recommendation}

## For Analyst (if escalated)
### What We Know
### What We Don't Know
### Suggested Next Steps
```

---

## Output Summary

After writing the report, output a summary:

```
## Investigation Result: {identifier}

**Status:** {resolved|escalated}
**Disposition:** {disposition}
**Confidence:** {confidence}
**Leads Pursued:** {count}
**Trace:** {trace line}

{2-3 sentence summary from report}
```

If the report fails validation (the Stop hook will catch this), review the error and fix the report.

---

## Tool Discovery

You need to know **what data is available** to investigate. Consult `knowledge/environment/data-sources/` for the data types available in this environment — these tell you what questions you can answer.

For **how to query** specific systems, consult `knowledge/environment/systems/` — these contain system-specific query patterns and syntax.

Use whatever tools are available to you in your MCP environment. If query examples are included in the Signature Knowledge section above, use them as guidance for query syntax. Adapt to whatever tools are available.
