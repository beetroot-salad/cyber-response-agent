# Security Model

Threat model, defense layers, and operational security guidance for the Cyber Response Agent.

This is a living document. It describes the *current* security posture, including intentional trade-offs and known gaps. It does not duplicate code-level details — see the referenced source files for implementation.

## Threat Model

Five threat classes are addressed, in priority order:

| # | Threat | Vector | Primary Defense | Status |
|---|--------|--------|-----------------|--------|
| 1 | **Prompt injection** | Malicious strings in alert fields or SIEM query results | Salted delimiters, "evidence not instructions" semantics, field truncation | Implemented |
| 2 | **Precedent poisoning** | Attacker creates false-positive history, then exploits the precedent | Git-backed KB with PR review, signature_id + recency validation, Tier 2 judge | Implemented |
| 3 | **Model hallucination / reward hacking** | Agent fabricates evidence, invents precedents, makes disruptive tool calls | Write scoping (run dir only), state machine enforcement, two-tier validation, budget tracking | Partially implemented |
| 4 | **Privilege escalation** | Agent credentials misused or leaked into context | SIEM CLI as credential boundary, env-var injection, no creds in LLM context | Implemented |
| 5 | **Knowledge base corruption** | Unauthorized modification of playbooks, precedents, or leads | Git with branch protection, PR-based review, signed commits | Deployment concern (see below) |

### Out of scope (current MVP)

- **Denial of service** (alert flooding) — deferred to SIEM-level rate limiting.
- **Reproduction escape** — reproduction sandbox not yet implemented. Design in `docs/design-v3-reproduction.md`.
- **Act mode abuse** — MVP is recommend-only. Mitigation actions gated by `permissions.yaml` when implemented.

## Defense Layers

### Layer 1: Input Boundary

Alert data is sanitized at ingestion (`scripts/setup_run.py`):
- Dangerous Unicode codepoints stripped (zero-width chars, bidi overrides, tag chars)
- ANSI escape sequences removed
- Field values truncated to 4096 chars
- Alert treated as untrusted evidence throughout the skill prompt

**Limitation:** Sanitization is structural only. It stops hidden-text attacks and context overflow, not semantic manipulation. This is intentional — semantic defense is the methodology's job (Layer 4).

### Layer 2: State Machine

`hooks/scripts/write_state.py` enforces legal phase transitions:

```
CONTEXTUALIZE -> [SCREEN] -> HYPOTHESIZE -> GATHER -> ANALYZE -> CONCLUDE
                                  ^                       |
                                  +------- loop ----------+
```

- Max 7 hypothesis loops before forced escalation
- CONCLUDE is terminal — no backtracking
- Screen-resolved reports require playbook `## Screen` section

### Layer 3: Tool Output Tagging

External data from SIEM queries is wrapped in salted delimiters to establish trust boundaries:

| Tool type | Mechanism | Strength |
|-----------|-----------|----------|
| MCP tools (SIEM servers) | `updatedMCPToolOutput` in PostToolUse hook — replaces raw output | Strong (model only sees wrapped version) |
| Bash (SIEM CLI) | CLI emits delimiters itself via `--run-dir` flag | Strong (wrapping is in the output) |
| Read (alert.json) | `additionalContext` in PostToolUse hook | Moderate (annotation, not wrapping) |

Salt is per-run, generated at setup (`secrets.token_hex(8)`), stored in `meta.json`.

Hook implementation: `hooks/scripts/tag_tool_results.py`.

### Layer 4: Investigation Methodology

The hypothesis-driven approach is itself a defense against both injection and hallucination:

- **Adversarial hypothesis requirement** — at least one threat hypothesis must be maintained until explicitly refuted with `--` evidence. Prevents premature benign conclusions.
- **Lead severity** — playbooks prioritize leads that are hard to fake (IP classification, auth history correlation, composite rule firing) over leads that are easy to manipulate (string fields, banners).
- **Structured assessments** (`++`/`+`/`-`/`--`) replace subjective confidence, making reasoning auditable.

### Layer 5: Two-Tier Validation

Fires on every `report.md` write (`hooks/scripts/validate_report.py`):

**Tier 1 (deterministic, ~instant):**
- Frontmatter schema validation (required fields, valid enums)
- `status=resolved` requires `matched_precedent` pointing to existing file
- Precedent `signature_id` must match report `signature_id`
- Precedent `validated_at` must be within configured recency window (default 90 days)
- `leads_pursued` meets minimum per severity level (screen-resolved exempt)

**Tier 2 (LLM judge, ~5s):**
- Separate model (Haiku) evaluates 5 criteria: precedent match, internal consistency, evidence sufficiency, completeness, adversarial check
- Untrusted content (alert data, investigation log) wrapped in per-run salted delimiters
- Two modes: full (5 checks for resolved) and no-precedent (4 checks for escalated)

Exit code 2 rejects the report — agent must revise.

### Layer 6: Audit Trail

Append-only JSONL logging (`hooks/scripts/audit_tool_calls.py`):
- `tool_audit.jsonl` — state-changing tools (Bash, Write, Edit, Agent, MCP)
- `tool_trace.jsonl` — read-only tools (Read, Glob, Grep)
- `audit.jsonl` — per-investigation outcome summary (Stop hook)

Field values truncated to 2000 chars in logs.

## Tool Permission Recommendations

The investigation agent's tool access should be scoped via Claude Code's `settings.json` permission patterns. Recommended configuration for production:

```json
{
  "permissions": {
    "allow": [
      "Read(*)",
      "Glob(*)",
      "Grep(*)",
      "Write(*/runs/*/report.md)",
      "Write(*/runs/*/investigation.md)",
      "Edit(*/runs/*/report.md)",
      "Edit(*/runs/*/investigation.md)",
      "Bash(python3 */write_state.py:*)",
      "Bash(python3 */wazuh_cli.py:*)",
      "Bash(python3 */setup_run.py:*)"
    ],
    "deny": [
      "Write(*/knowledge/*)",
      "Write(*/hooks/*)",
      "Write(*/schemas/*)",
      "Write(*/config/*)",
      "Edit(*/knowledge/*)",
      "Edit(*/hooks/*)",
      "Edit(*/schemas/*)",
      "Edit(*/config/*)",
      "WebFetch(*)",
      "WebSearch(*)"
    ]
  }
}
```

**Rationale:**
- **Read-only tools are unrestricted** — the agent needs to read KB, playbooks, precedents, and investigation artifacts freely.
- **Writes scoped to run directory** — prevents KB corruption and hook/schema tampering. The whitelist approach (allow specific paths) is preferred over blacklist (deny specific paths) because unknown paths default to denied.
- **Bash restricted to known scripts** — SIEM CLI, state machine, and setup script are the only legitimate Bash use cases during investigation.
- **WebFetch/WebSearch denied** — no legitimate use during investigation; prevents data exfiltration via search queries.

Note: these are recommendations. The exact patterns depend on the deployment's directory layout and SIEM tools. Claude Code's auto mode provides additional interactive approval for unlisted tools.

## Known Gaps and Intentional Trade-offs

### Budget enforcement is warning-only (intentional)

`hooks/scripts/budget_enforcer.py` tracks tool calls, subagent spawns, and wall clock time, but always exits 0. Warnings print at 75% and 100% of limits. This is an intentional adjustment period to calibrate realistic limits before enabling hard enforcement. See `budget_enforcer.py` line 10.

**Risk:** A runaway or compromised agent can exceed all budgets.
**Mitigation plan:** After calibration, switch to exit code 2 when limits are exceeded, forcing the agent to conclude with current evidence or escalate.

### Alert schema is not validated (intentional)

Alert JSON structure varies across SIEMs and organizations. Schema normalization would be high-maintenance with unclear security benefit — LLMs handle schema variance naturally. The agent treats alert fields as opaque evidence.

**What is validated:** Alert origin should be confirmed by querying the SIEM for the alert ID during the CONTEXTUALIZE phase. This prevents fabricated alerts from being investigated.

### additionalContext wrapping is weak for built-in tools

For Bash and Read tool results, `additionalContext` appears as a system reminder adjacent to (not wrapping) the tool output. The model has already ingested the raw output. This is a reinforcement signal, not a hard boundary.

**Primary defense for Bash:** SIEM CLI wraps its own output via `--run-dir` flag.
**Primary defense for Read:** Alert data is marked as untrusted in the skill prompt itself.

### Judge model availability

The system requires Claude API availability for: the investigation agent, the Tier 2 judge, and the SCREEN subagent. If the API is down, the entire workflow is unavailable. The judge is not a new single point of failure — it shares the existing dependency.

If the judge specifically is unreachable (timeout, CLI not found), Tier 2 validation fails and the report is rejected. A future enhancement could force-escalate on judge unavailability rather than blocking.

### Semantic manipulation of alert content

An attacker who controls alert field values can craft content that makes benign-looking evidence appear corroborative (e.g., setting an SSH banner to match monitoring probe patterns). Salted delimiters defend against structural injection but not semantic manipulation.

**Primary defense:** Playbook quality. Leads should prioritize evidence that is hard to fake (IP classification, authentication history, composite rule correlation) over evidence that is easy to manipulate (string fields, banners, hostnames). See the "lead severity" concept in `skills/investigate/SKILL.md`.

## Knowledge Base Security (Deployment Guidance)

The knowledge base (`knowledge/`) is the foundation of investigation quality. Corrupted or poisoned KB content undermines all other defenses.

**Recommended posture:**
1. **Git-backed** with branch protection on `main`
2. **PR-based updates** with mandatory review by >=1 analyst
3. **Signed commits** for KB changes (audit trail)
4. **CI validation** — run `pytest test_kb_schema.py` on every PR to validate precedent structure, frontmatter, and import resolution
5. **Precedent expiry** — `validated_at` field enforced by Tier 1 validation (default: 90 days). Stale precedents force escalation until re-validated.
6. **No agent write access** — production `settings.json` should deny writes to `knowledge/` (see Tool Permission Recommendations above)
