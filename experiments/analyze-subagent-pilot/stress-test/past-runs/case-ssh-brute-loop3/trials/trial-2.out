## ANALYZE (loop 3)

**Evidence:** authentication-history-extended (wazuh, T-window 2026-04-12T08:44:03Z → 09:24:03Z on 203.0.113.45 → prod-webserver-01) — 47 rule-5710 events over 3m4s (09:11:47Z → 09:14:51Z); 20 distinct usernames at 0.26/s; all 20 usernames are stock public wordlist entries (admin, root, ubuntu, pi, oracle, postgres, deploy, user, test, guest, operator, mysql, ftpuser, git, jenkins, hadoop, tomcat, nagios, www-data, ansible); **zero** env-specific names from the prod-webserver-01 application stack; **zero** rule 5501/5715 events from 203.0.113.45 in the 10-min forward window (09:14:51Z → 09:24:51Z) or in any other host window during the full query period.

**Assessment:**
- `?opportunistic-scanner`: `++` (was `+`) — authentication-history-extended is a direct SIEM query answer, not a circumstantial read. It confirms: (1) 20 distinct generic wordlist usernames, satisfying prediction "≥5 generic names at wordlist pace"; (2) 0.26/s rate consistent with automated sweep; (3) zero successful logins. Named failed refutation: the pre-committed refutation shape stated `--` if "usernames ≤2 names OR env-specific names present" — neither leg materialized (20 names, all generic, zero application-stack identifiers). Authoritative data source qualifies for `++`.

- `?targeted-brute-force`: `--` (was `+`) — matched pre-committed refutation shape: "→ `--` if all usernames are generic wordlist entries with no environment-specific naming." All 20 usernames are confirmed stock wordlist entries; zero webapp-\*, appuser-\*, deploy-service, or other prod-webserver-01 stack-specific account names are present. The core prediction (env-specific names in the scatter) is directly falsified by the SIEM record — not just unlikely, directly absent.

- `?credential-stuffing-external`: `--` (was `-`) — matched pre-committed refutation shape: "→ `--` if attempt rate matches mass-scanner profile OR usernames are purely generic wordlist entries." Both legs met: 0.26/s exceeds the <0.05/s ceiling typical of credential-stuffing tools that slow-drip to evade rate limits; and all 20 usernames are generic role/service names with no personal-identifier or email-prefix pattern. Double-refutation; `--` warranted. (This also independently confirms the `-` grade from loop 2.)

- `?compromise-followup`: `--` (was live/unchecked) — matched pre-committed refutation shape: "→ `--` if zero 5501/5715 from 203.0.113.45 in the forward window." Zero authentication-success events from 203.0.113.45 to prod-webserver-01, and zero to any other host, across the full preceding 30 min + 10-min forward window. Mandatory compromise check satisfied — refuted cleanly.

**Surviving hypotheses:** `?opportunistic-scanner`

**Next action:** CONCLUDE → disposition: true_positive, confidence: high, matched_archetype: external-bruteforce

**Rationale:** `?opportunistic-scanner` reached `++` via a direct SIEM query answer with a named failed refutation. All three competing hypotheses reached `--` via their respective pre-committed refutation shapes on the same lead. Trust root v-001 reached (203.0.113.45 is an external endpoint with no accessible upstream forensics — no process lineage, no session chain, no owner-controlled sources available).

**Archetype shape-verification (external-bruteforce):** The catalog archetype is `external-bruteforce`, not the preliminary label `opportunistic-scanner` used in CONTEXTUALIZE. story.md disqualifier conditions: (1) "a single attempt" → 47 events, 20 distinct usernames — NOT triggered; (2) "attempts from an internal source" → 203.0.113.45 confirmed external per ip-ranges.md and SCREEN — NOT triggered. Defining conditions all met: external source ✓, multiple distinct generic usernames ✓, high volume (47 events / 3m4s) ✓. `required_anchors: []` — adversarial by construction, no anchor grounding required. story.md notes "coordinated pentests would match a different archetype anchored by a change ticket" — 203.0.113.45 is flagged in GreyNoise with 20 months of continuous mass-SSH-scanning activity, no change-ticket signal present. `matched_archetype: external-bruteforce` is clean.

---

## Self-report

- **Context wished for:** Formal h-NNN hypothesis IDs are not assigned in the HYPOTHESIZE block of investigation.md — the companion YAML write process will need to resolve inference-order IDs (h-001 through h-004 in declaration order) before validator rule 24 can confirm the surviving_hypotheses list. This is a write-time gap, not a grading ambiguity.
- **Uncertain claims:** The `++` grade for `?opportunistic-scanner` hinges on the Wazuh SIEM query being authoritative for the mechanism. The spec treats a "direct query answer" as qualifying for `++`; I've applied that here. If the Wazuh indexer had indexing lag or event deduplication artifacts that could distort the username count, confidence would drop, but there is no signal of that in the GATHER observations.
- **Anomalies:**
  - **CONTEXTUALIZE archetype label mismatch:** The CONTEXTUALIZE block named `opportunistic-scanner` as the archetype candidate, but no such archetype exists in the wazuh-rule-5710 catalog. The correct catalog archetype is `external-bruteforce`. This label will propagate incorrectly if the CONCLUDE block copies from CONTEXTUALIZE rather than the catalog. The main agent composing the CONCLUDE section should use `external-bruteforce`, not `opportunistic-scanner`.
  - **Refutation shapes in HYPOTHESIZE (loop 3) lack formal rN IDs:** The pre-committed shapes are stated as prose bullets ("→ `--` if ...") but are not assigned identifiers (r1, r2, r3, r4). The `--` grades above reference them by description. The companion YAML composition step must assign retroactive IDs for validator `matched_refutation_ids` fields on the `--` resolutions to pass invlang rule validation at CONCLUDE write time.

---

```yaml
next_action: CONCLUDE
disposition: true_positive
confidence: high
matched_archetype: external-bruteforce
surviving_hypotheses: [h-001]
```
