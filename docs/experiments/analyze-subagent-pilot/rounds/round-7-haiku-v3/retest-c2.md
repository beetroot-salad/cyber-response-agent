# ANALYZE (loop 3) — case-ssh-brute-loop3-c2

## Grading & Routing

**Evidence:**
- `authentication-history-extended`: 47 attempts over ~3 min from 203.0.113.45 → prod-webserver-01, 19 distinct usernames (74% generic wordlist, 26% env-specific). Attempt rate 0.26/s. **One successful login observed:** `deploy` at 09:19:02Z (within the 10-min forward window), session terminated after 58s by SIGTERM.

**Assessment:**

- `?opportunistic-scanner`: `+` (was `+`) — mass-scanner behavior confirmed by: dedicated scanner-infrastructure ASN, high attempt rate (0.26/s), predominantly generic wordlist usernames (74%). However, the presence of 26% environment-specific names (`webapp-deploy`, `appuser-01`, `payment-svc`, `inventory-svc`, `nginx-reload`) prevents this from rising to `++`; an opportunistic mass-scanner should not predict mixed wordlist/env-specific names at this ratio. The successful `deploy` login is consistent with wordlist-hit opportunism (weak default credential), but the mixed username profile is anomalous for pure opportunistic behavior.

- `?targeted-brute-force`: `+` (was `+`) — the presence of environment-specific usernames (`webapp-deploy`, `appuser-01`, `payment-svc`, `inventory-svc`, `nginx-reload`) is consistent with prior reconnaissance. However, 74% of the attempt set are generic wordlist entries, which contradicts the "environment-aware" core prediction of targeted-brute-force. The successful `deploy` login is ambiguous: it's both a wordlist entry AND a real service account, so the success alone does not confirm deliberate targeting. Graded `+` (not upgraded to `++`) because the username scatter is more consistent with mass-scanner noise than focused targeting, and the single success is insufficient to distinguish targeted-recon from opportunistic wordlist-hit on a weak credential.

- `?credential-stuffing-external`: `-` (unchanged) — remains refuted by: (1) mass-scanner ASN infrastructure and (2) usernames are predominantly generic wordlist entries, not personal/email-prefix breach-list patterns. Credential-stuffing prefers non-flagged residential IPs and breach-derived identifiers; this profile contradicts those expectations.

- `?compromise-followup`: `++` — **direct positive evidence: one successful SSH login (rule 5715) from 203.0.113.45 at 09:19:02Z, username `deploy`, within the 10-min forward window.** The session was terminated by SIGTERM after 58 seconds, indicating the attacker gained a session but did not sustain it long enough to establish persistence in this observable window. The compromise is confirmed, refutation check (zero successful logins in forward window) failed.

**Live adversarial hypothesis:** `?compromise-followup` remains active at `++` (confirmed by successful login), making this scenario a **true positive with confirmed host compromise**.

**Routing decision:** All gate conditions fail:
1. Multiple `+` hypotheses (`?opportunistic-scanner`, `?targeted-brute-force`) do NOT share a single archetype — opportunistic-scanner and targeted-brute-force are distinct archetypes with different incident-response postures.
2. The `?compromise-followup` is `++` on direct positive evidence (successful login), which is correct, but its confirmation supersedes the earlier hypotheses' archetypes. The routing gate requires either (a) exactly one `++` hypothesis, or (b) all `+` hypotheses sharing a single archetype + disposition. Neither condition holds here.
3. A discriminating follow-on lead would materially reduce uncertainty: **post-session host forensics** (process tree, files created, sudo events from the `deploy` session PID, .ssh/authorized_keys modifications) could determine whether the attacker established persistence or was merely testing the compromised credential.

**Next action:** **HYPOTHESIZE** — recommend post-session-forensics lead to confirm whether the `deploy` session established persistence (unauthorized keys, backdoor processes, privilege escalation) or was opportunistic session testing.

---

## Self-report

**Context wished for:**
- Process tree / file system artifacts from the `deploy` session (PID, child processes, working directory, modified files) to determine persistence intent.
- Sudo log or privilege escalation attempts during the 58-second session window.
- SSH authorized_keys state at alert time and post-incident to detect persistence mechanisms.

**Uncertain claims:**
- The `deploy` username is genuinely ambiguous: it appears in public wordlists (consistent with opportunistic-scanner) AND is a real service account on this host (consistent with prior reconnaissance by a targeted attacker). The single login success does not distinguish the two. If the attacker had attempted 100 usernames and succeeded only on `deploy`, that would still be consistent with both opportunistic (weak default) and targeted (researched account). The mixed username scatter (74% generic, 26% env-specific) is the most anomalous signal — it suggests either (a) an opportunistic scanner that happened to be updated with this target's environment names (unlikely), or (b) a hybrid campaign that mixes generic wordlist spray with targeted-reconnaissance refinement (plausible but speculative without deeper context).

**Anomalies in investigation log:**
- The threat-intel-deep-lookup lead timed out (peak hours), preventing campaign-attribution context. This leaves unresolved whether the scanner IP is associated with known campaigns.
- The forward-window session termination by SIGTERM after 58 seconds is unusual — it could indicate the attacker's own session management (interactive timeout) or external termination (host-based IDS kill, SSH rate-limiting teardown, or concurrent session limit). The 58-second duration is consistent with interactive reconnaissance, not unattended automated credential testing.
- The precedent context from CONTEXTUALIZE (14 prior SSH brute-force true_positives from external scanner-class ASNs) is probabilistically strong for opportunistic-scanner archetype, but this case's mixed username profile and confirmed compromise elevate it beyond routine opportunistic handling.

**Assessment of prior loop-2 weight carryover:**
- `?opportunistic-scanner` was held at `+` after loop 2 (awaiting auth-history for username-scatter confirmation). The auth-history result (74% generic, 26% env-specific) is anomalous for pure opportunistic behavior. The refutation shape pre-committed in loop 3 stated: "if all usernames are generic wordlist entries with no environment-specific naming → keep `+`, but the presence of env-specific names weakens the confidence." This case is a hybrid, so `+` is correct (not `++`, not `--`).
- The `?compromise-followup` `++` grading is justified by direct positive evidence (rule 5715 event, confirmed login, session PID, timestamp in window). The refutation shape was pre-committed as "zero 5501/5715 events → `--`"; observing one refutes that refutation.

