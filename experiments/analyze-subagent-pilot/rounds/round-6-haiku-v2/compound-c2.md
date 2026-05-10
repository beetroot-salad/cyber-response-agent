# ANALYZE (loop 3) — authentication-history-extended result

**Evidence:**
- authentication-history-extended (wazuh) on data.srcip:203.0.113.45 / agent.name:prod-webserver-01 / rule:5710:
  - Window: 2026-04-12T09:11:47Z → 09:14:51Z (burst)
  - Event count: 47
  - Distinct usernames: 19 (14 generic wordlist: admin, root, ubuntu, pi, oracle, postgres, user, test, guest, operator, mysql, git, jenkins, nginx-reload; 5 env-specific: deploy, webapp-deploy, appuser-01, payment-svc, inventory-svc)
  - Attempt rate: 0.26/s (steady sweep, ~4s between usernames)
  - Forward-window success (5501/5715): 1 successful auth at 09:19:02Z, username `deploy` (real local account on prod-webserver-01), session 58s duration
- `deploy` username profile: ambiguous — appears in public wordlists AND is a real low-privilege service account on this host

**Assessment:**

- `?opportunistic-scanner`: `+` (was +) — 74% generic wordlist usernames and 0.26/s rate are consistent with mass-scanner automation. Reputation (GreyNoise: mass-ssh-scanner) corroborates. However, 26% env-specific names (including the username that succeeded) prevent upgrade to `++` — a pure opportunistic scanner would not deliberately target environment-specific accounts. This evidence is circumstantial, not uniquely discriminating.

- `?targeted-brute-force`: `-` (was +) — env-specific usernames present (deploy, webapp-deploy, appuser-01, payment-svc, inventory-svc) support prior-reconnaissance profile. However, 74% generic wordlist entries and attempt rate of 0.26/s are inconsistent with typical targeted brute-force behavior, which concentrates on researched accounts at slower pacing to avoid detection. The mixed profile suggests opportunistic with incidental env-specific hits, not deliberate targeting. Downgraded from `+`.

- `?credential-stuffing-external`: `-` (unchanged) — attempt rate 0.26/s is inconsistent with credential-stuffing methodology, which relies on slower pacing (human-aware or human-paced) to evade rate limiting. Usernames are also inconsistent with typical breach-list profiles (mix of generic and env-specific, not personal identifiers or email-prefix patterns).

- `?compromise-followup`: `++` (was live) — core prediction confirmed by direct evidence: successful authentication (rule 5715) from 203.0.113.45 at 09:19:02Z, username `deploy`. Refutation shape (no 5501/5715 in forward window) explicitly failed — a success was observed. This is a load-bearing fact: the source has a live shell on prod-webserver-01.

**Surviving hypotheses:** `?opportunistic-scanner` (+), `?targeted-brute-force` (-), `?credential-stuffing-external` (-), `?compromise-followup` (++, confirmed).

**Routing decision:** HYPOTHESIZE. Although `?compromise-followup` is confirmed, a discriminating follow-on lead exists that would materially reduce uncertainty about threat scope and trajectory: post-session forensics on the `deploy` session (process tree, files created, sudo events from that PID, outbound connections). This lead is load-bearing because it discriminates between (a) a live, active attacker using the shell to pivot or exfiltrate, and (b) an automated scanner that happened to crack a weak credential but abandoned the session after default inactivity timeout. The original investigation loop budget allows this discriminator.

**Selected lead (HYPOTHESIZE → next loop):** post-session-forensics (host-query or EDR endpoint if available) — capture process tree, file modifications, and lateral-movement indicators from the `deploy` session window (09:19:02Z ± 2min). This distinguishes active post-compromise attacker behavior from credential hit + timeout.

---

## Self-report

**Context wished for:**
- Confirmation that the `deploy` session termination at 58 seconds was user-initiated (SIGTERM from attacker) vs. automatic (inactivity timeout). This distinguishes deliberate exploration from blind credential hit.
- Endpoint or file-integrity monitoring data for prod-webserver-01 covering 09:19:02Z → 09:20:00Z to check for suspicious process spawning or file modifications under the `deploy` PID.

**Claims uncertain:**
- Whether the 26% env-specific names in the burst represent genuine environment research (targeted) or incidental overlap with generic wordlist entries that happen to collide with real account names. The 0.26/s rate argues for automated wordlist scanning with coincidental hits rather than deliberate research.
- Whether `deploy`'s success is a genuine weak credential (default/unmanaged service account password) or a rare breach-list match.

**Anomalies or inconsistencies noticed:**
- The investigation log correctly identified mixed evidence (74/26 generic/env-specific split) but did not fully commit to the implication: the presence of env-specific usernames is consistent with both opportunistic-scanner-with-incidental-hits and targeted-brute-force-with-cover. The routing gate correctly identifies that this ambiguity is not resolved by the username evidence alone — the discriminator is not username profile but post-compromise behavior. A targeted attacker who succeeded would likely explore the system; a mass scanner that succeeded would timeout. The next lead is correct.
- No inconsistency in prior grades — the loop 1 and loop 2 assessments held `?opportunistic-scanner` and `?targeted-brute-force` at equal weight pending auth-history, which was appropriate given the incomplete evidence at those stages.
