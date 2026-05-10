# ANALYZE Output — case-ssh-brute-loop3-d1

## ANALYZE (loop 3)

**Evidence:** authentication-history-extended recovered 47 failed + 1 successful SSH attempt from 203.0.113.45 to prod-webserver-01 over 2026-04-12T09:11:47Z → 09:14:51Z. 18 distinct usernames, 16 environment-specific (webapp-deploy, appuser-01, appuser-02, payment-svc, inventory-svc, grafana-agent, kafka-consumer, etc.) matched to the application stack; only 2 generic (admin, root). Attempt rate 0.26/s. Forward-window check (10 min) returned 1 successful authentication (rule 5715) as `webapp-deploy` at 09:18:42Z with 4m 12s session duration before SIGTERM.

**Assessment:**

- `?opportunistic-scanner` (was `+`): `--` — refutation check directly matched. Mass-scanner prediction requires ≥5 distinct generic usernames at wordlist pace; observed username profile is 89% environment-specific service accounts with zero public-wordlist overlap. Refutation shape confirmed. Decisively ruled out.

- `?targeted-brute-force` (was `++`): `++` — maintained. Refutation check (env-specific names absent) failed — 16 of 18 usernames are environment-specific, precisely matching the prod-webserver-01 application stack. Core prediction confirmed: adversary with prior reconnaissance of this server's service inventory, attempting credential guessing against known internal account names. Rate and targeting pattern consistent with directed activity against a named production asset.

- `?credential-stuffing-external` (was `-`): `-` — further weakened. Refutation check: "rate matches mass-scanner OR purely generic wordlist" — observed rate is 0.26/s (not mass-scanner pace) but username profile is 89% environment-specific (not generic wordlist or breach-list personal names). Neither refutation condition met, but the explicit targeting contradicts the opportunistic credential-stuffing premise. Held at `-`.

- `?compromise-followup` (adversarial, was live): `++` — elevated to confirmed. Core prediction: successful SSH authentication from 203.0.113.45 in the forward window. Direct positive evidence: 1 successful authentication (rule 5715) at 09:18:42Z as `webapp-deploy` (a legitimate service account), session duration 4m 12s. Refutation shape for adversarial hypothesis ("zero 5501/5715 in forward window") explicitly failed — compromise confirmed.

**Surviving hypotheses:** `?targeted-brute-force` (++), `?compromise-followup` (++).

**Next action:** HYPOTHESIZE — compromise-activity-extended lead to determine post-auth behavior. The successful `webapp-deploy` session lasted 4m 12s before SIGTERM. Query: processes spawned from that session, outbound connections, lateral-movement attempts, privilege escalation, or data exfiltration. Discriminator: Was the session a one-off brute-force hit (true_positive, contained) or a foothold for deeper activity (true_positive + escalation concern)? This determines whether the disposition is simple containment or triggers incident-response escalation.

---

## Self-report

**Context wished for:**
- Whether the `webapp-deploy` account is privileged or restricted (can it sudo? Does it have write to critical directories?). The 4m 12s session + SIGTERM suggests automated tooling (possibly the attacker's initial-access payload or deploy automation), but account privilege level would determine blast radius.
- Whether 203.0.113.45 has prior successful compromises on other hosts in the environment (cross-host pattern clustering). The 14 prior SSH brute-force incidents on prod-webserver-01 from external scanner ASNs is strong precedent for opportunistic-scanner resolution, but this IP's username-specific targeting argues for intentional reconnaissance—a possible indicator of targeted campaigns with wider scope.
- Post-auth syslog/auth.log entry for the successful session (user, IP, port, timestamp) to confirm the match and rule out log anomalies.

**Claims uncertain:**
- Whether SIGTERM at 4m 12s came from attacker or host instrumentation (fail2ban, automated session limit, or legitimate activity timeout). No direct evidence provided in the lead output. If attacker-generated, suggests failed initial-access payload or automated reconnaissance. If host-generated, suggests containment by system policy.
- Whether the 16 environment-specific usernames derive from public GitHub repositories (e.g., prod-webserver-01 is an open-source project) or represent truly internal reconnaissance. The username set is highly specific to this stack but could be reverse-engineered from application manifests, deployment files, or container images exposed online.

**Anomalies noticed:**
- None in the investigation logic. The earlier ANALYZE (loop 2) upgraded `?targeted-brute-force` to `++` on the basis that "dedicated scanner ASN is strong evidence this IP was stood up for directed activity." This reasoning was somewhat speculative—scanner ASNs are commonly shared across both indiscriminate scanners and targeted operations. However, the loop 3 evidence (16 environment-specific usernames, zero public-wordlist overlap) provides the *actual* discriminator that validates the loop 2 upgrade. The loop 2 refutation check ("would residential/VPN hosting be more consistent?") was not load-bearing; the real refutation came from username specificity.
- Loop 3 pre-committed refutation shapes are well-formed. The `?opportunistic-scanner` refutation ("≤2 names or include env-specific names") was unambiguously met. The `?targeted-brute-force` refutation check correctly did not trigger because the evidence (16 env-specific names) supported rather than contradicted the hypothesis at `++`.
- `?compromise-followup` is now `++`, which correctly elevates it from "live mandate" to "confirmed threat." The routing gate now requires discrimination on *compromise scope* rather than *compromise fact*. This is appropriate—the question shifts from "did the attacker succeed?" to "how deep did they go?" and is well-scoped for the next HYPOTHESIZE phase.
