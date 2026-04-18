# ANALYZE (loop 3) — authentication-history-extended resolution

## Hypothesis weights and rollup

**Evidence:**
- authentication-history-extended (wazuh, 203.0.113.45 → prod-webserver-01, 30 min preceding + 10 min forward): 47 events, 19 distinct usernames, 0.26/s attempt rate, 0 successful authentications in forward window.
- Username breakdown: 14 generic public-wordlist names (admin, root, ubuntu, pi, oracle, postgres, deploy, user, test, guest, operator, mysql, git, jenkins) + 5 environment-specific names matching prod-webserver-01 stack (webapp-deploy, appuser-01, payment-svc, inventory-svc, nginx-reload). Mixed ratio ~74% generic / 26% environment-specific.

**Assessment:**

- `?opportunistic-scanner`: `+` (was `+`) — evidence is *consistent* with mass-scanner profile (0.26/s, 14 generic names, dedicated scanner ASN, reputation tags). However, 26% environment-specific names contradict the pure opportunistic model (wordlist scanners carry ~100% generic names). Mixed username set is *not discriminating* — cannot confirm opportunistic-scanner as sole hypothesis.

- `?targeted-brute-force`: `+` (was `+`) — presence of 5 environment-specific names (webapp-deploy, appuser-01, payment-svc, inventory-svc, nginx-reload) is consistent with targeted reconnaissance and env-aware guessing. However, 74% generic padding is unusual for targeted-brute-force (which typically leads with environment-specific accounts). Again, mixed set is *not discriminating* — cannot confirm targeted-brute-force as sole hypothesis. Not graded `++` because the environment-specific names do not *confirm* targeting in isolation (both pure opportunistic and targeted-with-padding predict some env-specific names).

- `?credential-stuffing-external`: `--` (was `-`) — attempt rate (0.26/s) and username profile contradict credential-stuffing fundamentals. Breach-list credential replay relies on lower rates and personal/email-prefix identifiers, not generic wordlist scatter. Direct contradiction of core prediction (attempted refutation: lower rate + personal-identifier usernames failed).

- `?compromise-followup`: live (no forward-window successful auth) — adversarial hypothesis retained with explicit rationale. Zero 5501/5715 from 203.0.113.45 in the forward window (09:14:51Z → 09:24:51Z) means *no successful compromise* from this burst. However, does not refute `?compromise-followup` globally (attacker may retry later).

**Surviving hypotheses:** `?opportunistic-scanner` (+), `?targeted-brute-force` (+), `?compromise-followup` (live).

## Routing decision

**HYPOTHESIZE** — The routing gate is not satisfied:

- **Condition 1 fails:** Two `+` hypotheses (`?opportunistic-scanner` and `?targeted-brute-force`) with *different archetypes* and conflicting disposition guidance. Opportunistic-scanner → true_positive/firewall-hygiene vs. targeted-brute-force → true_positive/prior-recon investigation. Cannot resolve to single archetype + disposition without further evidence.

- **Condition 3 satisfied:** Adversarial hypothesis `?compromise-followup` is retained live with explicit rationale (forward-window check yielded zero successes; attacker may retry later).

- **Condition 4 fails:** The investigation log explicitly notes the username set is "not discriminated by this evidence" and suggests two plausible explanations: (a) opportunistic scanner with customized wordlist seeded from prior recon or public leaks (hybrid tooling), or (b) targeted actor deliberately padding env-specific attempts with generic-wordlist mask. A follow-on lead targeting *wordlist origin* or *naming pattern consistency* would materially reduce uncertainty. Example discriminators: check wazuh FIM or web-app logs for evidence of prior recon on prod-webserver-01 (supports hybrid-seeded hypothesis) or check whether the 5 environment-specific names correlate with actual deployed service accounts (supports targeted hypothesis).

**Discriminating lead:** `authentication-history-extended` with extended prior window (6 hours preceding the burst instead of 30 min) to detect prior recon activity on prod-webserver-01 from the same source. If 203.0.113.45 appeared in earlier probes or scans on this host, supports hybrid-opportunistic-with-seeded-wordlist. If no prior activity, slightly increases confidence in targeted-brute-force (fresh attack, not cumulative scanning).

---

## Self-report

**Context wished for:**
- Clarity on whether the 5 environment-specific names (`webapp-deploy`, `appuser-01`, `payment-svc`, `inventory-svc`, `nginx-reload`) match *actual deployed accounts* on prod-webserver-01, or whether they are plausible guesses harvested from public leak sources or OSINT. A grep of `/etc/passwd` or service manifest would disambiguate targeted-recon from hybrid-seeded-wordlist.
- Prior recon history: did 203.0.113.45 appear in authentication logs, DNS queries, or FIM events on prod-webserver-01 in the 6 hours preceding this burst? Absence strongly narrows the hypothesis space toward pure opportunistic (even if seeded).

**Claims uncertain:**
- Whether the mixed username set (74% generic, 26% env-specific) represents deliberate obfuscation (targeted actor padding with wordlist names) or legitimate dual-mode opportunistic tooling (mass scanner with a customized wordlist). Both are consistent with the evidence.
- Whether the 5 environment-specific names are *fresh discoveries* by the attacker (would strengthen targeted hypothesis) or *precomputed from public sources* (weakens targeted, supports hybrid-opportunistic).

**Anomalies or inconsistencies:**
- No anomalies detected in the prior investigation log. The authentication-history observations are consistent with the lead predictions and the cross-lead notes appropriately flagged the username set as discriminating failure (mixed profile, not pure opportunistic and not pure targeted). The forward-window check (zero successful auth) is consistent with `?compromise-followup` remaining live but not confirmed. No contradictions between loop 1 / loop 2 assessments and loop 3 evidence.
