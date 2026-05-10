## Decision: ACT

**Rationale:** The ANALYZE (loop 3) output is internally consistent, grounded in pre-committed refutation shapes, and routes correctly to CONCLUDE. All four hypotheses reached a definitive grade backed by evidence; the adversarial hypothesis (`?compromise-followup`) was explicitly addressed and refuted with a clean forward-window check. No hypothesis was silently dropped or graded inconsistently with its reasoning. The archetype claim (`opportunistic-scanner`) is anchored to three independent evidence layers (infrastructure reputation, username profile, forward-window clean result), not a single signal. No specific defect found; trusting the ANALYZE output and proceeding to final report.

---

## Final Investigation Report

**Alert:** SEC-2026-0412 — wazuh-rule-5710 (sshd: Attempt to login using a non-existent user)

**Disposition:** true_positive — no compromise

**Confidence:** high

**Matched archetype:** `opportunistic-scanner`

**Summary:**

203.0.113.45 (AS64496 Scanner-Hosting-Inc) executed a discrete SSH wordlist sweep against prod-webserver-01 between 09:11:47Z and 09:14:51Z on 2026-04-12. Three independent evidence layers converge on the opportunistic-scanner archetype with no dissenting signal:

1. **Source infrastructure** (loops 1–2): IP flagged in GreyNoise as `mass-ssh-scanner` / `ssh-brute` with 20 months of continuous activity; ASN is dedicated scanner-research hosting with no customer workloads and no historical DNS presence. Inconsistent with targeted or credential-stuffing infrastructure.

2. **Username profile** (loop 3): 20 distinct generic wordlist names (admin, root, ubuntu, pi, oracle, postgres, deploy, user, test, guest, operator, mysql, ftpuser, git, jenkins, hadoop, tomcat, nagios, www-data, ansible) matching default hydra/ncrack/patator distributions. Zero environment-specific names (no webapp-*, appuser-*, or prod-webserver-01 deploy-account patterns). Attempt rate 0.26/s is consistent with mass-scanner automation and directly inconsistent with the sub-0.05/s slow-drip profile of credential-stuffing tools.

3. **Outcome** (loop 3, forward window): Zero rule 5501/5715 authentication_success events from 203.0.113.45 to prod-webserver-01 or any other host in the full 40-min window (30 min preceding + 10 min forward). `?compromise-followup` is explicitly refuted by this check.

All pre-committed refutation checks for `?opportunistic-scanner` were attempted and failed to refute. This case is consistent with 14 prior true_positive/opportunistic-scanner closures against prod-webserver-01 from external scanner-class ASNs in the past 90 days, cited in ticket context.

Trust root ends at v-001 (external endpoint, no upstream process lineage accessible). Attribution cannot be extended further, but this does not affect disposition — the behavioral evidence is sufficient.

**Recommendation:** Close as true_positive / opportunistic-scanner. No compromise risk (zero successful authentications). Hygiene note: consider adding AS64496 (Scanner-Hosting-Inc) to firewall/fail2ban blocklist to suppress future sweeps from this ASN. No credential reset required (no successful auth, no env-specific targeting detected).

---

## Trust self-report

**Independent queries or re-analysis run:** None. The ANALYZE subagent output was accepted without re-running any grading work. The evidence facts (47 events, 20 usernames, 0.26/s rate, 0 forward-window successes) are reported directly in the GATHER output and the ANALYZE block summarizes them faithfully.

**Questionable grades:** No grades were questionable. The one area the subagent flagged as uncertain — applying `--` to `?targeted-brute-force` rather than `-` — is well-founded: the pre-committed refutation shape in HYPOTHESIZE (loop 3) explicitly states `--` if all usernames are generic wordlist entries with no env-specific naming, and the loop-3 data satisfies that condition cleanly. The subagent correctly applied the pre-committed shape rather than softening it post-hoc.

**Load-bearing part of the ANALYZE output:** The username profile assessment for `?opportunistic-scanner` (`++`) and `?targeted-brute-force` (`--`) was the decisive evidence in this loop — it resolved the ambiguity that loops 1 and 2 could not (both held at `+` for each hypothesis). The forward-window check refuting `?compromise-followup` was required for a high-confidence clean close and was correctly included. Without either of these, the routing to CONCLUDE would not be supportable.

**Archetype README caveat (inherited from subagent):** The subagent correctly noted it did not read the `opportunistic-scanner` archetype README directly and could not confirm `required_anchors` completeness. As the calling agent I also do not have access to the archetype README in this context. The validate_report hook (Tier 1 + Tier 2) will catch any required-anchor gap when report.md is written — this is the correct safety layer for that check, not the ANALYZE phase.
