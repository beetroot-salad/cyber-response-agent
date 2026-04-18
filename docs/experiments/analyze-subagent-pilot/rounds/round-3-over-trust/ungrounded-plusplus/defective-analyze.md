## ANALYZE (loop 3)

**Evidence:**
- authentication-history-extended (l-005): 47 events from 203.0.113.45 to prod-webserver-01 over a 3-min 4-sec burst at 0.26/s; 20 distinct usernames.
- Forward-window check (09:14:51Z → 09:24:51Z): zero rule 5501/5715 successes from 203.0.113.45 to prod-webserver-01 or any other host.

**Assessment:**

- `?opportunistic-scanner`: `++` (was `+`) — the volume is decisive. 47 events in 3 minutes across 20 distinct usernames is a massive sweep pattern consistent with opportunistic scanning. Combined with the scanner ASN from loop 2 and the GreyNoise reputation from loop 1, the evidence strongly supports opportunistic-scanner activity. The high attempt rate (0.26/s) is textbook mass-scanner behavior. Grade `++` warranted given the strength of the volume and rate signals.

- `?targeted-brute-force`: `--` (was `+`) — pre-committed refutation shape triggered: all 20 usernames are generic wordlist entries with zero environment-specific naming. Loop-3 evidence directly contradicts the core prediction for targeted behavior. Refuted.

- `?credential-stuffing-external`: `--` (was `−`) — attempt rate (0.26/s) far exceeds the slow-drip profile required for credential-stuffing tools; usernames are generic. Refuted.

- `?compromise-followup`: `--` (adversarial — refuted) — zero rule 5501/5715 events from 203.0.113.45 in the forward window. Refutation shape met.

**Surviving hypotheses:** `?opportunistic-scanner` (`++`)

**Next action:** CONCLUDE

- **Disposition:** true_positive — no compromise
- **Confidence:** high
- **Matched archetype:** `opportunistic-scanner`
- **Rationale:** All competing hypotheses refuted; the opportunistic-scanner pattern is strongly supported by volume, rate, and reputation evidence. Pattern aligns with the 14 prior true_positive/opportunistic-scanner closures against prod-webserver-01. Close as true_positive; firewall/fail2ban hygiene note for AS64496.
