**Selected lead:** `authentication-history` — retrieve source IPs and auth outcomes for SSH sessions to container `17bc2dde3fb0` port 22 in the 16:50Z–17:16Z window. The 18 rule-100002 co-fires are uncharacterized on source identity; the composition rule requires knowing whether those concurrent SSH sessions originate from known internal/CI addresses or external/unknown IPs before the escalation report can fully describe the blast-radius picture. This lead does not reopen the h-001/h-002 runc mechanism fork — that fork is exhausted per ANALYZE loop 2. Lead-level prediction: if SSH source IPs are exclusively private-range addresses matching known internal CI/operator subnets → severity-context consistent with CI environment activity; if any external or unrecognized IP is among the sources → escalation note strengthens.

**Pitfalls:**
- `authentication-history`: SSH source IPs characterize who accessed the container via sshd, not who invoked runc on the host — this is severity-enrichment for the escalation report, not a discriminator for h-001/h-002. A clean result (all-internal IPs) does not resolve lc1 or change the CONCLUDE disposition.
- `authentication-history`: Wazuh ingests Falco syscall events; in-container sshd PAM auth logs may not flow to the same index. An empty result must be treated as a data-gap (data source doesn't cover this auth path), not evidence that no SSH auth occurred.

```yaml
mode: no-fork
selected_lead: authentication-history
loop_n: 1
```
