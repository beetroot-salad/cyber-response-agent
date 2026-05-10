# Arm B test: 09-printer-anomalous-smb

### Test defender (Arm B addendum)

- cost: $0.1049
- tokens: in=2 out=1916 cache_read=11896 cache_create=18977

```
### TRIAGE

**Claim:** A domain-joined embedded printer is making structurally anomalous SMB beacon-pattern connections — negotiate-and-drop, no file operations, 90-day zero baseline — which is inconsistent with any legitimate MFP function and consistent with a compromised firmware implant using the device as a network beachhead.

**Hypotheses and leads:**

1. **?firmware-implant / adversary-controlled-printer** — Attacker exploited the admin web UI (authenticated or via a pre-auth vuln) at some point before the 30-day log window, installed a persistent implant, and is using the printer's domain Kerberos credentials for SMB reconnaissance or C2 keepalive.
   - *Lead:* Pull the admin UI access log beyond 30 days; check for logins around the firmware 5.18.1→5.18.2 upgrade timestamp.

2. **?kerberos-ticket-theft / lateral-movement-pivot** — An attacker on the same VLAN is ARP-spoofing the printer's static IP, using a harvested computer-account TGS to authenticate to the fileserver, and the printer itself is unaffected.
   - *Lead:* Compare ARP table entries on the distribution switch for the printer's MAC against the expected static assignment over the 6h window.

3. **Firmware bug (SMB connectivity probe)** — A defect in 5.18.2 triggers periodic SMB negotiate attempts against a misconfigured "scan to folder" target. Release notes claim no networking changes, but that is weak exculpation for stability defects.
   - *Lead:* Check PrintCo support KB and field service bulletins for 5.18.x SMB regression reports; ask vendor TAM directly before ruling out.

4. **Legitimate scan-to-folder misconfiguration** — A user configured a scan destination pointing to fileserver-prod-01 that fails authentication and retries.
   - *Lead:* Inspect the printer admin UI scan-destination config (web UI snapshot) for any configured SMB targets; 30s idle-disconnect is too short for a retry-backoff pattern, making this unlikely.

5. **Network scanner / asset discovery tool** — An internal scanner is sourcing connections through the printer's IP via a NAT or routing anomaly.
   - *Lead:* Verify netflow for the printer's VLAN segment — confirm all 23 source connections have the printer's MAC as the L2 origin.

**Disposition: `escalate`**

**Load-bearing assumption:** The SMB connections genuinely originate at the printer's physical Ethernet interface (not ARP/MAC-spoofed from another host). If that holds, the negotiate-and-drop pattern with no file operations has no plausible legitimate MFP explanation, and the device cannot be forensically examined — no agent, no console, no attestation. Escalation to vendor IR + network isolation is the only safe path.

---

### ADDENDUM USE

Addendum **#1** directly shaped hypothesis ordering: the firmware release notes state "no networking changes vs 5.18.1," but that claim is weak evidence for a stability defect — embedded firmware defects are systematically under-indexed in public advisories and release notes. This kept the firmware-bug hypothesis live rather than letting the vendor's own documentation quietly eliminate it. Addendum **#2** enforced causal discipline: the co-occurring signals here (valid Kerberos ticket + negotiate-only SMB + zero baseline) demand a single upstream cause before branching — which is why the ARP-spoof and firmware-implant hypotheses are kept structurally separate and ordered by testability, not collapsed into a vague "compromise or misconfiguration" fork.
```
