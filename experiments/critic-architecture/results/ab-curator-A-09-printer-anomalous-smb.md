# Arm A test: 09-printer-anomalous-smb

### Test defender (Arm A addendum)

- cost: $0.1090
- tokens: in=2 out=2202 cache_read=11896 cache_create=18937

```
### TRIAGE

**Claim:** An embedded MFP with zero SMB history is initiating periodic SMB sessions with no file I/O — a pattern inconsistent with any legitimate print/scan function and consistent with C2 beaconing or reconnaissance.

**Hypotheses considered:**

1. `?scan-to-folder-misconfiguration` — A new scan-to-folder target was configured, but scan-to-folder writes files; 30s idle-disconnect with no read/write rules this out. Lead: Check printer admin UI scan-destination config (even without recent logins, config may predate the 30d window).

2. `?firmware-behavior-change` — Firmware 5.18.2 introduced undocumented SMB network discovery or DFS probing. Lead: Diff 5.18.1→5.18.2 firmware changelogs beyond the release notes summary; check vendor security advisories for this model.

3. `?adversary-controlled-firmware` — Malicious firmware flashed via a brief admin UI session, supply-chain compromise, or unauthenticated vulnerability in the web UI. Firmware now uses the domain computer account to probe the file server. Lead: Audit admin web UI access logs beyond the 30d window; check for CVEs against PrintCo MFP-7250 web interface.

4. `?kerberos-ticket-relay` — The printer's AD computer account credentials were captured and are being replayed from a separate compromised host spoofing the printer's static IP. Lead: Correlate ARP table / DHCP lease for `printer-floor3-04`'s IP against the MAC observed on fileserver-prod-01 SMB sessions; check for ARP cache poisoning on the floor-3 segment.

5. `?C2-beacon-via-MFP` — Device is compromised (firmware or OS layer) and using the printer's legitimate Kerberos identity to beacon fileserver-prod-01 — possibly staging SMB relay, testing connectivity before exfiltration, or waiting for a file to appear. Lead: Inspect full 6h netflow for outbound connections from the printer's IP to any non-internal destination.

6. `?domain-policy-push` — A new GPO applied to the printer's OU triggered SMB enumeration. Lead: Check AD change log for GPO modifications to the OU containing this computer account in the last 7 days.

**Disposition: `escalate`**

The negotiate-then-idle pattern at regular intervals with no file I/O is the behavioral fingerprint of a beacon, not any legitimate MFP function. The device is a closed, unattestable black box.

**Load-bearing assumption:** The SMB connections genuinely originate from the physical printer hardware. If ARP/IP spoofing is occurring, the printer itself is clean and the threat actor is elsewhere on the floor-3 segment — a different (and more tractable) incident scope.

---

### ADDENDUM USE

Rules **3** and **4** were decisive. The vendor release note stating "no networking changes vs. 5.18.1" is closed-firmware telemetry — it describes what PrintCo *intended* to ship, not what the executing image is actually doing; it does not rule out a firmware supply-chain or web-UI compromise (rule 3). Rule 4 sharpened this: the absence of SMB anomaly *signal* from a device with no agent, no attestation API, and no console access bounds observability, not causation — so the "no file I/O yet" observation cannot be read as benign. Together these two rules pushed `?adversary-controlled-firmware` to the top of the hypothesis stack and justified escalation despite surface indicators (valid Kerberos, current firmware, no visible file access) that might otherwise anchor toward benign.
```
