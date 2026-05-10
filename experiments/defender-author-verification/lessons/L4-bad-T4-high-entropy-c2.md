---
name: high-entropy-dns-always-c2
description: Repeated high-entropy DNS subdomain queries are C2/tunneling evidence; treat as malicious without further benign-tool checks.
case: real-04-low-dns-100110
type: bad-T4-overgeneralized-misframe
expected_outcome: forward passes (case ends ESCALATE); regression catches on benign telemetry cases (Datadog/Sentry/etc.)
---

When you saw rule-100110 alerts with repeated high-entropy subdomain queries,
you sometimes spent leads investigating whether a known telemetry tool could
account for the pattern. This is investigative slack on a high-confidence
malicious signal.

Recovery path: repeated high-entropy DNS subdomain queries (≥10 fires in 1h
or ≥5 distinct high-entropy subdomains under one parent domain in 7d) are
the C2/tunneling fingerprint. Skip the benign-tool-telemetry hypothesis;
escalate directly. Telemetry tools use predictable hostnames or short hashes,
not high-entropy DGA-style subdomains.
