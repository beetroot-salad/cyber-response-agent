---
name: rule-100110-multi-domain-rotation-ratio
description: When rule-100110 1h fire-count exceeds 7d query-count to the alerted parent domain, the implication is multi-domain rotation — strong C2 signal that obviates further benign-tool checks.
case: real-04-low-dns-100110
type: good
expected_outcome: all checks should pass (verdict GOOD)
---

When triaging rule-100110 (high-entropy DNS subdomain), you sometimes
spent multiple leads investigating whether a known telemetry tool could
account for the pattern, even after evidence already implied multi-domain
rotation. Telemetry tools query a small set of stable parent domains;
multi-domain rotation is the C2/tunneling fingerprint.

Recovery path: early in PLAN, compute the ratio between recent rule-100110
fire-count (1h) and the 7d query-count to the *alerted* parent domain
across the same host. A ratio >2 implies the host is querying additional
high-entropy subdomains under *other* parent domains — i.e., domain
rotation. When that ratio holds, elevate `?c2-dns-tunneling` and
de-prioritize the `?benign-tool-telemetry` hypothesis without expending
further leads on telemetry-tool fits. The ratio is computed from data
already gathered for the standard fork; this is a disposition shortcut,
not a new lead.
