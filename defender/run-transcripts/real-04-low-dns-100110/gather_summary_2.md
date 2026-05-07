## Queries run
- id: wazuh.dns-query-history
  params:
    rule_id: "100110"
    agent: "target-endpoint"
    window: "7d"
    aggregations: ["by_domain", "by_hour", "cardinality"]

## Characterization

**All distinct dns_domain values in rule 100110 fires:**
- 636 unique DNS domains queried over the 7-day window
- Query pattern dominated by high-entropy subdomains (DGA-like generation)
- Parent domain aggregation reveals 29 distinct registrable domains

**Query count per domain/subdomain:**
- dynamicupdate.net subdomain variants: 588 total queries (27.8%)
  - Example high-entropy subdomains: `01zbcwszdlq2pecezngh.dynamicupdate.net`, `099chzp6hm36rmbtxq.dynamicupdate.net` (1 query each)
- staging-cdn{1-20}.xyz (20 separate registrable domains): 1,240 total (41.7%)
  - Uniform distribution: exactly 62 queries per cdn domain
- exfil.example.net: 94 queries (4.5%)
  - Contains hex-encoded payloads: `hostname=target-endpoint&uid=0`, `username=admin&password=secret`
- ghostnebula.net (from original alert): 6 queries (0.3%)
  - Subdomain examples: `7ARacKkP58qcgLUB.api.ghostnebula.net`, `c3Vjp9MCHnfKREE5.api.ghostnebula.net`

**Parent domains (registrable domain under each high-entropy subdomain):**
1. dynamicupdate.net: 588 queries (27.8%)
2. staging-cdn{1-20}.xyz: 1,240 queries (41.7%, 62 per domain)
3. exfil.example.net: 94 queries (4.5%)
4. ghostnebula.net: 6 queries (0.3%)
5. account-verify.club: 42 queries (2.0%)
6. free-download.xyz: 42 queries (2.0%)
7. secure-login.top: 42 queries (2.0%)
8. update-service.buzz: 42 queries (2.0%)
9. eventloop-cdn.net: 8 queries (0.4%)
10. trackpixel-io.com: 8 queries (0.4%)
... (19 total parent domains identified)

**Temporal clustering — when did each parent domain's queries occur:**
- **dynamicupdate.net**: continuous activity 2026-04-30 12:00Z through 2026-05-07 12:00Z, peaks on 2026-05-02 and 2026-05-07
- **staging-cdn{1-20}.xyz**: same 7-day span, consistent queries across all 6h buckets
- **exfil.example.net**: confirmed active during 2026-05-02 through 2026-05-07 (peak intervals align with dynamicupdate.net)
- **ghostnebula.net**: sparse activity (6 total), distributed across the 7-day window but with low density

Temporal buckets (6h intervals):
- 2026-04-30 12:00-18:00Z: 126 queries (start of window)
- 2026-05-01 00:00-18:00Z: 214 queries (ramping up)
- 2026-05-02 00:00-23:59Z: 454 queries (first major peak)
- 2026-05-03 00:00-23:59Z: 278 queries
- 2026-05-04 00:00-17:59Z: 240 queries (tail-off at 18:00Z)
- 2026-05-05 00:00-17:59Z: 325 queries (recovery, falls to 4 at 18:00Z)
- 2026-05-06 12:00Z: 76 queries (isolated activity)
- 2026-05-07 00:00-12:00Z: 399 queries (second major peak, most recent)

**Simultaneous C2 channels vs sequential:**
- **SIMULTANEOUS**: dynamicupdate.net, exfil.example.net, staging-cdn*.xyz, and ghostnebula.net all active in overlapping time windows
  - No temporal segregation by parent domain
  - All four parent domain families firing during 2026-05-02 through 2026-05-07
- **Characteristic**: scripted/scheduled activity pattern (not interactive manual C2)
  - Uniform 62-query pattern per staging-cdn domain suggests automated batch queries
  - Gaps on 2026-04-04 18:00Z and 2026-05-06 00:00-06:00Z, 18:00Z indicate scheduled pause/failure, not network latency
  - **Interpretation**: multi-channel command & control with parallel exfiltration paths (account credentials, system info encoded in DNS subdomains)

## Raw payload
gather_raw/2.json (2,112 matching events, 636 unique domains)
