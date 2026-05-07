## Queries run
- id: wazuh.auth-events
  params: {host: target-endpoint, srcip: 172.22.0.10, window: 24h}

## Characterization

- **Full set of usernames attempted:** 3 distinct users
  - nagios: 186 attempts (54%)
  - zabbix: 97 attempts (28%)
  - healthcheck: 61 attempts (18%)

- **Count of attempts:** 344 total SSH authentication failures (rule 5710: "sshd: Attempt to login using a non-existent user")

- **Timing spread:** Highly periodic/scheduled, not bursty
  - Consistent rate of ~22 events/hour during active periods
  - 2026-05-06T14:00–T18:00: 87 events across 5 hours (ramp-up then plateau)
  - Gap 2026-05-06T18:00–2026-05-07T02:00: 12 events (8 hours, reduced activity)
  - 2026-05-07T02:00–T13:00: 257 events across 12 hours (steady ~21–24/hour)
  - Distribution is flat during active hours, indicating automated probe with consistent request rate

- **Port(s) used:** 336 unique source ports (ephemeral port range, consistent with OS port allocation during repeated connection attempts)
  - Top repeated: ports 34606, 33620, 46892, 49792, 46308, 33350, 55134, 53700 (each 2 events)
  - Most ports appear exactly 1 time
  - Pattern: one attempt per unique port, indicating fresh connection per probe attempt

## Raw payload
gather_raw/0.json
