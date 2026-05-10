```yaml
gather:
  - id: l-001
    loop: 1
    name: authentication-history
    target: e-001
    predictions:
      - {id: lp1, if: "≥1 successful SSH login (rule group authentication_success) from 172.22.0.10 within 60s forward of 2026-04-17T10:30:06.326Z", read_as: "success-after-failure", advance_to: CONCLUDE}
      - {id: lp2, if: "no forward success AND (srcip=172.22.0.10, srcuser=healthcheck) cluster_count ≥ 3 AND max_cluster_size ≤ 3 over the 1h backward window", read_as: "periodic-probe-cadence", advance_to: HYPOTHESIZE}
      - {id: lp3, if: "no forward success AND cluster_count < 3 OR max_cluster_size > 3", read_as: "non-periodic-or-bursty-shape", advance_to: HYPOTHESIZE}
```

Selected lead: `authentication-history` — pull all sshd auth events (success + failure rule groups) for srcip 172.22.0.10 over the 1h window ending at alert time, plus a 60s forward window for successful-login follow-up. Answers compromise axis (forward success) and cadence shape for the monitoring-probe anchor pathway simultaneously.

Pitfalls:
- l-001: success-after-failure check must include rules 5501 and 5715 (both authentication_success). Missing either mask-routes a potential compromise into the benign fast-path.
- l-001: cadence clustering uses a 10s retry gap — natural sshd retry bursts (client TCP retransmit, key renegotiation) inflate cluster size and disqualify a genuinely periodic probe. Verify clustering rule was applied, not raw event count.
- l-001: srcip 172.22.0.10 is the monitoring host — other usernames from the same srcip in the window are expected and must NOT be folded into the (srcip, srcuser) pair stats; scope the cadence query to the pair, not the srcip alone.
