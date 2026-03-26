---
name: authentication-history
data_tags: [auth-events]
---

## Goal

Retrieve and characterize authentication patterns for a given entity
(IP, user, or host) over a time window.

## What to Characterize

- **Timing pattern**: Classify as periodic (regular intervals — note
  interval and variance), burst (clustered in short window — note
  window and count), or irregular (no clear pattern).
- **Username diversity**: Single username, small set (<5), or many
  distinct usernames. Note if any match known patterns from
  environment/context/identity-patterns.md (service accounts, admin accounts).
- **Success/failure sequence**: All failures, all successes, or
  mixed. If mixed, note the temporal relationship (success after
  failures is a critical signal).
- **Volume and rate**: Total event count, events per hour, and
  whether rate is constant or changing.
- **Source context**: Cross-reference source IP against
  environment/context/ip-ranges.md. Note if internal/external, known subnet.

## Common Pitfalls

- NAT can collapse multiple sources into one IP. Check if srcip
  is a known NAT gateway (see environment/context/ip-ranges.md).
- Failed auth for non-existent users vs existing users are different
  signals (different SIEM rules, different threat implications).
- Cached/stale credentials cause periodic failures after password
  rotation — looks like low-frequency brute force but isn't.
- Time windows matter: always state the window you queried.
  Missing events outside your window can change the interpretation.
