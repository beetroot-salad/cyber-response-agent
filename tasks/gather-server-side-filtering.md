---
title: Gather query templates over-return — push filtering server-side
status: todo
groups: defender, gather, elastic
---

**Context.** On the 2026-05-31 live v2 run (`20260531T0745Z-live-sshd-success`),
the `loopback-ssh-failure-prior` lead query returned **6011 hits** for what
should have been a handful. The elastic query used
`message:*"Failed password"* AND (message:*"127.0.0.1"* OR message:*"::1"*)` —
substring-wildcard clauses over the free-text `message` field that do **not**
bind as an effective server-side filter. The whole auth stream (cron, pam,
accepted-password lines) came back; the gather subagent then hand-counted one
genuine loopback failure out of 6011 noisy records. That noisy return is also
what eroded the main loop's trust in the summaries and triggered the
`gather_raw` spelunking (principle-5 violation).

**Mitigation already shipped (this session).** The *symptom* is contained:
`gather_exec.py` now caps the pass-through (count + samples + on-disk path +
a jq nudge) so the subagent filters the persisted payload with jq/grep
instead of hand-counting a flooded context. See the gather SKILL §3
"Large payloads" block. The main loop is also now blocked from reading
`gather_raw` (hook `block_main_loop_raw_access.py`).

**Root cause still open.** The query should not over-return in the first place.

- Prefer structured field filters over `message` substring wildcards:
  `event.outcome:failure AND source.ip:"::1" AND process.name:"sshd"` instead
  of `message:*"Failed password"*`. Audit the elastic query templates under
  `defender/skills/gather/queries/elastic/` for the same anti-pattern.
- Consider a gather §3 smell-test rule: when `total` greatly exceeds what a
  narrow lead expects, treat it as a mis-bound filter (re-query on structured
  fields) — the dual of the existing empty-result smell test.
- Check whether the elastic adapter / index mappings expose `event.outcome`,
  `source.ip`, `user.name` as keyword fields for exact filtering (the run
  showed these present as nested fields in the hits).

**Deferred from:** 2026-05-31 live-run review (fallback chosen over query-layer
fix for that session).
