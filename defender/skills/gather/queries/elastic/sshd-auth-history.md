---
id: elastic.sshd-auth-history
status: established
verb: esql
params: []
body_substitutions: [dst, end, src, start, user]
---

## Goal

SSH authentication history on the `logs-system.auth-*` data — accepted/failed
counts, auth-method distribution (`system.auth.ssh.method`), the source IPs,
the target hosts, and the first/last timestamps — over a time window. One
**capability** template for every auth-history question: alert-window sequence,
7-day baseline, "has this src ever reached this host", per-user or per-host
breakdowns. Keyword recall: sshd, ssh, OpenSSH, Accepted, Failed password,
publickey, auth, login, brute force, source.ip, user.name.

This is a **wide/superset** query — it carries every filter axis (`user`, `src`,
`dst`, `window`) and a broad aggregation. **You narrow it to the lead**: drop the
predicates the lead doesn't constrain, and drop the `BY` keys it doesn't ask for.
Fork to a different template only for a different *measurement*, never for a
different parameter.

## Query

ES|QL. Server-side aggregation — the result rows ARE the answer; never pull docs
and reduce them yourself.

```esql
FROM logs-system.auth-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND user.name == "${user}"
        AND source.ip == "${src}"
        AND host.name == "${dst}"
        AND event.outcome IS NOT NULL
| STATS accepted   = COUNT(*) WHERE event.outcome == "success",
        failed     = COUNT(*) WHERE event.outcome == "failure",
        first_seen = MIN(@timestamp),
        last_seen  = MAX(@timestamp)
        BY auth_method = system.auth.ssh.method, source.ip, host.name
| SORT accepted DESC, failed DESC
```

**Narrowing examples** (each is the query above with axes removed):

- *User baseline* ("dev.dana's normal auth"): keep `user.name`, drop the
  `source.ip`/`host.name` predicates; keep `BY source.ip, host.name` to see the
  spread.
- *src→host pair baseline* ("has 172.18.0.14 ever reached db-1"): keep
  `source.ip` + `host.name`, drop `user.name`; the `accepted`/`failed` scalars
  answer the zero-vs-nonzero question, so you can drop the `BY` entirely.
- *Method distribution only*: keep `BY auth_method`, drop `source.ip`/`host.name`
  from the `BY`.

Bind `${start}`/`${end}` as ISO-8601 strings (`"2026-05-25T13:38:00Z"`); ES|QL
compares them to `@timestamp` directly.

## Pitfalls

- **`event.outcome` is null on ~96% of this index** — session open/close, PAM,
  systemd-user, and cron lines all live in `logs-system.auth-*` with a null
  outcome (≈4.6M null vs ≈165K success / ≈92K failure cluster-wide). The
  `event.outcome IS NOT NULL` predicate is **mandatory**: without it the `BY`
  grouping floods with non-auth noise. (The conditional
  `COUNT(*) WHERE event.outcome == "..."` scalars are safe either way — nulls
  count toward neither — but the `BY` grouping is not.)
- **Auth method IS a structured field: `system.auth.ssh.method`** (keyword,
  `password` / `publickey`). Group on it directly — reconstructing it from the
  message text costs a `CASE` you don't need and throws the type away. It is
  **null where no auth method was ever reached**: `Invalid user` rejections and
  the `pam_unix(sshd:auth): authentication failure` lines both land in the null
  bucket, so the null separates "a credential was offered and refused" (a
  populated `password`/`publickey` row) from the rest — it does **not** tell the
  two null causes apart. Split those on `event.action`, which is populated on
  both: `ssh_login` on the OpenSSH-format lines (`Accepted` / `Failed` /
  `Invalid user`), `authentication_failure` on `pam_unix(sshd:auth)`, and
  `logged-on` / `logged-off` on the session lines.
- **Structured fields ARE populated and typed here** — `source.ip` (ip),
  `source.port` (long), `user.name` (keyword), `host.name` (keyword),
  `event.outcome` (keyword), `system.auth.ssh.event` (keyword: `Accepted` /
  `Failed` / `Invalid`), `system.auth.ssh.method` (keyword), `@timestamp` (date).
  Filter and group on them directly; do not GROK them out of `message`. (An older
  catalog note claimed OpenSSH fields were unparsed and message-only — that is
  stale for this cluster.) Populated on the **OpenSSH-format** lines; the
  `pam_unix(sshd:auth)` / session / cron lines in the same index carry a null
  `user.name` and a null `system.auth.ssh.*` pair. A null actor there is a
  parser gap, not an anonymous login — never report it as one.
- **`user.name` carries a leading space on `Failed password for invalid user`.**
  Observed on this cluster: the `Failed password for invalid user dev.dana …`
  line lands `user.name = " dev.dana"` while its sibling `Invalid user
  dev.dana …` line lands `"dev.dana"`. So `AND user.name == "${user}"` returns
  the `Invalid user` rows and **silently drops every `Failed password` row** —
  a confidently-wrong zero on exactly the brute-force evidence you were sent
  for. When the lead is about failures, either drop the `user.name` predicate
  and read the value off the `BY` (both variants surface as their own rows), or
  bind `TRIM(user.name) == "${user}"`.
- **Timing.** `MIN`/`MAX(@timestamp)` give the window edges; for a per-bucket
  rate add `BY bucket = DATE_TRUNC(1 hour, @timestamp)`.
