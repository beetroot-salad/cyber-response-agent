---
id: elastic.keycloak-auth-events
status: established
verb: esql
params: []
body_substitutions: [end, start, token]
---

## Goal

Keycloak IdP authentication events (`logs-keycloak.events-*`) over a window — the
login / login-error / logout mix from the realm's OIDC event stream, and which
identity or client-IP drove them. Use to surface credential brute-forcing against the
identity provider, an anomalous login from an unexpected address, or a spike of
`LOGIN_ERROR`. Keyword recall: keycloak, IdP, OIDC, realm, `LOGIN_ERROR`, LOGIN,
LOGOUT, username, ipAddress, clientId, grant_type, single sign-on, identity provider,
`org.keycloak.events`.

**Wide/superset** — `${token}` scopes one identity/client/IP mentioned in the event;
drop it for the realm-wide type mix. Narrow by adding a second `message LIKE` for a
specific `clientId=` or `ipAddress=`.

## Query

ES|QL. The event detail is a flat `key="value"` string in `message`; parse it with
`LIKE`, not structured fields.

```esql
FROM logs-keycloak.events-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND loggerName == "org.keycloak.events"
        AND message LIKE "*${token}*"
| STATS events      = COUNT(*),
        logins      = COUNT(*) WHERE message LIKE "*type=\"LOGIN\"*",
        login_error = COUNT(*) WHERE message LIKE "*type=\"LOGIN_ERROR\"*",
        logouts     = COUNT(*) WHERE message LIKE "*type=\"LOGOUT\"*",
        first_seen  = MIN(@timestamp),
        last_seen   = MAX(@timestamp)
```

**Narrowing examples:**

- *Realm-wide type mix* ("what is the IdP seeing"): set `${token}` empty (or drop the
  `message LIKE "*${token}*"` line); the counters give the login/error/logout shape.
- *One identity's logins* ("did svc.backups authenticate off-hours"): set `${token}`
  to `username="svc.backups"`.
- *Brute-force from one client* ("errors from 172.18.0.x"): set `${token}` to
  `ipAddress="172.18.0.x"` and read `login_error`.

## Pitfalls

- **`loggerName == "org.keycloak.events"` is mandatory.** The same data stream carries
  Keycloak's server lifecycle log (`KC-SERVICES…` startup/import lines) under other
  loggers; without this predicate the counts are dominated by boot noise. The auth
  events are exactly the rows this logger emits.
- **`host.name` is `soc-playground`, not a per-host identity** — the events are tailed
  from the Keycloak container's log volume on the VPS, so every row shares the host.
  Attribute by `username=` / `ipAddress=` inside `message`, never by `host.name`.
- **Escaped quotes.** The type marker is literally `type="LOGIN"` *with* the quotes, so
  the predicate is `message LIKE "*type=\"LOGIN\"*"`; matching `*LOGIN*` also catches
  `LOGIN_ERROR` and `username` substrings.
- **Sparse unless the IdP is exercised.** Baseline does not drive interactive Keycloak
  logins, so a quiet window legitimately returns near-zero — read an empty result as
  "no IdP auth activity", not as a dark stream.
