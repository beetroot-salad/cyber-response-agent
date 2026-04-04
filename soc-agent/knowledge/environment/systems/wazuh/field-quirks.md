---
tags: [wazuh, fields, gotchas]
---

# Wazuh: Field Quirks

Non-obvious field semantics that cause wrong queries. Even a familiar analyst
may not recall these after time away. This section closes the gap — it
provides the "what" so you don't have to rediscover it each time.

## Authentication Events — Gotchas

- **Username field splits by event source:**
  SSH events → `data.srcuser` (the user attempting login)
  Windows AD events → `data.dstuser` (NOT `data.srcuser` — Wazuh maps
  AD's TargetUserName to dstuser). Using srcuser for AD queries returns nothing.

- **No auth type for SSH:** Wazuh SSH events don't carry an equivalent
  of Windows logon_type. You cannot distinguish interactive from
  key-based SSH auth from Wazuh fields alone.

- **NTSTATUS codes in Windows auth:** `data.win.eventdata.status` and
  `data.win.eventdata.subStatus` are hex codes, not human-readable.
  Common: 0xC000006D = bad username/password, 0xC0000234 = locked out.

- **agent.name is the target host:** Not the Wazuh agent software version.
  This is where the event was collected — the destination of the auth attempt.

## General Field Gotchas

- **data.* prefix required:** All extracted log fields live under `data.`.
  Raw syslog is in `full_log`. Rule metadata is in `rule.*`.

- **Timestamp is ISO 8601 UTC:** The `timestamp` field is always UTC.
  The `@timestamp` field (if present from the indexer) may differ by
  pipeline delay. Use `timestamp` for investigative time comparisons.

- **rule.id is a string:** Even though rule IDs look numeric, they're
  stored as strings in the index. Query `rule.id:"5710"`, not `rule.id:5710`
  as integer — most query interfaces handle this, but programmatic
  access may need explicit string comparison.
