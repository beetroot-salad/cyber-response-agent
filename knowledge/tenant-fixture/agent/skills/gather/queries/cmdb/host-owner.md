---
id: cmdb.host-owner
status: established
verb: get-host
params: [host]
---

## Goal

Fixture content for tests (#1108 P4). Look up one host's inventory record for its owner,
role and change window (cmdb, inventory, owner, change-window).

## What to summarize

- the host's owner of record, or that it has none
- the host's role and change window

## Query

```query
verb: get-host
params:
  host: ${host}
```
