---
id: wazuh.file-integrity-changes
status: established
---

## Goal

Retrieve file integrity monitoring (FIM / syscheck) events from the
Wazuh alerts index over a time window, optionally filtered by host
and/or path. Surfaces files that were `added`, `modified`, or `deleted`
on disk — the syscheck daemon writes these as `rule.groups:syscheck`
fires (rule ids 550 modified, 553 deleted, 554 added, plus FIM-related
escalations). Used to answer "did anything change on host X?" and
"who/what touched /etc/passwd lately?" style leads.

## What to summarize

- Total FIM event count over the window
- Distinct files touched (count + top `syscheck.path` values)
- Event-type breakdown — added vs modified vs deleted (rule.id 554 / 550 / 553)
- Host diversity (count of distinct `agent.name`, top hosts)
  — when not already bound as a filter
- Timing distribution (burst around a known event, steady churn,
  off-hours spikes)
- Notable paths — anything under `/etc/`, `/root/`, `/usr/bin/`,
  `/usr/sbin/`, ssh authorized_keys, cron dirs

## Query

Default Lucene form for "show me FIM events":

```bash
python3 defender/scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:syscheck${host_clause}${path_clause}' \
  --window ${window} \
  --run-dir ${run_dir}
```

`${host_clause}` is `" AND agent.name:<host>"` when filtering by host,
empty otherwise. `${path_clause}` is `" AND syscheck.path:<path>"` (or
a wildcard like `syscheck.path:\\/etc\\/*`) when scoping to a path
prefix. Bind whichever the lead requires; leave the rest empty.

For "which files were touched, and how often" leads, the default
breakdown does not aggregate by `syscheck.path`. Pass a JSON body with
a path aggregation:

```bash
python3 defender/scripts/tools/wazuh_cli.py query \
  --query '{
    "query": {
      "bool": {
        "must":   [{"query_string": {"query": "rule.groups:syscheck${host_clause}"}}],
        "filter": [{"range": {"timestamp": {"gte": "${start}", "lte": "${end}"}}}]
      }
    },
    "aggs": {
      "by_path":  {"terms": {"field": "syscheck.path", "size": 50}},
      "by_event": {"terms": {"field": "rule.id",       "size": 5}},
      "by_hour":  {"date_histogram": {"field": "timestamp", "fixed_interval": "1h"}}
    }
  }' \
  --limit 5 \
  --run-dir ${run_dir}
```

## Common pitfalls

- Package upgrades produce large bursts of `modified` under `/usr/bin`,
  `/usr/lib`, `/etc` — cross-reference with package manager logs
  before reading malicious intent.
- syscheck only reports paths under the agent's monitored directories
  (`<directories>` blocks in `ossec.conf`); absence of an event is
  *not* evidence the file is unchanged unless the path is in scope.
- `syscheck.diff` is only populated when `report_changes="yes"` is set
  on the directory block — many deployments don't enable it.
- The `whodata` audit linkage (`syscheck.audit.user.name`) requires the
  Linux audit subsystem; on hosts without it, FIM events have no actor.
- Real-time FIM has a small batching delay; tight time windows around
  an alert may miss the corresponding syscheck fire by a few seconds.

## Baseline

When the lead asks whether a burst is unusual (e.g. "is this
modification volume normal for this host?"), shift the window 7 days
earlier with the same host binding and compare event count, distinct
path count, and event-type ratio.
