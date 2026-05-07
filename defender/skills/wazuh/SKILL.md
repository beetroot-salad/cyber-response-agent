---
name: defender-wazuh
description: Wazuh environment reference for the defender — what data Wazuh holds, the CLI shape, and where the production adapter lives.
---

Wazuh is the org's primary SIEM. Authentication events, file integrity
monitoring, syscall audit, and rule-correlated alerts all surface here.

## CLI

The defender and gather dispatch Wazuh queries through the production
adapter at `soc-agent/scripts/tools/wazuh_cli.py`:

```bash
python3 soc-agent/scripts/tools/wazuh_cli.py query \
  --query '<Lucene>' \
  --window 2h \
  --run-dir {run_dir}
```

Common subcommands:

- `query` — search the alerts index. `--query` is polymorphic:
  - **Lucene string** (`rule.id:5710 AND agent.name:web-03`) — the CLI
    wraps it in a bool with the time-range filter from `--start` /
    `--end` / `--window`. Best for "show me events" leads.
  - **JSON search body** (`'{"query": {...}, "aggs": {...}}'`) — the
    agent owns the entire body, including time filtering. Use this
    whenever the lead asks for counts, top-N, or distributions over a
    population that may exceed `--limit` — server-side aggs return true
    totals over the full match set, while the default Count Breakdown
    is a post-`--limit` sample.
  Other flags: `--limit` (default 500, max 10000; use `0` for
  count+aggs only), `--run-dir` (persists raw payload under
  `{run_dir}/gather_raw/` and wraps stdout in salted untrusted-data
  delimiters), `--raw` (rarely needed; default already embeds first 3
  events' `_source`).
- `health-check` — connectivity probe; the defender does not need to
  invoke this directly during a run.

Lucene is OpenSearch query_string syntax: `rule.groups:sshd AND
data.srcip:10.0.0.5`. JSON bodies use the standard OpenSearch search
DSL — `query.bool.must` / `query.bool.filter`, `aggs.{name}.terms` /
`date_histogram` / `cardinality`, etc.

Working query examples + field-level pitfalls live with the templates
under `defender/skills/gather/queries/wazuh/`. Reach for those when
authoring or grepping for a Wazuh measurement; this SKILL covers only
the system surface.
