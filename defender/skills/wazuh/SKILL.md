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

- `query` — Lucene against the alerts index. `--query`, `--start` /
  `--end` / `--window`, `--limit` (default 500), `--run-dir`
  (wraps stdout in salted untrusted-data delimiters), `--raw` (rarely
  needed; default already embeds first 3 events' `_source`).
- `health-check` — connectivity probe; the defender does not need to
  invoke this directly during a run.

Lucene is OpenSearch syntax: `rule.groups:sshd AND data.srcip:10.0.0.5`.

## Field reference

Per-field quirks and authentication query patterns are documented at:

- `soc-agent/knowledge/environment/systems/wazuh/auth-queries.md`
- `soc-agent/knowledge/environment/systems/wazuh/field-quirks.md`

Load them when authoring a query template that touches an unfamiliar
field.

## Fixture-backed mode

When the run is against a synthetic fixture from
`experiments/critic-architecture/fixtures/`, gather looks up tool
results in the fixture's `{NN}.tool_facts.json` keyed by
`{tool}:{param=value|...}` rather than hitting live Wazuh. The fixture
file documents the keying convention. The defender does not need to
care which mode it's in — gather hides the difference.
