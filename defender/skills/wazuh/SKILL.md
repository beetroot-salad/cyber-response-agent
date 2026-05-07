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
  (persists raw payload under `{run_dir}/gather_raw/` and wraps stdout
  in salted untrusted-data delimiters), `--raw` (rarely needed; default
  already embeds first 3 events' `_source`).
- `health-check` — connectivity probe; the defender does not need to
  invoke this directly during a run.

Lucene is OpenSearch syntax: `rule.groups:sshd AND data.srcip:10.0.0.5`.

Working query examples + field-level pitfalls live with the templates
under `defender/skills/gather/queries/wazuh/`. Reach for those when
authoring or grepping for a Wazuh measurement; this SKILL covers only
the system surface.
