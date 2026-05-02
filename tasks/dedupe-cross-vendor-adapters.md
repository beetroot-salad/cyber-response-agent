---
title: Decide whether to dedupe cross-vendor adapter boilerplate (jscpd findings)
status: backlog
groups: code-quality, refactor, adapters
---

`jscpd` (in CI's `code-smells` job) reports several near-duplicate blocks
between vendor adapter CLIs. Whether to dedupe is a **policy question**, not a
straight refactor — see the existing decision in
[Adapter contract bases stay generic](memory: feedback_generic_contract_bases).

## Current jscpd findings

| Lines | Files |
|---:|---|
| 38 | `scripts/tools/playground_ticket_cli.py` ↔ `scripts/tools/stub_ticket_cli.py` |
| 17 | `scripts/tools/playground_ticket_cli.py` ↔ `scripts/tools/wazuh_cli.py` |
| 14 | `scripts/tools/elastic_cli.py` ↔ `scripts/tools/wazuh_cli.py` (block 1) |
| 13 | `scripts/tools/elastic_cli.py` ↔ `scripts/tools/wazuh_cli.py` (block 2) |
| 14 | `scripts/tools/wazuh_cli.py` ↔ `tests/test_siem_cli_wrapping.py` (test mirrors prod intentionally?) |

Smaller (<13L) clones in tests omitted — extract test helpers as encountered.

## The tension

The two ticket adapters (`playground_ticket_cli` is a fully-stateful FastAPI
client; `stub_ticket_cli` is a reference-implementation stub) share argparse
glue and JSON envelope shape. Same for the SIEM adapters
(`wazuh_cli`/`elastic_cli`) — both wrap an OpenSearch-shaped index query
behind the AdapterContract surface.

Per the standing decision (`feedback_generic_contract_bases`), the ABC base
in `schemas/adapter_contract.py` only declares **universal** ops; vendor
families' verbs (close_ticket, block_ip) live in concrete adapters. Pulling
boilerplate into a shared `_adapter_cli_skeleton.py` would:

- **Pro:** delete ~80L of duplication; one place to fix CLI envelope bugs
- **Con:** couples ticket and SIEM adapters to a shared helper; new vendor
  adapters now have to learn the helper before standing one up; the "stubs are
  independently readable" property (called out in
  `knowledge/signatures/_template/README.md`) erodes

## Suggested resolution

Dedupe **within** a vendor family, not **across** families:

- `_ticket_cli_helpers.py` shared by `playground_ticket_cli` + `stub_ticket_cli`
  (38L block — clear win, both are ticket adapters)
- Leave SIEM adapters alone for now (the 14+13L duplication is small enough
  that a future Splunk/Sentinel adapter will tell us whether the pattern is
  load-bearing or accidental)
- Do **not** factor across SIEM↔ticket families

Drop this task when the ticket-helper extraction lands.
