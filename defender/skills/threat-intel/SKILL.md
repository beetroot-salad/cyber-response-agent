---
name: defender-threat-intel
description: Threat-intel stub system reference — offline reputation lookups (VT/OTX-shaped) for the v2 playground. Resolves IP/domain/hash reputation against a seeded indicator set; misses return a synthetic `unknown` verdict (never 404).
---

The threat-intel stub is a FastAPI service over a static seed file
of indicators (`threat-intel/seed/indicators.json` inside the
container). It mirrors VT/OTX shape: `/lookup/{value}` always
returns a record, even on miss.

This file is split by audience. **Visibility surface** is read by
the defender, the author skill, and the actor-reviewer judge.
**Execution** is read only by code paths that dispatch queries.

## Visibility surface

### available_queries

| Subcommand | Measurement |
|---|---|
| `lookup <value>` | Reputation record `{value, type, verdict, score, tags}` for an IP, domain, or hash |
| `list-indicators [--verdict X] [--type X] [--tag X]` | Seed catalog (filterable) |

### gaps

- **`verdict: unknown` is a lookup-miss synthetic, not a benign
  signal.** This is the single most important read-discipline for
  this system. The stub never 404s on `/lookup/{value}` so callers
  can treat the API as a pure function — but the lookup-miss case
  emerges as `{verdict: "unknown", score: 0}`, which is structurally
  indistinguishable from a deliberate `unknown` record. Treat
  `unknown` as **absence of signal**, never as refutation.
- **Offline / seeded only.** No live VT/OTX queries. Indicators not
  in the seed are by definition unknown. Adding indicators requires
  a stub rebuild.
- **No relationship graph.** The stub answers per-value records; no
  campaign/cluster/related-indicator surface.
- **Verdicts are static.** No `last_seen` decay or score reweighting
  over time; a `malicious` record stays `malicious` until the seed
  changes.

### read_guidance

- **Refutation requires `verdict ∈ {benign, malicious,
  suspicious}`.** `unknown` only refutes "is this indicator listed
  in the seed at all," which is rarely the hypothesis at hand.
- **`score` is the seeded confidence (0–100), not a recent count.**
  Treat it as the curator's verdict strength.
- **`tags` carry the curator's structured rationale** (e.g.
  `tor-exit`, `c2`, `phishing`). Useful for fan-out hypotheses (a
  `tor-exit` IP suggests a categorically different threat surface
  than a `c2` IP).
- **Mass-lookups via `list-indicators` are cheap.** Use the catalog
  to enumerate which IPs/domains the seed currently flags, rather
  than fishing with speculative `lookup` calls.

### when_to_use

- **Use to corroborate** a suspicious external IP or domain
  observed in a Zeek/proxy/dns event.
- **Use to enumerate** known-bad indicators when scoping a possible
  campaign — "do any seeded indicators match what we've seen on
  this host?" via `list-indicators` + cross-filter.

### when_not_to_use

- **Not for "is this IP internal."** That's a cmdb + network-CIDR
  question, not a reputation question.
- **Not for "has this domain been seen in our traffic."** That's
  Elastic `logs-zeek.dns-*` / `logs-squid.access-*`.
- **Not for live-threat enrichment.** The seed is curated for
  playground predictability — treating `unknown` as "probably
  benign because the world is mostly benign" is exactly the failure
  mode the stub is designed to surface.

## Execution

### CLI

```bash
defender-threat-intel health-check
defender-threat-intel lookup <value> [--raw]
defender-threat-intel list-indicators [--verdict X] [--type X] [--tag X] [--limit N] [--raw]
```

**Do not Read `threat_intel_cli.py` source to discover flags.** This
SKILL plus `defender-threat-intel {subcommand} --help` is the
authoritative surface.

`lookup` text output includes an explicit note when `verdict` is
`unknown`, reminding the caller that this is not refutation. `--raw`
emits the upstream JSON response unchanged (which omits that note).

### Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://threat-intel:8080/...`. Bastion default `web-1`.

### Config

`defender/knowledge/environment/systems/threat-intel/config.env`
declares `THREAT_INTEL_URL_BASE`, `THREAT_INTEL_BASTION_HOST`,
`THREAT_INTEL_TIMEOUT_SEC`.

### Exit codes

- `0` — success (including `verdict: unknown`)
- `1` — query error (bad arg)
- `2` — connectivity / docker / upstream 5xx
