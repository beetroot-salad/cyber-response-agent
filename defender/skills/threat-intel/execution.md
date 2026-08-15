# Threat-intel stub — execution

Read this file when gather is dispatched against `system: threat-intel`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## Verbs

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types.

**Call `list_verbs(system="threat-intel")` for the verbs you may run and the params each
one binds**, with types, defaults and which are required. It reads the adapter's live
signatures and is filtered to your grant, so it is the same surface the `query` tool
enforces — a param it names will bind, one it omits is refused. Don't Read
`threat_intel_adapter.py` to discover params either.

`lookup` emits the upstream JSON payload (`{value, verdict, score, …}`).
Treat `verdict: unknown` as *absence of signal*, never as refutation.

## Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://threat-intel:8080/...`. Bastion default `web-1`.

## Config

`defender/knowledge/environment/systems/threat-intel/config.env`
declares `THREAT_INTEL_URL_BASE`, `THREAT_INTEL_BASTION_HOST`,
`THREAT_INTEL_TIMEOUT_SEC`.

## Exit codes

- `0` — success (including `verdict: unknown`)
- `1` — query error (bad arg)
- `2` — connectivity / docker / upstream 5xx
- `64` — a usage mistake in YOUR call: an unknown verb, or an
  unknown/missing/mistyped param name (e.g. `indicator` where the verb
  declares `value`). The one class you can fix yourself — the rejection
  names the declared verb/param roster; re-issue with a declared param. It
  never trips the circuit breaker, so a param typo is not a data-source
  outage.
