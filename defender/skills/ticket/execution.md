# Ticket stub — execution

Read this file when gather is dispatched against `system: ticket`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## Verbs

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types.

**Call `list_verbs(system="ticket")` for the verbs you may run and the params each one
binds**, with types, defaults and which are required. It reads the adapter's live
signatures and is filtered to your grant, so it is the same surface the `query` tool
enforces — a param it names will bind, one it omits is refused. Don't Read
`ticket_adapter.py` to discover params either.

The adapter returns the upstream JSON response unchanged. At gather's query
boundary, the current run's own ticket is removed before both the model-facing
view and `gather_raw` capture. This is an identity exclusion, not a closed-only
filter: other open and in-progress tickets are valid correlation context, while
closed-only actor/judge reads remain the confirmation path for precedent.

## Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://ticket-server:8080/...`. Bastion default `web-1`.

## Config

`defender/knowledge/environment/systems/ticket/config.env` declares
`TICKET_URL_BASE`, `TICKET_BASTION_HOST`, `TICKET_TIMEOUT_SEC`,
`TICKET_KEY_PATTERN`. All are required — a missing one means the system is
down (`ConfigFault`, exit 2), never a default.

## Exit codes

- `0` — success
- `1` — query error (ticket not found, malformed arg)
- `2` — connectivity / docker / upstream 5xx
- `64` — a usage mistake in YOUR call: an unknown verb, or an
  unknown/missing/mistyped param name (e.g. `query` where the verb declares
  `q`). The one class you can fix yourself — the rejection names the
  declared verb/param roster; re-issue with a declared param. It never trips
  the circuit breaker, so a param typo is not a data-source outage.
