# Tacit-knowledge registry — execution

Read this file when gather is dispatched against `system: tacit-knowledge`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## Verbs

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types.

**Call `list_verbs(system="tacit-knowledge")` for the verbs you may run and the params
each one binds**, with types, defaults and which are required. It reads the adapter's
live signatures and is filtered to your grant, so it is the same surface the `query`
tool enforces — a param it names will bind, one it omits is refused. Don't Read
`tacit_knowledge_adapter.py` to discover params either.

`lookup` binds three params — the actor, the host and the action being
asked about. Bind them from the alerted edge, not from a summary: the
actor and host are matched against the entry's globs and the action is
matched **exactly**.

The return carries one key, `matched`. `matched: null` is a MISS —
either no entry covers the three values, or the covering entry is past
its own `review_by`. A miss names nothing: it does not report the entry
it nearly matched, because an almost-hit that named an id is a citation
waiting to be written.

## Connectivity

None. The registry is a version-controlled file inside this tree
(`skills/tacit-knowledge/registry.yaml`); the verb reads it off the
defender directory its call carries. Nothing leaves the box, and there
is no service that can be down.

## Config

None. The file IS the system of record, so there is no endpoint, no
credential and no environment variable to resolve. Expiry is judged
against the moment the call is served as of, which the run supplies.

## Exit codes

- `0` — success (a hit AND a miss are both successes; `matched: null`
  is an answer, not an error)
- `1` — query error (the registry file is unreadable or malformed as a
  whole; individual malformed entries are skipped with a warning rather
  than failing the read)
- `2` — connectivity / upstream. Not reachable for this system: there is
  no transport to fail.
- `64` — a usage mistake in YOUR call: an unknown verb, or an
  unknown/missing/mistyped param name (e.g. `user` where the verb declares
  `actor`). The one class you can fix yourself — the rejection names the
  declared verb/param roster; re-issue with a declared param. It never trips
  the circuit breaker, so a param typo is not a data-source outage.
