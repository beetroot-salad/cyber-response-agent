---
signature_id: elastic-ssh-invalid-user
purpose: Field-level quirks for shape comparison. Read by archetype-scan and other subagents that extract observables from the alert. Not a substitute for context.md — just the gotchas.
---

# Field Quirks — elastic-ssh-invalid-user

## Key observables

| Observable | JSON path | Why it matters for shape comparison |
|-----------|-----------|-------------------------------------|
| Attempted username | `user.name` | Primary shape discriminator — sentinel (`nagios`, `probe`, `healthcheck`) vs service-account (`svc-*`, `backup-*`) vs wordlist (`admin`, `root`) vs real-looking (`alice.smith`, `jenkins`) |
| Source IP | `source.ip` | Trust axis — internal RFC1918 vs external. Classification drives which half of the archetype catalog applies |
| Source port | `source.port` | Connection-tuple discriminator — distinct ports across N rows = N real connections, identical port = one connection re-logged |
| Target host | `host.name` | Scope — targeted vs spray-and-pray |
| Raw line | `message` | Recovers the `Invalid user` vs `Failed password` distinction that ECS normalizes away |
| Timestamp | `@timestamp` | Cadence anchor — single vs burst vs periodic |

## Field gotchas

- **`user.name` is the *attempted* username, not the user who connected.**
  sshd's `Invalid user` line names a user that does not exist on the host;
  `Failed password` names a user that does. Either way, the connecting
  party's identity is unverified — `user.name` is what they typed, not who
  they are.
- **`event.outcome: failure` does not distinguish "no such user" from
  "wrong password".** ECS collapses both into the same outcome. To recover
  the distinction, parse the `message` / `event.original` field for
  `Invalid user` (no such user) vs `Failed password` (user exists, creds
  wrong).
- **`source.ip` may be a NAT egress, not the actual attacker.** External
  IPs are often shared (cloud egress, proxy exit, CGNAT). Two failures
  sharing `source.ip` do not necessarily share an actor.
- **`host.name` is the target.** The system integration tags events with
  the agent's own hostname; that's the host where sshd ran and failed,
  i.e. the destination of the auth attempt.
- **PAM auth-failure noise.** sshd-without-`-e` writes both its own
  `Failed password` line AND PAM's `authentication failure` line for the
  same attempt. PAM lines do not populate `user.name` / `source.ip` —
  they show up as documents with the failure outcome but without the
  identity fields. Filter on `user.name: *` to drop the PAM-only docs.
