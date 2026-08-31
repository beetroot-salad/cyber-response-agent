---
name: defender-tacit-knowledge
description: Tacit-knowledge registry reference — the estate's human-authored record of sanctioned patterns. Resolves "has someone signed off that THIS actor may do THIS on THIS host?" for authorization contracts no live identity or change-management system can cover.
---

The tacit-knowledge registry is a version-controlled FILE, not a service:
`skills/tacit-knowledge/registry.yaml`, one entry per sanctioned pattern.
Every entry was written by a person and landed through a commit — the
commit IS the sign-off, and `git log` on that file is the audit trail.
Nothing an investigation does can add one. This system is **read-only**
end to end.

It exists for the authorization question no registry in this deployment
can otherwise answer. Container UID 0 is the motivating case: no identity
system holds a record for it, so an `iam-policy` contract about it
dead-ends at `indeterminate` no matter how the activity looks.

This file is split by audience. **Visibility surface** is read by
the defender, the author skill, and the actor-reviewer judge.
**Execution** is read only by code paths that dispatch queries.

## Visibility surface

### available_queries

| Verb | Measurement |
|---|---|
| `lookup` | Does an authored, unexpired entry cover this actor, host and action — the discriminating "has a human sanctioned this" check |

### gaps

- **The registry is deliberately sparse.** It holds only patterns
  somebody took the trouble to write down. A miss is the ordinary case
  and says nothing about whether the action is permitted — only that
  nobody has attested it.
- **Entries expire.** Each carries a `review_by` at most 180 days past
  its `added_at`. Past that date it stops answering, and the lookup is a
  plain miss. A file entry cannot re-verify itself the way a live IAM
  query does; the bound stands in for that.
- **Scope is a glob, not a proof of breadth.** `host_scope:
  build-runner-*.prod` covers a fleet. The loader refuses blanket
  spellings (blank, `*`, `all`/`any`, or a scope that is mostly
  wildcard), but it cannot tell a fleet-wide sanction a human MEANT from
  one written carelessly.
- **No history surface.** The file says what is sanctioned NOW. What
  changed and when is `git log`'s answer, not this system's.
- **The action is matched exactly.** `pattern` is compared literally, so
  a near variant of a sanctioned action is a miss.

### read_guidance

- **A miss is `indeterminate`, never `unauthorized`.** An absent or
  expired sanction says nobody has attested the action, not that anyone
  refused it. Writing `unauthorized` on a miss escalates every action
  whose sanction simply aged out.
- **A hit is full authority.** An entry is an affirmative record in a
  system of record, the same kind of thing an `iam-policy` or
  `change-mgmt` hit is — it is just filed in a document. Resolve
  `verdict=authorized anchor_kind=tacit-knowledge grounding=org-authority`
  and cite the entry's `id` as `anchor_id`.
- **Record what came back before you cite it.** The `:R authz` row's
  `anchor_id` is cross-checked against a `:R consultations` row on the
  SAME lead carrying `anchor_kind: tacit-knowledge` and that entry's id.
  A citation no lookup produced is refused at the write gate.
- **Read the whole entry, not just the hit.** `justification`,
  `added_by` and `review_by` are what a human reviewing the close needs
  in order to judge whether the sanction still holds.

### when_to_use

- **Use for an authorization contract no identity system can answer** —
  container UID 0, a build-runner service context, any actor class that
  has no record anywhere.
- **Use as the last anchor kind before declaring a contract exhausted.**
  `basis=exhausted` on a `:R authz` row means every applicable anchor
  kind was actually queried; for a tacit-knowledge contract that means
  this lookup was dispatched.

### when_not_to_use

- **Not for planned-change context.** A CR covering a host at an instant
  is change-mgmt's question.
- **Not for policy evaluation.** Whether a principal *may* do something
  under IAM is identity's; this system records only what a human wrote
  down.
- **Not as evidence of recurrence.** How often the estate does something
  is a `runtime-evidence` consultation, which is context and never a
  verdict. This system answers whether it was sanctioned, not whether it
  is common.

## Execution

Verb surface, connectivity, config, and exit codes live in
`execution.md` — read by gather only.
