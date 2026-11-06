---
name: defender-tacit-knowledge
description: Tacit-knowledge registry reference. The estate's human-authored record of sanctioned patterns. Resolves "has someone signed off that THIS actor may do THIS on THIS host?" for authorization contracts no live identity or change-management system can cover.
---

The tacit-knowledge registry is a version-controlled file, not a service:
`skills/tacit-knowledge/registry.yaml`, one entry per sanctioned pattern. Every entry was written
by a person and landed through a commit: the commit is the sign-off. Nothing an investigation does
can add one, so this system is read-only end to end.

It exists for the authorization question nothing else in the estate can answer. Container UID 0
is the motivating case: no identity system holds a record for it, so an `iam-policy` contract
about it dead-ends at `indeterminate` however the activity looks.

## Visibility surface

### available_queries

| Verb | Measurement |
|---|---|
| `lookup` | Does an authored, unexpired entry cover this actor, host and action |

### gaps

- **The registry is deliberately sparse.** It holds only patterns somebody wrote down. A miss is
  the ordinary case, and it says only that nobody has attested the action.
- **Entries expire.** Each carries a `review_by` at most 180 days past its `added_at`. Past that
  date it stops answering, and the lookup is a plain miss.
- **A scope is a glob.** `host_scope: build-runner-*.prod` covers a fleet. Blanket spellings are
  refused at load, but nothing can tell a fleet-wide sanction a human meant from one written
  carelessly.
- **No history.** The file says what is sanctioned now.
- **The action is matched exactly.** `pattern` is compared literally, so a near variant of a
  sanctioned action is a miss.

### read_guidance

- **A miss is `indeterminate`, never `unauthorized`.** It says nobody has attested the action, not
  that anyone refused it.
- **`registry_problems` in an answer means the miss proves less.** The registry is missing or
  lost entries, so say that in your summary.
- **A hit is full authority.** An entry is an affirmative record in a system of record. Resolve
  `verdict=authorized anchor_kind=tacit-knowledge grounding=org-authority` and cite the entry's
  `id` as `anchor_id`.
- **Record what came back before you cite it.** The `:R authz` row's `anchor_id` is cross-checked
  against a `:R consultations` row on the same lead carrying `anchor_kind: tacit-knowledge` and
  that entry's id. A citation no lookup produced is refused.
- **Read the whole entry.** `justification`, `added_by` and `review_by` are what a human reviewing
  the close needs in order to judge whether the sanction still holds.

### when_to_use

- For an authorization contract no identity system can answer: container UID 0, a build-runner
  service context, any actor class with no record anywhere.
- As the last anchor kind before declaring a contract exhausted. `basis=exhausted` on a `:R authz`
  row means every applicable anchor kind was queried; for a tacit-knowledge contract, that means
  this lookup was dispatched.

### when_not_to_use

- For planned-change context. A change covering a host at an instant is change-mgmt's question.
- For policy evaluation. Whether a principal may do something under IAM is identity's; this system
  records only what a human wrote down.
- As evidence of recurrence. How often the estate does something is a `runtime-evidence`
  consultation, which is context and never a verdict.
