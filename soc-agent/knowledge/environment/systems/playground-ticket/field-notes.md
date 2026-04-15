---
tags: [playground-ticket, fields, gotchas]
---

# playground-ticket field gotchas

Stub schema is intentionally tiny — the gotchas list is short.

- **Status enum is `open | in_progress | closed`** — not Jira's
  `To Do / Done` or anything fancier. Anything else 422s on the upstream.
- **`resolution` is only set when `status=closed`.** Transitions that move a
  ticket back to `open` or `in_progress` clear `resolution` to null. Don't
  assume a non-null resolution carries across reopens.
- **One ticket per close invocation.** The upstream supports it, but the
  ActionContract is single-target; batch closes are not modeled.
- **Reset wipes state.** `POST /admin/reset` reloads from the seed file and
  wipes runtime state. Tests should be self-seeding rather than relying on
  pre-existing tickets.

<!-- grown via post-mortem /author runs -->
