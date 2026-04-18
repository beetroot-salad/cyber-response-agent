---
archetype: _template
signature_id: _template
required_anchors: []
---

# {Archetype Name} — Story

One or two paragraphs describing the abstract pattern this archetype
represents. Focus on **observable shape**: what the alert looks like,
what primitives fire, what cadence / volume / identity class the
pattern has. Write the story so a reader can read it and say "yes,
this alert fits" or "no, it doesn't." Avoid claims about *intent* —
intent is what the grounding legs (trust anchors, precedents) are for.

Explicitly name what takes an alert *out* of this archetype. The most
useful sentence in an archetype story is often "this is not
`other-archetype` because ...".

Call out features that depend on environmental context (specific
monitoring hosts, specific user naming conventions). Archetypes
should be portable across environments *as stories* — the specific
bindings live in the trust anchors (see `README.md`).
