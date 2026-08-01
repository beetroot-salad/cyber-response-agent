"""The three challenger composition strategies. One variable: how the story is composed.

Inputs, model, and output schema are identical across arms.
"""

TAIL_SPEC = """
## Required output shape

Emit the story as markdown, then a final fenced ```yaml block with this shape and
nothing after it:

```yaml
claims:
  - entity: <the named thing the claim is about — host, account, process, IP, file>
    field: <the observable property>
    asserted_value: <what your story requires it to be>
    would_show_in: <the lead id whose payload would carry it, or "unqueried">
```

Every claim must be one your story LOAD-BEARS on: if it were false, the story fails.
Do not list background colour. Do not hedge a claim into unfalsifiability — an
asserted_value of "something suspicious" is not a claim.
"""

ONE_SHOT = """You are the challenger. The investigation below closed with disposition
`{disposition}`. Your job is to argue the opposite: construct the most plausible
`{counter}` reading of this same evidence.

You can see everything the investigator saw — its full working log, every lead it ran,
and the real payloads those leads returned. Your story must be consistent with all of
it. You are not inventing evidence; you are re-reading the evidence that exists.

Compose the counter-story in one pass.

{tail}

# The investigation's working log

{investigation}

# The leads it ran

{leads}

# The payloads those leads returned

{payloads}
"""

ITER_ROUGH = """You are the challenger. The investigation below closed with disposition
`{disposition}`. Your job is to argue the opposite: the most plausible `{counter}`
reading of this same evidence.

This is pass 1 of 4. Right now, commit ONLY to a mechanism class — what kind of thing
happened, in general terms. Do not name specific hosts, accounts, processes, times, or
field values yet; later passes bind those. A paragraph is enough.

# The investigation's working log

{investigation}

# The leads it ran

{leads}

# The payloads those leads returned

{payloads}
"""

ITER_SHARPEN = """You are the challenger, refining a counter-story toward disposition
`{counter}`. This is pass {n} of 4. Sharpen the story exactly one level:

- pass 2: bind the entities — which specific hosts, accounts, processes, IPs.
- pass 3: bind the timing — the sequence and when each step happened.
- pass 4: bind the field values — the specific observable values your story requires.

Keep everything already fixed by earlier passes unless the evidence forces a change; if
it does, say what changed and why. Stay consistent with every payload below.

{tail_or_blank}

# The story so far

{story}

# The investigation's working log

{investigation}

# The leads it ran

{leads}

# The payloads those leads returned

{payloads}
"""

LENS_ROUGH = ITER_ROUGH

LENS_ONE = """You are examining ONE lead's payload as a lens on a proposed counter-story.

The investigation closed `{disposition}`. The challenger proposes the `{counter}`
reading below. You see a single lead — its goal, its queries, and its real payload.

Answer only for THIS lead:

1. What does this payload FORCE the story to change or bind more specifically?
2. What does this payload CONCEDE — is there anything here the story cannot account for?
3. What does this lead NOT measure that the story turns on?

Be concrete and cite values from the payload. Do not rewrite the story; report what this
lead does to it.

# The proposed counter-story

{story}

# This lead

{lead}

# Its payload

{payload}
"""

LENS_FOLD = """You are the challenger. Fold the per-lead findings below into one coherent
`{counter}` counter-story.

Each finding came from a reader who saw exactly one lead. Some will force bindings, some
will concede, some will note what a lead does not measure. Resolve conflicts between them
in favour of what the payloads actually show. A concession that no reading can absorb is
worth stating plainly rather than writing around.

{tail}

# The rough story

{story}

# What each lead did to it

{findings}

# The investigation's working log

{investigation}
"""
