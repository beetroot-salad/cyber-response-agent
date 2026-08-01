"""Round 3. Three fixes over round 2, each targeting a defect that round exposed.

FIX 1 — the tail spec. Every arm in rounds 1 and 2 filled its claims block with the
account's *evidential support* rather than its *unsettled requirements*: "list what your
account load-bears on" reads as "the observations it depends on", which are observed by
construction. An all-settled tail gives the oracle only settled things to project on, so it
finds everything consistent and nothing silent — and the gate then forces `inconclusive`
every time. The tail now asks the question the round-2 lens check phrased for itself: what
would the account need to argue that the data does not show either way.

FIX 2 — the lens fold. Round 2 answered its open question: the per-lead checks DO produce
contradictions and named unsettled assumptions; the fold dissolved them into a smooth story
and emitted 13 claims, none unsettled. The fold is now required to carry every unsettled
item through and to resolve contradictions in the mechanism rather than drop them.

FIX 3 — loose. Its third pass emitted 130K characters and no account: with "make it more
consistent" and every payload in context, auditing the data is the path of least resistance.
Bounded, and told to emit the account only.
"""

TAIL_SPEC = """
## Required output shape

The account as markdown, then a final fenced ```yaml block, nothing after it:

```yaml
requires:
  - assertion: <something your account needs to be true>
    settled_by: <the lead id whose payload already shows it, or "unsettled">
    if_false: <what breaks in your account if it is not true>
```

Both kinds of entry are required.

- Where the observations already show what your account needs, name the lead.
- Where your account needs something **the data does not show either way** — an assumption
  a reader would have to go and check to tell your account apart from a routine one — mark
  it `unsettled`.

The `unsettled` entries are the ones that matter. Your account is not weaker for having
them; every account of an incident rests on things nobody looked at. An account that lists
none has either not examined itself or is asserting nothing.

Do not list observations your account merely mentions. If it would survive the assertion
being false, it is not a requirement.
"""

SEED = """An alert fired in this environment. Below is the alert, the questions that were
asked about it, and the real data those questions returned.

Construct the most plausible account of what happened in which the correct disposition is
**{target}**.

Two requirements, in this order:

1. **Consistency.** Your account must be compatible with every observation below. Not
   "mostly" — if any observation contradicts your account, the account is wrong and you
   must find a different one. Where an observation looks awkward for your account, say how
   your account accommodates it.
2. **Commitment.** The account holds `{target}`. Do not qualify it into a maybe.

You are not restricted to what the data proves; you are restricted to what it does not
contradict.

{tail}

# The working log of the questions asked

{investigation}

# The questions

{leads}

# What they returned

{payloads}
"""

LOOSE = """Below is an account of an incident, holding disposition `{target}`, together with
the data it must be consistent with.

Revise it. Your only objective is to make it **more consistent with the observations**:

- If the account asserts something the data contradicts, that is a defect — fix it.
- If the account glosses over an observation that sits awkwardly with it, address it.
- If the account is already consistent somewhere, leave it alone. Restating data the
  account does not turn on makes it worse, not better.

Keep the disposition at `{target}` and keep the account committed.

**Output the revised account and nothing else.** Not your analysis of the data, not a
per-lead walkthrough, not a list of what you checked. The revised account must be no longer
than the one you were given.

{tail}

# The account

{story}

# The working log of the questions asked

{investigation}

# The questions

{leads}

# What they returned

{payloads}
"""

LENS_ONE = """Below is an account of an incident holding disposition `{target}`, and ONE
question that was asked, with the real data it returned.

Check the account against this data alone. Report only:

1. **Contradictions** — anything in this payload the account is incompatible with. Quote
   the value.
2. **Strain** — anything the account can accommodate but only awkwardly, and what it would
   have to say to accommodate it cleanly.
3. **Unsettled** — anything the account needs that this payload **does not show either
   way**. State it as the assertion a reader would have to go and check.
4. **Support** — anything here the account positively requires and that is present.

Do not rewrite the account. Do not judge whether the account is right overall — you see one
question out of many.

# The account

{story}

# This question

{lead}

# What it returned

{payload}
"""

LENS_FOLD = """Below is an account of an incident holding disposition `{target}`, and a set
of per-question checks against it. Each checker saw one question's data and reported
contradictions, strain, unsettled assumptions, and support.

Revise the account so it is consistent with all of them at once. Three rules, in order:

1. **A contradiction must be resolved, not acknowledged.** Change the mechanism so the
   contradiction no longer arises. If no mechanism holding `{target}` survives the
   contradiction, say so plainly and say which observation killed it — that is a real
   result, not a failure.
2. **Strain must be addressed in the account**, in the terms the checker named.
3. **Every `unsettled` item a checker reported must appear in your tail**, marked
   `unsettled`. You may reword it. You may not drop it, and you may not convert it into a
   settled claim by citing a different lead — if a checker said the data does not show it
   either way, it does not.

Keep the disposition at `{target}` and keep the account committed. Do not turn it into a
list of caveats.

{tail}

# The account

{story}

# The per-question checks

{findings}

# The working log of the questions asked

{investigation}
"""
