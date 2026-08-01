"""Round 2. Two fixes over round 1, and a reframed objective.

Round 1 confounds, both removed here:

  1. The refinement arms seeded from a DIFFERENT prompt than one-shot — one that said
     "commit only to a mechanism class, do not name specifics yet." Later passes were
     then asked to bind specifics, which is plausibly what produced the transcription
     the round attributed to refinement itself. Here all three arms share ONE seed,
     generated once, and only what happens after it varies.

  2. Every prompt named a defender, its disposition, and framed the job as arguing the
     opposite. That anchors the model on the report's reasoning instead of the evidence,
     and it is the likeliest cause of the lens arm arguing itself into concessions. Here
     no defender exists, nothing has "closed", and there is no contest. The target
     disposition is stated as the task, not as an opponent's position.

Objective, restated: the account must be CONSISTENT WITH EVERY OBSERVATION while holding
a different disposition. Naming gaps is not the goal — the oracle finds what discriminates,
later. Asking the account to do that job was round 1's error.
"""

TAIL_SPEC = """
## Required output shape

The account as markdown, then a final fenced ```yaml block, nothing after it:

```yaml
claims:
  - entity: <the named thing — host, account, process, IP, file>
    field: <the observable property>
    asserted_value: <what your account requires it to be>
    would_show_in: <the lead id whose payload carries it, or "unqueried">
```

List only what your account LOAD-BEARS on: if it were false, the account fails. Not
background. An asserted_value that could not be checked against data is not a claim.
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

- If the account asserts something the data contradicts, that is a defect — fix it, and say
  what changed.
- If the account glosses over an observation that sits awkwardly with it, address the
  observation directly.
- If the account is already consistent somewhere, leave it alone. Do not add detail for
  its own sake; restating data the account does not turn on makes it worse, not better.

Keep the disposition at `{target}` and keep the account committed.

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
3. **Support** — anything here that the account positively requires and that is present.

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
of per-question checks against it. Each checker saw exactly one question's data and reported
contradictions, strain, and support.

Revise the account so it is consistent with all of them at once.

- A contradiction must be resolved, not acknowledged. If it cannot be, the account's
  mechanism is wrong and you should change the mechanism rather than concede the point.
- Strain should be addressed directly in the account.
- Where checkers disagree, the payload values decide.

Keep the disposition at `{target}` and keep the account committed. Do not turn this into a
list of caveats.

{tail}

# The account

{story}

# The per-question checks

{findings}

# The working log of the questions asked

{investigation}
"""
