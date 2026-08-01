# Pilot 02 — shared seed, framing removed

Same fixture. Fixes over pilot 01: all arms revise **one** seed story (pilot 01's arms used
different seed prompts, so it compared composition and seeding at once); no prompt mentions a
defender, a reached disposition, or a contest; `:T conclude` stripped from the working log.

Objective restated per the design: the account must be **consistent with every observation
while holding the opposite disposition**. Naming gaps is not its job — the oracle finds what
discriminates.

| arm | claims | unqueried | calls | note |
|---|---|---|---|---|
| seed | 6 | 0 | 1 | coherent, committed account |
| lens | 13 | 0 | 12 | per-lead checks strong, fold discards them |
| loose | 0 | — | 3 | degenerated; no account, no claims block |

## The round-01 open question is answered

Pilot 01 could not tell whether the per-lead lenses generated the unsettled facts and the fold
discarded them, or never generated them. **They generate them; the fold discards them.**

The l-011 check, verbatim:

> **Container age vs. claimed 14-hour campaign:** `tini` (PID 1) with `ELAPSED 29:13` … places
> container start at approximately 06:09Z on **July 28** — roughly 15 minutes before the alert,
> not 14 hours.

> sshd as parent does not uniquely imply an SSH *session* — sshd could be configured to exec a
> process at startup. To accommodate this cleanly, the account would need to argue that no sshd
> startup configuration for scheduler.py exists (**which this payload does not show either
> way**).

That is a contradiction and a named unsettled load-bearing assumption, per lead, structured.
It is the strongest artifact any arm has produced. The fold then emitted 13 claims, **zero**
unqueried, all restatements.

So the lens defect is one prompt, not the strategy. Pilot 01 ranked this arm last.

## Loose degenerates under repeated consistency pressure

Pass 3 emitted 130K characters and no claims block. It stopped writing an account and started
writing a consistency audit of the data — "Let me carefully analyze the data … 1. **l-001**: …
✓ consistent." With "make it more consistent" as the instruction and every payload in context,
auditing is the path of least resistance.

## The tail spec is the common defect, in both rounds

Every arm's claims block collects the account's **evidential support**, not its **unsettled
requirements**. The seed's prose load-bears on "a legitimate scheduled task would be launched by
cron or the entrypoint," "the key comment is deliberate masquerading," "the 14-hour history is
the campaign, not a pre-existing baseline" — none unqueried-checkable, none in the tail. The
tail instead carries `parent_process = sshd (PID 7)`: the evidence for the inference, not the
inference.

"List what your account load-bears on" reads as "the observations it depends on", which are
observed by construction. The lens check already phrases the right question — *what the account
would need to argue, that this payload does not show either way*. The tail spec should ask for
that.

This is load-bearing for #774, not cosmetic: an all-settled tail gives the oracle only settled
things to project on, so it finds everything consistent and nothing silent, and the gate forces
`inconclusive` every time.

## Next

1. Rewrite the tail spec to ask for unsettled requirements, in the lens check's phrasing.
2. Rewrite the lens fold to preserve, not dissolve, what the checks surfaced.
3. Drop `loose`, or bound its output and re-test — but its failure is a property of
   unstructured refinement over in-context data, not of this fixture.
4. Re-seed and re-run before any scaling.
