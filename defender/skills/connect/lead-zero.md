# `connect` — lead-0, and what an alert source owes it

Read this when the system you are connecting **raises the alerts
investigations start from**. Skip it for a system that only answers
queries — CMDB, identity, ticketing, threat intel, an EDR you read.

## What lead-0 is

Before MAIN's first turn, the harness runs two pre-turn items against the
alert source (`runtime/lead_zero.py`):

- **item 1** resolves the alert's **ancestor documents** — the events the
  detection actually fired on — and renders them into ORIENT, so the
  investigation opens with the evidence instead of spending a lead
  fetching it.
- **item 3** dispatches one bounded correlation lead (`l-00c`) that reads
  those documents, judges which entities discriminate this alert, and
  counts how often they appear elsewhere.

## It is bound to ONE system, and that binding is authored, not configured

`ITEM1_SYSTEM` and `CORRELATION_GRANT` in `runtime/lead_zero.py` name the
alert source as module constants. `_sole_system` **raises** if the
correlation grant reaches more than one system — deliberately, so which
system lead-0 speaks to is a decision someone makes in code, not one that
resolves silently at run time.

**So connecting a new SIEM does not point lead-0 at it.** If the
deployment's alert source is a system other than the one those constants
name, lead-0 keeps querying the old one. Say this to the maintainer
plainly rather than letting them discover it on a live run: connecting the
system makes it queryable by gather; it does not make it lead-0's source.

Repointing lead-0 is a code change, not part of this skill's lane. Flag it
as an open item and let the maintainer decide.

## What the source must provide for item 1 to work

Item 1 is not generic document retrieval — it is a specific walk, and it
needs three things from the alert source:

1. **The alert names its constituent events.** Item 1 resolves ancestors
   by identifier, so the alert (or the projection of it that reaches
   `run.py`) has to carry pointers to the events that produced it, each
   with enough to address it: an id and where the id lives.
2. **A verb that fetches those events by identifier**, inside the reach
   the deployment confines the lead to.
3. **A group/sequence marker, if multi-event detections exist.** A
   detection that fires on a *sequence* has more than one constituent, and
   item 1 needs a way to ask for the set rather than one member.

Where the current implementation gets each of these from Elastic — the
alert's `ancestors` array, a fetch by `_id`, and a shared group id with a
building-block marker — is an illustration of the shape, not the contract.
A different source satisfies it differently, and some cannot satisfy it at
all.

## If the source cannot provide them

That is a legitimate outcome and the runtime already handles it: item 1
renders `_(unavailable: …)` in its slot, its status says the resolution
found nothing, and item 3 does not dispatch. The investigation proceeds
without the pre-turn evidence — MAIN spends a lead on it instead.

**Declare it as a gap** in `skills/{system}/SKILL.md`, in the same voice as
every other gap: what the source cannot answer, and the shape of the
failure. "This source's alerts do not name their constituent events, so
lead-0's ancestor resolution is unavailable and the first gather lead
carries that cost" is the kind of line that separates *we didn't ask* from
*we can't ask*.

## The confinement question, before you widen anything

The correlation lead's safety rests on the query verb taking its **target
as a separate parameter** the harness validates before dispatch
(`confine_index`). A verb whose target is embedded in a free-form query
string cannot be confined that way — which is exactly why the correlation
grant excludes Elastic's `esql`, whose `FROM` target is never confined.

If the system you are connecting only offers a search language with the
target inside the query text, then a bounded correlation lead over it
needs either a validator for that language or confinement pushed into the
platform (a service account whose own permissions bound the reach). Do not
hand the lead an unconfined verb and call it bounded. Raise it as an open
item; it is a design decision, not a scaffolding one.

## Seed template

If the source is going to serve lead-0, one of the seed templates under
`skills/gather/queries/{system}/` should be the **correlation** one: count
alerts naming a given entity over a window, with the entity clause
substitutable rather than a fixed field list. The existing
`elastic.correlate-alerts-by-entity` is the worked example — including its
pitfalls, which are the ones this class of query keeps hitting: a count
must come from the result total rather than the returned sample, and a
zero from a field the index does not map is a mapping fact, not an
absence.
