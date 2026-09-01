# Track 1 result: the briefing informs, and nothing re-asks

**Arm:** open frontier rendered with edges, injected at every loop close.
**Baseline:** `20260830T100154Z-fresh-alert-input`, the #986 run, on disk.
**Conditions:** `glm-5.2` via Fireworks; `playground-v2` restored from snapshot; sandbox
under `runc` (operator decision — gVisor unavailable on this daemon, and the baseline ran
under gVisor, so this is a recorded asymmetry).

## Grades

| run | D1 subject re-pointed | D2 governance re-asked | D3 closing claim scoped |
|---|---|---|---|
| baseline | partial | no | no |
| t1 | partial | no | **partial** |
| t2 | partial | no | no |
| t3 | partial | no | **partial** |
| t4 | partial | **partial** (`identity`) | no |
| t5 | partial | no | no |
| t6 | partial | no | no |
| t7 | partial | no | no |
| t8 | partial | no | no |

**n=8. D1 `partial` 8/8. D2 `no` 7/8, `partial` 1/8. D3 `no` 6/8, `partial` 2/8.**

Regression clean: every record validates with zero findings, every run concluded.

### The denominator is smaller than 8, and the reason is itself a finding

**Three trials never wrote `db-1` into the record at all** (t2, t6, t7), so the precondition
D2 asks about — was the RESOLVED entity re-asked — never arose in them. Counting only the
five runs that did resolve it (t1, t3, t4, t5, t8), D2 is `partial` 1/5 and `no` 4/5. Same
conclusion, honest denominator.

The three that did not divide further, and one of them matters:

- **t6 never resolved it.** The host-state lead did not run; the container vertex carries
  `name=<NA>`. Nothing to re-point to.
- **t2 never named it** — it wrote the container as a vertex and hung the escalation edge on
  it, but by container id only.
- **t7 resolved it and did not write it.** It ran host-state `proc-tree`, `passwd` and FIM
  checks *against `db-1`* and the name appears nowhere in `investigation.md`.

t7 is #986's original claim — a fact the run obtained and left outside the record — occurring
exactly as reported. The baseline is a different shape (it wrote the vertex and both edges and
failed to re-point). **Both failure modes are real**; the issue described one of them and the
baseline happens to be the other.

### Run-to-run variance is large, and it bounds what this measures

t6 investigated a materially different story — external SSH from `147.235.199.7`, a root
password change, log clearing — and closed `malicious`. Dispositions across the nine runs:
5 `inconclusive`, 2 `benign`, 2 `malicious`. The live playground carries baseline generator
activity and prior attack traffic, so the same alert does not reproduce the same
investigation. D2 stays coherent across that variance (it asks a question about the run's own
query table), but any future arm on this fixture needs a larger n than 8 to separate a real
effect from this spread.

**D1 is identical to the baseline in every single run** — the container's own vertex gets
filled in, the alerted vertex never does. Not once in eight.

**D2 moved once in eight**, and that one run re-asked a single system. Against a baseline of
`no`, one `partial` in eight is not a result; it is the rate at which a run wanders back to
a system on its own. Nothing reached `yes`.

D3 moved twice, both to `partial` — a closing claim that stopped overreaching without
becoming correctly scoped.

**The arm does not win on the plan's criterion** ("B wins if M2 or M3 moves, at R1
unchanged"). The briefing is built, correct, and read; it changes what the run records and
not what it asks next.

The change works as built: the briefing fires (8 times in t1; 0 in the baseline, which
predates it) and renders what it should. The model reads it and records better. It does not
go back and re-ask.

## Why nothing re-asks — the actual mechanism

The system already HAS the blocking mechanism this experiment was going to recommend
building. It is defeated by a one-way door.

The governance questions are not free-floating; they are **authorization contracts**, and
a contract's claim text bakes in the entity name at declaration time — at ORIENT, from the
alert, before any lead has run. From the baseline (identical in every trial):

```
ac1|e-001|change-mgmt|"approved change or training window covers sudo activity on
                       soc-playground at this time"|escalate|escalate
ac2|e-001|iam-policy|"the identified identity is authorized for sudo on
                       soc-playground"|escalate|escalate
```

Both name `soc-playground` — the outer host, which is the wrong entity and will stay wrong
for the rest of the run. Then:

| | baseline | t2 |
|---|---|---|
| ac1 discharged | loop 1, `unauthorized` | loop 1, `unauthorized` |
| container resolved | loop 3 | loop 2 |
| ac2 discharged | loop 2, `indeterminate` | loop 2, `indeterminate` |

**Every governance contract is discharged before or alongside the resolution, against a
claim naming the wrong entity — and discharge is permanent.** A discharged contract leaves
the frontier and never returns. By the time the run knows which machine it is looking at,
the questions that would have made it re-ask are all closed.

That is why a briefing cannot fix this. The briefing says "this vertex is still open". It
has nothing to say about a contract that is *closed and should not be*.

## The natural experiment inside the eight runs

Three runs diverged from the rest, and they separate the EDGE from the CONTRACT:

| run | new privileged edge | new contract | D2 |
|---|---|---|---|
| t2 | `e-003 escalated_privilege v-002 → v-003` (**the container**) | none | no |
| t4 | `e-003 escalated_privilege v-002 → v-001` (the host) | `ac3`, claim names `root in container e5b0213bd690` | **partial** (`identity`) |
| t6 | none | `ac3` on `e-001`, claim names the host again | no |
| other 5 + baseline | none | none | no |

The only run that re-asked a governance system is the one that declared a contract whose
CLAIM named the container. Writing the edge to the container and hanging no contract on it
(t2) did nothing. Adding a contract still pointed at the host (t6) did nothing.

**The contract drives the re-ask; the edge is only where contracts hang.** t2 had the
topology right and stayed inert; t4 had the edge anchor wrong and still went back to
identity.

This also explains the null result on its own terms. The briefing renders open VERTICES,
and both the host and the container were on it in every run. What was missing was a
contract that was never declared — and a frontier reports what is open, not what was never
written. An absence is not open; it is absent.

## What this points at

Not "add an identification contract", and not "re-open discharged contracts" either — that
was the first reading here, and t4 shows it is heavier than the evidence needs. The
contracts already exist and are already the gate; an undischarged one already blocks a
confident close. What is missing is that nothing ever OWES a new one.

**When a run resolves the entity that privileged activity actually happened on, that
resolution owes a contract naming it.** Then the existing rules do all the work: the new
contract is undischarged, an undischarged contract blocks the close, and the only way to
discharge it is to ask the governance systems about the entity it names — which is exactly
the re-ask that never happens today.

Two things follow, in decreasing confidence:

1. **A contract's claim should be bound to an entity, not to a string.** Today the entity
   is spelled into free text at declaration (`"... sudo activity on soc-playground ..."`),
   so nothing can tell that `ac1` is a question *about v-001*. Without that binding,
   "does a contract exist for the resolved entity" is not a question the system can ask.
2. **Discharge staying one-way is survivable once (1) holds** — the old contract can stay
   closed and wrong, because a NEW open one now blocks. Re-opening is only needed if the
   run never writes the new contract, which is the thing (1) makes checkable.

This is #986's own part 2 — "restating a vertex's `ident` should invalidate leads whose
dispatch was parameterised on the old value" — located one layer in from where the issue
guessed. Not at lead dispatch: at what the resolution OWES.

**Confidence.** The mechanism is legible in the documents; the count is one re-ask in eight
runs. Treat t4 as an existence proof of the pathway, not as a measured effect size.

## Caveat worth keeping

The briefing is appended after ~1,700 characters of lesson precedent in the same tool
return. A reordering test would separate "the model did not act on it" from "the model did
not read it". That does not affect the mechanism above — a re-read briefing still cannot
reopen a closed contract — but it does affect any future claim about briefings in general.
