# Two changes, two questions

Split out of one proposal after reading the failing run. They are justified differently,
measured differently, and should not share a fixture.

- **Track 1 — frontier at PLAN.** Aimed at #986's mechanism. Cheap.
- **Track 2 — role split.** Aimed at task interference in MAIN. Not measured by #986.

## What the failing run actually shows

The run did **not** fail to write the resolution. Loop 3 wrote:

```
v-005|compute|container/internal/novel|db-1|container_id=e5b0213bd690;image=soc-playground/host-db:22.04;runs=postgresql-14
```

A whole vertex, correctly attributed. What never happened is anything tying it to
`v-001` — the alerted host — or re-pointing the investigation at it. Every governance
lead stayed aimed at `soc-playground`, and the close paid for it:

```
disposition   inconclusive
ceiling_test  "soc-playground is unregistered in all available governance systems…"
```

`db-1`'s governance record was in hand from loop 1.

Two facts about MAIN's context explain the rest:

- **Nothing re-renders state.** The stale row was written in turn 1 and never shown
  again. At PLAN, MAIN is pushed lessons and nothing else. What the graph currently says
  is memory.
- **Compaction is not that mechanism.** It replays the investigation *document* when
  budget forces a fold, folds only closed loops, and never fired in this run. Append-only
  text re-read is still text to fold in your head — the state is only visible if
  something computes it.

Measured from the run's wire log: system prompt 35,826 chars; orientation 47,017, of
which **41,370 (88%) is the invlang spec**; MAIN's conversation reached ~1.69M chars
with no compaction.

---

# Track 1 — inject the folded frontier at PLAN

## Question

**Engineering** — does showing MAIN the *computed current state* of the record at each
PLAN prevent a resolved identity from leaving the investigation pointed at the old one?

## Variants

Single arm. `20260830T100154Z-fresh-alert-input` on disk is the baseline — the current
agent's behaviour on this fixture is observed, not re-measured.

### B — `+frontier at PLAN`

Before each PLAN, inject the open frontier: every vertex carrying an unresolved slot,
**rendered with its edges**, so an open node is shown in the company of what attaches
to it.

The computation already exists. `skills/invlang/frontier.py`'s node axis is exactly this
— open `??` / candidate-set slots on `:V` vertices, class, `ident` and `attrs.<name>`,
recomputed on every write, deliberately including `ident` ("an unresolved identifier is
the single most retrieval-worthy open slot there is"). It feeds lesson retrieval and has
never been shown to MAIN. **Reuse it; do not write a second walk.**

```
defender/runtime/driver/_prompts.py   render + inject at PLAN
defender/skills/invlang/frontier.py   reuse the node axis; add the edge rendering
```

Deliberately **not** compaction's frontier: that replays document text under budget
pressure and folds only closed loops. This is computed open state on a phase boundary.

**Known limitation inherited from `frontier.py`:** open slots that live on an EDGE are
dropped, because a frontier entry carries a vertex `type` for selector matching and an
`:E` row has none. An authz question opened on an edge attribute renders nothing.

## Why this shape, from the record

`v-001|compute|??/??/known-corp|soc-playground` carried two unresolved slots from turn 1
to the close — it was on the frontier for the entire run. The container was **not**
orphaned; loop 6 wrote both edges:

```
e-005|runs_on|v-005|v-001|…
e-006|contained_in|v-005|v-001|…
```

So the graph was structurally complete and correct. Rendering open vertices *with* their
edges is what makes the defect legible:

```
v-001  compute  ??/??/known-corp  soc-playground          ← open
   ↑ contained_in — v-005  compute  container/…  db-1     ← resolved
```

An unresolved host with a fully-resolved container inside it, while every governance
lead goes to the host.

**Caveat this predicts.** An open vertex is the normal state; most vertices carry `??`
for most of a run. The frontier does not say *you asked the wrong node* — it
re-presents the graph and relies on MAIN noticing. Expect it to move the identity row
more reliably than the verdict.

## Fixture

`/workspace/.defender-runs/fresh-alert-input.json` — the `v2-off-hours-sudo` alert
(alert_id `e9064a67…`, 2026-08-30T09:59:51Z). Discriminating by construction: the alert
names the Docker host, the real subject is a container, and resolving it requires
re-pointing four governance leads.

**Blocker:** live fixture. `playground-v2` is down (`docker compose ps` returns nothing).

## Metrics

Machine-checkable from the run dir; `analyze.py` reads `investigation.md`,
`executed_queries.jsonl`, `report.md`.

| id | question | baseline run | source |
|---|---|---|---|
| M1 | is the alerted vertex's `ident` restated, or the container marked the alert's true subject? | NO | `investigation.md` |
| M2 | is any governance query re-issued under the resolved name afterwards? | NO | `executed_queries.jsonl` |
| M3 | does the closing `ceiling_test` rest on the stale host's governance gap? | YES | `report.md` |
| C1 | are the container↔host edges written? | **YES** | `investigation.md` |
| R1 | does the run still conclude, and does the record validate? | YES | exit + `validate_companion` |

**C1 is a control, and it is why M1 is worded the way it is.** The edges were already
written in the failing run. Any metric that scores "is the container tied to the host"
marks the baseline a pass. What was missing is the *subject* moving, not the topology.

M2 and M3 are what cost the verdict. M1 alone is a near-miss.

## Trials

**N=8 on the single arm**, mid-run analysis at 3.

No regression arm: the baseline is the run on disk. But one green trial cannot
distinguish a fix from a lucky run, so the whole budget goes to B rather than being
split — the issue's 2-of-2 tells us the failure is common, not that it is certain.

### Run conditions (fixed, and why)

| | | |
|---|---|---|
| model | `glm-5.2` via Fireworks | what the baseline ran on — its wire log records `accounts/fireworks/models/glm-5p2`. A trial on any other model is not comparable to it. |
| world | `playground-v2`, restored from the lever-down snapshot | ES holds history back to April, so the 30-day baseline the investigation leans on is intact. A freshly provisioned stack would have none and the fixture would not reproduce. |
| sandbox | `DEFENDER_BOX_RUNTIME=runc` | gVisor is not registered on this Docker daemon and the daemon is the host's, so it cannot be from here. Operator decision, recorded because it is a weaker isolation tier than the runs it is being compared against — the baseline ran under gVisor. |
| judge | `claude -p`, `claude-opus-5` | the Anthropic API key is out of credit; `claude -p` falls through to the claude.ai login when that key is UNSET. |

### Judge calibration (run before any trial)

Graded the baseline run — the known failure — and it lands where it should:

```
D1 subject re-pointed    partial   "the alerted vertex v-001 keeps its original identity
                                    cell soc-playground and is never restated"
D2 governance re-asked   no        no query against db-1/e5b0213bd690 after l-006
D3 closing claim scoped  no        ceiling_test asserts the alerted host is absent from
                                    every governance system, which the run never re-checked
```

D1=`partial` rather than `no` is the calibration that matters: the judge separates the
bookkeeping the failing run DID do (container vertex, both edges) from the re-pointing it
did not. A judge that scored that `no` would flatter any arm; one that scored it `yes`
would pass the baseline.

## Decision criteria

- **B wins** if M2 or M3 moves, at R1 unchanged.
- **Current retained** if only M1 flips. That says the record got tidier and the verdict
  did not, and the lever is the next one down: make an identification lead's goal a
  **contract** only a named cell can discharge — the shape `:H h-NNN.authz` contracts
  already have, where the run is refused a conclusion while one sits open.

---

# Track 2 — split invlang authorship out of MAIN

## Question

**Engineering** — does holding the row-writing grammar in MAIN's context interfere with
MAIN's reasoning?

Not a #986 experiment. The run above wrote a richer row than a clerk would have; the
split is not predicted to fix that bug and should not be graded on it.

## Why it is still worth testing

Share of context is the wrong measure and the earlier framing of it here was wrong. The
41,370 characters sit at the **front of every request**, where position buys attention
that proportion does not capture — and they are instructions for a different task than
the one MAIN is doing when it reads them. Interference is a real hypothesis; it is just
not the one #986 tests.

## Variants

### A — `current`
MAIN authors every block; the grammar is injected at orientation
(`defender/SKILL.md:131`).

### B — `+auditor`
MAIN keeps invlang. A second role reads each loop's prose against the rows committed and
answers one question: *what does the prose assert that no row carries?* Emits repair rows
only.

### C — `clerk`
B, plus the grammar leaves MAIN's orientation and MAIN's block authorship is withdrawn.
**Not a config flag** — MAIN authors every block today, so this rewrites MAIN's output
contract.

Build shape for B/C (not yet written):
```
defender/agents.py                +AUDITOR_DEF in build_registry(...)
defender/runtime/review_roles.py  +AUDITOR_DEF
defender/runtime/driver/          one call after block commit
defender/skills/auditor/SKILL.md  the role prompt
```

## Fixtures

A **set**, not this alert — interference shows up across cases or not at all. Candidates
from `defender/fixtures/`: `v2-cross-tier-ssh-pivot`,
`v2-falco-suspicious-network-tool`, `v2-sshd-success-after-failures`, plus the held-out
set.

## Metrics

Reasoning quality, not row hygiene — row hygiene is what the split trivially improves
and is not the claim.

- disposition correctness against the held-out labels (`defender/evals/held_out.py`)
- leads dispatched per settled question (does MAIN plan better with less in front of it)
- validator findings per run (the trivially-improved control — expected to move; a win
  here alone is not a win)

## Decision criteria

- **Split wins** if held-out disposition accuracy improves at equal or lower cost.
- **Retained** if only validator findings improve. That is the record getting tidier,
  which was never the argument.

---

## Layout

```
experiments/auditor-role-986/
  plan.md
  variants/{A-current,B-frontier,B-auditor,C-clerk}/
  fixtures/
  runs/
  analyze.py
  results/
```

## Order

Track 1 first. The computation it needs already exists and is already recomputed on
every write — the build is a renderer and an injection point, not a new mechanism. Track
2 needs a new role, a new prompt, a driver seam, and a fixture set, and its claim is not
tested by this alert.
