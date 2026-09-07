# The learning-loop cutover (#922)

**Status: the record of one change, not a live spec.** What the loop does now is
`docs/learning-loop.md`. This answers the question a reader of an older doc,
commit or run dir arrives with: what used to be here, why it went, and what not
to go looking for.

PR #1009 (merge `1fe18daa`), on top of #920/#921/#947. The deletion is `e9e11a48`;
the commits around it are the test migration that had to land with it.

## What went, and why

A **four-role pipeline** ran over a finished investigation and invented the
material it learned from: a **malicious actor** wrote an attack story that had to
pass the run's actual lead sequence, a **benign actor** wrote the innocent
explanation, an **oracle** invented the telemetry each story would have produced,
and a **judge** graded the defender against both.

Everything it learned from was imagined — the judge graded against a world no
system had ever answered for, and a finding could never be stronger than the
story and projection behind it. The oracle sat where its error was undetectable.
Its real job was never "model the world" but **blinding**: the actor had to be
kept from seeing results, and the oracle stood between them. Fusing "blind the
actor" with "answer for the environment" put an unaudited model on the critical
path of the measurement.

The branched episode (#947) forks a **real** investigation and runs a family of
worlds from it, each a staged corpus a real `run.py` queries with every served
answer recorded. It was already feeding the same findings queue — so there were
two producers for one consumer, one inventing its evidence and one executing it.
Deleting the first is the whole change.

Going with it: the disposition→direction routing (`core/directions.py`), the
per-case cycle (`core/run_cycle.py`), the actor/oracle engines, the closed-ticket
tool, the MITRE menu, the ticket-seed loop, the judge visualizer, and the
`actor`/`oracle`/`judge` roles. Three limbs closed by following callers rather
than by reading the issue: the two observation curators and their corpora (their
only producer was the deleted judge), the ticket-seed loop behind
`ticket_enrichment`, and the forward-checks gating edits to those corpora.

## What survived, and what it cost

- **The findings queue is the joint it swung on.** `_pending/findings.jsonl`, the
  threshold, the curator, the forward-check and `defender/lessons/` are
  untouched. The producer changed; the consumer did not.
- **`AgentRole.JUDGE` left with its definition.** `set(AGENTS.keys()) ==
  set(AgentRole)` is asserted, so leaving the key behind would have been red. The
  family judge runs under the questioner's definition until #1008.
- **Self-play was given up.** The old actor was adversarial against the
  defender's prior runs, making the loop a one-sided autocurriculum. See
  `docs/learning-loop.md` §Future Enhancements for what bringing one back needs.

## Two traps worth naming

**The drain derived its own shape from the direction table** — its channels, its
curators *and* its box's writable mounts. Deleting the table would have narrowed
the surviving stage from four channels to one **with no error and no failing
test**. It now names its one channel and one mount literally.

**The transcript page was part defender-output, part pipeline-output.** The
defender's own report card lived inside the deleted `visualize_judge.py`, so it
moved rather than went. `transcript.html` is now the run's alert, report card and
transcript; there is no judge view.

## What not to go looking for

```
learning/pipeline/                    the whole four-role tree
learning/core/run_cycle.py            the per-case cycle
learning/core/directions.py           disposition → direction routing
learning/core/subagents.py            the pipeline's subagent protocol
learning/ops/replay_actor.py          the actor-stage replay
learning/tickets/ticket_seeds.py      the ticket-seed loop
scripts/visualize/visualize_judge.py  the judge view
evals/oracle_golden/{build_case,replay}.py

actor_input.yaml  actor_story.md  projected_telemetry.yaml  judge_findings.yaml
lead_sequence.yaml
```

`defender/lessons-actor/` and `defender/lessons-environment/` are the exception:
the directories and their authored lessons are **left in place** as frozen
archives. Nothing produces or reads them; the posture view marks them retired.

Design docs describing the deleted pipeline carry a status banner pointing here.
They are kept for the reasoning that produced the current shape.
