# The learning-loop cutover (#922)

**Status: the record of one change, not a live spec.** What the loop does now is
`docs/learning-loop.md`; when a doc and the code disagree, the code wins. This
file exists to answer "what used to be here, why did it go, and what should I not
go looking for" — the question a reader of an older doc, an older commit or an
older run dir arrives with.

Landed in PR #1009 (merge `1fe18daa`), on top of the branched-episode work
(#920, #921, #947). The deletion itself is `e9e11a48`; the ~30 commits around it
are the test-tree migration that had to land with it.

## What was deleted

A **four-role pipeline** that ran over a finished investigation and invented the
material it learned from:

| Role | What it did |
|---|---|
| **actor** (malicious) | wrote a candidate attack story that had to pass through the run's actual lead sequence |
| **actor** (benign) | wrote the innocent explanation for the same alert |
| **oracle** | invented the telemetry each story would have produced, and routed it under the leads whose queries would have caught it |
| **judge** | graded the defender against the story and the projected telemetry, and emitted findings |

Around them went the machinery that only they needed: the disposition→direction
routing that chose which side ran (`core/directions.py`), the per-case cycle that
drove them (`core/run_cycle.py`), the actor/oracle engines, the closed-ticket
tool, the MITRE technique menu, the ticket-seed loop, the judge visualizer, and
the `actor` / `oracle` / `judge` entries in the agent registry.

Three limbs closed by following callers rather than by reading the issue: the two
observation curators and their corpora (their only producer was the deleted
judge), the ticket-seed loop behind `ticket_enrichment`, and the actor and
environment forward-checks that gated edits to those retired corpora.

## Why

**Everything it learned from was imagined.** The judge was grading the defender
against a world no system had ever answered for. A finding could never be
stronger than the story and the projection behind it, and neither was checkable.

The oracle in particular sat in the one place where its error was undetectable.
Its real job was never "model the world" — it was **blinding**: the actor had to
be kept from seeing the investigation's results, and the oracle was what stood
between them. Fusing "blind the actor" with "answer for the environment" put an
unaudited model on the critical path of the measurement.

The branched episode (#947) forks a **real** investigation at a chosen turn and
runs a family of sibling worlds from it. Its worlds are staged corpora that a
real `run.py` process queries, and every answer served is recorded in a ledger.
It was already feeding the same findings queue, so the old pipeline was a second
producer for one consumer — one of them inventing its evidence and one of them
executing it. Deleting the first is the whole change.

## What survived, and what it cost

- **The findings queue is the joint the cutover swung on.**
  `learning/_pending/findings.jsonl`, the `LEARNING_AUTHOR_THRESHOLD`, the lessons
  curator, the forward-check gate and the `defender/lessons/` corpus are all
  untouched. The producer changed; the consumer did not.
- **`AgentRole.JUDGE` left with its definition.** `set(AGENTS.keys()) ==
  set(AgentRole)` is asserted, so leaving the key behind would have been red. The
  family judge runs under the questioner's definition with an `agent_id` prefix of
  `judge:` until #1008 gives it the key back.
- **Self-play was given up.** The old actor was adversarial against the defender's
  prior runs, which made the loop a one-sided autocurriculum. The branched episode
  has no adversary; its difficulty comes from the case distribution. See
  `docs/learning-loop.md` §Future Enhancements for what bringing one back would
  have to look like.

## Two traps worth naming

**The drain discovered its own shape by iterating the direction table.** Its
channels, its curators *and* its box's writable mounts were all derived from that
table, so deleting the table would have narrowed the surviving stage from four
channels to one **with no error and no failing test**. It now names its one
channel and its one mount literally, so a second channel returning is an edit in a
diff (`core/drains.py` `_curator_queue_checks`).

**The run's transcript page was part defender-output, part pipeline-output.** The
defender's own report card lived inside the file being deleted
(`visualize_judge.py`), so it moved rather than went — `transcript.html` is now
the run's alert, report card and model transcript, and there is no judge view.

## What you should not go looking for

Deleted modules and artifacts whose names still appear in older docs, commits and
run dirs:

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
archives. Nothing produces them and nothing reads them. The posture view
(`learning/frontend/`) shows them marked retired rather than deleting or hiding
them.

Design docs under `defender/docs/` that describe the deleted pipeline carry a
status banner pointing here. They are kept for the reasoning that produced the
current shape, not as descriptions of it.
