# Learning development reference

Read when changing branch replay, grading, curation, or lesson retrieval.

Off-process and operator-initiated. A finished run is not fed anywhere automatically; it is a
**starting point** someone picks up later by naming it.

`learning/branch/cli.py` forks that run at a chosen message — keeping what the defender had
observed, discarding what it had concluded — and the **questioner** authors a family of sibling
worlds that differ by one deliberate fact. Each world's corpus is staged into its own namespace,
and that staged estate is what the siblings' queries are answered from. Every world is replayed
against the capture first: one that contradicts it, or whose declared difference no query could
reach, ends the whole episode before any sibling runs. The accepted worlds then run as their own
`run.py --tenant <T> --episode <episode_id> --world <label>` processes, and the **judge** grades the archived episode and appends its
findings to `_pending/findings.jsonl`.

That queue is the joint the cutover swung on — and since #1007 it is TWO queues, partitioned by
what a finding is ABOUT. A finding about the defender's conduct lands on `_pending/findings.jsonl`
and accumulates until the **lessons curator** folds it into `defender/lessons/`; nothing re-checks a
lesson before it commits (#1166 deleted the same-case forward check; #397). A finding about the WORLD — an invented field shape, a story the overlay never backed, a
family that failed to discriminate — lands on `_pending/questioner_findings.jsonl` and is folded by
the **questioner curator** into `defender/lessons-questioner/`, which the questioner reads back when
it authors the next family. Both curators run inside one drain tick.
Each worker commits from its own git worktree off `origin/main`, one PR per batch — the loop is
the sole committer, and spawned agents run no git. Lessons feed back into the runtime three times: at
PLAN time via `defender-lessons`, on every write that moves the investigation's open set via
`investigation/lessons_engine/lessons_frontier.py`, and on the compaction fold's frontier row, which carries
the block the whole document matches at the fold — derived fresh, not a re-show of what the
folded-away turns carried (`investigation/lessons_push.py`).
