---
title: External retry-on-truncation wrapper for eval_run.sh
status: backlog
group: evaluation
---

Classes of "the CLI hangs up mid-investigation" bugs will keep happening (tool errors, transient API failures, hook misbehavior). The right structural fix is not to hunt them one by one.

Observed in run #8: agent produced high-quality CONTEXTUALIZE + SCREEN, transitioned into HYPOTHESIZE, then called Read against knowledge/environment/operations/ (a directory). Tool returned EISDIR is_error=true, Stop hook fired, Claude Code loop closed the session — without feeding the tool error back to the model for another turn. $1.15 and 331s consumed, no report.md.

Wrapper design:
- When claude --print exits, check if runs/<uuid>/report.md exists. If not, the run is truncated.
- Walk runs/<uuid>/state.json (last phase), runs/<uuid>/investigation.md (phase sections populated), and transcript.jsonl tail to identify where the agent stopped.
- Re-invoke claude with a continuation prompt that hands the agent the existing run dir and asks it to pick up from the recorded phase.
- Continuation MUST NOT restart CONTEXTUALIZE — reads existing investigation.md + state.json and resumes at recorded phase.
- Hard cap on retry count (e.g. 2) to avoid infinite loops on genuine dead-ends.
- Log every retry to runs/<uuid>/retry.jsonl.

Also: file Claude Code feedback on the termination-after-tool-error observation.
