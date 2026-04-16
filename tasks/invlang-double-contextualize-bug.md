---
title: Investigate double-CONTEXTUALIZE hook rejection in run 20260416-052335-rule100001
status: done
groups: reliability, hooks, invlang
---

## Symptom

Run `20260416-052335-rule100001` (wazuh-rule-100001, Sonnet 4.6) produced two consecutive hook rejections:

```
Illegal state transition: illegal transition CONTEXTUALIZE -> CONTEXTUALIZE.
Allowed from CONTEXTUALIZE: ['HYPOTHESIZE', 'CONCLUDE', 'SCREEN']
```

Both rejections occurred during the CONTEXTUALIZE phase before any other phase header was written. The agent recovered and proceeded normally, but the two spurious rejections added cost and turn overhead.

## Hypotheses

**H1 — Agent wrote `## CONTEXTUALIZE` twice**: the agent wrote a partial CONTEXTUALIZE block in a first Edit, then attempted to write an additional/corrected block in a second Edit. `infer_state.py` detected `## CONTEXTUALIZE` in both edit contents and fired the illegal-transition check on the second one.

**H2 — infer_state scans full file content, not just the diff**: `infer_state.py` may be re-reading the full post-edit file on every Edit event rather than only detecting phase headers *newly introduced* by the edit. If the file already contains `## CONTEXTUALIZE` when a subsequent Edit fires, a full-file scan would see it again and treat it as a new transition attempt.

H2 would be a correctness bug: the hook should detect only phase headers that appear in the *delta* introduced by the edit, not headers already present in the file.

## Investigation steps

1. Read the transcript at `/tmp/cra-eval/20260416-052335-rule100001/transcript.jsonl` and find the two Edit calls that triggered the rejections. Check: were both edits writing `## CONTEXTUALIZE` content, or was the second edit writing something else?
2. Read `soc-agent/hooks/scripts/infer_state.py` — check whether it scans the full file or only the new content from the edit's `new_string` field.
3. If H2: fix `infer_state.py` to detect phase headers only in `tool_input["new_string"]`, not in the full file content.
4. If H1: the agent authored the CONTEXTUALIZE section in two separate writes — consider whether the skill instructions are clear enough that a single write is expected.

## Run artifacts

- Transcript: `/tmp/cra-eval/20260416-052335-rule100001/transcript.jsonl`
- Hook events: look for `PostToolUse:Edit` events with non-zero exit in the analyzer output
- Run: `20260416-052335-rule100001`

## Resolution

**Root cause: H1.** The agent wrote `## CONTEXTUALIZE` (correct), then edited it to `## PHASE: CONTEXTUALIZE\n\n## CONTEXTUALIZE` (confused about format), then tried to undo that — replacing `## PHASE: CONTEXTUALIZE` with `## CONTEXTUALIZE`, which left two `## CONTEXTUALIZE` headers in the file. `infer_state.py` (PostToolUse, full-file scan) correctly rejected the duplicate. H2 was not the bug: full-file scanning is intentional.

**Fixes shipped in PR #60:**

1. **`infer_state_pre.py`** — new PreToolUse hook that simulates the post-write file content (Write: uses `content` directly; Edit: reads current file + applies `old_string→new_string`) and blocks the tool call with exit 2 before the file is modified. The exact bad Edit from this run would now be blocked before it lands.

2. **`SKILL.md`** — phase headers must be exactly `## PHASENAME` with no prefix or suffix (was `## PHASE section header`, which the agent misread as a literal `## PHASE:` prefix).

3. **`validate_phase_sequence()`** extracted from `infer_state.py` as an importable function shared by both hooks.

**Regression caught in eval run #21:** removing `Bash` from the PostToolUse infer_state matcher caused `state.json` to stall at HYPOTHESIZE when the agent used `cat >>` heredocs for GATHER/ANALYZE/CONCLUDE. Restored `Bash` to the matcher before shipping.
