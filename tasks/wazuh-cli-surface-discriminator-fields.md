---
title: wazuh_cli query — surface discriminator fields + raw sample events
status: todo
groups: tools, evaluation, quality
---

Eval runs #27 (5710 bait) and #28 (100001 whoami) both produced confidently-wrong dispositions whose root cause traces to the same tool-output defect: `scripts/tools/wazuh_cli.py query` renders `Sample Events` as `[timestamp] rule:X srcip:Y srcuser:Z agent:W desc:...` and nothing else. In both runs the rows that would have refuted the agent's narrative looked identical in the summary because the discriminating fields were elided — srcport on the 5×5710 burst, `proc.name`/`evt.type`/connection-tuple on the 4×100002 co-fires. `--raw` exists but was never reached for; no SKILL.md or lead-definition prose directs the agent there.

Fix on two axes, both required:

## 1. Add 2-3 raw sample events to the summary output

`wazuh_cli.py query` currently prints 5 formatted `Sample Events` lines followed by a `Count Breakdown`. Append a new section that emits 2-3 of those events in **full raw JSON** (or at minimum the complete `_source` body), labelled as `Raw sample events (for field-level inspection)`. Agents reading the output get the discriminator fields for free without needing to know `--raw` exists.

- Cap at 2-3 events so the output stays readable (full `_source` per event is large).
- Keep them ordered deterministically (earliest first, or same order as the summary lines).
- Do NOT remove the existing summary / count-breakdown sections — they stay as the fast path.
- Wrap under the same salted `<run-XYZ-siem-data>` delimiter as the rest.

## 2. Add srcport to the `authentication-history` lead summary

Independently of the raw-events fix, the `authentication-history` lead definition (`knowledge/common-investigation/leads/authentication-history/definition.md`) and the Wazuh query template under it should call out srcport as a required discriminator whenever the investigator is reasoning about "are these N events the same connection or N different connections?" Lead definitions shape what the agent queries for; the template should either (a) select srcport into a projected column so the summary line shows it, or (b) add guidance prose that says "when you see N rows with identical summary fields, inspect srcport explicitly — distinct srcports = distinct connections, identical srcport = indexer duplication of one log line".

This is a one-off lead-definition edit; no wazuh_cli changes needed for (2).

## Context

- Root cause is documented in detail in `.claude/skills/evaluate/SKILL.md` §15 (meta-findings).
- This block sits downstream of PR #74 (parallel Haiku judges) — PR #74 preserves structural reliability at lower cost but surfaces that Sonnet's dominant quality gap is semantic fabrication on top of this tool-output defect.
- Pre-refactor inline self-check had the same blind spot; run #11 on 100001 produced the same false reverse-shell narrative. So fixing this is not a prerequisite for merging PR #74 — it's the logical next step after.
- Fix priority is high because Sonnet-main on mature signatures is otherwise viable (runs #13, #14, #19) and this defect is the largest remaining quality gap visible in the eval corpus.
