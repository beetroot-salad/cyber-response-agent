# contract-first cache

This project's applications of the contract-first plugin's rules: facts about this repo that a skill's rule needs, and that would be wrong in another project. Project-owned; the plugin's own caches, at the end of each skill file, hold only what is true wherever the plugin runs.

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: repo | <application>`. Find a skill's entries with `grep '^- <skill>' .claude/contract-first-cache.md`. When an entry disagrees with its rule, or the repo has changed under it, recompute it from the rule, which wins. Add an entry when a stage applies a rule to this repo in a way the next run should not have to rediscover.

- refactor §keep-the-pattern lint-conventions | ctx: repo | a new rule starts with an empty baseline.
- write-code-from-tests/claims-adversary §why-the-gap-exists shipped-false-claims | ctx: repo | *"faking an authorization takes two coordinated rows instead of one cell"*: it took **zero**, the cell the check read was optional. *"the two cells that ride into `report.md`'s BODY"*: there were **seven**. *"the spellings covering EVERYTHING cannot be written at all"*: `[!QQQQ]*` matches every actor and cleared the rule. *"THE freshness bound"*: only one end was checked, so moving both dates bought unlimited validity.
- write-code-from-tests §2 ownership-declarations | ctx: repo | `@owns <field>` markers.
- finalize/trace §the-trail older-run-records | ctx: repo | `.contract-first/frontiers/`: lens premises (`30-*`), probes and dispositions (`44-*`, `45-*`), design tensions (`47-*`), human resolutions (`70-*`), gate residue (`76-*`; formerly `60-*`), verification (`90-*`), reconciliation (`92-*`).
- write-code-from-tests/triage §1 excluded-conditions | ctx: repo | produced only by a malicious host, a different OS, or a hand-edited internal file.
