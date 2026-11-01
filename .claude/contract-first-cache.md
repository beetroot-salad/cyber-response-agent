# contract-first cache

This project's applications of the contract-first plugin's rules: facts about this repo that a skill's rule needs, and that would be wrong in another project. Project-owned; the plugin's own caches, at the end of each skill file, hold only what is true wherever the plugin runs.

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: repo | <fact> | src: <issue or PR>`. Find a skill's entries with `grep '^- <skill>' .claude/contract-first-cache.md`, and everything one run wrote with `grep 'src: #<n>$'`. When an entry disagrees with its rule, or the repo has changed under it, the rule wins.

Written only by the plugin's `maintain-cache` skill, which write-tests, write-code-from-tests and finalize run in a fresh agent at the end of their review steps. It adds facts a run had to work out, removes entries a run contradicted, and, when several entries share a cause, writes the rule that removes it to `.claude/contract-first-rules.md` (or, for a cause in the plugin itself, files an issue proposing a skill change). Entries are facts about this repo, never requirements. Every change reaches the human at merge.

- write-code-from-tests/claims-adversary §why-the-gap-exists shipped-false-claims | ctx: repo | *"faking an authorization takes two coordinated rows instead of one cell"*: it took **zero**, the cell the check read was optional. *"the two cells that ride into `report.md`'s BODY"*: there were **seven**. *"the spellings covering EVERYTHING cannot be written at all"*: `[!QQQQ]*` matches every actor and cleared the rule. *"THE freshness bound"*: only one end was checked, so moving both dates bought unlimited validity. | src: #1358
- write-code-from-tests §2 ownership-declarations | ctx: repo | `@owns <field>` markers. | src: #1358
- write-code-from-tests/triage §1 excluded-conditions | ctx: repo | produced only by a malicious host, a different OS, or a hand-edited internal file. | src: #1358
