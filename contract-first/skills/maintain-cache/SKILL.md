---
name: maintain-cache
description: "Maintain the project's contract-first cache (.claude/contract-first-cache.md): add repo facts a run had to work out, remove entries the run contradicted, and consolidate similar entries. write-tests and write-code-from-tests run it in a fresh agent at the end of their review steps; with no issue argument it only consolidates. The cache's only writer."
argument-hint: "[issue # and the skill it serves, or nothing to consolidate only]"
model: sonnet
effort: medium
---

# Maintain cache

You keep the project cache, `.claude/contract-first-cache.md`, so the next run doesn't rediscover what this one had to work out. Run in a session that did not write this run's tests or code; if this one did, stop and say so, because the stage must hand the work to a fresh agent. Don't read the authors' reasoning: read what the run produced and record the facts in it. Run with no issue, skip straight to Consolidate.

You receive the skill you serve (`write-tests` or `write-code-from-tests`), the issue number, that skill's rules, the current cache lines for it, and the run's record. For write-tests, that record is the spike's friction log, the design check and fidelity findings with their dispositions, and the repairs. For write-code-from-tests, it is the triage verdicts, the stale-test batch, the deferred-verification results, and the local check and CI failures. You are the only writer of the cache: the stage that dispatched you commits your changes unchanged. Edit only the cache file, in the worktree you are given, and commit nothing.

## What an entry is

A fact about this repo that one of the skill's rules needed, that the run had to work out, and that would be false or useless in another project. It records where something is, how something here behaves, or which convention or trap applies: the seam that reaches a kind of entry point, the marker that declares ownership, the lint that bounced a green change.

**An entry is never a requirement.** "The job store owns retries" is a fact; "the implementation should retry twice" is a requirement, and requirements live in the design and the tests. If a fact can only be phrased as what code should do, it doesn't belong here; name it in your report instead. A fact true of any project using the same tools belongs in the plugin's own cache, which the human maintains; name it in your report too.

## Add, replace, remove

- **Add** a fact the run had to work out and the next run would need again. One line per fact, in the file's format, with this issue as the source: `- <skill>[/<file>] §<section> <rule> | ctx: repo | <fact> | src: #<issue>`. The rule is the one in the skill that needed the fact.
- **Replace or remove** an entry the run contradicted, quoting the evidence: what the entry said and what the run observed. One contradicting observation is enough to act, since the human reviews every change at merge.
- **Check the existing entries** for this skill: every path or symbol one cites in backticks still exists in the repo. Remove an entry whose subject is gone; update one whose subject only moved.
- **On the code stage**, also read every line this run's write-tests keeper added (`src: #<issue>`). Remove or rewrite any that state a requirement rather than a fact.

Leave entries you have no evidence about alone. Most runs add a few lines or none; an empty change is a normal result.

## Consolidate

Then read the whole file, not only this skill's entries, and fold together what has accumulated. Entries are added one run at a time, so the same fact arrives in several phrasings, and several instances of one pattern arrive as separate lines.

- **Same fact:** two lines that state the same thing, or where one implies the other, become one line.
- **Instances of one fact:** several lines that are each an instance of one statement about the repo become that statement, with the instances kept as examples only if they help a reader apply it. Generalize only as far as every instance supports; a pattern seen once is not a pattern.
- **Keep every source** on the merged line (`src: #1342 #1350`), and never drop a fact in the merge: a reader of the merged line must be able to recover what each original said.
- **Across skills:** merge only lines filed under the same skill. When two skills each need the same fact, keep one line per skill, worded the same, so each skill's grep still finds it.

Consolidation never changes what an entry claims. A merge that would need a new fact, or would turn facts into a requirement, is a merge you don't make.

## Return

The cache diff, and per change one line: added, replaced, removed or merged, with the run evidence behind it, or for a merge, the lines it folded. Then any facts you left out as requirements or as project-agnostic, each in one line.
