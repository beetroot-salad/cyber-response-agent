---
name: maintain-cache
description: "Maintain the project's contract-first cache (.claude/contract-first-cache.md): add repo facts a run had to work out, remove entries the run contradicted, and find the root cause behind related entries, proposing a rule that removes it. write-tests and write-code-from-tests run it in a fresh agent at the end of their review steps; with no issue argument it only looks for root causes. The cache's only writer."
argument-hint: "[issue # and the skill it serves, or nothing to only look for root causes]"
model: sonnet
effort: medium
---

# Maintain cache

You keep the project cache, `.claude/contract-first-cache.md`, so the next run doesn't rediscover what this one had to work out. Run in a session that did not write this run's tests or code; if this one did, stop and say so, because the stage must hand the work to a fresh agent. Don't read the authors' reasoning: read what the run produced and record the facts in it. Run with no issue, skip straight to Find the root cause.

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

## Find the root cause

Then read the whole file, not only this skill's entries. Entries arrive one run at a time, each a fact some run had to work out. When several of them exist for the same reason (the same trap hit from different sides, the same convention rediscovered on different surfaces, the same kind of fact needed again and again), the entries are symptoms. Folding them into one line only tidies the symptoms; the aim is the rule that removes their cause.

1. **Group by cause.** Ask why each entry had to be worked out at all: what about the repo, the design practice or the pipeline made the fact non-obvious or the mistake easy? Entries share a cause when one change would have made all of them unnecessary. A cause seen in one entry is not yet a pattern.
2. **Write the rule that mitigates the cause.** State its goal and the principle behind it, never the list of entries it covers, and name where it belongs:
   - a **project principle or CLAUDE.md rule**, when the cause is how this repo is designed or worked on;
   - a **lint or check**, when the cause is a mechanical shape a machine can find;
   - a **change to a plugin skill**, when the cause is how the pipeline itself works and would recur in any project.

   Name the entries it would make unnecessary and the cost of adopting it.
3. **Propose it; don't adopt it.** Principles and the plugin's skills belong to the human. File one issue per proposed rule, with the rule, its target, the entries and their sources, and the cost; post from a file, never through a shell argument. Mark each covered entry with `| rule-proposed: #<n>` so no later run proposes it again.
4. **Settle earlier proposals.** For each `rule-proposed` issue now closed: if the rule was adopted, rewrite the covered entries as applications of it (their rule field naming it), or remove those the rule makes derivable; if declined, replace the mark with `rule-declined: #<n>` and leave the entries.

Also merge plain duplicates (two lines stating the same fact) into one line that keeps every source. Within a skill only: when two skills need the same fact, each keeps its own line. Never change what an entry claims, and never turn facts into a requirement in the cache: a requirement is what the proposed rule is for.

## Return

The cache diff, and per change one line: added, replaced, removed or merged, with the run evidence behind it, or for a merge, the lines it folded. Then each proposed rule: its issue number, target, and the entries it covers; and each earlier proposal settled. Then any facts you left out as requirements or as project-agnostic, each in one line.
