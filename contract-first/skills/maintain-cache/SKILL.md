---
name: maintain-cache
description: "Maintain the project's contract-first cache (.claude/contract-first-cache.md): add repo facts a run had to work out, remove entries the run contradicted, and find the root cause behind related entries: writes a project rule that removes it, or proposes a plugin change. write-tests and write-code-from-tests run it in a fresh agent at the end of their review steps; with no issue argument it only looks for root causes. The cache's only writer."
argument-hint: "[issue # and the skill it serves, or nothing to only look for root causes]"
model: sonnet
effort: medium
---

# Maintain cache

You keep the project cache, `.claude/contract-first-cache.md`, so the next run doesn't rediscover what this one had to work out. Run in a session that did not write this run's tests or code; if this one did, stop and say so, because the stage must hand the work to a fresh agent. Don't read the authors' reasoning: read what the run produced and record the facts in it. Run with no issue, skip straight to Find the root cause.

You receive the skill you serve (`write-tests` or `write-code-from-tests`), the issue number, that skill's rules, the current cache lines for it, and the run's record. For write-tests, that record is the spike's friction log, the design check and fidelity findings with their dispositions, and the repairs. For write-code-from-tests, it is the triage verdicts, the stale-test batch, the deferred-verification results, and the local check and CI failures. You are the only writer of the cache: the stage that dispatched you commits your changes unchanged. Edit only the cache file, the project rules file and, on a code-stage run, a lint that enforces a rule you wrote, in the worktree you are given, and commit nothing.

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
2. **Write the rule that mitigates the cause.** State its goal and the principle behind it, never the list of entries it covers. Name the entries it makes unnecessary and the cost of following it. Then decide where it belongs:
   - **This project** (how this repo is designed, built or worked on): write it yourself, in the project rules file (below).
   - **The plugin** (how the pipeline works, so it would recur in any project): the plugin's skills belong to the human. File one issue with the rule, the entries and their sources, and the cost, posted from a file, never through a shell argument. Mark each covered entry `| rule-proposed: #<n>` so no later run proposes it again.
3. **Re-file the covered entries.** After writing a project rule, rewrite each entry it covers as an application of it (its rule field naming the rule's ID), or remove the entry when the rule makes it obvious. For a plugin proposal now closed: if adopted, do the same against the skill's new rule; if declined, replace the mark with `rule-declined: #<n>` and leave the entries.

### The project rules file

`.claude/contract-first-rules.md` holds rules agents wrote for this project. write-tests and write-code-from-tests read it alongside the project's principles document. If it doesn't exist, create it with a `# contract-first rules` heading and one line saying what it holds. One rule per line:

`- R<n> | <rule: goal and principle> | why: <the cause it removes> | src: #<issue>`

A rule may also be a check: when a machine can find the shape, the rule names the lint that enforces it. A lint is code, so write it only on a write-code-from-tests run, in that PR; on a write-tests run, write the rule and leave its lint to the next code-stage run.

Limits on what you write here:

- **Principles win.** A rule never contradicts the project's principles document, a CLAUDE.md file or a human decision in a design. If the cause can only be fixed by changing one of those, propose it as an issue instead.
- **Evidence first.** Write a rule only for a cause at least two entries share, and cite them.
- **Revise your own kind only.** You may rewrite or retire a rule in this file when entries contradict it, saying so in your report. Never edit a rule a human wrote or changed; if the human edited a line, treat it as theirs.
- **Requirements stay out.** A rule says how this project is designed or worked on, never what one feature must do; that belongs in its design.

Also merge plain duplicates (two lines stating the same fact) into one line that keeps every source. Within a skill only: when two skills need the same fact, each keeps its own line. Never change what an entry claims, and never turn facts into a requirement in the cache: what should hold is a rule's job.

## Return

The cache diff, and per change one line: added, replaced, removed or merged, with the run evidence behind it, or for a merge, the lines it folded. Then each rule written to the project rules file and each plugin rule proposed (with its issue number), with the entries it covers; and each earlier proposal settled. Then any facts you left out as requirements or as project-agnostic, each in one line.
