# `/author` — Design Rationale

**Version:** 0.2 | **Date:** April 2026 | **Status:** Shipped

Why `/author` is shaped the way it is. The **what** and **how** live in `SKILL.md`; this file captures the decisions behind those choices so future edits don't accidentally unwind them.

---

## 1. Problem statement

Every knowledge-base change today is hand-edited, and there is no guardrail against:

- Writing a playbook that references a lead definition or archetype that doesn't exist.
- Adding an archetype whose `required_anchors` aren't defined in `environment/operations/`.
- Breaking `resolve_imports.py` by referencing a missing `@import:` atom.
- Writing knowledge that parses fine but doesn't actually communicate — a reader cannot reconstruct the SIEM rule from a `context.md`, or cannot name the discriminator between two archetypes from a playbook.
- Silently regressing runtime behavior — a screen pattern that now matches cases it shouldn't, a hypothesis space that quietly shrank, a prescriptive rule that got softened.
- Drifting from the design philosophy ("grounded in real data", conservative, hypothesis-driven) without anyone noticing until the next investigation surfaces the drift.

`/author` is the one workflow that handles all of these — the human-driven editor for `knowledge/` and `config/signatures/`. Automated post-mortem learning is a sibling pipeline (`scripts/postmortem/`, see `skills/handbook/content/postmortem.md`) that fires at Stop and proposes lead-pool edits as a PR; it does not invoke `/author` and is scoped to `knowledge/common-investigation/leads/` in slice 1.

---

## 2. Design principles

1. **Handbook is the library; `/author` is the editor.** When the skill needs to know where things live, what the runtime rules are, or how the report judge behaves, it invokes `/handbook` rather than carrying its own copy of that knowledge. One source of truth.
2. **Knowledge-only scope.** `/author` edits `knowledge/` and `config/signatures/`. Never `schemas/`, `scripts/`, or `hooks/`. Code changes go through normal review.
3. **Git is version control.** We assume the KB is a git working tree. No dry-run, no soft-revert, no audit log — rollback is git. The skill does not commit, branch, or push.
4. **Validate every edit.** Deterministic checks, then probe evidence, then self-reflection on that evidence. Uncommunicative or regressed knowledge is as bad as structurally broken knowledge.
5. **Fail loud on ambiguity.** Same rule as the rest of the plugin: when a file location, field name, or intent is unclear, surface it. Never guess silently.
6. **Trust the agent to scope.** The skill doesn't classify edits into four buckets or walk a state machine. Sonnet is smart enough to decide whether a task needs planning — over-structuring the prompt teaches it rigidity, not judgment.

---

## 3. Handbook relationship

The biggest architectural choice in this skill. Handbook documents KB layout, two-leg resolution, the report judge, and the investigation loop. `/author` **consumes** all of that by invoking `/handbook` on demand; it does not duplicate the content in its own prompt.

Reasons:

- The KB surface is too large and too volatile for `/author` to pin a copy. Two signature models landed in parallel (archetype-as-directory, precedent snapshots); the next refactor will move things again.
- Handbook is read-only by contract. `/author` is read-write. Clean separation keeps both honest.
- When layout changes, only the handbook content files get updated. `/author` picks up the new reality automatically.

Rejected alternative: bake "here's how the KB is structured" into `SKILL.md`. This is what the Claude Code `statusline-setup` agent does — it has its own bundled knowledge. That works when the surface is tiny and stable (one config file, one schema). Ours is neither.

What `/author`'s `SKILL.md` owns, then: workflow, validation philosophy, and the ground rules. Nothing about KB layout.

---

## 4. Validation

Three aspects. `SKILL.md` has the operational detail; this section explains *why* each aspect exists.

### Deterministic checks

No LLM. `resolve_imports.py`, schema pytest, Grep-based cross-ref checks, `list_lead_tags.py` for tag vocabulary. These catch a specific class of failure — dangling references, broken imports, malformed frontmatter, tag drift — that a reader probe would also catch but less reliably and more expensively. Running deterministic first is a fast-fail: if the file is structurally broken, there's no point probing it.

### Tag consistency for query templates

Lead query templates (`leads/{name}/templates/{vendor}.md`) declare a flat `tags` list in frontmatter. The tag list is the discovery surface — the investigation agent greps sibling templates by tag overlap when constructing novel queries, so tag drift silently degrades discoverability. Three layers guard against drift:

1. **Shared vocabulary via `list_lead_tags.py`.** A general utility under `scripts/tools/` that collects every existing tag across `leads/*/templates/*.md` and, in `--check` mode, reports tags on a target file that are new to the vocabulary or near-duplicates of an existing tag (`auth` vs `authentication`, `net` vs `network`). Near-duplicate detection is prefix-based — cheap and deliberately noisy, because a false positive is a short human decision and a false negative is a silent discoverability hole.
2. **Snake_case convention.** The same script validates every tag against `^[a-z][a-z0-9_]*$`. Picking one convention and enforcing it deterministically is cheaper than arguing taste in review. Snake_case specifically because the rest of the KB's identifier surface (Python modules, anchor names) leans the same way.
3. **Tag-search probe.** Haiku runners are spawned with fabricated investigation context and asked to *search* for the queries they need — never asked *what tags would you pick*. The framing matters: asking "what tags should this have" cues the subagent to reason about the tagging system, which produces tidy, theory-driven terms. Asking them to search in the middle of a realistic scenario surfaces the vocabulary a reader actually reaches for under pressure. Two runners with different scenarios give two independent vocabulary samples; zero overlap with the declared tags means the template is invisible to the exact investigations it serves.

The three layers sit at different levels of the problem. The enum script enforces *consistency with what already exists*. The convention enforces *shape*. The search probe validates *discoverability from the reader's side* — whether the tags match the vocabulary a real investigator would produce. None of the three alone is sufficient: consistency without discoverability just perfectly preserves a bad vocabulary, and discoverability without consistency lets every new template invent its own dialect.

### Probes (evidence, not verdicts)

Four Haiku probes. Each targets a specific failure mode. Each produces structured evidence, not a grade. **You are the only judge** — only the main agent has the edit intent and the full surrounding context, so only it can decide whether a probe's output reflects a real problem or an expected difference.

This split matters. An earlier draft of this design had subagents "grade the edit," and the natural instinct was for the reviewer to contaminate its own judgment with the intent. Separating evidence from verdict removes that failure mode.

**Tag-search** — observes the vocabulary a reader reaches for mid-investigation, framed as a search task rather than a tagging question. See "Tag consistency" above for the dispatch pattern and rationale; it's listed as a probe here because it produces evidence (search terms) that the main agent compares against the declared tags, same contract as every other probe.

**Reconstruction** — the most important probe. The question it answers: *can a reader regenerate the real underlying artifact from the description?* For a `context.md`, that means writing the SIEM detection rule in native syntax. For an archetype `story.md`, the canonical alert JSON and a one-line closing reason. For a lead definition, the query the lead runs plus the fields it examines.

This is strictly stronger than "summarize the file." A summary that says "this archetype matches monitoring probes" passes a comprehension check. A reconstruction that produces an alert skeleton missing the `srcip` classification rule *fails* — because an agent at runtime cannot execute the rule from a description that leaves out the internal-vs-external distinction.

Comparison target is the pre-edit `git diff` plus (when available) the actual underlying artifact — the real Wazuh rule, the real historical alert. When those aren't locally available, the reviewer compares against the pre-edit reconstruction instead, which still catches information loss introduced by the edit.

**Comprehension** — targeted questions the file is supposed to answer ("what discriminates `?X` from `?Y`?", "what anchors must confirm before this resolves?"). Catches prescriptive weakening, internal contradictions between frontmatter and body, and typo'd field names. Simpler than reconstruction; also cheaper.

**Coherence** — given N related files, report what each says about shared topics. No pair restriction — a playbook + context + two archetypes is a valid probe target. The reviewer reads the paired statements and decides whether they contradict.

**Replay** — traces **two steps** of an investigation against the edited playbook: step 1 is the first hypothesis and lead; step 2 is what happens next given two plausible outcomes of that lead. One step of replay is not enough — many investigations resolve only on step 2 or later, and an edit can quietly change the step-2 path while the step-1 selection looks unchanged. The reviewer compares the traced path against historical traces in `runs/*/report.md` and archetype example JSONs.

Total probe cap per edit: **10**. Sanity boundary, not a target. 10 is well above what any routine edit needs; it exists to catch runaway re-probing loops rather than clamp normal use.

### Self-reflection

Three questions, answered with probe evidence:

1. **Did the edit lose information?** — reconstruction vs. pre-edit comparison.
2. **Did the edit introduce contradiction?** — comprehension and coherence.
3. **Would past investigations still resolve correctly?** — replay.

If any answer surfaces an unresolved concern, re-edit and re-probe. Cap at 3 iterations, then escalate to the user with the evidence. No infinite loops.

### Known gaps

Being honest about what this model doesn't catch:

- **Real runtime fidelity.** Haiku replay approximates a Sonnet-size investigator. It can miss regressions the real investigate agent would hit. Acceptable because the replay is a sanity check, not the last line of defense — git review and the live investigate feedback loop catch what this misses.
- **Multi-edit sessions.** Validation runs per-edit, so an intermediate broken state can validate if a later edit fixes it. Git's final state is what matters; intermediate validation is advisory.
- **Grounding in real tickets.** The main agent asks "is this grounded?" but neither it nor Haiku can verify a claim is backed by a real ticket the agent doesn't have access to. That stays a human-review concern.
- **Future attack patterns.** Replay regression-tests only against history. New patterns are unrepresented by construction.
- **Subtle prescriptive drift.** "MUST" → "SHOULD" is detectable. "verify carefully" → "verify" may not be.

---

## 5. Model and cost

Main agent: **Sonnet 4.6**, pinned in `SKILL.md` frontmatter. Probes: **Haiku 4.5**, hardcoded in the Task dispatch.

Rationale:

- Sonnet is strong enough for every edit class including full-signature writes. Opus is a 5× cost jump for marginal judgment improvement on a task that's mostly structured content editing.
- No model-escalation logic. The earlier draft had Haiku-main-with-Sonnet-escalation-for-massive-edits, which required classifying every edit into a tier and adding state-machine complexity to the prompt. Dropped — the cost delta ($3.68/wk for Sonnet-everywhere vs $1.67/wk for Haiku-routine + Sonnet-massive) doesn't justify the complexity.
- Haiku probes stay cheap and parallelizable. Probes are ~$0.50/week regardless of main-agent choice.

Estimated cost at ~22 edits/week (2–3/day + 1 massive/week): **~$15/month uncached, ~$9/month with prompt caching.**

Override via `SOC_AGENT_AUTHOR_MODEL` environment variable. Set to `claude-opus-4-6` for higher-stakes environments.

---

## 6. SIEM access

`/author` has **no SIEM tools** in `allowed-tools`. Signature authoring that needs historical SIEM data is a two-step workflow:

1. `/investigate` runs in an exploratory mode against the SIEM, produces a scratch file with alert data, patterns, and recurring dispositions.
2. `/author` reads that scratch file as input material and shapes it into `context.md`, `playbook.md`, archetype dirs.

Three alternatives were considered and rejected:

- **Abstract `siem-read` capability tag.** Claude Code's `allowed-tools` is concrete (`Bash(...)`, `mcp__vendor__tool`), not abstract. No portable way to declare "I want SIEM read access" in frontmatter.
- **Hardcoded MCP patterns** (`mcp__*__query`). Brittle and skips the deterministic adapter-CLI path for deployments that don't use MCP.
- **Shared CLI invocation.** Would duplicate `/investigate`'s adapter logic, violate DRY, and force `/author` to know about vendor quirks.

The two-step flow keeps `/author` pure (knowledge files only, no external tools) and leans on the one place that already knows how to talk to the SIEM. When access models change (new vendor, MCP vs CLI, identity proxy), only the research step cares.

The research scratch format is TBD — see open question 1.

---

## 7. Open questions

Parked for follow-up:

1. **Research scratch format.** The `/investigate` → `/author` handoff (human-driven, when an analyst wants to bake learnings from a recent run) accepts whatever the caller passes — typically a run dir path. The automated post-mortem pipeline (`scripts/postmortem/`) is a separate path: it consumes `investigation.md` directly via `extract.py` and does not need a scratch format. Whether the human-driven `/author` flow ever needs a more structured handoff is open and depends on how often analysts invoke it after the automated pipeline runs.

2. **Probe quality baseline.** Haiku replay and reconstruction are sanity checks, not strong validation. Before relying on them, run an eval: take N past edits with known outcomes, see whether the probe layer would have caught the bad ones. Tracks the suite's true precision/recall.

3. **Template / schema drift.** When a schema gains a required field, existing files become invalid. `/author` should detect this during scope-and-understand and surface it to the user with three options: *defer*, *migrate all*, *mark as TODO*. Detection heuristic and UX are TBD. Out of scope for MVP.

4. **Idempotency.** Running the same request twice should not duplicate. Git makes this recoverable but not prevented. A fully idempotent skill-only implementation is possible (diff intended state against current state before editing) but adds complexity. Deferred.

---

## 8. Relationship to other skills

| Skill | Relationship |
|---|---|
| `/handbook` | Source of truth for KB layout and runtime rules. `/author` invokes it on demand; does not duplicate. |
| `/investigate` | Consumer of `/author`'s output. Post-mortem invocations hand off to `/author`. `/author` never invokes `/investigate`. Research-mode `/investigate` is the SIEM access path. |
| `/connect` (planned) | Sibling. Owns data-source wiring. `/author` writes knowledge that uses data sources; does not touch adapter configs. |
