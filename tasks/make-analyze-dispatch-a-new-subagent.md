---
title: Make analyze dispatch a new subagent
status: done
groups: cost, context-management, subagent-extraction
---

Extract the ANALYZE phase of the investigation loop into a dedicated subagent. The main investigation agent hands off truncated investigation context + GATHER output; the subagent returns a weighted ANALYZE block + routing decision; the main agent acts on it.

**Motivation:** ANALYZE consumes a large share of the main loop's tokens (structured weighing of hypotheses, rollup reasoning, refutation checks) — most of which is *not* load-bearing for later phases. Extracting it keeps the main context lean and enables model-tier specialization (cheaper tier for ANALYZE, Sonnet for the main loop).

---

## Empirical basis (pilot results)

Pilot experiment under `docs/experiments/analyze-subagent-pilot/` ran three rounds across two fixtures with multiple context-bundle variants.

### Decided

1. **Contract shape: decision-owning.** The subagent produces grades, routing (CONCLUDE vs HYPOTHESIZE), and — when routing to CONCLUDE — the disposition + confidence + archetype claim. Callers in the trust-handoff test accepted this output cleanly and did not re-run grading work.

2. **Minimal bundle is sufficient.** The required inputs are:
   - Truncated investigation log (CONTEXTUALIZE + SCREEN + HYPOTHESIZE, with prior ANALYZE blocks for rollup context)
   - GATHER lead output for the just-run loop
   No pre-commitments supplement, no org-context supplement, no archetype-README access. Arm A (minimal) matched Arm C (enriched) on grade accuracy and routing on both fixtures in Rounds 1-v2 and 2.

3. **Archetype anchor grounding stays with `validate_report`.** The subagent makes an archetype *claim* (e.g., `matched_archetype: opportunistic-scanner`). The anchor-grounding check (confirming `required_anchors` are satisfied or a precedent snapshot is matched) is enforced at the `validate_report` hook, not inside ANALYZE. Both trust-handoff callers reached the same conclusion independently.

4. **Self-report slot for anomalies in prior log.** Subagent prompt should include a self-report section with an explicit "anomalies or inconsistencies noticed in the prior investigation log" line. The stress test showed that the subagent detects poisoned upstream grades through structural reasoning about refutation discipline; surfacing these in self-report (not in the ANALYZE body) gives callers a channel for error detection without polluting the main output.

5. **Discretionary error-flagging.** The subagent prompt includes a license to flag prior-loop grade defects ("If a prior grade appears unjustified or inconsistent with the refutation discipline, you may flag it in your reasoning"). Keep this discretionary, not mandatory — a spurious flag on a legitimate upgrade would be worse than a silent correction.

### Open

- **Haiku-tier accuracy.** All pilot arms used Sonnet. Before production extraction, run one round of Arm A minimal bundle on `claude-haiku-4-5` to check whether grade + routing accuracy + refutation discipline + anomaly detection all hold at the cheaper tier. If yes, ship with Haiku.
- **Wrong-grade defective ANALYZE detection.** The over-trust round tested silent-drop and ungrounded-reasoning defects; both were caught. A wrong-grade defect (evidence clearly refutes, subagent grades `+`) is not yet tested.
- **Longer rollup chains.** Current mid-loop fixture is loop 3. A 4–5 loop fixture would exercise longer rollup drift opportunity.
- **Hypothesis-atomicity enforcement.** See `tasks/hypothesis-atomicity-invariant.md`. The Round 1 failures traced upstream to HYPOTHESIZE producing disjunctive hypothesis claims. ANALYZE extraction is downstream of fixing that invariant; without atomicity, ANALYZE accuracy collapses regardless of extraction.

### Retired concerns (disproved by the pilot)

- Checklist-bias in pre-commitments extraction (Round 1 v1 finding that did not survive Round 1-v2 with atomized hypotheses).
- Context level determines routing (disproved by Round 2 convergence across arms).
- Rollup drift accumulates error silently (stress round detected and corrected poisoned upstream grade).
- Caller over-trust (both over-trust runs produced correct REJECT with specific defect citations).

---

## Open question: discoverability / file-index

During the pilot, subagents (and the caller agents) repeatedly had to infer structural context that would be easier to look up via a tagged index. Examples:

- "Where is the archetype README for `opportunistic-scanner`?" — subagent and caller both wished for this; answer lives at `soc-agent/knowledge/signatures/{signature-id}/archetypes/{name}/README.md`, but the path is not surfaced anywhere the subagent would see.
- "Where is the grounding recipe for anchor `approved-monitoring-sources`?" — answer lives at `soc-agent/knowledge/environment/operations/approved-monitoring-sources.md`.
- "Where are the pitfalls for lead `authentication-history`?" — `soc-agent/knowledge/common-investigation/leads/authentication-history/definition.md`.

Currently the knowledge base relies on:
- CLAUDE.md's architecture table (describes directories, not individual files)
- `!command`-style import resolution in the investigate skill (bakes context into the prompt at load time)
- Implicit knowledge from the agent's training that "archetypes live under signatures/"

There is no top-level **INDEX** — a tagged, grep-friendly file that answers "where is the doc for X?" across: signatures, archetypes, anchors, leads, systems, environment operations, skills.

**Proposed approach (draft, for evaluation):**
- One `INDEX.md` per knowledge subtree (signatures/, environment/, common-investigation/, skills/) with a flat list: `tag: short-description → path`.
- Tags are short keywords (`archetype:opportunistic-scanner`, `anchor:approved-monitoring-sources`, `lead:authentication-history`, `system:wazuh`, `op:grounding`, `op:threat-model`).
- Grep-friendly shape: each entry one line, starts with `tag:`, colon-separated, no tables.
- Optionally: a root INDEX.md that points to the subtree INDEX files.

This is distinct from (and complements) the `@import:` resolver — the resolver bakes content into the prompt at skill load; the index tells an agent *where to look* when it needs to fetch something not pre-baked.

**Verify before building:**
- Confirm no existing INDEX.md or equivalent (checked 2026-04-18 — none found at `/workspace/docs/INDEX.md`, `/workspace/INDEX.md`, or `/workspace/soc-agent/knowledge/INDEX.md`).
- Check whether lead `definition.md` / archetype `README.md` frontmatter already carries tag-like fields that could be aggregated rather than hand-authored (some leads have frontmatter; not yet surveyed for uniformity).
- Decide whether INDEX is hand-maintained or generated from frontmatter (generation beats hand-sync).

This is a separate task, but adjacent: the ANALYZE subagent's self-reported context gaps ("wished for archetype README") are one concrete user of a good index. Filing here as context; if we pursue the INDEX, split into its own task.

---

## Next concrete steps

1. Run the Haiku-tier Arm A replication (one round, existing fixtures, Haiku-4-5).
2. If Haiku passes: author the ANALYZE subagent prompt at `soc-agent/skills/investigate/analyze.md` using Arm A minimal-bundle prompt as the template.
3. Wire the ANALYZE dispatch into the investigate SKILL.md main loop (extract phase boundary, inject subagent call with truncated log + lead output).
4. Promote `tasks/hypothesis-atomicity-invariant.md` as a blocking upstream invariant — the ANALYZE subagent's accuracy depends on it.
5. (Separate task, if pursued) Author INDEX.md across the knowledge subtrees.

---

## Pilot artifacts

- Skill: `.claude/skills/analyze-pilot/SKILL.md`
- Experiment dir: `docs/experiments/analyze-subagent-pilot/`
  - `fixtures/case-rule5710-loop1/` — ambiguous-routing fixture
  - `fixtures/case-ssh-brute-loop3/` — crisp-routing mid-loop fixture
  - `fixtures/case-ssh-brute-loop3-poisoned/` — rollup-error stress (directory-name-leak variant)
  - `fixtures/case-ssh-brute-loop3-var1/` — rollup-error stress (neutral name)
  - `rounds/round-1/` — baseline run (disjunctive hypothesis; retired)
  - `rounds/round-1-v2/` — atomized hypothesis run (6/6 all arms)
  - `rounds/round-2/` — mid-loop run (4/4 all arms, CONCLUDE converged)
  - `rounds/round-3-stress/` — poisoned fixture + trust handoff
  - `rounds/round-3-stress-neutral/` — neutral-name replication
  - `rounds/round-3-trust-handoff/` — clean and ambiguous handoff runs
  - `rounds/round-3-over-trust/` — silent-drop and ungrounded-`++` defective-ANALYZE runs