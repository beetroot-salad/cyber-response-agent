# Investigation Review and Learning Loop

## Status

This document describes an **offline learning mechanism** that mines completed
investigations for reusable lessons and ships them as pull requests against the
playbook / knowledge base. It is not a real-time guard.

The live investigation path is unchanged: a single investigator with optional
same-context self-review (described briefly below for completeness, but not the
focus of this doc).

The previous version of this doc bundled live review and cross-case learning
together and proposed a heavyweight schema (multi-axis subjective rewards,
canonical taxonomy, anti-scope fields, addendum library, retrieval algorithm).
That scope was wrong for where we are. This version replaces it with a much
lighter schema and a PR-based delivery mechanism.

## Purpose

Improve investigation **correctness and efficiency** by sampling counterfactual
actors against completed cases and converting their findings into concrete
playbook edits.

Two modes:

1. **Adversarial-defender** — could a competent adversary have survived this
   exact lead sequence? If yes, what assumption let them through?
2. **Benign-defender** — if the defender had simply phoned the (legitimate)
   operator or service-account owner, would they have been "washed" — told
   that the question could have been answered cheaply with one specific query?

Both modes produce concrete, citation-backed edits to playbooks and knowledge
docs, delivered as pull requests.

## Design Principles

1. **Offline only.** No live latency cost. No production gating. The curator
   is a human reviewing a PR.
2. **One reward signal per mode.** No additive subjective scoring. Adversarial
   reward is `survives_evidence: bool`. Benign reward is
   `was_in_lead_set: bool`.
3. **Concrete observables only.** A lesson must name a specific field,
   artifact, or system-of-record query. Abstract advice is rejected.
4. **PRs as the audit trail.** Lessons land as inline edits to playbook /
   knowledge files via PR. Git history is the lesson store. CI can be added
   later to gate promotion.
5. **No addendum library, no retrieval engine, no taxonomy.** The playbook is
   the addendum library. Retrieval is whatever the live investigator already
   does when it loads its skill prompt.

## Loop Shape

```text
Completed investigation (alert.json + investigation.md + report.md + tool_trace.jsonl)
        │
        ├── Adversarial-defender run ──┐
        │                              │
        ├── Benign-defender run ───────┤
        │                              │
        ▼                              ▼
   findings.yaml (per-mode)     findings.yaml (per-mode)
        │                              │
        └──────────────┬───────────────┘
                       ▼
            Lesson author agent
                       │
                       ▼
            Playbook / knowledge edits in a worktree
                       │
                       ▼
                     Pull request (human review)
```

## Adversarial-Defender Mode

### Goal

The adversary's objective is to pass as benign through the actual lead
sequence the investigator pursued. The defender's objective is for the lead
sequence to break the adversary's story.

### Variants

Three exposure levels, in increasing usefulness:

1. **Direct review** — adversary reads the full investigation and proposes
   where reasoning is brittle. Cheap; biased because the adversary sees the
   answer.
2. **Black-box story** — adversary reads only `alert.json` and writes a
   malicious story consistent with it. Tests intrinsic alert ambiguity, not
   investigator quality.
3. **Gray-box: leads-only reveal** *(primary)* — adversary sees `alert.json`
   plus the ordered lead contracts PREDICT selected (lead definitions, not
   answers). Adversary writes the most coherent malicious story consistent
   with that lead set.
   Then the actual lead results are revealed. Adversary self-reflects on
   whether the story survived.

Gray-box is the primary mode because it directly tests whether the lead set is
**discriminating** rather than **confirming**.

### Lead set projection

The "lead set" is the ordered set of PLAN → GATHER lead contracts used in
the investigation, not a loose prose summary of what the investigator did.
Each entry pairs a free-form lead description (PLAN's intent: goal + what
to characterize) with the **query template** GATHER actually ran. The
template id + bound parameters are the cross-case key the learning loop
joins on — not a lead slug. PLAN does not pick from a slugged lead
catalog; GATHER picks (or mints) a query template per lead, and the
template id is what makes a lead addressable across cases.

The learning job materializes that ordered contract as:

```yaml
lead_sequence:
  case_id: <run id>
  entries:
    - position: 0
      mode: single | composite
      lead_description:
        goal: <PLAN's measurement contract>
        what_to_characterize:
          - <dimension the gather result must characterize>
        emphasis: <optional PLAN emphasis, or null>
        scope: <window / anchor scope, if present>
      query_template:
        id: <system-prefixed kebab, e.g. wazuh.auth-events-by-host>
        source: catalog | minted    # `minted` = GATHER created it on the fly
        params: {<param>: <bound value>}
      legs:                          # populated only when mode == composite
        - lead_description: {...}
          query_template: {...}
      gather_status: <ok | partial | data_missing | empty | error>
      result_ref: <citation to actual result, hidden during gray-box story phase>
```

The cross-case key is `(query_template.id, params)`. Templates minted in
one run are written back to the per-system catalog (under
`defender/skills/gather/queries/{system}/`
in the POC), so the catalog grows organically with usage — early
near-duplicates are accepted and normalized downstream when patterns
stabilize.

For gray-box adversarial runs, the actor first sees `alert.json` plus the
answer-redacted lead contracts: `position`, `mode`, `lead_description`,
`query_template` (id + params — the actor sees *what query ran*, not what
it returned), and composite `legs`. The `gather_status` and `result_ref`
material are revealed only after the story is written. If the PLAN/GATHER
contract cannot be projected cleanly, the learning run is rejected rather
than asking the actor to infer the lead set from prose.

> **Production note.** The legacy `knowledge/common-investigation/leads/`
> slug catalog (used by the production `soc-agent/` investigate loop) is
> unchanged; production runs continue to project a slug-keyed
> `selected_lead`. The query-template keying above is the contract for
> the `defender/` POC and any future
> defender that drops the slug catalog. The learning-loop tooling treats
> `query_template.id` and `selected_lead` as parallel cross-case keys
> during the transition.

### Schema

```yaml
adversarial_run:
  case_id: <run id>
  mode: gray_box | direct_review | black_box
  lead_sequence_ref: <runs/{run_id}/learning/lead_sequence.yaml>
  story: <causal chain consistent with leads pursued>
  survives_evidence: true | false
  survival_check:
    checked_by: independent_judge
    agrees: true | false
    note: <short rationale>
  breaking_observation: <field/artifact that killed the story, or null>
  exploited_assumption: <investigator assumption that almost let it pass, or null>
  suggested_lead: <one concrete additional lead that would have caught this, or null>
  evidence_refs:
    lead_results: [<refs used in the evidence reveal>]
    survival_rationale: [<refs supporting survives_evidence or breaking_observation>]
    suggested_lead_basis: [<refs supporting the suggested lead, or []>]
```

The reward signal is still only `survives_evidence: bool`. `survival_check`
and `evidence_refs` are audit metadata, not extra scoring axes. No confidence
ratings. No `protects_against`, no `discriminator_class`, no anti-scope.

If `survives_evidence: true` and the independent survival check agrees, the run
is a finding — the lead set was not discriminating against this attack class.
The `suggested_lead` becomes the lesson candidate.

If `survives_evidence: false`, log the run for later analysis (it confirms the
lead set works against this story class) but no PR is generated.

## Benign-Defender Mode

### Mental model

> The defender calls the operator (or the service-account owner). The operator
> answers, then washes them: "you could have verified this yourself by
> doing XYZ." XYZ is a concrete query against a system of record.

If XYZ was already in the lead set, the investigation was efficient. If XYZ
was *not* in the lead set, that's the lesson: the playbook is missing a
cheap, decisive legitimacy check.

### Schema

```yaml
benign_run:
  case_id: <run id>
  lead_sequence_ref: <runs/{run_id}/learning/lead_sequence.yaml>
  minimum_resolving_query:
    system_of_record: <CI/CD | IAM | ticketing | change-calendar | orchestration-audit | ...>
    query: <concrete query, field, or API call>
    expected_answer: <what would resolve the case as benign>
  was_in_lead_set: true | false
  position_in_sequence: <int — index in actual lead order, or null if absent>
  sequence_savings: <int — leads after position that became unnecessary, or null>
  evidence_refs:
    minimum_query_basis: [<refs proving this system/query exists>]
    lead_sequence_match: [<refs proving the query was present, late, or absent>]
```

If `was_in_lead_set: false`, the lesson candidate is "add this query to the
playbook." If `was_in_lead_set: true` but `position_in_sequence` is late,
the lesson candidate is "reorder this query earlier." If
`position_in_sequence == 0`, no finding.

The benign actor must name a query against an actual system of record present
in the environment. "The operator would have told you" without a system query
is rejected — that's the post-hoc rationalization failure mode.

## Lesson Delivery via Pull Request

### Pipeline

1. **Run** — async job samples either adversarial or benign mode against a
   completed case, writes `lead_sequence.yaml` and `findings.yaml` to
   `runs/{run_id}/learning/`.
2. **Author** — a lesson-author agent reads `findings.yaml` and the current
   playbook for the signature, decides where the edit belongs (one of:
   `knowledge/signatures/{sig}/playbook.md`, `knowledge/signatures/{sig}/
   archetypes/{arch}/README.md`, `knowledge/common-investigation/leads/`,
   `knowledge/environment/operations/{anchor}.md`), and stages inline edits
   in a worktree.
3. **PR** — orchestrator opens a PR with title `[lesson] {sig}: {one-line
   summary}`, body containing: finding type, citation to source run,
   schema-form findings, and rationale for placement.
4. **Human review** — reviewer accepts, edits, or rejects. CI can be added
   later (e.g., replay the PR's edits against a held-out fixture set and
   block on inverse-failure rate).

### Why PRs, not an addendum library

- Git history is the audit trail. No separate `runs/_lessons/lessons.yaml`
  to maintain.
- Edits land in the same files the investigator already reads at skill-load
  time. No retrieval algorithm, no prompt projection, no 2KB budget.
- A reviewer can edit-in-flight, which is the only realistic inverse-failure
  filter at this stage.
- CI can later replay learning-derived PRs against a fixture corpus before
  merge — the cleanest possible inverse-failure measurement.

### Citation requirement

Every PR must cite at least one source run id and either the breaking
observation (adversarial) or the missing minimum query (benign). PRs that
modify shared knowledge (`common-investigation/`, `environment/operations/`)
must cite at least two source runs across distinct signatures, to avoid
fixture-specific rules leaking into shared surfaces.

The citation source is the structured `evidence_refs` block in
`findings.yaml`. A lesson-author PR may add prose rationale, but it cannot
invent new evidence after the finding is emitted; if the needed citation is
missing, the finding is rejected or re-run.

## Sampling Policy

One mode sample per completed case (cost control), with mode assignment drawn
from a tunable policy rather than a fixed disposition map.

Initial policy:

1. **Counter-disposition sample** *(default)* — resolved-benign cases sample
   adversarial-defender; resolved-malicious or threat-escalated cases sample
   benign-defender. This tests the question most likely to expose false
   closure: "what would have flipped the call?"
2. **Random exploration bucket** — reserve a guessed fraction of cases for
   random mode assignment, stratified by signature and severity. This prevents
   the learning loop from only finding failures we already expected.
3. **Ambiguous / inconclusive cases** — sample either mode, with preference for
   the mode that is underrepresented for that signature in the current month.

No statistical tuning at MVP stage. Start with an explicit guessed distribution
(for example, mostly counter-disposition with a smaller random bucket), then
aggregate findings monthly. If one mode or signature dominates accepted PRs,
that is a playbook gap signal — no formal test required yet.

## Live Self-Review (Brief)

Out of scope for this learning loop, but noted for completeness:

The live investigator may run a same-context self-review before commit that
asks "what counter-disposition story explains the same observations, and is
there one cheap missing check?" This is a separate workstream. The schema
above is intentionally independent of it — learning runs against the
investigation as it actually happened, regardless of whether self-review
fired.

## Run Artifacts

```text
runs/{run_id}/learning/
  lead_sequence.yaml    # projected ordered lead contracts, result refs included
  findings.yaml         # adversarial_run or benign_run record
  prompt_inputs.md      # what the actor saw (gray-box reveal log)
  pr_url               # populated after PR opens
```

The PR itself is the lesson record. There is no separate lesson store.

## MVP

1. Implement lead-sequence projection against existing run artifacts.
2. Implement gray-box adversarial mode against existing fixtures. One agent,
   one prompt, schema output.
3. Implement benign-defender mode against completed fixtures selected by the
   sampling policy.
4. Implement independent survival check for adversarial findings.
5. Implement lesson-author agent that converts a `findings.yaml` into a
   worktree of inline edits and opens a PR.
6. Run manually on ~10 cases per signature; review PRs; iterate on author
   prompt until placements are correct ≥80% of the time without human
   reshuffling.
7. Defer: scheduling, automatic CI gating, holdout replay, multi-mode
   sampling, calibration.

## Evaluation

- **Adversarial mode**: of cases where `survives_evidence: true`, what
  fraction yielded a PR a reviewer accepted without rewrite?
- **Benign mode**: of cases where `was_in_lead_set: false`, did the
  proposed minimum query actually exist as a tool/query in the environment?
- **Citation validity**: fraction of findings whose `evidence_refs` resolve to
  the claimed run artifact and support the finding.
- **Survival-check quality**: adversarial actor / independent judge
  disagreement rate, reviewed manually for the first batch.
- **PR quality**: human edit distance between authored diff and merged diff.
- **Inverse failure (deferred)**: replay merged lesson PRs against a
  held-out fixture set; measure correct-disposition runs that the lesson
  would have made worse.

## Open Questions

- Where does shared knowledge live when a lesson recurs across signatures?
  `common-investigation/leads/` is the obvious target, but the two-signature
  citation rule may be too strict early.
- Should the lesson-author agent see prior accepted PRs as exemplars? If
  yes, how to avoid drift toward a single editing style.
- For benign mode, how strict should "system of record actually queryable"
  be enforced? Hard-fail in the schema, or accept and flag in the PR body?
