# Scoring rubric — hypothesize subagent outputs

For arm outputs. Not part of the runtime prompt. Each criterion is
pass/fail against the shape taught by `system-prompt.md`.

## Structural

1. **One-hop form.** Every hypothesis names `attached_to_vertex`, a
   single `proposed_edge.relation`, and a single `parent_vertex`
   `{type, classification}`. No multi-hop narrative in the label or
   claim.
2. **Leanness.** ≤ 2 predictions per hypothesis. Each prediction names
   one attribute of one vertex (no conjunctions packing attributes
   across multiple vertices).
3. **Refutation shape present** and observable by the named lead.
4. **Hierarchical IDs on refinement.** When a parent is shelved,
   children use `h-{parent}-{ordinal}` IDs; `shelved:` list names the
   parent.
5. **Output fields complete** — `id`, `name`, `attached_to_vertex`,
   `proposed_edge`, `predictions`, `refutation_shape`, `weight: null`.

## Entry discipline

6. **Fork exists.** ≥ 2 competing classifications whose predictions
   diverge on an observable field. If not, output is a GATHER block
   with lead-level predictions, not a HYPOTHESIZE block.
7. **No parallel adversarial hypothesis.** No entry that attaches to a
   hypothetical future edge to cover "what if this is bad." Legitimacy
   is treated as an attribute.

## Content discipline

8. **Mechanism-shaped labels.** Classification names a topology or
   mechanism (`in-container-runtime-descendant`, `runtime-exec-
   injection`, `sanctioned-automation`, `unsanctioned-origin`). No
   narrative umbrellas (`?credential-guessing`, `?post-exploit-shell`,
   `?dga-malware`).
9. **No pre-decomposition at loop 1.** Sub-archetypes
   (`monitoring-probe` vs. `k8s-exec-probe`; `app-spawned-shell` vs.
   `post-exploit-interactive`; `credential-stuffing` vs. `external-
   bruteforce`) are disposition-layer distinctions, not loop-1
   hypothesis peers.
10. **Coverage across plausible mechanism buckets.** At least one
    hypothesis per applicable bucket for the signature (topology
    variants, sanctioned vs. unsanctioned legitimacy when mechanism is
    established, etc.). Pruning by observable is fine; silent omission
    is not.

## Lead and pitfalls

11. **Selected lead discriminates the active set.** The named lead's
    outcome field partitions the hypotheses (or a composite is
    justified).
12. **Per-hypothesis pitfalls.** One or two alert-specific traps per
    active hypothesis. Not generic lead pitfalls.

## Scoring

A pass requires all of 1–7 and at least 10 of 12 overall. 1–7 are
structural and not negotiable — a hypothesize block that fails any
structural criterion is unusable regardless of content quality.
