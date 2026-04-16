---
title: Model gathering leads as first-class citizens in invlang schema
status: backlog
groups: invlang, investigate, schema
---

## Problem

The current skill frames all leads as discriminating — HYPOTHESIZE asks "which lead is most diagnostic?" and Class 8 (`lead_effectiveness`) scores leads by hypothesis weight delta. Gathering leads (entity profiling, session reconstruction, timeline enrichment) don't change hypothesis weights but enrich the investigation graph with additional vertices and edges. They are currently:

- Penalized by Class 8 (weight delta ≈ 0 → low effectiveness score)
- Excluded from lead selection guidance ("pick the most diagnostic lead")
- Recorded as low-value leads even when they meaningfully expanded the investigation context

## What gathering leads do

A gathering lead's purpose is to enhance *existing* vertices and edges in the investigation graph — not discover new hypotheses or discriminate between existing ones. Examples:
- "What did this user do in the past 7 days?" (entity profiling)
- "What other containers ran on this host in the same time window?" (scope enrichment)
- "Reconstruct the full session timeline for this IP" (temporal enrichment)

These leads inform CONCLUDE (scope, blast radius, analyst hand-off) and can narrow the field for later discriminating leads, but they don't directly move hypothesis weights.

## Changes needed

**Schema:** Add `lead_kind: discriminating | gathering | trust-anchor | scoping` to the companion lead block. Currently the `_infer_lead_type` function in `queries.py` infers type from outcome content — this should become an explicit field, with `_infer_lead_type` as a fallback for existing companions that lack it.

**Scoring:** Class 8's effectiveness score should filter to `discriminating` leads only (or accept a `--kind` flag to select which lead kinds to include). Gathering leads should be scored separately by graph enrichment: `vertices_added + edges_added` in the outcome's observation block.

**Skill:** HYPOTHESIZE guidance should distinguish "discriminating lead selection" from "gathering lead selection." Gathering leads are appropriate when the investigation graph is thin (few vertices, limited entity context) before hypothesis discrimination begins. The skill currently has no guidance for this choice.

## Why not in scope today

The schema addition is straightforward. The harder part is the skill-side guidance — when should the agent choose gathering over discriminating? This requires thinking through the investigation graph model more carefully, which is in-progress in `invlang-structured-observations.md`. Defer the skill change until that work lands; the schema field can be added independently.
