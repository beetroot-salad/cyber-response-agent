"""Past-investigation priors retrieval and rendering for PREDICT.

Two paths, picked at call time based on whether the investigation has a
prior `hypothesize:` block:

  - **Loop 1** (no prior `hypothesize:`): key retrieval off the *prologue*
    topology rather than synthesizing per-seed fingerprints that
    structurally can't match topology tiers 0–3. Falls back from
    same-signature to cross-signature scope when same-signature is empty.
    Renders a single "use this scaffold" recommendation when the corpus
    carries strong support, otherwise a sparse-prior fallback.

  - **Loop 2+**: extract the live frontier from the last `hypothesize:`
    block, resolve each hypothesis's topology against the prologue, run
    per-hypothesis topology retrieval, and render one section per entry.

Lifted out of predict.py because the priors flow is a self-contained
sub-concern: parse → retrieve → format. The handler delegates via
`_safe_priors_section` and falls back to a banner on any exception so
priors never block the loop.

invlang and the playbook loader are imported inline inside the helpers
that need them so a corpus / signature-config issue degrades to the
banner rather than blocking module import.
"""

from __future__ import annotations

from typing import Any


from scripts.orchestrate import Context

from scripts.handlers._markdown import iter_companion_dicts
from scripts.handlers._playbook import load_playbook_metadata


_PRIORS_LEADS_TOP_N = 5
_PRIORS_PEERS_TOP_N = 5

# Baseline-recommendation thresholds for the loop-1 prologue priors block.
# Calibrated against the current corpus depth (~40 companions); revisit as
# the corpus grows or if eval shows the recommendation missing real patterns.
#   - support (branching_support): the per-lead case count at this topology.
#     Below 5 we can't reliably distinguish signal from coincidence.
#   - fidelity (fidelity_rate): fraction of cases where the lead's
#     prediction materialized — i.e. the lead actually discriminated when
#     it was fired. Below 0.5 the prior is a coin flip.
_STRONG_PRIOR_MIN_SUPPORT = 5
_STRONG_PRIOR_MIN_FIDELITY = 0.5

def safe_priors_section(ctx: Context) -> str:
    """Produce the `## Past-investigation priors` markdown block.

    Loop-aware: at loop 1 (no prior hypothesize block) we key retrieval off
    the *prologue* shape rather than synthesizing per-seed fingerprints
    that structurally can't match topology tiers 0–3. At loop 2+ the
    hypothesis frontier carries real proposed upstream edges, so
    per-hypothesis topology retrieval works as designed.

    All exceptions degrade to a banner — priors must never block the loop.
    """
    try:
        frontier = _extract_current_frontier(ctx)
        is_loop_1 = not frontier or all(
            _fp_get_relation(e["fingerprint"]) is None for e in frontier
        )
        if is_loop_1:
            return _format_prologue_priors(_compute_prologue_priors(ctx))
        priors = _compute_priors(frontier)
        return _format_priors(priors)
    except Exception as exc:  # noqa: BLE001 — intentional broad catch
        return (
            "## Past-investigation priors\n"
            f"(priors unavailable: {type(exc).__name__}: {exc})"
        )


def _fp_get_relation(fp: dict) -> str | None:
    r = fp.get("relation") if isinstance(fp, dict) else None
    return r if isinstance(r, str) else None


def _compute_prologue_priors(ctx: Context) -> dict:
    """Loop-1 prologue-keyed retrieval.

    Reads the prologue from the run's `investigation.md`, runs
    same-signature-scoped prologue retrieval, and falls back to
    cross-signature when the same-signature pass returns no cases.
    """
    from invlang import (  # type: ignore
        lead_effectiveness_for_prologue,
        load_corpus,
        peer_hypothesis_distribution_for_prologue,
    )

    inv_path = ctx.run_dir / "investigation.md"
    text = inv_path.read_text() if inv_path.exists() else ""
    prologue, _ = parse_prologue_and_last_hypothesize(text)
    prologue = prologue or {}

    corpus = load_corpus()

    leads_same = lead_effectiveness_for_prologue(
        corpus, prologue, signature_id=ctx.signature_id
    )
    peers_same = peer_hypothesis_distribution_for_prologue(
        corpus, prologue, signature_id=ctx.signature_id
    )
    scope = "same-signature"
    leads = leads_same
    peers = peers_same
    if not leads_same.get("cases_matched"):
        leads_any = lead_effectiveness_for_prologue(
            corpus, prologue, signature_id=None
        )
        peers_any = peer_hypothesis_distribution_for_prologue(
            corpus, prologue, signature_id=None
        )
        if leads_any.get("cases_matched"):
            scope = "cross-signature"
            leads = leads_any
            peers = peers_any

    return {
        "prologue_signature": _prologue_signature_summary(prologue),
        "scope": scope,
        "leads": leads,
        "peers": peers,
    }


def _prologue_signature_summary(prologue: dict) -> dict:
    """Compact self-describing signature — shown in the rendered block so the
    subagent sees exactly what was matched on."""
    vertices = prologue.get("vertices") or []
    edges = prologue.get("edges") or []
    return {
        "vertex_types": sorted({v.get("type") for v in vertices if isinstance(v, dict) and v.get("type")}),
        "vertex_classifications": sorted({v.get("classification") for v in vertices if isinstance(v, dict) and v.get("classification")}),
        "edge_relations": sorted({e.get("relation") for e in edges if isinstance(e, dict) and e.get("relation")}),
    }


def _format_prologue_priors(payload: dict) -> str:
    """Render the loop-1 prologue-keyed priors block.

    Baseline-recommendation format: when the corpus carries strong support
    for a top-lead at this prologue topology, emit a single recommendation
    line — "use this scaffold unless the alert contradicts it." When
    support is weak, emit a sparse-prior fallback that tells PREDICT to
    scaffold from first principles.

    Peer-classification rendering is intentionally absent. A list of
    historically-proposed classifications drives enumerate-every-mechanism
    behavior (the FM4/FM5 failure modes); the priors block should nudge
    scaffold choice, not seed a fork space.
    """
    sig = payload["prologue_signature"]
    scope = payload["scope"]
    leads = payload["leads"]

    lead_rows = leads.get("hits") or []
    top = lead_rows[0] if lead_rows else None

    is_strong = (
        top is not None
        and (top.get("branching_support") or 0) >= _STRONG_PRIOR_MIN_SUPPORT
        and (top.get("fidelity_rate") or 0.0) >= _STRONG_PRIOR_MIN_FIDELITY
    )

    lines = [
        "## Past-investigation priors",
        "",
        f"Prologue topology — {scope} scope, "
        f"tier {leads['tier_used']}: {leads['tier_label']}, "
        f"{leads.get('cases_matched', 0)} cases matched. "
        f"Vertex types: {', '.join(sig['vertex_types']) or '—'}. "
        f"Edge relations: {', '.join(sig['edge_relations']) or '—'}.",
        "",
    ]

    if is_strong:
        n = top.get("branching_support") or 0
        total = leads.get("cases_matched") or n
        fidelity = top.get("fidelity_rate") or 0.0
        lines.append(
            f"**Strongest prior at this topology:** `{top['lead_name']}` "
            f"({n}/{total} cases, {int(fidelity * 100)}% fidelity rate). "
            "Use this scaffold unless the alert specifically contradicts it."
        )
    else:
        lines.append(
            "Priors at this topology are sparse — scaffold from first principles "
            "per PREDICT's ASSESS gate."
        )

    return "\n".join(lines)


def _extract_current_frontier(ctx: Context) -> list[dict]:
    """Return a list of `{name, fingerprint}` entries describing the frontier.

    Loop N (N ≥ 2): use the *last* `hypothesize:` yaml block in
    `investigation.md`; resolve each hypothesis's topology against the
    investigation's own prologue (first yaml block carrying `prologue:`).

    Loop 1 (no prior `hypothesize:`): synthesize one entry per playbook
    hypothesis seed, with `relation=None` and parent classification = the
    seed name stripped of the leading `?`. Loop-1 fingerprints never match
    tiers 0–3 (relation is required); retrieval naturally falls back to the
    name-glob tier, which is what the subagent expects at loop 1.
    """
    inv_path = ctx.run_dir / "investigation.md"
    text = inv_path.read_text() if inv_path.exists() else ""

    prologue, last_hypothesize = parse_prologue_and_last_hypothesize(text)

    from invlang import hypothesis_topology  # type: ignore

    if last_hypothesize is not None:
        hypotheses = last_hypothesize.get("hypotheses") or []
        shelved = set(last_hypothesize.get("shelved") or [])
        active = [h for h in hypotheses if h.get("id") not in shelved]
        return [
            {
                "name": _hyp_name(h),
                "fingerprint": hypothesis_topology(prologue or {}, h, active),
            }
            for h in active
            if _hyp_name(h)
        ]

    # Loop 1 fallback — seeds from the signature playbook.
    meta = load_playbook_metadata(ctx.signature_id)
    seeds = meta.hypothesis_seeds or []
    peers = tuple(sorted(seeds))
    frontier: list[dict] = []
    for seed in seeds:
        classification = seed.lstrip("?")
        frontier.append({
            "name": seed if seed.startswith("?") else f"?{seed}",
            "fingerprint": {
                "attached_vertex": None,
                "relation": None,
                "parent_vertex": {"type": None, "classification": classification},
                "peers": peers,
            },
        })
    return frontier


def parse_prologue_and_last_hypothesize(
    text: str,
) -> tuple[dict | None, dict | None]:
    """Walk all structured fences once; return (prologue, last_hypothesize)."""
    prologue: dict | None = None
    last_hyp: dict | None = None
    for parsed in iter_companion_dicts(text):
        if prologue is None and isinstance(parsed.get("prologue"), dict):
            prologue = parsed["prologue"]
        if isinstance(parsed.get("hypothesize"), dict):
            last_hyp = parsed["hypothesize"]
    return prologue, last_hyp


def _hyp_name(h: dict) -> str:
    return h.get("name") or ""


def _compute_priors(frontier: list[dict]) -> list[dict]:
    """Compute `{name, fingerprint, tier_used, tier_label, leads, peers}` per entry."""
    from invlang import (  # type: ignore
        lead_effectiveness_for_topology,
        load_corpus,
        peer_hypothesis_distribution_for_topology,
    )

    corpus = load_corpus()
    out: list[dict] = []
    for entry in frontier:
        fp = entry["fingerprint"]
        leads = lead_effectiveness_for_topology(corpus, fp)
        peers = peer_hypothesis_distribution_for_topology(corpus, fp)
        out.append({
            "name": entry["name"],
            "fingerprint": fp,
            "tier_used": leads.get("tier_used"),
            "tier_label": leads.get("tier_label"),
            "leads": leads.get("hits") or [],
            "peers": peers.get("hits") or [],
        })
    return out


def _format_priors(priors: list[dict]) -> str:
    """Render a concise markdown block. Empty frontier or empty retrieval
    both still emit the section — honesty beats silent omission."""
    lines = ["## Past-investigation priors"]
    if not priors:
        lines.append("(no frontier extracted)")
        return "\n".join(lines)
    for entry in priors:
        lines.append("")
        lines.append(
            f"### {entry['name']} (tier {entry['tier_used']} — {entry['tier_label']})"
        )
        leads = entry["leads"][:_PRIORS_LEADS_TOP_N]
        if not leads:
            lines.append("Leads: (no corpus matches at any tier)")
        else:
            lines.append("Leads (per-occurrence effectiveness; n = support):")
            for row in leads:
                score = row.get("mean_branching_delta")
                fidelity = row.get("fidelity_rate")
                n = row.get("branching_support") or 0
                lines.append(
                    f"  - {row['lead_name']}: "
                    f"score={_fmt_num(score)}, fidelity={_fmt_num(fidelity)}, n={n}"
                )
        peers = entry["peers"][:_PRIORS_PEERS_TOP_N]
        if peers:
            lines.append("Peer hypotheses co-proposed at this topology:")
            for p in peers:
                hist = p.get("final_weight_histogram") or {}
                hist_str = ", ".join(
                    f"{k}={v}" for k, v in hist.items() if v
                ) or "—"
                lines.append(
                    f"  - {p['classification']} "
                    f"({p['peer_count']} cases, weights: {hist_str})"
                )
    return "\n".join(lines)


def _fmt_num(v: float | None) -> str:
    if v is None:
        return "—"
    return f"{v:.3f}"
