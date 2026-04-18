# Loop 2 — HYPOTHESIZE decision: recovery-C

## Decision: Option C — emit one focused fork on the genuinely open classification question

```yaml
hypothesize:
  hypotheses:
    - id: h-004
      name: "?sanctioned-internal-endpoint"
      attached_to_vertex: v-src-ip-10.30.18.42
      proposed_edge:
        relation: classified_as
        parent_vertex:
          type: endpoint
          classification: sanctioned-internal-endpoint
      predictions:
        - {id: p1, claim: "10.30.18.42 has an organizational trace in at least one of: DHCP reservation, AD computer object, or internal asset registry — consistent with a registered but misconfigured system"}
      refutation_shape:
        - {id: r1, claim: "no organizational anchor found in DHCP, AD, or any internal registry; IP is genuinely unknown to org infrastructure"}
      weight: null
    - id: h-005
      name: "?unsanctioned-internal-endpoint"
      attached_to_vertex: v-src-ip-10.30.18.42
      proposed_edge:
        relation: classified_as
        parent_vertex:
          type: endpoint
          classification: unsanctioned-internal-endpoint
      predictions:
        - {id: p1, claim: "no organizational trace in DHCP, AD, or internal registry; the IP is reachable but unregistered — consistent with a rogue or attacker-controlled host on the internal segment"}
      refutation_shape:
        - {id: r1, claim: "any organizational anchor found (DHCP reservation, AD object, asset record) — even an informal one — attributing the IP to a known internal system"}
      weight: null
```

Selected lead: `source-anchor-lookup`

Pitfalls:
- h-004: a misconfigured system may be partially registered (e.g., has a DHCP lease but no AD object). Partial organizational trace should not auto-confirm sanctioned status; the missing fields are themselves evidence of under-management, not legitimacy. Grade + not ++ unless the full registration profile matches an established service account or approved system class.
- h-005: internal attacker-controlled hosts occasionally inherit stale DHCP leases from a previously registered device. A DHCP record alone — without an accompanying AD object or active asset registration — should not refute this hypothesis; check lease age and whether the MAC address maps to a known device in the asset DB.

---

## Recovery rationale

**Option chosen:** C — emit a single focused hypothesis pair scoped to the classification of the confirmed source vertex, and rely on ANALYZE (not HYPOTHESIZE) to record the legacy h-001/h-002/h-003 outcomes.

**Why not A (re-express legacy hypotheses in mechanism-shaped form):** the GATHER outcomes have already scored the major prediction dimensions of the legacy hypotheses. Emitting mechanism-shaped rewrites of h-001, h-002, and h-003 would extend the frontier for questions that are effectively answered. It would also create an artificial parallel set of active hypotheses that duplicate reasoning the ANALYZE step is equipped to close. The frontier would be artificially wide.

**Why not B (skip HYPOTHESIZE, route to GATHER for anchor lookup):** the system prompt requires "no HYPOTHESIZE without a fork — enter only when ≥2 competing classifications have predictions that diverge on already-observable fields." The key question is whether the anchor lookup is an already-observable discriminant or a new lead. Here, the source IP's organizational status (registered vs. unregistered) was not probed in loop 1 — `approved-monitoring-sources` and `scheduled-jobs` were checked, but broader DHCP/AD/asset-registry anchor fields were not. There is a genuine fork: two classifications (`sanctioned-internal-endpoint` vs. `unsanctioned-internal-endpoint`) with diverging predictions on an observable the next lead will return. The "no HYPOTHESIZE" case is when the discriminating data is already in hand; here it is not. A HYPOTHESIZE block is therefore warranted.

**Why not narrative umbrella labels:** the legacy h-001 (`?legitimate-automation`) and h-002 (`?credential-guessing`) pack mechanism + intent + volume-shape into single names. h-004 and h-005 name only the parent-vertex classification of the confirmed IP vertex — `sanctioned-internal-endpoint` vs. `unsanctioned-internal-endpoint`. Each has one prediction scoped to one attribute (organizational anchor trace). Intent, attack mechanism, and disposition are deferred to ANALYZE and CONCLUDE.

**How the legacy hypotheses are closed:** the ANALYZE step for loop 2 should record assessments on h-001, h-002, and h-003 using the loop-1 GATHER outcomes:
- h-001 (`?legitimate-automation`): `--` (p1 and p2 both refuted; p3 partial support is insufficient to sustain the hypothesis after two refutations).
- h-002 (`?credential-guessing`): umbrella disintegrating — p1 and p2 held, p3 refuted. The load-bearing question (source legitimacy) is now cleanly captured by h-004/h-005; h-002 can be graded `null → inconclusive` with a note that the sub-questions are redistributed to the new fork.
- h-003 (`?compromise-followup`): `--` (p1 cleanly refuted by zero 5501/5715 events).

**How the umbrella shape is avoided:** the new hypotheses (h-004, h-005) each carry exactly one prediction, scoped to a single vertex attribute (organizational anchor presence). The loop-1 multi-prediction umbrella structure — where distinct observables (source-classification, username-classification, volume, success-window) were packed under one hypothesis name — is not reproduced. Each remaining open question is a classification attribute on a single confirmed vertex, handled by a single prediction per hypothesis.
