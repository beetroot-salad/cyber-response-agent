# Investigation Language v2.3 — User Survey Walk
## Alert: m365-alert-9f3a2c — Suspicious inbox forwarding rule

---

## Part 1 — Retrieval Wishes Log

### R1 — CONTEXTUALIZE: classifying the session IP

**Where in the walk:** Filling the prologue. I see `203.0.113.45 / Bucharest, Romania` as the client IP and `user_usual_country: United States`. I need to classify this IP vertex before I even frame hypotheses.

**The question:** "Show me past investigations where the session IP was flagged as geographically anomalous for a US-based user. What did the disposition turn out to be? Was the geo-anomaly reliably predictive of actual compromise, or was it mostly travel / VPN noise?"

**Why it matters:** If past cases show geo-anomaly alone resolves 80% benign (travel, VPN, remote access), I'd classify `v-005 (ip)` as `external-endpoint` with a low-signal flag and weight geo-anomaly lower in my predictions. If past cases show it correlates strongly with TP, I'd front-load the session-authentication lead and treat geo-anomaly as a severe discriminator.

**Shape of match:** A distribution over dispositions for cases with `ip.classification: external-endpoint + geo_anomaly_flagged`. Not one case — I want the base rate.

**Indexability hunch:** The IP vertex `classification` is structured (`external-endpoint` vs `corp-vpn-egress` etc.) and derivable from the prologue. Geo-anomaly isn't a classification enum in v2.3 — it would need to live as a vertex `concern` string or in `attributes`. Semi-structured; a distiller would need to grep `concerns` strings or a custom `attributes.geo_mismatch` flag that v2.3 doesn't define. **Not fully served by current schema alone.**

---

### R2 — CONTEXTUALIZE: forwarding rule targeting Protonmail

**Where in the walk:** I note that `forward_to: outside-dropoff@protonmail.com` and `delete_message: true`. Before forming hypotheses I want to know if this *forwarding-to-external + hide* pattern has appeared before.

**The question:** "Find past investigations triggered by external inbox forwarding rules — specifically rules that forward AND delete/hide. What archetypes dominated? Was 'compromised account conducting exfiltration staging' ever confirmed, or did prior cases mostly end as accidental IT or travel setup?"

**Why it matters:** This directly seeds my hypothesis prior. If past cases show this pattern almost always resolves as `account-takeover-exfil-staging`, I should start with that hypothesis named more specifically, not just `?compromised-account`. If it resolves benign 70% of the time (user set up forwarding before a laptop swap), I should weight my benign hypotheses higher at the start.

**Shape of match:** Distribution over `conclude.matched_archetype` and `conclude.disposition` filtered by rule name `Suspicious inbox forwarding rule created`. I'd also want the lead sequences — did those cases resolve via `entra-id-sign-in-log` quickly, or did they need out-of-band contact?

**Indexability hunch:** `conclude.matched_archetype` and `conclude.disposition` are structured in v2.3. Alert source / rule name is not in the companion schema directly — it would need to come from the run metadata (the `alert.json` envelope). Hybrid: structured fields on the conclusion side, but the "same trigger rule" filter requires joining the companion with run metadata. Likely feasible for a distiller.

---

### R3 — HYPOTHESIZE: deciding whether to start lean or named

**Where in the walk:** Writing the `hypothesize` block. I need to decide: do I write `?account-takeover` as a lean top-level hypothesis, or am I already at the discrimination level where I can write named children directly?

**The question:** "In past cases with this rule type, how many GATHER loops did it take before the first lean hypothesis was refined? What were the split points?" 

**Why it matters:** If past cases almost always refined at loop 1 (the sign-in log immediately shows anomalous auth → bifurcates to `?stolen-cred-exfil` vs `?user-setup-themselves`), I should write a lean `?account-action-at-session-boundary` at loop 0 and plan to refine immediately. If the cases stayed at the top-level lean hypothesis for 3 loops, pre-naming children wastes work. The leanness rule in §6 is methodology, but knowing where past cases forked would calibrate how lean to go.

**Shape of match:** A list of refinement chain shapes (e.g., `h-001 → [h-001-001, h-001-002] at loop 1`) for cases with the same alert source. Maybe 5-10 cases, not a distribution.

**Indexability hunch:** Hierarchical IDs encode the chain structurally in v2.3. The distiller can reconstruct refinement trees by parsing IDs and correlate them with `lead.loop`. This is a structured-field query — it should be fully derivable from the schema. One of the stronger retrieval capabilities v2.3 enables.

---

### R4 — HYPOTHESIZE: whether to include a "benign self-setup" hypothesis

**Where in the walk:** Deciding whether to write `?user-self-configured-forwarding` as an explicit hypothesis or not.

**The question:** "Are there past cases where Alice (or users in the Finance Operations role) created external forwarding rules and the explanation turned out to be self-setup — rule configured during a device swap, job change, or before a vacation? What evidence pattern confirmed that hypothesis?"

**Why it matters:** If `?user-self-configured` was confirmed in past cases via `entra-id-sign-in-log` showing consistent IP + MFA + normal cadence, then I should include that hypothesis with those predictions. If it was never confirmed benign-via-scope-alone and always required out-of-band contact, I'd note it as a hypothesis that inherently tops out at severity-ceiling and model it accordingly.

**Shape of match:** Cases where `conclude.disposition: benign` and the forwarding rule type matches. I want the evidence path that confirmed benign, not just the outcome.

**Indexability hunch:** This requires searching by hypothesis name (`?user-self-configured` or equivalent) plus disposition. Hypothesis names are structured strings in v2.3 but the vocabulary is analyst-defined — not a closed enum. A semantic match over hypothesis names would help, but keyword match on `?*self*` or `?*user-configured*` might also work. Borderline: semi-structured.

---

### R5 — GATHER loop 1: querying entra-id-sign-in-log, deciding what to look for

**Where in the walk:** About to write `l-001`, a scope lead against `entra-id-sign-in-log` to materialize the session. I need to decide which attributes to pull and what constitutes evidence.

**The question:** "In past cases where `entra-id-sign-in-log` was the first lead run on an M365 forwarding-rule alert, what did the scope lead materialize? Which vertex attributes turned out to be load-bearing in the resolution? Were there known dead-ends (e.g., `device_compliance` from Entra sign-in alone is too coarse to confirm?)"

**Why it matters:** If past cases show that the sign-in log's `conditional_access_result` was the key discriminator (passed → weight toward benign; failed or not evaluated → weight toward compromised), I'd make sure to pull that field. If past cases show it's a dead lead (Entra records MFA result but not enough to confirm device identity), I'd add a concern note and plan for MDM follow-up. Knowing the dead leads avoids redundant work.

**Shape of match:** Dead-leads index entries where `system: entra-id-sign-in-log` and `failure_reason: attribution-opaque` or `partial-coverage` — plus the cases that did resolve via this anchor. I want the contrast, not just one shape.

**Indexability hunch:** `lead.query_details.system` is a structured string in v2.3. `failure_reason` has a small enum. The distiller can build `dead_leads_index.yaml` from `attribution-opaque` failure reasons (per §7 — this is explicitly mentioned as a distiller projection). This query is well-served by the schema.

---

### R6 — GATHER loop 1: deciding `authority_for_question` for sign-in data

**Where in the walk:** Writing `trust_anchor_result.authority_for_question` for the `entra-id-sign-in-log` anchor. I need to decide: `full` or `partial`?

**The question:** "In past cases where `entra-id-sign-in-log` was used to confirm account authentication, was it treated as full-authority or partial-authority? Specifically: can the Entra sign-in log confirm that the person authenticating was the legitimate user, or only that the credential was presented with MFA?"

**Why it matters:** This directly affects whether I can cap a hypothesis at `++` or only `-`/`+`. If past cases treated Entra MFA confirmation as `full` authority for "was this a legitimate user session," I'd do the same. If past cases consistently marked it `partial` (because MFA confirms the device, not the human behind it), I'd use `partial` and plan for an out-of-band contact ceiling.

**Shape of match:** A small number of cases (3-5) showing how they classified `authority_for_question` for `entra-id-sign-in-log`. Not a distribution — I want examples with their reasoning.

**Indexability hunch:** `trust_anchor_result.authority_for_question` is a structured field (`full` | `partial`) in v2.3. Querying `anchor_id: entra-id-sign-in-log, authority_for_question: *` across cases is a pure structured-field query. Well-served.

---

### R7 — GATHER loop 2: deciding whether to run `mail-forwarding-policy-registry`

**Where in the walk:** After loop 1 materializes the session. I have the sign-in data and need to decide if I should check whether forwarding is *permitted* for Alice's role before going further.

**The question:** "In past investigations against this rule type, was checking the mail-forwarding-policy registry a useful discriminating lead, or was it reliably uninformative (everyone in Finance gets blocked by default, so the rule creation itself is already a policy violation that doesn't add information)?"

**Why it matters:** If every past case showed that external forwarding is organizationally forbidden regardless of role (making the policy check vacuous — the alert firing already implies violation), I'd skip the policy check and note the lack of legitimate use case directly in the hypothesis concerns. If the policy registry showed some roles are permitted, it would be a real discrimination lead.

**Shape of match:** A binary: was `mail-forwarding-policy-registry` ever run on this alert class, and did it produce a non-trivial result? A single past case showing the lead outcome is enough.

**Indexability hunch:** `lead.query_details.system: mail-forwarding-policy-registry` is queryable as a structured string. Whether the result was informative requires looking at the resolution reasoning. Semi-structured.

---

### R8 — GATHER loop 2: deciding whether `hr-directory` changes the weight

**Where in the walk:** I'm considering whether Alice's recent employment changes (did she just give notice? was she demoted? is she still active?) would discriminate between `?insider-threat-exfil` and `?compromised-account-external`.

**The question:** "In confirmed insider-threat cases on M365 alerts, how often was `hr-directory` a load-bearing lead? Did it ever push a hypothesis to `--` by confirming normal employment status, or is it typically weak/circumstantial evidence that only adds a concern note?"

**Why it matters:** If `hr-directory` appeared in confirmed insider-threat cases' lead sequences but always ended as `weak` severity, I'd include it as a later loop lead with low priority. If it appeared as a `severe` discriminator (e.g., employee gave notice same day → `++` for `?insider-exfil`), I'd front-load it.

**Shape of match:** Cases where `conclude.matched_archetype` contains something like `insider-threat` or `exfil-staging`, showing the `lead.query_details.system` sequence and severity-of-test for `hr-directory` leads.

**Indexability hunch:** `lead.query_details.system` and `resolutions.severity_of_test` are structured. `matched_archetype` is a structured string. This is a multi-field join query — feasible from the schema, but requires a non-trivial distiller projection (join archetype outcome → lead sequence → severity per system). Probably needs the `case_index.yaml` trace string the distiller produces.

---

### R9 — CONCLUDE: severity-ceiling vs escalation-exhaustion

**Where in the walk:** Writing the conclude block. I've reached a state where MFA was confirmed but I can't close the loop — was it really Alice who authenticated, or a stolen session? I need to decide between `severity-ceiling` (requires direct human contact) and `exhaustion-escalation` (I ran everything I could, still unclear).

**The question:** "In past M365 account-compromise investigations with similar evidence states — MFA confirmed, geo-anomaly present, external forwarding rule active — how were they terminated? Did analysts consistently call `severity-ceiling` (needing out-of-band Alice contact), or did some get to a definitive `true_positive` via MDM device corroboration alone?"

**Why it matters:** If MDM+EDR corroboration was enough to push past severity-ceiling in past cases (device compliance confirmed → the "was it really Alice" question becomes answerable without calling her), I might not be at a ceiling. If past cases consistently hit the ceiling, I should model the ceiling_test correctly now.

**Shape of match:** Distribution over `termination.category` for cases with `entra-id-sign-in-log: confirmed + mdm-intune: confirmed + geo-anomaly present`. I want to see where the ceiling was drawn.

**Indexability hunch:** `termination.category` is a structured enum. The condition involves multiple anchor results joined with vertex attributes (geo annotation). The multi-anchor join would require the distiller to build a normalized per-case anchor result summary. Partially served — the distiller needs `anchor_manifest.yaml` projections per §7.

---

### R10 — CONCLUDE: ceiling_test subject

**Where in the walk:** Writing `ceiling_test.subject`. I've settled on `kind: out-of-band-human-contact`. I need to name the subject — is it Alice herself, or her manager (`raj.patel@company.com`)?

**The question:** "In past severity-ceiling cases for M365 account-compromise on Finance users, who was contacted — the user directly or the manager? Did contacting the user ever trigger alert destruction (user deletes evidence on hearing they're under investigation)?"

**Why it matters:** If past cases show that contacting the user directly in `?compromised-account` scenarios risks tipping off an insider, the analyst note should flag manager-first contact as the protocol. The `ceiling_test.subject` field might better name the manager, with a note in `ceiling_rationale` about why direct user contact was deferred.

**Shape of match:** Prose-driven — this is really about operational protocol embedded in case notes. The `ceiling_rationale` field carries the analyst's reasoning in free text. Not well-served by structured fields.

**Indexability hunch:** Almost entirely prose. The `ceiling_test.subject` is a free string — "alice.chen@company.com" vs "raj.patel@company.com" has no structural meaning distinguishing direct-user from manager-contact. **Not served by v2.3 schema fields.**

---

### Retrieval wishes NOT served by v2.3 schema alone

1. **Geo-anomaly signal quality.** R1 depends on a geo-mismatch attribute that v2.3 has no standard slot for. It would need to live in vertex `concerns` as free text or in `attributes` under an analyst-defined key — neither is queryable by the distiller without string search. The schema could benefit from a structured `ip.attributes.geo_country` field, but v2.3 deliberately avoids adding domain-specific fields.

2. **Operational contact protocol.** R10's question about who to contact (user vs manager) and the risk of tipping off an insider lives entirely in `ceiling_rationale` prose. There's no structured field distinguishing "contact the subject directly" from "contact the subject's manager" from "contact security-on-call." The `ceiling_test.kind` enum covers the medium (human contact) but not the recipient relationship. A `ceiling_test.recipient_role` field (e.g., `subject-user | subject-manager | security-team | legal`) would enable this.

3. **Alert rule metadata.** R2's "filter by same trigger rule" requires joining the companion with the run's `alert.json` envelope. The companion schema has no field for the alert rule name or source. This is intentional (the companion is investigation-centric, not alert-centric), but it means rule-type-based retrieval needs an external join.

4. **Hypothesis prior from base rates.** R4's question about benign vs TP base rates for this rule type requires aggregate statistics over many cases. v2.3 captures per-case outcomes, but the distribution query requires a built index (`case_index.yaml` per §15). The schema supports it, but the indexing infrastructure to make base-rate queries fast is out-of-scope for the companion format itself.

---

## Part 2 — The Companion YAML

```yaml
prologue:
  vertices:
    # The SIEM-observed action: rule creation (action shape)
    - id: v-001
      type: command
      classification: cloud-api-call
      identifier: "New-InboxRule by alice.chen @2026-04-14T14:32:11Z → outside-dropoff@protonmail.com"
      attributes:
        api_name: "New-InboxRule"
        rule_name: "System"
        forward_to: "outside-dropoff@protonmail.com"
        delete_message: true
        stop_processing_rules: true
        conditions: "ALL incoming messages"
        status: succeeded
      citations: ["m365-defender:alert=m365-alert-9f3a2c"]

    # The acting identity
    - id: v-002
      type: identity
      classification: employee-without-exec-rbac
      identifier: "alice.chen@company.com"
      attributes:
        kind: user
        provider: azure-ad
        upn: "alice.chen@company.com"
        department: "finance-ops"
        manager: "raj.patel@company.com"
        role_assignments: ["Finance Operations", "SAP-Read"]
      concerns:
        - "mailbox classified internal-confidential; finance-ops users typically have access to sensitive financial correspondence"

    # The OWA session in which the rule was created (lifecycle perspective)
    - id: v-003
      type: session
      classification: unclassified-session
      identifier: "OWA session alice.chen @14:32:11Z from 203.0.113.45"
      attributes:
        client_type: "OutlookWebApp"
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/126.0.0.0"
        azure_ad_session_id: "7788ff..."
        session_id: "b2f91a4c-..."

    # The IP from which the session originated
    - id: v-004
      type: ip
      classification: external-endpoint
      identifier: "203.0.113.45"
      attributes:
        geo_city: "Bucharest"
        geo_country: "Romania"
      concerns:
        - "user_usual_country is United States; Romania origin is a geographic anomaly for this account"

    # Mailbox as storage target of the forwarding rule
    - id: v-005
      type: storage
      classification: internal-restricted-store
      identifier: "alice.chen@company.com mailbox"
      attributes:
        kind: file
        sensitivity: "internal-confidential"

  edges:
    - id: e-001
      relation: executed_in
      source_vertex: v-001
      target_vertex: v-003
      when: { timestamp: "2026-04-14T14:32:11Z" }
      authority:
        kind: authoritative-source
        source: "m365-defender:alert=m365-alert-9f3a2c:unified-audit-log"

    - id: e-002
      relation: targeted
      source_vertex: v-001
      target_vertex: v-005
      when: { timestamp: "2026-04-14T14:32:11Z" }
      authority:
        kind: authoritative-source
        source: "m365-defender:alert=m365-alert-9f3a2c:unified-audit-log"

    - id: e-003
      relation: authenticated_as
      source_vertex: v-003
      target_vertex: v-002
      authority:
        kind: authoritative-source
        source: "m365-defender:alert=m365-alert-9f3a2c:unified-audit-log"

    - id: e-004
      relation: initiated_by
      source_vertex: v-003
      target_vertex: v-004
      authority:
        kind: siem-event
        source: "m365-defender:alert=m365-alert-9f3a2c:session.client_ip"

# Discrimination level is v-003 (the OWA session): did the legitimate Alice
# create this rule, or did someone else access her account?
hypothesize:
  hypotheses:
    # LEAN: "was this session initiated by the legitimate account holder?"
    # Single discrimination claim. Does NOT pre-commit to attacker-vs-self-setup.
    - id: h-001
      name: "?legitimate-user-action"
      attached_to_vertex: v-003
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: identity
          classification: employee-without-exec-rbac
      predictions:
        - id: p1
          claim: "the session authenticated with MFA from a device and network path consistent with alice.chen's established usage pattern"
      refutation_shape:
        - id: r1
          claim: "the session showed no MFA, originated from an unrecognized device, or showed a conditional-access failure"
      weight: null

    # Mandatory adversarial hypothesis
    - id: h-002
      name: "?account-takeover-session"
      attached_to_vertex: v-003
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: identity
          classification: unknown-attacker
      predictions:
        - id: p1
          claim: "the session origin, device, or auth context shows an anomaly inconsistent with alice.chen's historical pattern"
      refutation_shape:
        - id: r1
          claim: "the session was authenticated with MFA from alice.chen's known MDM-managed device on a typical network path"
      concerns:
        - "account takeover cannot be fully ruled out by MFA alone if MFA was phished or coerced; refutation here means 'no current technical indicator of compromise', not 'ATO ruled out'"
      weight: null

gather:
  # Loop 1: Trust lead — Entra ID sign-in log. Primary discriminator:
  # did the legitimate principal authenticate this session?
  - lead:
      id: l-001
      loop: 1
      name: "anchor-lookup(entra-id-sign-in-log)"
      mode: trust
      target: v-003
      intended_hypothesis_set: [h-001, h-002]
      observes:
        - hypothesis: h-001
          predictions: [p1]
          refutations: [r1]
        - hypothesis: h-002
          predictions: [p1]
          refutations: [r1]
      query_details:
        system: entra-id-sign-in-log
        template: "leads/anchor-lookup/templates/entra-id.md"
        query: "sign-in events for alice.chen@company.com within ±15m of 2026-04-14T14:32:11Z, including MFA result, device_id, conditional_access_result, risk_state"
        time_window: "2026-04-14T14:17:11Z - 2026-04-14T14:47:11Z"
      outcome:
        observations:
          vertices:
            # Sign-in event materializes as an MFA session (lifecycle perspective:
            # this session object outlives the event and will be reasoned about further)
            - id: v-006
              type: session
              classification: unclassified-session
              identifier: "alice.chen Entra sign-in @14:31:55Z from 203.0.113.45"
              attributes:
                signed_in_at: "2026-04-14T14:31:55Z"
                mfa_result: "success"
                mfa_method: "authenticator-app"
                device_id: "unknown-device-id"
                device_compliant: false
                conditional_access_result: "success"
                risk_state: "none"
                risk_level_aggregated: "none"
              concerns:
                - "device_id not recognized in MDM-Intune registry — device compliance could not be verified by Entra at time of sign-in"
          edges:
            - id: e-005
              relation: authenticated_as
              source_vertex: v-006
              target_vertex: v-002
              when: { timestamp: "2026-04-14T14:31:55Z" }
              authority:
                kind: authoritative-source
                source: "entra-id-sign-in-log:alice.chen@company.com:2026-04-14T14:31:55Z"
            - id: e-006
              relation: initiated_by
              source_vertex: v-006
              target_vertex: v-004
              authority:
                kind: authoritative-source
                source: "entra-id-sign-in-log:alice.chen@company.com:2026-04-14T14:31:55Z"
        trust_anchor_result:
          anchor_id: entra-id-sign-in-log
          kind: entra-id-sign-in-log
          result: partial
          # MFA passed, but device is unrecognized — the anchor confirms credential
          # presentation with second factor but cannot confirm the human is the
          # legitimate user. Partial authority for "was this the real Alice."
          authority_for_question: partial

      # h-001 (?legitimate-user-action) was lean. MFA succeeded but device is
      # unrecognized — evidence splits into: did Alice act on an unmanaged device
      # (travel laptop, personal device), vs did an attacker phish Alice's MFA?
      # Refine now that the session is materialized with its device posture.
      shelved: [h-001]
      new_hypotheses:
        - id: h-001-001
          name: "?user-self-configured-unmanaged-device"
          attached_to_vertex: v-006
          proposed_edge:
            relation: authenticated_as
            parent_vertex:
              type: identity
              classification: employee-without-exec-rbac
          predictions:
            - id: p1
              claim: "alice.chen has recently accessed M365 from other unmanaged or non-corp devices (travel, personal device), consistent with this session being her own"
            - id: p2
              claim: "no change ticket or legitimate operational reason exists for the forwarding rule, but alice can directly confirm she created it"
          refutation_shape:
            - id: r1
              claim: "alice has no history of unmanaged-device access and denies creating the rule"
          weight: null

        - id: h-001-002
          name: "?mfa-phished-account-takeover"
          attached_to_vertex: v-006
          proposed_edge:
            relation: authenticated_as
            parent_vertex:
              type: identity
              classification: unknown-attacker
          predictions:
            - id: p1
              claim: "the device_id is absent from any known Alice endpoint in MDM, and Alice's other recent sessions originated from expected US IPs on compliant devices"
          refutation_shape:
            - id: r1
              claim: "alice regularly authenticates from non-corp devices internationally, or the device_id resolves to one of her known personal/travel devices"
          concerns:
            - "MFA phishing (adversary-in-the-middle proxy) can pass MFA checks; Entra sign-in success does not rule out AiTM. Refutation here is 'no technical indicator', not 'AiTM ruled out'"
          weight: null

      resolutions:
        - hypothesis: h-002
          before: null
          after: "-"
          severity_of_test: moderate
          matched_refutation_ids: [r1]
          reasoning: "Entra confirmed MFA success and risk_state: none. Conditional access passed. No risk elevation flagged. r1 partially satisfied: MFA from the credential side is consistent with the real user. BUT device_id is unrecognized and device_compliant: false — the 'known MDM-managed device' clause of r1 is NOT satisfied. Cannot advance to --. Weight: -. Not --: device-posture gap means ATO via AiTM proxy remains live. Rule 16: trust_anchor_result.authority_for_question is partial — weight capped at - regardless of prediction coverage."
          supporting_edges: [e-005]

  # Loop 1: Trust lead — MDM Intune. Check if the unrecognized device_id
  # appears anywhere in the device registry.
  - lead:
      id: l-002
      loop: 1
      name: "anchor-lookup(mdm-intune)"
      mode: trust
      target: v-006
      intended_hypothesis_set: [h-001-001, h-001-002]
      observes:
        - hypothesis: h-001-001
          predictions: [p1]
        - hypothesis: h-001-002
          predictions: [p1]
          refutations: [r1]
      query_details:
        system: mdm-intune
        template: "leads/anchor-lookup/templates/mdm-intune.md"
        query: "device registry for alice.chen@company.com — list all enrolled devices, compliance status, last-seen; also query device_id=unknown-device-id specifically"
        time_window: "current"
      outcome:
        observations:
          vertices: []
          # MDM returned: no device with the session device_id is enrolled for
          # alice.chen. Three corp-managed devices exist (two US-based Windows
          # laptops, one iOS phone), none matching the session device.
          edges: []
        trust_anchor_result:
          anchor_id: mdm-intune
          kind: mdm-intune
          result: refuted
          authority_for_question: full
        failure_reason: null
      resolutions:
        - hypothesis: h-001-001
          before: null
          after: "-"
          severity_of_test: severe
          matched_refutation_ids: [r1]
          reasoning: "MDM-Intune reports zero devices enrolled for alice.chen matching the session device_id. Alice's three enrolled corp devices (two laptops, one iOS) are all US-registered. The 'recent access from other unmanaged devices' baseline check (p1) cannot be confirmed — there is no baseline of unmanaged-device use. r1 condition (no history of unmanaged access) is satisfied. Weight: -. Not -- because MDM only covers corp-managed devices; a genuinely personal device Alice owns but never enrolled would be invisible to MDM."
          supporting_edges: []
        - hypothesis: h-001-002
          before: null
          after: "+"
          severity_of_test: severe
          matched_prediction_ids: [p1]
          reasoning: "MDM-Intune confirmed the session device is not any of Alice's enrolled corp or personal devices, and her normal sessions originate from enrolled US-based devices. p1 supported: device_id absent from MDM, Alice's other sessions on compliant US devices — consistent with an unauthorized actor on an unmanaged endpoint. Rule 16: authority_for_question is full. Weight advances to +. Not ++ because the absence of a device registration is consistent with Alice owning an unenrolled personal device — not strictly impossible without out-of-band confirmation."
          supporting_edges: []

  # Loop 2: Trust lead — mail-forwarding-policy-registry.
  # Is external forwarding permitted for alice.chen's role?
  - lead:
      id: l-003
      loop: 2
      name: "anchor-lookup(mail-forwarding-policy-registry)"
      mode: trust
      target: v-002
      intended_hypothesis_set: [h-001-001, h-001-002]
      observes:
        - hypothesis: h-001-001
          predictions: [p2]
        - hypothesis: h-001-002
          predictions: [p1]
      query_details:
        system: mail-forwarding-policy-registry
        template: "leads/anchor-lookup/templates/mail-policy.md"
        query: "is external mail forwarding permitted for alice.chen@company.com (Finance Operations / SAP-Read roles)?"
        time_window: "current"
      outcome:
        observations:
          vertices: []
          edges: []
        trust_anchor_result:
          anchor_id: mail-forwarding-policy-registry
          kind: mail-forwarding-policy-registry
          result: refuted
          authority_for_question: full
      resolutions:
        - hypothesis: h-001-001
          before: "-"
          after: "--"
          severity_of_test: moderate
          matched_refutation_ids: [r1]
          reasoning: "Policy registry confirms external forwarding is prohibited for Finance Operations. No legitimate self-setup reason exists — Alice cannot have had an authorized operational reason to create this rule. r1 (can directly confirm she created it for legitimate purpose) is blocked: even if Alice created the rule, it was a policy violation. h-001-001 advances to --: the self-setup benign story requires a policy exception that does not exist."
          supporting_edges: []
        - hypothesis: h-001-002
          before: "+"
          after: "++"
          severity_of_test: moderate
          matched_prediction_ids: [p1]
          reasoning: "Policy registry confirms no legitimate use case for this rule for alice.chen's role — the rule is inherently anomalous regardless of who created it. Combined with the unrecognized device (l-002), this satisfies all predictions for h-001-002: device absent from MDM (p1 confirmed in l-002), Alice's normal sessions are US/compliant (p1 confirmed in l-002), and the forwarding action is organizationally unauthorized (policy anchor, full authority). Rule 6 completeness: p1 is the only prediction. union of matched_prediction_ids = {p1} = full prediction set. Weight: ++."
          supporting_edges: []

conclude:
  termination:
    category: trust-root
    rationale: "h-001-002 (?mfa-phished-account-takeover) reached ++ via two full-authority anchors (MDM-Intune: device absent, mail-forwarding-policy-registry: forwarding prohibited). h-001-001 (?user-self-configured-unmanaged-device) reached --. h-002 (?account-takeover-session) at - (MFA confirmed, but partial-authority cap prevented advance; now superseded by h-001-002 reaching ++ on the refined chain). Adversarial hypothesis h-001-002 confirmed at ++. No ceiling or exhaustion condition — a trust-root conclusion is warranted."
  disposition: true_positive
  confidence: high
  matched_archetype: "mfa-phished-account-takeover-exfil-staging"
  summary: "alice.chen@company.com's mailbox had an external forwarding rule (to outside-dropoff@protonmail.com, hiding forwarded messages) created from an unrecognized device in Bucharest, Romania. Entra sign-in confirmed MFA success but flagged an unregistered device. MDM-Intune confirmed the device is not enrolled for Alice. Mail-forwarding-policy-registry confirmed external forwarding is prohibited for her role. h-001-001 (?user-self-configured-unmanaged-device) reached --; h-001-002 (?mfa-phished-account-takeover) reached ++. Disposition: true_positive. Recommended action: disable the forwarding rule immediately, revoke Alice's active sessions, initiate account recovery workflow, notify alice.chen and raj.patel, escalate to IR for scope determination."
```

---

## Part 3 — Closing Observations

### Spec ambiguities and friction

1. **`storage` as target of a forwarding rule.** The rule doesn't directly target the mailbox as a storage object — it installs a rule on the mailbox. I modeled the `New-InboxRule` command as `targeted → mailbox (storage)` because the mailbox is what the rule acts on, but there's an argument it targets the rule object itself (which doesn't have a vertex type in v2.3). The spec's action-as-vertex pattern is clear for reads/writes/queries but less obvious for "install a configuration rule on a resource." I picked `storage` because the downstream effect is mail data being forwarded, but I'm not confident.

2. **OWA session vs Entra sign-in session.** The alert gives a `session_id` (OWA) and an `azure_ad_session_id` (Entra). I modeled one session vertex from the alert envelope and let the trust lead materialize a second session vertex from the sign-in log — two projections of the same login, each carrying distinct attributes. The spec supports this (dual-shape/same-session) but the guidance is for dual-shape events with different structural shapes (action + lifecycle). Here both are lifecycle-shaped. I made the same choice the spec recommends for dual-EDR records: one vertex per data-source projection with distinct attributes, no `correlates_with` edge.

3. **Hypothesis weight reaching `++` via partial-authority partial-anchor chain.** In l-003 I advanced h-001-002 to `++`. The supporting evidence came from two `full-authority` anchors (MDM at `full`, policy registry at `full`). I checked rule 16: no partial-authority issue. But I'm not sure the validator's rule 6 completeness check works across leads — rule 6 says "the union across resolutions on the hypothesis must equal the full prediction set." h-001-002 had only p1. l-002 resolved p1 to `+` and l-003 resolved the same p1 again to `++`. That's one prediction, matched in two separate leads with increasing weight. The spec doesn't explicitly address a single prediction being confirmed by two successive leads; I took it as allowed since each lead is self-contained and the union of matched_prediction_ids = {p1} = full set.

4. **No `command` classification for Exchange inbox-rule creation.** The classification vocabulary for `command` vertices in §9 includes `cloud-api-call` as the catchall, but `New-InboxRule` is more specifically an Exchange management command than a generic cloud API. I used `cloud-api-call` with the Exchange specifics in `attributes.api_name`. Fine, but Exchange power users writing multiple companions might want a `mail-rule-create` classification.

### Retrieval-wish shape: structured fields vs semantic prose

The retrieval wishes split roughly 60/40 between structured-field queries and semantic/prose needs.

The structured side — termination category, anchor verdict results, authority_for_question values, hypothesis refinement chains derivable from hierarchical IDs, dead-leads indexed from failure_reason enums — is genuinely well-served by what v2.3 captured. R3 (refinement chain shape), R5 (dead-lead history for a data source), R6 (authority_for_question precedents for an anchor), and R9 (termination category distribution) are all queries a distiller could answer by joining structured fields. These feel like the spec's central design bet paying off.

The harder wishes — R1 (geo-anomaly base rates needing vertex attribute string search), R4 (benign self-setup confirmation paths needing hypothesis name semantic matching), R7 (was a specific anchor informative in similar cases, requiring resolution reasoning prose), R10 (contact protocol for ceiling cases, entirely in ceiling_rationale prose) — require either semantic match over prose fields or a custom attribute vocabulary that v2.3 defers to `attributes.kind` free-form objects. The schema correctly defers these to the distiller and semantic layer; the survey just confirms there's a real class of retrieval needs that won't be fast without some prose indexing.

### What to make fast first in the query script

If I were building the query script, I'd make **anchor-result aggregation fast first**: for a given `anchor_id`, return the distribution of `{result, authority_for_question}` values across all cases, joined with `conclude.disposition`. This covers the highest-frequency question an analyst has when deciding whether to trust a new anchor verdict ("has `entra-id-sign-in-log` with `result: partial, authority_for_question: partial` ever resolved TP? What did those cases look like?"). It's a three-field join on structured data that requires no prose parsing, and it directly answers the kind of calibration question that changes how aggressively you weight an anchor result — which is the decision that propagates to every hypothesis in the current investigation.
