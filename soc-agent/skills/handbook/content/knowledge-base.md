# Knowledge Base Layout

How the plugin's knowledge composes at runtime. The pieces are deliberately split along the axis of "what is portable across deployments" vs "what is specific to this org".

## The five directories

```
soc-agent/
├── knowledge/
│   ├── common-investigation/      # portable methodology — same for every deployment
│   │   ├── SKILL.md
│   │   ├── checklist.md
│   │   ├── leads/
│   │   └── lessons/
│   │
│   ├── environment/               # org-specific deployment knowledge
│   │   ├── context/
│   │   ├── data-sources/
│   │   ├── operations/
│   │   └── systems/
│   │
│   └── signatures/                # per-alert-type knowledge
│       ├── _template/
│       └── {signature-id}/
│           ├── context.md
│           ├── playbook.md
│           ├── archetypes/        # analyst-shared patterns with trust anchors (new model)
│           └── precedents/        # past resolved investigations (legacy model, still supported)
│
├── config/
│   └── signatures/
│       └── {signature-id}/
│           └── permissions.yaml   # per-signature safety config
│
└── schemas/                       # dataclass validators — system contracts
    ├── report_frontmatter.py
    ├── state.py
    └── precedent.py
```

Each of these plays a different role. The runtime composition is what makes them useful.

## common-investigation — portable methodology

Universal investigation methodology. Nothing in this directory is vendor-specific, org-specific, or signature-specific — it's the parts of "how to investigate a security alert" that don't change when you swap the SIEM or the org.

- **`SKILL.md`** — investigation vocabulary (hypotheses with `?` prefix, assessments `++/+/-/--`, trace format) and the top-level index.
- **`checklist.md`** — self-check guide the agent reads at CONTEXTUALIZE and verifies at CONCLUDE. Investigation completeness, adversarial hypothesis, report shape, common mistakes.
- **`leads/`** — reusable **lead definitions**. Each lead is a directory:
  ```
  leads/{lead-name}/
  ├── definition.md          # methodology: what to characterize, pitfalls, data tags
  └── templates/             # optional per-vendor query templates
      ├── wazuh.md           # base query + field mapping in Wazuh's native syntax
      ├── splunk.md          # base query + field mapping in SPL
      └── ...
  ```
  `definition.md` is the portable "how to think about this lead" — what signals to characterize, what pitfalls to avoid, what data tags it needs. `templates/{vendor}.md` is the "how to actually run it on this SIEM" — base query in native syntax, field mappings, notes. The definition is always read; the template is only read if a matching vendor is available.

  `_template/` shows the standard structure for new leads. `ad-hoc/` is a meta-lead for undefined leads (follow the methodology to construct one from scratch). `data-source-debug/` is a meta-lead for verifying that a suspiciously empty result is "nothing happened" rather than "pipeline is broken".

- **`lessons/`** — cross-cutting lessons from past investigations. Referenced inline from playbooks via `@import:lesson-name` — the resolver loads them automatically at skill load time so the playbook stays compact and the lesson stays deduplicated.

## environment — org-specific knowledge

Everything that varies per deployment. Editing files in this tree is how an org tells the agent "this is how our infrastructure is set up."

- **`context/`** — classification heuristics. "Which IP ranges are internal vs DMZ vs production?" "How are service accounts named?" "Which identities belong to which teams?" Used as fallbacks when external system lookups are unavailable, and as hints for hypothesis generation ("this source is in the vendor scanner range, so `?vendor-scanner` belongs in the hypothesis space").

- **`data-sources/`** — the catalog of **what data lives where**. For each data type (authentication events, process execution, network flows, asset inventory, identity/role data) this directory says: which systems hold it, what fields are canonical, what the coverage window is, how fresh the data typically is. When a lead needs `auth-events`, the agent reads this directory to find out which system to query and how much coverage to expect.

- **`operations/`** — queryable lookups against external authorities. Primarily **trust anchors**: named sources that confirm whether an observed activity is sanctioned. "Is this automation job known to the platform team?" "Is this account owned by a real employee?" "Is this IP registered as a sanctioned vendor scanner?" Trust anchors are how investigations escape "looks benign" and get to "is authoritatively sanctioned." The `operations/` files describe each anchor's question shape, query method, and failure modes.

  Archetypes declare which anchors are required in their `required_anchors` frontmatter. The runtime check (Tier 1 validation) enforces that every required anchor was consulted and confirmed before a resolved status is legal.

- **`systems/`** — system-specific implementation knowledge. For each SIEM/EDR/lookup system: query patterns, field mappings, known quirks, config shape. `systems/wazuh/` documents Wazuh field semantics, index naming, and common gotchas. `systems/target-endpoint/` documents the playground's stand-in for endpoint tooling (live inspection via `docker exec`). A new system lives under a new subdirectory.

## signatures — per-alert-type knowledge

One directory per alert type. Each signature's directory is the domain knowledge the agent loads when investigating that specific alert. `resolve_imports.py` bakes everything in this directory into the investigation skill prompt at skill load time.

- **`context.md`** — the signature reference. Frontmatter carries `signature_id`, `name`, `severity`, `data_sources`, MITRE mapping, related rules, base rate estimates. The body describes: detection logic (what triggers the rule), alert fields (what's in the payload), threat model (what an attacker would be doing if this is a true positive), known false positives (grounded in real closed tickets), risk indicators that actually discriminated outcomes historically, operational notes, tuning guidance, detection gaps. This is the document the agent reads to understand what kind of alert it's looking at and what the stakes are.

- **`playbook.md`** — the hypothesis catalog and lead list. Hypotheses come from real outcome clusters in past tickets (plus at least one adversarial hypothesis). Each lead cross-references the `common-investigation/leads/` library where possible. An optional `## Screen` section defines mechanical fast-path patterns. Auto-close criteria and escalation criteria are signature-specific.

  Playbooks can use `@import:lesson-name` inline to reference files in `common-investigation/lessons/` — the import resolver pulls them in at skill load time so playbooks don't duplicate cross-cutting content.

- **`archetypes/`** *(new model)* — analyst-shared named patterns, each with its own story, discriminating boundary, and frontmatter-declared `required_anchors`. An archetype is how a team writes down "this is the shape of a `known-scanner` resolution; here's how to recognize it, here are the trust anchors you must confirm before you're allowed to call it resolved." Archetypes are preferred over ad-hoc hypotheses when the team has consolidated a recurring pattern.

- **`precedents/`** *(legacy model, still supported)* — past resolved investigations as JSON files. Each precedent records an alert, the leads pursued, the observations, the confirmed hypothesis, and the disposition. Resolved reports that use `matched_precedent` must point at one of these files, and the precedent's `signature_id` must match and its `validated_at` must be within the signature's `precedent_max_age_days`.

New signatures should prefer the archetype shape. The precedent shape remains supported for signatures that haven't been migrated and for screen-resolved investigations, which always match against precedents.

## config/signatures — safety configuration

Per-signature operational configuration that isn't part of the investigation knowledge itself.

- **`permissions.yaml`** — `mode.allowed`, `mode.default` (which execution modes are allowed and which is the default), allowed tools, and `precedent_max_age_days` (how old a precedent is allowed to be before it no longer counts as a valid match). The permissions file is read by the investigation skill at runtime and by `validate_report.py` when checking precedent recency.

Keeping `config/signatures/` separate from `knowledge/signatures/` maintains a clean split: the `knowledge/` tree is the investigative content, and the `config/` tree is the policy. Different lifecycles, different review paths.

## schemas — system contracts

Python dataclass validators that formalize the shape of the runtime artifacts. They're code, not documentation, but they're the authoritative source of truth for what's allowed.

- **`report_frontmatter.py`** — `ReportFrontmatter` dataclass, `parse_frontmatter` helper, `MIN_LEADS_BY_SEVERITY` constant, enum validation (status, disposition, confidence, anchor kinds and results). Used by Tier 1 validation.
- **`state.py`** — `Phase` enum, `TRANSITIONS` dict, `INITIAL_PHASE`, `MAX_LOOPS`, `validate_transition`, `count_loops`, `make_state`. Used by `write_state.py`.
- **`precedent.py`** — precedent JSON shape, `check_recency`, `DEFAULT_MAX_AGE_DAYS`. Used by Tier 1 validation.

## How a lead resolves at runtime

The knowledge base composes at runtime through a sequence of lookups. Here's what happens when the agent decides to pursue an `authentication-history` lead:

1. **Signature playbook names the lead.**
   `knowledge/signatures/wazuh-rule-5710/playbook.md` includes `authentication-history` in its lead list for the active hypothesis.

2. **Portable lead definition describes the methodology.**
   `knowledge/common-investigation/leads/authentication-history/definition.md` says: *"Characterize the source-target auth relationship over the last N days. Look for volume, success/failure ratio, time distribution, username enumeration patterns. Pitfall: absence of failures doesn't mean absence of brute force if logging is sampled. Data tags: `auth-events`."*

3. **Environment data-sources answers "where do auth events live?"**
   `knowledge/environment/data-sources/auth-events.md` maps the `auth-events` tag to the systems that hold the data — in the reference deployment, Wazuh. It also reports coverage and retention.

4. **Per-vendor lead template provides the base query.**
   `knowledge/common-investigation/leads/authentication-history/templates/wazuh.md` contains the Wazuh Lucene query in native syntax with placeholder slots for the source entity, target entity, and time window.

5. **System-specific knowledge provides field mappings and quirks.**
   `knowledge/environment/systems/wazuh/` is consulted for field names (`data.srcip` vs `agent.ip`, for example) and known quirks that affect the query.

6. **Adapter CLI executes the query.**
   `scripts/siem/wazuh_cli.py query "<composed lucene>"` runs the query with the loaded credentials and returns raw results. The agent never sees the credentials — they're loaded from environment variables or `config.env` by the adapter.

7. **Results flow back into GATHER.**
   The agent post-processes the raw results in Python, characterizes them (not interprets), and writes the observation into `investigation.md`.

The whole flow is composable: swap Wazuh for Splunk and the only thing that changes is the data-source mapping, the system-specific knowledge, the lead template, and the adapter CLI. The playbook, the lead definition, and the investigation methodology are all unchanged.

## Where extensions go

| If you want to... | Edit this |
|---|---|
| Add a new alert type | `knowledge/signatures/{new-id}/` + `config/signatures/{new-id}/permissions.yaml` |
| Add a new SIEM or data source | `knowledge/environment/systems/{new-system}/` + `knowledge/environment/data-sources/` entries + a new adapter CLI |
| Add a new reusable lead | `knowledge/common-investigation/leads/{new-lead}/definition.md` + per-vendor templates as needed |
| Capture a cross-cutting investigation lesson | `knowledge/common-investigation/lessons/{lesson}.md` + `@import:{lesson}` from playbooks |
| Change how trust anchors work | `knowledge/environment/operations/` and the `required_anchors` frontmatter of the archetypes that use them |
| Change the validation rules | `schemas/` — but understand the contract implications first |

See `knowledge/signatures/_template/README.md` for the full signature onboarding workflow.
