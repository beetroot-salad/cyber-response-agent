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
│           ├── field-quirks.md    # scanner-scoped subset of context.md
│           ├── playbook.md
│           └── archetypes/        # one directory per recognized archetype
│               └── {archetype-name}/
│                   ├── story.md        # observable-shape narrative (scanner target)
│                   ├── trust-anchors.md # required anchors + precedent pointer (grounding contract)
│                   └── {TICKET-ID}.json  # precedent snapshots (cached past tickets)
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
- **`checklist.md`** — self-check guide the agent reads at CONTEXTUALIZE and verifies at CONCLUDE. Investigation completeness, legitimacy-contract declaration + resolution, report shape, common mistakes.
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

- **`systems/`** — system-specific implementation knowledge. For each SIEM / EDR / lookup system: query patterns, field mappings, known quirks, config shape. Examples ship under this directory as worked references — the plugin's Wazuh knowledge lives under `systems/wazuh/`, and a constrained host-inspection CLI (an EDR stand-in for the playground deployment) lives under `systems/host-query/`. Each system's own SKILL.md describes its invocation pattern and constraints; the handbook does not hardcode those details. A new system lives under a new subdirectory.

## signatures — per-alert-type knowledge

One directory per alert type. Each signature's directory is the domain knowledge the agent loads when investigating that specific alert. `resolve_imports.py` bakes everything in this directory into the investigation skill prompt at skill load time.

- **`context.md`** — the signature reference. Frontmatter carries `signature_id`, `name`, `severity`, `data_sources`, MITRE mapping, related rules, base rate estimates. The body describes: detection logic (what triggers the rule), alert fields (what's in the payload), threat model (what an attacker would be doing if this is a true positive), known false positives (grounded in real closed tickets), risk indicators that actually discriminated outcomes historically, operational notes, tuning guidance, detection gaps. This is the document the agent reads to understand what kind of alert it's looking at and what the stakes are.

- **`field-quirks.md`** — a tight, scanner-scoped extract of `context.md` holding just the Key Observables table (observable → JSON path → why it matters for shape comparison) plus any field-level gotchas (counterintuitive semantics, NAT-egress caveats). Read by the archetype-scan subagent instead of the full `context.md` — keeps the scanner's context small without depriving it of the field semantics it needs to extract observables from the alert.

- **`playbook.md`** — the body carries two complementary catalogs plus the operational scaffolding:
  - **Hypothesis seeds** — lean, mechanism-shaped candidate explanations ("legitimate automation", "authentication mistake", "credential guessing", adversarial follow-up). These are *lacking by design*, skeletal prompts for the HYPOTHESIZE phase that the agent develops from evidence. They map roughly to archetypes when the shape fits, but an investigation can confirm a hypothesis without matching any archetype.
  - **Archetype catalog** — a pointer table into `archetypes/{name}/`, described below.
  - **Starter lead order** — the signature-specific leads that discriminate between the seeds/archetypes cheaply.
  - **Screen table (optional)** — mechanical fast-path patterns against the most common benign archetype. Only included when every indicator is unambiguous and queryable.
  - **Quirks, scope, and composition rules** — signature-specific guardrails that don't fit anywhere else.

  Playbooks can use `@import:lesson-name` inline to reference files in `common-investigation/lessons/` — the import resolver pulls them in at skill load time so playbooks don't duplicate cross-cutting content.

- **`archetypes/`** — the pattern-recognition **cache**, not the source of truth. One subdirectory per recognized archetype. Each archetype is a named pattern rooted in past tickets, used at HYPOTHESIZE time to frame / steer the investigation and at CONCLUDE time to short-circuit resolution via the grounding leg when the shape cleanly matches. Archetypes are *recommendations*, not the primary reasoning layer: the hypothesis loop always runs, and an investigation that doesn't match any archetype is a valid outcome (usually escalation, occasionally a novel pattern that deserves a new archetype after the fact). Each archetype directory holds:
  - **`story.md`** — the archetype story: the abstract pattern and the discriminating boundary that takes alerts out of this archetype into siblings. Frontmatter declares `archetype`, `signature_id`, and `required_anchors`. Read by the archetype-scan subagent at CONTEXTUALIZE time.
  - **`trust-anchors.md`** — the grounding contract: one subsection per `required_anchors` entry (question the anchor answers + what counts as confirmation) and a pointer to the precedent snapshots. Same frontmatter as `story.md`. Read by the main agent at ANALYZE/CONCLUDE time (for grounding) and by Judge B (for sibling completeness).
  - **`{TICKET-ID}.json`** (zero or more) — cached precedent snapshots. Each file is a pointer to a real past ticket in the source-of-truth ticketing system. The JSON captures `ticket_id`, `archetype`, `captured_at`, `disposition`, `narrative`, the raw `alert` snapshot, and `anchors_at_time` — the trust anchor responses at the moment the ticket closed. Entries in `anchors_at_time` marked `temporal: true` represent time-bounded confirmations (on-call windows, change tickets, deploy runs) that do NOT transfer forward in time and must be re-confirmed against live anchors.

When an archetype *does* match, resolution requires both legs: a shape match (`matched_archetype` naming a real archetype directory) AND grounding — at least one of (every `required_anchors` entry confirmed, OR `matched_ticket_id` citing a valid precedent snapshot under the same archetype). Archetypes that declare no `required_anchors` can only resolve with a cited precedent. See `content/validation.md` for the Tier 1 enforcement details. When no archetype matches, `status=resolved` is not an option — the investigation escalates with whatever evidence and reasoning it has gathered.

## config/signatures — safety configuration

Per-signature operational configuration that isn't part of the investigation knowledge itself.

- **`permissions.yaml`** — `mode.allowed`, `mode.default` (which execution modes are allowed and which is the default), allowed tools, and `precedent_max_age_days` (how old a precedent is allowed to be before it no longer counts as a valid match). The permissions file is read by the investigation skill at runtime and by `validate_report.py` when checking precedent recency.

Keeping `config/signatures/` separate from `knowledge/signatures/` maintains a clean split: the `knowledge/` tree is the investigative content, and the `config/` tree is the policy. Different lifecycles, different review paths.

## schemas — system contracts

Python dataclass validators that formalize the shape of the runtime artifacts. They're code, not documentation, but they're the authoritative source of truth for what's allowed.

- **`report_frontmatter.py`** — `ReportFrontmatter` dataclass, `parse_frontmatter` helper, enum validation (status, disposition, confidence, anchor kinds and results). Used by Tier 1 validation. A legacy `MIN_LEADS_BY_SEVERITY` constant is still defined here but is no longer enforced — the severity→min-leads floor was dropped from the CONCLUDE gate as empirically artificial (lead depth correlates with signature scaffolding and data availability, not with the severity label).
- **`state.py`** — `Phase` enum, `TRANSITIONS` dict, `INITIAL_PHASE`, `MAX_LOOPS`, `validate_transition`, `count_loops`, `make_state`. Used by `infer_state.py` hook.
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
   `scripts/tools/wazuh_cli.py query --query "<composed lucene>"` runs the query with the loaded credentials and returns raw results. The agent never sees the credentials — they're loaded from environment variables or `config.env` by the adapter.

7. **Results flow back into GATHER.**
   The agent post-processes the raw results in Python, characterizes them (not interprets), and writes the observation into `investigation.md`.

The whole flow is composable: swap Wazuh for Splunk and the only thing that changes is the data-source mapping, the system-specific knowledge, the lead template, and the adapter CLI. The playbook, the lead definition, and the investigation methodology are all unchanged.

## Where extensions go

| If you want to... | Edit this |
|---|---|
| Add a new alert type | `knowledge/signatures/{new-id}/` + `config/signatures/{new-id}/permissions.yaml` |
| Add a new SIEM or data source | `knowledge/environment/systems/{new-system}/` + `knowledge/environment/data-sources/` entries + a new adapter CLI under `scripts/tools/` that implements the base in `schemas/adapter_contract.py` (use `/connect` to bootstrap the scaffolding) |
| Add a new ticketing connector | A new CLI under `scripts/tools/` implementing the ticketing family in `schemas/adapter_contract.py` (see `content/act-mode.md` for the `ActionContract` dry-run-first dispatch) |
| Add a new reusable lead | `knowledge/common-investigation/leads/{new-lead}/definition.md` + per-vendor templates as needed |
| Capture a cross-cutting investigation lesson | `knowledge/common-investigation/lessons/{lesson}.md` + `@import:{lesson}` from playbooks |
| Change how trust anchors work | `knowledge/environment/operations/` and the `required_anchors` frontmatter of the archetypes that use them |
| Change the validation rules | `schemas/` — but understand the contract implications first |

See `knowledge/signatures/_template/README.md` for the full signature onboarding workflow.
