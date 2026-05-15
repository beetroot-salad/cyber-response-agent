# Query-template test fixtures

Per-template test fixtures the **lead-author** (`defender/learning/lead_author.py`)
runs to verify a template edit didn't break selectability or correctness. The
fixtures live alongside the templates they cover, not inside them, so the
single-file template layout the gather subagent grep-walks stays unchanged.

## Layout

```
defender/skills/gather/queries/
├── {system}/                                    # e.g. wazuh/
│   └── {template-id}.md                         # the template
└── tests/
    └── {system}/                                # e.g. wazuh/
        └── {template-id}/                       # e.g. auth-events/
            ├── customization.yaml               # Tier 1 (single edited template)
            ├── positive.yaml                    # Tier 2 (background: should match)
            ├── negative.yaml                    # Tier 2 (background: must reject)
            └── neighbors.yaml                   # Tier 2 (background: ranking guard)
```

`{template-id}` matches the template's basename without the `.md` extension.
The fixtures dir is created lazily — missing fixture files are not an error;
they cause the corresponding check to be skipped with `verdict: skipped`.

This PR backfills **`customization.yaml`** only. `positive.yaml`,
`negative.yaml`, and `neighbors.yaml` are declared here for forward
compatibility with the Tier 2 background routine; their fixtures will be
authored when the Tier 2 runner exists. Do not author them speculatively —
they need the runner to validate against.

## Tiers

* **Tier 1** runs only on the **edited** template after each lead-author
  commit. Two legs, both deterministic in their pass/fail signal:
  * **Static**: frontmatter shape, required sections, parameter
    documentation. No LLM. Fast.
  * **Customization**: `defender.learning.customization_test` invokes Haiku
    three times per case and scores against an expected/forbidden-substring
    rubric. Per-case verdict is `pass` if ≥ ceil(trials * 2/3) trials pass.
* **Tier 2** runs in the background across the **whole catalog** (not gated
  on a single edit). It surfaces selectability drift via positive/negative
  fixtures and ranking regressions via neighbors fixtures. Not implemented
  in this PR.

## `customization.yaml` (Tier 1)

```yaml
cases:
  - id: srcip-baseline-shift          # required; short, kebab-case
    category: baseline-shift          # optional; free-form tag for analysis
    alert_excerpt:                    # optional; inserted verbatim as JSON
      rule: {id: "5710", groups: ["sshd"]}
      data: {srcip: "198.51.100.22"}
      "@timestamp": "2026-04-17T10:30:00.000Z"
    adaptation_note: |                # required; what the customizer must produce
      Foreground was queried with --start 2026-04-17T09:30:00Z --window 2h,
      scoped to data.srcip:198.51.100.22. Produce the baseline shift query:
      same IP, same window duration, shifted 7 days earlier.
    rubric:                           # required; substring scoring
      expected_substrings:            # every entry must appear in the output
        - "data.srcip:198.51.100.22"
        - "2026-04-10T09:30:00"
        - "--window 2h"
      forbidden_substrings:           # no entry may appear in the output
        - "2026-04-17"                # the foreground date
        - "monitorprobe"              # noise that wasn't asked for
```

Field contracts:

* **`id`** — short, kebab-case. Used in log paths and run summaries.
* **`adaptation_note`** — the only customizer-facing instruction. Be specific
  about what changes (date, scope, entity), what stays (same window, same
  filter), and what to leave out (don't include the foreground date,
  irrelevant fields). The note is the contract; the rubric is the check.
* **`rubric.expected_substrings`** — pick substrings that uniquely
  characterize the right answer. A timestamp prefix, a literal field
  reference, a flag with its value. Avoid generic substrings ("query",
  "wazuh") — they pass when the customizer hallucinated.
* **`rubric.forbidden_substrings`** — values that look right but are wrong:
  the date the customizer should have shifted, an entity from the alert that
  isn't in scope. Catches "near-miss" failures.

Each case is independent; the file verdict is `pass` only when every case
passes its 2/3 threshold.

## `positive.yaml` (Tier 2 — forward-compat)

For each (alert excerpt × lead description) tuple the catalog should match,
declare which template should win selection. The Tier 2 runner enforces the
ranking.

```yaml
cases:
  - id: brute-force-by-srcip
    alert_excerpt: { ... }
    lead_description:
      goal: "characterize who's logging in from a specific source IP"
      what_to_characterize:
        - "Source IP diversity"
    expected_template_id: wazuh.auth-events
```

## `negative.yaml` (Tier 2 — forward-compat)

For each (alert excerpt × lead description) tuple the catalog should NOT
match this template for, declare the negative. The Tier 2 runner enforces
non-selection.

```yaml
cases:
  - id: outbound-network-not-auth
    alert_excerpt: { ... }
    lead_description:
      goal: "characterize outbound C2 traffic from a host"
    rejected_template_id: wazuh.auth-events
    reason: "outbound network is not in scope for auth-events"
```

## `neighbors.yaml` (Tier 2 — forward-compat)

Pinned top-k neighbor lists. Catches refactor-induced ranking regressions
(e.g. tokenizer change demoting a previously-top-1 template).

```yaml
cases:
  - id: auth-events-siblings
    target_template_id: wazuh.auth-events
    expected_top_k:
      - wazuh.sudo-commands
      - wazuh.recent-rule-fires
      - wazuh.agent-alerts-in-window
    k: 3
```
