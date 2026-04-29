# Dense PREDICT envelope — comprehensive reference

This doc is the **edge-case + parser-rejection reference** for the dense PREDICT trailer. The §Output format guidelines in `SKILL.md` plus the matching `examples/shape-{E,A,M}.md` carry ~80% of authoring needs. Reach for this doc when:

1. You hit a parser rejection in `remediation_notes` and want the rule's rationale + the correct shape.
2. You're authoring something the worked examples don't cover (multi-hypothesis Shape M with `attribute_predictions`, hierarchical refinement IDs, `scope_override` semantics, `integrity_waived` rationale, hypothesis with `concerns?`, lead-pred carrying both `comparison` and an unusual `advance_to` value).
3. You need to escape a literal `]` inside an annotation, use ASCII fallbacks for unicode operators, or understand how the handler composes your dense output back into invlang YAML.

Sections:
- §1 Envelope structure (header, block grammar, escapes, ASCII fallbacks)
- §2 `kind` slot — full enum + comparison rule + grading implications
- §3 `:H hypotheses` — column definitions + value enums
- §4 `:P h-{id}.<sub>` — preds, attr_preds, refuts, authz, comparisons (all five)
- §5 `:L lead_preds` + `:L lead_preds.comparisons` — Shape E branch plan
- §6 `:R routing` + sub-blocks — required + optional surfaces
- §7 Story prose grammar + sentence-ID referent rule
- §8 Field-presence matrix — formal table by shape
- §9 Parser error catalogue — every error string the parser can raise + remediation
- §10 Checkpoint contract — YAML wrapper carrying dense scalar
- §11 Handler post-parse contract — what happens after the parser accepts your output

---

## §1 Envelope structure

The envelope is a sequence of newline-delimited blocks. The literal first non-empty line is the header:

```
predict loop=<int> shape=<E|A|M>
```

After the header, blocks appear in any order. Each block opens with a header line:

```
:<TAG> <name>[ [col1|col2|col3?|...]]
```

- `<TAG>` ∈ `{H, L, R, P}` (single uppercase letter, prefixed `:`).
- `<name>` matches `[A-Za-z0-9_.\-]+` — alphanumerics + `.` + `_` + `-`. The dot separates parent from sub-name (e.g., `routing`, `routing.lead_hints`, `h-001.preds`).
- The optional `[col1|col2|...]` declares column names. A trailing `?` on a column name marks it optional — the parser right-pads missing trailing cells with empty strings, but cells preceding any non-empty cell are not optional.

After the header, each non-empty line until the next `:` header is a row. Rows are `|`-separated cells. The cell count must not exceed the column count; missing trailing cells (when the column is `?`-marked) are auto-filled with empty strings.

Cells may contain quoted strings (`"..."`) for content with embedded `|`, `:`, `;`, or whitespace. The parser strips the outer quotes when extracting cell values.

### Bracket escape

Inside annotation strings (e.g., the `:: <annotation>` slot on `:T resolutions` for ANALYZE; PREDICT doesn't use `[...] :: ...` annotations directly, but the parser is bracket-aware everywhere), embed a literal `]` as `\]`. The parser strips the backslash on read.

### ASCII fallbacks

Unicode operators are accepted on parse with these ASCII equivalents:

| Unicode | ASCII | Meaning |
|---|---|---|
| `→`     | `=>`  | implies / advances-to |
| `⟺`    | `<=>` | iff (used by ANALYZE; not present in PREDICT today, but parser supports both) |
| `∧`     | `&`   | logical AND |
| `¬`     | `~`   | logical NOT |
| `∨`     | `\|`  | logical OR (rare; cell separator collision — quote the segment) |

Use unicode in worked examples (cleaner read), accept ASCII without complaint when emitted by smaller models that don't reach for unicode.

### Comments

Lines starting with `#` (after leading whitespace) are comments and skipped by the tokenizer. Use sparingly — comments inside dense rows are rare; the worked examples don't use them.

### Outer fence tolerance

The parser tolerates a single outer ``` fence pair around the envelope (with or without a `text` / `dense` info string). Subagents may emit fenced output for terminal rendering; the parser strips one outer fence pair before tokenizing. Do not emit nested fences inside the envelope.

---

## §2 `kind` slot

Every prediction-shaped row carries an explicit `kind` from this closed enum:

| `kind`           | Semantics                                                                                          | Comparison row required? | Disallowed contexts |
|---|---|---|---|
| `geometry`       | Foreground matches / deviates from the recurring baseline geometry on a recorded dimension.        | Yes                       | — |
| `cadence`        | Foreground rate / inter-event distribution falls within / outside the baseline distribution.       | Yes                       | — |
| `novel-artifact` | A category of artifact appears in foreground that's absent from baseline of comparable shape.      | Yes                       | — |
| `absence`        | Foreground deviates from a structurally-zero baseline (any presence is the deviation).             | Yes                       | — |
| `presence`       | Bare-presence claim NOT tied to a zero baseline.                                                   | No                        | **Forbidden on `:P h-{id}.refuts`** rows (presence-test refutation anti-pattern). |
| `absolute`       | Direct field-read threshold — the field exists in the alert payload or anchor response.            | No                        | — |

### The comparison rule

A row with `kind ∈ {geometry, cadence, novel-artifact, absence}` (the **deviation set**) **requires** a matching row in `:P h-{id}.comparisons` (for `:H`-attached predictions) or `:L lead_preds.comparisons` (for `lp*` rows). The comparison row declares the selector (what historical / peer / population set to fetch) and the dimension (which field of that set the foreground is being compared against).

A row with `kind ∈ {presence, absolute}` must not carry a comparison — the parser rejects it as "non-deviation kind must not carry a comparison."

### Why the rule exists

`absolute` and `presence` are claims about the **alert's own data** — direct field-reads on the alert payload or the immediate gather response. No external comparison set is needed; the answer is in front of the reader.

Deviation kinds are claims about **how the alert's data sits within a population** (the population being a historical self-comparison, a peer class, the broader population, or a cross-rule slice). The selector + dimension together define what population to fetch and what to compare on. Without them, the deviation claim has no referent.

### Common rejection: "kind='absence' requires a row in :P h-{id}.comparisons"

`absence` is the kind that smaller models most often misuse. The intuition trap is: "if the comparison set is empty, why declare a comparison?" The answer is that `absence` describes a *baseline shape* — "the selector returns zero events" — and you still have to declare *which selector* is expected to return non-zero. Without that, "absence" is meaningless: absence of what?

Correct shape:

```
:P h-001.preds [id|subject|kind|from_story|claim]
p3|proposed_parent|absence|s2|"selector returns zero events (no recurring runc-exec history for this image)"

:P h-001.comparisons [pred_ref|selector_kind|selector|dimension]
p3|historical-self|"image=<image> AND rule=<this_rule> over 168h"|event-count
```

The dimension `event-count` makes the absence concrete: the selector should return zero on `event-count`, the foreground breaks that (any presence > 0).

### Refutation kinds

A `:P h-{id}.refuts` row's `kind` is **independent** from the predictions it refutes — it describes the *refutation*, not the original claim. Common patterns:

- A `kind=absolute` prediction refuted by `kind=absolute` (both check the same field, opposite values).
- A `kind=cadence` prediction refuted by `kind=cadence` (both grade against the same cadence baseline, opposite directions).
- A `kind=presence` prediction refuted by `kind=absolute` (presence claim that becomes a direct field-read at refutation time) or `kind=absence` (presence-baselined-against-zero-history) — but never `kind=presence` (presence-test anti-pattern: a refutation that fires on any signal at all is structurally weak).

The parser hard-rejects `kind=presence` on refutation rows. Rewrite with `kind=absolute` (if the refutation can name a specific field-value the alert telemetry already records) or `kind=absence` (if the refutation is grounded in a structurally-zero baseline).

---

## §3 `:H hypotheses`

The hypothesis metadata block. Single instance per envelope; ≥ 1 row for Shape A, ≥ 2 rows for Shape M, absent for Shape E.

### Columns

```
:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
```

| Column            | Required? | Format                                                | Notes |
|---|---|---|---|
| `id`              | yes       | `^h-\d+(?:-\d+)?$`                                    | `h-001`, `h-002`, ...; hierarchical refinement uses `h-{parent}-{ordinal}` (e.g., `h-001-1`, `h-001-2`). |
| `name`            | yes       | `?<mechanism-name>` (kebab-case, prefixed `?`)        | Mechanism only — never verdict. Validator rejects evaluation-packed prefixes (`?authorized-`, `?legitimate-`, `?malicious-`, `?adversary-`, ...). |
| `attached_to`     | yes       | vertex id (`v-NNN`) from prologue or prior loops      | The vertex this hypothesis's proposed_edge attaches to — i.e., the *child* of the proposed parent_vertex. |
| `rel`             | yes       | relation name from the schema                         | e.g., `initiated_by`, `spawned`, `modified_policy`, `emitted_dns_queries`. |
| `parent_type`     | yes       | vertex type from the schema                           | e.g., `process`, `identity`, `host_config`, `deploy_run`. |
| `parent_class`    | yes       | classification (kebab-case, no `?` prefix)            | The stereotype of the proposed parent. Same anti-evaluation rules as `name`. |
| `parent_attrs?`   | optional  | `key=value;key=value`                                 | Only when the classification carries a non-trivial attribute (e.g., `kind=service-account`, `interactivity=non-interactive`). |
| `integrity_waived?` | optional | quoted string                                         | Rationale for bundling identity-of-use into the authorization contract's anchor verdict. Use on Shape A when one anchor closes both `is this allowed?` and `who actually did it?`. |
| `weight`          | yes       | literal `null`                                        | Always `null` on hypotheses you author. ANALYZE grades; you propose. |
| `status`          | yes       | literal `active`                                      | Always `active` for new hypotheses. The schema permits other values for cross-loop transitions but PREDICT only ever authors `active`. |

### Empty `parent_attrs?` and `integrity_waived?`

Render as empty cells (between `||` separators). The parser does not require `null` placeholders for empty optionals.

### Concerns

If the playbook's schema includes a `concerns?` cell on `:H` for this signature, render concerns as `;`-separated bare strings. PREDICT today does not use `concerns?` on `:H` (concerns are authored by ANALYZE on `:R consultations` and `:T resolutions` rows for the corresponding analyze surface), but the column slot is reserved.

### Hierarchical refinement IDs

When loop N graded hypothesis `h-001` `++` and the next question is a sub-mechanism distinction on the **same parent vertex** (subtype, schedule, mechanism-internal variant — but **not** actor-identity, orchestrator, configuration, or session-of-origin), shelve `h-001` and emit children as `h-001-1`, `h-001-2`, `h-001-3` with independent weights. Hierarchical refinement is for sub-mechanisms only.

When the next question introduces a **new vertex** upstream of the confirmed parent (`actor`, `orchestrator`, `session`, `configuration`, `policy`), use fresh `h-002`, `h-003`, ... — never `h-001-N`. The new vertex is not a child of the parent's grade; its weight is independent.

---

## §4 `:P h-{id}.<sub>` blocks

Five sub-block names, each scoped to one hypothesis declared in `:H hypotheses`:

- `:P h-{id}.preds`         — predictions on the proposed edge / parent / attached vertex.
- `:P h-{id}.attr_preds`    — attribute predictions on the proposed parent's stereotype.
- `:P h-{id}.refuts`        — refutation shapes citing one or more `p*`/`ap*` IDs.
- `:P h-{id}.authz`         — authorization contracts (Shape A only).
- `:P h-{id}.comparisons`   — comparison rows declaring selectors/dimensions for deviation-kind preds + refuts.

The parser rejects any sub-block referencing an undeclared hypothesis ID.

### `:P h-{id}.preds`

```
:P h-001.preds [id|subject|kind|from_story|claim]
```

| Column        | Required | Format                                                              |
|---|---|---|
| `id`          | yes      | `^p\d+$`                                                            |
| `subject`     | yes      | `proposed_edge` \| `proposed_parent` \| `attached_vertex`           |
| `kind`        | yes      | one of the §2 enum                                                  |
| `from_story`  | yes      | `^s\d+$` — must match a sentence ID present in the matching story  |
| `claim`       | yes      | quoted string, one observable per claim (no compound AND/OR)        |

### `:P h-{id}.attr_preds`

```
:P h-001.attr_preds [id|target|attribute|kind|claim]
```

| Column        | Required | Format                                                              |
|---|---|---|
| `id`          | yes      | `^ap\d+$`                                                           |
| `target`      | yes      | `proposed_parent` \| `attached_vertex` \| `proposed_edge`           |
| `attribute`   | yes      | field name (e.g., `cmdline`, `user_loginuid`, `parent_pname`, `tty`) |
| `kind`        | yes      | one of the §2 enum                                                  |
| `claim`       | yes      | quoted string, one assertion per claim                              |

Use when the parent's classification carries a non-trivial stereotype AND a peer hypothesis exists whose predictions diverge on those attributes. Single-hypothesis Shape A doesn't need attr_preds — the classification is a label, not a discriminator.

`:P attr_preds` rows never carry a `comparison` (attribute claims are field-shape claims, not population deviations). The parser rejects an attr_pred ID appearing in `:P h-{id}.comparisons` rows.

### `:P h-{id}.refuts`

```
:P h-001.refuts [id|refutes|kind|claim]
```

| Column     | Required | Format                                                            |
|---|---|---|
| `id`       | yes      | `^r\d+$`                                                          |
| `refutes`  | yes      | comma-separated `p*` / `ap*` IDs from the same hypothesis         |
| `kind`     | yes      | one of the §2 enum, **excluding `presence`** (parser rejects)     |
| `claim`    | yes      | quoted string, the refutation's observable shape                  |

The `kind=presence` rejection is **not** a stylistic preference — it's a structural anti-pattern. A refutation that fires on any signal at all (regardless of whether the signal matches the alert's shape) is a presence-test, which doesn't refute the hypothesis's mechanism, just the absence-of-anything case.

### `:P h-{id}.authz`

```
:P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
```

| Column         | Required | Format                                                                 |
|---|---|---|
| `id`           | yes      | `^ac\d+$` (no hyphen: `ac1`, not `ac-1`)                               |
| `edge_ref`     | yes      | `proposed` \| existing edge id (`e-NNN`)                               |
| `anchor_kind`  | yes      | anchor catalog name (e.g., `approved-monitoring-sources`, `deploy-pipeline-runs`, `change-management-tickets`) |
| `predicate`    | yes      | quoted string — natural-language "authorized iff …"                    |
| `on_unauth`    | yes      | `esc` \| `downgrade` \| `accept`                                       |
| `on_indet`     | yes      | `esc` \| `downgrade` \| `accept`                                       |

Required on Shape A (≥ 1 hypothesis carrying ≥ 1 authz row); absent on Shape E and Shape M.

### `:P h-{id}.comparisons`

```
:P h-001.comparisons [pred_ref|selector_kind|selector|dimension]
```

| Column         | Required | Format                                                          |
|---|---|---|
| `pred_ref`     | yes      | `p*` or `r*` ID from this hypothesis (not `ap*`)                |
| `selector_kind` | yes     | `historical-self` \| `peer-class` \| `population` \| `cross-rule` |
| `selector`     | yes      | quoted string — query / spec defining the comparison set       |
| `dimension`    | yes      | name of the attribute the foreground is being compared against |

Required iff at least one row in `:P h-{id}.preds` or `:P h-{id}.refuts` carries a deviation kind. Each pred/refut deviation row needs exactly one matching comparison row (matched by `pred_ref`).

The parser rejects:
- a deviation-kind row without a comparison row,
- a non-deviation-kind row with a comparison row,
- a comparison row referencing a non-existent pred_ref.

---

## §5 `:L lead_preds` + `:L lead_preds.comparisons`

Shape E only. Required if and only if Shape E.

### `:L lead_preds`

```
:L lead_preds [id|kind|if|read_as|advance_to]
```

| Column        | Required | Format                                                          |
|---|---|---|
| `id`          | yes      | `^lp\d+$`                                                       |
| `kind`        | yes      | one of the §2 enum                                              |
| `if`          | yes      | quoted string — observable condition                            |
| `read_as`     | yes      | interpretation token (kebab-case, no quotes needed)             |
| `advance_to`  | yes      | `escalate` \| `halt` \| `fork-at-<question>` \| `<lead-slug>`   |

Readings should be mutually exclusive and partition the lead's outcome space without gap. Common pattern: 3 readings (a baseline-match, a deviation, an escalation) or 4 readings (add an `absence`-kind reading for the empty-baseline case).

### `:L lead_preds.comparisons`

```
:L lead_preds.comparisons [pred_ref|selector_kind|selector|dimension]
```

Same column shape as `:P h-{id}.comparisons`. Required iff at least one `lp*` row carries a deviation kind.

### Interaction with `:R routing.scope_override`

Lead-pred selectors that reach beyond GATHER's default 1h window need the scope_override block (§6) on `:R routing` to extend the lookback. A `selector` like `"client.ip:<X> [past 24h]"` won't actually return 24h of data unless `routing.scope_override.window_hours: 24` is set.

---

## §6 `:R routing` + sub-blocks

Always required, regardless of shape. Three blocks total:

- `:R routing` (required) — flat key/value
- `:R routing.lead_hints` (optional) — `[lead|hint]` rows
- `:R routing.scope_override` (optional) — `[key|value]` rows

### `:R routing` flat block

Each row is `<key><whitespace><value>`. The parser accepts either a single space or aligned multi-space separation. Required keys:

| Key                    | Format                                            | Notes |
|---|---|---|
| `selected_lead`        | non-empty string (lead slug)                     | Required; non-empty. The single primary lead GATHER will dispatch. |
| `composite_secondary`  | comma-separated lead slugs, or `-` for none       | List of secondary leads for composite GATHER dispatch. |
| `override_data_source` | data-source slug, or `-` for none                 | Optional override; emit only with specific signal from a prior loop. |
| `rationale`            | quoted string                                     | One sentence explaining why this lead/composite/scope at this loop. |

The parser preserves required fields' validity via the existing `_extract_routing` helper (`selected_lead` non-empty, `composite_secondary` is a list of non-empty strings).

### `:R routing.lead_hints`

```
:R routing.lead_hints [lead|hint]
<lead-slug>|"<prose hint>"
```

`<lead-slug>` must match `selected_lead` or one of the entries in `composite_secondary` — the parser rejects keys that don't name a prescribed lead.

Each hint is one sentence of prose advising GATHER about *intent* — not query construction (that's GATHER's job). Example: `"walk ancestry above runc"`, `"cross-check session window"`. Composite leads can each carry their own hint.

### `:R routing.scope_override`

```
:R routing.scope_override [key|value]
window_hours|<positive int>
anchor|<alert|now>
```

`window_hours` must be a positive integer. `anchor` defaults to `alert` (window ends at alert @timestamp); `now` ends at wall-clock time (rare — used for "since last known-good baseline" patterns).

Use `scope_override` when the lead's semantics are *historical* (24h+ cadence baseline, 72h frequency check, 7d event horizon). The default GATHER window is 1h alert-anchored — anything beyond needs the override.

---

## §7 Story prose with sentence IDs

For each hypothesis declared on `:H hypotheses` (Shape A or M), emit a Markdown story block above (or co-located with) the hypothesis row:

```markdown
### story h-<id>
s1. <one sentence describing one mechanism beat>
s2. <next mechanism beat — what the parent does, how the edge gets formed>
s3. <optional — what the resolving anchor / lead would observe>
```

### Sentence ID format

Each sentence starts with `s\d+\.` followed by whitespace. The parser extracts sentence IDs via `^(s\d+)\.` regex per line. Predictions cite sentence IDs in their `from_story` cell — the parser rejects any `from_story_link` value that isn't in the matching story's sentence-ID set.

### Story content rules (prose discipline)

- 2–4 sentences. Less is a label; more is narrative.
- Each sentence describes one beat: what the parent does, how the edge forms, what observable signal would confirm it. Sentences should be referrable from predictions.
- Story starts at `proposed_edge.parent_vertex`, ends at `attached_to_vertex`. One hop. No earlier causes, no downstream consequences, no disposition claims.
- Baseline grounds predictions: when the observed vertex has prior history, name it in one sentence. When no baseline exists, say so.
- Predictions name deviations by role (`matches the recurring baseline geometry`), not by value (`lport is not 22`).

### Block boundaries

The parser closes a story block on:
- The next `:` block header.
- Another `### story h-{id}` heading (saves the previous story, opens a new one).
- A blank line followed by another `:` header (intermediate blank lines inside the story are tolerated).

### Shape E

No story prose block. Shape E doesn't declare hypotheses, so there's no `h-{id}` to attach a story to. The parser rejects unattached story blocks (`### story` headings without a matching hypothesis).

---

## §8 Field-presence matrix

The parser enforces this matrix at parse time before any other validation. Violations produce `Shape <X> requires/must ...` errors.

| Shape | `:H hypotheses`                                                                 | `:L lead_preds` | `:R routing` | story blocks                |
|---|---|---|---|---|
| **E** | absent                                                                          | required         | required      | absent                      |
| **A** | required (≥ 1, ≥ 1 hypothesis carrying ≥ 1 `:P h-{id}.authz`)                   | absent           | required      | one per declared hypothesis |
| **M** | required (≥ 2, hypotheses must diverge on observable fields)                    | absent           | required      | one per declared hypothesis |

Authz requirement on Shape A is enforced as: at least one row in any `:P h-{id}.authz` block. The parser does not require authz on every hypothesis, only that at least one hypothesis carries the contract (which is also the contract carrier per the integrity-bundling pattern).

---

## §9 Parser error catalogue

Every error string the parser can raise, organized by remediation. When the handler dispatches a retry, the error string lands verbatim in `remediation_notes`. Read it literally; the fix is usually obvious once mapped to the rule.

### Header / envelope

| Error                                                                             | Cause                                                                                   | Fix |
|---|---|---|
| `predict output is empty`                                                         | Stdout was 0 bytes.                                                                     | Emit the envelope. The handler usually triggers the M_last checkpoint-recovery path before surfacing this. |
| `predict output: bare \`\`\` with no body`                                          | Subagent emitted just an opening fence with no envelope.                                | Emit the envelope inside the fence, or drop the fence entirely. |
| `predict output missing header line \`predict loop=<int> shape=<E\|A\|M>\``        | First non-empty content line doesn't match the header regex.                            | Make the literal first content line `predict loop=<int> shape=<E\|A\|M>` — no quoting, no fences inside, no leading prose. |
| `predict.shape must be one of ['A', 'E', 'M']`                                    | Shape value not in the enum (probably typo or unsupported letter).                      | Fix the shape letter. |
| `predict.loop=<X> does not match orchestrator-computed loop_n=<Y>`                 | Header `loop=` value disagrees with the orchestrator's prompt.                          | Read the loop_n from the prompt's `loop_n=` line and emit it verbatim. |

### Block / row structure

| Error                                                                       | Cause                                                                          | Fix |
|---|---|---|
| `:<TAG> <name>: row has more cells than columns: ...`                        | Row has too many `|`-separated cells for the declared columns.                  | Count `|` separators in the row vs. the column header. Quote any cell content that contains a `|`. |
| `unknown :P block name: ...`                                                | `:P` block name doesn't match `h-{id}.{preds\|attr_preds\|refuts\|authz\|comparisons}`. | Rename the block. Common typo: `h-001.predictions` (long form) instead of `h-001.preds`. |
| `unknown :L block name: ...`                                                | `:L` block name isn't `lead_preds` or `lead_preds.comparisons`.                 | Use the right name; PREDICT has only those two `:L` blocks. |
| `unknown :R block name: ...`                                                | `:R` block name isn't `routing`, `routing.lead_hints`, or `routing.scope_override`. | Use the right name. |
| `:P <block>: hypothesis '<id>' not declared in :H hypotheses`               | Sub-block references a hypothesis ID not in `:H hypotheses`.                    | Either declare the hypothesis on `:H hypotheses`, or fix the sub-block's prefix to match a declared ID. |

### Field-presence matrix

| Error                                                                       | Cause                                                                | Fix |
|---|---|---|
| `predict.shape=E requires a branch_plan ...`                                | Shape E without a `:L lead_preds` block (or empty rows under it).    | Add the `:L lead_preds` block with ≥ 1 reading. |
| `predict.shape=E must have empty hypotheses ...`                            | Shape E with `:H hypotheses` rows.                                   | Drop the `:H` block (and any `:P h-{id}.*` sub-blocks) and re-author as Shape E. |
| `predict.shape=A requires at least one hypothesis`                          | Shape A with no `:H hypotheses` rows.                                | Add ≥ 1 hypothesis row + the matching `:P h-{id}.preds`/`.refuts`/`.authz` blocks. |
| `predict.shape=A must not emit a branch_plan ...`                           | Shape A with a `:L lead_preds` block.                                | Drop `:L lead_preds`. Shape A doesn't use lead-level readings. |
| `predict.shape=M requires at least two hypotheses`                          | Shape M with `:H hypotheses` count < 2.                              | Add a second hypothesis (and its sub-blocks + story prose), or downgrade to Shape A / E. |
| `predict.shape=M must not emit a branch_plan ...`                           | Shape M with a `:L lead_preds` block.                                | Drop `:L lead_preds`. Shape M's discriminators are predictions on competing hypotheses. |

### `kind` / comparison

| Error                                                                       | Cause                                                                 | Fix |
|---|---|---|
| `<id>: unknown kind '<value>'`                                              | `kind` cell value not in the §2 enum.                                 | Use one of: `geometry`, `cadence`, `novel-artifact`, `absence`, `presence`, `absolute`. |
| `<id>: kind='presence' is forbidden on refutations`                         | `:P h-{id}.refuts` row has `kind=presence`.                           | Rewrite with `kind=absolute` (if the refutation can name a specific field-value the alert telemetry already records) or `kind=absence` (grounded in a structurally-zero baseline). See §2 refutation kinds. |
| `<id>: kind='<deviation>' requires a comparison row in :P h-{id}.comparisons` | A pred or refut row has a deviation kind but no matching `:P h-{id}.comparisons` row. | Add a comparison row with `pred_ref` matching this row's `id`. The selector + dimension pin what population is being compared and on what attribute. |
| `<id>: kind='<non-deviation>' must not carry a comparison row`              | A pred or refut row has `kind=presence` or `kind=absolute` but a `:P h-{id}.comparisons` row references its `id`. | Drop the comparison row (or change the pred/refut's kind to a deviation kind if the comparison is genuinely needed). |
| `<id>: :P h-{id}.comparisons row references unknown pred_ref '<ref>'`        | A comparison row's `pred_ref` doesn't match any `p*`/`r*` ID on the same hypothesis. | Fix the `pred_ref` to match a row's `id`. Note: `pred_ref` cannot reference `ap*` (attribute predictions never carry comparisons). |
| `attribute_predictions must not carry comparison`                           | An `ap*` ID appears as `pred_ref` in a comparisons row.               | Drop the offending comparisons row. Attribute claims are field-shape claims, not population deviations. |

### Story prose / sentence-ID

| Error                                                                       | Cause                                                                 | Fix |
|---|---|---|
| `<hid>: missing story prose block (\`### story <hid>\` heading + \`s1.\`/\`s2.\` lines)` | A hypothesis was declared on `:H hypotheses` but no `### story h-<id>` block exists. | Add the story block above (or co-located with) the `:H` row. 2–4 sentences, each with a sentence ID. |
| `<hid>.<pid>: from_story_link='<value>' not in story sentence IDs [...]`     | A prediction's `from_story` cell references a sentence ID that doesn't exist in the matching story. | Either fix the `from_story` value to match an existing sentence ID, or add the missing sentence to the story. |

### Routing

| Error                                                                       | Cause                                                                 | Fix |
|---|---|---|
| `:R routing bad row: <line>`                                                | A row in `:R routing` doesn't match `<key><whitespace><value>`.       | Reformat the row. Key + whitespace + value (multi-space alignment is fine). |
| `predict.routing.selected_lead must be a non-empty string`                   | `selected_lead` cell is empty.                                       | Provide a lead slug. PREDICT always selects a lead (no halt path). |
| `predict.routing.lead_hints[<name>] does not name a prescribed lead`         | A `lead_hints` row's `lead` cell isn't in `selected_lead ∪ composite_secondary`. | Either drop the hint, or add the lead to `composite_secondary`. |
| `predict.routing.scope_override.window_hours must be a positive integer`     | `window_hours` value is zero, negative, non-integer, or boolean.      | Use a positive integer. |
| `predict.routing.scope_override.anchor must be one of ['alert', 'now']`      | `anchor` value isn't `alert` or `now`.                                | Use one of the two. |

### Other

| Error                                                                       | Cause                                                                 | Fix |
|---|---|---|
| `:H hypotheses: row missing id: ...`                                         | A `:H hypotheses` row has an empty `id` cell.                         | Add the hypothesis ID. |
| `:R routing.scope_override: unknown key '<key>'`                            | `scope_override` block has a key other than `window_hours` or `anchor`. | Drop the unknown key. The block accepts only those two keys. |

---

## §10 Checkpoint contract

Write `{run_dir}/subagent_checkpoints/predict-loop-{loop_n}.yaml` **before** your final stdout turn. The checkpoint is a YAML wrapper carrying the dense envelope as a multi-line scalar string:

```yaml
status: complete
predict: |
  predict loop=2 shape=A

  ### story h-001
  s1. ...

  :H hypotheses [...]
  ...

  :R routing
  ...
```

The leading `|` makes YAML preserve the dense form verbatim — no trailing-whitespace stripping, no quote escapes. The handler reads `data["predict"]` as a string and runs it through the same dense parser as stdout.

### Why YAML wrapper

Two reasons:

1. The handler needs to distinguish a *complete* checkpoint (subagent finished its work, emitted the envelope, then ran out of turns) from an *incomplete* one (subagent crashed mid-emission). The `status: complete` marker carries that signal. A pure-dense checkpoint would have no place to put the marker.
2. Forwards-compatibility: future fields on the checkpoint envelope (telemetry, partial-run metadata, model-emitted hints to the handler) live in the YAML wrapper without changing the dense grammar.

### When the recovery path fires

`claude --print` drops any tool_use that follows the last text turn. If the subagent's last action is `Write(checkpoint)` instead of a text response, stdout will be empty. The handler treats that as the M_last pathology, reads the checkpoint, parses the embedded dense scalar, and proceeds as if the subagent had emitted to stdout.

To avoid the recovery path entirely: write the checkpoint, then emit the dense envelope to stdout as your final turn. Checkpoint-after-stdout is also fine; checkpoint-after-text + stdout works; the only failure shape is checkpoint-as-last-tool-use with no subsequent text.

---

## §11 Handler post-parse contract

After the parser accepts your envelope, the handler:

1. **Extracts buckets**: `invlang_delta` (hypotheses + branch_plan), `routing`, `telemetry`. None of routing leaks into invlang state.
2. **Composes the invlang `hypothesize:` block** (when your envelope carries hypotheses) and appends it to `{run_dir}/investigation.md` under a `## PREDICT (loop N)` header.
3. **Validates** the proposed companion via `validate_companion_proposed` — this is the invlang validator that catches schema-level errors (duplicate IDs, unknown vertex/edge refs, refutation citing a non-existent prediction, etc.) the dense parser doesn't enforce.
4. **On validator rejection**: handler retries with `resume_from_checkpoint=true` and the validator's error list as `remediation_notes`. The dense parser's structural acceptance does not guarantee invlang validity — schema errors land here.
5. **On accept**: handler routes to GATHER (via `next_phase`), passes `routing` (selected_lead, composite_secondary, lead_hints, scope_override) and (Shape E only) `branch_plan_predictions` to GATHER's payload.

### What you don't author

- The invlang YAML composition. The handler builds `hypothesize.hypotheses[]` from the `:H` rows + `:P` sub-blocks + story prose, with the story rendered as the YAML `story:` field.
- The `## PREDICT (loop N)` header. Handler emits it.
- Any write to `investigation.md`. Handler owns it. You only write the checkpoint.
- The fast-path return (when the orchestrator's predict_fastpath cache hits, the handler returns directly without dispatching the subagent at all).

### What you do author

- The dense envelope on stdout (the deliverable).
- The YAML-wrapped checkpoint (the backup the handler reads when stdout is empty).
- That's it.

If inputs are malformed or investigation state is incomprehensible, emit a minimal Shape E envelope with a single `:L lead_preds` reading whose `advance_to=escalate` — explain the blocker in the `read_as` token. Do not invent free-form blocks; the parser rejects unknown block tags.
