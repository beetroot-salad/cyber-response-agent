## Shape M — worked examples

You've already decided Shape M: two+ mechanisms, divergent on already-observable fields, no authorization contract because authorization isn't the open question. The craft questions are **story-driven prediction** (each story sentence licenses one prediction; predictions diverge where the stories diverge), and **discriminator selection** (the lead has to read the field where the stories actually disagree).

The pattern: write each parent's behavior as a concrete causal story, then derive predictions by asking *"what would I see if this story is true?"* — for each hypothesis. Predictions on h-001 and h-002 should be near-mirrors on the same observable, opposite verdicts. The lead measures that observable directly.

The dense form for Shape M is ≥ 2 `:H` rows (no `authz?` cell — Shape M is contract-free), ≥ 2 sets of per-hypothesis sub-blocks `:P h-{id}.preds` / `.refuts` / `.comparisons`, ≥ 2 `### story h-{id}` prose blocks, and the always-required `:R routing` block. No `:L lead_preds`, no `:P h-{id}.authz`.

### Example 1 — DNS NXDOMAIN burst from one client

**Alert:** the recursive resolver logged 3,184 NXDOMAIN responses for client `client-X` in the last 5 minutes (baseline ≈ 40). Prologue carries `v-client-X` and an `emitted_dns_queries` edge with the burst attached. Loop 1 ran process-dns-attribution and returned per-process NX counts and a per-process qname-entropy distribution.

**Story-to-prediction derivation.** Two competing parents:

*h-001 ?misconfigured-resolver-path.* Story: "A resolver-path or search-domain misconfiguration on `client-X` is rewriting otherwise-valid lookups into an unresolvable suffix, so most processes that resolve names hit the same broken path."
- Sentence 1: *"most processes hit the same broken path"* → if true, NX share is **spread across processes**, no single one dominates. → `p1` says burst geometry matches a recurring multi-process baseline.
- Sentence 2: *"otherwise-valid lookups"* → the underlying qnames are the host's normal traffic, just rewritten. The qname-entropy *distribution* should still resemble baseline. → `p2` says burst qname-entropy matches the client's baseline.

*h-002 ?single-process-algorithmic-qnames.* Story: "One process on `client-X` is generating qnames at a rate and shape inconsistent with the client's recurring DNS traffic — high concentration in one process, qname-entropy distribution shifted versus baseline. The mechanism is algorithmic name generation (a tool, library, or beaconing agent), regardless of intent."
- Sentence 1: *"high concentration in one process"* → mirror predicate on h-001.p1 — burst geometry deviates from the multi-process baseline.
- Sentence 2: *"qname-entropy distribution shifted versus baseline"* → mirror predicate on h-001.p2 — burst entropy deviates from baseline.

The two p1 claims are mirror predictions on per-process share geometry; the two p2 claims are mirror predictions on entropy-distribution-vs-baseline. Both pairs share the same `selector` + `dimension` in their `:P h-{id}.comparisons` rows — that's the structural payoff: GATHER fetches one paired-window envelope (alert window + comparison set per dimension), ANALYZE grades all four predictions in one trip.

```
predict loop=2 shape=M

### story h-001
s1. A resolver-path or search-domain misconfiguration on `client-X` is rewriting otherwise-valid lookups, so most processes hit the same broken path.
s2. The underlying qnames are the host's normal traffic, just rewritten — qname entropy distribution should still resemble the client's recurring baseline.

### story h-002
s1. One process on `client-X` is generating qnames at a rate and shape inconsistent with the client's recurring DNS traffic — high concentration in one process.
s2. The qname-entropy distribution shifts materially higher than baseline because the mechanism is algorithmic name generation (a tool, library, or beaconing agent).

:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
h-001|?misconfigured-resolver-path|v-client-X|emitted_dns_queries|host_config|resolver-config-on-client|||null|active
h-002|?single-process-algorithmic-qnames|v-client-X|emitted_dns_queries|process|dns-emitting-process-on-client|||null|active

:P h-001.preds [id|subject|kind|from_story|claim]
p1|proposed_edge|geometry|s1|"burst-window per-process NX-query share is uniform across processes; matches the recurring multi-process baseline geometry"
p2|proposed_edge|geometry|s2|"burst-window qname-entropy distribution matches the client's recurring baseline distribution"

:P h-001.refuts [id|refutes|kind|claim]
r1|p1|geometry|"burst-window per-process share concentrates in one process; deviates from the recurring multi-process baseline geometry"
r2|p2|geometry|"burst-window qname-entropy distribution shifts materially higher than the recurring baseline distribution"

:P h-001.comparisons [pred_ref|selector_kind|selector|dimension]
p1|historical-self|"client.ip:<client-X> AND query.response_code:NXDOMAIN [past 24h]"|per_process_query_share_distribution
r1|historical-self|"client.ip:<client-X> AND query.response_code:NXDOMAIN [past 24h]"|per_process_query_share_distribution
p2|historical-self|"client.ip:<client-X> [past 24h]"|qname_shannon_entropy_distribution
r2|historical-self|"client.ip:<client-X> [past 24h]"|qname_shannon_entropy_distribution

:P h-002.preds [id|subject|kind|from_story|claim]
p1|proposed_edge|geometry|s1|"burst-window per-process NX-query share concentrates in one process; deviates from the recurring multi-process baseline geometry"
p2|proposed_edge|geometry|s2|"burst-window qname-entropy distribution shifts materially higher than the recurring baseline distribution"

:P h-002.refuts [id|refutes|kind|claim]
r1|p1|geometry|"burst-window per-process share is uniform across processes; matches the recurring multi-process baseline geometry"
r2|p2|geometry|"burst-window qname-entropy distribution matches the client's recurring baseline distribution"

:P h-002.comparisons [pred_ref|selector_kind|selector|dimension]
p1|historical-self|"client.ip:<client-X> AND query.response_code:NXDOMAIN [past 24h]"|per_process_query_share_distribution
r1|historical-self|"client.ip:<client-X> AND query.response_code:NXDOMAIN [past 24h]"|per_process_query_share_distribution
p2|historical-self|"client.ip:<client-X> [past 24h]"|qname_shannon_entropy_distribution
r2|historical-self|"client.ip:<client-X> [past 24h]"|qname_shannon_entropy_distribution

:R routing
selected_lead         dns-process-concentration
composite_secondary   dns-qname-entropy-baseline
override_data_source  -
rationale             "composite measures both axes — per-process share and qname-entropy — against the same client's 24h baseline; mirror comparisons on h-001/h-002 let ANALYZE grade all four predictions on one paired-window observation"

:R routing.scope_override [key|value]
window_hours|24
anchor|alert
```

**Pitfalls:**
- Don't write `p1` as `"single process dominates AND entropy is high"` — compound. Splitting into p1 (concentration) and p2 (entropy deviation) lets the lead pivot on either axis if the other is indeterminate.
- Don't pin specific qname-entropy thresholds in `p2` — name the deviation by role against the client's baseline; the entropy lead returns the concrete distribution.
- **Mirror predictions must share `selector_kind` + `selector` + `dimension`.** Only the predicted direction differs (matches vs. deviates). Diverging selectors makes the predictions non-comparable.

---

### Example 2 — SMB session burst from a workstation to many internal hosts

**Alert:** network sensor reports `workstation-W` opened SMB sessions to 47 distinct internal hosts in the last 10 minutes (baseline ≈ 2 distinct hosts/10min for this workstation). Prologue carries `v-workstation-W`, the set of target hosts, and an `opened_smb_sessions` edge with the burst attached. Loop 1 ran process-attribution and target-set characterization, returning per-process session counts plus the target set's relationship to the workstation's prior SMB destinations.

**Story-to-prediction derivation.** Two competing parents:

*h-001 ?backup-tool-fanout.* Story: "A backup or sync tool on `workstation-W` is iterating through a configured target list (file shares, user-home backup mounts, or a NAS roster) and opening SMB sessions in sequence. The target set should be a stable subset that the workstation has touched before; one process accounts for the bulk of sessions."

*h-002 ?lateral-discovery-scan.* Story: "An interactive process (or a recently-launched short-lived binary) on `workstation-W` is sweeping the local subnet for SMB-reachable hosts. Targets are being enumerated rather than retrieved from a configured list; many hits will be hosts the workstation has never touched, and session shape will skew toward connect-and-close rather than sustained transfer."

Note the predictions diverge on **two different observables**: target-overlap (p1 in both hypotheses, mirror) and per-session byte-volume distribution (p2 in both hypotheses, mirror). That's fine — what matters is that each hypothesis's predictions are observable and the lead reads both axes.

```
predict loop=2 shape=M

### story h-001
s1. A backup or sync tool on `workstation-W` is iterating through a configured target list (file shares, user-home backup mounts, or a NAS roster) and opening SMB sessions in sequence.
s2. The target set should be a stable subset that the workstation has touched before; per-session byte volume matches the workstation's recurring SMB session-volume baseline.

### story h-002
s1. An interactive process (or a recently-launched short-lived binary) on `workstation-W` is sweeping the local subnet for SMB-reachable hosts; targets are being enumerated rather than retrieved from a configured list.
s2. Session shape skews toward connect-and-close rather than sustained transfer; per-session byte-volume distribution falls materially below the workstation's recurring baseline.

:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
h-001|?backup-tool-fanout|v-workstation-W|opened_smb_sessions|process|backup-or-sync-process-on-workstation|||null|active
h-002|?lateral-discovery-scan|v-workstation-W|opened_smb_sessions|process|discovery-scan-process-on-workstation|||null|active

:P h-001.preds [id|subject|kind|from_story|claim]
p1|proposed_edge|geometry|s1|"the burst's target set substantially overlaps the workstation's 30d SMB-target history"
p2|proposed_edge|geometry|s2|"the burst's per-session byte-volume distribution matches the workstation's recurring SMB session-volume baseline"

:P h-001.refuts [id|refutes|kind|claim]
r1|p1|geometry|"the burst's target set has minimal overlap with the workstation's 30d SMB-target history"
r2|p2|geometry|"the burst's per-session byte-volume distribution falls materially below the workstation's recurring SMB session-volume baseline"

:P h-001.comparisons [pred_ref|selector_kind|selector|dimension]
p1|historical-self|"src.host:<workstation-W> AND protocol:smb [past 30d]"|target_host_set
r1|historical-self|"src.host:<workstation-W> AND protocol:smb [past 30d]"|target_host_set
p2|historical-self|"src.host:<workstation-W> AND protocol:smb [past 30d]"|per_session_byte_volume_distribution
r2|historical-self|"src.host:<workstation-W> AND protocol:smb [past 30d]"|per_session_byte_volume_distribution

:P h-002.preds [id|subject|kind|from_story|claim]
p1|proposed_edge|geometry|s1|"the burst's target set has minimal overlap with the workstation's 30d SMB-target history"
p2|proposed_edge|geometry|s2|"the burst's per-session byte-volume distribution falls materially below the workstation's recurring SMB session-volume baseline"

:P h-002.refuts [id|refutes|kind|claim]
r1|p1|geometry|"the burst's target set substantially overlaps the workstation's 30d SMB-target history"
r2|p2|geometry|"the burst's per-session byte-volume distribution matches the workstation's recurring SMB session-volume baseline"

:P h-002.comparisons [pred_ref|selector_kind|selector|dimension]
p1|historical-self|"src.host:<workstation-W> AND protocol:smb [past 30d]"|target_host_set
r1|historical-self|"src.host:<workstation-W> AND protocol:smb [past 30d]"|target_host_set
p2|historical-self|"src.host:<workstation-W> AND protocol:smb [past 30d]"|per_session_byte_volume_distribution
r2|historical-self|"src.host:<workstation-W> AND protocol:smb [past 30d]"|per_session_byte_volume_distribution

:R routing
selected_lead         smb-target-overlap-and-session-shape
composite_secondary   smb-target-history-baseline
override_data_source  -
rationale             "two-axis discriminator: target-set overlap with 30d history (configured-list vs enumeration) and per-session byte-volume distribution (sustained transfer vs connect-and-close); both axes share the same historical-self selector"

:R routing.scope_override [key|value]
window_hours|720
anchor|alert
```

**Pitfalls:**
- Don't write either story as just *"backup tool"* / *"scan"* — those are labels, not stories. The story has to name *what the parent does* in causal terms (iterates a list / sweeps a subnet) so that predictions derive from concrete behavior.
- Don't let the two p1 claims overlap (e.g. h-001 says "≥ 80% overlap", h-002 says "≤ 50% overlap" — leaving 50–80% in no-man's-land). Use the deviation vocabulary (`substantially overlaps` / `minimal overlap`) and let the lead's distribution settle the threshold.
- Don't pin specific byte-volume thresholds — name the deviation by role against the workstation's baseline; the lead returns the distribution.

---

### Anti-patterns specific to Shape M

- ❌ **Mirror predictions on different `dimension` values** — mirrors must share `selector_kind` + `selector` + `dimension`; only the predicted direction differs. Different dimensions means you have *four* predictions, not two mirrored pairs.
- ❌ **Compound dimension names** (`destination_geometry_AND_volume_per_5min`) — split into two `comparison` rows under the matching prediction's hypothesis comparisons block.
- ❌ **`:P h-{id}.authz` rows on Shape M hypotheses** — Shape M is contract-free; if you find yourself reaching for an authorization contract, the open question is actually authorization and you should be on Shape A.
- ❌ **One hypothesis** — Shape M requires ≥ 2 hypotheses by definition. If only one mechanism is plausible, you're on Shape A (with a contract) or Shape E (single non-branching lead).
- ❌ **Hypotheses whose predictions are subsets of one another** — that's the invoker-identity anti-pattern (rule #32). Predictions on h-001 and h-002 must diverge on observable fields; if removing them collapses the two hypotheses into one, it's a Shape A authorization fork.
