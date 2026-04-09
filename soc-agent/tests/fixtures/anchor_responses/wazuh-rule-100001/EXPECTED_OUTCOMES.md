# Worker Validation Matrix — wazuh-rule-100001

For each synthetic alert in `tests/fixtures/alerts/wazuh-rule-100001/`,
this document records:

- Which archetype the agent should recognize
- Which anchors it should consult and what they return (in
  `anchor_responses/wazuh-rule-100001/`)
- Which mock SIEM response set to use (in `siem_responses/`)
- The expected report frontmatter shape

These are the cases worker validation runs against to confirm the
archetype-shape playbook discriminates correctly.

---

## operator-debug-confirmed

**Alert fixture:** `alerts/wazuh-rule-100001/operator-debug-confirmed.json`
**SIEM fixture:** `siem_responses/wazuh-100001-operator-debug.json`
**Anchor fixture:** `anchor_responses/wazuh-rule-100001/operator-debug-confirmed.json`

**Story:** alice opens an interactive shell in `payment-api-canary` via
containerd-shim. Cmdline is bare `bash`. No co-firing. The image has a
sporadic history of operator-style exec events.

**Expected matched archetype:** `operator-runtime-debug`

**Expected anchor consultations:**
- `oncall-schedule` → `confirmed` (alice on-call for prod-payment)
- `change-windows` → `confirmed` (CHG-2026-1234 covers payment-api at this time)

**Expected report frontmatter shape:**
```yaml
status: resolved
disposition: benign
matched_archetype: operator-runtime-debug
trust_anchors_consulted:
  - anchor: oncall-schedule
    kind: org-authority
    result: confirmed
    citation: <non-empty>
  - anchor: change-windows
    kind: org-authority
    result: confirmed
    citation: <non-empty>
```

---

## post-exploit

**Alert fixture:** `alerts/wazuh-rule-100001/post-exploit.json`
**SIEM fixture:** `siem_responses/wazuh-100001-post-exploit.json`
**Anchor fixture:** `anchor_responses/wazuh-rule-100001/post-exploit.json`

**Story:** A Node.js process spawns `sh -i` in `checkout-frontend`. No
prior shell events for this image (47 days deployed, zero baseline).
No co-firing.

**Expected matched archetype:** `post-exploit-interactive`

**Expected anchor consultations:** none. This archetype declares
`required_anchors: []` — there is no organizational source of truth
that confirms "the application was supposed to spawn this shell."
Escalation is the only correct outcome.

**Expected report frontmatter shape:**
```yaml
status: escalated
disposition: true_positive  # or inconclusive — both acceptable
matched_archetype: post-exploit-interactive
trust_anchors_consulted: []
```

The report verdict must explain that no benign archetype could match
(no baseline for this image), and that no anchor exists for this
archetype.

---

## composition-co-firing

**Alert fixture:** `alerts/wazuh-rule-100001/composition-co-firing.json`
**SIEM fixture:** `siem_responses/wazuh-100001-composition.json`
**Anchor fixture:** `anchor_responses/wazuh-rule-100001/composition-co-firing.json`

**Story:** An ImageMagick wrapper spawns `sh -c 'gs ...'` in the
image-processor container. This image has 847 prior events of this
exact pattern over 54 days — a clearly established baseline. **However,**
rule 100007 (drop-and-exec of `/tmp/.x1`) co-fired from the same
container 3 seconds later.

**Expected behavior:** The agent should recognize that the primary
archetype match is `app-spawned-shell` (baseline confirms), but the
playbook's composition rule escalates whenever 100002/100006/100007/
100008 co-fire from the same container window — regardless of the
benign archetype match. **Anchor confirmation does not override
co-firing.**

**Expected matched archetype:** either `app-spawned-shell` or
`post-exploit-interactive` is acceptable. The verdict text matters more
than which archetype is named.

**Expected anchor consultations:**
- `image-baseline` → `confirmed` (847 events, telemetry-baseline kind)

**Expected report frontmatter shape:**
```yaml
status: escalated
disposition: true_positive
matched_archetype: app-spawned-shell  # or post-exploit-interactive
trust_anchors_consulted:
  - anchor: image-baseline
    kind: telemetry-baseline
    result: confirmed
    citation: <non-empty>
```

The verdict body must **explicitly cite the 100007 co-firing as the
escalation reason** — the report cannot resolve as benign just because
the baseline confirmed. This is the test of whether the composition
rule is load-bearing.
