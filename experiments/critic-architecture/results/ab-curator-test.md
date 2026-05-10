# A/B curator test — defender+critic vs single-agent self-review

**Question:** Does separating defender + critic produce better cross-fixture directives than a single agent reviewing its own work, when both feed the same curator with the same ≤250-token addendum budget?

**Spend:** $1.60 across 13 Sonnet calls. Wall-clock ~4 min (parallel).

## Per-arm curated addendum library (verbatim)

### Arm A (defender + critic + curator)

1. When surface legitimacy is strong (known credential, internal source, recent explanatory ticket), treat the ticket itself as the top falsification target: check creation timestamp vs. anomalous action, whether content is predictive rather than post-hoc, and whether a second party can independently confirm the work order.
2. For credentialed-write alert classes, actor standing satisfies "who," not "what": sequence (1) actor standing, (2) diff the changed artifact against pre-change state, (3) confirm the delta matches the stated purpose. Cover narratives are designed to pass step 1 and collapse at step 2.
3. Before treating a third-party "no anomaly" confirmation as ruling out a cause class, establish what their instrumentation covers and what vocabulary they used — a physical-layer confirmation does not attest to control-plane or application-layer quiescence.
4. When a verdict rests on benign-cause elimination rather than direct artifact observation, flag each elimination step for source visibility: absence of signal on closed-firmware or vendor-emitted telemetry bounds observability, not causation.
5. In split-artifact workflows (plan/apply, build/deploy, sign/release), the handoff between reviewed output and the executing artifact is the attack surface: verify whether the executing step re-derives from source or consumes a stored artifact, and confirm hash verification spans upload-to-download.

### Arm B (single-agent self-review + curator)

1. For closed-firmware network device alerts, consult the vendor support KB before constructing an adversarial hypothesis tree; absence of a published CVE is weak evidence, not exculpatory — firmware-stability defects are systematically under-indexed in public advisories.
2. When a network device shows co-occurring protocol-layer and control-plane anomalies, require a single causal explanation before splitting into independent branches; also obtain the upstream operator's peer-side teardown reason codes — "no link flap" and "no self-originated session reset" are different claims.
3. On credentialed-action alerts from automation or CI/CD roles, attack the plan-to-reality gap: enumerate every executed action in the role session and diff against the approved artifact. Principal legitimacy (OIDC chain, PR approvals) establishes *who* ran, not *what* ran; audit change content (trust relationships, wildcard grants) independent of volume.
4. When a recent legitimate-looking ticket creates surface cover for an anomalous access event, verify that the ticket's source IP, timing, and privilege footprint share coherent session lineage with the alert — ticket edit provenance is the highest-yield lead, not the access event itself.
5. For key-authenticated access alerts, complement credential fingerprint matching with agent-forwarding detection on intermediate hosts; an attacker forwarding a live agent produces an identical fingerprint without key extraction.

## Held-out test results

| Fixture | Ground truth | Arm A verdict | Arm B verdict | Δ |
|---|---|---|---|---|
| 03 novel-outbound-dns | malicious (supply chain) | **malicious** | **malicious** | tie |
| 09 printer-SMB | escalate-target | **escalate** | **escalate** | tie |

**Disposition correctness: 2/2 for both arms. Identical outcome.**

## Behavioral shaping comparison

| Dimension | Arm A | Arm B |
|---|---|---|
| Hypotheses on fixture 03 | 5 (incl. `?adversary-controlled-dependency-injection`, `?build-time-secret-exfil`, `?legitimate-telemetry-misconfigured`, `?rogue-developer-side-project`) | 5 (incl. `?adversary-controlled-npm-account`, `?transitive-dependency-beacon`, `?compromised-build-runner`) |
| Hypotheses on fixture 09 | 6 (incl. `?firmware-behavior-change`, `?kerberos-ticket-relay`, `?C2-beacon-via-MFP`, `?domain-policy-push`) | 5 (incl. `?firmware-implant`, `?kerberos-ticket-theft`, `?network-scanner / asset discovery`) |
| Load-bearing assumption named | Both: "process X is the actual source of behavior Y" — correctly identified |
| Addendum cited in reasoning | A: rules 5 + 2 (split-artifact + actor-vs-content) on F03; rules 3 + 4 (closed-firmware visibility) on F09 | B: rule 3 (CI plan-to-reality gap) on F03; rules 1 + 2 (vendor KB / co-occurring causes) on F09 |
| Tokens (test calls) | F03 1709 / F09 2202 | F03 1925 / F09 1916 |
| Cost (test calls combined) | $0.21 | $0.21 |

## Library quality comparison

**Arm A is more abstracted.** Five rules, none mention a specific tool, vendor, protocol, or alert class beyond the meta-pattern (split-artifact, third-party confirmation, benign-cause elimination, credentialed-write). Rules 1–5 are all framed as "when X-shape, prioritize Y over Z."

**Arm B is more concrete.** Rules 1–2 are network-device-specific ("vendor KB", "BGP teardown reason codes"). Rule 5 is SSH-specific ("agent-forwarding"). Rules 3–4 are abstracted (CI/CD, ticket-cover) at parity with Arm A. Mixed levels of abstraction.

The Arm A directive that fired on fixture 03 (rule 5: split-artifact handoff is the attack surface) cleanly generalized from terraform-plan/apply to npm-publish/exec — a transfer the v10 finding flagged as the central failure mode of un-curated directives. Arm B's rule 3 also fired on fixture 03 ("attack the plan-to-reality gap") and shaped a structurally similar tarball-inspection lead. **Both arms produced curator outputs abstract enough to transfer at least once.**

The Arm B specific-tool rule (#5 — SSH agent-forwarding) is the v10 finding's known anti-pattern: it would help if the test fixture were SSH-shaped, but neither test fixture is, so that rule lay dormant. Arm A has no analogous dead-on-arrival rule in this test set — but with only 2 test fixtures, this could be sampling.

## Headline

**On 2/2 held-out fixtures, both arms reached the correct disposition. Library quality differs in shape but not measurably in outcome.**

- Arm A library is more uniformly meta-patterned; Arm B mixes meta-patterns with one fixture-specific rule.
- Both libraries shaped behavior with cited addendum rules (no rubber-stamp citations on either side).
- Cost per test call is identical ($0.10–0.11).
- Hypothesis count and load-bearing assumption identification are statistically indistinguishable at N=2.

**Margin between arms: zero on disposition, marginal on library shape (favoring A's uniform abstraction). Sampling variance in this experiment is approximately 1 fixture's worth, which equals or exceeds any measured Arm-A advantage.**

## Honest caveats

- **N=2 test fixtures.** A 0.5-fixture margin would be invisible.
- **Bundled-evidence (no tool harness).** The test does not exercise the tool-selection mechanism that v9 identified as the architecture's measurable win condition. Arms compete on hypothesis enumeration only.
- **Single trial per cell.** No variance estimate within arm.
- **Curator prompt is identical and demanding** ("phrase as meta-patterns over investigation classes"). It does heavy lifting on Arm B's raw directives that originally bundled domain-specific tool names. Arm B's curator output is *because of* the curator, not in spite of the single-agent-derived inputs. This means the curator may be doing more of the abstraction work than the defender/critic separation.
- **Arm B's single agent already does counter-anchoring as a self-review step** (the prompt explicitly asks for it). This narrows the gap with Arm A's two-role separation by design.

## Decision input

The data does not show a significant Arm A advantage on the question that motivated the test. The defender/critic separation may produce a marginally cleaner library shape (uniform abstraction level), but this signal is within sampling noise at N=2.

**The curator step is doing more measurable work than the defender/critic split.** Both arms' raw directives contained fixture-specific noise; the curator successfully abstracted both, but Arm A's raw inputs were already closer to meta-pattern level (the critic role naturally produces more abstracted directives — likely because critics aren't anchored to the defender's specific narrative).

If the user has to choose, the cheap-and-defensible option is **single-agent self-review + curator** (Arm B): same outcome at slightly lower architectural cost (one Sonnet call per investigation instead of two for the directive-emission step). The defender/critic separation's distinguishing claim — that critic-side directives generalize better — is plausible from inspection but unsupported by the disposition outcomes here.
