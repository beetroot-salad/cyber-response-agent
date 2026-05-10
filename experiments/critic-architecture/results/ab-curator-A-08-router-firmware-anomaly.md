# Arm A training: 08-router-firmware-anomaly

### Defender

- cost: $0.1026
- tokens: in=2 out=1873 cache_read=11896 cache_create=18645

```
### TRIAGE

**Claim:** The border router is under active control-plane attack — most likely crafted BGP UPDATE or packet-flood exploitation targeting the control-plane CPU.

- ISP NOC confirms zero upstream link flaps during all three reset windows. This eliminates the dominant benign cause of BGP session resets (physical/upstream instability).
- The vendor documents control-plane CPU spikes only on config commit or full BGP table reconvergence. Neither occurred. A 78% spike co-located within seconds of the first reset falls entirely outside vendor-documented normal triggers — this is unexplained behavior by the vendor's own model.
- Three resets in one day against a 30-day baseline of one is a 90× rate increase. Hardware degradation producing this step-change without any accompanying syslog fault events is implausible.
- The environment has no firmware attestation, no host agent, and syslog that reflects only what vendor code chooses to emit — the absence of anomaly in syslog does not exonerate the device; it bounds our visibility.

**Disposition:** `malicious`

**Load-bearing assumption:** The vendor's documented CPU-spike trigger conditions (config commit, full reconvergence) are exhaustive for normal operation — i.e., no undisclosed firmware bug produces this spike pattern under quiescent traffic. If an undocumented firmware defect explains the co-occurrence, the call softens to `escalate`.

---

### DIRECTIVE-TO-CRITIC

When an investigation reaches a `malicious` verdict primarily through **elimination of benign explanations** rather than through direct observation of attack artifacts, prioritize stress-testing the completeness of the elimination logic. Specifically: were all plausible benign causes enumerated, and did each elimination step draw on a source with sufficient visibility to make the ruling authoritative? On closed-firmware network devices, vendor syslog is not an integrity-attested record — it surfaces what the vendor code chooses to surface. An investigation that treats "nothing unusual in syslog" as a negative finding conflates limited observability with negative evidence. Flag this conflation wherever the verdict depends on it.
```
### Critic

- cost: $0.1088
- tokens: in=2 out=2081 cache_read=11896 cache_create=19292

```
### VERDICT

**CRITIQUE**

Assumption attacked: *"ISP confirms no upstream link flaps in their NOC log during the alert windows"* — treated as eliminating upstream-driven BGP instability.

**Mechanism:** NOC operational vocabulary distinguishes "link flap" (physical interface state change) from BGP prefix churn (UPDATE floods, MED oscillations, prefix withdrawals from other ISP customers). A sustained BGP UPDATE storm originating elsewhere in the ISP's AS would not appear in NOC link-flap records but would drive rtr-edge-01's control-plane CPU into sustained high-utilization processing received UPDATEs — causing hold-timer expiry and session reset. This is a form of BGP reconvergence, but its trigger is upstream UPDATE volume, not local config commit. The defender's elimination of "upstream instability" was only as precise as the ISP's confirmation, which covered link state, not prefix dynamics.

**Observable consequence:** Public BGP route collectors (RouteViews, RIPE RIS) archive MRT UPDATE dumps with per-minute granularity for most tier-1/tier-2 ISP ASNs. If upstream-isp-1's ASN exported elevated UPDATE volume or prefix-withdrawal bursts at 02:14, 04:31, and 06:08 Tuesday, that signal is present in archived MRT data — testable without device access.

**Lead:** Pull RouteViews/RIPE RIS MRT dumps for the upstream ISP's ASN. Filter to the ±5-minute window around each reset. Count UPDATE messages and prefix-withdrawal events.

**Prediction:** If UPDATE volume is elevated at all three windows and flat in surrounding hours, the malicious call should soften to ESCALATE pending firmware ruling out.

---

### DIRECTIVE-TO-DEFENDER

For alerts where the verdict rests on third-party confirmation of "no anomaly," sequence a precision check before treating the confirmation as authoritative: ask what instrumentation the confirming party actually runs, at what granularity, and whether their terminology maps onto your causal hypothesis. An ISP NOC's "no link flaps" confirms physical layer stability — it does not attest to BGP control-plane quiescence. On closed-firmware network devices with no endpoint telemetry, the visibility gap means you are correlating operational events, not inspecting causation chains. When the benign-elimination logic rests on a third-party confirmation, make explicit what that party can and cannot see before treating the confirmation as ruling out the relevant class of upstream cause.
```
