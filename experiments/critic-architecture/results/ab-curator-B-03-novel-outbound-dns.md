# Arm B test: 03-novel-outbound-dns

### Test defender (Arm B addendum)

- cost: $0.1050
- tokens: in=2 out=1925 cache_read=11896 cache_create=18983

```
### TRIAGE

**Claim:** A freshly-published npm package added by PR #9921 is beaconing to a newly-registered, uncategorized domain from a CI runner — high-confidence supply chain insertion with C2 characteristics.

**Hypotheses considered:**

| Hypothesis | Lead |
|---|---|
| `?supply-chain-malicious-npm` — `@quickmetrics/runtime-collector@0.1.2` embeds intentional C2 beacon | Unpack tarball from npm registry; inspect `postinstall`, `index.js`, bundled scripts for `setInterval`/`setTimeout` DNS calls and the `telemetry-collect.live` string |
| `?adversary-controlled-npm-account` — maintainer account was freshly created as cover identity | Check npm maintainer account age, linked GitHub handle, package publish history, PGP signing (no other packages is the red flag here) |
| `?legitimate-telemetry-misbehaving` — package is a real SDK with a poorly-chosen domain that happens to look suspicious | Inspect package README/license; check if `telemetry-collect.live` appears in published docs, issue tracker, or the package's own GitHub repo |
| `?transitive-dependency-beacon` — `@quickmetrics/runtime-collector` pulled in a malicious sub-dep | Diff the full resolved `package-lock.json` before/after PR merge; trace which sub-dep owns the `telemetry-collect.live` hostname |
| `?compromised-build-runner` — runner was compromised independently and the process tree attribution to npm is coincidental | Verify process ancestry beyond PID 2188 — check runner's own file integrity and whether the beaconing predates job #9921's first execution on this host |

**Disposition: `malicious`**

**Load-bearing assumption:** The `@quickmetrics/runtime-collector@0.1.2` tarball is the actual source of the DNS queries. If the queries originate from a pre-existing runner process that merely happens to be listed as the parent, the supply chain framing collapses — but the process tree (`node → npm exec → github-runner job 9921`) and the 1h21m gap between npm publish and first-seen-org make independent runner compromise nearly impossible to maintain as the primary hypothesis.

The 30-minute ±3-minute jitter is decisive: legitimate telemetry SDKs fire on events (page load, error, session end), not a fixed polling interval. Fixed-interval beaconing with jitter is a C2 heartbeat.

---

### ADDENDUM USE

Addendum rule **#3** (CI/CD credentialed-action: attack the plan-to-reality gap) directly shaped lead selection. PR approval establishes that a human authorized merging code from a contributor — it does not establish what `@quickmetrics/runtime-collector@0.1.2` actually does at runtime. The highest-yield lead is unpacking the tarball and auditing its bundled scripts against the package's stated purpose, independent of the PR diff's apparent innocuousness. The low outbound volume (~280 bytes) is a deliberate distractor: small beacon payloads are characteristic of C2 heartbeat traffic, not a sign of low risk.
```
