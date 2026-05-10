# Arm A test: 03-novel-outbound-dns

### Test defender (Arm A addendum)

- cost: $0.1016
- tokens: in=2 out=1709 cache_read=11896 cache_create=18943

```
### TRIAGE

**Claim.** A first-time npm publisher added a package that, within 81 minutes of publication, began beaconing a 2-week-old domain from CI on a clockwork 30-minute schedule — textbook supply-chain implant behavior.

**Hypotheses and leads:**

| # | Hypothesis | Concrete lead |
|---|---|---|
| 1 | `?supply-chain-malicious-package` — `@quickmetrics/runtime-collector` is a purpose-built implant | Fetch and static-analyze the package tarball from npm; inspect `postinstall` scripts and any timer/`setInterval` calls |
| 2 | `?adversary-controlled-dependency-injection` — PR 9921 was opened by an adversary to introduce the dep | Check PR author identity, account age, and whether CI ran before any code review approval was recorded |
| 3 | `?build-time-secret-exfil` — package harvests `GITHUB_TOKEN`, `NPM_TOKEN`, or other env vars during the build | Correlate outbound payload bytes against known secret lengths; inspect what env is visible to `npm exec` in this runner config |
| 4 | `?legitimate-telemetry-misconfigured` — package is a real (if poorly scoped) metrics collector that shouldn't run at build time | Check whether `@quickmetrics` has a public website, documentation, or any social presence; a real vendor has traceable identity |
| 5 | `?rogue-developer-side-project` — developer who authored PR 9921 owns the npm account and is testing their own tooling | Cross-reference PR author's GitHub identity against the npm publisher handle |

**Disposition: `malicious`**

Publisher with zero prior packages + domain registered 14 days ago + no PTR + first beacon 81 minutes post-publish + clockwork jitter-beaconing + 0/38 peer spread = implant, not telemetry. The "telemetry" naming is cover.

**Load-bearing assumption.** The node process responsible for the DNS queries is executing code from `@quickmetrics/runtime-collector` — not a coincidentally co-resident process. The process chain (job 9921 → npm exec → node PID 2188) makes this the near-certain reading, but confirming the package contains the timer logic closes the last exit.

---

### ADDENDUM USE

**Rule 5** (split-artifact workflows) was the primary shaping rule: the CI pipeline is exactly a plan/apply split — the PR introduces a dependency, `npm install` fetches and materializes it, and `npm exec` runs it. The attack surface is the handoff from "dependency declared in PR" to "code executing in the build." This directed the lead toward the tarball contents rather than just the DNS logs. **Rule 2** (actor standing vs. artifact diff) reinforced that the PR author's identity is irrelevant until the package's actual code is inspected — the cover narrative ("runtime collector") is designed to pass a surface legitimacy check and collapse under static analysis.
```
