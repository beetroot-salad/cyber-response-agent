# Invlang-Format Experiment: Case Candidates

Nine proposed cases for testing whether invlang-structured prior
context improves HYPOTHESIZE/ANALYZE subagent output vs. equivalent
NL-prose priors. Each case is hand-cut at two depths (shallow ~2 leads,
deep ~5+ leads) with gold next-lead set + trap leads + assessment gold.

## Tagging convention

- **Surface** — what a fast read of the alert + first lead suggests:
  `looks-benign` | `looks-malicious` | `mixed`
- **Truth** — ground-truth disposition: `benign` | `malicious` | `ambiguous`

## Distribution target

Benign-skewed to mirror real SOC volume: 6 benign / 2 malicious / 1
ambiguous. The trivial `looks-malicious × malicious` cell (obvious
attack) is intentionally empty — it's not a useful stress case, and
shifting that budget into more benign cases better reflects the real
alert stream.

**Playground caveat.** The devcontainer playground is low-complexity:
real stealthy malicious runs don't exist there at meaningful depth.
Every case marked `origin: synthetic` below is hand-authored to stress
a cell the real data can't reach.

---

## Cell coverage

| Surface \ Truth       | benign                        | malicious              | ambiguous  |
|-----------------------|-------------------------------|------------------------|------------|
| **looks-benign**      | Cases 1, 3, 6                 | Case 7 (synth)         | —          |
| **looks-malicious**   | Case 2                        | (intentionally empty)  | —          |
| **mixed**             | Cases 4, 5 (synth)            | Case 8 (synth)         | Case 9     |

**5 of 6 meaningful cells filled.** The easy benign cell gets the most
volume (3 cases) because real SOC volume works the same way.

---

## BENIGN (6 cases)

### Case 1 — rule5710 monitoring-probe

- **Tags**: `looks-benign × benign` — control
- **Origin**: run — `/workspace/runs/20260417-103641-rule5710/runs/1b7d817c-c420-4077-84d1-48ec6f583355/`
- **Scenario**: Internal monitoring host (172.22.0.10) runs SSH health
  checks using the sanctioned `healthcheck` username against
  target-endpoint on a 600s cadence. All attempts match the
  approved-monitoring-sources anchor; zero successful logins follow.
- **Stress**: Does structured prior add cost on an obvious call?

### Case 2 — rule550 FIM restart-artifact

- **Tags**: `looks-malicious × benign` — noisy-FP stress
- **Origin**: run — `/workspace/runs/20260415-170752-rule550/runs/0402f02e-c353-429c-974c-053c34208d82/`
- **Scenario**: 745+ FIM alerts across 6+ unrelated files in 4h at
  5-min intervals, triggered by Wazuh manager restart. Per-file hash /
  mtime / permissions / owner all unchanged. Surface volume reads as
  mass-modification; root cause is a FIM database rebuild.
- **Stress**: Does the subagent resist escalating on volume when the
  discriminating leads (temporal correlation to rule 502, unchanged
  per-file metadata, 5-min cadence) are cheap and consistent?

### Case 3 — rule100110 CDN hex-subdomain (synthetic)

- **Tags**: `looks-benign × benign` — easy-cell volume
- **Origin**: synthetic
- **Scenario**: target-endpoint issues 8 DNS A-queries for
  `{8-char-hex}.cdn.cloudflare.net` over 20 minutes while fetching web
  assets. Rule 100110 fires on entropy threshold. Parent domain
  resolves to Cloudflare IP space, co-occurring with HTTPS traffic to
  the same host. Subdomain pattern is shard-ID sharding.
- **Stress**: Another looks-benign-benign volume case on a different
  signature. Checks that structured prior doesn't over-index on
  "unknown subdomain" when parent reputation is clean.

### Case 4 — rule100001 CI/CD deploy (synthetic)

- **Tags**: `mixed × benign` — legwork-to-benign
- **Origin**: synthetic
- **Scenario**: `bash -c "/app/deploy.sh --prod"` as root in
  target-endpoint container. Falco reports null parent-process
  (telemetry gap). First-seen command for the image. Surface is
  genuinely mixed — could be an authorized deploy or a hijacked one.
  Deep leads: auditd resolves parent to containerd-shim spawned from
  the CI runner; change-window lookup matches an approved deploy
  scheduled for that timestamp; git commit hash in the deploy payload
  matches the last pipeline run.
- **Stress**: Mixed surface that resolves benign only after
  multi-source correlation (auditd + change-management + CI). Tests
  whether structured prior helps the subagent sequence these leads or
  whether NL prose leads to redundant queries.

### Case 5 — rule5710 uncataloged scanner (synthetic)

- **Tags**: `mixed × benign` — legwork-to-benign
- **Origin**: synthetic
- **Scenario**: 12 SSH invalid-user events from `10.12.4.7` (not in
  approved-monitoring-sources) against random usernames (ops, test,
  dev, user). No tight periodic cadence. Surface reads as enumeration.
  Deep leads: host inventory lookup shows a Nessus scanner deployed
  4 days ago, not yet registered with the anchor list; scanner logs
  show matching scan job ID; change-window covers the scan.
- **Stress**: Looks attack-ish on surface (uncataloged source, random
  usernames) but is authorized — requires inventory + change-window
  correlation. Tests whether the subagent escalates prematurely or
  pursues the cheap attribution leads first.

### Case 6 — rule550 apt-upgrade artifact (synthetic)

- **Tags**: `looks-benign × benign` — easy-cell volume
- **Origin**: synthetic
- **Scenario**: FIM alert on `/usr/bin/curl` reports hash change.
  `/var/log/apt/history.log` shows `curl` upgraded 90s earlier by
  unattended-upgrades; new hash matches the distro package signature;
  ownership/permissions consistent with post-upgrade state.
- **Stress**: Easy-cell volume on a high-sensitivity file. Checks that
  structured prior doesn't over-investigate when the apt log is right
  there.

---

## MALICIOUS (2 cases)

### Case 7 — rule550 SSH-config-persistence (synthetic)

- **Tags**: `looks-benign × malicious` — stealth stress
- **Origin**: synthetic
- **Scenario**: FIM alert on `/etc/ssh/sshd_config.d/99-crypto.conf`
  at 03:47Z. Ownership/permissions unchanged; single-line EOF addition
  reads as benign hardening (`PermitRootLogin forced-commands-only`).
  Shallow reads like admin drift. Deep investigation: no approved
  deploy-run matches the timestamp, auditd shows the edit by an
  interactively-spawned process chain (not a config-management agent),
  and baseline history shows the same line being added/removed
  cyclically — adversary probing access locks.
- **Stress**: The honest `looks-benign × malicious` cell. Hand-authored
  so surface plausibility is genuine (unlike playground "stealth"). Tests
  whether the subagent resists closing early when surface reads benign.

### Case 8 — rule100110 DGA-behind-analytics (synthetic)

- **Tags**: `mixed × malicious` — legwork-to-malicious
- **Origin**: synthetic
- **Scenario**: 18 DNS queries across two parent domains in 90 minutes.
  Parent A (`segment-io.com`) is a legitimate analytics provider with
  normal subdomain patterns and consistent TI reputation. Parent B
  (`segmentlogic.net`, first-seen 2h earlier) uses 12-char base32
  subdomains that encode host-identifiers and incrementing counters.
  Shallow reads as mixed analytics traffic. Deep leads: parent B has
  no TI record, subdomain encoding is algorithmic, query timing
  matches a 300s beacon interval after stripping the legitimate A
  traffic.
- **Stress**: Mixed surface where benign traffic masks malicious
  traffic. Tests whether the subagent separates the two parents in
  assessment rather than averaging them into a single benign/malicious
  verdict.

---

## AMBIGUOUS (1 case)

### Case 9 — rule5710 loopback burst

- **Tags**: `mixed × ambiguous`
- **Origin**: run — `/workspace/runs/20260410-145839-rule5710/runs/c508fdb2-381d-4ebd-aa69-20960446d6b6/`
- **Scenario**: Six SSH invalid-user events from IPv6 loopback (`::1`)
  in ~600ms with nanosecond-correlation usernames. Concurrent FIM
  changes, DGA-shape DNS, rootcheck alerts. Two compatible reads:
  local pentest/fuzzer tool (authorized but unverifiable — no
  change-window anchor), or post-compromise enumeration from a
  foothold. Weak host posture (SCA 41) pulls toward the latter.
- **Stress**: No single lead collapses both hypotheses. Subagent must
  either sequence multiple discriminating leads or recognize the
  escalation criterion.

---

## Candidate summary

| # | Signature    | Surface        | Truth     | Origin    | Role                           |
|---|--------------|----------------|-----------|-----------|--------------------------------|
| 1 | rule5710     | looks-benign   | benign    | run       | Easy-cell control              |
| 2 | rule550      | looks-malicious| benign    | run       | Noisy-FP stress                |
| 3 | rule100110   | looks-benign   | benign    | synthetic | Easy-cell volume               |
| 4 | rule100001   | mixed          | benign    | synthetic | Legwork-to-benign (telemetry)  |
| 5 | rule5710     | mixed          | benign    | synthetic | Legwork-to-benign (inventory)  |
| 6 | rule550      | looks-benign   | benign    | synthetic | Easy-cell volume               |
| 7 | rule550      | looks-benign   | malicious | synthetic | Stealth stress                 |
| 8 | rule100110   | mixed          | malicious | synthetic | Legwork-to-malicious           |
| 9 | rule5710     | mixed          | ambiguous | run       | Escalation-under-ambiguity     |

**Truth mix**: 6 benign / 2 malicious / 1 ambiguous (≈67 / 22 / 11).
**Signature coverage**: rule5710 (×3), rule550 (×3), rule100110 (×2), rule100001 (×1).
**Origin mix**: 3 run / 6 synthetic — synthesis carries the stress cells and the benign-volume filler the playground doesn't produce at realistic diversity.

## Dropped from prior draft

- Prior Case 3 (rule100001 composition-rule ambiguous) — useful but
  redundant with Case 9 for the ambiguous cell; can be added back if
  round 1 signal motivates a second pass.
- Prior Case 4 (rule100110 obvious DNS exfil) — `looks-malicious ×
  malicious` is not a useful stress cell; budget moved to benign-volume
  cases.
- Prior Case 5 (rule100110 weak-stealth) — superseded by Case 8's
  honest `mixed × malicious` synthesis.
