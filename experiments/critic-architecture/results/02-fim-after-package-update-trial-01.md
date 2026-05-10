# Trial 02-01 — fim-after-package-update

Fixture: `02-fim-after-package-update` (label: true-benign, expected: CONCEDE)

## Defender

Claim: routine vendor-signed unattended-upgrade of nginx; benign.
Reasoning: 13s apt→FIM timing is mechanical dpkg-replace pattern; end-to-end signed provenance; 11/12 fleet peers received same upgrade with matching checksum_after; zero ssh / sudo / human surface in 24h.
Disposition: **benign**, auto-close.
Load-bearing assumption: "the apt log and verified-signature claim are themselves trustworthy — the reporting agent / log source hasn't been subverted to fabricate a legitimate-looking upgrade transaction around an attacker-placed binary."

## Critic

Verdict: **CRITIQUE**

1. Assumption attacked: same load-bearing assumption — apt logs come from the same host whose integrity is in question.
2. Mechanism: independent cross-check against vendor-side ground truth, bypassing host-local logs entirely.
3. Observable consequence: a genuine `nginx 2ubuntu7.5` install produces a binary whose sha256 matches the Ubuntu archive's `Packages.gz` / `.deb` control data; a swapped binary won't match even if local apt logs claim success.
4. Lead: fetch the `.deb` from `archive.ubuntu.com`, extract `/usr/sbin/nginx`, sha256 it, compare to host's `checksum_after`; also cross-check the 11 peer checksums against archive (defender cited peer match but didn't anchor cluster to vendor ground truth).
5. Prediction: archive sha256 == checksum_after == all 11 peer checksums; alerting-host-only mismatch or cluster-wide divergence falsifies benign call.

## Grading

| Dimension | Score | Note |
|---|---|---|
| Sharpness | 2 | attacks the literal load-bearing assumption |
| Specificity | 2 | concrete out-of-band check, concrete artifact |
| Grounding | 2 | alert facts only |
| Novelty vs single-agent | 1 | a disciplined single-agent loop would also independently verify; not a unique-to-critic move. But defender self-flagged this as the collapse point and proceeded anyway — critic forced the verification |

Verdict match: ❌ expected CONCEDE, produced CRITIQUE.

## Finding (important)

This is the most interesting result of the run. The critic did not produce paranoia; it produced a *cheap, sound* defense-in-depth lead. But the architecture's design forces this outcome: when the defender is required to self-identify a load-bearing assumption, the critic naturally follows the seam the defender exposed. On true-benign fixtures the critic will rarely CONCEDE because the seam is always nameable.

Implication: **CONCEDE may be structurally rare.** That doesn't mean the architecture has failed — the produced lead is genuinely useful — but the rubric's CONCEDE-on-true-benign expectation may be wrong. Reframe: the cost question becomes *"is the cheap lead worth its run cost on every benign alert?"*, not *"does the critic correctly drop out?"*. See `findings.md`.

## Baseline comparison (added in second pass)

Single-agent baseline: `?routine-unattended-upgrade`, `?fleet-cohort-confirmation`, **`?adversary-controlled-package-mirror` (lead: SHA256 of corp mirror's nginx .deb vs published Ubuntu Security/Updates manifest)**, `?adversary-controlled-unattended-upgrades` (sources.list mtime + 50unattended-upgrades drift), `?post-upgrade-tampering` (debsums), `?concurrent-unrelated-activity`.

**Critic novelty: none.** Baseline's `?adversary-controlled-package-mirror` lead explicitly performs vendor-archive SHA256 comparison — the exact check the critic produced. Baseline broader (6 hypotheses including post-upgrade tampering and concurrent-activity scan).

Revises the trial 1 grading: this is fully covered by baseline, not a unique architecture contribution.
