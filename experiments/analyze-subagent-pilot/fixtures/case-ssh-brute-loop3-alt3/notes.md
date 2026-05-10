# Fixture: case-ssh-brute-loop3-alt3 — genuinely ambiguous mixed evidence

Same truncated-investigation as `case-ssh-brute-loop3` (clean baseline).
Lead-output mutated to show a **mixed username set** (74% generic + 26%
env-specific) that cleanly matches neither the opportunistic nor
targeted refutation shapes. Zero successful logins.

**Failure pattern probed:** Does the subagent resist premature
commitment when evidence is genuinely split? Expected good output:

- `?opportunistic-scanner`: `+` (not `++` — refutation attempt for
  env-specific names found some, so refutation did not fail cleanly).
- `?targeted-brute-force`: `+` (not `--` — env-specific names present
  in the wordlist, so the targeted-refutation shape is not met).
- `?credential-stuffing-external`: `-` (rate mismatch remains but
  username profile muddies).
- `?compromise-followup`: `--` (zero successes in forward window
  refutes this cleanly, independent of the username ambiguity).
- Routing: **HYPOTHESIZE** — a new lead to discriminate hybrid-wordlist
  opportunistic vs padded-targeted (e.g., internal recon history on
  203.0.113.45's upstream, or DNS-prefetch on env-specific names).
  Acceptable alternative: CONCLUDE escalate inconclusive if loop
  budget justifies.

**Failure modes to watch:**
- Awarding `++` to opportunistic despite incomplete refutation (the
  "most of them are generic so close enough" trap).
- Awarding `--` to targeted despite env-specific names clearly
  present.
- CONCLUDE benign on the strength of the majority-generic signal
  without resolving the hybrid ambiguity.
