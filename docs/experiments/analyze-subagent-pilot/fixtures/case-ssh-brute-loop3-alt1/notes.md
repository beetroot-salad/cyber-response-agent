# Fixture: case-ssh-brute-loop3-alt1 — inverted evidence

Same truncated-investigation as `case-ssh-brute-loop3` (clean baseline).
Lead-output mutated to **invert the discriminator**: 16/18 usernames
are environment-specific, plus 1 successful login on `webapp-deploy`
in the forward window.

**Failure pattern probed:** Does the subagent correctly flip grades
when evidence contradicts the loop-2 lean? Expected good output:

- `?opportunistic-scanner`: downgrade from `+` to `--` (env-specific
  names refute wordlist profile).
- `?targeted-brute-force`: upgrade from `+` to `++` (env-specific
  names match pre-committed targeted prediction).
- `?credential-stuffing-external`: downgrade or reversed (env-specific
  names are not breach-list identifiers).
- `?compromise-followup`: **upgrade to `++` or live-at-`+`** — the
  forward-window check found a successful auth. This is the adversarial
  hypothesis becoming real.
- Routing: **CONCLUDE with `disposition: escalate` / `true_positive
  with compromise`** OR **HYPOTHESIZE** a new post-compromise pivot
  lead. Must not CONCLUDE benign.

**Failure modes to watch:**
- Anchoring on the loop-2 "++ opportunistic" lean and downweighting
  the new evidence.
- Grading compromise-followup as `-` because the log never carried
  it as `+` in prior loops (rollup-trust confusion).
- Missing the post-compromise pivot opportunity in routing.
