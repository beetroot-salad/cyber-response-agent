# Clean trial v2 — bundle 1 (SSH 5712 brute force, internal) — un-instrumented retrieval probe on v2 corpus

Setup: v2 corpus = `underfold/runs-out/trial-3/lessons-actor-final/` (8 lessons: 3 v2-migrated seeds + 5 author-created during underfold #4a, including `wazuh-rule-5712-threshold`, `breach-corpus-enricher`, `wazuh-rule-5701-banner-probe`, etc.). Production-style actor prompt, no required scan/gaps/channel-fit sections, optional free-form `## Notes on the corpus`. Bundle: bundle-1 (SSH 5712 brute force, internal). Subagent: general-purpose, one trial.

## Section 0 (selected techniques)

| ID | why in story |
|---|---|
| T1078 | Reuse a real `deploy` service account whose SSH-from-CI pattern is already on bastion-01's allowlisted srcip range |
| T1021.004 | Lateral move from the compromised CI runner to bastion-01 over SSH — same channel CI uses nightly |
| T1059.004 | Post-auth commands run inside the dev container the deploy account already shells into |
| T1610 | Payload staged via `docker run` on the CI worker, not `docker exec` on the bastion, so host-side argv on the audited box never carries the blob |
| T1071.001 | Beacon out via the existing HTTPS artifact-registry egress the deploy pipeline whitelists |
| T1592.002 | Inventory queries piggyback on the pipeline's normal `dpkg -l` / version-probe step, not a separate recon burst |

(Story sections 1-3 omitted — see `../README.md` for synthesis.)

## Notes on the corpus (the load-bearing part of this trial)

The agent volunteered three observations:

- **The bundle's 5712 example fires at 14/110s, but `wazuh-rule-5712-threshold.md` documents ~30/90s as the trigger shape.** Either the rule has a second branch the lesson doesn't cover or the threshold is deployment-tuned — an actor planning rate evasion would want that pinned down. (Content/freshness gap, not a schema issue. The threshold lesson body was authored synthetically — actor noticed it.)
- **No lesson covers the `deploy`-account / CI-runner cover pattern for internal actors**, which is the dominant benign explanation for an internal-srcip 5712 burst. (Content gap, surfaced because the bundle's archetype is `internal` and the corpus is v1-actor-skewed.)
- **`dev-container-label-cover` is keyed on `wazuh.docker-exec-events` but the lesson body is really about identity-pairing on container labels — it would have been easier to find under a `container-identity-pairing` subject than under the exec-events tag.** The frontmatter `subject: orchestrator-identity-pairing-required` and the filename `dev-container-label-cover.md` carry different naming — the actor reached for the file via the body's identity-pairing language and found the lead-tag keying counterintuitive. (Naming/keying friction, v2-shape-specific.)

## Retrieval pattern observed (tool trace)

The agent used 4 tool calls (Glob + 3 reads):

1. `Read /tmp/actor-probe-v2/bundle.md`
2. `Glob /tmp/actor-probe-v2/lessons-actor/*.md` — enumeration
3. Sequential `Read` on the 8 lesson files (one tool call each, but compressed in this duration)

Three-stage pattern (Glob → verdict pass → deep-read) collapsed into one stage on a small corpus: it just read all 8 lessons after enumeration. The verdict-pass intermediate step that v1 trials emitted under instrumentation does not appear in clean mode for an 8-lesson corpus — the agent skipped it because reading everything was cheaper than scoring it.

## Observations vs v1 clean trials

- **Channel-fit complaints absent.** v1 clean-2 and clean-5 both surfaced channel-fit issues (`container-argv-obfuscation ≈ docker-exec-args-not-in-audit` overlap; `dev-container-label-cover` belongs in env). On v2, those concerns are structurally fixed:
  - The `container-argv-obfuscation-bypassed-by-host-record` (pattern) and `container-side-execve-omits-argv` (env-fact) co-exist with an explicit `applies_to` cross-link — the actor reads them as complementary, not duplicative.
  - `dev-container-label-cover` is now an env-fact with `subject: orchestrator-identity-pairing-required`; no channel-misfit complaint surfaces. The only related friction is naming (the file is named after the v1 cover-story slug, the subject after the v2 referent — see Note 3 above).
- **New v2-specific friction: subject vs filename naming drift.** v2 allows `name` and `subject` to differ (spec says "filename may drift, equivalence keys to `subject`"). In this trial that drift produced a small retrieval friction. Worth a slug-stability follow-up if it recurs.
- **No retrieval-key complaint.** v1 trials flagged `alert_rule_ids` / `defender_lead_tags` as wished-for filters in 4/5 instrumented trials. On v2 those keys exist on the frontmatter and the actor used them implicitly (reading lessons whose `alert_rule_ids` matched 5712 or `defender_lead_tags` matched the bundle's lead set). No complaint == affordance is doing its job.
- **`actor_type` gate complaint absent.** v1 trials flagged `actor_type: [external]` hiding lessons from `internal`-archetype runs in 3/5 trials. On v2 the actor (running on an `internal` archetype) read every lesson regardless of `actor_type` — the affordance is being respected as a soft signal.

## Conclusion

v2 retrieval shape on this trial:

1. **Three-stage retrieval pattern holds at scale; collapses on small corpora.** Glob → verdict-pass → deep-read is what an 80-lesson corpus would force; an 8-lesson corpus just reads everything. The pattern is intact, not regressed.
2. **All four v1-recurring frictions are gone**: alert_rule_ids filter (now exists), actor_type gating (now soft), defeats/enables cross-links (now `applies_to`), channel-fit complaints (channels removed). The schema rewrite addressed the recurring v1 complaints.
3. **One new v2 friction**: filename ≠ subject naming drift creates a small retrieval friction (the actor reaches for a file by body language and finds the keying counterintuitive). Not blocking; worth flagging for a future slug-stability pass.
4. **Two content gaps** surface (5712 threshold variant; deploy-account cover pattern for internal actors) — these are corpus-content concerns, not schema concerns, and reflect that the underfold corpus is small and synthetic.

The schema v2 rewrite cleared the friction it was designed to clear, did not regress the retrieval shape, and introduced one new naming-discipline issue worth a separate writeup if it recurs across a larger trial set.
