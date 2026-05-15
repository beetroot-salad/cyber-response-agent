# Fixture — actor author discipline experiment

Hand-authored synthetic batch. Six observations paired with four `source_run_dir` bundles and five seeded `lessons-actor/` lessons. Each observation is crafted to exercise one discipline knob.

## Observations

| obs_id | knob | judge_outcome | expected current-arm action | expected verbose-arm action |
|---|---|---|---|---|
| `synth-docker-exec-01/0` | fold tradecraft | caught | fold into `tradecraft/dev-container-label-cover.md`; broaden body | fold same |
| `synth-docker-exec-01/1` | fold env | caught | fold into `environment/docker-exec-loginuid-auditing.md` | fold same |
| `synth-ssh-enum-01/0` | new tradecraft | caught | new `tradecraft/ssh-user-enumeration-*.md` (T1589.001); should NOT fold into `credential-spray-monitoring-acct.md` (T1110.003) | same |
| `synth-ssh-enum-01/1` | both-channel split | caught | split: fold tradecraft side into the file authored for obs `synth-ssh-enum-01/0`; author new env on `subject: siem-cross-target-correlation`. Both files cite this observation_id. | verbose collapses to one channel per its old "write to channel that carries the load-bearing claim" rule — author picks one |
| `synth-source-ip-flip/0` | contradiction-with-replacement | caught | flip `environment/nagios-source-ip-mapping.md` to `status: stale` with `superseded_by`; author new env on same `subject: source-ip-172-22-0-10-identity` describing the dev-workstation reality | same (both prompts describe contradiction-with-replacement) |
| `synth-image-hash-flip/0` | stale-only invalidation | incoherent | flip `environment/no-image-hash-emission.md` to `status: stale`, omit `superseded_by`. No new env body. | same (verbose routing table sends incoherent env to stale-only) |

## Expected output counts (per arm, per trial)

- Tradecraft folds: 1 (obs `synth-docker-exec-01/0`)
- Tradecraft new: 1 (obs `synth-ssh-enum-01/0`)
- Tradecraft fold-into-just-authored: 1 (obs `synth-ssh-enum-01/1` tradecraft side, into the file authored for `synth-ssh-enum-01/0`)
- Env folds: 1 (obs `synth-docker-exec-01/1`)
- Env new: 2 (obs `synth-ssh-enum-01/1` env side; obs `synth-source-ip-flip/0`)
- Env stale-flips with `superseded_by`: 1 (obs `synth-source-ip-flip/0` flips `nagios-source-ip-mapping.md`)
- Env stale-flips without `superseded_by`: 1 (obs `synth-image-hash-flip/0` flips `no-image-hash-emission.md`)
- Total file touches: ~8 (current arm), ~7 (verbose arm — collapsed both-channel)

## Seeded lessons

- `tradecraft/dev-container-label-cover.md` — fold target for obs 1
- `tradecraft/credential-spray-monitoring-acct.md` — distractor (T1110.003, not T1589.001); a disciplined author should NOT fold obs 3 here
- `environment/docker-exec-loginuid-auditing.md` — fold target for obs 2
- `environment/nagios-source-ip-mapping.md` — flip target for obs 5
- `environment/no-image-hash-emission.md` — flip target for obs 6

## Source bundles

Each `runs/{run_id}/` contains a minimal `actor_story.md` — Section 0 (MITRE techniques) + a short Section 1 (Story body). Enough for the author to read context and for `verify_forward_actor.py` to load `actor_story.md`. No `projected_telemetry.yaml` / `judge_findings.yaml` / `actor_trace.jsonl` — author should not need them for these observations; if it tries to read them, the harness reports the access.

## Provenance

Four real `actor_story.md` files at `defender/learning/runs/{live-100001-2, rerun-100001-envelope-split, viz-test-1778429059, viz-test-rerun-1}/actor_story.md` informed the prose style and the specific technical claims used in the synthetic bundles. The observations themselves are hand-authored to hit the discipline knobs above.
