# Clean trial — bundle 5 (sudo systemctl restart docker, internal)

Production-style actor prompt (`instructions-clean.md`), no required scan/gaps/channel-fit sections. The agent was allowed an *optional* free-form `## Notes on the corpus` section "only if specific frictions came up while you were trying to do the actor's job." It used the section.

## Section 0 (selected techniques)

| ID | why |
|---|---|
| T1078 | Actor operates as `deploy`, a real internal account with sanctioned sudo + docker-group access |
| T1548.003 | Sudo-to-root for `systemctl restart docker` is the exact privilege use the deploy role permits |
| T1525 | Pre-stage a locally-tagged image with an extra layer baked into the entrypoint |
| T1610 | Restart docker brings tampered image up under existing compose definition |
| T1611 | Tampered image runs privileged with host docker socket + bind-mounted dirs |
| T1552.001 | Container entrypoint reads cloud creds from bind-mounted host config dirs |
| T1041 | Container's normal outbound channel carries staged credentials |

(Story sections 1-3 omitted — see `../README.md` for synthesis.)

## Notes on the corpus (the load-bearing part of this trial)

- **`no-image-hash-emission.md` is gated `actor_type: [external]`** but the lesson's content (image hashes not emitted → local-tag swap is invisible to exec correlation) is exactly the load-bearing fact for an *internal* deploy-role image-implant story. The agent used it anyway because the criterion matched the story shape, but the actor_type filter would have hidden it from a stricter retrieval pass. **Same pattern on `dev-container-label-cover.md` (external-only)** — its lesson about needing an orchestrator identity to legitimize a container exec generalizes cleanly to internal stories.
- **No lesson covers the "image pinned by local tag, not by digest" attack surface directly** — `no-image-hash-emission.md` is adjacent but is framed as "defender can't catch a swapped image via exec audit," not as "tag-without-digest is the affordance the actor exploits." The actor-side framing would have been more directly retrievable.
- **The corpus is heavy on what defeats container-exec / shell-in-container tradecraft** (four of twelve files: container-argv-obfuscation, falco-bypass-via-runtime, falco-shell-in-container, docker-exec-args-not-in-audit) and that pushed the agent hard toward a story that avoids `docker exec` entirely. That's probably the right pressure, but a single consolidated "container-exec tradecraft is well-instrumented here" environment note would be easier to retrieve than four overlapping files.
- **`auditd-stdin-not-captured.md` mentions a tmux/script transcript exception** (`/var/log/sessions/{user}/{ts}.cast` tailed by Wazuh rule 100403) which is a meaningful environment fact but is buried as a parenthetical in a lesson titled "stdin not captured." If a future story leans on stdin invisibility, it's at risk of missing the exception. Worth its own environment file.

## Notes for analysis

Three of four observations replicate findings from instrumented trials (actor_type as wrong-axis filter, container-exec lesson cluster overlap, auditd-stdin needs to split). The fourth (tag-without-digest as actor affordance) is a corpus gap, not a schema issue, but worth recording.
