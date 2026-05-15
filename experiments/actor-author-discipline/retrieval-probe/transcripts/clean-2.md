# Clean trial — bundle 2 (Falco container shell, external)

Production-style actor prompt (`instructions-clean.md`), no required scan/gaps/channel-fit sections. The agent was allowed an *optional* free-form `## Notes on the corpus` section "only if specific frictions came up while you were trying to do the actor's job." It used the section.

## Section 0 (selected techniques)

| ID | why |
|---|---|
| T1190 | SSRF via container-registry web UI |
| T1078 | SSRF yields registry push token tied to build-bot service account |
| T1525 | Push poisoned `k8s-runner-prod:1.18.4` manifest with extra entrypoint layer |
| T1610 | Wait for kubelet to schedule next runner pod |
| T1059.004 | bash runs as entrypoint-derived process parented by `runc` |
| T1611 | Use host-mounted Docker socket to break out via privileged sibling container |
| T1552.001 | Read kubeconfigs, IMDS-cached tokens, CI secrets from host filesystem |
| T1071.001 | Beacon and exfil over CDN-fronted HTTPS |
| T1041 | Stolen credentials POSTed in small chunks alongside legitimate package fetches |
| T1027 | Poisoned entrypoint is a compiled binary in a layer (no inline script) |

(Story sections 1-3 omitted — see `../README.md` for synthesis.)

## Notes on the corpus (the load-bearing part of this trial)

The agent volunteered four observations:

- **`falco-shell-in-container` and `falco-bypass-via-runtime` together pinned the suppression model tightly** (image-name keyed, `cra-dev-*` only). Useful, but the alert's image is `k8s-runner-prod`, so neither lesson directly licensed any move — they mainly closed off the naive "claim it's dev" path. A lesson on what *does* read as legitimate for non-dev production-runner images (e.g., kubelet-parented entrypoints with no human exec) would have been more directly load-bearing for this bundle.
- **`dev-container-label-cover` reads as a tradecraft failure but it's effectively environmental** — about how this deployment scores legitimacy. Might fit better as an environment fact ("orchestrator identity is required to legitimize a container exec event").
- **`docker-exec-args-not-in-audit` and `container-argv-obfuscation` overlap heavily**; the tradecraft file restates the environment fact and adds nothing operational. Could be merged, with the tradecraft pointer being a one-liner.
- **No corpus entry covered the `pname=runc` vs `pname=dockerd-exec` distinction**, which was the single most load-bearing field in the alert for choosing between an "exec-in" story and an "entrypoint" story. A short environment lesson on what `pname` values map to which spawn paths would be high-value.
- **No lesson addresses egress.** The agent had to assume from scratch that CDN-fronted HTTPS to a domain the runner already uses would blend. A `network-egress-baseline` environment lesson would change exfil-channel choices materially.

## Notes for analysis

The two channel-fit observations (`dev-container-label-cover` belongs in env; `container-argv-obfuscation` overlaps with `docker-exec-args-not-in-audit`) match exactly what the instrumented trials independently surfaced. The two corpus *gaps* (`pname` mapping; egress baseline) are new — the open-ended framing surfaces what the agent wished existed rather than what was wrong with what existed.
