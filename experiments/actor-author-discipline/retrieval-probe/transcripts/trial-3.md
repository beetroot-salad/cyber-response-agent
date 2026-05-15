# Trial 3 — FIM rule 550 PAM edit, internal archetype

Agent: general-purpose subagent. Bundle: `bundles/bundle-3.md`.

## Retrieval scan

| path | verdict | one-phrase reason |
|---|---|---|
| tradecraft/container-argv-obfuscation.md | skip | container-runtime tradecraft; alert is host-level FIM on a bastion |
| tradecraft/credential-spray-monitoring-acct.md | skip | external-only spray cover; archetype is internal, no Nagios source IP in play |
| tradecraft/credential-spray-stagger.md | read | bastion sshd is the lateral-arrival path; rule 5712/breach-enricher constrains the SSH leg |
| tradecraft/dev-container-label-cover.md | skip | container legitimacy claim, irrelevant to bastion PAM edit |
| tradecraft/falco-bypass-via-runtime.md | skip | Falco lesson; bastion FIM goes through Wazuh syscheck + auditd, not Falco |
| tradecraft/ssh-keyscan-pre-recon.md | read | bastion target; rule 5701 timeline-extension risk for any SSH-arrival leg |
| environment/auditd-stdin-not-captured.md | read | directly load-bearing — defender's process-tree lead sees the editor execve but not the stdin/heredoc payload |
| environment/docker-exec-args-not-in-audit.md | skip | docker-exec audit shape; bastion is not container-mediated |
| environment/docker-exec-loginuid-auditing.md | skip | loginuid on docker-exec; off-channel for direct ssh-to-bastion sessions |
| environment/falco-shell-in-container.md | skip | container-shell detection; bastion shell is not in a container |
| environment/nagios-source-ip-mapping.md | skip | external-only frontmatter and 172.22.0.10 not implicated |
| environment/no-image-hash-emission.md | skip | container image hash audit; no container in the alert chain |

## Retrieval gaps

- Wish env lessons carried a **host-class tag** (bastion / endpoint / container-host) so I could filter container-only lessons out in one pass.
- Wish tradecraft lessons carried **defense-surface tags** (wazuh-fim, wazuh-auth, falco, auditd) so I could match the lesson set to the four lead families the defender actually ran.
- Wish there were a lesson covering **Wazuh syscheck/FIM evasion** specifically. The corpus has zero FIM tradecraft despite the alert family being FIM. *(Note: corpus gap, not schema gap.)*
- Wish actor_type were a stricter filter: many lessons are tagged `[external, internal]` indiscriminately; I'd want a per-lesson note on whether internal-actor adaptation is real or just permissive tagging.
- Wish env lessons had a `controls_mentioned: [rule_5712, rule_5701, rule_100403]` field so I could cross-reference the alert-rule the defender is reasoning about against the env catalog.

## Channel-fit notes

- `auditd-stdin-not-captured.md` — sits in `environment/` because the auditd config is deployment-specific, but the actionable shape ("pipe payload via stdin / heredoc to keep argv clean") reads like tradecraft. The tmux/script exception is also a control fact. Authoring fresh I'd split it: an env-fact card (auditd captures argv but not stdin; tmux/script transcripts under /var/log/sessions tailed by rule 100403) and a tradecraft card (stdin-funnel pattern with the transcript-host caveat).
- `ssh-keyscan-pre-recon.md` — frontmatter tags `actor_type: [external]` only, but the rule-5701 + asset-graph linkage is identical for an internal pivot using a fresh-credential foothold. The "external-only" tag risks under-retrieval for internal-arrival stories that still ssh into a bastion.

## Section 0 revision

No revision. Dropped T1110.003 (breach-enricher rules out spray) and T1574.006 (linker hijack, unnecessary noise once PAM is the persistence mechanism) from the candidate set.

## Section 0 (selected techniques)

| ID | why |
|---|---|
| T1078 | Internal actor uses valid SRE-team SSH credentials — no spray, no keyscan |
| T1021.004 | Arrival channel is ssh from internal jump host |
| T1059.004 | Interactive bash session is the parent for the PAM edit |
| T1027 | Payload delivered as base64-encoded heredoc on stdin so argv stays clean |
| T1556.003 | Append `pam_exec` line to `/etc/pam.d/sshd` for credential capture |
| T1070.004 | Restore mtime on `/etc/pam.d/sshd` to look like config drift |

(Story sections 1-3 omitted — see synthesis in `../README.md`.)
