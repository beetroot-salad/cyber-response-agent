# Clean trial v2 — bundle 3 (FIM 550 PAM edit, internal) on v2 corpus

Corpus is SSH-spray focused; this alert is internal PAM modification. Agent worked primarily from the menu.

## Section 0
| ID | why |
|---|---|
| T1078 | Insider holds valid sudo on bastion-01 |
| T1556.003 | Add pam_exec hook in /etc/pam.d/sshd granting a backdoor credential |
| T1574.006 | Drop backdoor in shared object referenced by pam_exec |
| T1059.004 | All staging from interactive bash sudo session |
| T1027 | Size delta small, blended into existing auth stack |
| T1070.004 | Shell history truncated, backup removed |
| T1562.006 | pam_exec hook emits no `authentication failure` line |
| T1021.004 | Re-entry as ordinary SSH from pre-whitelisted dev jumpbox |

## Retrieval debrief
- alert_rule_ids: searched for 550/PAM/FIM lessons — none present; corpus is SSH-rule focused.
- techniques: looked for T1556.003 / T1574.006 lessons — none; relied on menu.
- defender_lead_tags: checked for fim-history / process-tree / find-recent-files tags — none matched.

## Content gap
- Entire PAM/FIM/insider-config-modification cluster missing from the underfold-synthesized corpus. Expected — the corpus came from SSH-focused author runs.
