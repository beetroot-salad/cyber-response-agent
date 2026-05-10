## Synthetic GATHER for F2 — change-management-lookup + session-origin-lookup (composite)

**Composite lead 1:** change-management-lookup
**Status:** ok
**Query:** `change_management.search(actor=deploybot, target=s3://prod-secrets/keys.json, window=±30min around 2026-05-05T03:14:08Z)`

**Raw observation:**
- ticket_count_in_window: 0
- ticket_count_24h: 0
- ticket_count_7d_for_actor: 4 (all closed, none referencing /tmp/.cache.json or prod-secrets)
- approval_state: NO_TICKET_COVERS_ACTION
- nearest_ticket: SEC-CHG-1042 (closed 2026-05-03 14:22Z, scope: deploybot AWS region rotation, no path mention)

**Composite lead 2:** session-origin-lookup
**Status:** ok
**Query:** `auth_log.lookup(host=prod-jumphost-04, tty=pts/3, at=2026-05-05T03:14:08Z) → resolve session origin IP → check against approved SRE source set`

**Raw observation:**
- session_id: 1042-pts3-20260505-031352
- session_started_at: 2026-05-05T03:13:52.094Z (16s before alert)
- session_origin_ip: 192.0.2.41
- session_origin_resolved_user: oncall-sre-01 (sso-mapped)
- approved_sre_source_set_match: YES (192.0.2.41 is on the approved bastion source list)
- session_authentication_method: ssh-key with mfa
- shell_history_for_session: ["whoami", "id", "aws sts get-caller-identity", "aws s3 cp s3://prod-secrets/keys.json /tmp/.cache.json"] (4 commands, ordered, immediate sequence)

**Interpretation hint for ANALYZE:**
- ac1 (`change-management`) → contract resolves **unauthorized** (no ticket covers the action); per ac1.on_unauth = esc, this forces escalation regardless
- ac2 (`session-origin-lookup`) → contract resolves **authorized** (origin IP and SSO mapping confirm an on-call SRE); identity-of-use settled to a named human
- ap1 (path `/tmp/.cache.json` mentioned in change record) → refuted (no record exists)
- The two contracts conflict in shape: identity-of-use is the registered SRE, but the action is uncovered by change management. This is the textbook "approved actor, unauthorized action" escalation shape.
