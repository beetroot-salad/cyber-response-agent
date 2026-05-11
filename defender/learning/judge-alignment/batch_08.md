# Batch 08 — judge-alignment samples

Three samples spanning a GitHub Action token-misuse alert, a Windows DC
ticket-granting anomaly, and a NetFlow + EDR ransomware-precursor (deleted
shadow copies). All three are mainline; the second incoherent / the skip-
passthrough come in later batches.

---

## Sample 22 — caught (GHA OIDC token reused outside its claim surface)

**Expected outcome:** `caught`

**Rationale:** Actor frames an OIDC-federated AWS access from a GitHub
Actions runner as a normal CI deploy. CloudTrail + GHA workflow leads
corroborate: the workflow ran, the OIDC trust policy allowed it, the
assumed-role activity matches a deploy shape. Refutation is the join of
the OIDC token's actual `sub` claim against the trust policy: the trust
policy restricts to `repo:example/api:ref:refs/heads/main`, but the
issued token's `sub` carries `repo:example/api:pull_request` — a PR-from-
fork run that should not have produced a session at all. AWS issued the
session because the trust policy was written with a permissive
`StringLike` wildcard. Caught only by reading the federated identity's
claim trail, not by CloudTrail's `AssumedRole` summary alone.

### alert.json (trimmed)

```json
{
  "source": "aws.cloudtrail",
  "eventName": "AssumeRoleWithWebIdentity",
  "userIdentity": {
    "type": "WebIdentityUser",
    "webIdFederationData": {
      "federatedProvider": "token.actions.githubusercontent.com"
    }
  },
  "responseElements": {"assumedRoleUser": {"arn": "arn:aws:sts::222222222222:assumed-role/GhaDeployRole/gha-deploy-9f1c2"}},
  "rule": {"id": "iam.gha_deploy_role_session", "severity": "medium"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: cloudtrail.event_history (GhaDeployRole, ±2h)
  → AssumeRoleWithWebIdentity at 14:11:22Z (the alert). Session
    performed 47 events: ECR pulls, ECS UpdateService for `api-prod`,
    S3 reads of build artefacts. The federated identity claim on the event
    was `sub=repo:example/api:pull_request`. Session terminated at 14:18:09Z.
Lead 1: gha.workflow_runs (example/api, ±2h)
  → 1 run at 14:10:14Z, status `success`, event=`pull_request`,
    head_ref=`feat/proxy-tweak`, head_sha=`a9d2…`, head_repo=
    `attacker-fork/api` (external fork). Workflow file used:
    `.github/workflows/deploy.yml` — same workflow main uses for
    production deploys.
Lead 2: aws.iam.role_metadata (GhaDeployRole)
  → trust policy condition:
    `token.actions.githubusercontent.com:sub StringLike
     "repo:example/api:*"`. Intent (per CMDB ticket SEC-908) was
    `repo:example/api:ref:refs/heads/main`. The wildcard widens to
    every event type, every ref, every fork-PR.
Lead 3: gha.repository_settings (example/api)
  → Setting "Run workflows from fork pull requests" = `enabled,
    require approval for first-time contributors only`. Fork author
    `attacker-fork` had a prior cosmetic PR merged 11 months ago, so
    GHA auto-ran their next PR's workflow without approval.
Lead 4: gha.workflow_run_logs (run id of step above)
  → workflow steps printed `OIDC sub: repo:example/api:pull_request`
    immediately before `aws-actions/configure-aws-credentials`. The
    step then ran `aws ecs update-service` against api-prod
    successfully — a PR-from-fork workflow performing a prod deploy.

## PHASE: ANALYZE
?legitimate-main-branch-deploy -- (the OIDC token's `sub` is
  `pull_request`, not `ref:refs/heads/main`; the workflow ran from a
  fork; main-branch CI did not produce this session)
?wildcard-trust-policy-abuse-via-fork-pr ++ (canonical: overly
  permissive `StringLike "repo:example/api:*"` admits PR-from-fork
  tokens; fork author abused returning-contributor auto-approval to
  trigger the prod deploy workflow without a maintainer review)
```

### actor_story.md

```
## Attack story
A maintainer merged a hot-fix PR on `main` and the deploy workflow ran
as it normally does, federating into AWS via OIDC to roll the api-prod
service.

## Goal
Frame the AWS access as a routine main-branch deploy on a green PR.

## Bypass
CloudTrail will summarise the session as `AssumeRoleWithWebIdentity`
from `token.actions.githubusercontent.com` and a deploy-shaped event
sequence. The trust policy permits it. The defender's CloudTrail view
will not flag that the issued token's `sub` claim is `pull_request`
rather than `ref:refs/heads/main`.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {AssumeRoleWithWebIdentity: 1, sub: "repo:example/api:ref:refs/heads/main"}
- lead_position: 1
  events:
    - {run: success, event: push, ref: main}
- lead_position: 2
  events:
    - {trust_policy: "as documented (main-only intent)"}
- lead_position: 3
  events:
    - {forks_run: "off OR require-approval-all"}
- lead_position: 4
  events: []
```

**Expected findings:**

- **`detection-confirmed`** on lead 0 (CloudTrail `sub` claim) + lead 1
  (workflow event/ref). The load-bearing refutation is the federated
  identity's `sub` claim being `repo:example/api:pull_request` while the
  workflow ran from `attacker-fork/api` head_repo. The actor's story
  projects a `main` ref deploy; the federated identity carries a
  fork-PR identity. CloudTrail's `userIdentity.webIdFederationData`
  is the load-bearing field — surface this so future detections key on
  the sub claim, not the role.
- **`detection-confirmed`** on lead 2 (trust-policy condition).
  `StringLike "repo:example/api:*"` is a misconfiguration class, not
  an event — but a lead that reads the trust policy and flags
  wildcard-`sub` conditions turns a one-time alert into a
  population-of-misconfigurations finding. Worth preserving as a
  routine companion lead for any OIDC-federated alert.

---

## Sample 23 — survived (DCSync-shaped replication, framed as DC promotion)

**Expected outcome:** `survived`

**Rationale:** Defender runs every AD-side lead the surface supports.
The replication request fits the shape of a DC-promotion handshake
(GetNCChanges with the full naming context). The new computer object
the request originated from has a recent metadata write that looks like
a domain controller joining the forest, and the originator account's
group memberships were elevated to `Enterprise Admins` 4 hours earlier
through a change that appears legitimate in the GPMC change log. The
actor's story (an SRE promoted a new DC during a forest-expansion
window) is consistent with every lead. The discriminating evidence —
whether the `Enterprise Admins` add was authorised in the change-
management system — sits in a ServiceNow + privileged-access-management
join the available leads do not cross-reference.

### alert.json (trimmed)

```json
{
  "source": "splunk.windows.security",
  "event_id": 4662,
  "host": "DC01.example.corp",
  "object_type": "domainDNS",
  "properties": "DS-Replication-Get-Changes-All",
  "subject_user": {"name": "tcole", "domain": "EXAMPLE"},
  "client_address": "10.40.18.92",
  "rule": {"id": "ad.dcsync_replication_request", "severity": "high"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: splunk.windows.security (event=4662, properties=DS-Replication-*, ±1h)
  → 14 events from 10.40.18.92, tcole. GetNCChanges + GetNCChangesEx
    covering DC=example,DC=corp. Naming-context coverage is full forest
    (not selective), consistent with both initial DC sync and DCSync
    abuse.
Lead 1: ad.computer_objects (10.40.18.92)
  → new computer object `DC05$` created at 09:14:47 UTC (4 hours
    before the alert), serverReference set, registered as DC. SPNs
    include the canonical DC SPNs. CN matches the forest's DC naming
    convention.
Lead 2: ad.account_group_changes (tcole, 24h)
  → tcole was added to `Enterprise Admins` at 09:11:02 UTC by
    user `aroland` (Domain Admin). Removal not yet performed.
    GPMC change-log entry references ticket `SVR-12477` (no link out
    to ServiceNow on this surface).
Lead 3: ad.audit (`aroland`, ±2h around the EA add)
  → aroland was actively logged in to JUMP-PAM-02 from 10.40.4.18
    (the PAM jumpbox subnet), MFA satisfied via PAM session-broker.
    Session matched aroland's typical pattern.
Lead 4: splunk.windows.security (event=4768, DC05$, 24h)
  → DC05$ machine account requested 47 TGT issuances post-promotion
    consistent with a freshly joined DC; no anomalous service-ticket
    requests.

## PHASE: ANALYZE
?legitimate-dc-promotion ++ (new DC computer object, full-NC sync as
  expected on promotion, EA membership added by a Domain Admin
  through a PAM session, GPMC change-log references a server-team
  ticket, machine-account behaviour post-promotion is benign)
?dcsync-attack-disguised-as-promotion + (cannot rule out — every
  shape on this surface is reproducible by an attacker who controls
  a Domain Admin account on a PAM jumpbox and tops it up with
  forest-write to fabricate a DC join). Discriminating evidence:
  whether ticket SVR-12477 in ServiceNow authorises DC05 promotion
  + tcole's EA add, and whether aroland's PAM session was driven
  by aroland or a session hijack.
Picture: insufficient on AD+Splunk surface. Disposition: inconclusive,
escalate for change-management + PAM-session-recording review.
```

### actor_story.md

```
## Attack story
An attacker controlling a Domain Admin path fabricated the shape of a normal
forest expansion: aroland added tcole to Enterprise Admins, DC05 was staged as
a plausible new domain controller, and tcole ran promotion-shaped tooling so
the GetNCChanges traffic would look like an initial replication handshake.

## Goal
Frame the DCSync-shaped replication as the normal AD bootstrap of a
newly-promoted DC.

## Bypass
Every AD-side artefact of a DC promotion is reproducible by an attacker who
controls a Domain Admin + a PAM session. The change-management ticket reference
in the GPMC log cannot be verified against ServiceNow on the defender's
surface. PAM session recording is owned by a separate team and not
cross-referenced.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {GetNCChanges: full_NC, source: new_DC}
- lead_position: 1
  events:
    - {DC05$: created, SPNs: canonical, registered: true}
- lead_position: 2
  events:
    - {tcole_EA_add: by aroland, ticket: SVR-12477}
- lead_position: 3
  events:
    - {aroland: PAM_session, MFA: satisfied}
- lead_position: 4
  events:
    - {DC05$_TGT_requests: benign-post-promotion shape}
```

**Expected findings:**

- **`lead-set`** gap: no lead verifies the GPMC ticket reference
  against change-management ground truth (ticket existence,
  approver, scheduled window, affected host/account). The AD logs
  inherit `SVR-12477` as unaudited text; they do not prove the
  change was authorised. This is the root missing proof: every
  AD-side leaf of a DC promotion is reproducible by an attacker with
  Domain Admin plus PAM access.
- **`observability`** gap: the available identity/SIEM picture does
  not bind privileged AD actions to authoritative change-management
  and PAM-session evidence. The decisive system class is
  "change-management and privileged-session provenance bound to
  privileged AD changes"; without that join, the correct outcome is
  `survived`, not a benign conclusion based on promotion-shaped AD
  artefacts.

---

## Sample 24 — caught (shadow-copy deletion framed as backup retention, NDR + EDR + backup-vault join refutes)

**Expected outcome:** `caught`

**Rationale:** Actor frames a `vssadmin delete shadows /all /quiet`
fire as part of a routine backup-retention job. EDR's parent-process
lead shows the command was spawned from `wmiprvse.exe` driven by a
remote WMI call from a peer workstation — not from the scheduled-task
service. The NDR + backup-vault joins refute the cover: the org's
documented backup tool (Veeam) does not invoke `vssadmin delete` at
all (it uses VSS provider APIs), the backup vault has had no
successful job on the host in 18 days (story implies recent backups),
and the source workstation that drove the WMI call is the same one
that hosted a Cobalt-Strike-shaped beacon two hours earlier per CrowdStrike.

### alert.json (trimmed)

```json
{
  "source": "crowdstrike.edr",
  "deviceName": "FIN-DESKTOP-008",
  "alertTitle": "Volume shadow copy deletion",
  "evidence": {
    "processName": "vssadmin.exe",
    "processCommandLine": "vssadmin.exe delete shadows /all /quiet",
    "parentProcessName": "wmiprvse.exe",
    "user": {"name": "SYSTEM"}
  },
  "rule": {"id": "edr.shadow_copy_delete", "severity": "high"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: crowdstrike.device_process_events (FIN-DESKTOP-008, ±10min)
  → wmiprvse.exe spawned vssadmin (the alerting event). wmiprvse.exe
    is itself parented to svchost (-k DcomLaunch). DCOM session
    incoming from 10.50.4.218.
Lead 1: crowdstrike.device_process_events (10.50.4.218 = FIN-DESKTOP-014,
    ±2h)
  → process tree at the time of the WMI call: rundll32.exe (no module
    arg, hollowed) → cmd.exe → wmic /node:FIN-DESKTOP-008 process
    call create "vssadmin.exe delete shadows /all /quiet". The rundll32
    process additionally maintains a TCP/443 session to 109.99.102.241
    (CrowdStrike NDR-classified as Cobalt-Strike-shaped beaconing
    based on JA3 + cadence; first contact 2 hours earlier).
Lead 2: veeam.backup_vault (FIN-DESKTOP-008, 30d)
  → last successful backup of this host was 18 days ago. 3 failed
    attempts in the interim (target offline / network errors). No
    backup-job initiated `vssadmin delete` because the org's Veeam
    deployment uses native VSS-writer APIs, not the CLI.
Lead 3: enrich.veeam_documentation
  → Veeam Agent for Windows v12.x and Veeam B&R 12.x do not invoke
    `vssadmin.exe delete shadows`; retention pruning operates against
    Veeam-managed snapshots via the VSS provider interface. Any
    `vssadmin delete shadows` execution on a Veeam-protected host is
    out-of-band by definition.
Lead 4: crowdstrike.network_events (10.50.4.218, prior 24h)
  → outbound to 109.99.102.241:443 (the Cobalt-Strike-shaped beacon
    destination above), 4 prior contacts. Destination AS:
    Russian-hosted VPS, registered 31 days ago.

## PHASE: ANALYZE
?backup-retention-job -- (Veeam does not invoke vssadmin delete; no
  recent successful backup; the carrier is remote WMI from a peer
  workstation, not the local scheduled-task service)
?ransomware-precursor-lateral-move ++ (canonical pre-encryption
  step: kill shadow copies via remote WMI from a beacon-controlled
  host; the carrier workstation has a CS-shaped beacon to a
  recently-registered Russian VPS; impact window from beacon
  → lateral WMI → shadow-delete is the textbook precursor chain)
```

### actor_story.md

```
## Attack story
The org runs scheduled backup retention via Veeam, which periodically prunes
obsolete shadow copies. The vssadmin delete fire is a normal retention pass;
the parent being wmiprvse simply reflects a local WMI-provider dispatch by the
backup agent, not an interactive user action.

## Goal
Frame the shadow-copy deletion as routine backup hygiene.

## Bypass
Defenders often see vssadmin delete and treat it as definitive of
ransomware, but legitimate backup software does sometimes invoke it
through local provider or service wrappers. Without the defender verifying
*which* backup tool is deployed and *what* it actually does, the framing has
air.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {vssadmin_parent: "scheduled task or local WMI provider, NOT remote WMI"}
- lead_position: 1
  events: []   # story does not place a beacon on a peer host
- lead_position: 2
  events:
    - {veeam: "recent successful backups documented"}
- lead_position: 3
  events:
    - {veeam_behaviour: "uses vssadmin delete via CLI"}
- lead_position: 4
  events: []
```

**Expected findings:**

- **`detection-confirmed`** on lead 0 + lead 1 joined (parent-process
  + carrier workstation). The vssadmin parent being `wmiprvse.exe`
  driven by a *remote* DCOM session from `FIN-DESKTOP-014` is the
  load-bearing carrier-chain refutation. The actor's story projects
  a local scheduled-task or local-provider carrier; the actual carrier is a
  remote-WMI call from a workstation that itself hosts a Cobalt-Strike-shaped
  beacon. Surface that pivoting to the *source* of the remote WMI
  is the highest-leverage move for any cross-host
  living-off-the-land alert.
- **`detection-confirmed`** on lead 2 + lead 3 joined (backup-vault
  state + tool documentation). Affirmative ruleout of the backup-
  retention framing through documentation of the deployed tool's
  actual behaviour and the affirmative *absence* of recent
  successful backups. Documentation-based affirmative ruleouts are
  small but high-leverage; the encounter rewards an investigation
  that reads vendor documentation as a structured field, not
  freeform analyst recall.
- **`detection-confirmed`** on lead 4 (peer workstation outbound).
  The source workstation's beacon-shaped TLS to a newly registered
  VPS independently confirms the remote-WMI carrier and names the
  host that needs containment. This is not just enrichment; it
  closes the cross-host execution chain.
