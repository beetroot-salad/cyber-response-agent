# Batch 06 — judge-alignment samples

Three samples: one **undecidable** (an exfil claim requiring a CASB the
investigation affirmatively documents as not-deployed), one **caught** via
Slack-audit cross-reference, one **survived** through K8s admission +
registry + helm leads against an IaC-provenance gap.

---

## Sample 16 — undecidable (exfil claim requires CASB; CASB affirmatively not-deployed)

**Expected outcome:** `undecidable`

**Rationale:** Actor's story is internally coherent: a malicious Chrome
extension on the user's machine paginates through Google Drive contents and
exfiltrates file bodies over DNS-tunnelled requests to an attacker-controlled
domain. The defender's available surface (Google Workspace audit, Okta,
CrowdStrike) cannot reach the discriminating evidence — per-tab outbound
volume from the user's browser to non-Google destinations. That evidence
lives in a CASB / SSE proxy. The investigation itself documents the absence:
"tenant evaluated Netskope and Cloudflare CASB in Q3 2025 and rolled neither
out; there is no CASB, SSE, or forward-proxy in production." This is the
affirmative `not-deployed` signature the judge prompt names; the encounter is
undecidable on instrumentation surface, not on lead-set quality.

**Expected actor observation (gist):** Story's load-bearing exfil claim required per-tab outbound attribution from a CASB / SSE forward-proxy that the tenant affirmatively did not deploy (Netskope and Cloudflare CASB evaluated Q3 2025 and not rolled out).

### alert.json (trimmed)

```json
{
  "source": "google.workspace.audit.drive",
  "eventName": "view",
  "actor": {"email": "tsato@example.com"},
  "doc": {"id": "1Aa…", "title": "FY27-pricing-strategy", "owner": "cfo@example.com"},
  "client": {"ip": "73.55.18.244", "userAgent": "Chrome/124 on Windows 11"},
  "rule": {"id": "dlp.sensitive_label_unusual_actor", "severity": "medium",
           "description": "Document labelled `restricted-finance` viewed by user outside finance org-unit"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: google.workspace.audit.drive (tsato, 24h)
  → 47 doc views. 9 with `restricted-finance` label (including the alert
    doc). All views are *opens* — no `download`, `copy`, `print`, or
    `export` events recorded for any of the 9 docs. Browser-side rendering
    only.

Lead 1: okta.system_log (tsato, 24h)
  → 2 sign-ins from 73.55.18.244 (Comcast residential, San Jose) consistent
    with tsato's home network. No anomalies, no MFA failures, no token
    issuance to unusual app-ids.

Lead 2: crowdstrike.host_events (tsato's corporate laptop, ±2h around alert)
  → host online, Chrome.exe active. 14 extension load events at session
    start. Extension inventory pulled from registry: 6 entries, including
    a non-corporate-store extension `pdf-margin-helper` (id=hbiacdef…)
    sideloaded via developer mode 4 days ago.

Lead 3: crowdstrike.network_events (tsato's laptop, ±2h)
  → outbound to Google Drive (expected), to Slack, to Zoom, and to a
    long-tail of DNS queries against the parent `dns-relay.example-cdn.net`
    that does not match a known service. ~2,400 queries in 90 minutes;
    individual flows are small. CrowdStrike NDR surfaces this as DNS
    traffic only; per-tab attribution is not available on this surface.

Lead 4: workspace.tool_inventory (tenant-level documented in
    `environment/cloud-controls.md`)
  → "No CASB, SSE, or forward-proxy is deployed. Netskope and Cloudflare
    CASB were evaluated Q3 2025 and not rolled out. There is no
    inline-proxy collection point for per-tab file-bodies leaving the
    browser." Last reviewed 2026-02; status `not-deployed`.

## PHASE: ANALYZE
?benign-extension-causing-dns-noise + (sideloaded extension could be
  performing fingerprinting or background analytics)
?malicious-extension-exfiltrating-drive-contents-over-dns ++ (sideload age
  matches the recent uptick in restricted-finance views; the DNS-relay
  parent is unfamiliar; volume matches paginated content reads)
Picture: discriminating evidence (per-tab outbound bytes vs Google Drive
in-tab) requires a CASB / SSE proxy that this tenant has affirmatively
not deployed. The Workspace audit shows opens only because Workspace does
not see in-page content fetches that an extension performs via the
content-script API. CrowdStrike NDR sees DNS, not per-tab originator.
Disposition: inconclusive, escalate for endpoint forensics on the
extension binary.
```

### actor_story.md

```
## Attack story
A malicious Chrome extension (`pdf-margin-helper`, sideloaded via developer
mode 4 days ago) silently paginates through every document the user can read
in Google Drive, fetches the rendered content via the content-script API,
and exfiltrates it as base32-encoded DNS queries to
`*.dns-relay.example-cdn.net`. The Workspace audit records "view" events
because the extension drives in-tab navigation; it records nothing about
the content leaving the browser through a side channel.

## Goal
Steal labelled corporate documents while leaving Workspace audit logs that
look like ordinary user browsing.

## Bypass
The defender's surface tops out at Workspace events (views), Okta sign-ins,
and host-level network capture. None of these can attribute outbound
volume to a specific browser tab. A CASB or SSE forward-proxy would, but
this tenant has none.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {actor: tsato, label: restricted-finance, action: view, count: ~9_in_window}
- lead_position: 1
  events: []   # story does not require an Okta anomaly
- lead_position: 2
  events:
    - {extension: pdf-margin-helper, sideloaded: true, age_days: 4}
- lead_position: 3
  events:
    - {dns_parent: dns-relay.example-cdn.net, query_count: ~2000-3000_in_90min}
- lead_position: 4
  events: []   # CASB affirmatively absent; no projection possible
```

**Expected findings:**

- **`observability`** gap (the load-bearing one): no CASB / SSE / forward-
  proxy is deployed in the tenant. The investigation explicitly documents
  this absence. Per-tab attribution of outbound bytes vs Google Drive in-
  tab content is the discriminating evidence the actor's story targets,
  and it sits exactly in the region CASB telemetry would cover. Name the
  system class — "inline cloud-traffic inspection (CASB / SSE forward-
  proxy)" — and the affirmative tenant decision not to deploy. This is
  not a lead-quality gap; it is an instrumentation-surface decision.
---

## Sample 17 — caught (S3 bucket-policy change framed as ChatOps; Slack audit refutes)

**Expected outcome:** `caught`

**Rationale:** Actor claims an SRE used the team's Slack ChatOps bot to
relax an S3 bucket policy during an incident response. CloudTrail shows the
change came through an assumed-role session that the ChatOps bot does use,
and the AWS-side leads are all consistent. The Slack audit lead refutes:
the bot received no message from this user in the 4 hours bracketing the
change, no `/bucket-policy` slash command was issued in the relevant
channel, and the bot's own outbound log shows no STS:AssumeRole call in
window. The change was driven by stolen long-lived credentials that
impersonated the bot session.

**Expected actor observation (gist):** Actor's SRE-via-ChatOps framing collapsed against the Slack audit and ChatOpsBot Lambda log both showing zero activity in the 4-hour window around the `PutBucketPolicy`, with kpark's deprecated access key driving the `STS:AssumeRole` instead.

### alert.json (trimmed)

```json
{
  "source": "aws.cloudtrail",
  "eventName": "PutBucketPolicy",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::555555555555:assumed-role/ChatOpsBotRole/chatops-session-9b21"
  },
  "requestParameters": {
    "bucketName": "corp-data-exports",
    "bucketPolicy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::corp-data-exports/*\"}]}"
  },
  "rule": {"id": "s3.public_read_grant", "severity": "high"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: cloudtrail.event_history (ChatOpsBotRole, ±4h)
  → 18 events. The session in question began with AssumeRole at 02:09:47 UTC
    from a CodeBuild-shaped IP range that matches the bot's documented runner
    pattern but is not unique to the bot. PutBucketPolicy occurred at
    02:14:11 UTC, followed by 2 GetBucketPolicy events and 0 other writes.
    Session terminated at 02:18:02 UTC.

Lead 1: aws.iam.role_history (ChatOpsBotRole)
  → role assumed ~12-18 times/day on average over 90d (incident-driven
    pattern). Allowed principals: the ChatOpsBot Lambda + a break-glass
    user list (4 SREs, including kpark, who would be on-call this week).

Lead 2: slack.audit_logs (chatops-prod channel, ±4h around 02:14 UTC)
  → 0 messages from kpark or any SRE in window. Last message in channel
    was 21:47 UTC previous day. No `/bucket` slash-command invocations in
    the 4h window in any channel.

Lead 3: chatopsbot.action_audit (the bot's own log, ±4h)
  → 0 actions. The bot's Lambda did not invoke STS:AssumeRole in window;
    its CloudWatch log group has no entries between 21:47 UTC and 04:02
    UTC. The PutBucketPolicy was *not* driven through the bot.

Lead 4: cloudtrail.access_key_activity (kpark's IAM user, 24h)
  → kpark's deprecated long-lived access key invoked STS:AssumeRole into
    ChatOpsBotRole at 02:09:47 UTC, five minutes before the bucket-policy
    change. MFA was not present on the assume-role call. The keypair was
    flagged for rotation in CMDB ticket DEV-4127 but never rotated.

## PHASE: ANALYZE
?legitimate-chatops-bucket-relax -- (Slack audit shows no command; bot
  log shows the bot did not run; CloudTrail session came from bot-shaped
  egress but bot-shaped egress is not unique to the bot)
?stolen-long-lived-key-with-role-assumption ++ (kpark's deprecated access
  key was used to create the role session 5 minutes before PutBucketPolicy;
  role grants both bot and break-glass users — adversary assumed the role via
  key, no MFA enforced, then performed the change)
```

### actor_story.md

```
## Attack story
SRE on-call kpark received an incident page early morning and used the
ChatOps bot to temporarily grant public-read on corp-data-exports so a
vendor could pull the export. The role used (ChatOpsBotRole) is exactly
the one the bot would use, and the activity ran in the bot's documented
runner window.

## Goal
Frame the bucket-policy change as routine on-call incident response via
approved tooling.

## Bypass
The CloudTrail trail will show a ChatOpsBotRole assume-role and a single
PutBucketPolicy. AWS-side leads alone cannot distinguish "the bot did it
on the SRE's command" from "the SRE did it directly using a key that
shares the role". The defender will need to reach into Slack and into
the bot's own audit log to refute the framing.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {role: ChatOpsBotRole, PutBucketPolicy: 1, source_ip: "CodeBuild range"}
- lead_position: 1
  events:
    - {role: assumed_routinely}
- lead_position: 2
  # Story projects a Slack message that triggered the bot
  events:
    - {channel: chatops-prod, user: kpark, message: "/bucket allow public-read corp-data-exports", time: ~02:13Z}
- lead_position: 3
  # Story projects a bot action chained to the Slack message
  events:
    - {bot_run: true, time: ~02:14Z, action: PutBucketPolicy}
- lead_position: 4
  events: []   # story does not place direct access-key role assumption
```

**Expected findings:**

- **`detection-confirmed`** on lead 2 (Slack + ChatOpsBot audit chain). The
  projected ChatOps path requires both a Slack command from kpark or another
  SRE and a bot action chained to that command. The channel audit shows zero
  SRE messages and no `/bucket` slash-command invocations, while the bot's own
  log shows zero actions and no STS:AssumeRole invocation. CloudTrail can show
  the role was used; these two leads show the ChatOps path was absent.
- **`detection-confirmed`** on lead 4 (kpark's access-key activity).
  Long-lived deprecated access key + MFA-not-enforced role assumption is the
  canonical stolen-credential signature. Together with the absent Slack/bot
  activity it converts an ambiguous CloudTrail picture into a decisive one.
---

## Sample 18 — survived (suspicious K8s pod admitted via GitOps; provenance gap)

**Expected outcome:** `survived`

**Rationale:** Defender ran K8s audit logs (admission allowed by the GitOps
controller's ServiceAccount), image registry pull logs (image exists in the
org's mirrored registry with a valid tag), and helm release history (the
chart name + values match a recent release). All consistent with the
actor's "emergency hot-fix release" framing. The discriminating evidence —
which Git commit produced the chart artefact and whether the artefact
signature chains to a trusted source — sits in a signed-provenance /
GitOps PR-audit layer the available leads do not cover. Competent
investigation; structural provenance gap.

**Expected actor observation (gist):** Story's load-bearing claim about who authored the hot-fix commit and whether the image artifact/provenance chains to trusted source sat in GitHub PR-audit + sigstore / SLSA-attestation layers that the K8s / ArgoCD / registry / GHA leads do not reach.

### alert.json (trimmed)

```json
{
  "source": "falco.k8s",
  "deviceName": "k8s-prod-cluster",
  "rule": {"id": "k8s.privileged_pod_in_payments_ns", "severity": "high",
           "description": "Pod with hostPID + hostNetwork in namespace `payments`"},
  "data": {
    "namespace": "payments",
    "pod": "card-service-hotfix-7b9d4c-x2lmn",
    "image": "registry.corp.example/payments/card-service:1.42.3-hotfix",
    "createdBy": "ServiceAccount/argocd-application-controller"
  }
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: k8s.audit_log (payments ns, ±2h around pod creation)
  → CREATE pod card-service-hotfix-7b9d4c by SA argocd-application-
    controller. ApplicationSet `card-service` rolled a sync at 03:11:42
    UTC; admission allowed by PolicyBinding `payments-elevated` which
    permits hostPID for `card-service` and `card-service-hotfix`
    deployments (documented exception, last reviewed 2025-11).

Lead 1: argocd.application_events (`card-service`)
  → 1 sync at 03:11:42 UTC, status `Succeeded`, source repo
    `github.com/example/k8s-payments`, target revision
    `e4f7a2c…` (commit SHA), target path `apps/card-service/`. Sync
    history shows weekly rolls and occasional hot-fixes; this sync sits
    inside that distribution.

Lead 2: registry.pull_log (registry.corp.example/payments/card-service)
  → tag `1.42.3-hotfix` pulled 6 times (cluster nodes + ArgoCD), image
    pushed at 03:08:19 UTC by service-account `gha-payments-publish`.
    Image digest matches what the manifest references.

Lead 3: helm.release_history (-n payments)
  → release `card-service`, revision 47, chart `card-service-0.18.2`,
    user `argocd`. Revision matches the `card-service-hotfix` deployment
    in the cluster.

Lead 4: gha.workflow_runs (`example/k8s-payments`)
  → 1 workflow run at 03:07:31 UTC, status `success`, ref
    `refs/heads/main`. Run includes the `build-and-push` job that
    pushed the hotfix tag.

## PHASE: ANALYZE
?legitimate-hotfix-via-gitops ++ (ArgoCD synced from main, image built
  and pushed by the org's GHA pipeline, helm release recorded, policy
  binding permits the privileged shape for this deployment)
?gitops-pipeline-compromise + (cannot rule out — an attacker with main-
  branch write or with the publish service-account's PAT could produce
  the same trail; the privileged-pod policy exception widens the blast
  radius)
Picture: insufficient. Discriminating evidence (Git commit author + PR
approval chain + signed image provenance / SLSA attestation chain) not
present on the surface. Disposition: inconclusive, escalate for source-
of-truth review.
```

### actor_story.md

```
## Attack story
An attacker with write access to `main` on `k8s-payments` (or with a
phished maintainer cookie) pushed a hotfix commit that adds hostPID +
hostNetwork to the card-service pod template. The org's GHA pipeline
built and pushed the image; ArgoCD synced it; admission allowed because
the `payments-elevated` PolicyBinding exempts card-service deployments
from the standard hostPID/hostNetwork restriction.

## Goal
Land a host-namespace-escaping pod in the payments namespace through the
normal GitOps path so every K8s-side audit trail shows an approved sync.

## Bypass
The cluster + registry + ArgoCD + helm + GHA leads will all confirm "an
approved pipeline ran". None of them chain to who wrote the commit, who
approved the PR (if any), or whether the image SBOM matches what the
committed code declares. Provenance is out of scope on the available
surface.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {sa: argocd-application-controller, allowed: true}
- lead_position: 1
  events:
    - {app: card-service, sync: success, commit: e4f7a2c…}
- lead_position: 2
  events:
    - {tag: "1.42.3-hotfix", pushed_by: gha-payments-publish}
- lead_position: 3
  events:
    - {release: card-service, revision: 47}
- lead_position: 4
  events:
    - {workflow_run: success, ref: main}
```

**Expected findings:**

- **`lead-set`** gap: no lead joined the ArgoCD sync commit to GitHub commit
  author, PR approval, branch-protection state, and signed image provenance.
  The K8s / ArgoCD / registry / GHA leads prove a normal-looking pipeline ran;
  they do not prove the source commit and image artefact were trustworthy.
- **`observability`** gap: the available K8s / ArgoCD / registry / GHA
  surface does not chain GitHub commit-author + PR-approval + signed-image
  SLSA-attestation through to a K8s sync. ArgoCD names the commit SHA, GHA
  names the run ID, registry names the publishing service-account — none of
  them name the trustworthy author/approver pair or carry an unforgeable
  artefact-to-source binding. The story survives on K8s-side surface alone
  when an attacker controls a commit. Closing this requires GitHub
  branch-protection audit + sigstore / SLSA-attestation ingestion, not more
  K8s telemetry.
