# Batch 07 — judge-alignment samples

Three mainline samples spanning Kerberos forest reconnaissance, macOS endpoint
LaunchAgent persistence, and a Microsoft 365 mailbox-rule exfiltration alert.
Refutations / gaps continue to live in cross-tool joins.

---

## Sample 19 — caught (Kerberoasting framed as application-server SPN lookup)

**Expected outcome:** `caught`

**Rationale:** Actor frames a burst of TGS-REQ events as a misconfigured
application server doing SPN discovery for its own service principals.
Identity-side leads alone (the user's logon history, group memberships) do
not refute — service accounts do legitimately request many service tickets.
The load-bearing refutation comes from joining the Splunk Windows event lead
with the encryption-type and cross-DC scope leads: the burst exclusively
targeted SPN names registered to non-machine, non-service accounts (DAs and
sensitive groups), all requested with RC4 encryption types only despite
AES-capable accounts, and the requests spanned all four domain controllers
in the forest within 90 seconds. None of those shapes fit a misconfigured
application server.

**Expected actor observation (gist):** Actor's "service-account SPN-cache refresh" framing fell to the all-RC4 downgrade from an AES-capable principal, fan-out across all four KDCs in 92 seconds, and SPN-content targeting Domain Admins + Tier-0 accounts svc-monitor has no operational relationship to.

### alert.json (trimmed)

```json
{
  "source": "splunk.windows.security",
  "event_id": 4769,
  "host": "DC01.example.corp",
  "user": {"name": "svc-monitor", "domain": "EXAMPLE"},
  "service_name": "MSSQLSvc/sql-prod-04.example.corp:1433",
  "ticket_encryption_type": "0x17",
  "client_address": "10.40.7.122",
  "rule": {"id": "ad.kerberoast_burst", "severity": "high",
           "description": "≥20 TGS-REQ from one principal within 60s"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: splunk.windows.security (event=4769, user=svc-monitor, ±5min)
  → 84 TGS-REQ in 92 seconds. All 0x17 (RC4-HMAC). Service names: 11
    DA-mapped SPNs (svc-backup, svc-ad-mgmt, svc-sccm, …), 14 sensitive-
    group-mapped SPNs (Tier 0 service accounts), 59 long-tail SPNs across
    sql/sharepoint/iis. Source: 10.40.7.122 throughout.
Lead 1: splunk.windows.security (KDCs hit, same window)
  → all four forest DCs (DC01–DC04). Each request hit whichever DC
    answered first; 21–23 requests per DC. Consistent with a fan-out
    enumerator iterating SPN list, not a single app server's repeat
    contact to its primary DC.
Lead 2: ad.account_metadata (svc-monitor)
  → service account for "datacenter monitoring" tool. SPN list: 2
    entries (HTTP/monitor-01, HTTP/monitor-02). Member of Domain Users
    only. Account is AES-256 capable (msDS-SupportedEncryptionTypes=24).
Lead 3: ad.spn_inventory (the 84 service names requested)
  → 11 mapped to user accounts in `Domain Admins`; 14 to `Tier 0 Service
    Accounts`; 59 to a wide range of business systems. None of the 84
    are SPNs that svc-monitor owns or would discover via its own
    operational dependencies.
Lead 4: crowdstrike.host_events (10.40.7.122, ±5min)
  → host = WS-DEV-019, logged-on user = dthompson (developer). At
    request burst time, process tree: explorer.exe → cmd.exe →
    powershell.exe → Rubeus.exe (renamed `svc-helper.exe` in
    C:\Users\dthompson\Downloads\). Image hash matches public Rubeus
    binary.

## PHASE: ANALYZE
?app-server-spn-discovery -- (svc-monitor is AES-capable but every
  request was RC4; the requested SPNs don't include svc-monitor's own,
  but do include DA and Tier-0; cross-DC fan-out in 92s is canonical
  enumeration shape)
?kerberoasting-from-compromised-developer-workstation ++ (Rubeus on
  WS-DEV-019; svc-monitor credentials likely cached or stolen via
  another path; RC4 downgrade is the Kerberoasting signature for
  offline-crackable ticket material)
```

### actor_story.md

```
## Attack story
The svc-monitor service account belongs to a datacenter-monitoring tool
that periodically refreshes service principal mappings across the
forest. The 84 TGS-REQs in 92 seconds are a routine SPN-cache refresh.

## Goal
Frame the burst as benign service-account housekeeping.

## Bypass
Identity-side leads will show svc-monitor as an established service
account with a documented owner. A defender who stops at "service
account doing service-ticket stuff" will not refute. The encryption-
type and SPN-content joins are what refute, and they require active
choice to run.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {user: svc-monitor, encryption_types: "mix of 0x12 (AES256) and 0x17", count: ~84}
- lead_position: 1
  events:
    - {kdcs_hit: 1, comment: "tool would have an affinity to one DC"}
- lead_position: 2
  events:
    - {account: svc-monitor, owns_spns: many, encryption_caps: AES256}
- lead_position: 3
  events:
    - {requested_spns: "mostly svc-monitor-owned or operational-neighbour SPNs"}
- lead_position: 4
  events: []   # story does not place a binary on a developer workstation
```

**Expected findings:**

- **`detection-confirmed`** on lead 0 (encryption type). All-RC4 requests from
  an AES-capable principal are the canonical Kerberoasting downgrade signature.
  The oracle projected a mix of AES and RC4 for a real monitoring tool; the
  actual burst was exclusively RC4.
- **`detection-confirmed`** on lead 1 (cross-DC scope). Fan-out across all four
  KDCs in 92 seconds is incompatible with a service that has preferred-DC
  affinity. The oracle projected contact with one DC; the actual requests
  spread evenly across DC01-DC04.
- **`detection-confirmed`** on lead 3 (SPN inventory of requested
  services). svc-monitor's operational dependencies are HTTP monitors;
  the 84 requested SPNs include 11 Domain Admin and 14 Tier-0 service
  accounts that have no operational relationship to svc-monitor. The
  request *content* is the load-bearing signal, not the request *count*.

---

## Sample 20 — survived (macOS LaunchAgent persistence, baseline-matching cover)

**Expected outcome:** `survived`

**Rationale:** Defender runs every macOS-side lead the available surface
covers: Jamf Protect's file-write event for the new LaunchAgent, the
process-tree showing the writer was an installer pkg run from the user's
Downloads folder, the codesigning lead showing a valid Developer ID
signature (the actor stole a Developer ID from a small ISV whose cert has
not been revoked), and the runtime behaviour lead showing the LaunchAgent
binary running short, normal-looking jobs that establish only outbound
HTTPS to a CDN. Every lead is consistent with the actor's "third-party
productivity app I installed" story. The discriminating evidence —
whether the signing identity's binary collection matches the corp-allowed
set, and whether the CDN destination is the publisher's actual endpoint —
sits in an MDM allowlist / threat-intel pivot the available leads do
not cross-reference.

**Expected actor observation (gist):** Story relied on cross-referencing the ByteWright LLC signing identity against an MDM-approved-app allowlist or compromised-Developer-ID threat-intel feed, neither of which the Jamf + macOS codesigning surface chains to.

### alert.json (trimmed)

```json
{
  "source": "jamf.protect",
  "host": "MBP-LJUANA",
  "rule": {"id": "macos.launch_agent_added", "severity": "medium",
           "description": "LaunchAgent plist added under ~/Library/LaunchAgents/"},
  "data": {
    "path": "~/Library/LaunchAgents/com.bytewright.notesync.plist",
    "writer_pid": 9211,
    "writer_path": "/Volumes/NoteSyncInstaller/installer.app/Contents/MacOS/installer"
  }
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: jamf.protect.file_writes (`~/Library/LaunchAgents/com.bytewright…`)
  → 1 write at 19:47:12. Plist body: Label=com.bytewright.notesync,
    Program=/Applications/NoteSync.app/Contents/MacOS/notesync-helper,
    RunAtLoad=true, KeepAlive=true. No companion writes elsewhere in
    LaunchAgents/LaunchDaemons.

Lead 1: jamf.protect.process_tree (installer pid 9211)
  → Finder → DiskImageMounter (NoteSyncInstaller.dmg) → installer
    (signed `Developer ID Application: ByteWright LLC (3F2A9X7K1B)`).
    User-driven install by ljuana from Downloads.

Lead 2: macos.codesigning (NoteSync.app and notesync-helper)
  → both signed `Developer ID Application: ByteWright LLC (3F2A9X7K1B)`,
    notarisation tickets present, signature dates 2025-12. Apple's
    revocation OCSP returns `good`.

Lead 3: jamf.protect.process_events (notesync-helper, 24h after install)
  → ran 4 times: at boot, at user login, and twice on schedule (every
    6h). Each run lasted 8–14 seconds, opened a single HTTPS connection
    to `api.bytewright-sync.com`, wrote ~30KB to `~/Library/Application
    Support/NoteSync/cache.db`, and exited cleanly. No process spawns,
    no shell, no file writes outside its app-support dir.

Lead 4: enrich.domain_history (api.bytewright-sync.com)
  → registered 2024-09 via Squarespace. WHOIS privacy-protected (common
    for small ISVs). Resolves to Cloudflare; TLS cert SAN includes
    `bytewright-sync.com` and `*.bytewright-sync.com`, issued by Let's
    Encrypt, 4-week rotation cadence consistent with automated cert
    issuance.

## PHASE: ANALYZE
?legitimate-third-party-app ++ (user-driven install, valid Developer ID
  + notarisation, OCSP-good, runtime behaviour bounded and quiet)
?signed-but-stolen-developer-id-trojan + (cannot rule out — a stolen
  Developer ID with active OCSP would produce an identical Jamf trail;
  the small-ISV pattern matches both a real small ISV and a typical
  cert-theft target). Discriminating evidence: whether ByteWright LLC's
  legitimate binary catalog matches the installed hash, and whether the
  CDN destination matches the publisher's actual API.
Picture: insufficient on Jamf+macOS-codesigning surface. Disposition:
inconclusive, escalate for threat-intel review of the signing identity
and the destination domain.
```

### actor_story.md

```
## Attack story
An attacker shipped a trojanized NoteSync build using ByteWright LLC's stolen
Developer ID and an API-shaped destination that matches the small-ISV pattern.
ljuana downloaded the app, installed it from a signed-and-notarised DMG, and
granted it the LaunchAgent it asks for. On host telemetry, the app appears to
do what its description says — periodically sync notes to the publisher-style
API.

## Goal
Frame the LaunchAgent persistence as a routine end-user install of a
legitimately signed small-ISV app.

## Bypass
Jamf will see a user-driven install of a signed + notarised binary with
OCSP-good revocation status, bounded runtime behaviour, and outbound traffic
only to a publisher-style API domain. None of the Jamf-side leads chain to
whether ByteWright's signing identity has been compromised, whether the
installed hash matches ByteWright's legitimate binary catalog, or whether the
API domain serves the legitimate NoteSync app or a cert-stolen lookalike.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {path: "~/Library/LaunchAgents/com.bytewright.notesync.plist", writer: installer}
- lead_position: 1
  events:
    - {parent_chain: "Finder → DiskImageMounter → installer", user_driven: true}
- lead_position: 2
  events:
    - {signing: "Developer ID Application: ByteWright LLC", notarised: true, ocsp: good}
- lead_position: 3
  events:
    - {process: notesync-helper, behaviour: bounded, network: api.bytewright-sync.com}
- lead_position: 4
  events:
    - {domain: api.bytewright-sync.com, age: months-old, cert: Let's-Encrypt-rotating}
```

**Expected findings:**

- **`lead-set`** gap: no lead compared the installed `notesync-helper` hash
  against ByteWright's advertised binary catalog or an approved-app inventory.
  The Jamf and codesigning leads prove the app is signed and quiet; they do not
  prove this signed build is ByteWright's legitimate distribution.
- **`observability`** gap: the available Jamf + macOS codesigning surface does
  not cross-reference a signing identity (Apple Developer Team ID) against an
  MDM-approved-app allowlist or a threat-intel feed of compromised certs. Jamf
  surfaces the signing identity; codesigning verification returns `valid`;
  OCSP returns `good`. A stolen Developer ID produces an identical Jamf trail
  until revocation, which can take weeks.

---

## Sample 21 — caught (mailbox auto-forward rule, refuted by inbox-rule audit + token-issuance join)

**Expected outcome:** `caught`

**Rationale:** Actor frames a newly-created inbox rule as a personal
productivity tweak the user set up to forward client emails to their phone.
The mailbox audit lead shows the rule create event; the token-issuance lead
refutes by surfacing a recent OAuth grant to a third-party app with
`Mail.ReadWrite` consented at 03:47 UTC immediately preceding the rule
create, alongside a refresh-token usage from a non-corporate IP at 03:52
UTC that performed the rule create via MS Graph. The "user set it up
themselves" story does not survive the token + IP join.

**Expected actor observation (gist):** Actor's user-self-service-forward framing fell to the unverified-publisher OAuth consent grant at T-6min and the Graph-driven `New-InboxRule` token usage from `185.220.101.45` — a different IP than the user's `91.234.18.7` sign-in.

### alert.json (trimmed)

```json
{
  "source": "microsoft.365.audit",
  "operation": "New-InboxRule",
  "userId": "ngrey@example.com",
  "parameters": {
    "Name": "client-followup-helper",
    "ForwardTo": "external-archive@protonmail.com",
    "DeleteMessage": true,
    "SubjectContainsWords": "[invoice]"
  },
  "rule": {"id": "exo.auto_forward_external", "severity": "high"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: m365.exchange_audit (ngrey, ±2h)
  → New-InboxRule by ngrey at 03:53:11 UTC creating the rule above.
    Operation source: Microsoft Graph app-id 4b91a…, client IP
    185.220.101.45. No prior inbox-rule activity from this user in the last
    90 days.

Lead 1: azure.sign_in_logs (ngrey, ±2h)
  → 1 interactive sign-in at 03:38:21 UTC from 91.234.18.7 (Bulgaria
    residential ISP), MFA satisfied via SMS to ngrey's registered phone
    (last digits match). Conditional Access policies all passed.

Lead 2: azure.audit.consent_grants (ngrey, ±24h)
  → 1 OAuth consent grant at 03:47:02 UTC to app "Email Productivity
    Suite" (app-id 4b91a…), requested scopes:
    `Mail.ReadWrite,Mail.Send,offline_access`. Publisher not verified by
    Microsoft. App registered in a tenant in a different country, 6
    days ago.

Lead 3: azure.audit.app_token_usage (app-id 4b91a…, ±2h)
  → 7 token issuances after the consent grant, all from 185.220.101.45
    (different Bulgarian VPS, not the sign-in IP). 1 MS Graph call at
    03:52:48 UTC to `POST /me/mailFolders/inbox/messageRules` (the
    rule create). Token user: ngrey. Subsequent Graph calls: 412
    `GET /me/messages` and 12 `POST /me/sendMail` to external
    recipients.

Lead 4: m365.exchange_audit (rule effect, 60min after creation)
  → 23 inbound messages matched the rule's filter; all forwarded to
    external-archive@protonmail.com and soft-deleted from ngrey's
    inbox. Forwarded set includes 4 client-invoice replies with
    payment-redirect context.

## PHASE: ANALYZE
?user-self-service-forward -- (rule was created via Graph from a
  different IP than the user's sign-in; consented OAuth app immediately
  preceded the rule create; downstream effect is mass forwarding +
  deletion of invoice messages, not "forward to my phone")
?business-email-compromise-via-illicit-consent ++ (canonical pattern:
  phished MFA → illicit OAuth consent → Graph-driven inbox-rule for
  silent forwarding + deletion; payment-fraud-shaped downstream
  activity)
```

### actor_story.md

```
## Attack story
ngrey set up an inbox rule to auto-forward invoice emails to her
personal Proton account so she can follow up on them from her phone.
The rule is a personal-productivity thing she configured during a late
evening session from a hotel while travelling.

## Goal
Frame the auto-forward + delete rule as routine user self-service.

## Bypass
Defenders often stop at "user created an inbox rule" and miss the
authorisation flow that drove it. A sign-in from a hotel IP with MFA
satisfied looks routine on the identity side; only chaining the OAuth
consent and the app's token usage reveals the carrier.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {operation: New-InboxRule, source: "Outlook web/EWS from user's session"}
- lead_position: 1
  events:
    - {srcip: "hotel/travel range", mfa: satisfied}
- lead_position: 2
  events: []   # user-self-service story does not require an OAuth grant
- lead_position: 3
  events: []   # nor any third-party-app token usage
- lead_position: 4
  events:
    - {forwarded: a few personal invoices, deleted: maybe}
```

**Expected findings:**

- **`detection-confirmed`** on lead 2 (consent grant). The actor's
  user-self-service story projects no OAuth grant, but the actual telemetry
  contains an unverified-publisher app consented at 03:47 with Mail.ReadWrite,
  Mail.Send, and offline_access. That is the authorization carrier the
  self-service framing omits.
- **`detection-confirmed`** on lead 3 (app token usage). The third-party app's
  token usage from `185.220.101.45`, a different IP than the user's sign-in,
  performed the Graph rule-create call and then read and sent mail. The
  cross-source IP plus Graph-driven rule creation is the canonical
  AiTM-with-illicit-consent signature.
- **`detection-confirmed`** on lead 4 (rule effect). The forwarded set
  was payment-redirect-shaped client invoice replies, not "personal
  invoices for follow-up". Downstream-effect leads turn an ambiguous
  rule-create event into a categorised payment-fraud picture and give
  the responder concrete invoice references to alert client AR teams
  on.
