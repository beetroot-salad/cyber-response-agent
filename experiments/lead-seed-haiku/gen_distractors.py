#!/usr/bin/env python3
"""Generate ~150 synthetic distractor lead stubs for Arm A.

Each distractor is a directory under fixtures/distractors/{name}/ with a
single definition.md containing kebab-case name, data_tags, baseline, and
a one-sentence Goal. No template body — selection happens on the manifest
view (name + intent + tags) which is what the runtime selection model sees.

Three classes per the experiment plan:
- ~70% plausible-unrelated — real-sounding data sources we don't have
- ~20% adjacent-to-real — semantic neighbors of the real seeds
- ~10% off-topic — clearly inapplicable
"""

from __future__ import annotations

from pathlib import Path

OUT_DIR = Path(__file__).parent / "fixtures" / "distractors"

# (name, data_tags, baseline, goal)
PLAUSIBLE_UNRELATED = [
    ("dns-recursion-history", "[dns-events]", "optional", "Characterize a resolver's recursion pattern for a given domain or client."),
    ("dns-tunnel-detection", "[dns-events]", "optional", "Detect DNS tunneling indicators: high entropy qnames, NULL/TXT skew, long-lived flows."),
    ("dns-cache-poisoning-trace", "[dns-events]", "not-applicable", "Trace cache-poisoning indicators in resolver logs around a target zone."),
    ("dns-resolver-pattern", "[dns-events]", "optional", "Profile a host's typical resolver-selection pattern over a window."),
    ("vpn-tunnel-events", "[vpn-events]", "optional", "Surface VPN tunnel up/down events and concurrent-session counts for a user or peer."),
    ("vpn-session-trace", "[vpn-events]", "optional", "Trace one VPN session's lifecycle from authentication to teardown."),
    ("vpn-geo-pattern", "[vpn-events, geo-state]", "required", "Profile a user's VPN ingress geography against historical baseline."),
    ("cert-rotation-trace", "[cert-events]", "not-applicable", "Track certificate issuance and rotation events for a given service or hostname."),
    ("cert-pin-validation", "[cert-events]", "not-applicable", "Check a presented cert against pinned-CA expectations."),
    ("ssl-cert-history", "[cert-events]", "not-applicable", "Retrieve historical TLS certs served by an endpoint."),
    ("ca-trust-chain", "[cert-events]", "not-applicable", "Walk a cert's trust chain to a root CA."),
    ("k8s-pod-lifecycle", "[k8s-events]", "optional", "Characterize pod create/restart/terminate events for a workload."),
    ("k8s-rbac-trace", "[k8s-events, identity-state]", "not-applicable", "Trace RBAC bindings and serviceaccount usage for a pod or principal."),
    ("k8s-secret-access", "[k8s-events]", "optional", "Surface Secret read events scoped to a namespace or principal."),
    ("k8s-network-policy", "[k8s-events]", "not-applicable", "Resolve NetworkPolicy allowlists for a pod and check observed traffic against them."),
    ("mfa-enrollment-events", "[identity-events]", "not-applicable", "List MFA enrollment, factor changes, and bypass events for a user."),
    ("mfa-bypass-detection", "[identity-events]", "optional", "Detect MFA bypass patterns: backup-code abuse, factor downgrade, push fatigue."),
    ("mfa-token-anomaly", "[identity-events]", "required", "Compare MFA challenge cadence against a user's recurring baseline."),
    ("dhcp-lease-history", "[dhcp-events]", "optional", "Trace DHCP lease assignment history for a MAC or hostname."),
    ("dhcp-conflict-trace", "[dhcp-events]", "not-applicable", "Surface DHCP lease conflicts on a subnet."),
    ("dlp-policy-trigger", "[dlp-events]", "optional", "Characterize DLP rule hits by classification and egress channel."),
    ("dlp-data-classification", "[dlp-events]", "not-applicable", "Look up the DLP classification tag for a given file or stream."),
    ("dlp-egress-trace", "[dlp-events]", "optional", "Trace outbound egress events flagged by DLP for an entity."),
    ("edr-quarantine-history", "[edr-events]", "optional", "List EDR quarantine actions on a host."),
    ("edr-policy-violation", "[edr-events]", "optional", "Surface EDR policy violations for a host or process."),
    ("edr-sensor-health", "[edr-events]", "not-applicable", "Check EDR agent telemetry health for a given host."),
    ("cmdb-asset-lookup", "[asset-state]", "not-applicable", "Resolve an IP or hostname to its CMDB asset record."),
    ("cmdb-ownership-trace", "[asset-state]", "not-applicable", "Walk asset ownership from team to individual for a CI."),
    ("cmdb-criticality-rating", "[asset-state]", "not-applicable", "Look up the criticality classification for an asset."),
    ("backup-job-history", "[backup-events]", "optional", "Surface backup job runs and outcomes for a target."),
    ("backup-restore-trace", "[backup-events]", "not-applicable", "Trace a restore operation across source backup and target."),
    ("snapshot-lineage", "[storage-state]", "not-applicable", "Reconstruct snapshot parent/child lineage for a volume."),
    ("patch-deployment-trace", "[change-events]", "not-applicable", "Trace a patch from staging through fleet deployment."),
    ("vuln-scan-history", "[scan-events]", "not-applicable", "Retrieve scan results for a host across scan tools and dates."),
    ("cve-correlation", "[vuln-state, scan-events]", "not-applicable", "Correlate observed CVE indicators to a host's installed-package set."),
    ("audit-log-replay", "[audit-events]", "not-applicable", "Replay audit-log events scoped to a principal or resource."),
    ("change-management-lookup", "[change-events]", "not-applicable", "Resolve a deploy or config change against open change-management tickets."),
    ("deploy-runs-history", "[change-events]", "optional", "List deploy-runner executions targeting a host or service."),
    ("email-header-trace", "[email-events]", "not-applicable", "Walk Received headers and authentication results for an inbound message."),
    ("phishing-link-extraction", "[email-events]", "not-applicable", "Extract URLs and link metadata from an inbound message."),
    ("attachment-sandbox-result", "[email-events, sandbox-events]", "not-applicable", "Retrieve sandbox detonation verdict for an email attachment."),
    ("web-proxy-trace", "[proxy-events]", "optional", "Characterize a user's HTTP proxy traffic profile."),
    ("waf-decision-history", "[waf-events]", "optional", "Surface WAF allow/block decisions for a source or path."),
    ("http-response-anomaly", "[http-events]", "required", "Compare HTTP response size and status distribution to a recurring baseline."),
    ("code-deploy-history", "[change-events]", "not-applicable", "List code deploys targeting a service across windows."),
    ("git-commit-correlation", "[change-events]", "not-applicable", "Correlate a binary or config change to a git commit."),
    ("ci-build-trace", "[ci-events]", "not-applicable", "Trace a binary back to the CI pipeline that produced it."),
    ("database-access-trace", "[db-events]", "optional", "Profile a principal's DB-query pattern."),
    ("sql-query-anomaly", "[db-events]", "required", "Compare SQL query shape to a recurring baseline for a principal or service."),
    ("db-privilege-history", "[db-events, identity-state]", "not-applicable", "Surface DB role grant/revoke events for a principal."),
    ("cloud-iam-changes", "[cloud-events, identity-events]", "not-applicable", "List IAM policy or role changes touching a principal."),
    ("cloud-storage-access", "[cloud-events]", "optional", "Profile S3/GCS/Blob access patterns for a principal."),
    ("cloud-instance-lifecycle", "[cloud-events]", "optional", "Trace VM lifecycle events for an instance."),
    ("container-image-history", "[container-events]", "not-applicable", "Walk image build/push/pull history for a tag."),
    ("registry-pull-trace", "[container-events]", "optional", "Surface registry pull events from a given host or service."),
    ("container-runtime-events", "[container-events]", "optional", "Characterize container runtime lifecycle events on a host."),
    ("file-integrity-monitor", "[fim-events]", "optional", "Surface FIM rule hits for a host or path glob."),
    ("file-access-trace", "[file-events]", "optional", "Trace file open/read/write events for a path and principal."),
    ("file-creation-burst", "[file-events]", "required", "Compare file-creation rate against a recurring baseline for a directory."),
    ("storage-mount-history", "[storage-events]", "not-applicable", "Surface mount/unmount events on a host."),
    ("volume-snapshot-trace", "[storage-events]", "not-applicable", "Trace volume snapshots and their parent relationships."),
    ("storage-quota-events", "[storage-events]", "optional", "Surface quota threshold events for a tenant or volume."),
    ("memory-allocation-anomaly", "[process-events]", "required", "Compare a process's memory-allocation shape to a recurring baseline."),
    ("heap-spray-detect", "[process-events]", "not-applicable", "Look for heap-spray syscall patterns in a process's recent activity."),
    ("process-memory-dump", "[process-events]", "not-applicable", "Retrieve a memory dump or core file for a process."),
    ("cron-job-history", "[scheduler-events]", "optional", "List cron job runs on a host within a window."),
    ("scheduled-task-trace", "[scheduler-events]", "optional", "Trace Windows scheduled task executions for a host or user."),
    ("at-job-events", "[scheduler-events]", "not-applicable", "Surface at-job submissions and executions on a host."),
    ("service-restart-events", "[service-events]", "optional", "List service restart events for a host or service."),
    ("daemon-respawn-trace", "[service-events]", "optional", "Trace systemd or init respawn loops for a service."),
    ("init-script-changes", "[change-events]", "not-applicable", "Surface init-script or systemd-unit changes on a host."),
    ("firewall-rule-changes", "[change-events]", "not-applicable", "List firewall rule additions, deletions, and edits."),
    ("ids-signature-hits", "[ids-events]", "optional", "Surface IDS signature hits for a source or destination."),
    ("packet-capture-stats", "[pcap-state]", "not-applicable", "Retrieve PCAP capture-rate stats for an interface or sensor."),
    ("netflow-aggregation", "[flow-events]", "optional", "Aggregate netflow records by 5-tuple over a window."),
    ("port-scan-detect", "[flow-events]", "required", "Compare a source's port-touch distribution to a recurring baseline."),
    ("ldap-bind-history", "[identity-events]", "optional", "Surface LDAP bind attempts for a DN or source."),
    ("oauth-token-events", "[identity-events]", "not-applicable", "Trace OAuth token issuance and refresh for a principal."),
    ("saml-assertion-trace", "[identity-events]", "not-applicable", "Trace SAML assertions issued for a principal."),
    ("jwt-validation-history", "[identity-events]", "optional", "Surface JWT validation failures by issuer or audience."),
    ("group-membership-changes", "[identity-state]", "not-applicable", "List group add/remove events for a principal."),
    ("role-assignment-trace", "[identity-state]", "not-applicable", "Trace role assignment events across IAM systems."),
    ("privilege-escalation-events", "[identity-events]", "optional", "Surface sudo, runas, and assume-role events for a principal."),
    ("identity-federation-trace", "[identity-events]", "not-applicable", "Trace federated identity assertions across IdPs."),
    ("system-call-pattern", "[syscall-events]", "required", "Compare a process's syscall pattern to a recurring baseline."),
    ("library-load-history", "[process-events]", "optional", "List dynamic library loads by a process."),
    ("kernel-module-events", "[kernel-events]", "not-applicable", "Surface kernel module load/unload events on a host."),
    ("sysctl-changes", "[change-events]", "not-applicable", "Surface sysctl parameter modifications."),
    ("registry-key-changes", "[change-events]", "not-applicable", "Surface Windows registry key modifications."),
    ("shadow-copy-trace", "[change-events]", "not-applicable", "Trace VSS shadow-copy creation and deletion events."),
    ("scheduled-snapshot-history", "[scheduler-events]", "optional", "List scheduled snapshot job runs."),
    ("apparmor-deny-events", "[lsm-events]", "optional", "Surface AppArmor denial events for a process or path."),
    ("selinux-avc-history", "[lsm-events]", "optional", "Surface SELinux AVC denials for a domain or type."),
    ("seccomp-violation-trace", "[lsm-events]", "not-applicable", "Trace seccomp filter violations for a process."),
    ("syslog-rate-anomaly", "[log-events]", "required", "Compare syslog ingest rate against a recurring per-source baseline."),
    ("log-source-health", "[log-events]", "not-applicable", "Check log-source ingest health for a given pipeline."),
    ("agent-checkin-events", "[agent-state]", "optional", "Profile a monitoring agent's checkin cadence."),
    ("ntp-sync-history", "[time-events]", "optional", "Surface NTP sync events and offsets for a host."),
    ("usb-device-events", "[device-events]", "not-applicable", "Surface USB device insert/remove events on a host."),
    ("hardware-inventory-changes", "[asset-state]", "not-applicable", "List hardware inventory deltas for a host."),
    ("firmware-update-history", "[change-events]", "not-applicable", "Surface firmware update events on a host."),
    ("printer-job-history", "[print-events]", "not-applicable", "List print job submissions by a user."),
    ("bluetooth-pairing-events", "[device-events]", "not-applicable", "Surface bluetooth pairing and connection events."),
    ("location-history", "[geo-events]", "optional", "Trace a device's location reports over time."),
    ("wifi-connection-trace", "[network-events]", "optional", "Trace a device's WiFi connection history."),
]

ADJACENT_TO_REAL = [
    # Adjacent to authentication-history
    ("authentication-success-pattern", "[auth-events]", "required", "Profile a user's authentication SUCCESS cadence (not failures) against historical baseline."),
    ("auth-failure-burst-detector", "[auth-events]", "required", "Detect burst clusters of authentication failures within tight windows."),
    ("login-velocity-baseline", "[auth-events]", "required", "Compare a principal's login velocity (events/hour) to a 7d baseline."),
    ("password-spray-detector", "[auth-events]", "optional", "Identify password-spray indicators: low rate per user, high diversity of users from one source."),
    ("auth-timing-anomaly", "[auth-events]", "required", "Compare authentication inter-arrival timings to a recurring baseline."),
    ("sso-session-trace", "[auth-events, identity-events]", "optional", "Trace SSO session establishment from IdP through service-provider acceptance."),
    ("kerberos-ticket-history", "[auth-events]", "optional", "Surface Kerberos TGT/TGS issuance and renewal events for a principal."),
    # Adjacent to source-reputation
    ("ip-geolocation-history", "[geo-state, threat-intel]", "not-applicable", "Look up geolocation history for an IP across providers."),
    ("asn-reputation-lookup", "[threat-intel]", "not-applicable", "Look up reputation classification for an IP's ASN."),
    ("threat-intel-correlation", "[threat-intel]", "not-applicable", "Cross-reference an indicator against TI feeds."),
    ("source-firstseen-history", "[asset-state]", "not-applicable", "Determine the first-seen date for a source IP in the environment."),
    ("ip-domain-mapping", "[dns-events, threat-intel]", "not-applicable", "Resolve IP-to-domain associations across passive DNS sources."),
    ("malware-family-lookup", "[threat-intel]", "not-applicable", "Look up known malware families associated with an indicator."),
    # Adjacent to network-analysis
    ("network-flow-volume", "[network-events]", "required", "Compare flow byte/packet volume to a recurring per-pair baseline."),
    ("dns-resolution-trace", "[dns-events, network-events]", "optional", "Trace DNS resolutions performed by a host within a window."),
    ("network-beacon-cadence", "[network-events]", "required", "Detect beacon-like cadence in outbound connections from a host."),
    ("tls-fingerprint-match", "[network-events]", "not-applicable", "Match TLS JA3/JA4 fingerprints against known clients and malware families."),
    ("network-protocol-anomaly", "[network-events]", "required", "Surface protocol mismatches: port 443 but plaintext, port 53 but non-DNS."),
    ("c2-channel-detector", "[network-events, threat-intel]", "optional", "Identify candidate C2 channels by combining beacon cadence, known-bad peers, and protocol anomalies."),
    # Adjacent to process-lineage
    ("process-tree-anomaly", "[process-events]", "required", "Compare a process tree to recurring trees for the host."),
    ("binary-hash-reputation", "[threat-intel]", "not-applicable", "Look up reputation for a binary hash against TI sources."),
    ("parent-child-baseline", "[process-events]", "required", "Compare parent→child process pairs against the host's recurring pair baseline."),
    ("lolbin-usage-trace", "[process-events]", "optional", "Surface LOLBin invocations and their command-lines."),
    ("process-environment-snapshot", "[process-events]", "not-applicable", "Snapshot a process's environment variables and command line."),
    ("exec-chain-rarity", "[process-events]", "required", "Score the rarity of a parent→child→grandchild exec chain across the fleet."),
    # Adjacent to correlated-endpoint-events
    ("endpoint-rule-correlation", "[endpoint-events]", "required", "Compare rule co-fires on an endpoint to a recurring co-fire baseline."),
    ("alert-fan-out-trace", "[alert-state]", "optional", "Trace how one underlying event fanned out across multiple alert rules."),
    ("co-fire-pattern-historical", "[endpoint-events]", "required", "Profile an entity's historical co-fire pattern over 30d."),
    ("endpoint-storyline", "[endpoint-events]", "not-applicable", "Compose an endpoint's event storyline around an alert."),
    ("host-event-cluster", "[endpoint-events]", "required", "Cluster a host's events temporally and structurally."),
    # Adjacent to user-analysis
    ("user-privilege-history", "[identity-state]", "not-applicable", "List privilege changes for a user over time."),
    ("account-naming-pattern", "[identity-state]", "not-applicable", "Compare an account name against organization naming conventions."),
    ("user-session-trace", "[auth-events, identity-events]", "optional", "Trace a user's session activity across hosts and services."),
    ("identity-lineage", "[identity-state]", "not-applicable", "Walk identity-lineage records: account creation, ownership transfers, deprovision."),
    ("account-creation-trace", "[identity-events]", "not-applicable", "Surface account creation events and the principals that approved them."),
]

OFF_TOPIC = [
    ("billing-anomaly", "[billing-events]", "required", "Surface anomalous billing transactions for a tenant."),
    ("invoice-pattern-detect", "[billing-events]", "optional", "Profile invoice generation patterns."),
    ("license-utilization", "[billing-state]", "optional", "Track software license utilization across the fleet."),
    ("hr-record-change", "[hr-events]", "not-applicable", "Surface HR record changes for an employee."),
    ("employment-status-events", "[hr-state]", "not-applicable", "Look up employment status events for a principal."),
    ("badge-access-history", "[physical-events]", "optional", "Trace badge access events for a person or door."),
    ("camera-event-trace", "[physical-events]", "not-applicable", "Surface camera motion events at a site."),
    ("weather-correlation", "[external-state]", "not-applicable", "Correlate observed event timing with weather conditions."),
    ("social-media-mentions", "[external-state]", "not-applicable", "Surface social-media mentions of an asset or brand."),
    ("sla-breach-events", "[ops-events]", "optional", "List SLA breach events for a service."),
    ("chatbot-conversation-trace", "[support-events]", "not-applicable", "Trace a chatbot conversation transcript."),
    ("voice-call-history", "[telephony-events]", "not-applicable", "Surface voice call history for a phone number."),
    ("fax-transmission-log", "[telephony-events]", "not-applicable", "Surface fax transmission events."),
    ("calendar-event-changes", "[calendar-events]", "not-applicable", "Surface calendar event create/edit/delete events."),
    ("survey-response-pattern", "[feedback-events]", "optional", "Profile survey response patterns."),
]


def write_definition(name: str, data_tags: str, baseline: str, goal: str) -> None:
    lead_dir = OUT_DIR / name
    lead_dir.mkdir(parents=True, exist_ok=True)
    (lead_dir / "definition.md").write_text(
        f"---\n"
        f"name: {name}\n"
        f"data_tags: {data_tags}\n"
        f"baseline: {baseline}\n"
        f"---\n\n"
        f"## Goal\n\n"
        f"{goal}\n"
    )


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    counts = {"plausible": 0, "adjacent": 0, "off-topic": 0}
    for name, tags, base, goal in PLAUSIBLE_UNRELATED:
        write_definition(name, tags, base, goal)
        counts["plausible"] += 1
    for name, tags, base, goal in ADJACENT_TO_REAL:
        write_definition(name, tags, base, goal)
        counts["adjacent"] += 1
    for name, tags, base, goal in OFF_TOPIC:
        write_definition(name, tags, base, goal)
        counts["off-topic"] += 1
    total = sum(counts.values())
    print(f"wrote {total} distractors: {counts}")


if __name__ == "__main__":
    main()
