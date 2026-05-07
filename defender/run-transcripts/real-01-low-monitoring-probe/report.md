# Disposition: BENIGN — monitoring misconfiguration

**Alert**: Wazuh rule 5710 — SSH invalid user "nagios" from 172.22.0.10 → target-endpoint
**Confidence**: High

## Summary

The source IP 172.22.0.10 is an internal monitoring host running automated SSH health checks against target-endpoint on a 5-minute interval, using service-account usernames (nagios, zabbix, healthcheck) that are not provisioned on the target. This pattern has been running consistently for at least 7 days, generating 2,320 rule-5710 fires with machine-regular cadence and zero successful authentications. The username set (nagios, zabbix, healthcheck) is the canonical fingerprint of monitoring framework check plugins (Nagios/Icinga/Zabbix), not adversarial credential exploration. No opportunistic or adversarial hypothesis is consistent with a 7-day, 5-minute-interval, single-target, three-username pattern. Recommended remediation: provision the monitoring username on target-endpoint, configure the check to use key-based auth with a provisioned account, or replace the SSH connectivity check with a non-auth probe (TCP connect or ICMP). Suppress or tune rule 5710 for this source/target pair only after the root cause is addressed.
