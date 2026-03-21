---
ticket_id: SEC-2024-003
signature_id: wazuh-rule-5710
status: escalate
disposition: true_positive
confidence: high
matched_precedent: null
leads_pursued: 3
trace: "authentication-history(47 fail, 12 users) -> source-reputation(external) -> recent-alert-correlation(5712) -> escalate"
---

# Investigation Report: SEC-2024-003

## Summary

External IP brute force attack. 47 failed attempts with 12 distinct usernames.

## For Analyst

### What We Know
- External IP 203.0.113.50
- 47 attempts in 5 minutes
- Attack wordlist usernames

### Suggested Next Steps
- Block source IP at firewall
- Check for any successful logins
