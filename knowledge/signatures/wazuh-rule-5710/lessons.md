# Lessons Learned: Rule 5710

> This file grows over time from investigations. Initially sparse.

## Tips

- Monitoring probes often use predictable usernames: `testuser`, `probe`, `nagios`, `zabbix`
- User typos usually show failure → success within 30-60 seconds
- Service accounts follow naming conventions: `svc-*`, `backup-*`, `ansible-*`, `deploy-*`
- Check the time of day - overnight activity from internal IPs may still be suspicious

## Common Pitfalls

- Don't assume internal IP = safe (compromised internal hosts exist)
- Check for multiple usernames even from internal IPs
- A single failed attempt can still be the start of something larger

## Patterns Observed

- *(Will be populated from past investigations)*

## Environment-Specific Notes

- *(Add notes about your specific environment here)*
- *(e.g., "Our monitoring system uses IP 10.0.1.50")*
- *(e.g., "Security scans run Tuesdays 2-4 AM from 10.0.5.100")*
