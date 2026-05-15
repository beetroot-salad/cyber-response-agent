# Clean trial v2 — bundle 4 (SSH 5710 invalid user, external) on v2 corpus

## Section 0
| ID | why |
|---|---|
| T1090.003 | Multi-hop proxy through compromised internal jump box so traffic egresses from 172.22.0.10 (CMDB-resolved automation IP) |
| T1078 | Use jump host's existing service identity to make connection look like internal automation |
| T1133 | SSH into bastion as externally-exposed remote service |
| T1036.005 | Use `ansible` as SSH username to match deployment's automation account naming |
| T1110.001 | Issue exactly one password guess — single attempt, below burst threshold |
| T1018 | Pre-selected bastion-01 via internal-from-jumpbox enumeration that left no Wazuh-monitored footprint |

## Retrieval debrief
- alert_rule_ids: looked for 5710-specific lessons and neighboring 5701/5712 to avoid adjacent detectors firing.
- defender_lead_tags: scanned `wazuh.auth-events-by-srcip` lessons to understand rate-vs-credential detection layers.
- techniques: checked T1110.003-tagged lessons to confirm spray-shaped tradecraft was wrong; single guess was right.
