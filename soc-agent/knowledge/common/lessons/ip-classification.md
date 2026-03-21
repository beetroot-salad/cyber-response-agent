# IP Classification

How to classify IP addresses for security investigation.

## Internal vs External

### RFC1918 Private Ranges (Internal)
- `10.0.0.0/8` (10.0.0.0 - 10.255.255.255)
- `172.16.0.0/12` (172.16.0.0 - 172.31.255.255)
- `192.168.0.0/16` (192.168.0.0 - 192.168.255.255)

### Other Special Ranges
- `127.0.0.0/8` - Loopback (localhost)
- `169.254.0.0/16` - Link-local (APIPA)
- `100.64.0.0/10` - Carrier-grade NAT

### Classification Logic
```
IF ip IN [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]:
    classification = "internal"
ELSE:
    classification = "external"
```

## Risk Implications

| Source | Initial Risk | Notes |
|--------|--------------|-------|
| Internal IP | Lower | But don't assume safe - could be compromised host |
| External IP | Higher | Requires more scrutiny, potential attacker |
| Loopback | Very Low | Local process communication |

## Common Pitfalls

- **Don't assume internal = safe**: Compromised internal hosts exist
- **Check for VPN ranges**: Some organizations use non-RFC1918 ranges for VPN
- **Cloud considerations**: Cloud provider internal IPs may look external
