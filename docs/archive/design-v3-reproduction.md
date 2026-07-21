# Reproduction Agent Design (Deferred)

**Status:** Deferred from v3 implementation
**Prerequisite:** Network simulation capabilities (mock services, traffic replay)

See [design-v3-overview.md §2.4](design-v3-overview.md#24-reproduction-deferred) for the deferral rationale.

---

## Isolation Requirements (Non-Negotiable)

| Requirement | Why |
|-------------|-----|
| No network egress | Prevent exfiltration, C2, lateral movement |
| Ephemeral filesystem | No persistent artifacts on host |
| Resource limits (CPU, memory, time) | Prevent resource exhaustion |
| Capability dropping | Minimize kernel attack surface |
| Process isolation | Sandbox cannot affect host |
| Network simulation | Mock services and traffic replay |

## Technical Options

| Technology | Isolation | Speed | Best For |
|-----------|-----------|-------|----------|
| Docker (`--network none`, dropped caps) | Process-level | Fast | Host-only hypotheses |
| gVisor (runsc) | Syscall-level | Medium | Higher-risk with syscall filtering |
| Firecracker / microVM | VM-level | Slower | Full isolation with network sim |

**Recommended:** Docker + network simulation. Host-only reproduction is insufficient — most useful reproduction requires simulating network services (mock DNS, HTTP, LDAP, traffic replay).

## Reproduction Subagent

An LLM-powered subagent that validates causal hypotheses empirically. NOT a deterministic script — it reasons about environment recreation, test execution, and result interpretation.

### Input Schema

```json
{
  "hypothesis": "Running /opt/scripts/backup.sh as svc-backup creates /tmp/backup-YYYY-MM-DD.tar.gz and writes 'backup complete' to syslog",
  "environment_context": {
    "os": "Ubuntu 22.04",
    "relevant_packages": ["tar", "gzip", "rsyslog"],
    "relevant_configs": ["/opt/scripts/backup.sh", "/etc/cron.d/backup"],
    "relevant_user": "svc-backup"
  },
  "expected_artifacts": [
    {"type": "file", "path": "/tmp/backup-*.tar.gz"},
    {"type": "log_entry", "pattern": "backup complete"}
  ],
  "timeout_seconds": 120,
  "run_id": "SEC-001_20260309_abc123"
}
```

### Output Schema

```json
{
  "result": "confirmed | refuted | inconclusive",
  "hypothesis_tested": "...",
  "observations": ["..."],
  "artifact_comparison": [
    {"expected": "...", "observed": "...", "match": true}
  ],
  "not_reproducible_reason": null,
  "environment_notes": "..."
}
```

## When to Revisit

When the system handles enough network-dependent signatures that investment in traffic replay / mock service infrastructure is justified.
