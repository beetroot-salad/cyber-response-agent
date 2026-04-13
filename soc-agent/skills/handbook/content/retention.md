# Retention Policy

How soc-agent run artifacts are aged out and which knobs control the window.

## Why retention matters

Run directories and JSONL logs accumulate indefinitely without a cleanup policy. At 100–1000 alerts per day, run directories alone add up to 120 MB–1.2 GB per 90-day window. The three cross-run JSONL logs have different compliance profiles: `audit.jsonl` and `tool_audit.jsonl` are security compliance records that should survive for at least a year, while `tool_trace.jsonl` is read-only navigation noise with no compliance value and can be pruned aggressively. Each data type therefore has its own independent retention window.

See `content/run-artifacts.md` for a full description of what each artifact contains and which hook writes it.

## What is cleaned up

| Artifact | Controlled by | Default | Rationale |
|---|---|---|---|
| `runs/{uuid}/` dirs | `SOC_AGENT_RUN_MAX_AGE_DAYS` | 90 | Covers post-incident review; 1000/day stays under ~1.2 GB |
| `runs/audit.jsonl` | `SOC_AGENT_AUDIT_MAX_AGE_DAYS` | 365 | Compliance record — one line per completed investigation |
| `runs/tool_audit.jsonl` | `SOC_AGENT_AUDIT_MAX_AGE_DAYS` | 365 | Compliance record — state-changing tool calls |
| `runs/tool_trace.jsonl` | `SOC_AGENT_TRACE_MAX_AGE_DAYS` | 30 | Debug noise only; no compliance value |

`audit.jsonl` and `tool_audit.jsonl` share one knob because both are compliance records and there is no practical reason to keep them for different durations.

Incomplete or aborted run directories (those without a `report.md`) use the same `SOC_AGENT_RUN_MAX_AGE_DAYS` window as completed runs. Their mtime naturally reflects when the investigation ended or was interrupted.

## Configuration

Three optional environment variables control retention. All default to the values above when unset. The naming convention follows `SOC_AGENT_JUDGE_TIMEOUT_SECONDS` and `SOC_AGENT_JUDGE_MODEL`.

**`SOC_AGENT_RUN_MAX_AGE_DAYS`** (default: `90`)
Directories older than this many days are deleted. Age is measured by the directory's modification time in UTC. All age calculations use UTC throughout, consistent with the UTC timestamps written by the hooks — a 90-day window means entries older than 90 × 24 hours from the moment cleanup runs.

**`SOC_AGENT_AUDIT_MAX_AGE_DAYS`** (default: `365`)
JSONL lines with a `timestamp` field older than this are filtered from `audit.jsonl` and `tool_audit.jsonl`. 365 days matches common compliance requirements (SOC 2, ISO 27001 log retention guidance).

**`SOC_AGENT_TRACE_MAX_AGE_DAYS`** (default: `30`)
Same filtering applied to `tool_trace.jsonl`. Short window is deliberate — trace data is debug-only and has no forensic or compliance value beyond the immediate investigation window.

All three values must be positive integers. The script exits with code 1 and a clear message if a variable is set to an invalid value.

## Running the cleanup script

```bash
# Preview what would be deleted without making any changes
python3 scripts/cleanup_runs.py --dry-run

# Run cleanup with per-item output
python3 scripts/cleanup_runs.py --verbose

# Silent run (suitable for cron)
python3 scripts/cleanup_runs.py
```

The script exits 0 on success (including dry-run) and 1 on fatal errors.

**Safety properties:**
- Lines with missing or unparseable timestamps are always kept — the script never silently discards what it cannot date.
- JSONL rewrites are atomic: the script writes to a `.tmp` file first, then calls `os.replace()`, so concurrent readers always see a complete file.
- `--dry-run` never touches the filesystem.
- Directories are only deleted if they are direct children of the runs directory, protecting against a misconfigured `SOC_AGENT_RUNS_DIR`.

**Known limitation — JSONL race window:** The atomic rewrite does not prevent a concurrent hook append from being silently dropped. If a hook writes a new line to `audit.jsonl` in the millisecond interval between cleanup's read and its `os.replace`, that line will be lost. At daily-cron frequency the probability is low (~1% at 1000 alerts/day), and the full investigation log remains in the run directory for 90 days. Schedule cleanup during low-activity windows (e.g. 2am) to minimize exposure.

## Scheduling

The cleanup script is standalone — scheduling is the operator's responsibility. Choose the mechanism that fits your deployment model.

### cron (Linux / macOS analyst machine)

```cron
0 2 * * * cd /path/to/soc-agent && python3 scripts/cleanup_runs.py >> /var/log/soc-cleanup.log 2>&1
```

### systemd timer (centralized Linux VM — preferred over cron for auditability)

```ini
# /etc/systemd/system/soc-cleanup.service
[Unit]
Description=SOC Agent Run Cleanup

[Service]
Type=oneshot
WorkingDirectory=/path/to/soc-agent
ExecStart=python3 scripts/cleanup_runs.py
```

```ini
# /etc/systemd/system/soc-cleanup.timer
[Unit]
Description=Daily SOC Agent cleanup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable with: `systemctl enable --now soc-cleanup.timer`

### Docker sidecar

```yaml
services:
  soc-cleanup:
    image: python:3.11-slim
    volumes:
      - ./soc-agent:/soc-agent
    command: >
      sh -c "while true; do
        python3 /soc-agent/scripts/cleanup_runs.py;
        sleep 86400;
      done"
    environment:
      SOC_AGENT_RUNS_DIR: /soc-agent/runs
```

### Windows Task Scheduler (analyst machine)

```
schtasks /create /tn "SOC Agent Cleanup" ^
  /tr "python3 C:\path\to\soc-agent\scripts\cleanup_runs.py" ^
  /sc daily /st 02:00
```

### CI/CD (e.g. GitHub Actions scheduled workflow)

```yaml
on:
  schedule:
    - cron: "0 2 * * *"

jobs:
  cleanup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: python3 soc-agent/scripts/cleanup_runs.py
        env:
          SOC_AGENT_RUN_MAX_AGE_DAYS: 7   # shorter retention for CI environments
```

## Cross-references

- `content/run-artifacts.md` — full layout of the runs directory and what each file contains
- `content/design.md` — overall plugin architecture and safety model
