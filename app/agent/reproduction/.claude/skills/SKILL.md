---
name: reproduction-utilities
description: Shell utilities for environment discovery and sandbox management during hypothesis reproduction.
---

# Reproduction Utilities

Shell scripts for common reproduction tasks. Use these tagged utilities to discover environments and manage sandboxes.

## Available Utilities

### discover-env.sh @docker @environment
Discovers environment details from a source container. Outputs OS info, installed packages, running processes, and cron jobs.

```bash
./discover-env.sh <container_name>
```

### sandbox.sh @sandbox @isolation
Creates and manages isolated sandbox containers for hypothesis testing.

```bash
./sandbox.sh create <run_id> <image>    # Create isolated sandbox
./sandbox.sh exec <run_id> <command>    # Execute command in sandbox
./sandbox.sh cleanup <run_id>           # Remove sandbox
```

## When to Use

Use these utilities during reproduction to:
- Gather environment context from source containers before building sandbox
- Create properly isolated sandbox containers
- Execute hypothesis test steps safely
