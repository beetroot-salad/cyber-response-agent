# Reproduction Agent - Technical Design

**Version:** 1.1
**Status:** Draft
**Last Updated:** December 2025

---

## 1. Executive Summary

The Reproduction Agent validates medium-confidence findings from the Investigation Agent by recreating suspected activity in isolated, ephemeral containers. It compares observed behavior (logs, artifacts, state) against expected patterns to confirm or refute the investigation's hypothesis.

**Key Value Proposition:**
- Reduces hallucinations by requiring empirical validation
- Provides deterministic evidence for auto-close decisions
- Creates audit trail with reproducible steps
- Handles medium-confidence cases (0.70-0.90) that would otherwise require human review

**Design Philosophy (Phase 1):**
- Minimize engineering overhead - get a working POC first
- Agent does the thinking, orchestrator does the plumbing
- Unstructured inputs, structured outputs
- Tank cold starts (5-minute budget is generous)

---

## 2. Requirements Recap

| Requirement | Target | Phase 1 Approach |
|-------------|--------|------------------|
| Multi-environment support | Cloud, VMs, containers | Containers only (Docker) |
| Perfect isolation | No egress, no cross-contamination | `--network=none`, ephemeral fs |
| Scale | Enterprise alert volume | Single-threaded, defer to Phase 3 |
| Latency | < 5 minutes total | Accept cold starts, rely on Docker cache |
| Output | Structured report | JSON block + markdown narrative |

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INVESTIGATION AGENT                             │
│                                                                             │
│  Outputs:                                                                   │
│  • Investigation report (markdown + JSON findings)                          │
│  • Scratchpad (hypotheses, queries, notes)                                  │
│  • Confidence: medium (triggers reproduction)                               │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REPRODUCTION RUNNER                                  │
│                         (Python orchestrator)                                │
│                                                                             │
│  Responsibilities:                                                          │
│  • Create isolated runtime directory                                         │
│  • Copy investigation outputs + signature skills                             │
│  • Spawn Claude Code subprocess                                              │
│  • Enforce timeout (via subprocess timeout + hooks)                          │
│  • Parse output, extract result                                              │
│  • Clean up sandbox containers                                               │
│                                                                             │
│  Does NOT:                                                                  │
│  • Interpret the investigation                                               │
│  • Decide what to reproduce                                                  │
│  • Formulate reproduction steps                                              │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REPRODUCTION AGENT                                   │
│                     (Claude Code subagent)                                   │
│                                                                             │
│  Responsibilities:                                                          │
│  • Read investigation report + scratchpad                                    │
│  • Identify/infer the hypothesis to test                                     │
│  • Determine what environment is needed                                      │
│  • Create sandbox container (via Bash + Docker)                              │
│  • Execute reproduction steps in sandbox                                     │
│  • Compare observed vs expected behavior                                     │
│  • Output structured result                                                  │
│                                                                             │
│  Has access to:                                                             │
│  • Bash (can run docker commands)                                            │
│  • File read/write (in run directory)                                        │
│  • Investigation context (copied files)                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Key Design Decisions

### 4.1 Orchestrator = Plumbing, Agent = Thinking

**Orchestrator (ReproductionRunner):**
```python
# Pseudo-code - what the orchestrator does
def run():
    # 1. Setup - copy files, create directories
    setup_runtime_directory()
    copy_investigation_outputs()
    copy_signature_skills()

    # 2. Invoke - spawn Claude Code
    result = subprocess.run(
        ["claude", "--print", "-p", prompt],
        timeout=300,  # 5 minute hard limit
        cwd=run_dir
    )

    # 3. Parse - extract structured result
    return parse_output(result.stdout)

    # 4. Cleanup - remove sandbox containers
    # (Agent is responsible for cleanup, but we verify)
```

**Agent (Claude Code):**
- Reads the investigation report
- Identifies what hypothesis needs validation
- Figures out what environment to create
- Runs docker commands to create sandbox
- Executes test steps
- Compares results
- Writes conclusion

### 4.2 Unstructured Input, Structured Output

**Input (files in run directory):**
```
runs/{run_id}/
├── CLAUDE.md                    # Agent instructions
├── investigation/
│   ├── report.md               # Investigation output
│   ├── findings.json           # Parsed JSON findings
│   └── scratchpad/             # Investigation notes
├── skills/
│   ├── {signature_id}/         # Signature knowledge
│   │   ├── playbook.md
│   │   ├── rule.md
│   │   └── past-tickets/
│   └── common/                 # Common knowledge
└── output/                     # Agent writes results here
```

**Output (agent writes):**
```markdown
```json
{
  "result": "confirmed | refuted | inconclusive",
  "confidence_modifier": 0.15 | -0.30 | 0.0,
  "hypothesis_tested": "description of what was tested",
  "observations": ["observation 1", "observation 2"],
  "pattern_matches": [
    {"expected": "...", "observed": "...", "matched": true}
  ]
}
```

## Reproduction Report

### Hypothesis Identification
What I understood from the investigation...

### Environment Setup
What container I created and why...

### Execution Log
Commands run, outputs observed...

### Comparison
Expected vs observed behavior...

### Conclusion
Why I reached this result...
```

### 4.3 Docker, Not Podman (For Now)

**Rationale:**
- Docker socket already mounted in devcontainer
- Docker CLI available
- OCI images are identical between Docker and Podman
- Reproduction results are container-runtime-agnostic for our use cases

**Future consideration:** Podman for rootless execution in production (Phase 3).

### 4.4 No Warm Pool

Cold starts are acceptable with 5-minute budget:
- Image pull (cache miss): ~30s
- Container create + start: ~2s
- Agent execution: ~60-180s
- Total: well under 5 minutes

Docker's local image cache handles the common case (cache hit: ~1s).

### 4.5 Timeout Enforcement

Two layers:
1. **subprocess.run timeout** - Hard kill at 300s
2. **Hooks (optional)** - Can add pre-command timeout enforcement

For Phase 1, subprocess timeout is sufficient.

---

## 5. Isolation Model

### 5.1 Sandbox Container Configuration

The agent creates sandbox containers with these settings:

```bash
docker run \
  --name repro-{run_id}-sandbox \
  --network none \              # No network access
  --cap-drop ALL \              # Drop all capabilities
  --security-opt no-new-privileges \
  --read-only \                 # Read-only root fs
  --tmpfs /tmp:size=100m \      # Ephemeral temp
  --tmpfs /workspace:size=200m \# Ephemeral workspace
  --memory 512m \               # Memory limit
  --cpus 1 \                    # CPU limit
  --pids-limit 100 \            # Process limit
  --rm \                        # Auto-remove on exit
  {image} \
  {command}
```

### 5.2 What Isolation Guarantees

| Threat | Mitigation |
|--------|------------|
| Network exfiltration | `--network none` |
| Host filesystem access | `--read-only`, no volume mounts to host |
| Privilege escalation | `--cap-drop ALL`, `--security-opt no-new-privileges` |
| Resource exhaustion | `--memory`, `--cpus`, `--pids-limit` |
| Persistent state | `--rm`, tmpfs mounts |

### 5.3 What Agent CAN Do

- Run docker commands (create/start/exec/stop/rm containers)
- Read files in run directory
- Write files in run directory (for output)
- Execute commands in sandbox via `docker exec`

### 5.4 What Agent CANNOT Do

- Access network from sandbox
- Mount host paths into sandbox
- Escalate privileges
- Leave containers running after completion
- Access other reproduction runs

---

## 6. Agent Instructions (CLAUDE.md Summary)

The existing CLAUDE.md already covers the core principles. Key additions for implementation:

### 6.1 Hypothesis Extraction

The agent should:
1. Read investigation report and scratchpad
2. Identify the primary hypothesis (explicit or inferred)
3. Determine if it's reproducible (see categories below)
4. If not reproducible, return `inconclusive` with explanation

### 6.2 Reproducible vs Non-Reproducible

**Reproducible:**
- "Alert caused by scheduled task/cron job"
- "File created by legitimate software X"
- "Process spawned by known automation tool"
- "Log pattern from expected service behavior"

**Not Reproducible:**
- "User performed action X" (requires user context)
- "Malware execution" (safety risk)
- "Multi-step attack chain" (too complex)
- "Interactive session activity" (non-deterministic)

### 6.3 Docker Commands Pattern

```bash
# Create sandbox
docker run -d --name repro-{run_id} \
  --network none --cap-drop ALL \
  --read-only --tmpfs /tmp:size=100m \
  ubuntu:22.04 sleep infinity

# Copy files into sandbox (if needed)
docker cp config.txt repro-{run_id}:/tmp/

# Execute test
docker exec repro-{run_id} /bin/bash -c "command here"

# Collect output
docker exec repro-{run_id} cat /tmp/output.log

# Cleanup
docker stop repro-{run_id}
docker rm repro-{run_id}
```

---

## 7. Output Schema

### 7.1 Result JSON

```json
{
  "result": "confirmed | refuted | inconclusive",
  "confidence_modifier": 0.15,
  "hypothesis_tested": "The backup script at /opt/scripts/backup.sh creates /tmp/backup-*.tar.gz files when executed",
  "observations": [
    "Created sandbox with ubuntu:22.04 base",
    "Installed tar package",
    "Executed backup.sh script",
    "File /tmp/backup-2025-12-01.tar.gz was created",
    "File size matches expected range"
  ],
  "pattern_matches": [
    {
      "expected": "/tmp/backup-*.tar.gz",
      "observed": "/tmp/backup-2025-12-01.tar.gz",
      "matched": true
    }
  ],
  "sandbox_info": {
    "image": "ubuntu:22.04",
    "container_name": "repro-SEC5678-20251201-abc123",
    "duration_seconds": 45
  },
  "not_reproducible_reason": null
}
```

### 7.2 Confidence Modifiers

| Result | Modifier | When |
|--------|----------|------|
| `confirmed` | +0.15 | All expected patterns observed, no contradictions |
| `refuted` | -0.30 | Expected behavior not observed, contradictions found |
| `inconclusive` | 0.0 | Partial match, environment issues, not reproducible |

---

## 8. Implementation Plan (Phase 1)

### 8.1 File Structure

```
app/agent/reproduction/
├── CLAUDE.md              # Agent instructions (exists, update)
├── DESIGN.md              # This document
├── __init__.py
├── runner.py              # ReproductionRunner
├── models.py              # Simple dataclasses
└── runs/                  # Runtime directories (gitignored)
```

### 8.2 Minimal Models

```python
@dataclass
class ReproductionInput:
    """What we pass to the agent."""
    run_id: str
    investigation_report: str      # markdown
    investigation_findings: dict   # parsed JSON
    scratchpad_contents: dict      # filename -> content
    signature_id: str

@dataclass
class ReproductionResult:
    """What we get back."""
    success: bool
    result: str                    # confirmed/refuted/inconclusive
    confidence_modifier: float
    hypothesis_tested: str
    observations: list[str]
    pattern_matches: list[dict]
    report_body: str               # full markdown output
    error: Optional[str]
    duration_seconds: float
```

### 8.3 Runner Implementation

```python
class ReproductionRunner:
    """
    Manages reproduction lifecycle.

    1. Create run directory
    2. Copy investigation outputs + skills
    3. Spawn Claude Code
    4. Parse output
    5. Cleanup stray containers
    """

    def __init__(self, investigation_result, signature_id, timeout=300):
        self.investigation = investigation_result
        self.signature_id = signature_id
        self.timeout = timeout
        self.run_id = generate_run_id()

    def setup(self):
        """Create run directory, copy files."""

    def build_prompt(self):
        """Build the reproduction prompt."""
        return f"""
        Validate the findings from this investigation by reproducing
        the suspected activity in an isolated container.

        Read the investigation report and scratchpad in ./investigation/
        Use the signature knowledge in ./skills/{self.signature_id}/

        Follow the instructions in CLAUDE.md.
        Write your result to ./output/result.md
        """

    def run(self) -> ReproductionResult:
        """Execute reproduction."""

    def cleanup_containers(self):
        """Remove any containers with our run_id prefix."""
```

### 8.4 Success Criteria

1. Can reproduce "backup job created file" hypothesis
2. Returns correct result (confirmed/refuted/inconclusive)
3. Sandbox containers are properly isolated
4. Cleanup removes all containers
5. Full output captured in result.md

---

## 9. Environment Discovery

### 9.1 Design Goal

**Functional equivalence with version specificity when relevant.** We don't need byte-identical replicas, but if the alert references a specific software version, that version matters.

### 9.2 Discovery Layers (Priority Order)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ENVIRONMENT DISCOVERY LAYERS                         │
│                                                                             │
│  Layer 1: Source Container Image (Primary)                                  │
│  ├── docker inspect {container} --format='{{.Config.Image}}'                │
│  ├── Fresh container from same image (no state carryover)                   │
│  ├── Highest fidelity: same packages, configs, scripts                      │
│  └── Available for all container-based source environments                  │
│                                                                             │
│  Layer 2: Investigation Scratchpad (Supplementary)                          │
│  ├── OS info, relevant packages, config snippets                            │
│  ├── Gathered by investigation agent during analysis                        │
│  └── Used when image insufficient or for additional context                 │
│                                                                             │
│  Layer 3: On-Demand Discovery (Reproduction Agent)                          │
│  ├── Query source environment for specific details                          │
│  ├── docker exec {source} cat /path/to/config                               │
│  ├── docker exec {source} dpkg -l | grep {package}                          │
│  └── Read-only access to source container                                   │
│                                                                             │
│  Layer 4: Signature Knowledge (Fallback)                                    │
│  └── "This signature typically involves Ubuntu + openssh-server"            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.3 Primary Approach: Use Source Image Directly

For container-based alerts, the reproduction agent:

1. **Identifies source container** from investigation context
2. **Gets the image** via `docker inspect`
3. **Creates fresh sandbox** from same image (no state)
4. **Applies isolation settings** (network=none, caps dropped, etc.)

```bash
# Example flow
SOURCE_CONTAINER="target-endpoint"
IMAGE=$(docker inspect $SOURCE_CONTAINER --format='{{.Config.Image}}')
# IMAGE = "target-endpoint:latest"

# Create sandbox from same image
docker run -d --name repro-{run_id} \
  --network none --cap-drop ALL \
  --read-only --tmpfs /tmp:size=100m \
  $IMAGE sleep infinity
```

**Why this works:**
- Same base OS, same packages, same scripts
- No version mismatch issues
- No manual environment specification needed
- Fresh container = no state contamination

### 9.4 Private Registry

A private Docker registry is available at `registry:5000` for:
- Caching pulled images
- Storing environment snapshots if needed
- Managing reproduction-specific images

```bash
# Tag and push to local registry
docker tag target-endpoint:latest registry:5000/target-endpoint:latest
docker push registry:5000/target-endpoint:latest

# Pull from local registry (faster than rebuilding)
docker pull registry:5000/target-endpoint:latest
```

### 9.5 On-Demand Discovery

When the reproduction agent needs details not in the image or scratchpad:

```bash
# Read config files from source
docker exec target-endpoint cat /etc/cron.d/backup

# Check installed package versions
docker exec target-endpoint dpkg -l | grep openssh

# Get OS information
docker exec target-endpoint cat /etc/os-release

# List running services
docker exec target-endpoint systemctl list-units --type=service --state=running
```

**Guidelines for on-demand discovery:**
- Read-only operations only
- Query source environment, not production databases
- Cache results in scratchpad for audit trail
- Fail gracefully if source unavailable

### 9.6 What Can vs Cannot Be Reproduced

| Scenario | Environment Needs | Reproducible? |
|----------|-------------------|---------------|
| File creation by script | Script + dependencies | Yes |
| Log pattern from process | Process + logging config | Yes |
| Process spawning chain | Parent process exists | Yes |
| Scheduled task execution | Cron config + script | Yes |
| Auth failure logging | PAM/sshd config | Partially (no network in sandbox) |
| Network connection | Network stack | No (Phase 2 - requires mocking) |
| API call to service | Service endpoint | No (Phase 2 - requires mocking) |
| Database query | Database connection | No (Phase 2 - requires mocking) |

### 9.7 Network-Dependent Scenarios (Phase 2)

Deferred to Phase 2. When encountered, agent returns `inconclusive` with:
```json
{
  "result": "inconclusive",
  "confidence_modifier": 0.0,
  "not_reproducible_reason": "Hypothesis requires network access which is not available in isolated sandbox. Network mocking planned for Phase 2."
}
```

---

## 10. Future Considerations (Not Phase 1)

### 10.1 Scaling (Phase 3)
- Kubernetes workers
- Queue-based distribution
- gVisor/Kata for stricter isolation

### 10.2 Alternative Runtimes
- Podman for rootless execution
- Firecracker for VM-level isolation
- Cloud sandboxes for cloud-native alerts

### 10.3 Feedback Loop
- Track confirmation rates per precedent
- Upgrade/downgrade precedent tiers based on reproduction success
- Learn optimal reproduction strategies

---

## 11. Open Questions

1. **Should investigation agent explicitly state hypothesis?**
   - Pro: Clearer handoff, easier to validate
   - Con: Adds structure/constraints to investigation output
   - **Decision:** Reproduction agent infers from scratchpad. May revisit if inference proves unreliable.

2. **How to handle partial reproduction?**
   - Some patterns match, others don't
   - **Decision:** Return `inconclusive` with detailed observations

3. **Environment discovery depth?**
   - **Decision:** Use source container image directly (Layer 1), supplement with scratchpad (Layer 2), query source on-demand (Layer 3), signature knowledge as fallback (Layer 4)

4. **Network-dependent scenarios?**
   - **Decision:** Deferred to Phase 2. Return `inconclusive` for now.

---

## 12. Infrastructure Changes

### 12.1 Private Registry Added

Added to `.devcontainer/docker-compose.yml`:

```yaml
registry:
  image: registry:2
  container_name: registry
  hostname: registry
  ports:
    - "5000:5000"
  volumes:
    - registry_data:/var/lib/registry
```

Accessible at `registry:5000` from within the Docker network.

### 12.2 Investigation Agent Access

Investigation agent can query source containers via `docker exec` for:
- Config files
- Package versions
- OS information
- Service status

Results should be captured in scratchpad for reproduction agent to use.

---

*Document revised based on feedback. Focus on minimal POC that validates the core concept.*