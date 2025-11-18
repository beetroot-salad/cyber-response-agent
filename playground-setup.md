# Cyber Response Agent - Playground Setup Guide

## Overview

This guide sets up a complete playground environment for prototyping the cyber response agent using open-source tools that mirror commercial SIEM/EDR/ticketing platforms.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ DevContainer (Claude Code)                                  │
│ ├─ MCP Servers (SIEM, Ticketing, TI)                       │
│ ├─ Claude Skills (Past Investigations, Playbooks)          │
│ └─ Agent Code                                               │
└─────────────────┬───────────────────────────────────────────┘
                  │ (Docker socket mount)
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ Docker Compose Stack (Host Docker)                         │
│ ├─ Wazuh (SIEM) - API similar to Splunk/QRadar            │
│ ├─ PostgreSQL (Tickets + Knowledge Base)                   │
│ ├─ Elasticsearch (Log storage for Wazuh)                   │
│ ├─ Mock EDR Agent (generates telemetry)                    │
│ └─ Isolated Sandbox (for reproduction agent)               │
└─────────────────────────────────────────────────────────────┘
```

## Stack Components

### 1. Wazuh (SIEM)
- **Purpose**: Alert generation, log aggregation, rule engine
- **Commercial equivalent**: Splunk, QRadar, Elastic Security
- **API**: REST API for queries, similar to enterprise SIEMs
- **Features**: Pre-built rules, JSON alerts, agent management

### 2. PostgreSQL + pgvector
- **Purpose**: Ticket storage, knowledge base, past investigations
- **Commercial equivalent**: ServiceNow CMDB, Jira database
- **Features**: Vector similarity search for semantic matching

### 3. Mock EDR Agent
- **Purpose**: Generate realistic endpoint telemetry
- **Commercial equivalent**: CrowdStrike, SentinelOne, Carbon Black
- **Implementation**: Python script generating process, network, file events

### 4. Reproduction Sandbox
- **Purpose**: Isolated environment for alert reproduction
- **Implementation**: Docker-in-Docker or gVisor container

---

## Setup Instructions

### Prerequisites

```bash
# Verify Docker access from devcontainer
docker ps

# Install required tools in devcontainer
sudo apt-get update
sudo apt-get install -y docker-compose jq curl postgresql-client
```

### Step 1: Create Docker Compose Stack

Create the infrastructure stack:

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

  # PostgreSQL (Tickets + Knowledge Base)
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

  # Mock EDR Agent (generates telemetry)
  mock-edr:
    build:
      context: ./mock-edr
      dockerfile: Dockerfile
    hostname: mock-edr
    restart: always
    environment:
      - WAZUH_MANAGER=wazuh-manager
      - POSTGRES_HOST=postgres
      - POSTGRES_DB=cyber_response
      - POSTGRES_USER=agent
      - POSTGRES_PASSWORD=agent_password
    depends_on:
      - wazuh-manager
      - postgres
    volumes:
      - ./mock-edr:/app

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

### Step 2: Initialize Database Schema

```sql
-- init-db.sql
-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Alerts/Tickets table
CREATE TABLE tickets (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(255) UNIQUE NOT NULL,
    alert_signature VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    source_ip INET,
    dest_ip INET,
    username VARCHAR(255),
    process_name VARCHAR(255),
    file_hash VARCHAR(64),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    raw_alert JSONB NOT NULL,
    investigation_report JSONB,
    disposition VARCHAR(50), -- 'true_positive', 'false_positive', 'benign', 'escalated'
    confidence_score NUMERIC(5,2),
    closed_at TIMESTAMP,
    closed_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Past investigations (knowledge base)
CREATE TABLE investigations (
    id SERIAL PRIMARY KEY,
    ticket_id INTEGER REFERENCES tickets(id),
    alert_signature VARCHAR(255) NOT NULL,
    hypothesis TEXT NOT NULL,
    investigation_steps JSONB NOT NULL,
    findings TEXT NOT NULL,
    disposition VARCHAR(50) NOT NULL,
    analyst_notes TEXT,
    reproduction_performed BOOLEAN DEFAULT FALSE,
    reproduction_report JSONB,
    embedding vector(1536), -- For semantic search (OpenAI ada-002 dimensions)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Playbooks
CREATE TABLE playbooks (
    id SERIAL PRIMARY KEY,
    alert_type VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    investigation_steps JSONB NOT NULL,
    known_false_positives JSONB,
    reproduction_required VARCHAR(50) DEFAULT 'always', -- 'always', 'conditional', 'never'
    auto_close_threshold NUMERIC(5,2) DEFAULT 95.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Known false positive signatures
CREATE TABLE known_false_positives (
    id SERIAL PRIMARY KEY,
    alert_signature VARCHAR(255) NOT NULL,
    pattern JSONB NOT NULL, -- Matching criteria
    reason TEXT NOT NULL,
    auto_close BOOLEAN DEFAULT TRUE,
    added_by VARCHAR(100),
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    occurrence_count INTEGER DEFAULT 1
);

-- Threat intelligence cache
CREATE TABLE threat_intel (
    id SERIAL PRIMARY KEY,
    indicator VARCHAR(255) UNIQUE NOT NULL,
    indicator_type VARCHAR(50) NOT NULL, -- 'ip', 'domain', 'hash', 'url'
    reputation_score INTEGER, -- 0-100
    malicious BOOLEAN,
    tags TEXT[],
    source VARCHAR(100),
    metadata JSONB,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Agent metrics
CREATE TABLE agent_metrics (
    id SERIAL PRIMARY KEY,
    metric_type VARCHAR(100) NOT NULL,
    metric_value NUMERIC,
    metadata JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_signature ON tickets(alert_signature);
CREATE INDEX idx_tickets_timestamp ON tickets(timestamp DESC);
CREATE INDEX idx_investigations_signature ON investigations(alert_signature);
CREATE INDEX idx_investigations_disposition ON investigations(disposition);
CREATE INDEX idx_playbooks_alert_type ON playbooks(alert_type);
CREATE INDEX idx_threat_intel_indicator ON threat_intel(indicator);

-- Create vector similarity search function
CREATE OR REPLACE FUNCTION find_similar_investigations(
    query_embedding vector(1536),
    match_threshold FLOAT DEFAULT 0.8,
    match_count INT DEFAULT 5
)
RETURNS TABLE (
    id INTEGER,
    alert_signature VARCHAR,
    hypothesis TEXT,
    findings TEXT,
    disposition VARCHAR,
    similarity FLOAT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        i.id,
        i.alert_signature,
        i.hypothesis,
        i.findings,
        i.disposition,
        1 - (i.embedding <=> query_embedding) AS similarity
    FROM investigations i
    WHERE 1 - (i.embedding <=> query_embedding) > match_threshold
    ORDER BY i.embedding <=> query_embedding
    LIMIT match_count;
END;
$$;

-- Insert sample playbook
INSERT INTO playbooks (alert_type, name, description, investigation_steps, known_false_positives, reproduction_required)
VALUES (
    'suspicious_powershell',
    'Suspicious PowerShell Execution',
    'Investigate potentially malicious PowerShell command execution',
    '[
        "Check if PowerShell script is signed",
        "Analyze command line for obfuscation patterns",
        "Identify parent process and execution context",
        "Query recent PowerShell executions by same user",
        "Compare against known administrative scripts",
        "Check for encoded commands or download cradles"
    ]'::jsonb,
    '[
        "Signed scripts from IT department",
        "Known backup/monitoring tools",
        "Configuration management (Ansible, Chef, Puppet)"
    ]'::jsonb,
    'conditional'
);

-- Insert sample known false positive
INSERT INTO known_false_positives (alert_signature, pattern, reason, auto_close)
VALUES (
    'WINDOWS_DEFENDER_SCAN',
    '{"process_name": "MsMpEng.exe", "event_type": "process_create"}'::jsonb,
    'Windows Defender scheduled scan',
    true
);
```

### Step 3: Create Mock EDR Agent

```python
# mock-edr/generate_telemetry.py
#!/usr/bin/env python3
"""
Mock EDR agent that generates realistic endpoint telemetry and alerts.
Simulates various scenarios: benign activity, false positives, and some malicious patterns.
"""

import json
import random
import time
import hashlib
from datetime import datetime, timedelta
import psycopg2
import requests
from typing import Dict, List

# Configuration
WAZUH_API_URL = "http://wazuh-manager:55000"
WAZUH_USER = "wazuh-api"
WAZUH_PASSWORD = "MyS3cr37P450r.*-"

DB_CONFIG = {
    "host": "postgres",
    "database": "cyber_response",
    "user": "agent",
    "password": "agent_password"
}

# Alert templates
ALERT_TEMPLATES = {
    "suspicious_powershell": {
        "severity": "high",
        "category": "execution",
        "weight": 0.15,
        "false_positive_rate": 0.7  # 70% are FPs
    },
    "failed_login": {
        "severity": "medium",
        "category": "authentication",
        "weight": 0.30,
        "false_positive_rate": 0.85
    },
    "network_scan": {
        "severity": "medium",
        "category": "discovery",
        "weight": 0.10,
        "false_positive_rate": 0.60
    },
    "suspicious_file_download": {
        "severity": "high",
        "category": "initial_access",
        "weight": 0.15,
        "false_positive_rate": 0.50
    },
    "privilege_escalation": {
        "severity": "critical",
        "category": "privilege_escalation",
        "weight": 0.05,
        "false_positive_rate": 0.20
    },
    "data_exfiltration": {
        "severity": "critical",
        "category": "exfiltration",
        "weight": 0.05,
        "false_positive_rate": 0.30
    },
    "malware_execution": {
        "severity": "critical",
        "category": "execution",
        "weight": 0.05,
        "false_positive_rate": 0.10
    },
    "suspicious_registry_modification": {
        "severity": "medium",
        "category": "persistence",
        "weight": 0.15,
        "false_positive_rate": 0.75
    }
}

# Sample data for realistic alerts
BENIGN_USERS = ["john.doe", "jane.smith", "bob.admin", "alice.dev", "charlie.ops"]
BENIGN_IPS = ["10.0.1.10", "10.0.1.20", "10.0.1.30", "10.0.1.40", "10.0.1.50"]
BENIGN_PROCESSES = [
    "powershell.exe", "cmd.exe", "python.exe", "node.exe", "java.exe",
    "MsMpEng.exe", "explorer.exe", "chrome.exe", "teams.exe"
]

SUSPICIOUS_IPS = ["192.168.100.50", "203.0.113.42", "198.51.100.99"]
SUSPICIOUS_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "098f6bcd4621d373cade4e832627b4f6",
    "5d41402abc4b2a76b9719d911017c592"
]

def generate_alert(alert_type: str) -> Dict:
    """Generate a realistic alert based on type"""
    template = ALERT_TEMPLATES[alert_type]
    is_false_positive = random.random() < template["false_positive_rate"]

    base_alert = {
        "alert_id": f"alert-{int(time.time() * 1000)}-{random.randint(1000, 9999)}",
        "alert_signature": alert_type,
        "severity": template["severity"],
        "category": template["category"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "is_false_positive": is_false_positive  # Ground truth (not visible to agent)
    }

    # Generate type-specific details
    if alert_type == "suspicious_powershell":
        if is_false_positive:
            base_alert.update({
                "username": random.choice(BENIGN_USERS),
                "source_ip": random.choice(BENIGN_IPS),
                "process_name": "powershell.exe",
                "command_line": random.choice([
                    "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\backup-script.ps1",
                    "powershell.exe Get-EventLog -LogName System -Newest 100",
                    "powershell.exe -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'}\""
                ]),
                "parent_process": "explorer.exe",
                "signed": True
            })
        else:
            base_alert.update({
                "username": random.choice(BENIGN_USERS),
                "source_ip": random.choice(BENIGN_IPS),
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...",
                "parent_process": "winword.exe",
                "signed": False
            })

    elif alert_type == "failed_login":
        if is_false_positive:
            base_alert.update({
                "username": random.choice(BENIGN_USERS),
                "source_ip": random.choice(BENIGN_IPS),
                "dest_ip": "10.0.0.5",
                "failed_attempts": random.randint(3, 5),
                "reason": "wrong password"
            })
        else:
            base_alert.update({
                "username": "admin",
                "source_ip": random.choice(SUSPICIOUS_IPS),
                "dest_ip": "10.0.0.5",
                "failed_attempts": random.randint(50, 200),
                "reason": "brute force attempt"
            })

    elif alert_type == "network_scan":
        if is_false_positive:
            base_alert.update({
                "username": "monitoring-tool",
                "source_ip": "10.0.1.100",
                "scanned_ports": [80, 443, 8080],
                "target_count": 10,
                "process_name": "nmap.exe"
            })
        else:
            base_alert.update({
                "username": random.choice(BENIGN_USERS),
                "source_ip": random.choice(BENIGN_IPS),
                "scanned_ports": list(range(1, 1024)),
                "target_count": 256,
                "process_name": "scanner.exe"
            })

    elif alert_type == "suspicious_file_download":
        if is_false_positive:
            base_alert.update({
                "username": random.choice(BENIGN_USERS),
                "source_ip": random.choice(BENIGN_IPS),
                "url": "https://github.com/user/repo/releases/download/v1.0/tool.exe",
                "file_name": "tool.exe",
                "file_hash": hashlib.md5(str(random.random()).encode()).hexdigest(),
                "file_size": random.randint(1000, 50000)
            })
        else:
            base_alert.update({
                "username": random.choice(BENIGN_USERS),
                "source_ip": random.choice(BENIGN_IPS),
                "url": "http://malicious-domain.com/payload.exe",
                "file_name": "invoice.pdf.exe",
                "file_hash": random.choice(SUSPICIOUS_HASHES),
                "file_size": random.randint(100000, 500000)
            })

    return base_alert

def insert_alert_to_db(alert: Dict):
    """Insert alert into PostgreSQL tickets table"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO tickets (
                alert_id, alert_signature, severity, status,
                source_ip, username, process_name, file_hash,
                timestamp, raw_alert
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            alert["alert_id"],
            alert["alert_signature"],
            alert["severity"],
            "open",
            alert.get("source_ip"),
            alert.get("username"),
            alert.get("process_name"),
            alert.get("file_hash"),
            alert["timestamp"],
            json.dumps(alert)
        ))

        conn.commit()
        cur.close()
        conn.close()

        print(f"✓ Inserted alert: {alert['alert_id']} ({alert['alert_signature']})")
    except Exception as e:
        print(f"✗ Error inserting alert: {e}")

def generate_alerts_batch(count: int = 10):
    """Generate a batch of alerts"""
    alerts = []

    for _ in range(count):
        # Weighted random selection of alert type
        alert_type = random.choices(
            list(ALERT_TEMPLATES.keys()),
            weights=[t["weight"] for t in ALERT_TEMPLATES.values()]
        )[0]

        alert = generate_alert(alert_type)
        alerts.append(alert)
        insert_alert_to_db(alert)

        # Small delay to avoid timestamp collisions
        time.sleep(0.1)

    return alerts

def main():
    """Main loop - generate alerts continuously"""
    print("🚀 Mock EDR Agent started")
    print(f"📊 Alert templates loaded: {len(ALERT_TEMPLATES)}")
    print("⏳ Generating alerts every 30 seconds...")

    while True:
        try:
            # Generate 5-15 alerts per batch
            batch_size = random.randint(5, 15)
            print(f"\n📨 Generating {batch_size} alerts...")
            generate_alerts_batch(batch_size)

            # Wait before next batch
            time.sleep(30)
        except KeyboardInterrupt:
            print("\n⏹️  Shutting down...")
            break
        except Exception as e:
            print(f"✗ Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
```

```dockerfile
# mock-edr/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir psycopg2-binary requests

COPY generate_telemetry.py /app/

CMD ["python", "-u", "generate_telemetry.py"]
```

### Step 4: Create MCP Servers

#### SIEM MCP Server

```python
# mcp-servers/siem_server.py
#!/usr/bin/env python3
"""
MCP Server for SIEM queries (wraps PostgreSQL ticket system)
Provides read-only access to alerts and investigations
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

def query_alerts(filters: dict) -> list:
    """Query alerts from database"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    query = "SELECT alert_id, alert_signature, severity, status, source_ip, username, timestamp, raw_alert FROM tickets WHERE 1=1"
    params = []

    if filters.get("status"):
        query += " AND status = %s"
        params.append(filters["status"])

    if filters.get("severity"):
        query += " AND severity = %s"
        params.append(filters["severity"])

    if filters.get("alert_signature"):
        query += " AND alert_signature = %s"
        params.append(filters["alert_signature"])

    if filters.get("username"):
        query += " AND username = %s"
        params.append(filters["username"])

    if filters.get("time_range_hours"):
        query += " AND timestamp > NOW() - INTERVAL '%s hours'"
        params.append(filters["time_range_hours"])

    query += " ORDER BY timestamp DESC LIMIT %s"
    params.append(filters.get("limit", 100))

    cur.execute(query, params)
    results = cur.fetchall()

    alerts = []
    for row in results:
        alerts.append({
            "alert_id": row[0],
            "alert_signature": row[1],
            "severity": row[2],
            "status": row[3],
            "source_ip": str(row[4]) if row[4] else None,
            "username": row[5],
            "timestamp": row[6].isoformat() if row[6] else None,
            "raw_alert": row[7]
        })

    cur.close()
    conn.close()

    return alerts

def get_alert_details(alert_id: str) -> dict:
    """Get full details of a specific alert"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        SELECT alert_id, alert_signature, severity, status, source_ip, dest_ip,
               username, process_name, file_hash, timestamp, raw_alert,
               investigation_report, disposition, confidence_score
        FROM tickets
        WHERE alert_id = %s
    """, (alert_id,))

    row = cur.fetchone()

    if not row:
        return None

    alert = {
        "alert_id": row[0],
        "alert_signature": row[1],
        "severity": row[2],
        "status": row[3],
        "source_ip": str(row[4]) if row[4] else None,
        "dest_ip": str(row[5]) if row[5] else None,
        "username": row[6],
        "process_name": row[7],
        "file_hash": row[8],
        "timestamp": row[9].isoformat() if row[9] else None,
        "raw_alert": row[10],
        "investigation_report": row[11],
        "disposition": row[12],
        "confidence_score": float(row[13]) if row[13] else None
    }

    cur.close()
    conn.close()

    return alert

# MCP Server protocol implementation
def handle_request(request: dict) -> dict:
    """Handle MCP request"""
    method = request.get("method")
    params = request.get("params", {})

    if method == "query_alerts":
        results = query_alerts(params)
        return {"result": results}

    elif method == "get_alert_details":
        alert_id = params.get("alert_id")
        result = get_alert_details(alert_id)
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

#### Ticketing MCP Server

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

def close_ticket(alert_id: str, disposition: str, confidence_score: float, report: dict, closed_by: str = "agent") -> dict:
    """Close a ticket with investigation results"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        UPDATE tickets
        SET status = 'closed',
            disposition = %s,
            confidence_score = %s,
            investigation_report = %s,
            closed_at = NOW(),
            closed_by = %s,
            updated_at = NOW()
        WHERE alert_id = %s
        RETURNING id
    """, (disposition, confidence_score, json.dumps(report), closed_by, alert_id))

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

def update_ticket_status(alert_id: str, status: str, notes: str = None) -> dict:
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

def add_investigation_note(alert_id: str, note: str) -> dict:
    """Add a note to the investigation report"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    # Get current investigation report
    cur.execute("SELECT investigation_report FROM tickets WHERE alert_id = %s", (alert_id,))
    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        return {"success": False, "error": "Alert not found"}

    report = row[0] or {}
    if "notes" not in report:
        report["notes"] = []

    report["notes"].append({
        "timestamp": datetime.utcnow().isoformat(),
        "note": note
    })

    cur.execute("""
        UPDATE tickets
        SET investigation_report = %s,
            updated_at = NOW()
        WHERE alert_id = %s
    """, (json.dumps(report), alert_id))

    conn.commit()
    cur.close()
    conn.close()

    return {"success": True}

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
            params.get("report"),
            params.get("closed_by", "agent")
        )
        return {"result": result}

    elif method == "update_status":
        result = update_ticket_status(
            params.get("alert_id"),
            params.get("status"),
            params.get("notes")
        )
        return {"result": result}

    elif method == "add_note":
        result = add_investigation_note(
            params.get("alert_id"),
            params.get("note")
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

#### Threat Intelligence MCP Server

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
import hashlib

DB_CONFIG = {
    "host": "localhost",
    "port": "5432",
    "database": "cyber_response",
    "user": "agent",
    "password": "agent_password"
}

# Mock TI data for playground (replace with real API calls in production)
KNOWN_MALICIOUS_IPS = ["203.0.113.42", "198.51.100.99"]
KNOWN_MALICIOUS_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592"
]

def lookup_indicator(indicator: str, indicator_type: str) -> dict:
    """Lookup indicator in TI database and external sources"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    # Check cache first
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
            reputation_score = 10
            tags = ["malware-c2", "phishing"]
            metadata = {"campaigns": ["APT-X"], "first_seen": "2024-01-15"}
        elif indicator.startswith("10.") or indicator.startswith("192.168."):
            reputation_score = 80  # Internal IP
            tags = ["internal"]

    elif indicator_type == "hash":
        if indicator in KNOWN_MALICIOUS_HASHES:
            malicious = True
            reputation_score = 5
            tags = ["trojan", "ransomware"]
            metadata = {"file_name": "malware.exe", "family": "Generic"}

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

### Step 5: Claude Code Skills Setup

```python
# .claude/skills/past_investigations.py
"""
Query past investigations for similar alerts
Uses PostgreSQL with vector similarity search
"""

import psycopg2
import json

def query_past_investigations(alert_signature: str, limit: int = 5) -> list:
    """Query past investigations by alert signature"""
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
            i.id,
            i.alert_signature,
            i.hypothesis,
            i.investigation_steps,
            i.findings,
            i.disposition,
            i.analyst_notes,
            i.reproduction_performed,
            t.raw_alert
        FROM investigations i
        JOIN tickets t ON i.ticket_id = t.id
        WHERE i.alert_signature = %s
        ORDER BY i.created_at DESC
        LIMIT %s
    """, (alert_signature, limit))

    results = []
    for row in cur.fetchall():
        results.append({
            "id": row[0],
            "alert_signature": row[1],
            "hypothesis": row[2],
            "investigation_steps": row[3],
            "findings": row[4],
            "disposition": row[5],
            "analyst_notes": row[6],
            "reproduction_performed": row[7],
            "original_alert": row[8]
        })

    cur.close()
    conn.close()

    return results

def main():
    """Skill entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: past_investigations.py <alert_signature>")
        sys.exit(1)

    alert_signature = sys.argv[1]
    results = query_past_investigations(alert_signature)

    print(json.dumps(results, indent=2))

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

def get_playbook(alert_type: str) -> dict:
    """Get playbook for alert type"""
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
            known_false_positives,
            reproduction_required,
            auto_close_threshold
        FROM playbooks
        WHERE alert_type = %s
    """, (alert_type,))

    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        return None

    playbook = {
        "alert_type": alert_type,
        "name": row[0],
        "description": row[1],
        "investigation_steps": row[2],
        "known_false_positives": row[3],
        "reproduction_required": row[4],
        "auto_close_threshold": float(row[5])
    }

    cur.close()
    conn.close()

    return playbook

def main():
    """Skill entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: playbook.py <alert_type>")
        sys.exit(1)

    alert_type = sys.argv[1]
    playbook = get_playbook(alert_type)

    if playbook:
        print(json.dumps(playbook, indent=2))
    else:
        print(json.dumps({"error": "Playbook not found"}))

if __name__ == "__main__":
    main()
```

### Step 6: MCP Configuration for Claude Code

```json
// mcp_config.json (in devcontainer)
{
  "mcpServers": {
    "siem": {
      "command": "python3",
      "args": ["/workspace/mcp-servers/siem_server.py"],
      "env": {}
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

### Step 7: Startup Script

```bash
#!/bin/bash
# startup.sh - Start the playground environment

set -e

echo "🚀 Starting Cyber Response Agent Playground"
echo "==========================================="

# Create directory structure
mkdir -p mock-edr
mkdir -p mcp-servers
mkdir -p .claude/skills
mkdir -p sandbox-scripts

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
echo "⏳ Waiting for Wazuh..."
sleep 30

echo ""
echo "✅ Playground environment is ready!"
echo ""
echo "📊 Services:"
echo "  - Wazuh Dashboard: http://localhost:5601 (admin/SecretPassword)"
echo "  - PostgreSQL: localhost:5432 (agent/agent_password)"
echo "  - Mock EDR: Generating alerts every 30 seconds"
echo ""
echo "🔧 MCP Servers:"
echo "  - siem: Query alerts from SIEM"
echo "  - ticketing: Close tickets, update status"
echo "  - threat_intel: IOC lookups"
echo ""
echo "📝 Next steps:"
echo "  1. Configure MCP servers in Claude Code"
echo "  2. Test skills: python3 .claude/skills/playbook.py suspicious_powershell"
echo "  3. Query alerts: psql -h localhost -U agent -d cyber_response -c 'SELECT COUNT(*) FROM tickets;'"
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

# 3. Verify alerts are being generated
psql -h localhost -U agent -d cyber_response -c "SELECT alert_signature, COUNT(*) FROM tickets GROUP BY alert_signature;"

# 4. Test skills
python3 .claude/skills/playbook.py suspicious_powershell

# 5. Test MCP servers (manual test)
echo '{"method": "query_alerts", "params": {"status": "open", "limit": 5}}' | python3 mcp-servers/siem_server.py
```

---

## Next Steps

1. **Populate sample data**: Run mock EDR for a few hours to build up alert history
2. **Add past investigations**: Insert sample investigation outcomes
3. **Build main agent**: Create the investigation agent that uses these MCP servers
4. **Create reproduction agent**: Set up isolated Docker environment
5. **Implement confidence scoring**: Build the decision logic
6. **Add metrics dashboard**: Track agent performance

Let me know which component you'd like to build first!
