#!/bin/bash
# Simulates normal user activity on the endpoint
# Runs every 5 minutes via cron

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] Starting benign activity cycle"

# ============================================
# File Operations (Normal User Activity)
# ============================================

# Create temporary work files
touch /tmp/user_document_$(date +%s).txt
echo "User work data" > /tmp/work_file_$(date +%s).txt

# List common directories
ls -la /home > /dev/null 2>&1
ls -la /tmp > /dev/null 2>&1

# Read system information
cat /etc/passwd > /dev/null 2>&1
cat /etc/os-release > /dev/null 2>&1

# ============================================
# Process Execution (Normal Activity)
# ============================================

# System monitoring (common for users)
ps aux > /dev/null 2>&1
top -bn1 > /dev/null 2>&1
uptime > /dev/null 2>&1

# Check disk usage
df -h > /dev/null 2>&1

# Environment checks
env > /dev/null 2>&1

# ============================================
# Network Activity (Benign)
# ============================================

# DNS resolution (common)
nslookup google.com > /dev/null 2>&1 || true

# Ping common services
ping -c 2 8.8.8.8 > /dev/null 2>&1 || true

# Check network interfaces
ip addr show > /dev/null 2>&1 || true
netstat -tulpn > /dev/null 2>&1 || true

# ============================================
# User Activity Simulation
# ============================================

# Simulate text editing
echo "Sample content $(date)" > /tmp/edited_file_$(date +%s).txt

# Simulate file search
find /tmp -name "*.txt" -mtime -1 > /dev/null 2>&1 || true

# Simulate compression (backup-like)
tar -czf /tmp/backup_$(date +%s).tar.gz /tmp/*.txt > /dev/null 2>&1 || true

# ============================================
# Cleanup Old Files
# ============================================

# Remove files older than 1 hour from /tmp
find /tmp -name "user_document_*.txt" -mmin +60 -delete 2>/dev/null || true
find /tmp -name "work_file_*.txt" -mmin +60 -delete 2>/dev/null || true
find /tmp -name "edited_file_*.txt" -mmin +60 -delete 2>/dev/null || true
find /tmp -name "backup_*.tar.gz" -mmin +60 -delete 2>/dev/null || true

echo "[$TIMESTAMP] Benign activity completed"
