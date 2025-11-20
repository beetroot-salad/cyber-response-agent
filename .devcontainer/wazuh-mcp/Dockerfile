# Wazuh MCP Server
# Provides MCP interface for querying Wazuh SIEM
# Source: https://github.com/socfortress/wazuh-mcp-server

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Wazuh MCP Server from GitHub
RUN pip install --no-cache-dir git+https://github.com/socfortress/wazuh-mcp-server.git

# Create non-root user for security
RUN useradd -m -u 1000 mcp && \
    chown -R mcp:mcp /app

USER mcp

# Expose default MCP server port
EXPOSE 8000

# Health check using SSE endpoint (returns 307 redirect when healthy)
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/sse/ | grep -qE "^(200|307)$" || exit 1

# Run the MCP server
CMD ["wazuh-mcp-server", "--host", "0.0.0.0", "--port", "8000"]
