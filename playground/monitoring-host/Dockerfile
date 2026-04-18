FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-client \
    cron \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Elastic Agent (enrollment + start happens at container entrypoint,
# since the enrollment token is only known after fleet-server has booted).
# Stub systemctl during install: the deb's postinst tries to enable the
# service, which fails in a build container with no systemd.
RUN curl -fsSL https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.15.3-amd64.deb \
        -o /tmp/elastic-agent.deb && \
    ln -sf /bin/true /usr/bin/systemctl && \
    dpkg -i /tmp/elastic-agent.deb && \
    rm -f /usr/bin/systemctl /tmp/elastic-agent.deb

COPY workloads/ /opt/workloads/
RUN chmod +x /opt/workloads/*.sh

# Three independent monitoring tools probe target-endpoint on their own
# cadences, each with a stable username. This matches real orgs that run
# multiple health-check tools in parallel, and gives the agent's screen /
# ticket-context subagents clean repeats-clusters to work with (one cluster
# per (srcip, srcuser) triple rather than a single rotating one).
#
# Cadences offset to reduce exact-minute collisions:
#   nagios      every  5 min, starting at :00  → 12 alerts/hour
#   zabbix      every 10 min, starting at :02  →  6 alerts/hour
#   healthcheck every 15 min, starting at :07  →  4 alerts/hour
#
# Bait workload (multi-attempt variant) is NOT in cron — triggered on demand.
RUN { \
        echo "*/5 * * * * root /opt/workloads/monitoring_probe.sh nagios >> /var/log/monitoring.log 2>&1"; \
        echo "2-59/10 * * * * root /opt/workloads/monitoring_probe.sh zabbix >> /var/log/monitoring.log 2>&1"; \
        echo "7-59/15 * * * * root /opt/workloads/monitoring_probe.sh healthcheck >> /var/log/monitoring.log 2>&1"; \
    } > /etc/cron.d/monitoring && \
    chmod 0644 /etc/cron.d/monitoring && \
    touch /var/log/monitoring.log

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/var/log/monitoring.log"]
