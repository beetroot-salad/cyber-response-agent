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

# Monitoring probe runs every 10 min. Creates steady-state noise of routine
# health-check 5710 alerts against target-endpoint. Bait workload (multi-attempt
# variant) is NOT in cron — it's triggered on demand per eval scenario.
RUN echo "*/10 * * * * root /opt/workloads/monitoring_probe.sh >> /var/log/monitoring.log 2>&1" > /etc/cron.d/monitoring && \
    chmod 0644 /etc/cron.d/monitoring && \
    touch /var/log/monitoring.log

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/var/log/monitoring.log"]
