FROM ubuntu:22.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install base dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    net-tools \
    netcat \
    procps \
    cron \
    python3 \
    python3-pip \
    vim \
    sudo \
    iproute2 \
    iputils-ping \
    tcpdump \
    strace \
    gnupg \
    apt-transport-https \
    openssh-server \
    rsyslog \
    dnsmasq \
    dnsutils \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Configure openssh-server
RUN mkdir -p /run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Configure dnsmasq as local DNS resolver with query logging
RUN echo '# Local DNS resolver with query logging for security monitoring' > /etc/dnsmasq.conf && \
    echo 'listen-address=127.0.0.1' >> /etc/dnsmasq.conf && \
    echo 'port=53' >> /etc/dnsmasq.conf && \
    echo 'bind-interfaces' >> /etc/dnsmasq.conf && \
    echo 'log-queries' >> /etc/dnsmasq.conf && \
    echo 'log-facility=/var/log/dnsmasq.log' >> /etc/dnsmasq.conf && \
    echo 'cache-size=0' >> /etc/dnsmasq.conf && \
    echo '# Forward to external DNS' >> /etc/dnsmasq.conf && \
    echo 'server=8.8.8.8' >> /etc/dnsmasq.conf && \
    echo 'server=8.8.4.4' >> /etc/dnsmasq.conf

# Install Wazuh agent (must match manager version)
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=4.7.5-1 && \
    rm -rf /var/lib/apt/lists/* && \
    update-rc.d wazuh-agent defaults 95 10

# Configure Wazuh agent: localfile entries (auth.log, syslog, dnsmasq)
RUN sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/syslog</location>\n  </localfile>\n\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/dnsmasq.log</location>\n  </localfile>' /var/ossec/etc/ossec.conf

# Configure Wazuh agent: faster syscheck for testing (5 min instead of 12 hours)
# and realtime monitoring on /etc for FIM alerts
RUN sed -i 's|<frequency>43200</frequency>|<frequency>300</frequency>|' /var/ossec/etc/ossec.conf && \
    sed -i 's|<directories>/etc,/usr/bin,/usr/sbin</directories>|<directories realtime="yes" report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>|' /var/ossec/etc/ossec.conf

# Create a non-root user for simulating user activity
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:testpassword" | chpasswd && \
    usermod -aG sudo testuser

# Copy workload scripts
COPY workloads/ /opt/workloads/
RUN chmod +x /opt/workloads/*.sh

# Create cron jobs for workloads
RUN echo "*/5 * * * * root /opt/workloads/benign_activity.sh >> /var/log/workload.log 2>&1" > /etc/cron.d/workload && \
    echo "*/15 * * * * root /opt/workloads/suspicious_patterns.sh >> /var/log/workload.log 2>&1" >> /etc/cron.d/workload && \
    echo "*/10 * * * * root /opt/workloads/fim_activity.sh >> /var/log/workload.log 2>&1" >> /etc/cron.d/workload && \
    echo "*/5 * * * * root /opt/workloads/dns_activity.sh >> /var/log/workload.log 2>&1" >> /etc/cron.d/workload && \
    chmod 0644 /etc/cron.d/workload

# Startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create log files
RUN touch /var/log/workload.log /var/log/dnsmasq.log

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
