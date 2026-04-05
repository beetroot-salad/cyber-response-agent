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
    && rm -rf /var/lib/apt/lists/*

# Configure openssh-server
RUN mkdir -p /run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Install Wazuh agent (4.9.x to match manager)
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=4.9.2-1 && \
    rm -rf /var/lib/apt/lists/* && \
    update-rc.d wazuh-agent defaults 95 10

# Create a non-root user for simulating user activity
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:testpassword" | chpasswd && \
    usermod -aG sudo testuser

# Copy workload scripts
COPY workloads/ /opt/workloads/
RUN chmod +x /opt/workloads/*.sh

# Create cron job for workloads
RUN echo "*/5 * * * * root /opt/workloads/benign_activity.sh >> /var/log/workload.log 2>&1" > /etc/cron.d/workload && \
    echo "*/15 * * * * root /opt/workloads/suspicious_patterns.sh >> /var/log/workload.log 2>&1" >> /etc/cron.d/workload && \
    chmod 0644 /etc/cron.d/workload

# Startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create log directory
RUN touch /var/log/workload.log

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
