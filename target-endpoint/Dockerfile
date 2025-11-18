FROM ubuntu:22.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
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
    && rm -rf /var/lib/apt/lists/*

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
