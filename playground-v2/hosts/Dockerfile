# syntax=docker/dockerfile:1
#
# Multi-stage image for every role-clustered playground host. A single file
# keeps the base layer shared (BuildKit caches it once per BASE_OS) without
# requiring compose to order image builds across services — which compose
# doesn't do. Each compose service picks a stage via `target:` and a BASE_OS
# via build arg.
#
# Context: playground-v2/ (whole dir). Required so the image can pull both
# hosts/inventory.yaml and keycloak/realm.yaml, the joint source of truth for
# user seeding. See playground-v2/.dockerignore for the trim list.
#
# Stages:
#   base  — every host: sshd + rsyslog + cron + common tools + user seeding
#   plain — just `base` under a nicer target name (jump-box / dev-ws / office-ws / canary)
#   web   — base + nginx + stub index.html
#   db    — base + postgresql (default cluster; auth is batch-8 work)

ARG BASE_OS=22.04
# STACK_VERSION is threaded in by compose from .env so the agent deb stays
# pinned to the same version as Elasticsearch / Kibana / Fleet Server.
ARG STACK_VERSION

# ─────────────────────────────────────────────────────────────────────────────
# Stage: base
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:${BASE_OS} AS base
ARG STACK_VERSION

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server \
      sudo \
      rsyslog \
      cron \
      python3 \
      python3-yaml \
      ca-certificates \
      curl \
      dnsutils \
      iproute2 \
      iputils-ping \
      net-tools \
      netcat-openbsd \
      procps \
      less \
      vim-tiny \
      tini \
      sshpass \
      postgresql-client \
      gcc \
    && rm -rf /var/lib/apt/lists/*

# Install elastic-agent. Enrollment + `run` happen at container start (entrypoint
# → agent-enroll.sh) because the enrollment token isn't known until the
# fleet-host-policies init has run against Kibana.
#
# The deb's postinst tries to enable/start the service via systemctl, which
# fails in a systemd-less build container. Stub systemctl with /bin/true for
# the install window only. State dir /var/lib/elastic-agent is persisted via
# a per-host named volume (see compose.yml) so agent.id stays stable across
# recreates — avoids stale "offline" ghosts piling up in Fleet.
RUN if [ -z "$STACK_VERSION" ]; then echo "STACK_VERSION build-arg required"; exit 1; fi \
    && curl -fsSL "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${STACK_VERSION}-amd64.deb" \
         -o /tmp/elastic-agent.deb \
    && ln -sf /bin/true /usr/bin/systemctl \
    && dpkg -i /tmp/elastic-agent.deb \
    && rm -f /usr/bin/systemctl /tmp/elastic-agent.deb

# sshd requires /run/sshd; password auth on for realm users, root locked.
RUN mkdir -p /run/sshd \
    && sed -i -E \
        -e 's|^#?PermitRootLogin.*|PermitRootLogin no|' \
        -e 's|^#?PasswordAuthentication.*|PasswordAuthentication yes|' \
        -e 's|^#?UsePAM.*|UsePAM yes|' \
        /etc/ssh/sshd_config

# Pre-create rsyslog's output files — triage relies on /var/log/auth.log
# existing whether or not anyone has logged in yet.
RUN touch /var/log/auth.log /var/log/syslog \
    && chown syslog:adm /var/log/auth.log /var/log/syslog

COPY hosts/base/seed-users.py     /opt/soc-playground/seed-users.py
COPY hosts/base/entrypoint.sh     /usr/local/bin/host-entrypoint.sh
COPY hosts/base/agent-enroll.sh   /usr/local/bin/agent-enroll.sh
COPY hosts/base/baseline/         /opt/soc-playground/baseline/
COPY hosts/inventory.yaml         /opt/soc-playground/inventory.yaml
COPY keycloak/realm.yaml          /opt/soc-playground/realm.yaml
RUN chmod +x /usr/local/bin/host-entrypoint.sh \
             /usr/local/bin/agent-enroll.sh \
             /opt/soc-playground/seed-users.py \
             /opt/soc-playground/baseline/scheduler.py

# HOST_NAME must be set by compose — entrypoint fails loudly otherwise.
ENV HOST_NAME=""

# tini reaps zombies from background services (rsyslog/cron/role daemons) so
# sshd's short-lived session children don't turn into zombies either.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/host-entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D"]

# ─────────────────────────────────────────────────────────────────────────────
# Stage: plain — alias for base, used by role-less hosts
# ─────────────────────────────────────────────────────────────────────────────
FROM base AS plain

# ─────────────────────────────────────────────────────────────────────────────
# Stage: web — nginx serving a stub corporate landing page
# ─────────────────────────────────────────────────────────────────────────────
FROM base AS web

RUN apt-get update && apt-get install -y --no-install-recommends nginx \
    && rm -rf /var/lib/apt/lists/*

COPY hosts/web/index.html        /var/www/html/index.html
COPY hosts/web/role-start.sh     /opt/soc-playground/role-start.sh
RUN chmod +x /opt/soc-playground/role-start.sh

# ─────────────────────────────────────────────────────────────────────────────
# Stage: db — postgres default cluster
# ─────────────────────────────────────────────────────────────────────────────
FROM base AS db

RUN apt-get update && apt-get install -y --no-install-recommends postgresql \
    && rm -rf /var/lib/apt/lists/*

COPY hosts/db/role-start.sh      /opt/soc-playground/role-start.sh
RUN chmod +x /opt/soc-playground/role-start.sh
