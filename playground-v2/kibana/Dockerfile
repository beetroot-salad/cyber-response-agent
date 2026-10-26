# Kibana with the repo's kibana.yml baked in. Built rather than bind-mounted: compose resolves
# bind-mount paths on the remote daemon (the VPS), which has no copy of this repo.
ARG STACK_VERSION
FROM docker.elastic.co/kibana/kibana:${STACK_VERSION}
COPY kibana.yml /usr/share/kibana/config/kibana.yml
