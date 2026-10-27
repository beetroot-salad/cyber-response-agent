# Kibana with the repo's kibana.yml baked in. Built rather than bind-mounted: compose resolves
# bind-mount paths on the remote daemon (the VPS), which has no copy of this repo.
ARG STACK_VERSION
FROM docker.elastic.co/kibana/kibana:${STACK_VERSION}
COPY --chown=1000:0 kibana.yml /usr/share/kibana/config/kibana.yml
COPY --chmod=0755 with-previous-key.sh /usr/local/bin/with-previous-key.sh
CMD ["/usr/local/bin/with-previous-key.sh", "/usr/local/bin/kibana-docker"]
