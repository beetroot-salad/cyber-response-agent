# syntax=docker/dockerfile:1
#
# Falco image with the playground config baked in. Shipping config via a
# build-context image (rather than compose `configs: file:` or a bind mount)
# is required because both of those resolve paths on the remote daemon, which
# has no /workspace tree — see memory reference_compose_configs_remote_daemon.md.
ARG FALCO_VERSION
FROM falcosecurity/falco:${FALCO_VERSION}

COPY falco.yaml /etc/falco/falco.yaml
