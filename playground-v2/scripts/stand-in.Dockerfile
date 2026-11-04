# The frozen engine's Elasticsearch and Kibana stand-ins (#1347 D2 ii): the shell and curl the
# Elastic adapter execs into its container, and the forwarder to the live service. Built and
# saved by capture as a freeze part (scripts/lab_ops.py), so a launch installs nothing.
FROM alpine:3.20
RUN apk add --no-cache bash curl socat
