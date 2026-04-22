# Zeek passive monitor. Runs on host network mode, listens on `any` interface,
# writes conn/dns/http/ssl/files logs as JSON to the `zeek_logs` volume (ingestion
# into Elastic is a later batch — Elastic ships a Zeek integration).
#
# Using the upstream LTS image rather than rolling our own — Zeek's build surface
# (libpcap, openssl, broker, scripts) is not worth rebuilding for a playground.
FROM zeek/zeek:lts
# `ip` (iproute2) is needed by entrypoint.sh for interface discovery; not in the
# base image.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
