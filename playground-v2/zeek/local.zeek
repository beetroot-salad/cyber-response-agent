# Playground local site config.
# Keep changes here (not in zeek/share) so image bumps don't stomp on them.

# JSON logs — Elastic's zeek integration ingests either ASCII or JSON; JSON is
# easier to grep / jq when debugging, and avoids needing a separate log-format
# plugin on the collector side.
@load policy/tuning/json-logs.zeek

# Local CIDRs Zeek uses for "is this traffic originating internally" classification.
# These match the private RFC1918 ranges + docker's default bridge network; revise
# in batch 7 when the workload network gets its own /24.
redef Site::local_nets = {
    10.0.0.0/8,
    172.16.0.0/12,
    192.168.0.0/16,
    127.0.0.0/8,
};

# Tag the source — when multiple sensors land, this disambiguates which VPS / site.
redef peer_description = "soc-playground-vps";

# Rotate logs hourly (default) and keep the last 24h under /usr/local/zeek/logs.
# Volume mount is `zeek_logs:/usr/local/zeek/logs`; Elastic Agent will later watch
# current/ for files.log, conn.log, dns.log, http.log, ssl.log.
