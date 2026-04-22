# Tiny Unbound container — recursive resolver + playground-local zone with query logging.
# Alpine + `apk add unbound` keeps the surface small; no init system needed (unbound -d
# runs foreground, respects SIGTERM, works with docker's default PID 1 handling).
FROM alpine:3.20
RUN apk add --no-cache unbound \
  && mkdir -p /var/lib/unbound \
  && chown unbound:unbound /var/lib/unbound
COPY unbound.conf /etc/unbound/unbound.conf
EXPOSE 53/tcp 53/udp
# -d = foreground, -c = config path; default user is root but unbound drops to `unbound` per conf.
CMD ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
