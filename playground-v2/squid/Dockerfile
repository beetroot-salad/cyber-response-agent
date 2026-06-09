# Forward proxy with basic-auth user attribution. Two-stage build:
# 1. hashgen — alpine + apache2-utils produces bcrypt'd htpasswd entries for the
#    13 Keycloak-seed users (same plaintext password: "changeme"). Bcrypt is overkill
#    for a playground but it's what htpasswd emits by default under -B.
# 2. runtime — ubuntu/squid:latest with squid.conf + the baked passwd file.
#
# Username list matches playground-v2/keycloak/realm.yaml. If that list changes, update
# here too — there's no cross-file validation; the invariant is maintained by the human.

FROM alpine:3.20 AS hashgen
RUN apk add --no-cache apache2-utils && \
    touch /tmp/passwd && \
    for u in sre.alice sre.ben sre.chen \
             dev.dana dev.ethan dev.fatima dev.gabe dev.hira \
             dba.ivy \
             svc.backups svc.reports svc.monitoring \
             svc.config-mgmt svc.deploy svc.security \
             ctr.kai; do \
      htpasswd -bB /tmp/passwd "$u" changeme; \
    done

FROM ubuntu/squid:latest
COPY squid.conf /etc/squid/squid.conf
COPY --from=hashgen /tmp/passwd /etc/squid/passwd
# Squid runs as `proxy` and writes to regular files in /var/log/squid/; the
# ubuntu/squid image's entrypoint then runs `tail -F` on those files to forward
# content to container stdout. Symlinking them to /dev/stdout looks tempting but
# fails — squid's own parent-dir writability check can't traverse the symlink.
RUN chown proxy:proxy /etc/squid/passwd && chmod 640 /etc/squid/passwd \
  && mkdir -p /var/log/squid \
  && chown -R proxy:proxy /var/log/squid
