#!/bin/sh
# The lab edge (#1391 r6 L1): nginx with the config edge/render.py made from lab-surface.json.
# Live: the key comes from the environment, never the command line, and nginx starts only with one.
# `--no-key-check`: the frozen engine's frontend, reached only through the operator's SSH forward.
set -eu
if [ "${1:-}" = "--no-key-check" ]; then
    cp /etc/edge/nginx-open.conf /tmp/nginx.conf
else
    if [ -z "${V2_LAB_API_KEY:-}" ]; then
        echo "V2_LAB_API_KEY is not set: the edge refuses to start without a key" >&2
        exit 2
    fi
    # Lowercase hex, at least 32 digits (`openssl rand -hex 32`): nginx compares the key ignoring
    # case, which loses nothing when it has no letters of another case; and it lands inside a
    # quoted nginx string, which nothing in it can end.
    case "$V2_LAB_API_KEY" in
        *[!0-9a-f]*)
            echo "V2_LAB_API_KEY must be lowercase hex (openssl rand -hex 32): refusing" >&2
            exit 2 ;;
    esac
    if [ "${#V2_LAB_API_KEY}" -lt 32 ] || [ "${#V2_LAB_API_KEY}" -gt 128 ]; then
        echo "V2_LAB_API_KEY must be 32 to 128 hex digits (openssl rand -hex 32): refusing" >&2
        exit 2
    fi
    envsubst '${V2_LAB_API_KEY}' < /etc/edge/nginx-keyed.conf.template > /tmp/nginx.conf
    chmod 600 /tmp/nginx.conf
fi
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
