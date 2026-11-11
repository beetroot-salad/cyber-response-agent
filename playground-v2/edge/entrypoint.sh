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
    # The key lands inside a quoted nginx string: allow only characters that cannot end it.
    case "$V2_LAB_API_KEY" in
        *[!A-Za-z0-9._~+/=-]*)
            echo "V2_LAB_API_KEY has characters outside A-Za-z0-9._~+/=- : refusing" >&2
            exit 2 ;;
    esac
    envsubst '${V2_LAB_API_KEY}' < /etc/edge/nginx-keyed.conf.template > /tmp/nginx.conf
    chmod 600 /tmp/nginx.conf
fi
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
