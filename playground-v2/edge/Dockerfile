# The lab's keyed ingress (#1391 r6 L1): nginx, its rules rendered from lab-surface.json (the one
# table of ports and declared writes). Build context: playground-v2/.
FROM python:3.12-slim AS render
COPY lab-surface.json /src/lab-surface.json
COPY edge/render.py /src/render.py
RUN python /src/render.py /src/lab-surface.json /out

FROM nginx:1.27.5-alpine
COPY --from=render /out/ /etc/edge/
COPY edge/entrypoint.sh /usr/local/bin/edge-entrypoint
# nginx shuts down fast on SIGTERM itself, as PID 1. Never `python app.py` (Shuffle's reaper).
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/edge-entrypoint"]
