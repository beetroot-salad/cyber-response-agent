# The lab's keyed ingress (#1391 r6 L1). Build context: playground-v2/ (it copies
# lab-surface.json, the one table of ports and declared writes).
FROM python:3.12-slim
WORKDIR /app
COPY lab-surface.json /app/lab-surface.json
COPY edge/edge.py /app/edge.py
# Never `python app.py`: Shuffle's reaper kills any container whose command contains it.
ENTRYPOINT ["python", "/app/edge.py"]
