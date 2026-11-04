FROM python:3.12-slim

WORKDIR /app
COPY watcher.py /app/watcher.py

# Not `python app.py`: Shuffle's reaper kills any container whose command contains that
# (see playground-v2/CLAUDE.md).
CMD ["python", "-u", "/app/watcher.py"]
