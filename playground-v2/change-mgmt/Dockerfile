FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "fastapi==0.115.*" \
    "uvicorn[standard]==0.32.*" \
    "pyyaml==6.*"

COPY app.py /app/app.py
COPY seed /app/seed

ENV CHANGE_SEED_PATH=/app/seed/changes.yaml

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
