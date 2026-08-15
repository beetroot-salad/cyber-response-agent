FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "fastapi==0.115.*" \
    "uvicorn[standard]==0.32.*"

COPY app.py /app/app.py

ENV TICKET_SEED_PATH=/app/seed/tickets.json

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
