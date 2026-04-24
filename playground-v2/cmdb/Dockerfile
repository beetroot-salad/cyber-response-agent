# Build context is playground-v2/ (not ./cmdb) so the image can COPY
# hosts/inventory.yaml — that file is the CMDB's source of truth and it lives
# outside this dir. Matches the hosts/ build pattern; .dockerignore at the
# playground-v2/ root whitelists hosts/** and cmdb/** to keep the tar small.
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "fastapi==0.115.*" \
    "uvicorn[standard]==0.32.*" \
    "pyyaml==6.*"

COPY cmdb/app.py /app/app.py
COPY hosts/inventory.yaml /opt/cmdb/inventory.yaml

ENV CMDB_INVENTORY_PATH=/opt/cmdb/inventory.yaml

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
