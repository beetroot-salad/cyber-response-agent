# Build context is playground-v2/ (not ./identity) so the image can COPY
# keycloak/realm.yaml and hosts/inventory.yaml — both are sources of truth
# outside this dir. Matches the cmdb/ pattern; .dockerignore at the
# playground-v2/ root whitelists identity/** alongside hosts/** + cmdb/** +
# keycloak/realm.yaml to keep the build tar small.
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "fastapi==0.115.*" \
    "uvicorn[standard]==0.32.*" \
    "pyyaml==6.*"

COPY identity/app.py /app/app.py
COPY keycloak/realm.yaml /opt/identity/realm.yaml
COPY hosts/inventory.yaml /opt/identity/inventory.yaml

ENV IDENTITY_REALM_PATH=/opt/identity/realm.yaml \
    IDENTITY_INVENTORY_PATH=/opt/identity/inventory.yaml

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
