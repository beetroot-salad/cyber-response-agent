# Tiny image for the `keycloak-init` one-shot. Bundles realm.yaml + seed.py so the
# build context (uploaded to the remote Docker daemon at compose-build time) carries
# them to the VPS — bind-mounts / compose `configs:` resolve on the daemon side, not
# the client, so we can't just reference local paths.
FROM python:3.12-alpine
RUN pip install --quiet --disable-pip-version-check --no-cache-dir pyyaml
WORKDIR /config
COPY realm.yaml seed.py ./
