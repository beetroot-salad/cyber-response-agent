# syntax=docker/dockerfile:1
#
# Falco image with the playground config baked in. Shipping config via a
# build-context image (rather than compose `configs: file:` or a bind mount)
# is required because both of those resolve paths on the remote daemon, which
# has no /workspace tree — see memory reference_compose_configs_remote_daemon.md.
ARG FALCO_VERSION

# Stage 1: pull the official sandbox + incubating rule packs from the
# Falco artifact registry. The main falco image dropped falcoctl in
# 0.43.x; the driver-loader image still ships it, so we use it as a
# build-only sidecar to fetch the rule YAMLs.
FROM falcosecurity/falco-driver-loader:${FALCO_VERSION} AS rules-fetcher
# Pinned deliberately. `falcoctl artifact install container` (unpinned) resolves
# to the plugin's `latest`, whose required plugin-API version marches ahead of
# the framework API that the pinned FALCO_VERSION provides. An unpinned install
# therefore turns a rebuild months later into a crash loop:
#   cannot load plugin libcontainer.so: plugin required API version '3.10.0'
#   not compatible with the framework's API version '3.7.0'. Exiting.
# Bump this only together with FALCO_VERSION, and start the container once.
ARG CONTAINER_PLUGIN_VERSION
# The rule packs carry the same drift risk, for a sharper reason: the overrides
# in falco_rules.local.yaml bind to upstream rules by exact name with
# `override: condition: append`, which requires the parent rule to already
# exist. A rename or removal in a later `latest` therefore makes Falco refuse
# to load the file outright. Defaulted rather than sourced from .env so a
# checkout without the var still builds the verified pairing; override at build
# time to move them. These two are the versions `latest` resolved to for Falco
# 0.43.0 (digest-identical, so pinning changed no rule content).
ARG SANDBOX_RULES_VERSION=6.1.0
ARG INCUBATING_RULES_VERSION=6.0.1
# The var lives in .env, which is gitignored — an .env predating this pin
# interpolates to the empty string and compose passes `--build-arg
# CONTAINER_PLUGIN_VERSION=`, which reaches falcoctl as the ref `container:`.
# Fail here with the fix instead of on an unrelated-looking registry error.
RUN test -n "${CONTAINER_PLUGIN_VERSION}" \
       || { echo "CONTAINER_PLUGIN_VERSION is empty - add it to playground-v2/.env (see .env.example)" >&2; exit 1; } \
    && mkdir -p /rules /plugins \
    && falcoctl artifact install --rulesfiles-dir /rules falco-sandbox-rules:${SANDBOX_RULES_VERSION} \
    && falcoctl artifact install --rulesfiles-dir /rules falco-incubating-rules:${INCUBATING_RULES_VERSION} \
    && falcoctl artifact install --plugins-dir /plugins container:${CONTAINER_PLUGIN_VERSION}

# Stage 2: the runtime image. Sandbox adds breadth (write-below-root,
# payload decode, drift detection); incubating adds attack-pattern
# coverage (authorized_keys writes, package-manager launches, suspicious
# network tools). https://github.com/falcosecurity/rules
FROM falcosecurity/falco:${FALCO_VERSION}
COPY --from=rules-fetcher /rules/ /etc/falco/rules.d/
COPY --from=rules-fetcher /plugins/ /usr/share/falco/plugins/
COPY falco.yaml /etc/falco/falco.yaml
# Playground-specific suppressions for agent-internal + healthcheck
# noise. Lands in rules.d with a `zz_` prefix so it loads after the
# sandbox + incubating rule packs (`condition: append` requires the
# parent rule to already exist). See the file itself for per-rule
# rationale.
COPY falco_rules.local.yaml /etc/falco/rules.d/zz_playground_overrides.yaml
