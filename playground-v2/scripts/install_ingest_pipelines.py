#!/usr/bin/env python3
"""Install playground-v2/ingest/*.json as Elasticsearch ingest pipelines, and attach them to
the data streams they normalize.

WHY THIS EXISTS. Falco reaches Elasticsearch through a Fleet custom-logs input whose only
processing is `decode_json_fields` into `falco.*` (docs/runbook.md §Falco). The entities that
discriminate a container-runtime alert — container id, process name, command line — therefore
live only under `falco.output_fields.*`, and that namespace is NOT mapped in the security
alerts index: `_field_caps` for `falco.*` there returns zero fields. A detection alert built
from a Falco event carries those values in `_source` while no query can reach them, so a term
on one returns `total: 0` with no error, indistinguishable from a genuine absence. Measured on
2026-08-13: across all four Falco-sourced rules, `container.id` / `process.name` / `user.name`
/ `source.ip` are populated on ZERO alerts while `host.name` is populated on all of them and
names the shared VPS every containerized alert reports from (issue #867).

Copying the values onto the ECS fields the alerts index already maps is what makes a Falco
alert queryable by what it is about.

Transport mirrors install_detection_rules.py: `docker --context soc-playground exec
elasticsearch curl` against localhost:9200 inside the container, so no SSH tunnel is needed.

Usage:
  python3 playground-v2/scripts/install_ingest_pipelines.py [--dry-run] [--no-rollover]

Exit codes:
  0 — every pipeline installed and attached
  1 — an Elasticsearch API error on at least one step
  2 — config/auth/connectivity failure
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

PLAYGROUND = Path(__file__).resolve().parent.parent
INGEST_DIR = PLAYGROUND / "ingest"
DOCKER_CONTEXT = "soc-playground"
ES_CONTAINER = "elasticsearch"
ES_URL = "https://localhost:9200"

#: pipeline id -> the data stream it normalizes. The `@custom` component template is the
#: Elastic-sanctioned attachment point for an integration-managed data stream: Fleet owns the
#: index template and rewrites it on package upgrade, but it composes `<type>-<dataset>@custom`
#: last, so settings written there survive. Writing `default_pipeline` onto the Fleet-owned
#: template directly would be reverted by the next package install.
ATTACH = {
    "falco-ecs-entities": {
        "data_stream": "logs-falco.alerts-default",
        "component_template": "logs-falco.alerts@custom",
    },
}


def es_curl(method: str, path: str, body: str | None = None) -> tuple[int, str]:
    """curl inside the ES container, authenticating with THAT container's own
    `ELASTIC_PASSWORD` — the same approach as `infra/bin/es.sh`, and deliberately not
    `install_detection_rules.py`'s, which reads the password locally and passes it on the
    `docker exec` command line. Nothing here needs to hold the secret, so nothing here does."""
    args = ["docker", "--context", DOCKER_CONTEXT, "exec"]
    if body is not None:
        args += ["-e", f"BODY={body}"]
    parts = [
        "curl -ks", '-u "elastic:${ELASTIC_PASSWORD}"',
        '-H "Content-Type: application/json"',
        f"-X {method}", f'"{ES_URL}{path}"',
    ]
    if body is not None:
        parts.append('--data "$BODY"')
    parts.append(r'-w "\n%{http_code}\n"')
    args += [ES_CONTAINER, "sh", "-c", " ".join(parts)]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        # SAY WHY. A bare `sys.exit(1)` here printed nothing at all when the rollover's
        # `docker exec` failed, so the step looked like it had been skipped rather than like it
        # had broken — the same silent-failure shape this pipeline exists to remove.
        sys.exit(
            f"transport failed for {method} {path} (rc={proc.returncode}): "
            f"{proc.stderr.strip()[:300] or '(no stderr)'}"
        )
    out = proc.stdout
    lines = [ln for ln in out.split("\n") if ln != ""]
    if not lines:
        return 0, out
    try:
        return int(lines[-1]), "\n".join(lines[:-1])
    except ValueError:
        return 0, out


def _ok(code: int) -> bool:
    return 200 <= code < 300


def install(path: Path, dry_run: bool, rollover: bool) -> bool:
    pipeline_id = path.stem
    spec = json.loads(path.read_text(encoding="utf-8"))
    attach = ATTACH.get(pipeline_id)

    if dry_run:
        print(f"  DRY-RUN would install pipeline {pipeline_id} "
              f"({len(spec.get('processors', []))} processors)"
              + (f" and attach to {attach['data_stream']}" if attach else ""))
        return True

    code, body = es_curl("PUT", f"/_ingest/pipeline/{pipeline_id}", json.dumps(spec))
    if not _ok(code):
        print(f"  FAIL pipeline {pipeline_id}: HTTP {code} {body[:200]}", file=sys.stderr)
        return False
    print(f"  installed pipeline {pipeline_id}")

    if not attach:
        return True

    ct = attach["component_template"]
    ct_body = json.dumps({"template": {"settings": {"index.default_pipeline": pipeline_id}}})
    code, body = es_curl("PUT", f"/_component_template/{ct}", ct_body)
    if not _ok(code):
        print(f"  FAIL component template {ct}: HTTP {code} {body[:200]}", file=sys.stderr)
        return False
    print(f"  attached via {ct} (index.default_pipeline={pipeline_id})")

    # A component template only reaches documents through an index template that COMPOSES it.
    # Fleet's own template for an integration data stream composes `<type>-<dataset>@custom`,
    # but a custom-logs input's template is generated and that is worth verifying rather than
    # assuming — a silent non-composition is exactly the "looks installed, changes nothing"
    # shape this whole issue is about.
    code, body = es_curl("GET", f"/_index_template/{attach['data_stream'].rsplit('-', 1)[0]}")
    composed: list[str] = []
    if _ok(code):
        try:
            tpls = json.loads(body).get("index_templates", [])
            if tpls:
                composed = tpls[0].get("index_template", {}).get("composed_of", []) or []
        except (ValueError, KeyError, IndexError):
            composed = []
    if ct in composed:
        print(f"  verified: index template composes {ct}")
    else:
        print(f"  WARNING: the index template does not compose {ct} "
              f"(composed_of={composed}) — the pipeline is installed but will NOT run. "
              f"Add {ct} to the template's composed_of, or set index.default_pipeline "
              f"on the data stream directly.", file=sys.stderr)
        return False

    if rollover:
        code, body = es_curl("POST", f"/{attach['data_stream']}/_rollover", "{}")
        if _ok(code):
            print(f"  rolled over {attach['data_stream']} — new backing index picks the "
                  "pipeline up (existing documents are NOT reprocessed)")
        else:
            print(f"  WARNING: rollover failed HTTP {code} {body[:160]}", file=sys.stderr)
    return True


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-rollover", action="store_true",
                    help="install without rolling the data stream (the pipeline then applies "
                         "only from the next natural rollover)")
    ns = ap.parse_args(argv)

    if not INGEST_DIR.is_dir():
        print(f"no ingest dir at {INGEST_DIR}", file=sys.stderr)
        return 2
    specs = sorted(INGEST_DIR.glob("*.json"))
    if not specs:
        print(f"no *.json under {INGEST_DIR}", file=sys.stderr)
        return 2

    print(f"installing {len(specs)} pipeline(s) from {INGEST_DIR.relative_to(PLAYGROUND.parent)}")
    ok = all([install(p, ns.dry_run, not ns.no_rollover) for p in specs])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
