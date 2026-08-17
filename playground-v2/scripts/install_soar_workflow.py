#!/usr/bin/env python3
"""Install Shuffle workflows from playground-v2/soar/workflows/*.json.

Upserts each workflow by name: rewrites the instance-specific fields an exported
workflow carries (org_id, execution environment), then creates or updates it.
Idempotent and order-independent.

Transport: shells out to `docker --context soc-playground exec kibana curl`
against http://shuffle-backend:5001. Kibana is the curl host because the
shuffle-backend image ships no curl, and Kibana is dual-homed onto `soar` — so
no SSH tunnel is needed from the devcontainer.

Auth: bearer token from $V2_SHUFFLE_API_KEY or playground-v2/.env — whatever
SHUFFLE_DEFAULT_APIKEY was set to at first boot.

Workflow JSON comes from building a workflow in the UI and exporting it (see
soar/workflows/README.md); app creation has no API and stays a UI step.

Shuffle publishes no reference for these routes — they were read off a running
instance and collected in ROUTES. Run `--probe` after a Shuffle upgrade: it
exercises auth and every read path without writing, and names the route that
disagrees.

Usage:
  python3 playground-v2/scripts/install_soar_workflow.py [--dry-run|--probe]

Exit codes:
  0 — all workflows installed (or probe passed)
  1 — Shuffle API error on at least one workflow (others may still have
      installed), or a config/auth/connectivity failure, reason on stderr
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

PLAYGROUND = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = PLAYGROUND / "soar" / "workflows"
ENV_FILE = PLAYGROUND / ".env"
DOCKER_CONTEXT = "soc-playground"
CURL_CONTAINER = "kibana"
SHUFFLE_URL = "http://shuffle-backend:5001"

ROUTES = {
    "orgs": "/api/v1/orgs",
    "environments": "/api/v1/getenvironments",
    "workflows": "/api/v1/workflows",
}


def load_api_key() -> str:
    if key := os.environ.get("V2_SHUFFLE_API_KEY"):
        return key
    if ENV_FILE.is_file():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("V2_SHUFFLE_API_KEY="):
                return line.split("=", 1)[1].strip()
    sys.exit("V2_SHUFFLE_API_KEY not set and not found in playground-v2/.env")


def _curl_command(method: str, path: str, has_body: bool) -> str:
    parts = [
        "curl -ks",
        '-H "Authorization: Bearer $SHUFFLE_KEY"',
        '-H "Content-Type: application/json"',
        f"-X {method}",
        f'"{SHUFFLE_URL}{path}"',
    ]
    if has_body:
        parts.append('--data "$BODY"')
    # http code on its own trailing line so it splits off the body
    parts.append(r'-w "\n%{http_code}\n"')
    return " ".join(parts)


def shuffle_curl(key: str, method: str, path: str, body: str | None = None) -> tuple[int, str]:
    """Run curl inside the kibana container against Shuffle, return (http_code, body)."""
    args = ["docker", "--context", DOCKER_CONTEXT, "exec", "-e", f"SHUFFLE_KEY={key}"]
    if body is not None:
        args += ["-e", f"BODY={body}"]
    args += [CURL_CONTAINER, "sh", "-c", _curl_command(method, path, body is not None)]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"docker exec failed (rc={proc.returncode}): {proc.stderr.strip()}")
    out = proc.stdout
    lines = out.rsplit("\n", 2)
    if len(lines) < 2:
        return 0, out
    try:
        code = int(lines[-2] if lines[-1] == "" else lines[-1])
    except ValueError:
        return 0, out
    return code, "\n".join(lines[: -2 if lines[-1] == "" else -1])


def get_json(key: str, route: str) -> object:
    code, body = shuffle_curl(key, "GET", ROUTES[route])
    if code != 200:
        sys.exit(f"GET {ROUTES[route]} returned HTTP {code}: {body[:400]}")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        sys.exit(f"GET {ROUTES[route]} returned non-JSON (HTTP {code}): {body[:400]}")


def _as_list(payload: object) -> list:
    """Shuffle returns either a bare list or {"success":..., "data"|"orgs": [...]}."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for field in ("data", "orgs", "workflows", "environments"):
            if isinstance(payload.get(field), list):
                return payload[field]
    return []


def resolve_context(key: str) -> tuple[str, str]:
    """Return (org_id, environment_name) for this instance."""
    orgs = _as_list(get_json(key, "orgs"))
    if not orgs:
        sys.exit("no orgs returned — has the first-boot admin bootstrap run?")
    org_id = orgs[0].get("id") or orgs[0].get("Id") or ""
    if not org_id:
        sys.exit(f"could not read an org id from: {json.dumps(orgs[0])[:300]}")

    envs = _as_list(get_json(key, "environments"))
    names = [e.get("Name") or e.get("name") for e in envs if isinstance(e, dict)]
    names = [n for n in names if n]
    if not names:
        sys.exit("no execution environments returned — is shuffle-orborus running?")
    # Prefer the one Orborus registers (ENVIRONMENT_NAME in soar/compose.yml).
    env_name = "Shuffle" if "Shuffle" in names else names[0]
    return org_id, env_name


def existing_by_name(key: str) -> dict[str, str]:
    return {
        wf.get("name"): wf.get("id")
        for wf in _as_list(get_json(key, "workflows"))
        if isinstance(wf, dict) and wf.get("name") and wf.get("id")
    }


def retarget(workflow: dict, org_id: str, env_name: str) -> dict:
    """Rewrite the instance-specific fields an exported workflow carries."""
    wf = json.loads(json.dumps(workflow))  # deep copy
    wf["org_id"] = org_id
    wf.pop("owner", None)
    for action in wf.get("actions") or []:
        if isinstance(action, dict):
            action["environment"] = env_name
    for trigger in wf.get("triggers") or []:
        if isinstance(trigger, dict):
            trigger["environment"] = env_name
    return wf


def install(key: str, workflow: dict, existing: dict[str, str], org_id: str, env_name: str) -> bool:
    name = workflow.get("name")
    if not name:
        print("  ERROR: workflow file has no 'name'", file=sys.stderr)
        return False

    wf = retarget(workflow, org_id, env_name)
    wf_id = existing.get(name)
    if wf_id:
        wf["id"] = wf_id
        code, body = shuffle_curl(key, "PUT", f"{ROUTES['workflows']}/{wf_id}", json.dumps(wf))
        verb = "updated"
    else:
        code, body = shuffle_curl(key, "POST", ROUTES["workflows"], json.dumps(wf))
        verb = "created"

    if code not in (200, 201):
        print(f"  ERROR {name!r}: HTTP {code}: {body[:400]}", file=sys.stderr)
        return False
    print(f"  {verb} {name!r} (org={org_id} env={env_name})")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="list workflows and exit without calling Shuffle")
    mode.add_argument(
        "--probe",
        action="store_true",
        help="exercise auth and every read route without writing; run this first after a Shuffle upgrade",
    )
    args = ap.parse_args()

    if args.probe:
        key = load_api_key()
        org_id, env_name = resolve_context(key)
        found = existing_by_name(key)
        print(f"auth ok; org={org_id} environment={env_name}")
        print(f"{len(found)} existing workflow(s): {', '.join(sorted(found)) or '(none)'}")
        return 0

    if not WORKFLOW_DIR.is_dir():
        sys.exit(f"workflow dir not found: {WORKFLOW_DIR}")
    files = sorted(WORKFLOW_DIR.glob("*.json"))
    if not files:
        sys.exit(f"no workflow files in {WORKFLOW_DIR} — see its README.md")

    if args.dry_run:
        print(f"DRY-RUN {len(files)} workflow(s) from {WORKFLOW_DIR}")
        for path in files:
            wf = json.loads(path.read_text())
            print(f"  would install {wf.get('name', path.stem)!r} from {path.name}")
        return 0

    key = load_api_key()
    org_id, env_name = resolve_context(key)
    existing = existing_by_name(key)

    print(f"installing {len(files)} workflow(s) from {WORKFLOW_DIR}")
    all_ok = True
    for path in files:
        if not install(key, json.loads(path.read_text()), existing, org_id, env_name):
            all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
