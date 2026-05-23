#!/usr/bin/env python3
"""Install detection rules from playground-v2/detection-rules/*.json into Kibana.

Iterates every *.json in playground-v2/detection-rules/, deletes any existing
rule with the same rule_id, then POSTs the rule. Idempotent and order-independent.

Transport: shells out to `docker --context soc-playground exec kibana curl`
against localhost:5601 inside the kibana container, so the script does not
require an SSH tunnel from the devcontainer.

Auth: basic-auth as `elastic`. Password from $V2_ELASTIC_PASSWORD or
playground-v2/.env (V2_ELASTIC_PASSWORD line).

Usage:
  python3 playground-v2/scripts/install_detection_rules.py [--dry-run]

Exit codes:
  0 — all rules installed
  1 — Kibana API error on at least one rule (others may still have installed)
  2 — config/auth/connectivity failure
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

PLAYGROUND = Path(__file__).resolve().parent.parent
RULES_DIR = PLAYGROUND / "detection-rules"
ENV_FILE = PLAYGROUND / ".env"
DOCKER_CONTEXT = "soc-playground"
KIBANA_CONTAINER = "kibana"
KIBANA_URL = "http://localhost:5601"


def load_password() -> str:
    if pw := os.environ.get("V2_ELASTIC_PASSWORD"):
        return pw
    if ENV_FILE.is_file():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("V2_ELASTIC_PASSWORD="):
                return line.split("=", 1)[1].strip()
    sys.exit(
        "V2_ELASTIC_PASSWORD not set and not found in playground-v2/.env"
    )


def docker_curl(password: str, method: str, path: str, body: str | None = None) -> tuple[int, str]:
    """Run curl inside the kibana container, return (http_code, body)."""
    args = [
        "docker", "--context", DOCKER_CONTEXT,
        "exec", "-e", f"EP={password}",
    ]
    if body is not None:
        args += ["-e", f"BODY={body}"]
    args += [
        KIBANA_CONTAINER, "sh", "-c",
        _curl_command(method, path, body is not None),
    ]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(
            f"docker exec failed (rc={proc.returncode}): {proc.stderr.strip()}"
        )
    out = proc.stdout
    # last line is the HTTP code we appended via -w; preceding content is the body
    lines = out.rsplit("\n", 2)
    if len(lines) < 2:
        return 0, out
    try:
        code = int(lines[-2] if lines[-1] == "" else lines[-1])
    except ValueError:
        return 0, out
    body_out = "\n".join(lines[:-2 if lines[-1] == "" else -1])
    return code, body_out


def _curl_command(method: str, path: str, has_body: bool) -> str:
    parts = [
        "curl -ks",
        '-u "elastic:$EP"',
        '-H "kbn-xsrf: true"',
        '-H "Content-Type: application/json"',
        f"-X {method}",
        f'"{KIBANA_URL}{path}"',
    ]
    if has_body:
        parts.append('--data "$BODY"')
    # write http code on its own trailing line so we can split out
    parts.append(r'-w "\n%{http_code}\n"')
    return " ".join(parts)


def install_rule(password: str, rule: dict, dry_run: bool) -> bool:
    rule_id = rule["rule_id"]
    name = rule["name"]
    if dry_run:
        print(f"  DRY-RUN would install rule_id={rule_id} ({name!r})")
        return True

    # 1) delete any existing rule with this rule_id (idempotency); 404 is fine
    code, body = docker_curl(
        password, "DELETE",
        f"/api/detection_engine/rules?rule_id={rule_id}",
    )
    if code not in (200, 404):
        print(
            f"  ERROR rule_id={rule_id}: DELETE returned HTTP {code}: {body}",
            file=sys.stderr,
        )
        return False

    # 2) POST the rule body
    code, body = docker_curl(
        password, "POST",
        "/api/detection_engine/rules",
        body=json.dumps(rule),
    )
    if code not in (200, 201):
        print(
            f"  ERROR rule_id={rule_id}: POST returned HTTP {code}: {body}",
            file=sys.stderr,
        )
        return False

    print(f"  installed rule_id={rule_id} ({name!r})")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="list rules and exit without calling Kibana")
    args = ap.parse_args()

    if not RULES_DIR.is_dir():
        sys.exit(f"rules dir not found: {RULES_DIR}")
    rule_files = sorted(RULES_DIR.glob("*.json"))
    if not rule_files:
        sys.exit(f"no rule files in {RULES_DIR}")

    password = load_password()
    print(f"installing {len(rule_files)} rule(s) from {RULES_DIR}")
    all_ok = True
    for path in rule_files:
        rule = json.loads(path.read_text())
        if not install_rule(password, rule, args.dry_run):
            all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
