#!/usr/bin/env python3
"""Convert realm.yaml → Keycloak realm-import JSON.

Usage: seed.py <input.yaml> <output.json>

Run by the `keycloak-init` one-shot before Keycloak starts. Keycloak's
`--import-realm` flag then imports any JSON in /opt/keycloak/data/import/.
Import is idempotent: Keycloak skips if the realm already exists.
"""
import json
import sys
from pathlib import Path

import yaml

if len(sys.argv) != 3:
    sys.exit("usage: seed.py <input.yaml> <output.json>")

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

data = yaml.safe_load(src.read_text())

dst.parent.mkdir(parents=True, exist_ok=True)
dst.write_text(json.dumps(data, indent=2))
print(f"wrote {dst} ({len(data.get('users', []))} users, "
      f"{len(data.get('roles', {}).get('realm', []))} roles, "
      f"{len(data.get('clients', []))} clients)")
