#!/usr/bin/env python3
"""Seed UNIX accounts on a playground host from hosts/inventory.yaml.

Runs at container start (not image build) so inventory.yaml changes take
effect with `compose up -d` alone — no rebuild loop. Idempotent: re-running
on an already-seeded host is a no-op per user (useradd is skipped if the
account exists, password is re-set to keep drift out).

Keeping identity labels IDENTICAL across Keycloak (IdP events) and
/etc/passwd (auth.log, auditd) is the property that makes cross-source
correlation work — see docs/playground-environment-v2.md §Identities.
"""
import os
import pwd
import subprocess
import sys
from pathlib import Path

import yaml

DEFAULT_PASSWORD = "changeme"  # Playground-only — matches keycloak/realm.yaml seed passwords.

INVENTORY = Path("/opt/soc-playground/inventory.yaml")


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def user_exists(username: str) -> bool:
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def ensure_user(username: str, shell: str, sudo: bool) -> None:
    """Create the account if missing; update shell + sudo membership if present.

    Password is (re)set to DEFAULT_PASSWORD on every run — drift from the
    playground baseline is a footgun, not a feature. Real rotation happens
    out-of-band.
    """
    if user_exists(username):
        # Align shell + sudo with current inventory — inventory is truth.
        run(["usermod", "-s", shell, username])
    else:
        # -m creates $HOME; -U makes a matching group.
        run(["useradd", "-m", "-s", shell, "-U", username])

    # (Re)set password.
    subprocess.run(["chpasswd"], input=f"{username}:{DEFAULT_PASSWORD}\n",
                   text=True, check=True)

    # Sudo membership — add-if-missing, remove-if-no-longer-authorized.
    groups_line = run(["id", "-nG", username]).stdout.strip().split()
    if sudo and "sudo" not in groups_line:
        run(["usermod", "-aG", "sudo", username])
    elif not sudo and "sudo" in groups_line:
        run(["gpasswd", "-d", username, "sudo"])


def resolve_users(inv: dict, host_name: str) -> list[dict]:
    """Merge role-wide role→user mapping with per-host overrides.

    Returns a list of dicts: {username, shell, sudo}. Per-host entries win
    on conflicts (so a service account can keep /usr/sbin/nologin even if
    an sre-ops rule would grant a shell).
    """
    hosts = {h["name"]: h for h in inv["hosts"]}
    if host_name not in hosts:
        sys.exit(f"FATAL: host {host_name!r} not in inventory.yaml")
    host = hosts[host_name]

    # Load the realm user list — usernames + which realm role each belongs to.
    # Cross-file invariant with keycloak/realm.yaml; see inventory.yaml header.
    realm_path = Path("/opt/soc-playground/realm.yaml")
    realm_users: dict[str, str] = {}
    if realm_path.exists():
        realm = yaml.safe_load(realm_path.read_text())
        for u in realm.get("users", []):
            roles = u.get("realmRoles", [])
            if roles:
                realm_users[u["username"]] = roles[0]

    resolved: dict[str, dict] = {}

    # 1. Apply role-wide rules from inventory.roles[*].hosts.
    for role_name, role_cfg in inv.get("roles", {}).items():
        if host_name not in role_cfg.get("hosts", []):
            continue
        shell = role_cfg.get("shell", "/bin/bash")
        sudo = role_cfg.get("sudo", False)
        sudo_hosts = role_cfg.get("sudo_hosts")
        if sudo_hosts is not None:
            sudo = host_name in sudo_hosts
        # Find every realm user carrying this role.
        matching = [u for u, r in realm_users.items() if r == role_name]
        for username in matching:
            resolved[username] = {"username": username, "shell": shell, "sudo": sudo}

    # 2. Apply per-host overrides (later wins).
    for entry in host.get("users", []) or []:
        resolved[entry["username"]] = {
            "username": entry["username"],
            "shell": entry.get("shell", "/bin/bash"),
            "sudo": entry.get("sudo", False),
        }

    return list(resolved.values())


def main() -> None:
    host_name = os.environ.get("HOST_NAME", "").strip()
    if not host_name:
        sys.exit("FATAL: HOST_NAME env var is required")

    inv = yaml.safe_load(INVENTORY.read_text())

    # /etc/hostname + transient hostname — auditd / syslog stamp with this.
    Path("/etc/hostname").write_text(host_name + "\n")
    subprocess.run(["hostname", host_name], check=False)  # may fail in unprivileged containers; not fatal

    users = resolve_users(inv, host_name)
    for u in users:
        ensure_user(u["username"], u["shell"], u["sudo"])

    print(f"[seed-users] host={host_name} seeded {len(users)} account(s): "
          f"{', '.join(sorted(u['username'] for u in users))}")


if __name__ == "__main__":
    main()
