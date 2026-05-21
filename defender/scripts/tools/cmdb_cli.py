#!/usr/bin/env python3
"""CMDB stub CLI — thin wrapper for CMDB host lookups.

Usage:
    python3 cmdb_cli.py lookup --ip 172.22.0.10
    python3 cmdb_cli.py lookup --hostname monitoring-host
    python3 cmdb_cli.py lookup --ip 172.22.0.10 --run-dir /tmp/run-123 --position 0
    python3 cmdb_cli.py list-all
"""

import argparse
import json
import sys
from pathlib import Path

CMDB_FILE = Path("/workspace/playground/cmdb/hosts.json")
README_FILE = Path("/workspace/playground/cmdb/README.md")


def load_cmdb():
    """Load the CMDB hosts file."""
    if not CMDB_FILE.exists():
        print(f"error: CMDB file not found: {CMDB_FILE}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(CMDB_FILE) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"error: Failed to parse CMDB JSON: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"error: Failed to read CMDB: {e}", file=sys.stderr)
        sys.exit(2)


def lookup(ip=None, hostname=None):
    """Look up a host by IP or hostname."""
    if not ip and not hostname:
        print("error: Provide either --ip or --hostname", file=sys.stderr)
        sys.exit(1)

    if ip and hostname:
        print("error: Provide exactly one of --ip or --hostname, not both", file=sys.stderr)
        sys.exit(1)

    cmdb = load_cmdb()

    for host in cmdb.get("hosts", []):
        if ip and host.get("ip") == ip:
            print(json.dumps(host))
            return 0
        if hostname and host.get("hostname") == hostname:
            print(json.dumps(host))
            return 0

    # Not found — print empty result
    print(json.dumps({}))
    return 0


def list_all():
    """List all documented hosts."""
    cmdb = load_cmdb()
    for host in cmdb.get("hosts", []):
        print(json.dumps({
            "ip": host.get("ip"),
            "hostname": host.get("hostname"),
            "role": host.get("role"),
            "status": host.get("status"),
            "team": host.get("team"),
        }))
    return 0


def main():
    parser = argparse.ArgumentParser(description="CMDB host lookup")
    subparsers = parser.add_subparsers(dest="command")

    lookup_parser = subparsers.add_parser("lookup", help="Look up a host by IP or hostname")
    lookup_parser.add_argument("--ip", help="IPv4 or IPv6 address")
    lookup_parser.add_argument("--hostname", help="Hostname or FQDN")
    lookup_parser.add_argument("--run-dir", help="Investigation run directory (when set, output is persisted to gather_raw/)")
    lookup_parser.add_argument("--position", help="Sequence position of this dispatch (e.g. '0', '0a', '0b')")

    subparsers.add_parser("list-all", help="List all documented hosts")

    args = parser.parse_args()

    if args.command == "lookup":
        result_exit = lookup(ip=args.ip, hostname=args.hostname)

        # If --run-dir and --position are set, persist the output
        if args.run_dir and args.position:
            run_dir = Path(args.run_dir)
            gather_raw = run_dir / "gather_raw"
            gather_raw.mkdir(parents=True, exist_ok=True)

            # Reload and output to file
            cmdb = load_cmdb()
            for host in cmdb.get("hosts", []):
                if args.ip and host.get("ip") == args.ip:
                    output_path = gather_raw / f"{args.position}.json"
                    output_path.write_text(json.dumps(host))
                    break
                if args.hostname and host.get("hostname") == args.hostname:
                    output_path = gather_raw / f"{args.position}.json"
                    output_path.write_text(json.dumps(host))
                    break
            else:
                # Not found
                output_path = gather_raw / f"{args.position}.json"
                output_path.write_text(json.dumps({}))

        return result_exit
    elif args.command == "list-all":
        return list_all()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
