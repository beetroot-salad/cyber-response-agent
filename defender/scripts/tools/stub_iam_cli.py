#!/usr/bin/env python3
"""Stub IAM registry CLI — thin wrapper for account lookup.

The IAM registry is a static JSON file mapping account names to
authorization metadata: owning team, active status, allowed source/target
hosts, purpose, and narrative context.

Usage:
    python3 stub_iam_cli.py lookup --name nagios
    python3 stub_iam_cli.py lookup --name app-svc --run-dir /tmp/run-123 --position 0

Exit codes:
    0 — success
    1 — query error or account not found
    2 — invalid arguments
"""

import argparse
import json
import sys
from pathlib import Path

# Static path to the playground IAM registry.
# In a production environment this would be an API endpoint.
IAM_REGISTRY_PATH = Path("/workspace/playground/iam/accounts.json")


def load_registry():
    """Load the IAM registry from disk.

    Returns the parsed JSON object (expected to have an 'accounts' key
    with a list of account objects).
    """
    if not IAM_REGISTRY_PATH.exists():
        print(
            f"error: IAM registry not found: {IAM_REGISTRY_PATH}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        with open(IAM_REGISTRY_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: failed to load IAM registry: {e}", file=sys.stderr)
        sys.exit(1)


def lookup_account(name):
    """Look up a single account by name.

    Returns the account object (dict) if found, or None if not in registry.
    """
    registry = load_registry()
    accounts = registry.get("accounts", [])

    for account in accounts:
        if account.get("name") == name:
            return account

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Look up accounts in the IAM registry"
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="lookup",
        help="Subcommand (lookup)"
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Account name to look up"
    )
    parser.add_argument(
        "--run-dir",
        help="Run directory for writing output (optional)"
    )
    parser.add_argument(
        "--position",
        help="Position index for output file naming (optional)"
    )

    args = parser.parse_args()

    if args.command != "lookup":
        print(f"error: unknown command: {args.command}", file=sys.stderr)
        sys.exit(2)

    if not args.name:
        print("error: --name is required", file=sys.stderr)
        sys.exit(2)

    account = lookup_account(args.name)

    # Prepare output
    if account is None:
        # Account not in registry (null result is still a valid outcome)
        result = {"status": "not_found", "account": None}
        status_code = 0
    else:
        result = {"status": "ok", "account": account}
        status_code = 0

    output_json = json.dumps(result, indent=2)

    # Write to file if run-dir and position are provided
    if args.run_dir and args.position:
        output_path = Path(args.run_dir) / "gather_raw" / f"{args.position}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(output_json)
        print(f"Wrote output to {output_path}")
    else:
        # Write to stdout if not writing to file
        print(output_json)

    sys.exit(status_code)


if __name__ == "__main__":
    main()
