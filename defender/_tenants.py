"""The tenant knowledge folder's contract: `<data root>/<T>/knowledge/{settings,agent}/`.

A tenant's knowledge lives under the data root, beside its row and runs, never in the checkout:
`defender/` is mounted into every run's box, and the box must hold no tenant's settings. The
operator places it — a `git clone` of the tenant's own repo on the host, or a plain folder —
and `tenant.py setup <id>` adopts it. Two halves:

  * `settings/` — host-only (`config.env`s, `verb-grants.yaml`, `lead-zero.yaml`,
    `systems/case-history/mapping.yaml`). Never a mount source.
  * `agent/` — model-facing, mounted read-only into the run's box.

This module only names the folder's shape. The rules that judge a folder against it, and the
one acceptance of a tenant, are `_tenant.check_knowledge_folder` and `_tenant.accept_tenant`.
The repo keeps `knowledge/tenant-template/` (what `tenant.py scaffold` copies) and the frozen
test fixture beside it; neither is ever a run's tenant.
"""
from __future__ import annotations

import argparse
from pathlib import Path

#: Files required at start, relative to `settings/`. A system's `config.env` is not here: some
#: adapters need none, and its absence is the per-call `ConfigFault` (exit 2, trips the breaker).
REQUIRED_SETTINGS: tuple[str, ...] = (
    "verb-grants.yaml",
    "lead-zero.yaml",
    "systems/case-history/mapping.yaml",
)

SETTINGS_HALF = "settings"
AGENT_HALF = "agent"

#: Every name a knowledge folder may hold at its top level: the two halves, the tenant repo's
#: own git and CI files, a README, and `archive/` (outside both halves, never mounted). Anything
#: else — an operator's `.env` or `secrets/` — is refused, so it never sits unwalked in the data
#: root. `.tenant-id` lives inside `agent/`.
TOP_LEVEL_ALLOWED: frozenset[str] = frozenset({
    SETTINGS_HALF, AGENT_HALF, ".github", ".git", "archive", "README.md", ".gitignore",
    ".gitattributes",
})

#: The folder's own claim of which tenant it is, relative to the knowledge folder: the id plus at
#: most one line ending. The template and the fixture commit none; `scaffold` writes it.
TENANT_ID_FILE = Path(AGENT_HALF) / ".tenant-id"

#: The template's folder name under the checkout's `knowledge/`.
TEMPLATE_DIRNAME = "tenant-template"


def template_dir(repo_root: Path) -> Path:
    """The committed template tenant: `<repo_root>/knowledge/tenant-template`."""
    return Path(repo_root) / "knowledge" / TEMPLATE_DIRNAME


def add_tenant_arguments(parser: argparse.ArgumentParser, *, reads: str) -> None:
    """`--tenant` for an operator command that reads a tenant's settings. `reads` says what the
    command takes from the tenant's `settings/`, for `--help`. The tenant is found under
    `$DEFENDER_DATA_ROOT`; there is no other root to name."""
    parser.add_argument(
        "--tenant", default=None,
        help=f"the tenant whose settings/ {reads}, under $DEFENDER_DATA_ROOT; required "
             "wherever the command reads a tenant — there is no default tenant")


__all__ = [
    "AGENT_HALF",
    "REQUIRED_SETTINGS",
    "SETTINGS_HALF",
    "TEMPLATE_DIRNAME",
    "TENANT_ID_FILE",
    "TOP_LEVEL_ALLOWED",
    "add_tenant_arguments",
    "template_dir",
]
