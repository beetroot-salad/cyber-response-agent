"""The tenant knowledge folder's contract: `<data root>/<T>/knowledge/{settings,agent}/`."""
from __future__ import annotations

import argparse
from pathlib import Path

#: Files required at start, relative to `settings/`. A system's `config.env` is not here: some
#: adapters need none, and its absence is that system's own settings check failing at run start
#: (#1256: the system is down for the run and the agent is told why; the run goes on unless no
#: granted system is left usable, which the run's start check refuses — never the tenant check).
REQUIRED_SETTINGS: tuple[str, ...] = (
    "verb-grants.yaml",
    "lead-zero.yaml",
    "systems/case-history/mapping.yaml",
)

SETTINGS_HALF = "settings"
AGENT_HALF = "agent"

#: Every name a knowledge folder may hold at its top level: the two halves, the tenant repo's
#: own git and CI files, a README, and `archive/` (outside both halves, never mounted). Any
#: other top-level name — an operator's `.env` or `secrets/` — is refused. Only the two halves
#: are walked for links and special files; what sits under `.git`, `.github` and `archive/` is
#: the tenant repo's and is never read or mounted. `.tenant-id` lives inside `agent/`.
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
