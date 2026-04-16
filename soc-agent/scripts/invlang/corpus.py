"""Investigation-language companion loader.

Parses v2.5 companion YAML files into Companion objects for use by the
query classes. A companion is a single investigation expressed as the
four-phase structure: prologue → hypothesize → gather → conclude.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import yaml


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# workspace root: invlang/ → scripts/ → soc-agent/ → workspace
_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# Default corpus root — override via INVLANG_CORPUS_ROOT env var
_DEFAULT_CORPUS_ROOT = _WORKSPACE_ROOT / "docs/experiments/investigation-language-pilot"


def _corpus_root() -> Path:
    env = os.environ.get("INVLANG_CORPUS_ROOT")
    return Path(env) if env else _DEFAULT_CORPUS_ROOT


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMPANION_TOP_LEVEL = {"prologue", "hypothesize", "gather", "conclude"}
# v2.6: hypothesize is optional when screen_result: match short-circuits the loop.
_COMPANION_REQUIRED_KEYS = {"prologue", "gather", "conclude"}

YAML_BLOCK_RE = re.compile(r"```yaml\n(.*?)\n```", re.DOTALL)

# Pilot corpus allowlist — deliberate: only finalized v2.5/v2.6 translations.
# Update when a new case lands. Paths are relative to the corpus root.
PILOT_CORPUS_FILES: tuple[str, ...] = (
    "case-a1/walk-a1-v2.5.yaml",
    "case-a4/walk-a4-v2.5.yaml",
    "case-m365/walk-m365-v2.5.yaml",
    "case-real-rule5710/companion-v2.5.yaml",
    "case-ssh-brute/companion-v2.5.yaml",
    "case-ssh-cron/companion-v2.5.yaml",
)


# ---------------------------------------------------------------------------
# Companion dataclass
# ---------------------------------------------------------------------------

@dataclass
class Companion:
    """A loaded v2.5 companion with its source path and parsed body."""

    case_id: str
    source_path: Path
    body: dict[str, Any]

    @property
    def prologue(self) -> dict[str, Any]:
        return self.body.get("prologue", {})

    @property
    def hypotheses(self) -> list[dict[str, Any]]:
        return self.body.get("hypothesize", {}).get("hypotheses", [])

    @property
    def leads(self) -> list[dict[str, Any]]:
        return [entry["lead"] for entry in self.body.get("gather", []) if "lead" in entry]

    @property
    def conclude(self) -> dict[str, Any]:
        return self.body.get("conclude", {})

    def iter_new_hypotheses(self) -> Iterator[dict[str, Any]]:
        """Yields hypotheses from HYPOTHESIZE + any new_hypotheses spawned in leads."""
        yield from self.hypotheses
        for lead in self.leads:
            for h in lead.get("new_hypotheses", []) or []:
                yield h


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def conclude_field(conclude: dict[str, Any], *path: str) -> Any:
    """Defensive nested access — returns None if any hop isn't a dict."""
    cur: Any = conclude
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _looks_like_companion(doc: Any) -> bool:
    # hypothesize is optional in v2.6 when screen_result: match short-circuits the loop
    return isinstance(doc, dict) and _COMPANION_REQUIRED_KEYS.issubset(doc.keys())


def _case_id_from_path(path: Path) -> str:
    return path.parent.name if path.parent.name not in {"", "."} else path.stem


def _load_from_path(path: Path) -> list[Companion]:
    """Parse a file and return every companion it contains (0 or more)."""
    results: list[Companion] = []
    if path.suffix == ".yaml":
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            return results
        if _looks_like_companion(doc):
            results.append(Companion(_case_id_from_path(path), path, doc))
    elif path.suffix == ".md":
        text = path.read_text()
        for match in YAML_BLOCK_RE.finditer(text):
            try:
                doc = yaml.safe_load(match.group(1))
            except yaml.YAMLError:
                continue
            if _looks_like_companion(doc):
                results.append(Companion(_case_id_from_path(path), path, doc))
    return results


# ---------------------------------------------------------------------------
# Public loader
# ---------------------------------------------------------------------------

def load_corpus(
    root: Path | None = None,
    paths: tuple[str, ...] = PILOT_CORPUS_FILES,
) -> list[Companion]:
    """Load companions from the allowlisted file set.

    root  — corpus root directory. Defaults to INVLANG_CORPUS_ROOT env var,
            then to docs/experiments/investigation-language-pilot/.
    paths — relative file paths from root. Defaults to PILOT_CORPUS_FILES.
    """
    effective_root = root if root is not None else _corpus_root()
    companions: list[Companion] = []
    for rel in paths:
        abs_path = effective_root / rel
        if not abs_path.exists():
            print(f"warning: {rel} not found under {effective_root}, skipping", file=sys.stderr)
            continue
        companions.extend(_load_from_path(abs_path))
    return companions
