"""The turn-zero correlation lead's per-tenant config: one key, the template it binds.

A tenant's `settings/lead-zero.yaml` carries only `correlation_template: <id>`. The template's
front matter declares its system and verb, so the verb-disposition table only grants or
withholds, checked for agreement with the template at run start (`lead_zero._agreement`).

Read at run start from the run's tenant, not at import. It lives outside the `lead_zero`
package so `lead_zero._spec` stays a vocabulary leaf free of tree reads. The id is not
validated here; the run-start check does that against the catalog.

Every refusal is a `LeadZeroConfigError` naming the path, for the operator who just edited it.
"""
from __future__ import annotations

from pathlib import Path

from defender import _yaml

#: The file's name inside a tenant's `settings/` folder.
LEAD_ZERO_CONFIG_FILENAME = "lead-zero.yaml"

#: The only key the file may carry. Others are refused: an ignored key reads as configuration
#: the runtime does not honour.
CORRELATION_TEMPLATE_KEY = "correlation_template"


class LeadZeroConfigError(Exception):
    """Any unusable config (absent, unparseable, an unknown key, no usable id). One type
    because the handling is always the same: stop at startup, naming the file."""


def lead_zero_config_path(settings_dir: Path) -> Path:
    """The config's path inside the run's tenant `settings/` folder."""
    return Path(settings_dir) / LEAD_ZERO_CONFIG_FILENAME


def load_correlation_template(path: Path) -> str:
    """Read `path` and return its `correlation_template` id, or raise `LeadZeroConfigError`.

    @owns correlation_template — the one reader of the key.

    Returns the string as authored (stripped); `lead_zero.resolve_correlation_dispatch`
    checks it against the catalog and table. File-level checks are shared with the table
    loader (`_yaml.load_reviewed_mapping`).
    """
    path = Path(path)
    data = _yaml.load_reviewed_mapping(
        path, what="lead-zero config", known=(CORRELATION_TEMPLATE_KEY,),
        error=LeadZeroConfigError,
    )
    template_id = data.get(CORRELATION_TEMPLATE_KEY)
    if not isinstance(template_id, str) or not template_id.strip():
        raise LeadZeroConfigError(
            f"lead-zero config at {path} declares no usable `{CORRELATION_TEMPLATE_KEY}:` — "
            "it must be the id of the query template the correlation lead binds (got "
            f"{template_id!r})"
        )
    return template_id.strip()
