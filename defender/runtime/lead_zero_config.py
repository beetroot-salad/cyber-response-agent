"""The turn-zero correlation lead's per-deployment config: ONE key, the template it binds.

`knowledge/environment/lead-zero.yaml` carries `correlation_template: <id>` and nothing else.
The id is the unit of configuration (#1003): a query template's front matter already declares
the system and the verb it binds, so naming the template names the backend — and the
verb-disposition table's authority over the lead shrinks to grant-or-withhold, checked for
AGREEMENT with the template at run start (`lead_zero._agreement`). Before #1003 the id was a
literal in `lead_zero/_spec.py` naming one vendor, so a table that moved the holder loaded
clean and the lead burned its whole budget on a template its index could not list.

READ AT RUN START, FROM THE RUN'S OWN TREE — not at import, not from the checkout. The id has
exactly one consumer, the run-start check, and that check resolves it against the catalog of
the tree the run was pointed at (`run_investigation`'s `defender_dir`); a config read from
anywhere else would pair one tree's id with another tree's catalog. That is also why this
module is NOT inside the `lead_zero` package and `_spec` does not read it: `_spec` is the
vocabulary leaf a dozen test modules import for two strings, and it stays free of tree reads.

WHAT THE LOADER DOES NOT DO: validate the id against the catalog or its grammar. That is the
run-start check's job, where the catalog is visible.

Every refusal is `LeadZeroConfigError` naming the path, for the reason `DispositionError`
names the table: the failure is read at startup by someone who just edited the file.
"""
from __future__ import annotations

from pathlib import Path

from defender import _yaml

#: The file's home BELOW a defender tree, and the one place its name is spelled —
#: `LEAD_ZERO_CONFIG_REL` and `lead_zero_config_path` both derive from it.
_REL_TO_DEFENDER = Path("knowledge") / "environment" / "lead-zero.yaml"

#: Repo-relative home of the config. In the environment tree beside `verb-grants.yaml`: it is
#: per-deployment data, and the one file in the runtime's reach that legitimately names a
#: vendor's template.
LEAD_ZERO_CONFIG_REL = f"defender/{_REL_TO_DEFENDER.as_posix()}"

#: The ONE key the file may carry. Anything else is refused the way `verb-grants.yaml`'s
#: unread keys are: a key the loader ignores is a statement a reviewer reads and the runtime
#: does not honour.
CORRELATION_TEMPLATE_KEY = "correlation_template"


class LeadZeroConfigError(Exception):
    """Raised for any config this module will not stand behind — absent, unparseable, an
    unread key, no usable id. One exception because every one of them has the same correct
    handling at startup: stop, naming the file."""


def lead_zero_config_path(defender_dir: Path) -> Path:
    """The config's path inside an ARBITRARY defender tree — the tree, not a module-level
    constant, for the reason `verb_dispositions.dispositions_path` takes one."""
    return Path(defender_dir) / _REL_TO_DEFENDER


def load_correlation_template(path: Path) -> str:
    """Read `path` and return its `correlation_template` id, or raise `LeadZeroConfigError`.

    @owns correlation_template — the one reader of the key.

    Returns the STRING as authored. Whether it names an established template whose pair the
    table grants is decided at run start, against the deployment's own catalog
    (`lead_zero.resolve_correlation_dispatch`), not here. The file-trust preamble (absent,
    undecodable, a repeated key, unparseable, an unread key) is the table loader's, shared.
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
