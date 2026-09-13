"""The turn-zero correlation lead's per-deployment config: ONE key, the template it binds.

`knowledge/environment/lead-zero.yaml` carries `correlation_template: <id>` and nothing else.
The id is the unit of configuration (#1003): a query template's front matter already declares
the system and the verb it binds, so naming the template names the backend — and the
verb-disposition table's authority over the lead shrinks to grant-or-withhold, checked for
AGREEMENT with the template at run start (`lead_zero._agreement`). Before #1003 the id was a
literal in `lead_zero/_spec.py` naming one vendor, so a table that moved the holder loaded
clean and the lead burned its whole budget on a template its index could not list.

This module is deliberately NOT inside the `lead_zero` package: `_spec` reads the value at
import and "imports none of its siblings", so the reader lives one level up, beside
`verb_dispositions` — the other per-deployment file `_spec` already reads the same way.

WHAT THE LOADER DOES NOT DO: validate the id against the catalog or its grammar. That is the
run-start check's job, where the catalog is visible. A loader that walked the catalog would
put a tree read into `_spec`'s import — the vocabulary leaf a dozen test modules import for
two strings — and a malformed template elsewhere in the corpus (warn-and-skip on the walk)
would become an import failure for all of them.

Every refusal is `LeadZeroConfigError` naming the path, for the reason `DispositionError`
names the table: the failure is read at startup by someone who just edited the file.
"""
from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path

import yaml

from defender import _yaml
from defender._io import TEXT_READ_ERRORS

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

    @owns correlation_template — the one reader of the key; `shipped_correlation_template`
    and every consumer of `lead_zero.CORRELATION_TEMPLATE` take this function's value rather
    than parsing the file again.

    Returns the STRING as authored. Whether it names an established template whose pair the
    table grants is decided at run start, against the deployment's own catalog
    (`lead_zero.resolve_correlation_dispatch`), not here.
    """
    path = Path(path)
    where = f"lead-zero config at {path}"
    if not path.is_file():
        raise LeadZeroConfigError(f"lead-zero config not found at {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except TEXT_READ_ERRORS as e:
        # Undecodable bytes are as much "no usable id" as an absent file — a raw
        # `UnicodeDecodeError` out of an import-time read is not a refusal naming the file.
        raise LeadZeroConfigError(f"{where} is unreadable ({e})") from e

    duplicates = _yaml.duplicate_key_paths(text)
    if duplicates:
        raise LeadZeroConfigError(
            f"{where} repeats key(s) {list(duplicates)} — YAML would silently honour the "
            "last of each"
        )
    try:
        data = _yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise LeadZeroConfigError(f"{where} does not parse ({e})") from e

    if not isinstance(data, Mapping):
        raise LeadZeroConfigError(
            f"{where} must be a mapping with a `{CORRELATION_TEMPLATE_KEY}:` key"
        )
    unknown = sorted(str(k) for k in data if k != CORRELATION_TEMPLATE_KEY)
    if unknown:
        raise LeadZeroConfigError(
            f"{where} carries key(s) {unknown} that nothing reads — the only key read here "
            f"is `{CORRELATION_TEMPLATE_KEY}`"
        )
    template_id = data.get(CORRELATION_TEMPLATE_KEY)
    if not isinstance(template_id, str) or not template_id.strip():
        raise LeadZeroConfigError(
            f"{where} declares no usable `{CORRELATION_TEMPLATE_KEY}:` — it must be the id "
            "of the query template the correlation lead binds (got "
            f"{template_id!r})"
        )
    return template_id.strip()


@lru_cache(maxsize=1)
def shipped_correlation_template() -> str:
    """The id configured in the tree THIS process runs from, read once — the twin of
    `verb_dispositions.shipped_dispositions`, and read at import by `lead_zero._spec` for the
    same reason: a missing or malformed config stops startup rather than yielding a lead told
    to bind nothing.

    `PATHS` is imported lazily to keep the import edge one-way, as `shipped_dispositions`
    does."""
    from defender._paths import PATHS

    return load_correlation_template(lead_zero_config_path(PATHS.defender_dir))
