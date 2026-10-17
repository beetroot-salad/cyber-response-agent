"""check_config: validator behaviour for connected systems' config.env."""
from __future__ import annotations

from pathlib import Path

from defender.skills.connect import validate_scaffold

#: The scaffolded system and its key prefix. A name no committed tenant uses, so a row naming it
#: can only have come from the planted folder.
SYSTEM = "mysys"
PREFIX = "MYSYS"
DOCKER_EXEC = "docker-exec"



# ---- fixture planting (returns, never asserts) ----------------------------------------------------

def _scaffold(root: Path, *, extra: str = "", transport: str | None = DOCKER_EXEC,
              context: str | None = "ctx-mysys") -> Path:
    """A tenant `settings/` folder holding one scaffolded system's `config.env` (URL base plus the
    MF-8 access-method lines unless dropped, plus `extra` verbatim). Returns the settings folder."""
    settings = Path(root) / "settings"
    cfg = settings / "systems" / SYSTEM / "config.env"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    lines = [f'{PREFIX}_URL_BASE="http://mysys:8080"']
    if transport is not None:
        lines.append(f'{PREFIX}_TRANSPORT="{transport}"')
    if context is not None:
        lines.append(f'{PREFIX}_DOCKER_CONTEXT="{context}"')
    cfg.write_text("\n".join(lines) + "\n" + extra, encoding="utf-8")
    return settings


def _check(settings: Path) -> list[tuple[str, str]]:
    """The REAL validator over `settings`, returning its report rows."""
    report = validate_scaffold.Report()
    validate_scaffold.check_config(report, settings, SYSTEM)
    return list(report.rows)




def _passes(rows: list[tuple[str, str]]) -> list[str]:
    return [m for s, m in rows if s == validate_scaffold.PASS]


def _naming(messages: list[str], needle: str) -> list[str]:
    return [m for m in messages if needle in m]






# ---- O8: the retired _ENV convention -----------------------------------------------------------------



# ---- the access method is not the product's to check -----------------------------------------------

def test_validator_does_not_judge_an_access_method(tmp_path):
    """The docker access method is the lab transport's own requirement, not a product rule: a
    connected system's config.env draws no access-method row, whether it declares neither key,
    half a pair, or a method other than docker-exec. The rest of the file is still judged."""
    cases = {"neither": dict(transport=None, context=None),
             "half": dict(transport=DOCKER_EXEC, context=None),
             "other-method": dict(transport="http")}
    for label, kw in cases.items():
        rows = _check(_scaffold(tmp_path / label, **kw))
        messages = [m for _, m in rows]
        assert not _naming(messages, f"{PREFIX}_TRANSPORT"), f"{label}: an access-method row: {rows}"
        assert not _naming(messages, f"{PREFIX}_DOCKER_CONTEXT"), (
            f"{label}: an access-method row: {rows}")
        assert _passes(rows), f"{label}: the validator reported no PASS: {rows}"


# ---- the connect guide --------------------------------------------------------------------------



