"""#1107 O8 (the retired _ENV convention) and MF-8 (iii) — the connector author's side:
`validate_scaffold.check_config` and the connect guide (`skills/connect/adapter.md`).

The secret-reference half of O8, MF-15 and NF-14 (`*_SECRET_REF` references into the tenant's
`secrets.env`) moved with credential delivery to #1163.

`check_config(report, settings_dir, system)` keeps its signature and reports through `Report`'s
FAIL/PASS rows (§7 F0). Every test drives the REAL validator over a scaffolded system planted in
the test's own tmp settings folder — `settings/systems/mysys/config.env` — and reads the rows it
produced. Nothing is faked.

At base the validator treats `<KEY>_ENV` as a reference to a process environment variable (C4,
G16, executed). None of that is asserted here: each
test pins the corrected behaviour, so red at base is this file's expected state.

The scaffold is COMPLETE for MF-8 (iii): its `config.env` carries `MYSYS_TRANSPORT="docker-exec"` and
`MYSYS_DOCKER_CONTEXT`, so a test never rides an access-method FAIL — each test
asserts the FAIL it is about by the key (or value) that FAIL must name.
"""
from __future__ import annotations

import re
from pathlib import Path

from defender.skills.connect import validate_scaffold

#: The scaffolded system and its key prefix. A name no committed tenant uses, so a row naming it
#: can only have come from the planted folder.
SYSTEM = "mysys"
PREFIX = "MYSYS"
DOCKER_EXEC = "docker-exec"

ADAPTER_MD = Path(validate_scaffold.__file__).resolve().parent / "adapter.md"


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


def _fails(rows: list[tuple[str, str]]) -> list[str]:
    return [m for s, m in rows if s == validate_scaffold.FAIL]


def _passes(rows: list[tuple[str, str]]) -> list[str]:
    return [m for s, m in rows if s == validate_scaffold.PASS]


def _naming(messages: list[str], needle: str) -> list[str]:
    return [m for m in messages if needle in m]


def _section(text: str, heading: str) -> str:
    """The body of `## <heading>` up to the next `## ` heading ('' when absent)."""
    m = re.search(rf"^## {re.escape(heading)}\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    return m.group(1) if m else ""


def _paragraphs(text: str) -> list[str]:
    """Blank-line- and bullet-separated blocks, joined onto one line each."""
    blocks = re.split(r"\n\s*\n|\n(?=\s*[-*] )", text)
    return [" ".join(b.split()) for b in blocks if b.strip()]


# ---- O8: the retired _ENV convention -----------------------------------------------------------------

def test_o8_env_suffix_retired(tmp_path):
    """RESOLVED (F9, auto). The _ENV convention is retired: check_config no longer treats
    <KEY>_ENV as a reference to a process environment variable, and a leftover <KEY>_ENV key is
    judged like any other key (a secret-named one FAILs as an inline secret), with no reference
    treatment."""
    # Reading taken for "a secret-named one": the leftover's <KEY> half is a secret name
    # (`API_TOKEN` in `API_TOKEN_ENV`, the guide's own example of the old convention), so the key
    # holds a value under a secret's name — an inline secret. At base a well-formed env-var name
    # here PASSES as a reference (C4/G16).
    secret_named = f"{PREFIX}_API_TOKEN_ENV"
    rows = _check(_scaffold(tmp_path / "secret", extra=f'{secret_named}="{PREFIX}_API_TOKEN"\n'))
    hits = _naming(_fails(rows), secret_named)
    assert hits, (
        f"the leftover {secret_named} (a secret-named key holding a value) drew no FAIL as an "
        f"inline secret; rows: {rows}")
    # No reference treatment: nothing says the key should name an environment variable (the
    # base's reference-treatment FAIL, "should name an env var, not hold a value").
    for s, m in rows:
        assert not re.search(r"should name an env(ironment)?[ -]?var", m, re.I), (
            f"the report still treats a _ENV key as an environment-variable reference: {s} {m}")
    # A non-secret leftover is judged like any other non-secret key: no FAIL for it (at base a
    # value that is not env-var-shaped FAILs as "should name an env var" — reference treatment).
    plain = f"{PREFIX}_REGION_ENV"
    rows = _check(_scaffold(tmp_path / "plain", extra=f'{plain}="eu-west-1"\n'))
    assert not _naming(_fails(rows), plain), (
        f"a non-secret leftover {plain} was given reference treatment: {rows}")
    # The retired convention is not what an inline-secret FAIL points the author at.
    rows = _check(_scaffold(tmp_path / "inline", extra=f'{PREFIX}_PASSWORD="inline-pw-e7r"\n'))
    inline = _naming(_fails(rows), f"{PREFIX}_PASSWORD")
    assert inline, f"an inline secret drew no FAIL: {rows}"
    assert not any("_ENV" in m for m in inline), (
        f"the inline-secret FAIL still recommends the retired _ENV suffix: {inline}")


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

def test_o8_guide_rewritten():
    """adapter.md's Credentials section no longer says secrets come from environment variables, and
    the guide no longer names the _ENV suffix. Its VerbContext note no longer tells an adapter to
    resolve config.env from defender_dir. (What the section teaches instead — secret references
    into the tenant's secrets.env — moved with credential delivery to #1163.)"""
    text = ADAPTER_MD.read_text(encoding="utf-8")
    creds = _section(text, "Credentials")
    assert creds.strip(), f"{ADAPTER_MD} has no ## Credentials section"
    # "no longer says secrets come from environment variables" — the base's affirmative claims.
    for claim in (r"read from \W*environment variables", r"keep secrets in env(ironment)? var",
                  r"belongs in an env(ironment)? var", r"name\*? of the env(ironment)?[ -]var"):
        assert not re.search(claim, creds, re.I), (
            f"the Credentials section still says secrets come from environment variables "
            f"({claim!r})")
    # "no longer names the _ENV suffix" — anywhere in the guide.
    assert not re.search(r"`_ENV`|\w_ENV\b", text), "adapter.md still names the _ENV suffix"
    # "Its VerbContext note no longer tells an adapter to resolve config.env from defender_dir."
    for para in _paragraphs(text):
        assert not ("defender_dir" in para and "config.env" in para
                    and re.search(r"resolve", para, re.I)), (
            f"adapter.md still tells an adapter to resolve config.env from defender_dir: {para}")


def test_connect_guide_teaches_no_docker_access_method():
    """The connect guide and skill do not tell a tenant to declare the lab's docker access lines
    (<PREFIX>_TRANSPORT / <PREFIX>_DOCKER_CONTEXT) or to reach its system over `docker exec`: a
    tenant's systems are not containers on a Docker host the product controls."""
    for doc in (ADAPTER_MD, ADAPTER_MD.parent / "SKILL.md"):
        text = doc.read_text(encoding="utf-8")
        assert "_TRANSPORT" not in text, f"{doc.name} still documents <PREFIX>_TRANSPORT"
        assert "_DOCKER_CONTEXT" not in text, f"{doc.name} still documents <PREFIX>_DOCKER_CONTEXT"
        offered = [p for p in _paragraphs(text) if "docker exec" in p
                   and not re.search(r"\blab\b", p)]
        assert not offered, f"{doc.name} offers docker exec as a tenant transport: {offered}"
