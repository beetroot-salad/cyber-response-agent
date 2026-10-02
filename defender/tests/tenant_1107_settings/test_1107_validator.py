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


# ---- MF-8 (iii): the access method --------------------------------------------------------------------

def test_s7_mf8_validator_fails_missing_access_method(tmp_path):
    """validate_scaffold FAILs a scaffolded system's config.env that lacks <PREFIX>_TRANSPORT, and one
    that lacks <PREFIX>_DOCKER_CONTEXT; a config.env carrying both, with TRANSPORT=docker-exec, draws
    no such FAIL."""
    transport_key, context_key = f"{PREFIX}_TRANSPORT", f"{PREFIX}_DOCKER_CONTEXT"
    rows = _check(_scaffold(tmp_path / "no-transport", transport=None))
    assert _naming(_fails(rows), transport_key), (
        f"a config.env without {transport_key} drew no FAIL naming it; rows: {rows}")
    rows = _check(_scaffold(tmp_path / "no-context", context=None))
    assert _naming(_fails(rows), context_key), (
        f"a config.env without {context_key} drew no FAIL naming it; rows: {rows}")
    rows = _check(_scaffold(tmp_path / "both"))
    fails = _fails(rows)
    assert not _naming(fails, transport_key), (f"a config.env carrying both access-method lines (TRANSPORT=docker-exec) drew an "
        f"access-method FAIL: {rows}")
    assert not _naming(fails, context_key), (f"a config.env carrying both access-method lines (TRANSPORT=docker-exec) drew an "
        f"access-method FAIL: {rows}")
    assert _passes(rows), f"the validator reported no PASS for a complete scaffold: {rows}"


def test_s7_mf8_validator_fails_unimplemented_method(tmp_path):
    """validate_scaffold FAILs a config.env whose <PREFIX>_TRANSPORT names an unimplemented method
    (http, or any value other than docker-exec), naming the value."""
    for value in ("http", "ssh-tunnel", "docker_exec"):
        rows = _check(_scaffold(tmp_path / value, transport=value))
        assert _naming(_fails(rows), value), (
            f"{PREFIX}_TRANSPORT={value!r} (no such method) drew no FAIL naming the value; "
            f"rows: {rows}")
    # Control: the one implemented method draws no TRANSPORT FAIL.
    rows = _check(_scaffold(tmp_path / "docker-exec"))
    assert not _naming(_fails(rows), f"{PREFIX}_TRANSPORT"), (
        f"TRANSPORT=docker-exec drew a FAIL: {rows}")


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


def test_s7_mf8_guide_documents_access_method():
    """adapter.md documents <PREFIX>_TRANSPORT (docker-exec, the one implemented method) and
    <PREFIX>_DOCKER_CONTEXT as required config.env lines with no default. It also tells the
    operator that a tenant folder written before D2 has no systems/host-state/ folder at all, so
    every such tenant needs a new systems/host-state/config.env (R7)."""
    text = ADAPTER_MD.read_text(encoding="utf-8")
    assert "_TRANSPORT" in text, "adapter.md does not document <PREFIX>_TRANSPORT"
    assert "_DOCKER_CONTEXT" in text, "adapter.md does not document <PREFIX>_DOCKER_CONTEXT"
    paras = _paragraphs(text)
    transport = [p for p in paras if "_TRANSPORT" in p]
    assert any(DOCKER_EXEC in p for p in transport), (
        f"no paragraph documenting <PREFIX>_TRANSPORT names docker-exec: {transport}")
    access = [p for p in paras if "_TRANSPORT" in p or "_DOCKER_CONTEXT" in p]
    assert any(re.search(r"\brequired\b", p, re.I) for p in access), (
        f"adapter.md does not say the access-method lines are required: {access}")
    assert any(re.search(r"no (built-in )?default|without (a )?default|never default|"
                         r"not defaulted|has no default", p, re.I) for p in access), (
        f"adapter.md does not say the access-method lines have no default: {access}")
    # PF-R7 (reading A, auto): a tenant folder written before D2 has no systems/host-state/ at all
    # (G41), and the resolve warning lists only configs that lack an access-method key, never a
    # missing folder, so the guide is where the operator learns host-state needs a new file.
    host_state = [p for p in paras if "host-state" in p and "config.env" in p]
    assert any(re.search(r"\b(existing|older|earlier|pre-existing|before|predat\w*|upgrad\w*|migrat\w*)\b",
                         p, re.I)
               and re.search(r"\b(add|create|new|needs?|must)\b", p, re.I) for p in host_state), (
        "adapter.md does not tell the operator that a tenant folder written before this change needs "
        f"a new systems/host-state/config.env: {host_state}")

