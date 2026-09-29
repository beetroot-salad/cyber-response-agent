"""#1107 O8 and MF-8 (iii) / MF-15 / NF-14 — the connector author's side of the secret convention:
`validate_scaffold.check_config` and the connect guide (`skills/connect/adapter.md`).

`check_config(report, settings_dir, system)` keeps its signature and reports through `Report`'s
FAIL/PASS rows (§7 F0). Every test drives the REAL validator over a scaffolded system planted in
the test's own tmp settings folder — `settings/systems/mysys/config.env` plus, where the demand is
about it, `settings/secrets.env` — and reads the rows it produced. Nothing is faked: the unreadable
`secrets.env` (a directory, a FIFO with no writer, non-UTF-8 bytes) is a real file-system object
created in the test.

At base the validator treats `<KEY>_ENV` as a reference to a process environment variable, reads no
`secrets.env`, and passes a blank reference, a lowercase `_env` key and a blank secret (C4, G16,
executed); on an inline-secret FAIL it prints the value (G16). None of that is asserted here: each
test pins the corrected behaviour, so red at base is this file's expected state.

The scaffold is COMPLETE for MF-8 (iii): its `config.env` carries `MYSYS_TRANSPORT="docker-exec"` and
`MYSYS_DOCKER_CONTEXT`, so a secret-reference test never rides an access-method FAIL — each test
asserts the FAIL it is about by the key (or value) that FAIL must name.
"""
from __future__ import annotations

import os
import re
import stat
import threading
from pathlib import Path

from defender.skills.connect import validate_scaffold

#: The scaffolded system and its key prefix. A name no committed tenant uses, so a row naming it
#: can only have come from the planted folder.
SYSTEM = "mysys"
PREFIX = "MYSYS"
DOCKER_EXEC = "docker-exec"
REF = f"{PREFIX}_API_TOKEN_SECRET_REF"
NAME = f"{PREFIX}_API_TOKEN"

ADAPTER_MD = Path(validate_scaffold.__file__).resolve().parent / "adapter.md"


# ---- fixture planting (returns, never asserts) ----------------------------------------------------

def _scaffold(root: Path, *, extra: str = "", transport: str | None = DOCKER_EXEC,
              context: str | None = "ctx-mysys", secrets: str | bytes | None = None) -> Path:
    """A tenant `settings/` folder holding one scaffolded system's `config.env` (URL base plus the
    MF-8 access-method lines unless dropped, plus `extra` verbatim) and, when given, `secrets.env`
    written verbatim. Returns the settings folder."""
    settings = Path(root) / "settings"
    cfg = settings / "systems" / SYSTEM / "config.env"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    lines = [f'{PREFIX}_URL_BASE="http://mysys:8080"']
    if transport is not None:
        lines.append(f'{PREFIX}_TRANSPORT="{transport}"')
    if context is not None:
        lines.append(f'{PREFIX}_DOCKER_CONTEXT="{context}"')
    cfg.write_text("\n".join(lines) + "\n" + extra, encoding="utf-8")
    if secrets is not None:
        path = settings / "secrets.env"
        if isinstance(secrets, bytes):
            path.write_bytes(secrets)
        else:
            path.write_text(secrets, encoding="utf-8")
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


# ---- O8: the reference convention ------------------------------------------------------------------

def test_o8_blank_ref_fails(tmp_path):
    """check_config FAILs a config.env reference key ending in _SECRET_REF whose value is blank."""
    # rejected: the cold review's file-permission warning, dropped as invented scope
    for label, line in (("empty-quoted", f'{REF}=""\n'), ("bare", f"{REF}=\n")):
        settings = _scaffold(tmp_path / label, extra=line,
                             secrets=f'{NAME}="present-value-b1k"\n')
        rows = _check(settings)
        assert _naming(_fails(rows), REF), (
            f"a blank reference ({label}: {line.strip()!r}) drew no FAIL naming {REF}; "
            f"rows: {rows}")


def test_o8_ref_key_any_case(tmp_path):
    """RESOLVED at §7 (F2, human round 4: the plain reading). check_config matches the _SECRET_REF
    suffix in any letter case, and FAILs a reference key that is not all uppercase (x_secret_ref,
    X_Secret_Ref) as a mis-spelled reference, even when its value and its secrets.env entry are
    good. The uppercase spelling of the same reference draws no FAIL. At base a lowercase _env key
    holding an inline value passes (C4)."""
    good_entry = f'{NAME}="good-value-r4c"\n'
    for key in ("mysys_api_token_secret_ref", "Mysys_Api_Token_Secret_Ref"):
        settings = _scaffold(tmp_path / key, extra=f'{key}="{NAME}"\n', secrets=good_entry)
        rows = _check(settings)
        assert _naming(_fails(rows), key), (
            f"the non-uppercase reference key {key!r} (good value, good entry) drew no FAIL "
            f"naming it as a mis-spelled reference; rows: {rows}")
    # The uppercase spelling of the same reference, same value, same entry: no FAIL for it.
    settings = _scaffold(tmp_path / "upper", extra=f'{REF}="{NAME}"\n', secrets=good_entry)
    rows = _check(settings)
    assert not _naming(_fails(rows), REF), f"the uppercase reference {REF} drew a FAIL: {rows}"
    assert _passes(rows), f"the validator reported nothing for a good reference: {rows}"


def test_o8_missing_entry_fails(tmp_path):
    """check_config FAILs a declared reference whose secrets.env entry is missing, and one whose
    entry is blank."""
    declared = f'{REF}="{NAME}"\n'
    arms = {
        # secrets.env exists and holds another entry, but not the declared name.
        "missing": 'OTHER_TOKEN="other-value-m2x"\n',
        # the declared name is present with an empty value.
        "blank": f'{NAME}=""\nOTHER_TOKEN="other-value-m2x"\n',
    }
    for label, secrets in arms.items():
        rows = _check(_scaffold(tmp_path / label, extra=declared, secrets=secrets))
        # The FAIL identifies the reference: its declaring key or the name it holds (the key
        # spells the name, so a FAIL naming either contains NAME).
        assert _naming(_fails(rows), NAME), (
            f"a declared reference whose secrets.env entry is {label} drew no FAIL naming it; "
            f"rows: {rows}")
    # Control: the same declaration with a non-empty entry draws no FAIL for the reference —
    # the arms above differ from it only in the entry.
    rows = _check(_scaffold(tmp_path / "present", extra=declared,
                            secrets=f'{NAME}="present-value-m2x"\n'))
    assert not _naming(_fails(rows), NAME), f"a good entry drew a FAIL: {rows}"


def test_o8_value_never_printed(tmp_path):
    """No line of check_config's report contains any value from secrets.env, whether for a valid
    reference, a missing or blank one, or another entry in the same file."""
    valid_value = "vAlId-SeCrEt-9q7w"
    other_value = "oThEr-SeCrEt-3k8z"
    config = (
        f'{PREFIX}_GOOD_TOKEN_SECRET_REF="{PREFIX}_GOOD_TOKEN"\n'      # valid: entry present
        f'{PREFIX}_GONE_TOKEN_SECRET_REF="{PREFIX}_GONE_TOKEN"\n'      # missing entry
        f'{PREFIX}_EMPTY_TOKEN_SECRET_REF="{PREFIX}_EMPTY_TOKEN"\n'    # blank entry
    )
    secrets = (
        f'{PREFIX}_GOOD_TOKEN="{valid_value}"\n'
        f'{PREFIX}_EMPTY_TOKEN=""\n'
        f'UNDECLARED_OTHER="{other_value}"\n'
    )
    settings = _scaffold(tmp_path, extra=config, secrets=secrets)
    report = validate_scaffold.Report()
    validate_scaffold.check_config(report, settings, SYSTEM)
    rows = list(report.rows)
    # POSITIVE PRECONDITION: the validator did read secrets.env against the declarations — the
    # missing and the blank reference each drew a FAIL. Without it an empty report would satisfy
    # the absence below vacuously.
    fails = _fails(rows)
    assert _naming(fails, f"{PREFIX}_GONE_TOKEN"), f"the missing entry drew no FAIL: {rows}"
    assert _naming(fails, f"{PREFIX}_EMPTY_TOKEN"), f"the blank entry drew no FAIL: {rows}"
    # Every line of the report — the rows, and the report as rendered for the operator/model.
    rendered = "\n".join(f"{s} {m}" for s, m in rows)
    for value in (valid_value, other_value):
        assert value not in rendered, (
            f"a secrets.env value ({value!r}) reached the validator's report:\n{rendered}")


def test_o8_valid_ref_passes(tmp_path):
    """check_config draws no FAIL for a non-blank reference with a non-empty secrets.env entry."""
    declared = f'{REF}="{NAME}"\n'
    rows = _check(_scaffold(tmp_path / "good", extra=declared,
                            secrets=f'{NAME}="good-value-v5p"\n'))
    assert not _naming(_fails(rows), NAME), f"a good reference drew a FAIL: {rows}"
    assert _passes(rows), f"the validator reported no PASS for a good scaffold: {rows}"
    # In-test control: the checker does read the entry — the same declaration with the entry
    # removed draws a FAIL for it, so "no FAIL" above is the entry's doing.
    rows = _check(_scaffold(tmp_path / "gone", extra=declared,
                            secrets='OTHER_TOKEN="other-value-v5p"\n'))
    assert _naming(_fails(rows), NAME), (
        f"with the entry removed the reference still drew no FAIL — the pass above is not the "
        f"entry's doing; rows: {rows}")


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


# ---- MF-15: a reference that is not name-shaped -----------------------------------------------------

def test_s7_mf15_validator_fails_ref_not_name_shaped(tmp_path):
    """validate_scaffold FAILs a *_SECRET_REF whose value is not shaped like an environment-variable
    name (letters, digits and underscore, not starting with a digit), including a reference that
    holds the secret itself (FOO_TOKEN_SECRET_REF=hunter2-value!) and one holding a space or '=';
    its FAIL line names the key only, never the held string."""
    arms = {
        f"{PREFIX}_FOO_TOKEN_SECRET_REF": "hunter2-value!",   # the secret itself
        f"{PREFIX}_SPC_TOKEN_SECRET_REF": "held string zq7",  # a space
        f"{PREFIX}_EQ_TOKEN_SECRET_REF": "K=held-zq8",        # an '='
        f"{PREFIX}_DIG_TOKEN_SECRET_REF": "9zqheld",           # leading digit
    }
    for key, held in arms.items():
        # (a) No entry for the held string: the FAIL names the key, and no line of the report
        # carries the held string (for the first arm, that string IS the secret).
        rows = _check(_scaffold(tmp_path / f"{key}-a", extra=f'{key}="{held}"\n',
                                secrets='OTHER_TOKEN="other-value-s15"\n'))
        assert _naming(_fails(rows), key), (
            f"{key}={held!r} (not name-shaped) drew no FAIL naming the key; rows: {rows}")
        for s, m in rows:
            assert held not in m, f"a report line carries the held string {held!r}: {s} {m}"
        # (b) Where the one parser can key an entry by the held string (no space, no '='), plant
        # one: the FAIL must still name the key, so it is the name-shape check and not a
        # missing-entry FAIL standing in for it; and that FAIL line still omits the string.
        if re.fullmatch(r"\S+", held) and "=" not in held:
            rows = _check(_scaffold(tmp_path / f"{key}-b", extra=f'{key}="{held}"\n',
                                    secrets=f'{held}="entry-value-s15"\n'))
            hits = _naming(_fails(rows), key)
            assert hits, (
                f"{key}={held!r} with a secrets.env entry keyed by that string drew no FAIL "
                f"naming the key — the name-shape check did not fire; rows: {rows}")
            for m in hits:
                assert held not in m, f"the FAIL line for {key} carries the held string: {m}"
    # Control: a name-shaped reference with its entry draws no FAIL for its key.
    rows = _check(_scaffold(tmp_path / "shaped", extra=f'{REF}="{NAME}"\n',
                            secrets=f'{NAME}="good-value-s15"\n'))
    assert not _naming(_fails(rows), REF), f"a name-shaped reference drew a FAIL: {rows}"


# ---- NF-14: secrets.env the validator cannot read ---------------------------------------------------

_COULD_NOT_READ = re.compile(r"could not|cannot|can't|unreadable|not readable|unable", re.I)


def _assert_unreadable_reported(rows: list[tuple[str, str]], arm: str, value: str | None) -> None:
    fails = [m for m in _fails(rows) if "secrets.env" in m and _COULD_NOT_READ.search(m)]
    assert fails, (
        f"secrets.env {arm}: no FAIL line saying secrets.env could not be read; rows: {rows}")
    passes = [m for m in _passes(rows) if "secrets.env" in m or NAME in m]
    assert not passes, f"secrets.env {arm}: a PASS for what could not be read: {passes}"
    if value is not None:
        for s, m in rows:
            assert value not in m, f"secrets.env {arm}: a report line carries a value: {s} {m}"


def test_s7_nf14_validator_fails_unreadable_secrets_env(tmp_path):
    """validate_scaffold run where secrets.env cannot be read (no permission, not a regular file, or
    non-UTF-8 bytes) FAILs with a line saying secrets.env could not be read: never a PASS, never a
    crash, never a value."""
    declared = f'{REF}="{NAME}"\n'

    # Not a regular file: a directory at the name.
    settings = _scaffold(tmp_path / "dir", extra=declared)
    (settings / "secrets.env").mkdir()
    _assert_unreadable_reported(_check(settings), "is a directory", None)

    # Non-UTF-8 bytes, a value beside them.
    value = "undecodable-value-n14"
    settings = _scaffold(tmp_path / "bytes", extra=declared,
                         secrets=f'{NAME}="{value}"\n'.encode() + b"\xff\xfe=\xff\n")
    _assert_unreadable_reported(_check(settings), "is not UTF-8", value)

    # Not a regular file: a FIFO with no writer. A validator that opens it blocks forever, so the
    # call runs in a thread; if it has not returned, the FIFO is opened for writing (and closed) to
    # release it, and the block is itself the failure.
    settings = _scaffold(tmp_path / "fifo", extra=declared)
    fifo = settings / "secrets.env"
    os.mkfifo(fifo)
    out: dict[str, object] = {}

    def run() -> None:
        try:
            out["rows"] = _check(settings)
        except BaseException as e:  # noqa: BLE001 — surfaced by the assertion below
            out["raised"] = e

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(10)
    blocked = worker.is_alive()
    if blocked:
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        worker.join(10)
    assert not blocked, "the validator blocked opening a FIFO at secrets.env (NF-12: never block)"
    assert "raised" not in out, f"the validator crashed on a FIFO secrets.env: {out.get('raised')!r}"
    assert stat.S_ISFIFO(fifo.lstat().st_mode), "the fixture FIFO is gone"
    _assert_unreadable_reported(out["rows"], "is a FIFO", None)  # type: ignore[arg-type]

    # No permission: a mode-000 file. Root reads through any mode, so under root this arm cannot
    # make the file unreadable and is not asserted (the other three arms still bind the rule).
    if os.geteuid() != 0:
        value = "no-permission-value-n14"
        settings = _scaffold(tmp_path / "perm", extra=declared, secrets=f'{NAME}="{value}"\n')
        (settings / "secrets.env").chmod(0)
        try:
            _assert_unreadable_reported(_check(settings), "has no read permission", value)
        finally:
            (settings / "secrets.env").chmod(0o600)


# ---- the connect guide --------------------------------------------------------------------------

def test_o8_guide_rewritten():
    """adapter.md's Credentials section describes secrets as <KEY>_SECRET_REF references into the
    tenant's settings/secrets.env. It no longer says secrets come from environment variables, and it
    no longer names the _ENV suffix. Its VerbContext note no longer tells an adapter to resolve
    config.env from defender_dir. It states secrets.env's format (KEY=VALUE per line, one matched
    pair of quotes trimmed, no export prefix, no multi-line values; NF-11) and tells operators to
    rotate a secret by writing a new file and renaming it over secrets.env (NF-12)."""
    text = ADAPTER_MD.read_text(encoding="utf-8")
    creds = _section(text, "Credentials")
    assert creds.strip(), f"{ADAPTER_MD} has no ## Credentials section"
    # "<KEY>_SECRET_REF references into the tenant's settings/secrets.env"
    assert "_SECRET_REF" in creds, "the Credentials section does not describe _SECRET_REF references"
    assert "secrets.env" in creds, "the Credentials section does not name the tenant's settings/secrets.env"
    assert "settings/" in creds, "the Credentials section does not name the tenant's settings/secrets.env"
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
    # The format rules (NF-11) and rotation (NF-12), each by the demand's own nouns.
    assert re.search(r"KEY=VALUE", text, re.I), "adapter.md does not state secrets.env's KEY=VALUE-per-line format"
    assert re.search(r"quote", text, re.I), "adapter.md does not state that one matched pair of quotes is trimmed"
    assert (re.search(r"(one|single) matched pair|matched pair",
                                                         text, re.I)), "adapter.md does not state that one matched pair of quotes is trimmed"
    assert re.search(r"\bexport\b", text), "adapter.md does not state the no-export-prefix rule"
    assert re.search(r"multi-?line", text, re.I), (
        "adapter.md does not state the no-multi-line-values rule")
    assert re.search(r"renam", text, re.I), ("adapter.md does not tell operators to rotate a secret by writing a new file and "
        "renaming it over secrets.env")
    assert re.search(r"rotat", text, re.I), ("adapter.md does not tell operators to rotate a secret by writing a new file and "
        "renaming it over secrets.env")


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

