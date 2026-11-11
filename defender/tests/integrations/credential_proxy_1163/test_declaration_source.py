"""#1163 the proxy obeys only the declaration in the export `current` names: never the clone's
working tree or an unmerged commit, read without following a link; a merged change applies from
the next request."""
from __future__ import annotations

import base64
import functools
import json
from pathlib import Path

import pytest

from defender.integrations import identity_adapter
from defender.kit.faults import ConfigFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.integrations.credential_proxy_1163._target import (
    ACCESS_FILE,
)
from defender.tests.tenancy.tenant_1108_p4._support import (
    current_commit,
    export_dir,
    git,
)

ACCESS = ACCESS_FILE.format(system="identity")


def test_d1_a_merged_removal_applies_from_the_next_request(tmp_path, data_root):
    """A base replaced by a merged, published change refuses the old base on the next request
    with the same, earlier-minted token. O2, P-2."""
    with T.rig(tmp_path / "forge", data_root) as r:
        tok = r.tok()
        before = r.ask(tok=tok)
        merged = r.t.merge({ACCESS: H.declaration(f"http://127.0.0.1:{H.free_port()}/")},
                           "move the base")
        r.t.publish()
        assert current_commit(r.t.tenant) == merged
        after = r.ask(tok=tok)

    assert (before["fault"], before["status"]) == (None, 200)
    assert after["fault"] == "ConfigFault"
    assert r.up.paths() == ["/api/v2/users/x"]


def test_d1_a_merged_deletion_and_a_merged_addition_apply_from_the_next_request(
        tmp_path, data_root):
    """Deleting the declaration refuses the system; adding it back allows it, each with the
    one token and without a restart. O2, P-2, O7."""
    with T.rig(tmp_path / "forge", data_root) as r:
        tok = r.tok()
        assert r.ask(tok=tok)["fault"] is None
        r.t.merge({ACCESS: None}, "retire the declaration")
        r.t.publish()
        gone = r.ask(tok=tok)
        seen_when_gone = len(r.up.seen)
        r.t.merge({ACCESS: H.declaration(r.up.url + T.BASE_PATH)}, "declare it again")
        r.t.publish()
        back = r.ask(tok=tok)

    assert (gone["fault"], seen_when_gone) == ("ConfigFault", 1)
    assert back["fault"] is None
    assert len(r.up.seen) == 2


def test_d2_a_working_tree_edit_has_no_effect(tmp_path, data_root):
    """A base added only in the clone's working tree is refused unsent; the merged base still
    works. O2, C28."""
    with H.upstream() as wt_up, T.rig(tmp_path / "forge", data_root) as r:
        (Path(r.t.clone) / ACCESS).write_text(
            H.declaration(wt_up.url + T.BASE_PATH), encoding="utf-8")
        refused = r.ask(url=f"{wt_up.url}{T.BASE_PATH}/users/x")
        control = r.ask()

    assert refused["fault"] == "ConfigFault"
    assert wt_up.seen == []
    assert (control["fault"], r.up.paths()) == (None, ["/api/v2/users/x"])


def _unmerged_export(t, wt_up_url: str) -> str:
    """Commit a declaration for `wt_up_url` on a side branch of the clone and materialise an
    export of that commit (C33), leaving `main`, the working tree and `current` as they were."""
    from defender.learning.author import version_control

    git(t.clone, "checkout", "-q", "-b", "unmerged-proposal")
    (Path(t.clone) / ACCESS).write_text(H.declaration(wt_up_url + T.BASE_PATH), encoding="utf-8")
    git(t.clone, "commit", "-q", "-am", "unmerged declaration")
    commit = git(t.clone, "rev-parse", "HEAD")
    git(t.clone, "checkout", "-q", "main")
    version_control.materialise_export(t.tenant, commit)
    return commit


def test_d2_a_declaration_only_in_an_unmerged_commits_export_has_no_effect(
        tmp_path, data_root):
    """An export of an unmerged commit holds a declaration for another base; `current` names
    the merged one, so that base is refused and the merged one works. O2, C33."""
    with H.upstream() as unmerged_up, T.rig(tmp_path / "forge", data_root) as r:
        commit = _unmerged_export(r.t, unmerged_up.url)
        assert export_dir(r.t.tenant, commit).is_dir()
        assert current_commit(r.t.tenant) == r.t.commit
        refused = r.ask(url=f"{unmerged_up.url}{T.BASE_PATH}/users/x")
        control = r.ask()

    assert refused["fault"] == "ConfigFault"
    assert unmerged_up.seen == []
    assert control["fault"] is None


# Retired (#1366 O7: the proxy reads the system's current record, not an export, so a `current` pointer or a link
# inside an export is no longer a path to a declaration): test_d2_a_current_pointer_that_is_a_link_to_an_unmerged_export_is_not_followed
# and test_d3_a_declaration_reached_through_a_link_in_the_export_is_refused[access-file|system-folder|settings-folder].


BAD_NAMES = [
    "../other", "identity/../other", "Identity", "id entity", "-identity", "identity\n",
    "x" * 65, "",
]


def _forged(r, *, grant_system: str) -> str:
    """A real minted token with only its grant swapped for `grant_system`, re-signed by the rig's
    signer: every other claim is the minter's own, and the mint's name check is bypassed."""
    real = T.token(r.t.tenant_id, {("identity", "r")}, signer=r.signer)
    payload = real.rpartition(".")[0]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["grant"] = [[grant_system, "r"]]
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{forged}.{r.signer.sign(forged.encode())}"


@pytest.mark.parametrize("name", BAD_NAMES)
def test_d4_a_system_name_outside_the_grammar_is_refused_without_reading_beyond_it(
        tmp_path, data_root, name):
    """A token granting a system name outside the grammar, with files where it would resolve,
    is a `ConfigFault`, nothing is read or sent; a valid name is granted. O2, O7."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.verifier = H.FakeVerifier(True)  # the forged payload's wire form is not under test
        r.rebuild()
        settings = export_dir(r.t.tenant, r.t.commit) / "settings"
        # A declaration wherever the name would resolve, so a proxy that skips the grammar
        # check finds one and reads the store: traversal targets, and the name itself when it
        # is a legal path component.
        places = [settings / "other", settings / "systems" / "other"]
        if "/" not in name:
            places.append(settings / "systems" / name)  # "" resolves to systems/ itself
        for where in places:
            where.mkdir(exist_ok=True)
            (where / "access.yaml").write_text(
                H.declaration(r.up.url + T.BASE_PATH), encoding="utf-8")
        refused = r.ask(system=name, tok=_forged(r, grant_system=name))
        reads_after, seen_after = list(r.store.reads), len(r.up.seen)
        control = r.ask(tok=_forged(r, grant_system="identity"))

    assert refused["fault"] == "ConfigFault"
    assert (reads_after, seen_after) == ([], 0)
    assert control["fault"] is None
    assert (r.store.reads, len(r.up.seen)) == ([(r.t.tenant_id, "identity")], 1)


@pytest.mark.parametrize("name", BAD_NAMES)
def test_d4_minting_a_token_that_grants_a_system_outside_the_grammar_is_refused(name):
    """`mint_request_token` raises `ConfigFault` for a grant naming a bad system and signs
    nothing; control: a valid name is signed. O2."""
    signer = H.FakeSigner()
    with pytest.raises(ConfigFault):
        T.token(T.RUN_ID, {(name, "r")}, signer=signer)
    assert signer.payloads == []
    T.token(T.RUN_ID, {("identity", "r")}, signer=signer)
    assert len(signer.payloads) == 1


def _bad_declarations(up: str) -> dict[str, str]:
    base = H.declaration(up + T.BASE_PATH)
    return {
        "duplicate-key": base.rstrip().rstrip("}") + f', "base": "{up}/other"}}\n',
        "two-bases": base.replace(f'"{up}{T.BASE_PATH}"', f'["{up}{T.BASE_PATH}", "{up}/b"]'),
        "no-base": base.replace('"base"', '"bse"'),
        "not-http-proxy": base.replace('"http-proxy"', '"docker-exec"'),
        "not-a-mapping": "- just\n- a list\n",
        "empty": "",
        # r7 A19: a declaration no longer renames the stored fields
        "renamed-basic-field": H.declaration(up + T.BASE_PATH, scheme={
            "scheme": "basic", "username_field": "login", "password_field": "password"}),
        "renamed-oauth-field": H.declaration(up + T.BASE_PATH, scheme={
            **H.oauth_scheme(up + "/token"), "client_secret_field": "secret"}),
        "bearer-field-is-a-public-name": H.declaration(up + T.BASE_PATH, scheme={
            "scheme": "bearer", "field": "username"}),
        "header-field-is-a-public-name": H.declaration(up + T.BASE_PATH, scheme={
            "scheme": "header", "header": "X-Api-Key", "field": "client_id"}),
    }


@pytest.mark.parametrize("kind", ["duplicate-key", "two-bases", "no-base", "not-http-proxy",
                                  "not-a-mapping", "empty", "renamed-basic-field",
                                  "renamed-oauth-field", "bearer-field-is-a-public-name",
                                  "header-field-is-a-public-name"])
def test_d5_a_malformed_declaration_is_a_config_fault_unsent(tmp_path, data_root, kind):
    """A merged but unusable declaration (duplicate key, two bases, no base, other access
    method, not a mapping, empty, a renamed credential field, a secret field named by a public
    name) refuses the system. O2, A2, O7, r7 A19."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.t.merge({ACCESS: _bad_declarations(r.up.url)[kind]}, "bad declaration")
        r.t.publish()
        refused = r.ask()

    assert refused["fault"] == "ConfigFault"
    assert (r.up.seen, r.store.reads) == ([], [])


def test_d3_adapter_over_the_working_tree_reaches_nothing_the_merged_declaration_forbids(
        tmp_path, data_root):
    """An adapter whose run record is the clone's working tree (preflight, C34) and whose base exists only
    there is refused by the proxy, which enforces the system's CURRENT record; the run record built from
    the current records reaches the merged base. O7, A3."""

    with H.upstream() as wt_up, T.rig(tmp_path / "forge", data_root) as r:
        (Path(r.t.clone) / ACCESS).write_text(
            H.declaration(wt_up.url + T.BASE_PATH), encoding="utf-8")
        working_tree = R.run_tenant_for(r.t.tenant, dispatches_lead_zero=False)
        with A.proxy_for(r.t, r.store, verifier=r.verifier, audit=r.audit) as (proxy_url, tap):
            tok = r.tok()
            with pytest.raises(ConfigFault):
                identity_adapter.get_user(
                    A.ctx_for(tmp_path / "episode", working_tree, proxy_url, tok),
                    user="dev.dana")
            assert tap.tokens == [tok], "the refusal must be the proxy's: it was asked once"
            assert wt_up.seen == []
            merged = identity_adapter.get_user(
                A.ctx_for(tmp_path / "episode", T.run_record(r.t), proxy_url, tok),
                user="dev.dana")

    assert merged["path"].endswith("/users/dev.dana")
    assert [s.path for s in r.up.seen] == [f"{T.BASE_PATH}/users/dev.dana"]


ES = "https://es.corp.example/es"
_OTHER_LABELS = ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "PUBLIC KEY", "X509 CRL",
                 "TRUSTED CERTIFICATE", "CERTIFICATE REQUEST")


def _relabeled(pem: bytes, label: str) -> bytes:
    """Well-formed PEM of `pem`'s body under another block `label`."""
    kind = pem.splitlines()[0].decode().removeprefix("-----BEGIN ").removesuffix("-----")
    return pem.replace(kind.encode(), label.encode())


@functools.cache
def _pki():
    from defender.tests.support.shared._tls_server import chain

    return chain()


@functools.cache
def _ca_texts() -> dict[str, tuple[bytes, str]]:
    pki = _pki()
    texts = {
        "root-on-https": (pki.root.cert, ES),
        "root-and-intermediate": (pki.root.cert + pki.intermediate.cert, ES),
        "not-pem": (b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n", ES),
        "key-not-cert": (pki.root.key, ES),
        "cert-and-key": (pki.root.cert + pki.root.key, ES),
        "cert-then-junk": (pki.root.cert + b"junk after the certificate\n", ES),
        "on-an-http-base": (pki.root.cert, "http://es.corp.example/es"),
    }
    for label in _OTHER_LABELS:
        texts[f"cert-and-{label.lower().replace(' ', '-')}"] = (
            pki.root.cert + _relabeled(pki.root.key, label), ES)
    return texts


@pytest.mark.parametrize("kind", sorted(_ca_texts()))
def test_1391_o4_a_declarations_ca_is_judged_when_it_is_parsed(kind):
    """`ca` of certificates only, on an https base, parses; anything else (not PEM, a key, a
    certificate beside a non-certificate block or junk, an http base) is a ConfigFault. #1391 O4, F6."""
    from defender.tenancy._access import parse_access

    ca, base = _ca_texts()[kind]
    text = H.declaration(base, scheme=H.basic_scheme(), ca=ca)
    if kind in {"root-on-https", "root-and-intermediate"}:
        assert parse_access(text, system="elastic").base == base
    else:
        with pytest.raises(ConfigFault) as refused:
            parse_access(text, system="elastic")
        key_body = _pki().root.key.splitlines()[1]  # a line of the base64 body, whatever the label
        if key_body in ca:
            assert key_body.decode() not in str(refused.value), (
                "a pasted private key reached the fault text, so the run record")


def test_1391_o4_a_server_certificate_as_ca_is_refused_as_not_a_ca():
    """The server's own certificate pasted as `ca` (a valid certificate, not a CA) is refused
    with that reason, not as an invalid certificate: the operator is pointed at the CA's
    certificate. #1391 O4 (PR #1409 review)."""
    from defender.tenancy._access import parse_access

    text = H.declaration(ES, scheme=H.basic_scheme(), ca=_pki().leaf.cert)
    with pytest.raises(ConfigFault) as refused:
        parse_access(text, system="elastic")
    assert "no CA certificate" in str(refused.value), refused.value
    assert "not a valid certificate" not in str(refused.value), refused.value


@pytest.mark.parametrize("where", ["nbsp-before", "line-separator-inside"])
def test_1391_o4_a_ca_with_non_ascii_whitespace_is_a_settings_fault_not_a_crash(where):
    """Non-ASCII whitespace around or inside valid PEM text is a ConfigFault, never a TypeError,
    and the text is not echoed. #1391 O4, D13, F6."""
    from defender.tenancy._access import parse_access

    pem = _pki().root.cert.decode()
    ca = "\u00a0" + pem if where == "nbsp-before" else pem.replace("\n", "\u2028", 1)
    text = H.declaration(ES, scheme=H.basic_scheme(), ca=ca)
    with pytest.raises(ConfigFault) as refused:
        parse_access(text, system="elastic")
    assert pem.splitlines()[1] not in str(refused.value), "the certificate text reached the fault"


@pytest.mark.parametrize(("token_url", "ca", "fault"), [
    pytest.param("https://idp.corp.example/token", True, None, id="https-control"),
    pytest.param("http://idp.corp.example/token", False, None, id="http-without-ca"),
    pytest.param("http://idp.corp.example/token", True, ConfigFault, id="http-with-ca"),
])
def test_1391_o4_a_ca_with_an_http_token_url_is_a_settings_fault(token_url, ca, fault):
    """`ca` covers the token exchange, so it is refused beside an `http://` token URL. #1391 O4, D13, F6."""
    from defender.tenancy._access import parse_access
    from defender.tests.support.shared._tls_server import issue

    text = H.declaration(ES, scheme=H.oauth_scheme(token_url),
                         ca=issue("tenant private root", ca=True).cert if ca else None)
    if fault is None:
        assert parse_access(text, system="elastic").base == ES
    else:
        with pytest.raises(fault):
            parse_access(text, system="elastic")


_CLEAN = H.declaration(ES, scheme=H.oauth_scheme("https://idp.corp.example/token"))


@pytest.mark.parametrize(("text", "fault"), [
    pytest.param(_CLEAN, False, id="control"),
    pytest.param("# replace every CHANGE-ME\n" + _CLEAN, False, id="only-in-a-comment"),
    pytest.param(_CLEAN.replace(ES, "https://CHANGE-ME"), True, id="in-the-base"),
    pytest.param(_CLEAN.replace("idp.corp.example", "CHANGE-ME"), True, id="in-auth"),
    pytest.param(_CLEAN.replace('"read"', '"CHANGE-ME"'), True, id="in-a-list"),
])
def test_a_declaration_still_carrying_the_templates_placeholder_is_not_configured(text, fault):
    """A value still holding the tenant template's CHANGE-ME, at any depth, is a settings fault
    that says the system is not configured — never an address to call."""
    from defender.kit.settings import NOT_CONFIGURED
    from defender.tenancy._access import parse_access

    assert ("CHANGE-ME" in text) or not fault, "precondition: the faulting case carries the placeholder"
    if not fault:
        assert parse_access(text, system="elastic").base == ES
        return
    with pytest.raises(ConfigFault) as raised:
        parse_access(text, system="elastic")
    assert "CHANGE-ME" in str(raised.value), str(raised.value)
    assert NOT_CONFIGURED in str(raised.value), str(raised.value)
