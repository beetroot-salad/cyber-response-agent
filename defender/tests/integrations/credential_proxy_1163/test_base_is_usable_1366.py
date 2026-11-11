"""#1366 R15: a base, or an OAuth token URL, the access parser accepts is one the credential proxy can send to.

Entry points: `defender.tenancy.parse_access` over a declaration text (the store's, `check`'s and run start's judge of a
base) and the proxy's own `locate` (the URL rules every request is held to). The two meet over generated URLs: userinfo
(none, empty, user, user and password), port (valid, out of range, not a number, empty), host spellings, and path segments
(plain, `.` and `..` spelled out and percent-encoded, `;`, whitespace and control characters, an escaped `/`, a backslash,
non-ASCII, empty). The rule is one-way and total: whatever the parser accepts, `locate` admits a URL under; whatever the
parser refuses is nobody's loss. A login part, spelled any way, is refused. An escaped `/` and a backslash in a base stay
usable (the tenant's own base may name them, the proxy allows them).
"""
from __future__ import annotations

import dataclasses
import itertools
import random

import pytest

from defender.credential_proxy._refusal import Refused
from defender.credential_proxy._scope import locate
from defender.kit.faults import ConfigFault
from defender.tenancy import parse_access
from defender.tests.support.tenancy import _systems1366 as R

SCHEMES = ("http", "https")
HOSTS = ("soc.test", "SOC.Test", "soc.test.", "[::1]", "10.0.0.7")
#: The text before the host: nothing, and each way to write a login part (the empty one included).
USERINFO = ("", "@", "u@", "u:@", ":@", ":p@", "u:p@", "%40@", "u%40:p@")
LOGINS = [u for u in USERINFO if u]
#: The text after the host.
PORTS = ("", ":443", ":80", ":8080", ":0", ":65536", ":99999", ":abc", ":", ":-1", ":+80", ":8 0")
SEGMENTS = ("api", "v1", ".", "..", "%2e", "%2E", "%2e%2e", ".%2e", "%2e.", "..;", ";", "a;b", "a%3Bb", "%3b", "a b", "a%20b",
            "a\tb", "a\nb", "a\x00b", "a\x7fb", "a%00b", "a%2Fb", "a%2fb", "a%5Cb", "a\\b", "%2F", "é", "", " ", "a;")
#: Spellings the proxy allows in a base and the access parser must therefore keep accepting.
USABLE = ("/a%2Fb", "/a%2fb", "/a%5Cb", "/a\\b", "/%2F", "/api/v1", "/api/v1/", "")
KEYS = ("base", "token_url")


def _urls() -> list[str]:
    """Generated base spellings: every userinfo, port and host alone, every segment alone and second to a plain one,
    then a seeded sample over all the parts."""
    urls: set[str] = set()
    for scheme, host, info, port in itertools.product(SCHEMES, HOSTS, USERINFO, PORTS):
        urls.add(f"{scheme}://{info}{host}{port}/api")
    for scheme, segment in itertools.product(SCHEMES, SEGMENTS):
        urls.add(f"{scheme}://soc.test/{segment}")
        urls.add(f"{scheme}://soc.test:8443/api/{segment}/v1")
        urls.add(f"{scheme}://soc.test/api/{segment}")
        urls.add(f"{scheme}://soc.test/{segment}/")
    drawn = random.Random(1366)
    for _ in range(1500):
        path = "/".join(drawn.choice(SEGMENTS + ("api",)) for _ in range(drawn.randrange(0, 4)))
        urls.add(f"{drawn.choice(SCHEMES)}://{drawn.choice(USERINFO)}{drawn.choice(HOSTS)}{drawn.choice(PORTS)}"
                 f"{'/' if path or drawn.random() < 0.5 else ''}{path}{'/' if drawn.random() < 0.2 else ''}")
    urls.update(f"{scheme}://soc.test{tail}" for scheme in SCHEMES for tail in USABLE)
    return sorted(urls)


def _declaration(key: str, url: str) -> str:
    """A declaration whose `key` (the base, or the OAuth token URL) is `url`, everything else sound."""
    if key == "base":
        return R.declaration(url)
    return R.declaration("https://soc.test", scheme=R.OAUTH, token_url=url, scopes=("read",))


def _accepted(key: str, url: str):
    """The parsed declaration when the access parser accepts `url` as `key`, else None."""
    try:
        return parse_access(_declaration(key, url), system="ticket")
    except ConfigFault:
        return None


def _admits(parsed, key: str, url: str) -> list[str]:
    """The URLs the proxy's `locate` refuses among `url` itself and one path segment under it, judged against a
    declaration whose base is `url` (for a token URL: the one URL the exchange sends to)."""
    on = dataclasses.replace(parsed, base=url)
    refused = []
    for asked in (url, url.rstrip("/") + "/x"):
        try:
            locate(on, asked)
        except Refused as why:
            refused.append(f"{asked!r}: {why}")
    return refused


@pytest.mark.parametrize("key", KEYS)
def test_1366_r15_every_base_or_token_url_the_access_parser_accepts_is_one_the_proxy_admits_a_url_under(key):
    """Generated over userinfo, port, host and path spellings: the access parser refuses any base (or OAuth token URL)
    under which the proxy's own `locate` would refuse every URL, so no record is stored that the proxy can never use.
    (#1366 R15, O4, K4)"""
    accepted = {url: parsed for url in _urls() if (parsed := _accepted(key, url)) is not None}
    assert len(accepted) > 100, "the generator drew almost nothing the parser accepts: the property would be vacuous"

    unusable = {url: refused for url, parsed in accepted.items() if (refused := _admits(parsed, key, url))}

    assert not unusable, f"accepted by the parser and refused by the proxy ({len(unusable)}): {dict(list(unusable.items())[:6])}"


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("login", LOGINS)
@pytest.mark.parametrize("scheme", SCHEMES)
def test_1366_r15_a_login_part_is_refused_however_it_is_spelled(key, login, scheme):
    """`user@`, `user:password@`, `:password@`, `user:@` and the empty `@` after the scheme: the parser refuses each,
    for the base and the token URL alike (the proxy applies the credential; a login in the base is never the tenant's to
    set). Control: the same URL without it is accepted. (#1366 R15, K4)"""
    assert _accepted(key, f"{scheme}://soc.test:8443/api") is not None, "control: the same URL without a login"
    assert _accepted(key, f"{scheme}://{login}soc.test:8443/api") is None, f"{login!r} was accepted"


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("tail", USABLE)
def test_1366_r15_an_escaped_slash_and_a_backslash_in_a_base_stay_usable(key, tail):
    """The tenant's own base may name an escaped `/` or a backslash (only what is under it is held to the rule): the
    parser accepts these and the proxy admits a URL under each. (#1366 R15)"""
    url = f"https://soc.test{tail}"
    parsed = _accepted(key, url)

    assert parsed is not None, f"{url!r} was refused by the access parser"
    assert not _admits(parsed, key, url)
