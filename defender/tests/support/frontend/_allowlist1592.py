"""#1592 PP-3 "Edge" as test data (no test functions): the Forgejo site's allowlist and its off-list classes, written
once from the design's "Allowed paths" and "Off the list, by name", for the local Caddy tests (S3-11), the live edge
cases (S4-1, S4-15) and nothing else.

An entry holds the methods the design gives a path ("a path listed without a method allows GET only"), the pattern the
design writes (`{R}` the literal `/t-<uuid>/knowledge`, `{n}` a number, `{sha}` and `{hex}` hex, `{rest}` anything
non-empty) and concrete instances. Importing this module checks it: every instance matches its own entry, every entry
has an instance, and no off-list path, with its method, matches an allowed entry (the `/user/login` defect of
S4-1's old list, C9). It holds no policy of the edge: `matches` only reads these patterns.
"""
from __future__ import annotations

import random
import re
import string
import urllib.parse
from dataclasses import dataclass

SHA = "0123456789abcdef0123456789abcdef01234567"
HEX = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
#: `{R}` in a template; every instance below is a template over these.
_FILL = {"n": "3", "sha": SHA, "hex": HEX}
_GROUPS = {
    "R": r"/t-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/knowledge",
    "n": "[0-9]+", "sha": "[0-9a-f]+", "hex": "[0-9a-f]+", "rest": ".+",
}
ALL_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH")


@dataclass(frozen=True)
class Entry:
    methods: tuple[str, ...]
    pattern: str
    instances: tuple[str, ...]

    def regex(self) -> re.Pattern[str]:
        parts = re.split(r"(\{[A-Za-z]+\})", self.pattern)
        return re.compile("".join(_GROUPS[p[1:-1]] if p.startswith("{") else re.escape(p) for p in parts))


GET, POST, BOTH = ("GET",), ("POST",), ("GET", "POST")

ENTRIES: tuple[Entry, ...] = (
    # Sign-in and sign-out
    Entry(GET, "/", ("/",)),
    Entry(GET, "/user/login", ("/user/login",)),
    Entry(GET, "/user/oauth2/product", ("/user/oauth2/product",)),
    Entry(GET, "/user/oauth2/product/callback", ("/user/oauth2/product/callback",)),
    Entry(POST, "/user/logout", ("/user/logout",)),
    Entry(GET, "/repo/search", ("/repo/search",)),
    # Assets
    Entry(GET, "/assets/{rest}", ("/assets/js/index.js", "/assets/css/index.css")),
    Entry(GET, "/favicon.ico", ("/favicon.ico",)),
    Entry(GET, "/avatars/{hex}", ("/avatars/{hex}",)),
    # Repository
    Entry(GET, "{R}", ("{R}",)),
    Entry(GET, "{R}/src/{rest}", ("{R}/src/branch/main", "{R}/src/branch/main/agent/skills/a.md")),
    Entry(GET, "{R}/raw/{rest}", ("{R}/raw/branch/main/agent/skills/a.md",)),
    Entry(GET, "{R}/blame/{rest}", ("{R}/blame/branch/main/a.md",)),
    Entry(GET, "{R}/commits/{rest}", ("{R}/commits/branch/main",)),
    Entry(GET, "{R}/commit/{sha}", ("{R}/commit/{sha}",)),
    Entry(GET, "{R}/branches/list", ("{R}/branches/list",)),
    Entry(GET, "{R}/media/{rest}", ("{R}/media/branch/main/a.png",)),
    Entry(GET, "{R}/blob_excerpt/{sha}", ("{R}/blob_excerpt/{sha}",)),
    # Pull requests
    Entry(GET, "{R}/pulls", ("{R}/pulls",)),
    Entry(GET, "{R}/pulls/{n}", ("{R}/pulls/{n}",)),
    Entry(GET, "{R}/pulls/{n}/commits", ("{R}/pulls/{n}/commits",)),
    Entry(GET, "{R}/pulls/{n}/files", ("{R}/pulls/{n}/files",)),
    Entry(GET, "{R}/pulls/{n}/files/reviews/new_comment", ("{R}/pulls/{n}/files/reviews/new_comment",)),
    Entry(POST, "{R}/pulls/{n}/files/reviews/comments", ("{R}/pulls/{n}/files/reviews/comments",)),
    Entry(POST, "{R}/pulls/{n}/files/reviews/submit", ("{R}/pulls/{n}/files/reviews/submit",)),
    Entry(POST, "{R}/pulls/{n}/merge", ("{R}/pulls/{n}/merge",)),
    Entry(GET, "{R}/issues/{n}/content-history/overview", ("{R}/issues/{n}/content-history/overview",)),
    Entry(POST, "/-/fetch-redirect", ("/-/fetch-redirect",)),
    # Editor
    Entry(BOTH, "{R}/_edit/{rest}", ("{R}/_edit/main/a.md",)),
    Entry(BOTH, "{R}/_new/{rest}", ("{R}/_new/main/",)),
    Entry(BOTH, "{R}/_delete/{rest}", ("{R}/_delete/main/a.md",)),
    Entry(POST, "{R}/_preview/{rest}", ("{R}/_preview/main/a.md",)),
    Entry(POST, "{R}/markup", ("{R}/markup",)),
    Entry(BOTH, "{R}/compare/{rest}", ("{R}/compare/main...feature",)),
    # Issues
    Entry(GET, "{R}/issues", ("{R}/issues",)),
    Entry(GET, "{R}/issues/{n}", ("{R}/issues/{n}",)),
    Entry(GET, "{R}/issues/suggestions", ("{R}/issues/suggestions",)),
    Entry(POST, "{R}/issues/{n}/comments", ("{R}/issues/{n}/comments",)),
)

#: The sign-in start: the one path whose Cookie header the edge drops (P25, P26).
SIGNIN_START = "/user/oauth2/product"
#: Another tenant's repository path: `{R}` is the shape, Forgejo's own rules decide who may read it.
OTHER_R = "/t-0a0a0a0a-1b1b-4c1c-8d1d-2e2e2e2e2e2e/knowledge"
_R_PLACEHOLDER = "/t-4f1c7a52-3b9d-4c3e-8a21-5d0e9b7c1a66/knowledge"


def render(template: str, repo: str) -> str:
    out = template.replace("{R}", repo)
    for key, value in _FILL.items():
        out = out.replace("{" + key + "}", value)
    return out


def allowed(repo: str) -> list[tuple[str, str]]:
    """Every (method, path) the design allows, for every instance of every entry, with `{R}` as `repo`."""
    return [(m, render(i, repo)) for e in ENTRIES for i in e.instances for m in e.methods]


def wrong_method(repo: str) -> list[tuple[str, str]]:
    """Every instance with each method its entry does not give it: "a path listed without a method allows GET only"."""
    return [(m, render(i, repo)) for e in ENTRIES for i in e.instances[:1] for m in ALL_METHODS if m not in e.methods]


def matches(method: str, path: str) -> bool:
    """Whether the design's list allows (`method`, `path`) as written (no decoding: the refused-before-matching classes
    are off the list by their own rule)."""
    return any(method in e.methods and e.regex().fullmatch(path) for e in ENTRIES)


#: Off the list, by name, and the classes refused before matching. `{R}` is a repository's path.
OFF_LIST: dict[str, list[tuple[str, str]]] = {
    "git transport without a suffix": [
        ("GET", "{R}/info/refs?service=git-upload-pack"), ("POST", "{R}/git-upload-pack"),
        ("POST", "{R}/git-receive-pack"), ("GET", "{R}/HEAD"), ("GET", "{R}/objects/info/packs"), ("GET", "{R}/hooks")],
    "git transport with .git": [
        ("GET", "{R}.git"), ("GET", "{R}.git/info/refs?service=git-upload-pack"), ("POST", "{R}.git/git-upload-pack"),
        ("POST", "{R}.git/git-receive-pack")],
    "dot segments": [
        ("GET", "{R}/src/../../../user/settings"), ("GET", "/assets/../user/settings"), ("GET", "/./user/login"),
        ("GET", "{R}/src/branch/main/.."), ("GET", "/assets/%2e%2e/user/settings"), ("GET", "/assets/.%2e/user/settings"),
        ("GET", "/assets/%2E%2E/user/settings"), ("GET", "/user/./settings"), ("GET", "/user/oauth2/product/../../settings")],
    "encoded slashes": [
        ("GET", "/user%2flogin"), ("GET", "/user%2Flogin"), ("GET", "{R}/src/branch/main/a%2fb"),
        ("GET", "{R}%2fsettings"), ("GET", "/assets/js%2f..%2f..%2fuser/settings")],
    "doubled slashes": [
        ("GET", "//user/login"), ("GET", "{R}//src"), ("GET", "/assets//x.js"), ("GET", "//"), ("GET", "///"),
        ("GET", "/t-x//knowledge"), ("GET", "{R}//settings")],
    "case variants of a fixed segment": [
        ("GET", "/User/Login"), ("GET", "/USER/LOGIN"), ("GET", "/API/v1/version"), ("GET", "/Api/V1/Version"),
        ("GET", "/user/Settings"), ("GET", "/Explore/repos"), ("GET", "/User/Settings"), ("GET", "/USER/SETTINGS")],
    "a reserved first segment where a repository is expected": [
        ("GET", "/user/knowledge"), ("GET", "/api/knowledge/src/branch/main"), ("GET", "/explore/knowledge"),
        ("GET", "/-/knowledge"), ("GET", "/admin/knowledge"), ("GET", "/t-not-a-uuid/knowledge"),
        ("GET", "{Rother}"), ("GET", "{R}x"), ("GET", "{R}-other/src/branch/main")],
    "the API": [
        ("GET", "/api/v1/version"), ("GET", "/api/v1/user"), ("POST", "/api/v1/repos/migrate"), ("GET", "/api/healthz"),
        ("GET", "/api/swagger"), ("GET", "/api/v1/repos{R}"), ("DELETE", "/api/v1/user")],
    "the user's settings": [
        ("GET", "/user/settings"), ("GET", "/user/settings/applications"), ("GET", "/user/settings/security"),
        ("POST", "/user/settings/applications")],
    "account linking": [
        ("GET", "/user/link_account"), ("POST", "/user/link_account_signin"), ("GET", "/user/link_account_signup"),
        ("GET", "/user/link_account/x")],
    "administration": [("GET", "/-/admin"), ("GET", "/-/admin/users"), ("POST", "/-/admin/users/new")],
    "explore": [("GET", "/explore"), ("GET", "/explore/repos"), ("GET", "/explore/users")],
    "the repository's settings": [
        ("GET", "{R}/settings"), ("GET", "{R}/settings/hooks"), ("POST", "{R}/settings/collaboration"),
        ("POST", "{R}/settings/delete")],
    "other pages off the list": [
        ("GET", "/user/events"), ("GET", "/notifications"), ("GET", "/notifications/new"), ("GET", "/login/oauth/authorize"),
        ("POST", "/login/oauth/access_token"), ("GET", "/org/create"), ("GET", "/repo/create"), ("GET", "/repo/migrate"),
        ("GET", "/user/sign_up"), ("GET", "/user/forgot_password")],
}

#: The classes the edge refuses before matching (design "Edge"): a `{rest}` pattern would otherwise read them as a match.
REFUSED_BEFORE_MATCHING = ("dot segments", "encoded slashes", "doubled slashes")

#: Off-list paths Forgejo itself answers (not 404) to a signed-in member asked on its private address: the control that
#: a 404 at the edge is the edge's refusal and not Forgejo's. Plain paths: no dot-segment or encoding, so asking
#: Forgejo directly needs no rewrite.
FORGEJO_SERVES: tuple[str, ...] = ("/user/settings", "/api/v1/version")


def off_list(repo: str) -> dict[str, list[tuple[str, str]]]:
    return {why: [(m, t.replace("{Rother}", repo[:-len("knowledge")] + "other").replace("{R}", repo)) for m, t in cases]
            for why, cases in OFF_LIST.items()}


# --- generated requests (S3-11's mutations of the list) ----------------------------------------------------------------

#: Every method a generated request is sent with: the five above, the three a browser or a scanner adds, and a token of
#: its own (`random_method`), so no method outside the list's is assumed refused.
MUTATION_METHODS = (*ALL_METHODS, "HEAD", "OPTIONS", "TRACE")
#: A placeholder's value outside its group: not a number, not lower-case hex, empty where `.+` needs something.
_OUTSIDE = {"n": ("x", "3a", "-3", "%33"), "sha": ("0123z", "ABCDEF0123", "g" * 40), "hex": ("0a1g", "0A1B2C", "xyz")}
#: A dot-segment in every spelling: `.`/`..`, each dot as `.`, `%2e` or `%2E`.
DOT_SEGMENTS = tuple(a + b for a in ("", ".", "%2e", "%2E") for b in (".", "%2e", "%2E")) + (".", "%2e", "%2E")
_SUFFIXES = (".diff", ".patch", "/new", ".git", "/", ".json")


def random_method(rng: random.Random) -> str:
    return "".join(rng.choice(string.ascii_uppercase) for _ in range(rng.randint(3, 9)))


def has_dot_segment(path: str) -> bool:
    """Whether the path (before any query), once each segment is percent-decoded, holds a `.` or `..` segment."""
    return any(urllib.parse.unquote(seg) in (".", "..") for seg in path.split("?", 1)[0].split("/"))


def refused_first(path: str) -> bool:
    """The design's classes refused before matching, in the path (before any query): a dot-segment, an encoded slash,
    or two slashes in a row."""
    head = path.split("?", 1)[0]
    return has_dot_segment(head) or "//" in head or "%2f" in head.lower()


def _flips(segment: str) -> list[str]:
    variants = {segment.swapcase(), segment[:1].swapcase() + segment[1:], segment.upper()}
    return sorted(v for v in variants if v != segment)


def mutations(repo: str, rng: random.Random) -> list[tuple[str, str]]:
    """`(why, path)` for paths made from each entry's instances by one change: a placeholder given a value outside its
    group (an upper-case `{R}` uuid included), one literal segment's case flipped (`Knowledge`), a suffix on the last
    segment, or one segment replaced by a dot-segment in every spelling. Whether each is allowed is `matches`' call."""
    out: list[tuple[str, str]] = []
    first = repo.split("/")[1]
    upper_uuids = ("/t-" + first[2:].upper() + "/knowledge", "/" + first.upper() + "/knowledge")
    for entry in ENTRIES:
        for template in entry.instances:
            base = render(template, repo)
            for key, values in _OUTSIDE.items():
                if "{" + key + "}" in template:
                    out += [(f"{{{key}}} outside its group", render(template.replace("{" + key + "}", v), repo))
                            for v in values]
            if "{R}" in template:
                out += [("{R} with an upper-case uuid", render(template, upper)) for upper in upper_uuids]
            segments = base.split("/")
            for i in range(1, len(segments)):
                for flipped in _flips(segments[i]):
                    out.append(("a segment's case flipped", "/".join([*segments[:i], flipped, *segments[i + 1:]])))
            out += [("a suffix on the last segment", base + suffix) for suffix in _SUFFIXES]
            for spelling in DOT_SEGMENTS:
                if len(segments) > 1 and base != "/":
                    i = rng.randrange(1, len(segments))
                    out.append(("a dot-segment", "/".join([*segments[:i], spelling, *segments[i + 1:]])))
                    j = rng.randrange(1, len(segments) + 1)
                    out.append(("a dot-segment", "/".join([*segments[:j], spelling, *segments[j:]])))
                else:
                    out.append(("a dot-segment", "/" + spelling))
    return out


def _check() -> None:
    for entry in ENTRIES:
        assert entry.instances, f"an allowlist entry with no instance: {entry}"
        for instance in entry.instances:
            path = render(instance, _R_PLACEHOLDER)
            assert entry.regex().fullmatch(path), f"{path} is not matched by its own entry {entry.pattern}"
    for method, path in allowed(_R_PLACEHOLDER):
        assert matches(method, path)
    exact = set(allowed(_R_PLACEHOLDER))
    for why, cases in off_list(_R_PLACEHOLDER).items():
        for method, path in cases:
            assert (method, path) not in exact, f"off-list ({why}) {method} {path} is an allowed instance"
            if why not in REFUSED_BEFORE_MATCHING:  # these read as a match to a pattern's `{rest}`: the edge refuses them first
                assert not matches(method, path), f"off-list ({why}) {method} {path} matches an allowed entry"
    for path in FORGEJO_SERVES:
        assert not matches("GET", path), path


_check()
