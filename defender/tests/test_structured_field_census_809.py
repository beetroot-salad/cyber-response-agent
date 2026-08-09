"""Regression pin for #809 — the corpus stops teaching gather to re-derive a parsed field.

In run `reviewer-measure-0807-b`, lead l-004 spent a 28,232-character thinking block (104s)
hand-rolling a GROK pattern to pull `user.name` / `source.ip` / the auth method out of
`message` — fields the Filebeat integration had already extracted onto the index as their own
typed columns. It was doing what the corpus taught it: `skills/gather/SKILL.md` named "OpenSSH
auth method in `message`" as THE worked example of a field that lives in text, and three
elastic templates repeated the idiom. `sshd-auth-history.md` went further and asserted
outright that "auth method is not a structured field" — in a file whose next bullet said
structured fields ARE populated here.

The ground truth is the payload: `gather_raw/l-003/7.json` came back with `user.name` (keyword),
`source.ip` (ip), `source.port` (long), `event.outcome` (keyword), `system.auth.ssh.event`
(keyword) and `system.auth.ssh.method` (keyword) as columns of the ES|QL result.

This is deliberately a NARROW pin over those named fields, not a general "don't parse
`message`" detector. A lexical detector was measured against all 37 recorded `*.lead.json` in
`.defender-runs/` during #809's design and came back under 50% precise — 18 of 34 hits were
dotted service-account names (`svc.config-mgmt`, `dev.dana`), not field paths. A check that
mostly cries wolf gets suppressed, and then it holds nothing. Parsing `message` for a value
that genuinely lives only in text stays correct, so the three sites that do it are named here
with their reason rather than pattern-matched around.
"""
from __future__ import annotations

import re
from pathlib import Path

from defender._corpus import iter_query_templates

_DEFENDER = Path(__file__).resolve().parents[1]
_CATALOG = _DEFENDER / "skills" / "gather" / "queries"
_GATHER_SKILL = _DEFENDER / "skills" / "gather" / "SKILL.md"

# Populated, typed fields on `logs-system.auth-*` — verified against the `columns` of the
# ES|QL payload cited above. Deriving any of these out of `message` is the defect.
STRUCTURED_AUTH_FIELDS = (
    "user.name",
    "source.ip",
    "source.port",
    "event.outcome",
    "system.auth.ssh.event",
    "system.auth.ssh.method",
)

# The same fields as an author names them in prose. Both of the sites that described the field
# in English rather than spelling it — the gather SKILL's "OpenSSH auth method in `message`"
# and `sshd-auth-event-by-id`'s "user identity extracted from `message`" — are invisible
# without these, and those two are the ones that actually taught l-004.
STRUCTURED_AUTH_FIELDS_IN_PROSE = (
    "auth method",
    "authentication method",
    "user identity",
    "user name",
    "username",
    "source ip",
    "source port",
    "auth outcome",
)

# Text-only by nature — no integration parses these onto the index, so `LIKE`/`GROK` over
# `message` is the correct and only route. Keyed by path suffix, valued by the reason.
LEGITIMATE_MESSAGE_PARSERS = {
    "elastic/sshd-session-lifecycle.md": "session opened/closed carry no ECS field",
    "elastic/keycloak-auth-events.md": 'Keycloak type="LOGIN" tokens are key=value text',
    "elastic/syslog-ip-search.md": "a raw text scan across syslog, by design",
}

# `CASE(message LIKE ...)` / `GROK message` / "extracted from `message`" within a few lines of
# one of the structured field names is the shape that taught l-004 to hand-roll the parse.
_DERIVES_FROM_MESSAGE = re.compile(
    r"(?:CASE\s*\(\s*message\s+LIKE|GROK\s+message|"
    r"(?:extracted|parsed|derive[sd]?)\s+(?:back\s+)?(?:out\s+of|from)\s+`?message`?)",
    re.IGNORECASE,
)


_BULLET_RE = re.compile(r"\s*[-*]\s")


def _blocks(text: str) -> list[list[str]]:
    """Contiguous runs of lines — one wrapped markdown bullet, one paragraph, one fenced
    query body. A blank line or the start of a new bullet ends the run.

    The unit matters: a naive ±N-line window reaches across bullet boundaries and reads
    `sudo-commands.md`'s legitimate `GROK message "…COMMAND=…"` together with the *next*
    bullet's unrelated mention of `user.name`, reporting a defect that isn't there.
    """
    blocks: list[list[str]] = []
    cur: list[str] = []
    for line in text.splitlines():
        if not line.strip() or (_BULLET_RE.match(line) and cur):
            if cur:
                blocks.append(cur)
            cur = []
        if line.strip():
            cur.append(line)
    if cur:
        blocks.append(cur)
    return blocks


def _offending_lines(text: str) -> list[str]:
    """Blocks that derive a value from `message` while naming a field that is already parsed.

    Both halves must be present in the SAME block: `sshd-session-lifecycle`'s
    `message LIKE "*session opened*"` names no structured field and is not a finding, while a
    bare mention of `user.name` is a filter, not a derivation.
    """
    hits = []
    for block in _blocks(text):
        joined = " ".join(block)
        if not _DERIVES_FROM_MESSAGE.search(joined):
            continue
        names_a_parsed_field = any(f in joined for f in STRUCTURED_AUTH_FIELDS) or any(
            a in joined.lower() for a in STRUCTURED_AUTH_FIELDS_IN_PROSE
        )
        if names_a_parsed_field:
            hits.append(next(ln.strip() for ln in block if _DERIVES_FROM_MESSAGE.search(ln)))
    return hits


def test_gather_skill_does_not_teach_re_deriving_a_parsed_field():
    """The SKILL's own worked example was the root teacher — it named OpenSSH auth method as
    the canonical field-that-lives-in-text, which is exactly the field the index carries as
    `system.auth.ssh.method`."""
    offenders = _offending_lines(_GATHER_SKILL.read_text(encoding="utf-8"))
    assert not offenders, (
        f"{_GATHER_SKILL.name} teaches deriving an already-structured auth field out of "
        f"`message`: {offenders}"
    )


def test_no_auth_template_re_derives_a_parsed_field():
    """The catalog is walked through `_corpus.iter_query_templates` — the one corpus walk
    (#585) — rather than a hand-rolled glob, so a template added under `_draft/` is covered
    the moment it lands."""
    offenders = {}
    for tpl in iter_query_templates(_CATALOG):
        rel = f"{tpl.path.parent.name}/{tpl.path.name}"
        if rel in LEGITIMATE_MESSAGE_PARSERS:
            continue
        hits = _offending_lines(tpl.body)
        if hits:
            offenders[rel] = hits
    assert not offenders, (
        "query templates re-derive fields the integration already parsed onto the index "
        f"({', '.join(STRUCTURED_AUTH_FIELDS)}): {offenders}"
    )


def test_the_allowlisted_parsers_still_parse_message():
    """A positive control: the exemptions above are exemptions, not dead entries. If one of
    these templates stops parsing `message` the allowlist should shrink, and if it is renamed
    or deleted the suffix key silently stops matching — either way the census above quietly
    widens without anyone noticing. This test is what notices."""
    by_rel = {
        f"{t.path.parent.name}/{t.path.name}": t for t in iter_query_templates(_CATALOG)
    }
    for rel, reason in LEGITIMATE_MESSAGE_PARSERS.items():
        assert rel in by_rel, f"allowlisted template {rel} no longer exists ({reason})"
        assert "message" in by_rel[rel].body, (
            f"{rel} no longer parses `message` — drop it from LEGITIMATE_MESSAGE_PARSERS "
            f"({reason})"
        )


def test_the_pin_fires_on_the_text_it_was_written_against():
    """A check that cannot fail holds nothing. These four snippets are the corpus verbatim at
    `origin/main` before this issue — the exact prose that taught l-004 to hand-roll a GROK —
    and each must be caught. Kept inline rather than read back out of git: the pin has to
    discriminate on its own terms, not on the repository's history being reachable."""
    corpus_before = {
        "gather/SKILL.md": (
            "- Express the whole measurement *in the query*: counts via `COUNT(*) WHERE ...`,\n"
            "  via `MIN`/`MAX`/`DATE_TRUNC`. If a dimension needs a field that lives in text\n"
            '  (e.g. OpenSSH auth method in `message`), derive it in-query (`CASE(message LIKE\n'
            "  ...)`, `GROK`), not in a post-hoc pass.\n"
        ),
        "sshd-auth-history.md (query)": (
            "| STATS accepted = COUNT(*) WHERE event.outcome == \"success\",\n"
            '        BY auth_method = CASE(message LIKE "*publickey*", "publickey",\n'
            '                              message LIKE "*password*",  "password", "other"),\n'
            "           source.ip, host.name\n"
        ),
        "sshd-auth-event-by-id.md": (
            "- user identity extracted from `message` field substring (e.g., "
            '"Accepted password for alice")\n'
            '- source IP extracted from `message` field substring (e.g., "from 10.1.2.3")\n'
        ),
        "doc-fetch-by-id.md": (
            "- For system.auth events: `host.name`, `@timestamp`, `source.ip`, and auth "
            "outcome + target user extracted from `message` (OpenSSH syslog format)\n"
        ),
    }
    missed = [name for name, text in corpus_before.items() if not _offending_lines(text)]
    assert not missed, f"the pin no longer catches the defect it was written for: {missed}"


def test_the_pin_spares_a_legitimate_message_parse():
    """The other half of discrimination. `sudo`'s `COMMAND=` genuinely lives only in the audit
    line, and the bullet after it happens to mention `user.name` — a ±2-line window read the
    two together and reported a defect that wasn't there. Block scoping is what fixed it, and
    this is the case that proves it stays fixed."""
    sudo_before = (
        "- **The command is not a structured field.** The raw sudo\n"
        "  audit line is `... sudo: <user> : ... COMMAND=/path/to/cmd`. To surface the\n"
        '  commands, `GROK message "%{DATA}COMMAND=%{DATA:command}$"` and `STATS … BY command`.\n'
        "- **`user.name` can be null/empty** on `pam_unix(sudo:auth)` failure lines (the\n"
        "  user wasn't identified) — those rows aggregate under a null `user.name`.\n"
    )
    assert not _offending_lines(sudo_before)


def test_sshd_auth_history_reads_the_structured_auth_method():
    """The site this issue was filed against. `sshd-auth-history` is the one wide/superset
    template every auth-history lead binds, so its `## Query` body is the idiom that
    propagates — gather copies it verbatim."""
    tpl = next(t for t in iter_query_templates(_CATALOG) if t.id == "elastic.sshd-auth-history")
    assert "system.auth.ssh.method" in tpl.query, (
        "sshd-auth-history must group by the structured auth-method field"
    )
    assert "publickey" not in tpl.query, (
        "sshd-auth-history still CASEs the auth method out of `message`"
    )
