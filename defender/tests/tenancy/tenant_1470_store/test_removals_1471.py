"""#1471 r8 W7, the removals: the operator's `--update-ticket`, the case record's comment template and the page's own
flag are gone from product code, and a census over every shipped file holds it. The census is defined by membership
(every file under `defender/` outside the tests, the archive, the migrations' history and the upgrade notes), not by
a list of files. The refusals of the operator's command line and of the case record's text are tested where they are
made (`tenancy/case_comment_1359/test_record_leg.py`, `test_case_record_1471.py`)."""
from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path


#: #1471's removed operator commands (switches), beside #1470's O10 list (`_records1470.REMOVED_COMMANDS`, which the
#: `tenant.py` tests run as subcommands: a switch is not one, so the list is its own).
REMOVED_1471 = frozenset({"--update-ticket"})

_DEFENDER = Path(__file__).resolve().parents[3]
_SHIPPED_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".txt", ".sh", ".toml", ".json"}
_UPGRADE_NOTES = "## Upgrade from before"
#: Where the request flag lives (C-1, C-3, C-4: the API, the store and worker, the helper and its job). The flag's own
#: name `update_ticket` is allowed there; nowhere else in code, because the operator's plumbing was the only other place.
_REQUEST_FLAG_ZONES = ("api/", "api_server/", "jobs/", "job_host/", "job_socket/", "worker/", "migrations/")
#: The history of the schema names what it dropped: not shipped behaviour.
_HISTORY = "migrations/versions/"

_REMOVED_SWITCH = re.compile("|".join(re.escape(s) for s in sorted(REMOVED_1471)))
#: An identifier, not a substring: the escalation and unreadable sentences keep `*_comment_body` names.
_COMMENT_BODY = re.compile(r"(?<![A-Za-z0-9_])comment_body(?![A-Za-z0-9_])")
_COMMENT_DOT_BODY = re.compile(r"(?<![A-Za-z0-9_])comment\.body(?![A-Za-z0-9_])")
_FLAG_NAME = re.compile(r"(?<![A-Za-z0-9])update_ticket(?![A-Za-z0-9_])")


def _shipped() -> list[tuple[str, list[str]]]:
    """Each shipped file as (path relative to `defender/`, its lines), less the sections an `## Upgrade from before`
    heading opens (the one place a removed command may be named)."""
    found = []
    for path in sorted(_DEFENDER.rglob("*")):
        rel = path.relative_to(_DEFENDER).as_posix()
        if (not path.is_file() or path.is_symlink() or path.suffix not in _SHIPPED_SUFFIXES or rel.startswith("tests/")
                or rel.startswith("docs/archive/") or rel.startswith(_HISTORY)
                or any(part in {".venv", "__pycache__", "node_modules"} for part in path.parts)):
            continue
        kept, in_notes = [], False
        for line in path.read_text("utf-8", errors="replace").splitlines():
            if line.startswith("## "):
                in_notes = line.startswith(_UPGRADE_NOTES)
            if not in_notes:
                kept.append(line)
        found.append((rel, kept))
    return found


def _prose_and_strings(rel: str, lines: list[str]) -> list[str]:
    """What a reader of the file reads as text: a non-Python file whole; a Python file's string constants and
    comments, never its code (`comment.body` as an attribute read is a different thing from the template's name)."""
    source = "\n".join(lines)
    if not rel.endswith(".py"):
        return [source]
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [source]
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    comments = [t.string for t in tokenize.generate_tokens(io.StringIO(source).readline) if t.type == tokenize.COMMENT]
    return [*strings, *comments]


def _in_request_flag_zone(rel: str) -> bool:
    return rel.startswith(_REQUEST_FLAG_ZONES)


def _hits(files: list[tuple[str, list[str]]]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"switch": [], "comment_body": [], "comment.body": [], "update_ticket": []}
    for rel, lines in files:
        whole = "\n".join(lines)
        if _REMOVED_SWITCH.search(whole):
            found["switch"].append(rel)
        if _COMMENT_BODY.search(whole):
            found["comment_body"].append(rel)
        if any(_COMMENT_DOT_BODY.search(text) for text in _prose_and_strings(rel, lines)):
            found["comment.body"].append(rel)
        if rel.endswith(".py") and not _in_request_flag_zone(rel) and _FLAG_NAME.search(whole):
            found["update_ticket"].append(rel)
    return found


def test_1471_w7_the_census_patterns_find_what_was_removed_and_not_what_stays():
    """Control for the census: each pattern finds the removed name in the forms shipped text uses it and not the names
    that stay. (W7)"""
    zone = [("run.py", ["p.add_argument('--update-ticket')"]), ("jobs/x.py", ["--update-ticket"])]
    assert _hits(zone)["switch"] == ["run.py", "jobs/x.py"], "the switch is banned in every zone"
    stays = [("a.py", ["def escalation_comment_body(x): pass", "unreadable_comment_body()", "_comment_body = 1",  # lint-stale-ref: ok — census string
                       "body = comment.body", "# post with --post-ticket"]),
             ("b.md", ["the request flag `update_ticket`, and --post-ticket"])]
    assert not any(_hits(stays).values()), _hits(stays)
    assert _hits([("c.py", ["x = comment_body"])])["comment_body"] == ["c.py"]
    assert _hits([("c.md", ["the `comment_body` field"])])["comment_body"] == ["c.md"]
    assert _hits([("c.py", ["'''the comment.body template'''"])])["comment.body"] == ["c.py"]
    assert _hits([("c.py", ["x = 1  # a comment.body"])])["comment.body"] == ["c.py"]
    assert _hits([("c.md", ["`comment.body` is gone"])])["comment.body"] == ["c.md"]
    assert _hits([("run.py", ["update_ticket=ns.update_ticket"])])["update_ticket"] == ["run.py"]
    assert _hits([("presentation/v.py", ["def f(*, update_ticket=False): ..."])])["update_ticket"] == ["presentation/v.py"]
    assert _hits([("jobs/store.py", ["update_ticket=True"]), ("api/models.py", ["update_ticket: bool"])])[
        "update_ticket"] == [], "the request flag's own names are allowed where the request flag lives"


def test_1471_w7_the_census_reads_every_shipped_file_the_skills_and_docs_too_and_skips_the_upgrade_notes():
    """The scan is over membership: the product tree (code, skills, docs), not the tests, the archive, the schema's
    history or an upgrade section. (W7)"""
    files = _shipped()
    names = {rel for rel, _ in files}
    assert len(names) > 200, "premise: the scan reads the shipped tree"  # noqa: PLR2004
    assert {"skills", "docs", "presentation", "tenancy", "jobs", "api"} <= {rel.split("/")[0] for rel in names}
    assert "run.py" in names
    assert not [rel for rel in names if rel.startswith(("tests/", _HISTORY, "docs/archive/"))]
    notes = _DEFENDER / "CLAUDE.md"
    assert any("## Upgrade from before" in line for line in notes.read_text("utf-8").splitlines()), "premise: notes exist"
    kept = "\n".join(dict(files)["CLAUDE.md"])
    assert "defender_proxy_reader" not in kept, "a section under an upgrade heading is skipped"
    assert "defender_proxy_reader" in notes.read_text("utf-8"), "premise: the skipped section holds text"


def test_1471_w7_no_shipped_file_has_the_operators_switch_the_comment_template_or_operator_flag_plumbing():
    """A census over product code finds no `--update-ticket`, no `comment_body`, no `comment.body` in strings or prose,
    and no `update_ticket` in code outside the request flag's own zones. (W7)"""
    found = _hits(_shipped())
    assert found == {"switch": [], "comment_body": [], "comment.body": [], "update_ticket": []}, found
