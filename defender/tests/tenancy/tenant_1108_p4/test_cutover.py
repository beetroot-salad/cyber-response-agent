"""#1108 P4 S-F — O14, lab continuity across the cutover.

O14: the lab repo's `agent/` equals the product content the P4 PR deletes, minus the retired
corpora (U5), by digest — `lessons`, `lessons-questioner`, system skills, queries, registry —
recorded on the PR; lab `main` is protected before merge (P4-C13); no legacy pending delivery,
queued item with a `defender/...` path, or open product-repo learning PR remains at merge;
`tenant.py update` runs before the first post-merge run.

Two kinds of test live here:

* CI-safe self-checks of the comparator and scanners this file uses, over tmp git repos and
  tmp state folders (they pass now: they prove the checks can fail, nothing about the lab).
* `live`/manual checks run BY HAND at cutover, against the real lab clone and the product
  repo. The digest check prints the record to paste on the PR (run with `-s`). They are a
  procedure's gate, not CI.

    DEFENDER_LIVE_DATA_ROOT=/workspace/.defender-data DEFENDER_LIVE_TENANT=<lab id> \\
    DEFENDER_O14_PRODUCT_COMMIT=<the P4 PR's parent> PYTHONPATH="$PWD" \\
        flock /tmp/defender-pytest.lock defender/.venv/bin/python -m pytest -m live -s \\
        defender/tests/tenancy/tenant_1108_p4/test_cutover.py

Optional: DEFENDER_O14_LAB_REF (default `refs/remotes/origin/main` of the lab clone; fetch
first, e.g. with `tenant.py update`), DEFENDER_O14_LEGACY_STATE (default
`<main checkout>/defender/learning`), DEFENDER_O14_POST_MERGE=1 for the post-merge check.

Interpretations (reported to the orchestrator, not settled by the design):
* `skills/gather/queries/SCHEMA.md` is not lab content: O1 moves it to the product's
  `skills/gather/query-schema.md`, so it is not "deleted product content".
* The lab's `agent/.tenant-id` and an EMPTY `agent/.gitkeep` are not product content and are
  outside the comparison; anything else under the lab's `agent/` must be product content.
* A "`defender/...` path" in a queued item is a string naming a product corpus
  (`defender/lessons*`, `defender/skills/...`), repo-relative or absolute.
* "Product-repo learning PRs" are open GitHub PRs whose head starts `lessons/` or
  `lead-author/` (the legacy `AuthorBranch` prefixes at base 0f62791e).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from defender import _git
from defender._git import REPO_ROOT

#: O1's product allowlist: these skills stay in the product; every other `defender/skills/<x>/`
#: at the product commit is a system skill and moves to the lab.
KEPT_SKILLS = frozenset({"gather", "invlang", "handbook", "advisory", "connect"})
#: U5: deleted, not moved.
RETIRED = ("lessons-actor", "lessons-environment")
QUERIES = "skills/gather/queries"
QUERY_SCHEMA = f"{QUERIES}/SCHEMA.md"
REGISTRY = "skills/tacit-knowledge/registry.yaml"
CATEGORIES = ("lessons", "lessons-questioner", "system skills", "queries", "registry")
LEARNING_PR_PREFIXES = ("lessons/", "lead-author/")
#: The learning state folders (the `.gitignore`d ones under `defender/learning/` at base).
STATE_FOLDERS = ("_pending", "_pending_leads", "_pending_pitfalls", "_pending_delivery",
                 "author-queue", "learn-queue")
_PRODUCT_CORPUS_PATH = re.compile(
    r"(^|/)defender/(lessons|lessons-questioner|lessons-actor|lessons-environment|skills)(/|$)")


# ---------------------------------------------------------------------------------------------
# The comparator (both sides read from git objects, never a working tree)
# ---------------------------------------------------------------------------------------------

class NotRegular(AssertionError):
    pass


def _tree(repo: Path, rev: str, prefix: str) -> dict[str, str]:
    """`{path below prefix: sha256 of the blob}` for every entry under `prefix` at `rev`. Any
    entry that is not a regular file (a symlink, a submodule) refuses: the comparison is of
    content, and such an entry has none to compare."""
    listing = _git.git_bytes(["ls-tree", "-r", "-z", "--full-tree", rev, "--", prefix],  # lint-oracle: ok — the cutover check reads two repos' trees by hand; it is not the oracle of a production reader
                             cwd=repo)
    records = _git.tree_records(listing, errors="strict")
    odd = [(mode, path) for mode, kind, _oid, path in records
           if kind != "blob" or mode not in ("100644", "100755")]
    if odd:
        raise NotRegular(f"{repo}@{rev}: entries that are not regular files: {odd}")
    if not records:
        return {}
    args = ["cat-file", "--batch"]
    oids = [oid for _m, _k, oid, _p in records]
    out = _git.git_bytes(args, cwd=repo, input="".join(o + "\n" for o in oids).encode())
    blobs = _git.blob_batch(args, out, oids)
    base = prefix.rstrip("/") + "/"
    return {path[len(base):]: hashlib.sha256(blob).hexdigest()
            for (_m, _k, _o, path), blob in zip(records, blobs, strict=True)}


def _skill_names(repo: Path, commit: str) -> list[str]:
    out = _git.git_bytes(["ls-tree", "-z", "--full-tree", commit, "--", "defender/skills/"], cwd=repo)
    return sorted(Path(path).name for _m, kind, _o, path in _git.tree_records(out, errors="strict")
                  if kind == "tree")


def product_content(repo: Path, commit: str) -> dict[str, str]:
    """What the lab's `agent/` must hold, from the product tree at `commit`: `lessons/`,
    `lessons-questioner/`, every system skill (`skills/<x>/`, `x` not kept by O1), the query
    catalog minus `SCHEMA.md`. Retired corpora are simply not taken."""
    want: dict[str, str] = {}
    for corpus in ("lessons", "lessons-questioner"):
        want.update({f"{corpus}/{p}": d for p, d in _tree(repo, commit, f"defender/{corpus}").items()})
    for system in _skill_names(repo, commit):
        if system not in KEPT_SKILLS:
            want.update({f"skills/{system}/{p}": d
                         for p, d in _tree(repo, commit, f"defender/skills/{system}").items()})
    want.update({f"{QUERIES}/{p}": d for p, d in _tree(repo, commit, f"defender/{QUERIES}").items()})
    want.pop(QUERY_SCHEMA, None)
    return want


def lab_content(repo: Path, rev: str) -> dict[str, str]:
    """Everything under the lab's `agent/` at `rev` except the tenant marker and an empty
    placeholder."""
    have = _tree(repo, rev, "agent")
    have.pop(".tenant-id", None)
    if have.get(".gitkeep") == hashlib.sha256(b"").hexdigest():
        have.pop(".gitkeep")
    return have


def _category(path: str) -> str:
    if path == REGISTRY:
        return "registry"
    if path.startswith(QUERIES + "/"):
        return "queries"
    if path.startswith("skills/"):
        return "system skills"
    return path.split("/", 1)[0]


def differences(want: dict[str, str], have: dict[str, str]) -> dict[str, list[str]]:
    return {
        "missing from the lab": sorted(want.keys() - have.keys()),
        "not product content": sorted(have.keys() - want.keys()),
        "different bytes": sorted(p for p in want.keys() & have.keys() if want[p] != have[p]),
    }


def digest_record(content: dict[str, str]) -> dict[str, str]:
    """Per category (and in total): sha256 over its sorted `path NUL sha256 LF` lines, with
    the file count — the record pasted on the PR."""
    lines: dict[str, list[str]] = {c: [] for c in (*CATEGORIES, "total")}
    for path in sorted(content):
        line = f"{path}\0{content[path]}\n"
        lines[_category(path)].append(line)
        lines["total"].append(line)
    return {c: f"{hashlib.sha256(''.join(v).encode()).hexdigest()} ({len(v)} files)"
            for c, v in lines.items()}


# ---------------------------------------------------------------------------------------------
# Scanners for the pre-merge state
# ---------------------------------------------------------------------------------------------

def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def queued_corpus_paths(state_root: Path) -> list[tuple[str, str]]:
    """`(file, value)` for every string naming a product corpus in a queued item under
    `state_root`'s state folders (`.json` items and `.jsonl` rows; consumed history and logs
    excluded). A row that is not JSON is reported as unreadable rather than skipped."""
    found = []
    for folder in STATE_FOLDERS:
        base = state_root / folder
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.name.startswith("consumed") or path.suffix not in (".json", ".jsonl"):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            rows = text.splitlines() if path.suffix == ".jsonl" else [text]
            for row in rows:
                if not row.strip():
                    continue
                try:
                    value = json.loads(row)
                except ValueError:
                    found.append((str(path), "<unreadable row>"))
                    continue
                found += [(str(path), s) for s in _strings(value) if _PRODUCT_CORPUS_PATH.search(s)]
    return found


def pending_deliveries(state_root: Path) -> list[str]:
    base = state_root / "_pending_delivery"
    return sorted(str(p) for p in base.rglob("*") if p.is_file()) if base.is_dir() else []


def learning_prs(rows: list[dict]) -> list[dict]:
    return [r for r in rows if str(r.get("headRefName", "")).startswith(LEARNING_PR_PREFIXES)]


# ---------------------------------------------------------------------------------------------
# CI-safe self-checks: the comparator and scanners can fail
# ---------------------------------------------------------------------------------------------

def _repo(path: Path, files: dict[str, bytes], links: dict[str, str] | None = None) -> str:
    path.mkdir(parents=True)
    _git.git(["init", "-q", "-b", "main"], cwd=path)
    for rel, data in files.items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).write_bytes(data)
    for rel, target in (links or {}).items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).symlink_to(target)
    _git.git(["add", "-A"], cwd=path)
    _git.git(["-c", "user.name=F", "-c", "user.email=f@invalid", "commit", "-q", "-m", "x"], cwd=path)
    return _git.git(["rev-parse", "HEAD"], cwd=path)  # lint-oracle: ok — names the fixture commit just made


#: A product tree in miniature: every category, plus what must NOT move (retired corpora, a
#: kept skill, the query schema).
_PRODUCT = {
    "defender/lessons/a.md": b"lesson a\n",
    "defender/lessons/nested/b.md": b"lesson b\n",
    "defender/lessons-questioner/q.md": b"questioner\n",
    "defender/lessons-actor/x.md": b"retired\n",
    "defender/lessons-environment/y.md": b"retired\n",
    "defender/skills/cmdb/SKILL.md": b"cmdb skill\n",
    "defender/skills/tacit-knowledge/registry.yaml": b"entries: []\n",
    "defender/skills/gather/SKILL.md": b"kept\n",
    "defender/skills/connect/validate_scaffold.py": b"kept\n",
    "defender/skills/gather/queries/SCHEMA.md": b"schema\n",
    "defender/skills/gather/queries/cmdb/q.yaml": b"query\n",
}
_LAB = {
    "agent/.tenant-id": b"00000000-0000-4000-8000-000000000001\n",
    "agent/.gitkeep": b"",
    "agent/lessons/a.md": b"lesson a\n",
    "agent/lessons/nested/b.md": b"lesson b\n",
    "agent/lessons-questioner/q.md": b"questioner\n",
    "agent/skills/cmdb/SKILL.md": b"cmdb skill\n",
    "agent/skills/tacit-knowledge/registry.yaml": b"entries: []\n",
    "agent/skills/gather/queries/cmdb/q.yaml": b"query\n",
    "settings/alert-mapping.yaml": b"x: 1\n",
}


def _compare(tmp_path: Path, lab: dict[str, bytes], links: dict[str, str] | None = None):
    product = tmp_path / "product"
    commit = _repo(product, _PRODUCT)
    rev = _repo(tmp_path / "lab", lab, links)
    return differences(product_content(product, commit), lab_content(tmp_path / "lab", rev))


def test_o14_checker_finds_an_exact_import_equal_and_records_every_category(tmp_path):
    """Positive control for O14's comparator: a lab `agent/` holding exactly the moved content
    (plus `.tenant-id` and an empty `.gitkeep`, and its `settings/`) compares equal, and the
    record names each design category with a non-zero count."""
    product = tmp_path / "product"
    commit = _repo(product, _PRODUCT)
    want = product_content(product, commit)
    rev = _repo(tmp_path / "lab", _LAB)
    assert differences(want, lab_content(tmp_path / "lab", rev)) == {
        "missing from the lab": [], "not product content": [], "different bytes": []}
    record = digest_record(want)
    assert all(not record[c].endswith("(0 files)") for c in CATEGORIES), record


@pytest.mark.parametrize(("change", "key", "path"), [
    (lambda lab: lab.pop("agent/lessons/nested/b.md"), "missing from the lab", "lessons/nested/b.md"),
    (lambda lab: lab.update({"agent/skills/tacit-knowledge/registry.yaml": b"entries: [x]\n"}),
     "different bytes", REGISTRY),
    (lambda lab: lab.update({"agent/lessons-actor/x.md": b"retired\n"}),
     "not product content", "lessons-actor/x.md"),
    (lambda lab: lab.update({"agent/skills/gather/queries/SCHEMA.md": b"schema\n"}),
     "not product content", QUERY_SCHEMA),
    (lambda lab: lab.update({"agent/skills/gather/SKILL.md": b"kept\n"}),
     "not product content", "skills/gather/SKILL.md"),
    (lambda lab: lab.update({"agent/.gitkeep": b"not empty\n"}), "not product content", ".gitkeep"),
], ids=["lesson-missing", "registry-differs", "retired-corpus", "query-schema", "kept-skill",
        "non-empty-gitkeep"])
def test_o14_checker_names_each_departure_from_the_moved_content(tmp_path, change, key, path):
    """O14's comparator rejects a lab that misses a lesson, differs by one byte (registry),
    carries a retired corpus (U5), the query schema O1 keeps in the product, a kept skill, or a
    non-empty placeholder — each named under the right heading."""
    lab = dict(_LAB)
    change(lab)
    found = _compare(tmp_path, lab)
    assert path in found[key], found


def test_o14_checker_refuses_a_symlink_in_the_lab_agent_tree(tmp_path):
    """A symlink under the lab's `agent/` has no content to compare: refused, not skipped."""
    with pytest.raises(NotRegular):
        _compare(tmp_path, _LAB, links={"agent/lessons/link.md": "a.md"})


def test_o14_state_scanners_see_corpus_paths_pending_deliveries_and_learning_prs(tmp_path):
    """The pre-merge scanners can fail: a queued row naming `defender/lessons/x.md` (relative
    or absolute), a pending-delivery record and an open `lessons/` PR are each reported; a
    consumed row, a non-corpus path and a feature PR are not."""
    root = tmp_path / "learning"
    (root / "_pending").mkdir(parents=True)
    (root / "_pending" / "findings.jsonl").write_text(
        json.dumps({"target": "defender/lessons/x.md"}) + "\n"
        + json.dumps({"run_dir": "/data/runs/r1"}) + "\n", encoding="utf-8")
    (root / "_pending" / "consumed.jsonl").write_text(
        json.dumps({"target": "defender/lessons/old.md"}) + "\n", encoding="utf-8")
    (root / "author-queue").mkdir()
    (root / "author-queue" / "r2.json").write_text(
        json.dumps({"paths": ["/workspace/defender/skills/cmdb/SKILL.md"]}), encoding="utf-8")
    assert queued_corpus_paths(root) == [
        (str(root / "_pending" / "findings.jsonl"), "defender/lessons/x.md"),
        (str(root / "author-queue" / "r2.json"), "/workspace/defender/skills/cmdb/SKILL.md"),
    ]
    assert pending_deliveries(root) == []
    (root / "_pending_delivery" / "failed").mkdir(parents=True)
    (root / "_pending_delivery" / "failed" / "lessons-b1.json").write_text("{}", encoding="utf-8")
    assert pending_deliveries(root) == [str(root / "_pending_delivery" / "failed" / "lessons-b1.json")]
    rows = [{"number": 1, "headRefName": "lessons/b1"}, {"number": 2, "headRefName": "feat/x"},
            {"number": 3, "headRefName": "lead-author/b2"}]
    assert [r["number"] for r in learning_prs(rows)] == [1, 3]


# ---------------------------------------------------------------------------------------------
# Live / manual: the cutover gate
# ---------------------------------------------------------------------------------------------

def _lab_inputs():
    root, tenant_id = os.environ.get("DEFENDER_LIVE_DATA_ROOT"), os.environ.get("DEFENDER_LIVE_TENANT")
    if not (root and tenant_id):
        pytest.skip("set DEFENDER_LIVE_DATA_ROOT and DEFENDER_LIVE_TENANT (the lab tenant)")
    tenant_dir = Path(root) / tenant_id
    if not (tenant_dir / "knowledge").is_dir():
        pytest.skip(f"no lab clone at {tenant_dir / 'knowledge'}")
    return Path(root), tenant_id, tenant_dir


def _main_checkout() -> Path:
    common = _git.git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=REPO_ROOT)
    return Path(common).parent


@pytest.mark.live
def test_o14_lab_agent_equals_the_deleted_product_content_by_digest():
    """O14: the lab repo's `agent/` (at its `main`) equals the product content at the P4 PR's
    parent minus the retired corpora — lessons, lessons-questioner, system skills, queries,
    registry — by sha256 of every file, both directions. Prints the record for the PR."""
    _root, _tenant_id, tenant_dir = _lab_inputs()
    commit = os.environ.get("DEFENDER_O14_PRODUCT_COMMIT")
    if not commit:
        pytest.skip("set DEFENDER_O14_PRODUCT_COMMIT (the P4 PR's parent)")
    lab_ref = os.environ.get("DEFENDER_O14_LAB_REF", "refs/remotes/origin/main")
    clone = tenant_dir / "knowledge"
    want = product_content(REPO_ROOT, commit)
    have = lab_content(clone, lab_ref)
    lab_commit = _git.git(["rev-parse", lab_ref], cwd=clone)  # lint-oracle: ok — names the lab commit in the printed record
    print(f"\nO14 digest record — product {commit} vs lab {lab_commit} ({lab_ref})")
    for category, value in digest_record(want).items():
        print(f"  {category:20} {value}")
    assert differences(want, have) == {
        "missing from the lab": [], "not product content": [], "different bytes": []}
    assert not any(_tree(clone, lab_ref, f"agent/{r}") for r in RETIRED)


@pytest.mark.live
def test_o14_lab_main_is_publishable_for_the_lab_tenant_before_merge():
    """O14 ('`tenant.py update` runs before the first post-merge run') needs that publish to
    succeed: P3's publish refuses an `agent/.tenant-id` not naming the tenant and a clone whose
    `main` cannot fast-forward to `origin/main`. So before merge, the lab's `main` names the lab
    tenant and the clone holds no commit on `main` that the forge lacks. (Observed 2026-10-22:
    lab `origin/main` is 75b5e6a with `.tenant-id` = `playground`; the clone's `main` is 2
    commits ahead — the UUID migration c6cdf9f and 1784b0f were never delivered. Red.)"""
    _root, tenant_id, tenant_dir = _lab_inputs()
    clone = tenant_dir / "knowledge"
    marker = _git.git_tree_blobs(clone, "refs/remotes/origin/main", "agent/.tenant-id")
    assert marker == {"agent/.tenant-id": f"{tenant_id}\n".encode()}, marker
    ahead = _git.git(["rev-list", "refs/remotes/origin/main..refs/heads/main"], cwd=clone)
    assert ahead == "", f"the lab clone's main holds undelivered commits: {ahead.split()}"


@pytest.mark.live
def test_o14_lab_main_is_protected_before_merge_C13():
    """O14/P4-C13: lab `main` is protected against the bot before the P4 PR merges (the same
    check delivery makes; through the dev issuer). Red until the operator protects it."""
    from .test_live_dev_issuer import _forge, _lab, _login

    lab = _lab()
    _forge(lab, _login(lab)).verify_main_protection()


@pytest.mark.live
def test_o14_no_legacy_pending_delivery_or_queued_corpus_path_remains():
    """O14: at merge, neither the tenant's learning root nor the legacy product-tree learning
    state holds a pending delivery (failed ones included: they too are legacy deliveries no P4
    drain will pick up) or a queued item naming a `defender/...` corpus path. (Observed
    2026-10-22: no `<lab>/learning/`; the main checkout's `defender/learning/` holds 5
    author-queue items, 1 learn-queue item and `_pending` rows, none naming a corpus path, and
    no `_pending_delivery/`.)"""
    _root, _tenant_id, tenant_dir = _lab_inputs()
    legacy = Path(os.environ.get("DEFENDER_O14_LEGACY_STATE", _main_checkout() / "defender" / "learning"))
    roots = [tenant_dir / "learning", legacy]
    assert {r: pending_deliveries(r) for r in roots} == {r: [] for r in roots}
    assert {r: queued_corpus_paths(r) for r in roots} == {r: [] for r in roots}


@pytest.mark.live
def test_o14_no_open_product_repo_learning_pr_remains():
    """O14: no open product-repo (GitHub) learning PR remains at merge."""
    if shutil.which("gh") is None:
        pytest.skip("needs the GitHub CLI")
    out = subprocess.run(["gh", "pr", "list", "--state", "open", "--limit", "1000",
                          "--json", "number,headRefName,url"],
                         cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, check=False)
    if out.returncode != 0:
        pytest.skip(f"gh cannot list PRs here: {out.stderr.strip()}")
    assert learning_prs(json.loads(out.stdout)) == []


@pytest.mark.live
def test_o14_after_merge_update_published_the_imported_main_before_any_run():
    """O14: after the P4 PR merges, `tenant.py update` (or the first launch) has published:
    the lab's `current` export is its `main` tip, and that commit's `agent/` still equals the
    moved content. Opt-in: DEFENDER_O14_POST_MERGE=1 (and DEFENDER_O14_PRODUCT_COMMIT)."""
    if os.environ.get("DEFENDER_O14_POST_MERGE") != "1":
        pytest.skip("post-merge check: set DEFENDER_O14_POST_MERGE=1")
    root, tenant_id, tenant_dir = _lab_inputs()
    commit = os.environ.get("DEFENDER_O14_PRODUCT_COMMIT")
    if not commit:
        pytest.skip("set DEFENDER_O14_PRODUCT_COMMIT (the P4 PR's parent)")
    from defender.learning.author.version_control import current_export
    from defender.tenancy._tenant import data_root_from_path, requested_tenant

    tenant = requested_tenant(data_root_from_path(root), tenant_id)
    clone = tenant_dir / "knowledge"
    published = current_export(tenant).commit
    assert published == _git.git(["rev-parse", "refs/remotes/origin/main"], cwd=clone)  # lint-oracle: ok — the fetched tip `update` must have published
    assert differences(product_content(REPO_ROOT, commit), lab_content(clone, published)) == {
        "missing from the lab": [], "not product content": [], "different bytes": []}
