#!/usr/bin/env python3
"""Minimal lead-author driver: fold lessons from one defender run into
the executed-side query template catalog at
``defender/skills/gather/queries/``.

Per ``defender/CLAUDE.md``, defender is an experimental PoC; this
driver carries the minimum discipline needed for safe interleaving
with the gap-side authors (`author.py`, `author_actor.py`) and nothing
more. No Tier-1 gate, no streaming JSON parse, no result marker — git
is the source of truth.

Lifecycle, per tick:

  1. Acquire the per-author queue lock
     (``defender/learning/_pending_leads/.lock``). Non-blocking; another
     in-flight tick ⇒ return 0 silently.
  2. Acquire the shared repo lock
     (``defender/learning/_author.lock``) via ``_author_shared``.
     Blocking with timeout — same discipline as ``author.py``.
  3. Preflight brakes (in order):
       a. ``<run_dir>/lead_author/failure.txt`` ⇒ a prior tick aborted
          mid-stream; refuse to retry until a human clears it.
       b. ``<run_dir>/lead_author/done`` ⇒ already processed.
  4. Capture ``base_sha`` + ``baseline_status``. Refuse to author if the
     catalog itself is already dirty (uncommitted file under
     ``defender/skills/gather/queries/``).
  5. Extract ``ExecutedLead`` records from ``<run_dir>/lead_sequence.yaml``.
  6. Build per-lead handoff blocks (top-k neighbors via
     ``lead_neighbors.top_k_neighbors``).
  7. Spawn ``claude -p`` with a narrow allowlist. Stdout/stderr → log.
     Non-zero exit ⇒ write ``failure.txt`` and return rc=2, even if a
     valid catalog commit was made; the next tick refuses to retry
     until a human clears ``failure.txt``.
  8. Post-flight scope check: at most one commit; that commit's paths
     all under the catalog; no newly-dirty paths outside the catalog;
     no-commit runs must end clean. Violations ⇒ write ``violation.txt``,
     return rc=2. **No auto-reset** — destructive.
  9. Optional push (``LEAD_AUTHOR_PUSH=1``). Refuses ``origin/main`` /
     ``origin/master`` under any circumstance. Push failure ⇒ logged,
     manual retry required.
 10. Write ``<run_dir>/lead_author/done`` sentinel.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fcntl
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

try:
    from defender.learning import (
        _author_shared,
        lead_classifier,
        lead_neighbors,
        lead_render,
    )
except ImportError:  # pragma: no cover — direct-script execution fallback
    import _author_shared  # type: ignore[no-redef]
    import lead_classifier  # type: ignore[no-redef]
    import lead_neighbors  # type: ignore[no-redef]
    import lead_render  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
CATALOG_DIR = REPO_ROOT / "defender" / "skills" / "gather" / "queries"
CATALOG_REL = "defender/skills/gather/queries/"
PENDING_DIR = LEARNING_DIR / "_pending_leads"
QUEUE_LOCK_FILE = PENDING_DIR / ".lock"
RUN_LOG_FILE = PENDING_DIR / "lead_author_run.log"
LEAD_AUTHOR_PROMPT = LEARNING_DIR / "lead_author.md"

LEAD_AUTHOR_MODEL = os.environ.get("LEAD_AUTHOR_MODEL", "claude-sonnet-4-6")
LEAD_AUTHOR_TIMEOUT = int(os.environ.get("LEAD_AUTHOR_TIMEOUT_SECONDS", "1800"))


# ---------------------------------------------------------------------------
# Lead extraction (inlined from PR-209's lead_extract.py)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutedLead:
    position: int
    query_index: int
    is_multi_query: bool          # parent entry had >1 query
    entry_index: int              # index into the raw entries list
    query_id: str
    params: dict[str, Any]
    goal_text: str
    what_to_characterize: tuple[str, ...]
    result_ref: Path              # this invocation's payload file
    sidecar_path: Path            # this invocation's .observations.json


_VALID_PAYLOAD_STATUSES = frozenset(
    {"ok", "empty", "suspect_empty", "error", "partial"}
)


def _result_ref_for(run_dir: Path, position: int, query_index: int, is_multi: bool) -> Path:
    """Canonical payload path for one invocation.

    Single-query lead → ``gather_raw/{position}.json``.
    Multi-query lead  → ``gather_raw/{position}{a..z}.json`` by index.
    """
    raw_dir = run_dir / "gather_raw"
    if is_multi:
        suffix = chr(ord("a") + query_index)
        return raw_dir / f"{position}{suffix}.json"
    return raw_dir / f"{position}.json"


def _sidecar_for(result_ref: Path) -> Path:
    """``foo.json`` → ``foo.observations.json`` (same dir, same stem)."""
    return result_ref.with_name(result_ref.stem + ".observations.json")


def _load_entries(run_dir: Path) -> list[dict]:
    seq_path = run_dir / "lead_sequence.yaml"
    if not seq_path.is_file():
        raise FileNotFoundError(seq_path)
    doc = yaml.safe_load(seq_path.read_text())
    if not isinstance(doc, dict):
        raise ValueError(f"{seq_path}: top-level mapping required")
    entries = doc.get("entries") or []
    if not isinstance(entries, list):
        raise ValueError(f"{seq_path}: entries must be a list")
    return entries


def extract(run_dir: Path) -> list[ExecutedLead]:
    """Read ``lead_sequence.yaml`` and emit one ExecutedLead per query.

    Invocations whose canonical payload file is missing are dropped
    silently (the dispatch never landed or the projection is stale).
    Observation sidecars are *not* checked here — that happens in
    ``build_handoff``, where a missing sidecar is a hard error.
    """
    entries = _load_entries(run_dir)
    out: list[ExecutedLead] = []
    for entry_idx, raw_entry in enumerate(entries):
        if not isinstance(raw_entry, dict):
            continue
        position = raw_entry.get("position")
        if not isinstance(position, int):
            continue
        lead_desc = raw_entry.get("lead_description") or {}
        goal = lead_desc.get("goal") or ""
        wtc_raw = lead_desc.get("what_to_characterize") or []
        wtc = tuple(str(x) for x in wtc_raw if isinstance(x, (str, int)))

        queries = raw_entry.get("queries") or []
        if not isinstance(queries, list) or not queries:
            continue
        is_multi = len(queries) > 1

        for q_idx, q in enumerate(queries):
            if not isinstance(q, dict):
                continue
            result_ref = _result_ref_for(run_dir, position, q_idx, is_multi)
            if not result_ref.is_file():
                continue
            query_id = q.get("id") or ""
            params_raw = q.get("params") or {}
            params = dict(params_raw) if isinstance(params_raw, dict) else {}
            out.append(
                ExecutedLead(
                    position=position,
                    query_index=q_idx,
                    is_multi_query=is_multi,
                    entry_index=entry_idx,
                    query_id=query_id,
                    params=params,
                    goal_text=goal,
                    what_to_characterize=wtc,
                    result_ref=result_ref,
                    sidecar_path=_sidecar_for(result_ref),
                )
            )
    return out


# ---------------------------------------------------------------------------
# Driver primitives
# ---------------------------------------------------------------------------


class LeadAuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort."""


def _log(msg: str) -> None:
    print(f"[lead-author] {msg}", file=sys.stderr, flush=True)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def acquire_queue_lock() -> Any:
    """Non-blocking acquire of the per-author queue lock.

    Returns the open file handle on success, ``None`` if another tick
    holds it.
    """
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    _log(f"acquire queue-lock={QUEUE_LOCK_FILE}")
    fh = QUEUE_LOCK_FILE.open("a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        _log("queue-lock held by another tick — skipping")
        return None
    _log("queue-lock acquired")
    return fh


def release_queue_lock(fh: Any) -> None:
    if fh is None:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()
    _log("release queue-lock")


# ---------------------------------------------------------------------------
# Git helpers — porcelain v1 -z parsing
# ---------------------------------------------------------------------------


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=check,
    )


def _parse_status_z(blob: str) -> set[tuple[str, str]]:
    """Parse ``git status --porcelain=v1 -z`` into ``{(XY, path)}``.

    Porcelain v1 record format: ``XY <space> path`` where ``XY`` is
    exactly two characters (one for staged status, one for working-tree
    status — either can be space). With ``-z``, records are separated
    by NUL bytes. Rename/copy entries use TWO NUL-terminated records:
    the destination path first, then the source path. We key on the
    destination (the post-rename name) because that's the one a
    baseline-vs-post diff cares about.
    """
    out: set[tuple[str, str]] = set()
    parts = blob.split("\0")
    i = 0
    while i < len(parts):
        rec = parts[i]
        if not rec or len(rec) < 3:
            i += 1
            continue
        xy = rec[:2]
        path = rec[3:] if rec[2] == " " else rec[2:]
        if xy[0] in ("R", "C"):
            i += 2  # consume source record
        else:
            i += 1
        out.add((xy, path))
    return out


def _diff_name_only_z(base_sha: str, head_sha: str) -> list[str]:
    proc = _git("diff", "--name-only", "-z", f"{base_sha}..{head_sha}")
    return [p for p in proc.stdout.split("\0") if p]


def _diff_name_status_z(base_sha: str, head_sha: str) -> list[tuple[str, list[str]]]:
    """Parse ``git diff --name-status -z`` into ``[(code, [paths])]``.

    Status codes: ``M``/``A``/``D``/``T`` carry one path each; ``R<score>``
    and ``C<score>`` carry two (source then destination). With ``-z``
    each field is NUL-separated.
    """
    proc = _git("diff", "--name-status", "-z", f"{base_sha}..{head_sha}")
    parts = [p for p in proc.stdout.split("\0") if p]
    out: list[tuple[str, list[str]]] = []
    i = 0
    while i < len(parts):
        code = parts[i]
        i += 1
        if code[:1] in ("R", "C"):
            if i + 1 >= len(parts):
                break
            out.append((code, [parts[i], parts[i + 1]]))
            i += 2
        else:
            if i >= len(parts):
                break
            out.append((code, [parts[i]]))
            i += 1
    return out


def _under_draft(path: str) -> bool:
    """True if ``path`` lies under any ``{system}/_draft/`` subdirectory."""
    if not path.startswith(CATALOG_REL):
        return False
    rest = path[len(CATALOG_REL):]
    parts = rest.split("/")
    return len(parts) >= 3 and parts[1] == "_draft"


def _git_head() -> str:
    return _git("rev-parse", "HEAD").stdout.strip()


def _git_rev_list_count(base_sha: str) -> int:
    return int(_git("rev-list", "--count", f"{base_sha}..HEAD").stdout.strip())


def _git_status_records() -> set[tuple[str, str]]:
    proc = _git("status", "--porcelain=v1", "-z", "--untracked-files=all")
    return _parse_status_z(proc.stdout)


# ---------------------------------------------------------------------------
# Handoff construction
# ---------------------------------------------------------------------------


def _read_sidecar(sidecar_path: Path) -> dict[str, str]:
    """Read ``gather_raw/{position}.observations.json`` for one invocation.

    Missing or malformed sidecars are a gather-prompt regression — the
    loop refuses to author against a run that lacks the loud-failure
    signal, rather than silently masking it.
    """
    if not sidecar_path.is_file():
        raise LeadAuthorError(
            f"missing observation sidecar: {sidecar_path} "
            "(gather must write a sidecar per dispatch — see "
            "defender/skills/gather/SKILL.md §Return)"
        )
    try:
        data = json.loads(sidecar_path.read_text())
    except json.JSONDecodeError as e:
        raise LeadAuthorError(f"{sidecar_path}: invalid JSON ({e})") from e
    if not isinstance(data, dict):
        raise LeadAuthorError(f"{sidecar_path}: top-level mapping required")
    status = data.get("payload_status")
    if status not in _VALID_PAYLOAD_STATUSES:
        raise LeadAuthorError(
            f"{sidecar_path}: payload_status must be one of "
            f"{sorted(_VALID_PAYLOAD_STATUSES)}, got {status!r}"
        )
    digest = str(data.get("payload_digest") or "")
    return {"payload_status": status, "payload_digest": digest[:200]}


def build_handoff(
    run_dir: Path, executed: list[ExecutedLead]
) -> list[dict]:
    """Build per-*template* handoff blocks for the agent prompt.

    One handoff per ``executed_template_path``, even when the same
    template was touched multiple times in this run — the invocations
    list collapses what would otherwise be three sequential edit
    cycles on the same file into one decision.

    Leads whose ``query_id`` doesn't resolve in the catalog are dropped
    with a corpus-health warning. Per ``defender/CLAUDE.md`` every id
    is supposed to resolve at lead-author time; a miss is a runtime
    contract violation worth surfacing in the log but not worth taking
    the catalog out for.
    """
    catalog = lead_neighbors.load_catalog()
    by_id = {t.id: t for t in catalog}
    idf = lead_neighbors.build_idf(lead_neighbors._all_query_variants(catalog))
    entries = _load_entries(run_dir)
    template_path_by_id = {
        tid: str(tpl.path.relative_to(REPO_ROOT))
        for tid, tpl in by_id.items()
    }

    # Group invocations by the executed template path. Preserve
    # first-seen order so the handoff stream is deterministic.
    grouped: dict[Path, list[ExecutedLead]] = {}
    seen_order: list[Path] = []
    for lead in executed:
        tpl = by_id.get(lead.query_id)
        if tpl is None:
            _log(
                f"WARN unresolved query_id={lead.query_id!r} at position "
                f"{lead.position} (runtime contract violation; dropping invocation)"
            )
            continue
        if tpl.path not in grouped:
            grouped[tpl.path] = []
            seen_order.append(tpl.path)
        grouped[tpl.path].append(lead)

    handoffs: list[dict] = []
    for tpl_path in seen_order:
        invocations_raw = grouped[tpl_path]
        tpl = by_id[invocations_raw[0].query_id]
        neighbors = lead_neighbors.top_k_neighbors(
            tpl.id, catalog, idf=idf, k=3,
        )
        invocations: list[dict] = []
        for lead in invocations_raw:
            entry = entries[lead.entry_index] if lead.entry_index < len(entries) else {}
            sidecar = _read_sidecar(lead.sidecar_path)
            query = (entry.get("queries") or [])[lead.query_index] \
                if isinstance(entry.get("queries"), list) else {}
            composite_kind = lead_classifier.infer_composite_kind(
                entry, query, entries,
            )
            co_dispatched = lead_classifier.co_dispatched_template_paths(
                entry, lead.query_index, template_path_by_id,
            )
            try:
                rendered_query = lead_render.render_query(tpl.path, lead.params)
            except OSError as e:
                _log(f"WARN render_query failed for {tpl.path}: {e}")
                rendered_query = ""
            invocations.append(
                {
                    "position": lead.position,
                    "query_index": lead.query_index,
                    "goal_text": lead.goal_text,
                    "what_to_characterize": list(lead.what_to_characterize),
                    "params": dict(lead.params),
                    "rendered_query": rendered_query,
                    "payload_status": sidecar["payload_status"],
                    "payload_digest": sidecar["payload_digest"],
                    "result_refs": [str(lead.result_ref.relative_to(run_dir))],
                    "composite_kind": composite_kind,
                    "co_dispatched_with": co_dispatched,
                }
            )
        handoffs.append(
            {
                "executed_template_path": str(tpl.path.relative_to(REPO_ROOT)),
                "query_id": tpl.id,
                "status": tpl.status,
                "neighbors": [
                    {
                        "template_path": str(n.template_path.relative_to(REPO_ROOT)),
                        "score": n.score,
                    }
                    for n in neighbors
                ],
                "invocations": invocations,
            }
        )
    return handoffs


# ---------------------------------------------------------------------------
# Agent invocation
# ---------------------------------------------------------------------------


_ALLOWLIST = (
    "Read,Glob,Grep,"
    f"Edit({CATALOG_REL}**),"
    f"Write({CATALOG_REL}**),"
    f"Bash(git add {CATALOG_REL}:*),"
    "Bash(git mv:*),"
    "Bash(git rm:*),"
    "Bash(git commit:*),"
    "Bash(git status:*),"
    "Bash(git diff:*)"
)


def invoke_agent(run_dir: Path, handoffs: list[dict]) -> int:
    """Spawn ``claude -p`` with the lead-author prompt. Returns rc."""
    user_prompt = (
        f"run_dir: {run_dir}\n"
        f"catalog_dir: {CATALOG_REL}\n"
        f"handoffs ({len(handoffs)}):\n"
        f"{json.dumps(handoffs, indent=2)}\n"
    )
    cmd = [
        "claude",
        "-p",
        "--system-prompt-file", str(LEAD_AUTHOR_PROMPT),
        "--model", LEAD_AUTHOR_MODEL,
        "--allowed-tools", _ALLOWLIST,
    ]
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    _log(f"spawn claude (model={LEAD_AUTHOR_MODEL}, timeout={LEAD_AUTHOR_TIMEOUT}s)")
    try:
        proc = subprocess.run(
            cmd,
            input=user_prompt,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=LEAD_AUTHOR_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        with RUN_LOG_FILE.open("a") as f:
            f.write(f"[{_now_iso()}] TIMEOUT after {LEAD_AUTHOR_TIMEOUT}s\n")
            f.write(f"stderr-tail: {(e.stderr or '')[-2000:] if isinstance(e.stderr, str) else ''}\n")
        _log(f"claude timed out after {LEAD_AUTHOR_TIMEOUT}s")
        return 124
    with RUN_LOG_FILE.open("a") as f:
        f.write(f"[{_now_iso()}] rc={proc.returncode}\n")
        f.write("---stdout---\n")
        f.write(proc.stdout)
        f.write("\n---stderr---\n")
        f.write(proc.stderr)
        f.write("\n")
    _log(f"claude exited rc={proc.returncode}")
    return proc.returncode


# ---------------------------------------------------------------------------
# Post-flight
# ---------------------------------------------------------------------------


def _is_catalog_path(p: str) -> bool:
    return p.startswith(CATALOG_REL)


def _dirty_established_paths(baseline: set[tuple[str, str]]) -> list[str]:
    """Catalog paths present in ``baseline`` that aren't under ``_draft/``."""
    return [p for _, p in baseline if _is_catalog_path(p) and not _under_draft(p)]


def verify_postflight(
    base_sha: str, baseline: set[tuple[str, str]]
) -> tuple[bool, str, dict]:
    """Check post-flight git state. Returns (ok, reason, details)."""
    head_sha = _git_head()
    fail = _check_base_sha_ancestor(base_sha, head_sha)
    if fail:
        return fail
    count = _git_rev_list_count(base_sha)
    if count > 1:
        return False, "more than one commit since base", {
            "rev_list_count": count, "head": head_sha,
        }
    diff_paths: list[str] = []
    if count == 1:
        diff_paths = _diff_name_only_z(base_sha, head_sha)
        fail = _check_commit_contents(base_sha, head_sha, count, diff_paths)
        if fail:
            return fail
    new_paths, fail = _check_post_status(baseline, count)
    if fail:
        return fail
    return True, "ok", {
        "rev_list_count": count,
        "head": head_sha,
        "diff_paths": diff_paths,
        "new_paths": new_paths,
    }


def _check_base_sha_ancestor(
    base_sha: str, head_sha: str,
) -> tuple[bool, str, dict] | None:
    # If base_sha isn't an ancestor of HEAD, the agent rewrote history
    # (`git commit --amend`, `git rebase`, `git reset`), a hard-rule
    # violation that would make rev-list / diff comparisons against
    # base_sha lie. `merge-base --is-ancestor` exits 0 when ancestor,
    # 1 when not, ≥2 on error.
    anc = _git("merge-base", "--is-ancestor", base_sha, head_sha, check=False)
    if anc.returncode == 1:
        return False, "base_sha is not an ancestor of HEAD (history rewritten)", {
            "base": base_sha, "head": head_sha,
        }
    if anc.returncode != 0:
        return False, "merge-base --is-ancestor failed", {
            "base": base_sha, "head": head_sha,
            "stderr": anc.stderr.strip(),
        }
    return None


def _check_commit_contents(
    base_sha: str, head_sha: str, count: int, diff_paths: list[str],
) -> tuple[bool, str, dict] | None:
    for path in diff_paths:
        if not _is_catalog_path(path):
            return False, "commit touches paths outside catalog", {
                "rev_list_count": count, "head": head_sha,
                "diff_paths": diff_paths,
            }
    # Deletions are only allowed for drafts. Renames may move a draft
    # to the system root (promotion) but not the reverse.
    for code, paths in _diff_name_status_z(base_sha, head_sha):
        if code == "D" and not _under_draft(paths[0]):
            return False, "commit deletes an established template", {
                "rev_list_count": count, "head": head_sha,
                "diff_paths": diff_paths,
                "deleted_path": paths[0],
            }
        if (code.startswith(("R", "C"))
                and _under_draft(paths[1]) and not _under_draft(paths[0])):
            return False, "commit demotes an established template to _draft", {
                "rev_list_count": count, "head": head_sha,
                "rename_src": paths[0],
                "rename_dst": paths[1],
            }
    return None


def _check_post_status(
    baseline: set[tuple[str, str]], count: int,
) -> tuple[list[str], tuple[bool, str, dict] | None]:
    post = _git_status_records()
    new_records = post - baseline
    new_paths = sorted({p for _, p in new_records})
    if count == 0:
        if new_records:
            return new_paths, (False, "no commit but new dirty/untracked records exist", {
                "new_paths": new_paths,
            })
        return new_paths, None
    for _, path in new_records:
        if _is_catalog_path(path):
            return new_paths, (False, "uncommitted catalog dirt alongside commit", {
                "new_paths": new_paths,
            })
        if path.startswith("defender/"):
            return new_paths, (False, "new dirt under defender/ outside catalog", {
                "new_paths": new_paths,
            })
    return new_paths, None


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------


_FORBIDDEN_UPSTREAMS = {"origin/main", "origin/master"}


def maybe_push(commit_made: bool) -> None:
    """Push to upstream if ``LEAD_AUTHOR_PUSH=1`` and the upstream is allowed."""
    if not commit_made:
        return
    if os.environ.get("LEAD_AUTHOR_PUSH") != "1":
        _log("push skipped (LEAD_AUTHOR_PUSH not set)")
        return
    try:
        proc = _git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}",
                    check=False)
    except subprocess.CalledProcessError:
        proc = subprocess.CompletedProcess([], 1, "", "")
    if proc.returncode != 0 or not proc.stdout.strip():
        _log("push skipped — no upstream configured")
        return
    upstream = proc.stdout.strip()
    if upstream in _FORBIDDEN_UPSTREAMS:
        _log(f"push REFUSED — upstream={upstream} (origin/main and origin/master are forbidden)")
        return
    _log(f"push upstream={upstream}")
    push = _git("push", check=False)
    if push.returncode != 0:
        _log(f"push FAILED rc={push.returncode}: {push.stderr.strip()} "
             "(manual retry required — done sentinel will block driver retries)")
    else:
        _log("push ok")


# ---------------------------------------------------------------------------
# Run dir state
# ---------------------------------------------------------------------------


def _state_dir(run_dir: Path) -> Path:
    return run_dir / "lead_author"


def _done_sentinel(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "done"


def _failure_marker(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "failure.txt"


def _violation_marker(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "violation.txt"


def _write_state(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run(run_dir: Path) -> int:
    if not run_dir.is_dir():
        _log(f"FATAL: run_dir not found: {run_dir}")
        return 2

    queue_lock = acquire_queue_lock()
    if queue_lock is None:
        return 0
    repo_lock = None
    try:
        _log(f"acquire repo-lock={_author_shared.REPO_LOCK_FILE}")
        try:
            repo_lock = _author_shared.acquire_repo_lock()
        except TimeoutError as e:
            _log(f"repo-lock unavailable: {e}; releasing queue-lock")
            return 0
        _log("repo-lock acquired")
        return _run_locked(run_dir)
    finally:
        _author_shared.release_repo_lock(repo_lock)
        _log("release repo-lock")
        release_queue_lock(queue_lock)


def _run_locked(run_dir: Path) -> int:
    # Preflight brakes — failure first, then done sentinel.
    if _failure_marker(run_dir).is_file():
        _log(f"FATAL preflight: {_failure_marker(run_dir)} present — human cleanup required")
        return 2
    if _done_sentinel(run_dir).is_file():
        _log("already processed (done sentinel exists) — nothing to do")
        return 0

    base_sha = _git_head()
    baseline = _git_status_records()
    # Refuse if the established catalog is already dirty. Untracked drafts
    # under {system}/_draft/ are the expected gather output that this
    # author is being run to process — they belong in the baseline.
    dirty_catalog = _dirty_established_paths(baseline)
    if dirty_catalog:
        _log(f"FATAL preflight: catalog dirty before authoring: {dirty_catalog}")
        return 2

    handoffs, rc = _prepare_handoffs(run_dir, base_sha)
    if rc is not None:
        return rc
    _log(f"built {len(handoffs)} handoff block(s); base_sha={base_sha[:12]}")

    rc = invoke_agent(run_dir, handoffs)
    if rc != 0:
        _write_state(
            _failure_marker(run_dir),
            f"claude exited rc={rc} at {_now_iso()}\n"
            f"see {RUN_LOG_FILE} for stdout/stderr\n"
            "Human action required: review the catalog state, either drop\n"
            "any questionable commit from HEAD or remove this failure.txt\n"
            "to opt in to a retry on the next tick.\n",
        )
        _log(f"FATAL: claude exited non-zero; wrote {_failure_marker(run_dir)}")
        return 2

    ok, reason, detail = verify_postflight(base_sha, baseline)
    if not ok:
        _write_state(
            _violation_marker(run_dir),
            f"reason: {reason}\nat: {_now_iso()}\ndetail: {json.dumps(detail, indent=2)}\n",
        )
        _log(f"FATAL post-flight: {reason}; wrote {_violation_marker(run_dir)}")
        return 2

    commit_made = detail["rev_list_count"] == 1
    maybe_push(commit_made)
    _write_state(
        _done_sentinel(run_dir),
        f"head_sha: {detail['head']}\nat: {_now_iso()}\ncommit_made: {commit_made}\n",
    )
    _log(f"done; commit_made={commit_made} head={detail['head'][:12]}")
    return 0


def _prepare_handoffs(
    run_dir: Path, base_sha: str,
) -> tuple[list, int | None]:
    """Extract leads + build handoffs. Returns (handoffs, early-rc).

    early-rc is None when work remains; an int rc when the caller should
    return immediately (FATAL extract, no executed leads, or no handoffs
    after dropping unresolved query_ids).
    """
    try:
        executed = extract(run_dir)
    except (FileNotFoundError, ValueError) as e:
        _log(f"FATAL: cannot extract leads: {e}")
        return [], 2
    if not executed:
        _log("no executed leads with on-disk payloads — nothing to do")
        return [], 0
    try:
        handoffs = build_handoff(run_dir, executed)
    except LeadAuthorError as e:
        _log(f"FATAL: cannot build handoffs: {e}")
        return [], 2
    if not handoffs:
        _log(
            f"all {len(executed)} extracted lead(s) had unresolved "
            "query_ids — nothing to do"
        )
        _write_state(
            _done_sentinel(run_dir),
            f"head_sha: {base_sha}\nat: {_now_iso()}\ncommit_made: False\n",
        )
        return [], 0
    return handoffs, None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_HELP_EPILOG = """\
Preconditions
  * ``defender/skills/gather/queries/`` must be git-clean.
  * No other lead-author tick may be running (per-author queue lock at
    defender/learning/_pending_leads/.lock).
  * No defender-side author tick may be running (shared repo lock at
    defender/learning/_author.lock).
  * ``<run_dir>/lead_sequence.yaml`` and ``<run_dir>/gather_raw/`` must
    exist (produced by defender/scripts/project_lead_sequence.py).

State files written under ``<run_dir>/lead_author/``
  done           sentinel on successful completion; makes the run a no-op.
  failure.txt    written when ``claude`` exits non-zero; preflight refuses
                 to retry until a human removes it.
  violation.txt  written when post-flight scope check fails.

Environment
  LEAD_AUTHOR_MODEL              claude model id (default claude-sonnet-4-6)
  LEAD_AUTHOR_TIMEOUT_SECONDS    spawn timeout (default 1800)
  LEAD_AUTHOR_PUSH=1             attempt to push the commit upstream
                                 (refuses origin/main / origin/master)
"""


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="lead_author",
        description="Fold lessons from one defender run into the executed-side "
                    "query template catalog.",
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("run_dir", type=Path,
                   help="defender run dir containing lead_sequence.yaml + gather_raw/")
    args = p.parse_args(argv)
    return run(args.run_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
