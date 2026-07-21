# The git seam: `defender/_git.py` + the `Forge` port

**Status:** design — implemented. Resolves #460 (the low-level git
subprocess is reinvented ~8× and `evals/` carries a second worktree manager).
Mirrors the namespace-root hoists `defender/_io.py` (#447) and
`defender/_env.py` / `_clock.py` (#448); extends the author/curator git
consolidation of #330; adopts the inject→real-tmp-repo testing philosophy of
#389. The failure disposition composes with `defender/docs/error-disposition-types-design.md`
(#438 → #441 → #443, #468): a git failure is a `StageAbort`-class systemic fault.

## What this is

The learning loop shells out to `git` in roughly a dozen places, and the
"run a git argv, check the return code, return stripped stdout" primitive is
hand-rolled at each one. On top of that there are **three** `git status
--porcelain` parsers and **two** worktree managers (`author/branch.py` and
`evals/_generation.py`). This doc defines one shared git seam:

- **`defender/_git.py`** — a direct-imported, pure-`subprocess`, git-*semantic*
  facade (not a bag of argv), raising one `GitError`. Tested against real tmp
  git repos, like `author/shared.py` already is.
- **A `Forge` port** — the `gh`/PR provider, the *one* injected seam, behind a
  small protocol with a `GhForge` adapter.

The dividing principle: **inject across a boundary you can't exercise for real
in a hermetic test (the forge); direct-import the local, deterministic tools you
can (git, fs, env).** git is the latter; `gh` is the former.

## Design

### `_git.py` is a semantic facade, not a `subprocess` wrapper

It exposes git verbs that return parsed Python values, with a low-level escape
hatch for one-offs:

```python
def git(args, *, cwd=REPO_ROOT, check=True) -> str        # escape hatch (log/show, the orchestrate scrub)
def git_status(cwd, *, pathspec=None) -> list[tuple[str, str]]   # the single -z porcelain reader
def git_head_sha(cwd) -> str
def git_rev_list_count(cwd, *, grep=None, rev_range=None) -> int
def git_worktree_add(cwd, path, ref, *, branch=None, detach=False) -> None
def git_worktree_remove(cwd, path, *, force=True) -> None
def git_worktree_prune(cwd) -> None
```

Domain logic *composes* these and stays in its own module — the facade holds
generic git, not corpus knowledge:

- `actor_generation_count` → `git_rev_list_count(grep="^Actor-Model:") + 1`
- `changes_outside` → a filter over `git_status(...)`
- `commit_corpus` → stage + a pathspec-scoped commit-with-trailers helper

The module lives at the `defender.` namespace root (no `__init__.py`, PEP 420 —
the `_frontmatter` precedent, #322/#323) so `learning/`, `scripts/`, `runtime/`,
and `evals/` import it flat (`from defender._git import git_status`) without a
layering inversion or `sys.path` dance.

### One `-z` status reader; one set of worktree helpers

`git_status` standardizes on `git status --porcelain --untracked-files=all -z`,
returning `[(XY, path)]` records. This is a **correctness upgrade**, not just a
move: today's `changes_outside` parses non-`-z` output and mishandles spaced
paths. The three call shapes reduce to it — `changes_outside` filters the
records, the boolean predicate `corpus_dir_clean` becomes `bool(git_status(...))`,
and `path_validation._porcelain_records` *is* it.

The worktree helpers cover both existing managers with one signature:
`author/branch.py`'s branch worktree (`-B <branch> ... origin/main`) via
`branch=`, and `evals/_generation.py`'s detached worktree (`--detach <sha>`) via
`detach=`. `evals/`'s second manager collapses onto them.

### git is direct-imported; only the forge is injected

`author/branch.py` injects `git` *and* `gh` today, but its git injection is
near-dead (only a fake-`CompletedProcess` lease test references it, and a "Real
git" test already exists alongside), while `author/shared.py` and
`evals/_harness_util.init_git` already test against real tmp repos (#389). git is
local, free, deterministic, and *higher-fidelity tested* against real git than
against a fake runner (a fake re-encodes assumptions about git's output — exactly
the porcelain-parsing bug class). So:

- **git → direct import.** `branch.py` drops its git injection and routes through
  `_git.py`; its remaining fake-runner assertions migrate to the real-tmp-repo
  style already present in `learning/test_loop.py`.
- **`gh` → injected `Forge` port.** A protocol (`open_pr`, `list_open_prs`) with a
  `GhForge` adapter, injected into `AuthorBranch`. This is the genuine
  provider-swap boundary (GitHub today, GitLab/Gitea conceivable) and the only
  seam that can't be exercised hermetically.

`BranchError` survives as the **lifecycle-level union** spanning git *and* forge
failures in the worktree/PR path; a `GitError` surfacing inside `AuthorBranch`'s
lifecycle methods is wrapped to `BranchError` so its callers see one type and the
existing catches are unchanged.

### Error model: two tiers, split by operation class

**Unexpected subprocess failure → `GitError(RuntimeError)`**, carrying argv + rc +
stderr. Layer-neutral, loud-by-default — the `FatalConfigError(ValueError)`
shape exactly. The disposition lives at the catch site, not in `_git.py`.

**Deliberate precondition checks keep their domain error.** Validated states — a
dirty corpus (`assert_clean_corpus_dir` → the envelope's `return 2`), a lesson missing
from `origin/main` before a revert (`BranchError`) — are semantic guards, not subprocess
failures; they keep raising `AuthorError` / `BranchError` with their existing
messages.

The disposition for a `GitError`, **split by which operation failed** (not by
brittle, locale-bound stderr parsing):

| Operation | Class | Disposition |
|---|---|---|
| `status`, `rev-parse`, `rev-list`, `add`, `commit`, `diff`, `worktree add/remove` | local-state → **systemic** | `GitError` **enrolled alongside `StageAbort`/`FatalConfigError`** → **exit 2, loud** |
| `push`, `fetch`, `gh pr create` | remote/forge → plausibly transient | the **existing** `BranchError` catch-and-skip in `_run_worktree_batch` (`orchestrate.py:774,786`) — left untouched |

A local-state git failure means a broken tree/repo/config/disk — it dooms the
*whole batch*, not one marker, so it is a `StageAbort`-class systemic fault
(`defender/docs/error-disposition-types-design.md`). `GitError` is **enrolled alongside**
`StageAbort` in `_run_or_dead_letter`'s reraise tuple (`orchestrate.py:507`) and
the `:1090` catch — not subclassed under it, because (like `FatalConfigError`,
#468) the exit-2 *response* is learning-only while the *condition* is layer-neutral.

Net change from today: the local-state sites go from *crash with a bare
`CalledProcessError`* (uncaught traceback) → *clean contracted exit 2* (defined
code, supervisor-friendly, queue intact). The remote/forge retry lane is left
exactly as it is — the only plausibly-transient operations.

### Why fail-fast is safe: the queue is the durable origin

Failing loud is correct here precisely because **no work is lost when a batch
fails.** The worktree author/lead-author drains run `hold_committed=True`
(`curator.py:348`): even *successfully committed* findings stay in `_pending`
(stripped of the consumed stamp) until the PR actually merges — they rotate to
`consumed.jsonl` only once a merged PR filters them via `existing_*_ids`. So a
`GitError` at any point leaves the pending queue intact (a pre-commit failure
runs no rotation; a post-commit/pre-push failure holds the rows).

The **following batch rebuilds from the queue, it does not resume the failed
commit.** Every batch fetches and branches off fresh `origin/main`
(`_BRANCH_BASE`, `branch.py:152-158`) on a new random-`uuid` branch; the failed
batch's worktree and commit are orphaned and `cleanup`'d, never a base. The next
eligible tick re-reads the *whole* pending set (the preserved findings **+** any
that accumulated since), re-folds it into the corpus at current `origin/main`,
and commits a pathspec-scoped delta against that latest merged state — deduped
against merged history by `existing_*_ids`, gated so two divergent PRs never race
(the per-prefix writer lease, `open_pr_exists`). The only cost of a failed batch
is re-authoring (LLM spend), never data.

This is also the argument for keeping the remote/forge retry lane *narrow*: under
sustained failure each tick re-authors a growing backlog, so a genuinely-stuck
**local** repo must surface for intervention (exit 2) rather than silently
re-grinding the queue every tick.

## Kept / dropped

**In scope.** `defender/_git.py` (the facade + `GitError`); the `Forge` port +
`GhForge` adapter; migrating every raw `subprocess.run([...git...])` site —
`author/shared.py`, `leads/path_validation.py`, `evals/_generation.py` +
`evals/_harness_util.py` + `evals/harness*.py`, `core/orchestrate.py`,
`scripts/visualize/visualize_runtime.py`, `run.py` — onto the seam; collapsing
the three porcelain parsers to one `-z` reader and the two worktree managers to
one; dropping `AuthorBranch`'s git injection (keeping the forge injection);
enrolling `GitError` as a systemic fault.

**Out of scope.** A git *library* (GitPython/pygit2/dulwich): it would still
shell out for most porcelain (`repo.git.*`), add the first non-`pyyaml` core
dependency against the deliberately-slim install, and mismatch the
trailer/pathspec/`-z` semantics — the module *is* the library, minus the
dependency. Reworking the existing remote/forge **retry** behavior in
`_run_worktree_batch` (it lumps deterministic "branch already on origin" with
transient network, but that is pre-existing and deliberate). A drain-wide
retry-cap / health signal for the transient lane.

## Notes / open questions

- **Rollout shape (decided).** Shipped as one PR (consistent with #447/#448),
  closed with the `lint_raw_git_subprocess` AST gate mirroring `lint_unsafe_jsonl_io`
  (baseline + `# lint-git: ok` suppression; the facade itself and test fixtures are
  exempt). `AuthorBranch` also gained a `repo_root` field (defaulting to the real
  root) so the dropped git injection didn't make its repo-level ops untestable — the
  #389 inject-the-root pattern, which lets the branch tests run real git against a tmp
  repo.
- **Transient-lane spin detection.** Sustained push/forge failure re-authors a
  growing backlog with no cap. Out of scope here; would close with a drain-wide
  retry-cap or health signal applied uniformly to all infra retries, not a git
  special-case.
