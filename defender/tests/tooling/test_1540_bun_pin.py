"""#1540 F6: every place that downloads a Bun release (CI workflow steps, dev images; found by search, not by a list)
pins the same version and the same sha256, and checks that sha on the downloaded file before unpacking it.

The check is a function over texts, so it also runs on a synthetic good input and on mutations of it: a check that
cannot fail would be vacuous. It reads the install the way a shell would: `${VAR}`/`$VAR`/`${{ env.VAR }}` are
replaced from the step's, job's and workflow's `env` (workflows) or the `ARG`/`ENV` defaults (Dockerfiles), so it does
not care what the variables are called. It does need: the release URL spelled out (`.../releases/download/bun-vX.Y.Z/`),
the sha256 as a literal hex in the verifying `sha256sum -c` line, and the download written to a named file (`-o`/`-O`).
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

import pytest
import yaml

from defender._git import REPO_ROOT

_DOWNLOAD = "oven-sh/bun/releases/download"
_VERSION = re.compile(r"/releases/download/bun-v(\d+\.\d+\.\d+)/")
_TARGET = re.compile(r"\s(?:-[A-Za-z]*[oO]|--output(?:-document)?)[ =](\S+)")
_SHA_LINE = re.compile(r"\b([0-9a-f]{64})\s+\*?(\S+)")
_VERIFY = re.compile(r"sha256sum\s+(?:-c|--check)\b|shasum\s+-a\s+256\s+(?:-c|--check)\b")


@dataclass
class Site:
    label: str
    version: str | None = None
    sha: str | None = None
    problems: list[str] = field(default_factory=list)


def _expand(text: str, env: Mapping[str, str]) -> str:
    def name(match: re.Match[str]) -> str:
        return str(env.get(match.group(1), match.group(0)))

    for pattern in (r"\$\{\{\s*env\.(\w+)\s*\}\}", r"\$\{(\w+)\}", r"\$(\w+)"):
        text = re.sub(pattern, name, text)
    return text


def _analyse(label: str, text: str) -> Site:
    site = Site(label)
    found = _VERSION.search(text)
    if found:
        site.version = found.group(1)
    else:
        site.problems.append("the release URL does not spell out `bun-vX.Y.Z`")
    target = _TARGET.search(text)
    if not target:
        site.problems.append("the download is not written to a named file (`-o FILE`)")
        return site
    path = target.group(1).strip("\"'")
    checks = [m for m in _SHA_LINE.finditer(text) if m.group(2).strip("\"'") == path]
    verify = _VERIFY.search(text)
    if not checks or not verify:
        site.problems.append(f"no sha256 check of {path}: need a literal sha256 line for it and `sha256sum -c`")
        return site
    site.sha = checks[0].group(1)
    unpack = re.search(r"\bunzip\b", text)
    if unpack and unpack.start() < verify.start():
        site.problems.append("the zip is unpacked before its sha256 is checked")
    return site


#: A `bun` command word in a shell text: not a path's last segment (`/usr/local/bin/bun`) or part of a name (`bun-v1`).
_BUN_COMMAND = re.compile(r"(?<![\w./-])bun(?=\s|$)", re.M)


def _instructions(text: str) -> list[str]:
    """A Dockerfile's instructions, continuation lines joined, comments dropped."""
    joined = re.sub(r"\\\r?\n", " ", "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#")))
    return [line.strip() for line in joined.splitlines() if line.strip()]


def _dockerfile_sites(label: str, text: str) -> list[Site]:
    env: dict[str, str] = {}
    sites = []
    stage = 0
    for instruction in _instructions(text):
        words = instruction.split(None, 1)
        if words[0] == "FROM":
            stage += 1
            env = {}
        if words[0] in {"ARG", "ENV"} and len(words) > 1:
            for pair in words[1].split():
                key, sep, value = pair.partition("=")
                if sep:
                    env[key] = value.strip("\"'")
        elif words[0] == "RUN" and _DOWNLOAD in _expand(instruction, env):
            sites.append(_analyse(f"{label}:stage{stage}", _expand(instruction, env)))
    return sites


def _dockerfile_runners(label: str, text: str) -> set[str]:
    """The stages of a Dockerfile whose `RUN` holds a `bun` command (the site's own `bun --version` included)."""
    stage, found = 0, set()
    for instruction in _instructions(text):
        words = instruction.split(None, 1)
        if words[0] == "FROM":
            stage += 1
        elif words[0] == "RUN" and len(words) > 1 and _BUN_COMMAND.search(words[1]):
            found.add(f"{label}:stage{stage}")
    return found


def _workflow_sites(label: str, text: str) -> list[Site]:
    workflow = yaml.safe_load(text) or {}
    sites = []
    for job_id, job in (workflow.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            env = {**(workflow.get("env") or {}), **(job.get("env") or {}), **(step.get("env") or {})}
            run = _expand(str(step.get("run", "")), {k: str(v) for k, v in env.items()})
            if _DOWNLOAD in run:
                sites.append(_analyse(f"{label}:{job_id}", run))
    return sites


def _workflow_runners(label: str, text: str) -> tuple[set[str], list[str]]:
    """The jobs of a workflow whose steps run a `bun` command, and each step that takes Bun from `setup-bun`."""
    workflow = yaml.safe_load(text) or {}
    runners, setups = set(), []
    for job_id, job in (workflow.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            if _BUN_COMMAND.search(str(step.get("run", ""))):
                runners.add(f"{label}:{job_id}")
            if "setup-bun" in str(step.get("uses", "")):
                setups.append(f"{label}:{job_id}: Bun from `{step['uses']}`, not a pinned and checked download")
    return runners, setups


def bun_runners(texts: Mapping[str, str]) -> tuple[set[str], list[str]]:
    """Every workflow job and image stage in `texts` that runs a `bun` command, and every `setup-bun` step."""
    runners: set[str] = set()
    setups: list[str] = []
    for label, text in texts.items():
        if label.endswith((".yml", ".yaml")):
            found, steps = _workflow_runners(label, text)
            runners |= found
            setups += steps
        else:
            runners |= _dockerfile_runners(label, text)
    return runners, setups


def bun_sites(texts: Mapping[str, str]) -> list[Site]:
    """Every Bun download in the given `{path: text}` (`*.yml`/`*.yaml` as workflows, the rest as Dockerfiles)."""
    sites: list[Site] = []
    for label, text in texts.items():
        if _DOWNLOAD not in text:
            continue
        sites += _workflow_sites(label, text) if label.endswith((".yml", ".yaml")) else _dockerfile_sites(label, text)
    return sites


def check_every_bun_install_holds_one_pin(texts: Mapping[str, str]) -> None:
    """F6: Bun is installed in two CI jobs (test, lint) and a dev image; all sites share version and sha256, and each
    verifies the sha it pins. Every job or image stage that runs a `bun` command gets it from such a site in that same
    job or stage, never from `setup-bun` or from another job's site."""
    sites = bun_sites(texts)
    problems = [f"{s.label}: {p}" for s in sites for p in s.problems]
    assert not problems, problems
    jobs = {s.label for s in sites if ".yml" in s.label or ".yaml" in s.label}
    images = [s for s in sites if ".yml" not in s.label and ".yaml" not in s.label]
    assert len(jobs) >= 2, f"expected a Bun install in two workflow jobs, found {[s.label for s in sites]}"
    assert images, f"expected a Bun install in a dev image, found {[s.label for s in sites]}"
    assert len({s.version for s in sites}) == 1, {s.label: s.version for s in sites}
    assert len({s.sha for s in sites}) == 1, {s.label: s.sha for s in sites}
    runners, setups = bun_runners(texts)
    assert not setups, setups
    unpinned = sorted(runners - {s.label for s in sites})
    assert not unpinned, f"these run `bun` but get it from no pinned site in the same job or stage: {unpinned}"


def _repo_texts() -> dict[str, str]:
    workflows = sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml"))
    images = sorted((REPO_ROOT / ".devcontainer").rglob("Dockerfile*"))
    assert workflows, "control: the search finds the workflow files"
    assert images, "control: the search finds the Dockerfiles"
    return {str(p.relative_to(REPO_ROOT)): p.read_text(encoding="utf-8") for p in [*workflows, *images]}


def test_1540_f6_every_bun_install_in_ci_and_the_dev_image_holds_the_same_pinned_version_and_sha256():
    """Bun installs found by search share one version and sha256, each checked before unpacking. (F6)"""
    check_every_bun_install_holds_one_pin(_repo_texts())


# --- the check itself can fail ---------------------------------------------------------------------

SHA = "a" * 64
OTHER_SHA = "b" * 64
_STEP = """
      - name: Install Bun
        env:
          BUN_VERSION: 1.4.4
          BUN_SHA256: {sha}
        run: |
          curl -fsSL -o /tmp/bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v${{BUN_VERSION}}/bun-linux-x64.zip"
          echo "${{BUN_SHA256}}  /tmp/bun.zip" | sha256sum -c -
          sudo unzip -j /tmp/bun.zip -d /usr/local/bin
"""
_RUNS_BUN = "      - run: bun install --frozen-lockfile\n"
_DECOY_JOB = "  decoy:\n    runs-on: x\n    steps:" + _STEP.format(sha=SHA)
GOOD = {
    ".github/workflows/ci.yml": "on: push\njobs:\n  test:\n    runs-on: x\n    steps:" + _STEP.format(sha=SHA)
    + "  lint:\n    runs-on: x\n    steps:" + _STEP.format(sha=SHA) + _RUNS_BUN,
    ".devcontainer/Dockerfile.dev": (
        "FROM x\nARG BUN_VERSION=1.4.4\nARG BUN_SHA256=" + SHA + "\n"
        'RUN curl -fsSL -o /tmp/bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-x64.zip" \\\n'
        '    && echo "${BUN_SHA256}  /tmp/bun.zip" | sha256sum -c - \\\n'
        "    && unzip -j /tmp/bun.zip -d /usr/local/bin\n"
        "RUN bun --version\n"),
}


def _mutated(path: str, old: str, new: str, *, count: int = 1) -> dict[str, str]:
    assert old in GOOD[path], f"control: {old!r} is in the good text"
    return {**GOOD, path: GOOD[path].replace(old, new, count)}


MUTATIONS = {
    "version-differs-in-one-job": _mutated(".github/workflows/ci.yml", "1.4.4", "1.4.3"),
    "version-differs-in-the-image": _mutated(".devcontainer/Dockerfile.dev", "ARG BUN_VERSION=1.4.4", "ARG BUN_VERSION=1.4.3"),
    "sha-differs-in-one-job": _mutated(".github/workflows/ci.yml", SHA, OTHER_SHA),
    "sha-differs-in-the-image": _mutated(".devcontainer/Dockerfile.dev", "BUN_SHA256=" + SHA, "BUN_SHA256=" + OTHER_SHA),
    "no-sha-check-in-a-job": _mutated(".github/workflows/ci.yml", '          echo "${BUN_SHA256}  /tmp/bun.zip" | sha256sum -c -\n', ""),
    "no-sha-check-in-the-image": _mutated(".devcontainer/Dockerfile.dev", '    && echo "${BUN_SHA256}  /tmp/bun.zip" | sha256sum -c - \\\n', ""),
    "sha-names-another-file": _mutated(".devcontainer/Dockerfile.dev", "  /tmp/bun.zip\" | sha256sum", "  /tmp/other.zip\" | sha256sum"),
    "checked-after-unpacking": _mutated(
        ".devcontainer/Dockerfile.dev", '    && echo "${BUN_SHA256}  /tmp/bun.zip" | sha256sum -c - \\\n    && unzip -j /tmp/bun.zip -d /usr/local/bin\n',
        '    && unzip -j /tmp/bun.zip -d /usr/local/bin \\\n    && echo "${BUN_SHA256}  /tmp/bun.zip" | sha256sum -c -\n'),
    "a-fourth-site-in-another-image-with-another-pin": {
        **GOOD, ".devcontainer/Dockerfile.job": GOOD[".devcontainer/Dockerfile.dev"].replace(SHA, OTHER_SHA)},
    "a-job-without-bun": {**GOOD, ".github/workflows/ci.yml": GOOD[".github/workflows/ci.yml"].split("  lint:")[0]},
    "no-dev-image": {k: v for k, v in GOOD.items() if "Dockerfile" not in k},
    "a-job-takes-bun-from-setup-bun-with-a-decoy-pin-in-another-job": {
        **GOOD, ".github/workflows/ci.yml": GOOD[".github/workflows/ci.yml"].replace(
            "  lint:\n    runs-on: x\n    steps:" + _STEP.format(sha=SHA),
            "  lint:\n    runs-on: x\n    steps:\n      - uses: oven-sh/setup-bun@v2\n        with:\n          bun-version: latest\n")
        + _DECOY_JOB},
    "a-job-runs-bun-with-no-site-of-its-own": {
        **GOOD, ".github/workflows/ci.yml": GOOD[".github/workflows/ci.yml"] + "  other:\n    runs-on: x\n    steps:\n" + _RUNS_BUN},
    "an-image-stage-runs-bun-installed-in-another-stage": {
        **GOOD, ".devcontainer/Dockerfile.dev": GOOD[".devcontainer/Dockerfile.dev"] + "FROM y\nRUN bun install\n"},
}


def test_1540_f6_the_pin_check_accepts_a_good_set_of_sites():
    """Positive control for the mutations below: the synthetic sites pass and are all found. (F6)"""
    check_every_bun_install_holds_one_pin(GOOD)
    assert len(bun_sites(GOOD)) == 3


@pytest.mark.parametrize("texts", MUTATIONS.values(), ids=MUTATIONS.keys())
def test_1540_f6_the_pin_check_refuses_each_break(texts):
    """A different version or sha at one site, a missing or misdirected sha check, a late check, a new site, a job or image
    stage that runs `bun` without a pinned site of its own (setup-bun, another job's or stage's site). (F6)"""
    with pytest.raises(AssertionError):
        check_every_bun_install_holds_one_pin(texts)
