from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from defender import _git  # noqa: E402 — needs REPO_ROOT on sys.path


def run(cmd: list[str], cwd: Path, env: dict | None = None,
        input_: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, env=env, input=input_,
        capture_output=True, text=True, check=check, encoding="utf-8"
    )


def init_git(tmp: Path) -> None:
    _git.git(["init", "-q", "-b", "main"], cwd=tmp)
    _git.git(["config", "user.email", "eval@local"], cwd=tmp)
    _git.git(["config", "user.name", "eval"], cwd=tmp)
    _git.git(["add", "-A"], cwd=tmp)
    _git.git(["commit", "-q", "-m", "scenario baseline"], cwd=tmp)


def find_venv_py(repo_root: Path) -> Path:
    env = os.environ.get("LEARNING_VERIFIER_PYTHON")
    if env:
        return Path(env).resolve()
    candidates = [repo_root / "defender" / ".venv" / "bin" / "python3"]
    p = repo_root.parent
    for _ in range(6):
        candidates.append(p / "defender" / ".venv" / "bin" / "python3")
        candidates.append(p / "workspace" / "defender" / ".venv" / "bin" / "python3")
        if p.parent == p:
            break
        p = p.parent
    for c in candidates:
        if c.is_file():
            return c
    sys.exit(f"no defender venv found; tried {candidates}")


# ---------------------------------------------------------------------------------------------
# A local tenant for the eval harnesses (#1108 P4 O7): every corpus write goes through the
# tenant commit-maker into a batch draft, so a harness drives its lane against a draft of a
# real tenant repository. The origin is a local bare repository (git traffic stays local) and
# the forge is the drain tests' fake (`ForgeHTTP`, its PR rows kept beside the bare remote);
# no issuer is configured or contacted, and nothing opens a socket.
# ---------------------------------------------------------------------------------------------

#: The origin the fake forge answers for; git never dials it (`_LocalOriginRepository`).
FAKE_ORIGIN = "http://forge.invalid:3000/tenants/blue.git"
#: The id the harness tenant is set up under.
HARNESS_TENANT_ID = "11111111-1111-4111-8111-111111111111"


class _NoIssuer:
    """The forge credential of a harness tenant: no issuer, a fixed bearer the fake forge does
    not check."""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id

    def token(self, *, min_validity: int = 0) -> str:
        del min_validity
        return "evals-harness-no-issuer"


def _local_origin_repository() -> type:
    """`GitRepository` whose fetch and push move objects to and from a local bare repository
    (`remote`) — no network transport, no credential — while forge calls go to the fake."""
    import dataclasses

    from defender.learning.author.version_control.repository import GitRepository

    @dataclasses.dataclass(frozen=True, repr=False)
    class _LocalOriginRepository(GitRepository):
        remote: Path | None = None

        def fetch(self) -> None:
            _git.git(["fetch", "-q", str(self.remote), "+refs/heads/*:refs/remotes/origin/*"],
                     cwd=self.path)

        def push(self, commit: str, branch: str) -> None:
            _git.git(["push", "-q", str(self.remote), f"{commit}:refs/heads/{branch}"],
                     cwd=self.path)

    return _LocalOriginRepository


class LocalTenant:
    """A tenant under `tmp/data` whose knowledge clone holds `agent` (an agent root's tree) as
    one commit on `main`, its origin the bare repository `tmp/tenants/blue.git`, its forge the
    drain tests' fake over that repository."""

    def __init__(self, tmp: Path, agent: Path) -> None:
        from defender.tests.support.tenancy import _tenants1106 as tenants
        from defender.tests.tenancy.tenant_1108_delivery._support import BARE_NO_UPKEEP, ForgeHTTP
        from defender.tests.tenancy.tenant_1108_p4._support import place_fixture

        self.data_root = tmp / "data"
        clone = place_fixture(self.data_root, HARNESS_TENANT_ID, agent=agent)
        self.tenant = tenants.accept(self.data_root, HARNESS_TENANT_ID)
        _git.git(["init", "-q", "-b", "main"], cwd=clone)
        _git.git(["config", "user.name", "evals"], cwd=clone)
        _git.git(["config", "user.email", "evals@test.invalid"], cwd=clone)
        _git.git(["add", "-A"], cwd=clone)
        _git.git(["commit", "-q", "-m", "harness tenant"], cwd=clone)
        self.remote = tmp / "tenants" / "blue.git"
        self.remote.parent.mkdir(parents=True)
        _git.git(["clone", "-q", "--bare", *BARE_NO_UPKEEP, str(clone), str(self.remote)],
                 cwd=tmp)
        _git.git(["remote", "add", "origin", FAKE_ORIGIN], cwd=clone)
        _git.git(["fetch", "-q", str(self.remote), "+refs/heads/*:refs/remotes/origin/*"],
                 cwd=clone)
        self.clone = clone
        self.forge = ForgeHTTP(remote=self.remote, origin=FAKE_ORIGIN)

    def delivery(self, branch_prefix: str):  # noqa: ANN201 — P3's `TenantDelivery`
        """P3's real `TenantDelivery` over this tenant, its lane's branches under
        `branch_prefix`."""
        import dataclasses

        from defender._paths import process_defender_dir
        from defender.learning.author.version_control import TenantDelivery
        from defender.learning.author.version_control.forgejo import ForgejoForge

        from typing import cast

        from defender.learning.author.version_control.auth import ForgejoIdentity

        # Duck-typed: the forge reads only `token()` off its identity.
        identity = cast("ForgejoIdentity", _NoIssuer(HARNESS_TENANT_ID))
        repository = _local_origin_repository()(
            self.clone, FAKE_ORIGIN,
            ForgejoForge(origin=FAKE_ORIGIN, identity=identity, client=self.forge.client),
            identity, remote=self.remote,
        )
        delivery = TenantDelivery(tenant=self.tenant, defender_dir=process_defender_dir(),
                                  repository=repository)
        return dataclasses.replace(delivery, branch_prefix=branch_prefix)
