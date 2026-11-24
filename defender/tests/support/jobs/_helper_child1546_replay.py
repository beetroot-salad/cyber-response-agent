"""#1546 worker-lane child for the hermetic replay (`e2e/test_worker_replay.py`): `_helper_child1170.py` over a real evidence store.

The real per-job helper (`job_host.main`, kind investigation) whose docker is the stand-in (`ContainerStandIn`) and whose job
container is a real process, `_job_entry1342.py <mode> <commit> <marks> --job <id> --tenant <T>`, given only the environment
the helper handed it plus PATH and PYTHONPATH. Its knowledge fetch is `_helper_child1170.py`'s (#1618: the product's own fetch, in-process, over the test's bare
`<remote>`). What differs from `_helper_child1170.py`: the helper has what r8 requires of it at
setup, or it refuses the job terminally (an unconfigured store or key login): the blob store comes from the worker's own
environment (`DEFENDER_EVIDENCE_{ENDPOINT,BUCKET,ACCESS_KEY,SECRET_KEY,REGION}`, `_facts1546.evidence_env`), and the tenant's
key login is the `evidence_keys` seam, built from the JSON login in `DEFENDER_TEST_EVIDENCE_LOGIN` (`{addr, role_id, secret_id,
mount}`: an AppRole holding the policy the lifecycle writes for the tenant, `_helper_evidence1546.evidence_login`). The login
is taken out of the environment here, so the job container is never handed it.

`python _helper_child1546_replay.py <mode> <commit> <marks> <remote> --job <id> --tenant <T> --parent-pid <pid> [...]`: what a test hands
the worker as its `child_argv` for an investigation (`e2e/test_worker_replay.child_argv` builds it). The exit status is the
helper's."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from defender import evidence, job_host  # noqa: E402
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A  # noqa: E402
from defender.tests.support.jobs._job_helper import ContainerStandIn  # noqa: E402
from defender.tests.support.tenancy._fetch_standin_1618 import in_process_fetch  # noqa: E402

ENTRY = Path(__file__).resolve().with_name("_job_entry1342.py")
LOGIN_ENV = "DEFENDER_TEST_EVIDENCE_LOGIN"

mode, commit, marks, remote, argv = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
job_id, tenant = argv[argv.index("--job") + 1], argv[argv.index("--tenant") + 1]
parent = argv[argv.index("--parent-pid") + 1]
ticket = argv[argv.index("--parent-pid") + 2:]  # `--alert-digest`, and for a flagged job `--post-ticket --ticket-link`
login = json.loads(os.environ.pop(LOGIN_ENV))


def entry(container) -> int:
    env = {k: v for k, v in container.env.items() if v is not None}
    env.update(PATH=os.environ["PATH"], PYTHONPATH=f"{ROOT}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")
    return subprocess.run([sys.executable, str(ENTRY), mode, commit, marks, "--job", job_id, "--tenant", tenant],  # noqa: S603
                          env=env, cwd=str(ROOT), stdin=subprocess.DEVNULL, check=False).returncode


sys.exit(job_host.main(["--kind", "investigation", "--job", job_id, "--tenant", tenant, "--parent-pid", parent, *ticket],
                       docker=ContainerStandIn(entry), signer=A.MarkedSigner(),
                       fetch=in_process_fetch(remote),
                       evidence_keys=evidence.EvidenceKeys(addr=login["addr"], role_id=login["role_id"],
                                                           secret_id=login["secret_id"], mount=login["mount"])))
