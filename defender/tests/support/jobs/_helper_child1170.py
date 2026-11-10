"""#1170 (r4) worker-lane child: the per-job host helper in front of the replay job entry, as one process.

`python _helper_child1170.py <mode> <commit> <marks> --job <id> --tenant <T> --parent-pid <pid>` is what a test hands the
worker as its `child_argv` for an investigation (`_job_helper.helper_child` builds it). It runs the real helper
(`job_host.main`, the worker's helper argv: kind, job, tenant, parent pid) whose docker is the stand-in
(`ContainerStandIn`) and whose job container is a real process, `_job_entry1342.py <mode> <commit> <marks> --job <id>
--tenant <T>`, given only the environment the helper handed the container (its socket address, no database login) plus
PATH and PYTHONPATH. The helper's signer is the marked signer and its launch-time publish answers `fresh` at the commit
(as `drive_helper` does), so a worker-lane replay needs no real vault or knowledge publish. The container's output goes
to this process' stdout and stderr, and the helper's own refusals to its stderr, so a test reading the child's stderr
(`2>>file`) sees both. The exit status is the helper's."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from defender import job_host  # noqa: E402
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A  # noqa: E402
from defender.tests.support.jobs._job_helper import ContainerStandIn  # noqa: E402
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B  # noqa: E402

ENTRY = Path(__file__).resolve().with_name("_job_entry1342.py")

mode, commit, marks, argv = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
job_id, tenant = argv[argv.index("--job") + 1], argv[argv.index("--tenant") + 1]
parent = argv[argv.index("--parent-pid") + 1]


def entry(container) -> int:
    env = {k: v for k, v in container.env.items() if v is not None}
    env.update(PATH=os.environ["PATH"], PYTHONPATH=f"{ROOT}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")
    return subprocess.run([sys.executable, str(ENTRY), mode, commit, marks, "--job", job_id, "--tenant", tenant],  # noqa: S603
                          env=env, cwd=str(ROOT), stdin=subprocess.DEVNULL, check=False).returncode


sys.exit(job_host.main(["--kind", "investigation", "--job", job_id, "--tenant", tenant, "--parent-pid", parent],
                       docker=ContainerStandIn(entry), signer=A.MarkedSigner(),
                       publish=lambda *a, **k: B.fresh(commit)))
