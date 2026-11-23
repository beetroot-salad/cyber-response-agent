"""#1487 (O8) worker-lane child: `python _real_container_child1487.py <commit> <remote> --kind <learning|post-step> --job <id> --tenant <T>
[--source <inv>] --parent-pid <pid>`. The real per-job helper (`job_host.main`) over the REAL docker, its job container
running the kind's test program (`_real_containers1487`) in place of the entry. The signer is the marked signer and the
knowledge fetch is the product's own, in-process, over the tenant's bare `<remote>` (#1618, `_fetch_standin_1618`), as
`_helper_child1170.py`'s is. The exit status is the helper's."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from defender import job_host  # noqa: E402
from defender.box import run_docker  # noqa: E402
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A  # noqa: E402
from defender.tests.support.jobs import _real_containers1487 as R  # noqa: E402
from defender.tests.support.jobs._job_helper import ForgeCredentialRecorder  # noqa: E402
from defender.tests.support.tenancy._fetch_standin_1618 import in_process_fetch  # noqa: E402

commit, remote, argv = sys.argv[1], sys.argv[2], sys.argv[3:]
kind = argv[argv.index("--kind") + 1]
tenant, job = argv[argv.index("--tenant") + 1], argv[argv.index("--job") + 1]
program = {"learning": R.LEARNING, "post-step": R.POST_STEP}[kind]
command = ["python3", "-c", program, tenant, job]
sys.exit(job_host.main(argv, docker=run_docker, signer=A.MarkedSigner(), forge=ForgeCredentialRecorder(),
                       fetch=in_process_fetch(remote), command=command))
