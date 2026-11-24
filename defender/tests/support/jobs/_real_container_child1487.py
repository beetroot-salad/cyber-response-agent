"""#1487 (O8) worker-lane child: `python _real_container_child1487.py <commit> <remote> --kind <learning|post-step> --job <id> --tenant <T>
[--source <inv>] --parent-pid <pid>`. The real per-job helper (`job_host.main`) over the REAL docker, its job container
running the kind's test program (`_real_containers1487`) in place of the entry. The signer is the marked signer and the
knowledge fetch is the product's own, in-process, over the tenant's bare `<remote>` (#1618, `_fetch_standin_1618`), as
`_helper_child1170.py`'s is. The store is the worker's environment's (`DEFENDER_EVIDENCE_*`); the tenant's key login is the
`evidence_keys` seam, from the JSON login in `DEFENDER_TEST_EVIDENCE_LOGIN` (`{addr, role_id, secret_id, mount}`, as
`_helper_child1546.py` takes it), taken out of the environment here so no job container is handed it. The exit status is
the helper's."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from defender import evidence, job_host  # noqa: E402
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
login = json.loads(os.environ.pop("DEFENDER_TEST_EVIDENCE_LOGIN", "null"))
keys = None if login is None else evidence.EvidenceKeys(addr=login["addr"], role_id=login["role_id"],
                                                        secret_id=login["secret_id"], mount=login["mount"])
#: The real docker, carrying the program's observation through its container's own root when that root is not the data
#: root (`R.ObservingDocker`: a learning container binds no tenant folder, #1546 A-O9).
docker = R.ObservingDocker(run_docker, host_root=Path(os.environ["DEFENDER_DATA_ROOT"]), tenant=tenant,
                           name={"learning": "learning", "post-step": "post-step"}[kind])
sys.exit(job_host.main(argv, docker=docker, signer=A.MarkedSigner(), forge=ForgeCredentialRecorder(),
                       fetch=in_process_fetch(remote), command=command, evidence_keys=keys))
