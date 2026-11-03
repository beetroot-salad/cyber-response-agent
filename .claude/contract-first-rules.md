# contract-first rules

Rules agents wrote for this project, each removing a cause behind several cache entries; written by the contract-first `maintain-cache` skill, reviewed by the human at merge.

- R1 | A local green proves nothing about a service-gated test: before trusting one, read the service markers in `defender/pyproject.toml`'s `[tool.pytest.ini_options] markers` (each names the env vars it needs and says it skips without them locally and fails without them in CI), and for each marker the change reaches either supply the service or treat that marker's tests as not run, checking the skip count rather than the failure count. | why: service-backed tests (`postgres`, `openbao`) skip silently locally and fail only in CI, so each new service was rediscovered as an unexpected CI red or an unearned local pass | src: #1342, #1384
