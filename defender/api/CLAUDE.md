# Platform API changes

- Routes, wire models, and ports live here. Data rules belong to the store and are stated on ports; development fakes do not establish those invariants.
- Keep API code independent of runtime and learning imports. The runtime is `investigation/` plus what #1308 moved out of it (`systems/`, `providers/`, the session store); `tests/tooling/layout_contracts/_spec1080.py` (`API_FORBIDDEN`) is the full list.
- Tenant registration belongs to the user-facing product API, backed by a register-tenant command that performs setup and validation. Do not replace that product responsibility with an operator skill. Existing CLI setup recipes are in `../docs/development-operations.md`; they are not evidence that the registration API already exists.
