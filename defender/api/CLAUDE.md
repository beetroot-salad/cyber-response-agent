# Platform API changes

- Routes, wire models, and ports live here. Data rules belong to the store and are stated on ports; development fakes do not establish those invariants.
- Keep API code independent of runtime and learning imports.
- Tenant registration belongs to the user-facing product API, backed by a register-tenant command that performs setup and validation. Do not replace that product responsibility with an operator skill. Existing CLI setup recipes are in `../docs/development-operations.md`; they are not evidence that the registration API already exists.
