Produce a unified diff that adds per-tenant idempotent job submission to the
seeded async Python service in `workspace/`, followed by concise verification
notes.

The same `(tenant_id, idempotency_key)` submitted concurrently or through a
retry must return the same job and publish it only once. Reusing the key with a
different payload before expiry must raise a typed conflict. Keys expire after
60 seconds, after which a new job may be created. Tenants never share keys.
Preserve the existing public API and use only the Python standard library.

