# Elastic

## Credential

A `basic` credential (`username` and `password`) for a read-only user holding `read` on both the events and the alerts indexes the record names, plus the cluster-level `monitor` privilege. Without `monitor` the health check answers a settings fault naming it; without `read` on an index, a search answers one naming the index.

## Pitfalls

- When the cluster's certificate comes from a private CA, put its certificates in the record's `ca` (inline PEM, nothing else). That becomes the only trust for this system, so a public CA the cluster also relies on must be included too.
- Give the base as the cluster's own URL; a path prefix on it is allowed (a cluster behind a gateway), but a Kibana URL is not the cluster.
