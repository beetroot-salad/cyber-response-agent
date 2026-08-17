# soar/workflows/

Committed Shuffle workflows. `scripts/install_soar_workflow.py` upserts every
`*.json` here into the running instance by name, rewriting the instance-specific
fields (`org_id`, execution environment) on the way in.

## The reference workflow: `alert-triage-loop`

Mirrors the triage loop the defender performs, so there is a machine-executed
version of it to compare against. Every route below is one the stubs actually
serve — check `<stub>:8080/openapi.json` if you need the exact shapes.

1. **Webhook trigger** — fired by a Kibana webhook connector attached to a
   detection rule (see below).
2. **`GET /lookup/{value}`** on `threat-intel` — reputation for the hash or IP
   named in the alert.
3. **`GET /hosts/{name}`** on `cmdb` — asset context: role, owner, criticality.
4. **`GET /changes/active`** on `change-mgmt` — is there a change request
   covering this host right now?
5. **`POST /tickets`** then **`POST /tickets/{key}/comments`** on
   `ticket-server` — record the verdict.

`identity`'s `GET /users/{username}/can_access` is the natural sixth step for
any alert that names a user; it is left out of the reference so the shape stays
readable.

**Do not wire `/admin/*` into any of this.** `POST /admin/reset` on any stub,
and `POST|DELETE /admin/overlay/{name}` on cmdb, are chaos/reset controls.
Generating a Shuffle app from a stub's full OpenAPI spec pulls them in — trim
them from the generated app.

## Producing the JSON

Shuffle has no API for generating an app from an OpenAPI spec, so the first pass
is a UI pass. Once, per workflow:

1. Tunnel the UI: `ssh -L 8006:localhost:8006 soc-playground`, open
   `http://localhost:8006`, sign in with `V2_SHUFFLE_ADMIN_USERNAME` /
   `V2_SHUFFLE_ADMIN_PASSWORD` from `.env` (created on first boot — there is no
   click-through setup).
2. **Apps → Create app → Generate from OpenAPI** for each stub you need, pasting
   e.g. `http://cmdb:8080/openapi.json`. The backend fetches it in-cluster.
3. Build the workflow, run it once against a real alert, then **export** it.
4. Commit the export here and re-install it with
   `python3 scripts/install_soar_workflow.py` so a fresh lever-up reproduces it.

Step 4 keeps the repo's "committed YAML is source of truth" rule true for
*workflows*: anything built only in the UI is lost on a volume reset.

**It does not cover the apps from step 2, and that gap is load-bearing.** The
generated apps live only in `shuffle_opensearch_data`, and the workflow JSON
references them by `app_id`. So after `down -v` (or any reset of that volume),
re-running the installer recreates the workflows against apps that no longer
exist — they import without error and fail at execution. Until app creation has
an API, step 2 has to be redone by hand *before* step 4, and the app names must
match the ones the committed workflows reference. Treat a volume reset as a full
re-do of this README, not as a re-run of the installer.

## Wiring the Kibana trigger

Shuffle's webhook trigger gives you a URL of the form
`http://shuffle-backend:5001/api/v1/hooks/<hook-id>`. Kibana reaches that
in-cluster because Kibana is dual-homed onto the `soar` network.

In Kibana: **Stack Management → Connectors → Create connector → Webhook**, POST
to that URL, no auth. Then add it as an action on the detection rule you want to
drive. The webhook connector is GA on the Basic licence this stack runs — unlike
Elastic's own endpoint response actions, which are Enterprise-gated.

Fold the connector back into the repo the same way as the workflow, so it
survives a reset.

## Checking your assumptions after a Shuffle upgrade

```bash
python3 scripts/install_soar_workflow.py --probe
```

Exercises auth and every read route without writing anything, and names the
route that disagrees if one has moved.
