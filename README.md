# Mesh extension template

An external Mesh extension starter derived from
[mesh-ext-hello](https://git.entire.host/entire-vc/mesh-ext-hello), licensed under MIT.
It implements signed installation/events, JWT-authenticated UI, a health endpoint,
and the `sidebar.item` and `task.panel` slots.

Follow the complete [developer guide](https://spark.entire.vc/api/v1/mesh-extensions/docs/developer-guide)
to customize the manifest, validate, package and publish your own extension.
Replace the manifest's ID, publisher and repository before publishing.

## Permissions

`tasks:read`; `task.updated` events; `sidebar.item` and `task.panel` UI.
The starter does not write tasks or comments. UI token claims supply the current
user/task context; declaring a permission does not grant unused features.

## Network

Mesh calls the configured `hello_url`. This service fetches signing keys only
from the JWKS URL provided during installation (or configured via `MESH_JWKS_URL`).
Configure the service and signing keys for your own trusted Mesh instance.

## Accounts

None. The service verifies Mesh-issued UI JWTs and requires no external accounts.

## Telemetry

None sent to the publisher or third parties. The local log records escaped request
paths without query strings, installation version, event receipt and JWT rejection.
Request headers, payload fields and JWT error details are not logged.
Installation signing secret and JWKS URL are stored in `HELLO_STATE_FILE`;
the last 50 event types are held in memory. Protect the state file and disable
`HELLO_DEBUG` in production.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m hello
```

`GET /healthz` returns the running version. `PORT` defaults to 8080.
Deploy with persistent storage mounted at `/data` when using the Dockerfile.
`HELLO_STATE_FILE` defaults to `/tmp/hello-state.json` outside Docker.
`HELLO_JWT_AUDIENCE` defaults to `example`; set it to your own manifest ID.
`MESH_ORIGIN` restricts UI framing to
your Mesh origin. `HELLO_SIGNING_SECRET` and `MESH_JWKS_URL` can override install
configuration. Supply them through your secure configuration.

First installation is denied unless its direct peer is explicitly in
`HELLO_BOOTSTRAP_PEERS` (comma-separated trusted Mesh server IPs). Forwarded
headers are ignored. When using an HTTPS reverse proxy, first restrict
`/mesh/install` there to trusted Mesh sources, then allowlist that proxy's peer;
never allowlist a shared proxy without the source restriction. Remove the list
after bootstrap. All subsequent install requests, including JWKS changes,
require HMAC with the existing key. The state file is written atomically with
mode 0600 and must be backed up securely.

## Validation and releases

Install `mesh-ext` and Trivy as described in the guide. Run `mesh-ext validate .`
and tag releases with the plain manifest version, without a `v` prefix.
The GitLab pipeline validates with the same shared catalogue checks. The manifest
does not declare a container image; add your canonical registry/version only
after you have built and pushed that image.

Run the runtime security tests and malformed-manifest control locally after
installing `mesh-ext` in your environment:

```sh
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/mesh-ext validate .
.venv/bin/python -m pytest tests -q
```
