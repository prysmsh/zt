# ZT-next Controller API

The controller is the control plane for ZT-next. It owns networks, node
membership, access policies, relays, and credential issuance.

## Running

```bash
cargo run -p zt-controller --bin zt-controller
```

The service listens on `127.0.0.1:8080` by default. Override with:

```bash
ZT_CONTROLLER_LISTEN=0.0.0.0:8080 cargo run -p zt-controller --bin zt-controller
```

## Storage

State is persisted in SQLite. By default the controller uses a `data/`
directory in the working directory:

```text
data/
  controller.db      SQLite database (WAL mode)
  controller.db-wal  Write-ahead log
  controller.db-shm  Shared-memory index
  controller.key     Controller signing key, mode 0600
```

Override the location with `ZT_CONTROLLER_DATA_DIR`:

```bash
ZT_CONTROLLER_DATA_DIR=/var/lib/zt-next cargo run -p zt-controller --bin zt-controller
```

### Schema

| Table | Contents |
|---|---|
| `schema_version` | Applied migration version |
| `networks` | Network boundaries, CIDRs, and credential TTLs |
| `nodes` | Enrolled members, key fingerprints, tags, and credential expiry |
| `policies` | Default-deny access rules |
| `relays` | Per-network relay infrastructure |
| `events` | Append-only audit log |

Foreign keys cascade: deleting a network removes its nodes and policies, and
removes the network from relay assignments.

Migrations are applied at startup and are idempotent, so an existing database
can be reopened by a newer controller without losing data.

### Controller identity

The controller's Ed25519 signing key is stored separately from operational
data in `controller.key`, with owner-only permissions (`0600` on Unix). The
file contains the private seed, hex encoded.

This key is the **root of trust**: every credential the controller issues is
signed with it, and nodes pin it. Back it up separately from the database and
never distribute it to nodes.

If the key is lost, previously issued credentials remain valid until they
expire, but no new credentials can be issued for the same controller ID.

## Security model

- **Short-lived credentials.** Nodes receive credentials with a 24-hour default
  TTL. A stolen credential expires on its own and cannot be renewed once the
  node is revoked.
- **Key-bound.** Each credential commits to the node's Ed25519 public key.
  Possession of the credential alone is not enough to join.
- **Hybrid signatures.** Credentials are signed with Ed25519 + ML-DSA-65.
  Nodes verify both signatures.
- **Pull-based revocation.** Revoking a node prevents renewal. Access ends
  within one TTL, without needing a revocation push list.
- **Audit trail.** Every administrative mutation is recorded.

## Endpoints

All endpoints are under `/api/v1`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Controller health and object counts |
| `GET` | `/controller` | Controller ID and public trust anchor |
| `GET` | `/networks` | List networks |
| `POST` | `/networks` | Create a network |
| `DELETE` | `/networks/{id}` | Delete a network and its scoped objects |
| `GET` | `/nodes?network={id}` | List nodes, optionally scoped |
| `POST` | `/nodes` | Enroll a node and issue its credential |
| `GET` | `/nodes/{id}` | Get one node |
| `DELETE` | `/nodes/{id}` | Revoke a node |
| `POST` | `/nodes/{id}/revoke` | Revoke a node |
| `POST` | `/nodes/{id}/credential` | Renew a node credential |
| `GET` | `/policies?network={id}` | List access policies |
| `POST` | `/policies` | Create an access policy |
| `DELETE` | `/policies/{id}` | Delete an access policy |
| `GET` | `/relays?network={id}` | List relays |
| `POST` | `/relays` | Create a relay |
| `POST` | `/relays/{id}/drain` | Drain a relay before maintenance |
| `GET` | `/events` | Audit log |
| `POST` | `/join` | Ask to join a network (public, creates a pending node) |
| `POST` | `/join/{id}/poll` | A pending node collects its credential with a signature |
| `POST` | `/t/{tenant}/nodes/{id}/approve` | Approve a pending node (operator) |

### The join flow

`POST /join` takes a tenant slug, a network identifier, a name, and the
client's hex-encoded Ed25519 and ML-DSA-65 public keys. It needs no
token: knowing where to ask is enough to *ask*. The node it creates has
no credential and no access — the security lives in the approval, not
the join.

The operator approves with `/t/{tenant}/nodes/{id}/approve`, which marks
the node as accepted and issues nothing. The node then polls
`/join/{id}/poll` with a hex-encoded Ed25519 signature over the literal
string `zt-next-join-poll:{node_id}`. Before approval the poll answers
`"Pending"`. After approval it returns an `Approved` object carrying a
credential bound to the very key that signed the poll — so only the
holder of the private half can collect, and no secret ever passes
through the console.

## Creating a network

```bash
curl -X POST http://127.0.0.1:8080/api/v1/networks \
  -H 'content-type: application/json' \
  -d '{
    "name": "Production",
    "description": "Core production services",
    "cidr": "10.42.0.0/24",
    "credential_ttl_secs": 86400
  }'
```

## Enrolling a node

The node generates its own Ed25519 keypair and sends only the public key.
The controller derives the per-network address and returns a signed,
short-lived credential.

```bash
curl -X POST http://127.0.0.1:8080/api/v1/nodes \
  -H 'content-type: application/json' \
  -d '{
    "network_id": "<network uuid>",
    "name": "web-01",
    "public_key": "<64 hex characters>",
    "tags": ["production", "web"]
  }'
```

The response contains the node record and the credential, shown once:

```json
{
  "node": {
    "id": "...",
    "address": "9f2c1a0b4d6e8f102",
    "status": "pending",
    "credential_not_after": 1767225600
  },
  "credential": "01...",
  "credential_not_after": 1767225600
}
```

## Creating a policy

Policies are default-deny. A rule allows traffic when the protocol, port,
source selector, and destination selector all match.

```bash
curl -X POST http://127.0.0.1:8080/api/v1/policies \
  -H 'content-type: application/json' \
  -d '{
    "network_id": "<network uuid>",
    "name": "Web tier to database",
    "protocol": "tcp",
    "port": { "single": 5432 },
    "source": { "kind": "tag", "tag": "web" },
    "destination": { "kind": "tag", "tag": "database" }
  }'
```

### Selector kinds

- `any`
- `node` — exact node ID
- `tag` — node tag
- `platform` — reported platform
- `subnet` — CIDR behind the overlay
- `network` — another network

## Persistence

State is persisted in SQLite. The store is behind the `Store` trait, so the
HTTP API and console contract are unaffected by the storage backend. An
in-memory store remains available for tests and ephemeral deployments.
