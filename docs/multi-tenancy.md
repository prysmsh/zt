# Multi-tenancy and the master console

ZT-next's control plane is designed to run as a SaaS service. This document
describes the tenancy model, the master console, and how the two interact.

## The shape of the deployment

A ZT-next deployment has two planes.

```
┌──────────────────────────────────────────────────────────────┐
│ Control plane (one per region)                                │
│                                                              │
│   Master console  ──▶  /api/v1/tenants/...                   │
│        │                                                     │
│        ├──▶  Tenant A (shared)   ──▶  /api/v1/t/{tenant}/... │
│        ├──▶  Tenant B (shared)   ──▶  /api/v1/t/{tenant}/... │
│        └──▶  Tenant C (dedicated) ──▶ own process + key      │
└──────────────────────────────────────────────────────────────┘
```

### Shared tenants

Small tenants share one controller process and one database. Their data is
separated by a `tenant_id` column on every table, and every query is scoped
before anything is returned.

A shared tenant still gets a distinct network ID space, so its addresses can
never collide with another tenant's.

### Dedicated tenants

Larger or regulated tenants run their own controller process, database, and
signing key. The shared control plane tracks their lifecycle — plan, limits,
suspension, health — but does not hold their data.

This matters because a shared controller signs credentials for every tenant it
serves. A dedicated controller removes that shared trust anchor entirely, so
a compromise of the shared plane cannot issue credentials for the dedicated
tenant.

## Tenant lifecycle

```
  provisioning ──▶ active ──▶ suspended ──▶ active
       │              │            │
       │              ▼            ▼
       └──────────▶ deleted ◀─────┘
```

| State | Meaning |
|---|---|
| `provisioning` | The tenant exists but is being set up. |
| `active` | Fully operational. |
| `suspended` | Access blocked, data retained. Credentials stop being renewed. |
| `deleted` | Soft-deleted. A retention job purges the data later. |

### Why suspension is not deletion

Suspending a tenant blocks it without destroying anything. Because
credentials are short-lived and renewal is refused, the tenant's access
lapses within one credential TTL — usually 24 hours — without a revocation
list and without a race.

Deletion is deliberately **soft**. A retention job purges data on a later
schedule, so an accidental deletion can be reversed.

## The two API surfaces

### Master console API

Administers tenants and the control plane itself.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/control-plane` | Control-plane health and counts |
| `GET` | `/api/v1/tenants` | List every tenant |
| `POST` | `/api/v1/tenants` | Create a tenant |
| `GET` | `/api/v1/tenants/{id}` | Get one tenant |
| `PATCH` | `/api/v1/tenants/{id}` | Change plan or limits |
| `POST` | `/api/v1/tenants/{id}/suspend` | Suspend a tenant |
| `POST` | `/api/v1/tenants/{id}/reactivate` | Restore a tenant |
| `DELETE` | `/api/v1/tenants/{id}` | Soft-delete a tenant |
| `GET` | `/api/v1/tenants/{id}/usage` | Resource usage against limits |
| `GET` | `/api/v1/tenants/{id}/events` | One tenant's audit log |

### Tenant API

Everything a tenant touches. Every path carries the tenant ID.

| Method | Path |
|---|---|
| `GET` | `/api/v1/t/{tenant}/networks` |
| `POST` | `/api/v1/t/{tenant}/networks` |
| `DELETE` | `/api/v1/t/{tenant}/networks/{id}` |
| `GET` | `/api/v1/t/{tenant}/nodes` |
| `POST` | `/api/v1/t/{tenant}/nodes` |
| `GET` | `/api/v1/t/{tenant}/nodes/{id}` |
| `DELETE` | `/api/v1/t/{tenant}/nodes/{id}` |
| `POST` | `/api/v1/t/{tenant}/nodes/{id}/credential` |
| `POST` | `/api/v1/t/{tenant}/nodes/{id}/revoke` |
| `GET` | `/api/v1/t/{tenant}/policies` |
| `POST` | `/api/v1/t/{tenant}/policies` |
| `DELETE` | `/api/v1/t/{tenant}/policies/{id}` |
| `GET` | `/api/v1/t/{tenant}/relays` |
| `POST` | `/api/v1/t/{tenant}/relays` |
| `POST` | `/api/v1/t/{tenant}/relays/{id}/drain` |
| `GET` | `/api/v1/t/{tenant}/events` |

## Isolation guarantees

Isolation is enforced in the **service layer**, not the API layer. The CLI,
the HTTP API, and any future RPC surface all inherit the same guarantee.

The rules:

1. **Every read is filtered by tenant.** A tenant that guesses another
   tenant's object ID gets `404`, not `403` — the existence of the object is
   not disclosed.
2. **Every mutation checks ownership before it changes anything.** This is
   easy to get wrong: removing an object and then filtering it would delete
   another tenant's data before rejecting the request.
3. **Every query in the store is scoped.** Tenant IDs are indexed columns.
4. **Audit events are tenant-scoped.** A tenant sees its own history only.

The isolation tests in `crates/zt-controller/tests/tenant_isolation.rs`
assert each of these, including the cross-tenant delete and
cross-tenant credential renewal.

## Resource limits

Each tenant has limits on networks, nodes, policies, and relays, plus a
maximum credential TTL.

Limits are checked **before** a resource is created, so a tenant cannot
exceed its plan even momentarily. The projection is
`current_usage + requested`, which is why creating one network when eleven
of eleven are already used fails with a clear message rather than silently
going over.

## What the master console shows

- Every tenant, its plan, deployment type, and status
- Resource usage against limits
- Controller health: uptime, version, object counts
- Tenant health: node counts, online percentage, degraded relays
- The audit log across all tenants, filterable by tenant
- One-click lifecycle actions: suspend, reactivate, delete
- The control plane's own identity and trust anchor

## Operating a shared control plane

### Database

One SQLite database in WAL mode, or Postgres when the control plane is
horizontally scaled. Tenant IDs are the partition key.

### Controller identity

One Ed25519 key signs credentials for every shared tenant. It lives in
`controller.key` with owner-only permissions, separate from the database, and
must be backed up separately.

A dedicated tenant's key lives with its dedicated controller and never
touches the shared plane.

### Backup

Back up two things independently:

- `controller.db` — networks, nodes, policies, relays, audit log
- `controller.key` — the signing identity

Losing the database loses operational state but not trust. Losing the key
means previously issued credentials remain valid until they expire, but no
new credentials can be issued.

### Scaling out

When one process is no longer enough:

- The API layer is stateless, so it scales horizontally behind a load
  balancer.
- The store moves to Postgres with tenant IDs as the partition key.
- Dedicated tenants are simply pointed at their own controllers; the master
  console keeps tracking them.

## Authentication

The master console API is **not** yet authenticated. It must not be exposed
beyond localhost until it is.

The intended shape:

- **Operator access** — SSO with role claims. The master console requires
  the `operator` role.
- **Tenant access** — each tenant authenticates with its own identity
  provider. The tenant's ID comes from the token, not from the URL, so a
  token for one tenant cannot address another.
- **Node access** — nodes authenticate with the credential the controller
  issued them. A node may renew its own credential and nothing else.

The tenant ID in the URL is a routing convenience, not an authorization
decision. Authorization comes from the authenticated identity.

## Reference

- Model: `crates/zt-controller/src/tenant.rs`
- Service: `crates/zt-controller/src/service.rs`
- API: `crates/zt-controller/src/api.rs`
- Store: `crates/zt-controller/src/store.rs`
- Tests: `crates/zt-controller/tests/tenant_isolation.rs`
