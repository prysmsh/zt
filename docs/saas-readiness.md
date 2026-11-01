# SaaS readiness

An honest assessment of what the control plane supports today, and what
is still missing before it can carry paying tenants.

## Ready

### Tenant isolation

Enforced in the service layer, not the API layer. Every query filters on
the tenant, and a tenant that asks for another tenant's object gets a
`404`, not a `403` — the existence of another tenant's resource is not
disclosed.

A token names the tenant it belongs to, and the tenant-scoped API refuses
a token whose tenant does not match the path. This is checked in the
authentication middleware, before the handler runs.

### Tenant lifecycle

| Action | Effect |
|---|---|
| Create | The tenant is active and gets the shared controller's trust anchor |
| Suspend | The tenant's API is locked out and its credentials stop renewing |
| Reactivate | Access is restored |
| Delete | The tenant is soft-deleted; its data is retained |

Suspending is the interesting one. A suspended tenant's nodes cannot renew
their credentials, so their access lapses at the credential's expiry. The
operator can still read the tenant, because the master console has to be
able to show a suspended tenant and offer to reactivate it.

Deleting is a soft delete. The data is retained so a mistake can be
corrected; a separate retention job purges it later.

### Per-tenant quotas

Every tenant has limits on networks, nodes, policies, and relays, and a
credential lifetime cap. The limits are checked before a resource is
created, so a tenant cannot exceed its plan.

### Hybrid deployment

A tenant is either **shared** — it uses the platform's controller and its
trust anchor — or **dedicated**, which has its own controller identity and
its own key. The distinction is carried in the tenant record and affects
which controller key is issued to a node.

### Operator-only master console

The master console requires the operator role. A token without it is
refused. The role is held by exactly one account, and no machine-to-machine
application holds it, so the master console's blast radius is one person.

### Node credential lifecycle

A node enrols with a public key and receives a credential bound to that
key. The credential is short-lived and renewed before it lapses. A revoked
node cannot renew, and a credential replayed from another node is refused
because the binding is checked.

### Audit trail

Every administrative mutation is recorded with the actor that made it, the
tenant it belongs to, and a timestamp. The log is append-only, and a
tenant sees only its own events.

## Not ready

### No data plane

**This is the biggest gap.** The protocol layer is complete and tested —
two nodes handshake, exchange frames, and reject replays — but there is no
TUN device and no packet forwarding. Traffic does not route between nodes.

Everything above is the control plane for a network that cannot yet carry
traffic. A tenant would get a working management console and a working
credential system for a mesh that does not pass packets.

### No Tailscale interoperability

The Tailscale dialect is structurally complete — the framing, the
handshake, the credential format — but its transcript hash is BLAKE3 where
upstream uses BLAKE2s. A `tailscaled` peer will not complete the
handshake. This is a bounded fix: switch the hash, and the `blake2`
crate.

### No metering

The controller counts resources per tenant and enforces quotas, but
nothing records usage over time. There is no byte count, no connection
count, no per-hour or per-day series, so a tenant's invoice cannot be
computed from what the controller knows.

For a shared deployment this is the gap that matters most: the platform
cannot bill.

### No retention job

Deletion is a soft delete and the data is retained. Nothing purges it.
The comment in the model says a separate job does this; that job does not
exist.

### No rate limiting

The API has no rate limiting. A single tenant can consume the
controller's capacity. Quotas bound how many resources a tenant may
*hold*, not how fast it may act.

### No pagination

Every list endpoint returns everything it holds. A tenant with ten
thousand nodes gets ten thousand nodes in one response, and so does the
master console listing every tenant. The `ListResponse` type has a
`nextCursor` field that nothing populates.

### No email, invitations, or password reset

There is no way to invite a tenant's administrator, and no password reset.
Onboarding is manual: an operator creates the account and hands over the
credential.

### No MFA on the operator account

The operator account is protected by a password alone. The provider can do
MFA, and for an account that can delete every tenant it should.

## Where the deployment stands

The control plane is deployed and running:

- `https://zt.hardening.dev` — the console
- `https://admin.prysm.sh/console` — the Verity admin console
- `https://prysm.sh/oidc` — the core issuer, which the console uses

What is verified end to end: an operator signs in, creates a tenant,
creates a network, enrols a node, receives a credential, and the node
adopts it and renews with it over TLS. Suspending the tenant locks it
out and stops the renewal.

## The order I would build the rest in

1. **The data plane.** A TUN device and the forwarding path. Without it
   the product does not carry traffic, and everything else is a console
   around a mesh.
2. **Metering.** Needed before the first shared tenant is billed, and
   cheap to add once the data plane exists, because that is where the
   numbers come from.
3. **The retention job.** A small scheduled task. The soft delete is
   already correct; it just needs something to finish it.
4. **Pagination.** Needed before a tenant's node list is large enough to
   matter.
5. **Tailscale interoperability.** A bounded change, and the point of the
   compatibility work.
6. **Rate limiting, email, MFA.** Each is small on its own.
