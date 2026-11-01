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

A node can also join by request. The host asks with its public keys
alone, sits in pending with no access, and the operator approves it from
the console. The host then collects its credential by polling with a
signature over its own identifier, made with the key it joined with —
so only the holder of the private key can collect, and the console never
handles the credential. Both paths end in the same place: a short-lived
credential bound to the node's key.

### Audit trail

Every administrative mutation is recorded with the actor that made it, the
tenant it belongs to, and a timestamp. The log is append-only, and a
tenant sees only its own events.

## Not ready

### The data plane is not finished

The forwarding path is there and tested. A node reads an IP packet from
its virtual interface, looks up the peer that owns the destination, sends
it over the session, and writes the frames the peers send back to the
interface. The test drives two nodes over real UDP sockets and watches a
packet cross the overlay and land on the other device.

The wiring around it is there too. The controller assigns every node an
IPv4 address out of its network's range when it enrols, and hands each
node a topology: its own address, the range it lives in, and the peers it
shares the range with, each with the keys and the endpoint it needs to
reach them. The node agent opens the interface, reports how its peers
reach it, asks for the topology, completes the handshakes, and forwards.

The test drives two node agents against a real controller over HTTP, and
watches a packet cross the overlay and land on the other node's device.

What is still missing:

- **The interface is not configured.** The TUN crate opens the device,
  but the address, the route, and bringing it up are left to the
  operating system. A deployment has to configure the interface before
  the agent runs.
- **The topology is fetched on a timer, not on a change.** A node learns
  about a new peer when it next asks, not the moment the peer appears.
- **There is no relay.** A node can only reach a peer it has a route to.
  A peer behind a NAT that cannot be reached directly is out of reach.

So traffic routes between nodes that can reach each other, but the
deployment still needs the interface set up by hand, and a node cannot
reach a peer it has no route to.

### No Tailscale interoperability, end to end

The dialect now matches upstream exactly. The hash is BLAKE2s, the key
schedule is HMAC-BLAKE2s, the transcript is a chain, and the handshake
messages are framed exactly. The interoperability test replays a handshake
captured from the Linux kernel's WireGuard implementation and reproduces
the response that implementation accepted, byte for byte, including the
authentication tag.

What is not proven is a live session with a `tailscaled` peer: the control
plane that `tailscaled` expects has not been stood up, so there is nothing
to point it at. The protocol is the part that was open, and it is closed.

### Taking payment

The numbers a tenant is charged for now exist. The data plane counts the
bytes and the packets it carries, the node agent reports them with its
sightings, and the controller keeps the samples. From those it works out
the node-hours — the integral of the node count over the period — and
multiplies them by the tenant's rates. The master console shows what each
tenant owes, and a tenant can ask for its own invoice.

The invoice is computed and prorated: a plan change applies the old
rates for the elapsed time and the new rates for the rest. What is
missing is **taking the money** — a payment provider, the dunning, and
the collection side that turns an invoice into a debt and then into a
receipt.







### No email, invitations, or password reset

There is no way to invite a tenant's administrator, and no password reset.
Onboarding is manual: an operator creates the account and hands over the
credential.

### No MFA on the operator account

The operator account is protected by a password alone. The provider can do
MFA, and for an account that can delete every tenant it should.

## Where the deployment stands

The control plane is deployed and running:

- `https://zt.hardening.dev` — the landing page
- `https://zt.hardening.dev/console` — the console
- `https://admin.prysm.sh/console` — the Verity admin console
- `https://prysm.sh/oidc` — the core issuer, which the console uses

What is verified end to end: an operator signs in, creates a tenant,
creates a network, enrols a node, receives a credential, and the node
adopts it and renews with it over TLS. Suspending the tenant locks it
out and stops the renewal. And two node agents, against a real
controller, complete a handshake and carry a packet across the overlay.

## The order I would build the rest in

1. **The data plane.** The forwarding path, the addressing, and the
   topology are done. What is left is the deployment: the interface has
   to be configured, and a node needs a way to reach a peer it has no
   route to. Without it the product does not carry traffic, and
   everything else is a console around a mesh.
2. **Taking payment.** The invoice is computed; it is not collected.
   A payment provider, the proration rules, and the dunning are what
   stand between the numbers and an invoice that gets paid.
3. **The retention job.** A small scheduled task. The soft delete is
   already correct; it just needs something to finish it.
4. **Pagination.** Needed before a tenant's node list is large enough to
   matter.
5. **Tailscale interoperability.** The protocol is done; what is left is
   the control plane a `tailscaled` peer can be pointed at.
6. **Rate limiting, email, MFA.** Each is small on its own.
