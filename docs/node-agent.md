# The node agent

The agent is the piece that connects ZT-next's control plane to its data
plane. It runs on every node and does four things:

1. Holds the node's long-term Ed25519 identity.
2. Enrolls with a controller and stores the issued credential.
3. Renews the credential before it expires.
4. Supplies the membership material the handshake needs.

## Why it is separate from `zt-node`

`zt-node` is the transport and session layer. It knows nothing about
controllers and has no HTTP dependencies. The agent sits above it and
supplies the membership that the handshake consumes.

Keeping them apart means the protocol core stays small enough to audit, and
the control-plane concerns — HTTP, JSON, credential storage, clock skew —
stay in one crate.

## Using it

```console
$ zt-agent identity --controller http://127.0.0.1:8080 --tenant acme
public key: 13d138a07826b5519258196497d3a243b9a8f3d5a287b90d4ad0c289bbe9af18
state:      zt-node.json

$ zt-agent enroll --controller http://127.0.0.1:8080 --tenant acme \
      --network 3f9506c4-7710-483d-bcfc-9a6b9630818d --name web-01
Enrolled web-01 in network 3f9506c4-7710-483d-bcfc-9a6b9630818d
  node id:   0d32c965-7de5-4f30-ac67-4ce0776e1683
  address:   94e4bef4fcc70214ffa3
  expires:   2026-11-02 07:25:03
  state:     zt-node.json

$ zt-agent status --controller http://127.0.0.1:8080 --tenant acme
Node 0d32c965-7de5-4f30-ac67-4ce0776e1683
  network:   3f9506c4-7710-483d-bcfc-9a6b9630818d
  identity:  c6c2c340d73d4e2e8dddeddb32b2d3631e399cb5eb34fcb1375275365a875862
  expires:   2026-11-02 07:25:03
  remaining: 23h 59m
  status:    healthy

$ zt-agent renew --controller http://127.0.0.1:8080 --tenant acme
Renewed credential for web-01
  expires:   2026-11-02 07:25:10
```

### Commands

| Command | What it does |
|---|---|
| `enroll` | Register with a controller and store the credential |
| `join` | Ask to join and wait for the operator to approve |
| `adopt` | Store a credential an operator issued for this node |
| `renew` | Renew the credential, if it is due |
| `status` | Show enrollment state and credential expiry |
| `identity` | Print the node's public key |
| `checkin` | Tell the controller the node is here, and fetch the topology |
| `run` | Carry traffic: open the interface and forward packets |

### Options

| Option | Meaning |
|---|---|
| `--controller <URL>` | Controller base URL. Default `http://127.0.0.1:8080` |
| `--tenant <SLUG>` | Tenant to belong to. A slug or an ID both work |
| `--network <ID>` | Network to join |
| `--name <NAME>` | Human-readable node name |
| `--tags <A,B>` | Comma-separated tags |
| `--state <PATH>` | State file path. Default `zt-node.json` |
| `--force` | Renew even when the credential is not yet due |
| `--interval <SECONDS>` | Repeat the check-in every so many seconds |
| `--interface <NAME>` | Interface to open for the data plane. Default `zt0` |
| `--listen <ADDR:PORT>` | Address the node listens on. Default `0.0.0.0:9994` |

## Checking in

The console shows a node as online while it keeps hearing from it, and as
offline once it stops. A node checks in by reporting its presence and
asking for the topology.

```text
$ zt-agent checkin --controller https://zt.example.dev --tenant acme \
    --interval 30
Checked in as 10.42.0.7 in 10.42.0.0/24
  peers:   3
```

Without an interval it checks in once and prints what it learned. With one
it keeps checking in, which is what a node that carries the control plane
but not the traffic runs.

`deploy/zt-agent.service` is that as a systemd unit.

## Renewing the credential

A credential is short-lived. The controller stamps an expiry on it, and a
node whose credential has expired is refused: it falls off the mesh.

The agent renews on its own, without an operator asking. Both long-running
modes do it on every tick:

- `checkin` renews before it reports its presence.
- `run` renews before it refreshes the topology, and puts the new
  credential into the membership the node presents to its peers.

A renewal replaces the credential, so everything derived from it has to
follow: the credential the agent presents to the controller, the state on
disk, and the membership the node hands to a peer. A node that renewed but
kept the old membership would be offering a credential the controller has
already replaced, and its peers would refuse it.

### When the renewal comes due

The credential is renewed once **three quarters** of its life has elapsed
(the fraction is `renew_after_fraction` in the agent's configuration). That
leaves the last quarter as a margin: a controller that is briefly
unreachable is retried on the next tick, and the node still has a
credential that is good for hours rather than minutes.

The age is measured from the credential's **own issue time**, which the
controller stamped on it. It is not reconstructed from the remaining
time, because that only works while the lifetime never changes — and it
is wrong the moment the controller issues a credential with a different
TTL, which is what an operator does when they shorten a network's TTL to
test a renewal.

The same fraction is what the console uses to decide whether a credential
is worth an operator's attention. If the console warned sooner than the
agent renews, the warning would be on permanently: the agent renews on its
own schedule, and no operator action can make it renew sooner.

## Carrying traffic

`zt-agent run` is the data plane. It opens the virtual interface, tells
the controller how its peers reach it, asks for the topology, completes
the handshakes, and forwards packets between the interface and the peers.

```text
$ zt-agent run --controller https://zt.example.dev --tenant acme \
    --interface zt0 --listen 0.0.0.0:9994
```

The interface has to be configured by the operating system before the
agent runs: the address, the route, and bringing it up. The agent opens
the device and asks for no privilege.

The topology is what makes that work. The controller assigns the node an
address in its network's range when it enrols, and hands the node the
addresses and the endpoints of its peers. A node is told nothing about
any other network or tenant.

The interface the agent opens is a queue rather than a kernel device in
the tests, so the data plane is exercised without privileges. The test
drives two agents against a real controller and watches a packet cross
the overlay.

## How a node authenticates

A node holds no secret. It authenticates with the **credential the
controller issued it**, presented as a bearer token.

The credential is signed by the controller and bound to the node's own
Ed25519 key. The controller verifies the signature with its own public
key, checks the credential has not expired, and checks the binding. A
credential replayed from another node fails the binding check, so it is
useless.

A node's credential reaches **its own tenant** and nothing else. It cannot
reach the master console, and it cannot reach another tenant.

### Joining a controller that requires authentication

A node cannot enrol itself against an authenticated controller: it has no
credential yet, so it has nothing to authenticate with. The flow is:

1. The operator enrols the node from the console, which issues the
   credential and shows it once.
2. The node adopts it:

```console
$ zt-agent adopt --controller https://zt.example.dev --tenant acme \
    --credential 01df775733c32d178bdd8…
Adopted the credential for web-01
  node id:   0d32c965-7de5-4f30-ac67-4ce0776e1683
  network:   3f9506c4-7710-483d-bcfc-9a6b9630818d
  address:   94e4bef4fcc70214ffa3
  expires:   2026-11-02 07:25:03
```

3. The node asks the controller who it is, which is how it learns its own
   identifier for renewal. The credential authenticates that call.

`zt-agent enroll` remains for controllers that permit a node to enrol
itself, such as a first-run controller on a private network.

## Joining by request

The copy-a-key flow above needs the operator to touch both machines. The
join flow removes the copy: the host asks, the operator decides, and the
host collects its credential on its own.

```console
$ zt-agent join --controller https://zt.example.dev \
    --tenant acme --network <network-id> --name laptop-01
Asked to join acme — waiting for the operator to approve it in the console...
Joined laptop-01 in network 3f9506c4-7710-483d-bcfc-9a6b9630818d
  node id:   0d32c965-7de5-4f30-ac67-4ce0776e1683
  address:   94e4bef4fcc70214ffa3
  state:     /home/user/zt-node.json
```

On the console's Nodes page the host appears as pending with an Approve
button. Approving marks the node as accepted; the waiting host then polls
with a signature over its own identifier, made with the key it joined
with, and collects a credential bound to that same key. The console never
handles the credential, and a host whose operator says no simply stays
pending with no access at all.

The poll signature is what makes the exchange safe to leave open: knowing
the tenant slug and the network identifier lets a host *ask*, but only the
holder of the private key can *collect*.

## The HTTP client

The client is [ureq](https://docs.rs/ureq), with rustls for TLS. The
controller is normally reached over HTTPS through a reverse proxy, so the
client speaks TLS and follows redirects.

## The trust anchor

On first run the agent fetches the controller's public key from
`GET /api/v1/controller` and pins it in the state file. Every credential the
agent accepts afterwards must be signed by that key.

This is what makes the agent safe against a hostile or spoofed controller.
The pin happens once, at enrollment, and is never renegotiated. If the
controller's key changes, the node stops working — deliberately — rather
than silently trusting the new key.

The controller's identifier is pinned alongside the key.

## The state file

The state file holds the node's private key seed, so it is written with
owner-only permissions (`0600`) and replaced atomically through a
temporary file. A crash cannot leave a half-written state behind.

```json
{
  "identity_seed": "918a527b8dcce54b375aa2baa09e7dc1dfe68b3f0954db024ba152360c4a5d65",
  "controller_key": "a52004ce52aa2d79d6c6cf58011553c421efab42e0625bdd3da7863cb351dd7e",
  "controller_id": "a9c0865d93297273ff49a9fe0ad3e911",
  "node_id": "0d32c965-7de5-4f30-ac67-4ce0776e1683",
  "network_id": "3f9506c4-7710-483d-bcfc-9a6b9630818d",
  "credential": "01df7757...",
  "credential_not_after": 1793604303
}
```

## Renewal

Credentials are short-lived — 24 hours by default. The agent renews once
three quarters of the lifetime has elapsed, which leaves room for a retry
if the controller is briefly unavailable.

Renewal is idempotent in the sense that matters: the new credential
replaces the old one in the same atomic write, so a crash mid-renewal
leaves the node with a valid credential rather than none.

## Credential-gated handshakes

The agent's credential is not just bookkeeping. It is presented in the
handshake's first message and bound into the handshake transcript, so it
cannot be swapped after the fact.

On the receiving side, the responder:

1. Parses the presented membership.
2. Checks each credential is bound to the peer's own static key. This
   rejects a replayed credential from a different node.
3. Checks each credential was signed by a trusted controller and has not
   expired.
4. Only then derives traffic keys.

A peer that presents nothing is refused when the node requires membership,
which is the default for a node that belongs to a network.

```
Initiator                                Responder
   │                                         │
   ├── msg1 ────────────────────────────────▶│
   │    e, s, mlkem_ek, membership, payload   │
   │                                         │  ← verify membership here
   │◀── msg2 ────────────────────────────────┤
   │    e, mlkem_ct, payload                 │
   │                                         │
   ├── traffic keys derived ───────────────┤
```

Because the membership is mixed into the transcript hash before the
signature is computed, changing the credentials invalidates the
signature. A man in the middle cannot substitute their own credential.

## The HTTP client

The agent uses a small blocking HTTP client over `std::net::TcpStream`. It
reads the response against its `Content-Length` rather than waiting for the
connection to close, because a server that half-closes leaves the socket
readable until the read timeout fires, which would surface as a spurious
error.

The controller is a local service in the intended deployment, so the
simplicity is worth more than the performance.

## Testing

```console
$ cargo test -p zt-agent
```

The integration tests in `tests/controller_integration.rs` start a real
controller on a loopback port and drive the agent against it over HTTP.
They cover enrollment, renewal, slug resolution, cross-tenant isolation,
and rejection of credentials from an untrusted controller.

> The tests use a multi-threaded Tokio runtime. The agent's HTTP client is
> blocking, so a single-threaded runtime would starve the server task.
