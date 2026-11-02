ZT-next controller, console, and orchestration
=============================================

Copyright (C) 2026 the ZT-next authors.

The crates listed below, and the console under `apps/`, are licensed under
a dual licence. You may use them under either of the two terms:

  * the GNU Affero General Public License, version 3 — see LICENSE-CONTROLLER
    for the full text; or

  * a commercial licence, available on request.

    Self-hosting ZT-next under the AGPL requires no licence fee and no
    negotiation. The commercial licence exists for deployments that do not
    want the AGPL's copyleft obligations to reach the code they expose over
    a network.

The AGPL was chosen over the GPL because these crates are server-side: the
obligation it adds, that a modified version offered over a network must
publish its source, is the one that matters for a control plane.

The crates under this licence:

  crates/zt-controller/   Control plane: networks, nodes, policies, relays,
                          credential issuance
  crates/zt-agent/        Node agent: enrollment, credential renewal,
                          membership
  crates/zt-node/         Node: UDP transport, peer management, data path
  crates/zt-tun/          Linux TUN device for the data plane
  crates/zt-legacy/       Foreign-protocol dialects: WireGuard/Tailscale,
                          legacy ZeroTier
  apps/console/           The operator console

The protocol core is under the Mozilla Public License, version 2.0 — see
LICENSE for the full text:

  crates/zt-crypto/       Cryptographic primitives and key types
  crates/zt-testvectors/  Golden vectors and the validation harness

The core is MPL-2.0 because it is the part meant to be reused. A
commercial implementation of the protocol, or an implementation in another
language, may build on it under the MPL's file-level copyleft, which asks
only that changes to the MPL files themselves be published.

The two licences meet at the crate boundary: the commercial half depends
on the core, not the other way round.
