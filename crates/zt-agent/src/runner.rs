//! The node's data plane.
//!
//! The agent owns the node's identity and its credential. The runner turns
//! those into a running node: it opens the virtual interface, asks the
//! controller for the topology, connects to the peers, and forwards packets
//! between the interface and the sessions.
//!
//! # The loop
//!
//! One pass does three things, in this order:
//!
//! 1. Whatever arrived on the socket is handed to the node, and the frames
//!    it produced are written to the interface.
//! 2. Whatever the interface holds is read and sent to the peer that owns
//!    the destination.
//! 3. The peers that are not connected yet are given another handshake,
//!    and the topology is refreshed when it is due.
//!
//! The order matters. A frame that arrives is written to the interface
//! before the interface is read, so a packet that goes out and comes back
//! is not missed.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use zt_crypto::handshake_flow::{PeerStatic, StaticIdentity};
use zt_crypto::membership::{ControllerTrust, Membership};
use zt_crypto::pq::{KemSuite, SigSuite};
use zt_node::dataplane::DataPlane;
use zt_node::Node;
use zt_tun::PacketDevice;

use crate::client::{ControllerClient, Topology, TopologyPeer};
use crate::error::{AgentError, Result};

/// How the runner is set up.
#[derive(Clone, Debug)]
pub struct RunnerConfig {
    /// The name of the interface to open.
    pub interface: String,
    /// The maximum transmission unit.
    pub mtu: u16,
    /// The address the node listens on.
    pub listen: SocketAddr,
    /// How often the topology is refreshed.
    pub refresh_interval: Duration,
    /// How often a handshake is retried.
    pub handshake_interval: Duration,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            interface: "zt0".into(),
            mtu: 1400,
            listen: SocketAddr::from(([0, 0, 0, 0], 9994)),
            refresh_interval: Duration::from_secs(30),
            handshake_interval: Duration::from_secs(5),
        }
    }
}

/// A peer the node knows about.
#[derive(Clone, Debug)]
struct PeerRoute {
    /// The peer's address in the network's range.
    address: Ipv4Addr,
    /// The peer's keys.
    static_key: PeerStatic,
    /// Where the peer can be reached.
    endpoint: SocketAddr,
}

/// The node's data plane.
pub struct Runner {
    node: Node,
    plane: DataPlane,
    client: ControllerClient,
    config: RunnerConfig,
    peers: BTreeMap<Ipv4Addr, PeerRoute>,
    last_refresh: Option<Instant>,
}

impl Runner {
    /// Build a runner over a device.
    ///
    /// The device is a parameter, so the runner can be exercised without a
    /// kernel interface.
    pub fn new(
        device: Box<dyn PacketDevice>,
        client: ControllerClient,
        identity: StaticIdentity,
        membership: Membership,
        trust: ControllerTrust,
        config: RunnerConfig,
    ) -> Result<Self> {
        let socket = std::net::UdpSocket::bind(config.listen)
            .map_err(|error| AgentError::Io(error.to_string()))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|error| AgentError::Io(error.to_string()))?;

        let mut node = Node::from_socket(socket, identity)
            .map_err(|error| AgentError::Crypto(error.to_string()))?;
        node.set_suites(
            KemSuite::HybridX25519MlKem768,
            SigSuite::HybridEd25519MlDsa65,
        );
        node.set_membership(membership);
        // The trust anchor is what lets the node check the credential a
        // peer presents, so a handshake can complete.
        node.set_trust(trust);

        let plane = DataPlane::new(device);

        Ok(Self {
            node,
            plane,
            client,
            config,
            peers: BTreeMap::new(),
            last_refresh: None,
        })
    }

    /// The node's data plane.
    pub fn plane(&self) -> &DataPlane {
        &self.plane
    }

    /// The address the node listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.node.local_addr()
    }

    /// Ask the controller for the topology and apply it.
    ///
    /// The node's own address, the range it lives in, and the peers it
    /// shares the range with. A peer that has not reported an endpoint is
    /// left out: there is nowhere to send its packets.
    pub fn refresh_topology(&mut self) -> Result<()> {
        let topology = self.client.topology()?;

        self.apply_topology(&topology)?;
        self.last_refresh = Some(Instant::now());
        Ok(())
    }

    /// Apply a topology to the routing table.
    fn apply_topology(&mut self, topology: &Topology) -> Result<()> {
        // The network is registered once. A later topology that names the
        // same range is the same network.
        if self.plane.routes().is_empty() {
            self.plane.add_network_str(&topology.cidr)?;
        }

        let address: Ipv4Addr = topology.address.parse().map_err(|_| {
            AgentError::InvalidConfig("the topology address is not an IPv4 address".into())
        })?;

        if !self.plane.is_local(address) {
            self.plane.add_local_address(address)?;
        }

        let mut peers = BTreeMap::new();

        for peer in &topology.peers {
            let Some(route) = peer_route(peer)? else {
                continue;
            };

            // The route is only useful if the peer is reachable. A peer
            // whose endpoint is unknown is left out, and the topology is
            // refreshed until it reports one.
            self.plane.set_route(route.address, route.endpoint)?;
            peers.insert(route.address, route);
        }

        // A peer that is gone is forgotten, so a stale route cannot hold a
        // packet that will never be delivered.
        let gone: Vec<Ipv4Addr> = self
            .peers
            .keys()
            .filter(|address| !peers.contains_key(*address))
            .copied()
            .collect();

        for address in gone {
            self.peers.remove(&address);
        }

        self.peers = peers;
        Ok(())
    }

    /// Report how the node's peers reach it.
    pub fn report_presence(&self, pq_public_key: &str) -> Result<()> {
        let endpoint = self.node.local_addr().to_string();
        self.client.report_presence(&endpoint, pq_public_key)?;
        Ok(())
    }

    /// Whether a peer has a session.
    pub fn is_connected(&self, endpoint: SocketAddr) -> bool {
        self.node.is_connected(&endpoint)
    }

    /// Give the peers that are not connected a handshake.
    ///
    /// Returns how many handshakes were started.
    pub fn connect_peers(&mut self) -> Result<usize> {
        let mut started = 0;

        for peer in self.peers.values() {
            if self.node.is_connected(&peer.endpoint) {
                continue;
            }

            if self
                .node
                .connect(peer.endpoint, peer.static_key.clone())
                .is_ok()
            {
                started += 1;
            }
        }

        Ok(started)
    }

    /// One pass of the forwarding loop.
    ///
    /// Returns how many packets were forwarded in each direction.
    pub fn poll(&mut self) -> Result<(usize, usize)> {
        let mut received = 0usize;
        let mut buffer = [0u8; 65536];

        // Whatever arrived is handled first, so a frame is written to the
        // interface before the interface is read.
        while let Ok((count, from)) = self.node.socket_mut().recv_from(&mut buffer) {
            let Ok(packets) = self.node.handle_datagram(&buffer[..count], from) else {
                continue;
            };

            received += self.plane.forward_inbound(from, &packets)?;
        }

        let sent = self.plane.forward_outbound(&mut self.node)?;
        Ok((received, sent))
    }

    /// Run until the process is stopped.
    ///
    /// The loop refreshes the topology when it is due and retries the
    /// handshakes that have not completed.
    pub fn run(&mut self) -> Result<()> {
        // The first pass brings the topology in, so the interface knows
        // which network it is on before any packet arrives.
        self.refresh_topology()?;
        self.connect_peers()?;

        loop {
            self.poll()?;

            let now = Instant::now();

            let due = match self.last_refresh {
                Some(last) => now.duration_since(last) >= self.config.refresh_interval,
                None => true,
            };

            if due {
                // A failure to refresh is not fatal: the runner keeps the
                // topology it has and tries again on the next pass.
                let _ = self.refresh_topology();
            }

            let _ = self.connect_peers();

            std::thread::sleep(self.config.handshake_interval);
        }
    }
}

/// Turn a topology peer into a route, when it has an endpoint.
fn peer_route(peer: &TopologyPeer) -> Result<Option<PeerRoute>> {
    let Some(endpoint) = &peer.endpoint else {
        return Ok(None);
    };

    let address: Ipv4Addr = peer
        .address
        .parse()
        .map_err(|_| AgentError::InvalidConfig("a peer address is not an IPv4 address".into()))?;

    let endpoint: SocketAddr = endpoint.parse().map_err(|_| {
        AgentError::InvalidConfig(format!("the peer endpoint '{endpoint}' is not an address"))
    })?;

    let ed25519: [u8; 32] = hex::decode(&peer.public_key)
        .map_err(|_| AgentError::InvalidConfig("a peer key is not valid hex".into()))?
        .try_into()
        .map_err(|_| AgentError::InvalidConfig("a peer key must be 32 bytes".into()))?;

    let ml_dsa = hex::decode(&peer.pq_public_key)
        .map_err(|_| AgentError::InvalidConfig("a peer key is not valid hex".into()))?;

    Ok(Some(PeerRoute {
        address,
        static_key: PeerStatic { ed25519, ml_dsa },
        endpoint,
    }))
}
