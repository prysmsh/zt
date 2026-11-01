//! The data plane: forwarding IP packets between the device and the peers.
//!
//! The node's transport layer knows how to carry an encrypted packet to a
//! peer. This module is the layer above it: it decides **which peer** a
//! packet belongs to, and it moves packets between the virtual interface and
//! the sessions.
//!
//! # The two directions
//!
//! * **Outbound.** A packet the kernel routes to the virtual interface is
//!   read from the device, its destination is looked up, and the packet is
//!   sent to the peer that owns that address.
//!
//! * **Inbound.** A frame a peer sent is written to the device, so the
//!   kernel can route it.
//!
//! # What a node will not do
//!
//! A node only forwards packets for its own networks, and only accepts
//! packets addressed to it. Without those two rules a node is an open relay:
//! any peer could use it to reach the internet, or to reach a third network
//! it has no business knowing about.
//!
//! # Addressing
//!
//! A network has an IPv4 range, and every node in it has one address in
//! that range. The node's own address is what it accepts packets for, and
//! the addresses of its peers are what it sends them to. The protocol
//! address — the ten-byte identifier the handshake binds to — is a separate
//! thing and is not used for routing.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

use zt_crypto::packet::{Packet, TYPE_FRAME};
use zt_tun::PacketDevice;

use crate::{Node, NodeError, Result};

/// How many packets one pass takes from the device.
///
/// The device and the socket both have to be serviced, so an unbounded read
/// would starve the receive loop on a busy interface.
const MAX_BURST: usize = 32;

/// The IPv4 header of a packet, as far as the data plane needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    /// The address the packet came from.
    pub source: Ipv4Addr,
    /// The address the packet is for.
    pub destination: Ipv4Addr,
}

/// Read the addresses out of an IPv4 packet.
///
/// Returns `None` for anything that is not IPv4. The networks are IPv4
/// ranges, so an IPv6 packet has no destination this plane can route, and
/// it is dropped rather than guessed at.
pub fn parse_ipv4(packet: &[u8]) -> Option<Ipv4Header> {
    // The smallest IPv4 header is five 32-bit words.
    if packet.len() < 20 {
        return None;
    }

    // The version is the high nibble of the first byte.
    if packet[0] >> 4 != 4 {
        return None;
    }

    // The header length is the low nibble, in 32-bit words. A header that
    // claims to be longer than the packet is malformed.
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return None;
    }

    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    Some(Ipv4Header {
        source,
        destination,
    })
}

/// An IPv4 range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Network {
    /// The first address of the range.
    pub address: Ipv4Addr,
    /// How many leading bits of an address are fixed.
    pub prefix: u8,
}

impl Ipv4Network {
    /// Build a range, with the address masked to the prefix.
    pub fn new(address: Ipv4Addr, prefix: u8) -> Result<Self> {
        if prefix > 32 {
            return Err(NodeError::InvalidRoute(format!(
                "the prefix length {prefix} is not between 0 and 32"
            )));
        }

        Ok(Self {
            address: Self::mask(address, prefix),
            prefix,
        })
    }

    /// The address with its host bits cleared.
    fn mask(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
        let bits = u32::from(address);
        let keep = u32::MAX << (32 - u32::from(prefix));
        Ipv4Addr::from(bits & keep)
    }

    /// Whether an address falls in the range.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        Self::mask(address, self.prefix) == self.address
    }
}

impl FromStr for Ipv4Network {
    type Err = NodeError;

    /// Parse a range in the `10.88.0.0/24` form.
    fn from_str(text: &str) -> Result<Self> {
        let (address, prefix) = text.split_once('/').ok_or_else(|| {
            NodeError::InvalidRoute(format!("'{text}' is not a range: it has no prefix length"))
        })?;

        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| NodeError::InvalidRoute(format!("'{address}' is not an IPv4 address")))?;

        let prefix: u8 = prefix
            .parse()
            .map_err(|_| NodeError::InvalidRoute(format!("'{prefix}' is not a prefix length")))?;

        Self::new(address, prefix)
    }
}

/// The routes of the networks a node takes part in.
#[derive(Clone, Debug, Default)]
pub struct RouteTable {
    networks: Vec<NetworkRoutes>,
}

/// The routes of one network.
#[derive(Clone, Debug)]
struct NetworkRoutes {
    network: Ipv4Network,
    hosts: HashMap<Ipv4Addr, SocketAddr>,
}

impl RouteTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Take part in a network.
    ///
    /// A node only forwards for the networks it is in, so a network has to
    /// be registered before its addresses can be routed.
    pub fn add_network(&mut self, network: Ipv4Network) {
        if self.networks.iter().any(|entry| entry.network == network) {
            return;
        }

        self.networks.push(NetworkRoutes {
            network,
            hosts: HashMap::new(),
        });
    }

    /// Point an address at a peer.
    ///
    /// The address has to be in one of the registered networks. An address
    /// outside them is a mistake, and refusing it here means the mistake
    /// surfaces at configuration time rather than as packets that go
    /// nowhere.
    pub fn insert(&mut self, address: Ipv4Addr, peer: SocketAddr) -> Result<()> {
        let entry = self
            .networks
            .iter_mut()
            .filter(|entry| entry.network.contains(address))
            .max_by_key(|entry| entry.network.prefix)
            .ok_or_else(|| {
                NodeError::InvalidRoute(format!(
                    "the address {address} is not in any of this node's networks"
                ))
            })?;

        entry.hosts.insert(address, peer);
        Ok(())
    }

    /// Forget every route that points at a peer.
    pub fn remove_peer(&mut self, peer: SocketAddr) {
        for entry in &mut self.networks {
            entry.hosts.retain(|_, target| *target != peer);
        }
    }

    /// The peer that owns an address.
    ///
    /// The most specific network wins, so a node in both a wide and a
    /// narrow range reaches the narrow one.
    pub fn lookup(&self, address: Ipv4Addr) -> Option<SocketAddr> {
        let mut best: Option<(u8, SocketAddr)> = None;

        for entry in &self.networks {
            if !entry.network.contains(address) {
                continue;
            }

            let Some(peer) = entry.hosts.get(&address) else {
                continue;
            };

            let prefix = entry.network.prefix;
            let is_better = match best {
                Some((best_prefix, _)) => prefix > best_prefix,
                None => true,
            };

            if is_better {
                best = Some((prefix, *peer));
            }
        }

        best.map(|(_, peer)| peer)
    }

    /// The address a peer is reachable at, if any.
    pub fn address_of(&self, peer: SocketAddr) -> Option<Ipv4Addr> {
        self.networks
            .iter()
            .flat_map(|entry| entry.hosts.iter())
            .find(|(_, target)| **target == peer)
            .map(|(address, _)| *address)
    }

    /// How many addresses are routed.
    pub fn len(&self) -> usize {
        self.networks.iter().map(|entry| entry.hosts.len()).sum()
    }

    /// Whether nothing is routed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a node has carried since the last count was taken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Bytes received from the peers.
    pub bytes_in: u64,
    /// Bytes sent to the peers.
    pub bytes_out: u64,
    /// Packets received from the peers.
    pub packets_in: u64,
    /// Packets sent to the peers.
    pub packets_out: u64,
}

impl Usage {
    /// The bytes carried in both directions.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }
}

/// The data plane of a node.
pub struct DataPlane {
    device: Box<dyn PacketDevice>,
    routes: RouteTable,
    local: HashMap<Ipv4Addr, ()>,
    /// What the node has carried since the last count was taken.
    usage: Usage,
}

impl DataPlane {
    /// Build a data plane over a device.
    pub fn new(device: Box<dyn PacketDevice>) -> Self {
        Self {
            device,
            routes: RouteTable::new(),
            local: HashMap::new(),
            usage: Usage::default(),
        }
    }

    /// The maximum transmission unit of the device.
    pub fn mtu(&self) -> u16 {
        self.device.mtu()
    }

    /// The routes.
    pub fn routes(&self) -> &RouteTable {
        &self.routes
    }

    /// What the node has carried since the last count was taken.
    pub fn usage(&self) -> Usage {
        self.usage
    }

    /// Take the count, and start again from zero.
    ///
    /// A node reports what it carried and then hands the count over, so
    /// the same bytes are never counted twice.
    pub fn take_usage(&mut self) -> Usage {
        std::mem::take(&mut self.usage)
    }

    /// Take part in a network.
    pub fn add_network(&mut self, network: Ipv4Network) {
        self.routes.add_network(network);
    }

    /// Take part in a network, given its range in the `10.88.0.0/24` form.
    pub fn add_network_str(&mut self, cidr: &str) -> Result<()> {
        self.add_network(cidr.parse()?);
        Ok(())
    }

    /// Claim an address for this node.
    ///
    /// Only packets addressed here are accepted from the peers.
    pub fn add_local_address(&mut self, address: Ipv4Addr) -> Result<()> {
        if !self
            .routes
            .networks
            .iter()
            .any(|entry| entry.network.contains(address))
        {
            return Err(NodeError::InvalidRoute(format!(
                "the address {address} is not in any of this node's networks"
            )));
        }

        self.local.insert(address, ());
        Ok(())
    }

    /// Point an address at a peer.
    pub fn set_route(&mut self, address: Ipv4Addr, peer: SocketAddr) -> Result<()> {
        self.routes.insert(address, peer)
    }

    /// Forget every route that points at a peer.
    pub fn remove_peer(&mut self, peer: SocketAddr) {
        self.routes.remove_peer(peer);
    }

    /// Whether an address belongs to this node.
    pub fn is_local(&self, address: Ipv4Addr) -> bool {
        self.local.contains_key(&address)
    }

    /// Read packets from the device and send them to their peers.
    ///
    /// Returns how many packets were forwarded. A packet with a destination
    /// this node does not know is dropped: the kernel may have routes the
    /// overlay does not, and the overlay is not a gateway.
    pub fn forward_outbound(&mut self, node: &mut Node) -> Result<usize> {
        let mut buffer = vec![0u8; self.device.mtu() as usize];
        let mut forwarded = 0;

        while forwarded < MAX_BURST {
            let count = match self.device.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            };

            let Some(header) = parse_ipv4(&buffer[..count]) else {
                continue;
            };

            let Some(peer) = self.routes.lookup(header.destination) else {
                continue;
            };

            // The peer may not have a session yet. The packet is dropped
            // rather than queued: the topology layer is what establishes
            // sessions, and it has no way to know a packet is worth
            // keeping.
            let packet = Packet::new(TYPE_FRAME, buffer[..count].to_vec());
            if node.send(peer, &packet).is_err() {
                continue;
            }

            self.usage.bytes_out += count as u64;
            self.usage.packets_out += 1;
            forwarded += 1;
        }

        Ok(forwarded)
    }

    /// Write the frames a peer sent to the device.
    ///
    /// A frame is only written when it is addressed to this node and it
    /// came from the peer that owns the source address. Anything else is
    /// dropped: a node is not a relay for packets it did not ask for.
    pub fn forward_inbound(&mut self, from: SocketAddr, frames: &[Packet]) -> Result<usize> {
        let mut written = 0;

        for frame in frames {
            if frame.packet_type != TYPE_FRAME {
                continue;
            }

            let Some(header) = parse_ipv4(&frame.payload) else {
                continue;
            };

            if !self.is_local(header.destination) {
                continue;
            }

            // The source has to be the address of the peer that sent it,
            // or a peer could claim to be anyone.
            let Some(source) = self.routes.address_of(from) else {
                continue;
            };

            if source != header.source {
                continue;
            }

            if self.device.write(&frame.payload).is_err() {
                continue;
            }

            self.usage.bytes_in += frame.payload.len() as u64;
            self.usage.packets_in += 1;
            written += 1;
        }

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// The packets a device was given.
    type Written = Arc<Mutex<Vec<Vec<u8>>>>;

    /// A device that hands out the packets it was given, in reverse.
    #[derive(Default)]
    struct LoopDevice {
        outbound: Vec<Vec<u8>>,
        written: Written,
        mtu: u16,
    }

    impl LoopDevice {
        /// A device that records what is written to it.
        ///
        /// The record of what was written is handed back, so the test can
        /// look at it without reaching into the device.
        #[allow(clippy::new_ret_no_self)]
        fn recording(mtu: u16) -> (Box<dyn PacketDevice>, Written) {
            let written: Written = Arc::new(Mutex::new(Vec::new()));
            (
                Box::new(Self {
                    outbound: Vec::new(),
                    written: written.clone(),
                    mtu,
                }),
                written,
            )
        }
    }

    impl PacketDevice for LoopDevice {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let Some(packet) = self.outbound.pop() else {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet"));
            };

            let count = packet.len().min(buffer.len());
            buffer[..count].copy_from_slice(&packet[..count]);
            Ok(count)
        }

        fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
            self.written.lock().unwrap().push(packet.to_vec());
            Ok(packet.len())
        }

        fn mtu(&self) -> u16 {
            self.mtu
        }
    }

    /// Build an IPv4 packet with the given addresses.
    fn ipv4(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet
    }

    #[test]
    fn the_addresses_are_read_out_of_a_packet() {
        let packet = ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        let header = parse_ipv4(&packet).expect("header");
        assert_eq!(header.source, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(header.destination, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn a_packet_that_is_not_ipv4_is_refused() {
        // An IPv6 packet.
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        assert!(parse_ipv4(&packet).is_none());

        // Too short.
        assert!(parse_ipv4(&[0x45, 0, 0, 0]).is_none());

        // A header that claims to be longer than the packet.
        let mut packet = vec![0u8; 20];
        packet[0] = 0x4f;
        assert!(parse_ipv4(&packet).is_none());
    }

    #[test]
    fn a_range_is_parsed_and_masked() {
        let network: Ipv4Network = "10.88.0.7/24".parse().expect("range");
        assert_eq!(network.address, Ipv4Addr::new(10, 88, 0, 0));
        assert_eq!(network.prefix, 24);
        assert!(network.contains(Ipv4Addr::new(10, 88, 0, 200)));
        assert!(!network.contains(Ipv4Addr::new(10, 89, 0, 1)));
    }

    #[test]
    fn a_range_without_a_prefix_is_refused() {
        assert!("10.88.0.0".parse::<Ipv4Network>().is_err());
        assert!("10.88.0.0/33".parse::<Ipv4Network>().is_err());
        assert!("not an address/24".parse::<Ipv4Network>().is_err());
    }

    #[test]
    fn an_address_outside_the_networks_is_refused() {
        let mut routes = RouteTable::new();
        routes.add_network("10.88.0.0/24".parse().unwrap());
        assert!(routes
            .insert(
                Ipv4Addr::new(10, 99, 0, 1),
                "127.0.0.1:9994".parse().unwrap()
            )
            .is_err());
    }

    #[test]
    fn the_most_specific_network_wins() {
        let mut routes = RouteTable::new();
        routes.add_network("10.0.0.0/8".parse().unwrap());
        routes.add_network("10.88.0.0/24".parse().unwrap());

        let wide: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let narrow: SocketAddr = "127.0.0.1:2".parse().unwrap();

        routes.insert(Ipv4Addr::new(10, 1, 2, 3), wide).unwrap();
        routes.insert(Ipv4Addr::new(10, 88, 0, 5), narrow).unwrap();

        assert_eq!(routes.lookup(Ipv4Addr::new(10, 1, 2, 3)), Some(wide));
        assert_eq!(routes.lookup(Ipv4Addr::new(10, 88, 0, 5)), Some(narrow));
        assert_eq!(routes.lookup(Ipv4Addr::new(10, 88, 0, 6)), None);
    }

    #[test]
    fn a_peer_can_be_forgotten() {
        let mut routes = RouteTable::new();
        routes.add_network("10.88.0.0/24".parse().unwrap());

        let peer: SocketAddr = "127.0.0.1:9994".parse().unwrap();
        routes.insert(Ipv4Addr::new(10, 88, 0, 5), peer).unwrap();
        assert_eq!(routes.len(), 1);

        routes.remove_peer(peer);
        assert!(routes.is_empty());
        assert_eq!(routes.lookup(Ipv4Addr::new(10, 88, 0, 5)), None);
    }

    #[test]
    fn a_frame_for_someone_else_is_not_written() {
        let (device, written) = LoopDevice::recording(1400);
        let mut plane = DataPlane::new(device);
        plane.add_network_str("10.88.0.0/24").unwrap();
        plane
            .add_local_address(Ipv4Addr::new(10, 88, 0, 1))
            .unwrap();

        let peer: SocketAddr = "127.0.0.1:9994".parse().unwrap();
        plane.set_route(Ipv4Addr::new(10, 88, 0, 2), peer).unwrap();

        // A frame for a host that is not this node.
        let frame = Packet::new(
            TYPE_FRAME,
            ipv4(Ipv4Addr::new(10, 88, 0, 2), Ipv4Addr::new(10, 88, 0, 9)),
        );
        let count = plane.forward_inbound(peer, &[frame]).unwrap();
        assert_eq!(count, 0, "the frame should not have been written");
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn a_frame_that_claims_the_wrong_source_is_not_written() {
        let (device, written) = LoopDevice::recording(1400);
        let mut plane = DataPlane::new(device);
        plane.add_network_str("10.88.0.0/24").unwrap();
        plane
            .add_local_address(Ipv4Addr::new(10, 88, 0, 1))
            .unwrap();

        let peer: SocketAddr = "127.0.0.1:9994".parse().unwrap();
        let other: SocketAddr = "127.0.0.1:9995".parse().unwrap();
        plane.set_route(Ipv4Addr::new(10, 88, 0, 2), peer).unwrap();
        plane.set_route(Ipv4Addr::new(10, 88, 0, 3), other).unwrap();

        // The frame says it came from the third host, but the second host
        // sent it.
        let frame = Packet::new(
            TYPE_FRAME,
            ipv4(Ipv4Addr::new(10, 88, 0, 3), Ipv4Addr::new(10, 88, 0, 1)),
        );
        let count = plane.forward_inbound(peer, &[frame]).unwrap();
        assert_eq!(count, 0, "the frame should not have been written");
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn a_frame_for_this_node_is_written() {
        let (device, written) = LoopDevice::recording(1400);
        let mut plane = DataPlane::new(device);
        plane.add_network_str("10.88.0.0/24").unwrap();
        plane
            .add_local_address(Ipv4Addr::new(10, 88, 0, 1))
            .unwrap();

        let peer: SocketAddr = "127.0.0.1:9994".parse().unwrap();
        plane.set_route(Ipv4Addr::new(10, 88, 0, 2), peer).unwrap();

        let packet = ipv4(Ipv4Addr::new(10, 88, 0, 2), Ipv4Addr::new(10, 88, 0, 1));
        let frame = Packet::new(TYPE_FRAME, packet.clone());
        let count = plane.forward_inbound(peer, &[frame]).unwrap();
        assert_eq!(count, 1);

        assert_eq!(*written.lock().unwrap(), vec![packet]);
    }
}
