//! The data plane over real UDP sockets.
//!
//! Two nodes talk to each other over the loopback interface with the real
//! protocol: the handshake, the encryption, and the replay protection all
//! run over the wire. What is faked is only the network interface, which
//! is a queue instead of a kernel device, so the test needs no privileges.
//!
//! The point of the test is the whole path: a packet read from the device
//! is routed to the peer that owns its destination, encrypted, sent,
//! decrypted, and written to the other node's device.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use zt_crypto::handshake_flow::{PeerStatic, StaticIdentity};
use zt_crypto::identity::Identity;
use zt_crypto::membership::{ControllerTrust, Membership};
use zt_crypto::packet::{Packet, TYPE_FRAME};
use zt_crypto::pq::{KemSuite, SigSuite};
use zt_node::dataplane::DataPlane;
use zt_node::Node;
use zt_tun::PacketDevice;

/// How long a test will wait for something to happen.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The network the two nodes share.
const NETWORK: &str = "10.88.0.0/24";

/// The address of the node that runs on its own thread.
const SERVER_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);

/// The address of the node that drives its own node directly.
const CLIENT_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);

/// The packets waiting to be read, and the packets that were written.
#[derive(Clone, Default)]
struct Queue {
    outbound: Arc<Mutex<Vec<Vec<u8>>>>,
    written: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// A device that is a queue rather than a kernel interface.
struct QueueDevice {
    queue: Queue,
    mtu: u16,
}

impl PacketDevice for QueueDevice {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut outbound = self.queue.outbound.lock().unwrap();
        let Some(packet) = outbound.pop() else {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet"));
        };

        let count = packet.len().min(buffer.len());
        buffer[..count].copy_from_slice(&packet[..count]);
        Ok(count)
    }

    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.queue.written.lock().unwrap().push(packet.to_vec());
        Ok(packet.len())
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}

/// Build an IPv4 packet with the given addresses.
fn ipv4(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet.extend_from_slice(payload);
    packet
}

/// A node running on its own thread, with a data plane.
struct TestNode {
    addr: SocketAddr,
    peer_static: PeerStatic,
    queue: Queue,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestNode {
    /// Start a node on the loopback interface.
    ///
    /// The peer is given up front: a node only forwards for the addresses it
    /// knows, and in a deployment those come from the controller's topology.
    fn start(peer: SocketAddr, peer_address: Ipv4Addr) -> TestNode {
        let identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
        let peer_static = PeerStatic {
            ed25519: identity.public_key(),
            ml_dsa: identity.pq_public_key(),
        };

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        let addr = socket.local_addr().expect("addr");

        let queue = Queue::default();
        let stop = Arc::new(AtomicBool::new(false));

        let stop_c = stop.clone();
        let queue_c = queue.clone();
        let handle = thread::spawn(move || {
            let mut node = Node::from_socket(socket, identity).expect("node");
            node.set_suites(
                KemSuite::HybridX25519MlKem768,
                SigSuite::HybridEd25519MlDsa65,
            );

            let mut plane = DataPlane::new(Box::new(QueueDevice {
                queue: queue_c,
                mtu: 1400,
            }));
            plane.add_network_str(NETWORK).expect("network");
            plane.add_local_address(SERVER_ADDRESS).expect("address");
            plane.set_route(peer_address, peer).expect("route");

            let mut buffer = [0u8; 65536];
            while !stop_c.load(Ordering::Relaxed) {
                if let Ok((count, from)) = node.socket_mut().recv_from(&mut buffer) {
                    if let Ok(packets) = node.handle_datagram(&buffer[..count], from) {
                        plane
                            .forward_inbound(&mut node, from, &packets)
                            .expect("forward");
                    }
                }

                // The device is polled as well, so a packet the device
                // holds is not left waiting.
                let _ = plane.forward_outbound(&mut node);
            }
        });

        TestNode {
            addr,
            peer_static,
            queue,
            stop,
            handle: Some(handle),
        }
    }

    /// The packets written to this node's device.
    fn written(&self) -> Vec<Vec<u8>> {
        self.queue.written.lock().unwrap().clone()
    }

    /// Wait until the device has been written to.
    fn wait_for_written(&self, count: usize) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            let written = self.written();
            if written.len() >= count {
                return written;
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.written()
    }

    /// Queue a packet for the device to hand out.
    fn queue_packet(&self, packet: Vec<u8>) {
        self.queue.outbound.lock().unwrap().push(packet);
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A node that the test drives directly.
struct DirectNode {
    node: Node,
    plane: DataPlane,
    queue: Queue,
}

impl DirectNode {
    fn start() -> DirectNode {
        Self::with_address(CLIENT_ADDRESS)
    }

    /// Start a node that holds the given address.
    fn with_address(address: Ipv4Addr) -> DirectNode {
        let identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");

        let mut node = Node::from_socket(socket, identity).expect("node");
        node.set_suites(
            KemSuite::HybridX25519MlKem768,
            SigSuite::HybridEd25519MlDsa65,
        );

        let queue = Queue::default();
        let mut plane = DataPlane::new(Box::new(QueueDevice {
            queue: queue.clone(),
            mtu: 1400,
        }));
        plane.add_network_str(NETWORK).expect("network");
        plane.add_local_address(address).expect("address");

        DirectNode { node, plane, queue }
    }

    /// Complete the handshake with a peer.
    fn connect(&mut self, peer: SocketAddr, peer_static: PeerStatic) {
        self.node.connect(peer, peer_static).expect("connect");

        let deadline = Instant::now() + TIMEOUT;
        let mut buffer = [0u8; 65536];
        let mut connected = false;

        while Instant::now() < deadline && !connected {
            if let Ok((count, from)) = self.node.socket_mut().recv_from(&mut buffer) {
                let _ = self.node.handle_datagram(&buffer[..count], from);
            }

            connected = self.node.is_connected(&peer);
            if !connected {
                thread::sleep(Duration::from_millis(5));
            }
        }

        assert!(connected, "the handshake did not complete");
    }

    /// Queue a packet for the device to hand out.
    fn queue_packet(&self, packet: Vec<u8>) {
        self.queue.outbound.lock().unwrap().push(packet);
    }

    /// The packets written to this node's device.
    fn written(&self) -> Vec<Vec<u8>> {
        self.queue.written.lock().unwrap().clone()
    }

    /// Read whatever is waiting on the socket and hand it to the plane,
    /// and send whatever the device is holding.
    /// How many packets the device has handed out.
    fn handed_out(&self) -> usize {
        self.queue.outbound.lock().unwrap().len()
    }

    fn poll(&mut self) {
        let mut buffer = [0u8; 65536];

        while let Ok((count, from)) = self.node.socket_mut().recv_from(&mut buffer) {
            let Ok(packets) = self.node.handle_datagram(&buffer[..count], from) else {
                continue;
            };

            self.plane
                .forward_inbound(&mut self.node, from, &packets)
                .expect("forward");
        }

        self.plane
            .forward_outbound(&mut self.node)
            .expect("outbound");
    }
}

/// The address the relay holds.
/// The address the relay holds.
const RELAY_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 9);

/// Start a relay node: it forwards between the hosts and has no interface
/// of its own.
struct RelayNode {
    addr: SocketAddr,
    peer_static: PeerStatic,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl RelayNode {
    /// Start a relay that knows the two hosts.
    fn start(hosts: &[(SocketAddr, Ipv4Addr)], address: Ipv4Addr) -> RelayNode {
        let identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
        let peer_static = PeerStatic {
            ed25519: identity.public_key(),
            ml_dsa: identity.pq_public_key(),
        };

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let addr = socket.local_addr().unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = stop.clone();

        let hosts = hosts.to_vec();
        let handle = thread::spawn(move || {
            let mut node = Node::from_socket(socket, identity).unwrap();
            node.set_suites(
                KemSuite::HybridX25519MlKem768,
                SigSuite::HybridEd25519MlDsa65,
            );
            node.set_membership(Membership::new());
            node.set_trust(ControllerTrust::new());

            let mut plane = DataPlane::new(Box::new(zt_tun::NullDevice));
            plane.set_relaying(true);
            plane.add_network_str(NETWORK).unwrap();
            plane.add_local_address(address).unwrap();

            for (endpoint, address) in &hosts {
                plane.set_route(*address, *endpoint).unwrap();
            }

            let mut buffer = [0u8; 65536];
            while !stop_c.load(Ordering::Relaxed) {
                if let Ok((count, from)) = node.socket_mut().recv_from(&mut buffer) {
                    if let Ok(packets) = node.handle_datagram(&buffer[..count], from) {
                        plane.forward_inbound(&mut node, from, &packets).unwrap();
                    }
                }
                let _ = plane.forward_outbound(&mut node);
            }
        });

        RelayNode {
            addr,
            peer_static,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for RelayNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Start the two hosts, the relay between them, and complete the
/// handshakes.
fn relayed_pair() -> (RelayNode, DirectNode, DirectNode) {
    let mut a = DirectNode::with_address(CLIENT_ADDRESS);
    let mut b = DirectNode::with_address(SERVER_ADDRESS);
    let a_addr = a.node.local_addr();
    let b_addr = b.node.local_addr();

    // The relay holds its own address, so it is not one of the hosts.
    let relay = RelayNode::start(
        &[(a_addr, CLIENT_ADDRESS), (b_addr, SERVER_ADDRESS)],
        RELAY_ADDRESS,
    );

    // Both hosts know the relay, and handshake with it.
    a.plane.set_relay(relay.addr);
    b.plane.set_relay(relay.addr);

    a.connect(relay.addr, relay.peer_static.clone());
    b.connect(relay.addr, relay.peer_static.clone());

    (relay, a, b)
}

#[test]
fn a_packet_between_two_hosts_goes_through_the_relay() {
    let (_relay, mut a, mut b) = relayed_pair();

    // The first host sends a packet for the second, which it cannot reach
    // directly: it has no route to it, only a relay.
    let payload = b"through the relay";
    a.queue_packet(ipv4(CLIENT_ADDRESS, SERVER_ADDRESS, payload));

    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline && b.written().is_empty() {
        a.poll();
        b.poll();

        eprintln!(
            "[debug] a handed out {}, b written {}",
            a.handed_out(),
            b.written().len()
        );

        thread::sleep(Duration::from_millis(10));
    }

    let written = b.written();
    assert_eq!(
        written.len(),
        1,
        "the second host's device was not written to"
    );
    assert_eq!(
        written[0],
        ipv4(CLIENT_ADDRESS, SERVER_ADDRESS, payload),
        "the packet arrived altered"
    );
}

/// Start the two nodes and complete the handshake between them.
fn connected_pair() -> (TestNode, DirectNode) {
    let mut client = DirectNode::start();
    let client_addr = client.node.local_addr();
    let server = TestNode::start(client_addr, CLIENT_ADDRESS);

    client.connect(server.addr, server.peer_static.clone());
    client
        .plane
        .set_route(SERVER_ADDRESS, server.addr)
        .expect("route");

    (server, client)
}

#[test]
fn a_packet_crosses_the_overlay_and_lands_on_the_other_device() {
    let (server, mut client) = connected_pair();

    // A packet for the server, read from the client's device.
    let payload = b"the quick brown fox jumps over the lazy dog";
    client.queue_packet(ipv4(CLIENT_ADDRESS, SERVER_ADDRESS, payload));

    let forwarded = client
        .plane
        .forward_outbound(&mut client.node)
        .expect("forward");
    assert_eq!(forwarded, 1, "the packet was not forwarded");

    // The server's device receives it.
    let written = server.wait_for_written(1);
    assert_eq!(written.len(), 1, "the server's device was not written to");
    assert_eq!(
        written[0],
        ipv4(CLIENT_ADDRESS, SERVER_ADDRESS, payload),
        "the packet arrived altered"
    );
}

#[test]
fn a_packet_for_an_unknown_address_is_dropped() {
    let (server, mut client) = connected_pair();

    // Nobody owns this address.
    client.queue_packet(ipv4(
        CLIENT_ADDRESS,
        Ipv4Addr::new(10, 88, 0, 200),
        b"nowhere to go",
    ));

    let forwarded = client
        .plane
        .forward_outbound(&mut client.node)
        .expect("forward");
    assert_eq!(forwarded, 0, "the packet should have been dropped");

    // And it never reaches the other side.
    thread::sleep(Duration::from_millis(200));
    assert!(server.written().is_empty());
}

#[test]
fn a_packet_comes_back_the_other_way() {
    let (server, mut client) = connected_pair();

    // The server's device holds a packet for the client.
    let payload = b"and back again";
    server.queue_packet(ipv4(SERVER_ADDRESS, CLIENT_ADDRESS, payload));

    // The client's device receives it.
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline && client.written().is_empty() {
        client.poll();
        thread::sleep(Duration::from_millis(10));
    }

    let written = client.written();
    assert_eq!(written.len(), 1, "the client's device was not written to");
    assert_eq!(
        written[0],
        ipv4(SERVER_ADDRESS, CLIENT_ADDRESS, payload),
        "the packet arrived altered"
    );
}

#[test]
fn a_frame_the_peer_forged_is_not_written() {
    // The client sends a frame whose source address belongs to a third
    // host. The server must not accept it: a peer cannot claim to be
    // someone else.
    let (server, mut client) = connected_pair();

    let forged = ipv4(
        Ipv4Addr::new(10, 88, 0, 200),
        SERVER_ADDRESS,
        b"not from me",
    );

    let packet = Packet::new(TYPE_FRAME, forged);
    client
        .node
        .send(server.addr, &packet)
        .expect("send the forged frame");

    thread::sleep(Duration::from_millis(300));
    assert!(
        server.written().is_empty(),
        "the forged frame was written to the device"
    );
}
