//! End-to-end tests over real UDP sockets.
//!
//! These tests bind actual sockets on the loopback interface and exchange
//! real datagrams. Nothing is mocked: the handshake, the encryption, and the
//! replay protection all run over the wire.
//!
//! Each node runs on its own thread with a simple poll loop, which is how
//! the daemon will eventually be structured.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use zt_crypto::credential::ControllerIdentity;
use zt_crypto::handshake_flow::{PeerStatic, StaticIdentity};
use zt_crypto::identity::Identity;
use zt_crypto::membership::{ControllerTrust, Membership, TrustedController};
use zt_crypto::packet::{Packet, TYPE_FRAME};
use zt_crypto::pq::{KemSuite, SigSuite};
use zt_node::Node;

/// How long a test will wait for something to happen.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A node running on its own thread.
struct TestNode {
    addr: SocketAddr,
    peer_static: PeerStatic,
    stop: Arc<AtomicBool>,
    received: Arc<Mutex<Vec<Packet>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestNode {
    /// Start a node on the loopback interface.
    ///
    /// The node's static keys are computed before the thread starts so that
    /// the peer can connect back to it.
    fn start() -> TestNode {
        TestNode::start_with_suites(
            KemSuite::HybridX25519MlKem768,
            SigSuite::HybridEd25519MlDsa65,
        )
    }

    /// Start a node using specific cryptographic suites.
    fn start_with_suites(kem: KemSuite, sig: SigSuite) -> TestNode {
        TestNode::start_configured(kem, sig, |_| {})
    }

    /// Start a node, configuring it before the thread begins.
    ///
    /// The configuration closure runs against the node, which is how the
    /// membership and trust settings are applied.
    fn start_configured<C>(kem: KemSuite, sig: SigSuite, configure: C) -> TestNode
    where
        C: FnOnce(&mut Node) + Send + 'static,
    {
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

        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::new(Mutex::new(Vec::new()));

        let stop_c = stop.clone();
        let received_c = received.clone();
        let handle = thread::spawn(move || {
            let mut node = Node::from_socket(socket, identity).expect("node");
            node.set_suites(kem, sig);
            configure(&mut node);
            let mut buf = [0u8; 65536];
            while !stop_c.load(Ordering::Relaxed) {
                match node.socket_mut().recv_from(&mut buf) {
                    Ok((n, from)) => {
                        if let Ok(packets) = node.handle_datagram(&buf[..n], from) {
                            let mut rx = received_c.lock().unwrap();
                            rx.extend(packets);
                        }
                    }
                    Err(_) => continue,
                }
            }
        });

        TestNode {
            addr,
            peer_static,
            stop,
            received,
            handle: Some(handle),
        }
    }

    fn packets(&self) -> Vec<Packet> {
        self.received.lock().unwrap().clone()
    }

    fn wait_for_packets(&self, count: usize) -> Vec<Packet> {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            let p = self.packets();
            if p.len() >= count {
                return p;
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.packets()
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn handshake_and_frame_exchange_over_udp() {
    // --- the server runs on its own thread ---
    let server = TestNode::start();

    // --- the client drives its own node directly ---
    let client_identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let mut client = Node::from_socket(client_socket, client_identity).expect("client");

    // --- the client initiates the handshake ---
    client
        .connect(server.addr, server.peer_static.clone())
        .expect("connect");

    // Wait for the handshake to complete. The server thread answers, and
    // the client processes the response on its next receive.
    let deadline = Instant::now() + TIMEOUT;
    let mut buf = [0u8; 65536];
    let mut connected = false;

    while Instant::now() < deadline && !connected {
        if let Ok((n, from)) = client.socket_mut().recv_from(&mut buf) {
            let _ = client.handle_datagram(&buf[..n], from);
        }
        // The client considers the peer connected once it has processed the
        // handshake response.
        connected = client.is_connected(&server.addr);
        if !connected {
            thread::sleep(Duration::from_millis(5));
        }
    }

    assert!(connected, "client did not complete the handshake");

    // --- send a frame from client to server ---
    let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
    client
        .send(server.addr, &Packet::new(TYPE_FRAME, payload.clone()))
        .expect("send");

    let received = server.wait_for_packets(1);
    assert_eq!(received.len(), 1, "server received no packets");
    assert_eq!(received[0].packet_type, TYPE_FRAME);
    assert_eq!(received[0].payload, payload);
}

#[test]
fn replayed_datagram_is_rejected_end_to_end() {
    let server = TestNode::start();

    let client_identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let mut client = Node::from_socket(client_socket, client_identity).expect("client");

    client
        .connect(server.addr, server.peer_static.clone())
        .expect("connect");

    let deadline = Instant::now() + TIMEOUT;
    let mut buf = [0u8; 65536];
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        if let Ok((n, from)) = client.socket_mut().recv_from(&mut buf) {
            let _ = client.handle_datagram(&buf[..n], from);
        }
        connected = client.is_connected(&server.addr);
        if !connected {
            thread::sleep(Duration::from_millis(5));
        }
    }
    assert!(connected, "handshake did not complete");

    // Capture the exact bytes of a data packet so we can replay them.
    let payload = b"replay me".to_vec();
    let bytes = client
        .seal(server.addr, &Packet::new(TYPE_FRAME, payload.clone()))
        .expect("encrypt");

    // Deliver it twice.
    client.send_raw(&bytes, server.addr).expect("send 1");
    client.send_raw(&bytes, server.addr).expect("send 2");

    let received = server.wait_for_packets(2);
    // The first delivery is accepted; the replay is not.
    assert_eq!(received.len(), 1, "replay was not rejected: {received:?}");
    assert_eq!(received[0].payload, payload);
}

#[test]
fn handshake_completes_with_pure_post_quantum_suites() {
    let server = TestNode::start_with_suites(KemSuite::MlKem768, SigSuite::MlDsa65);

    let client_identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let mut client = Node::from_socket(client_socket, client_identity).expect("client");

    client.set_suites(KemSuite::MlKem768, SigSuite::MlDsa65);
    client
        .connect(server.addr, server.peer_static.clone())
        .expect("connect");

    let deadline = Instant::now() + TIMEOUT;
    let mut buf = [0u8; 65536];
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        if let Ok((n, from)) = client.socket_mut().recv_from(&mut buf) {
            let _ = client.handle_datagram(&buf[..n], from);
        }
        connected = client.is_connected(&server.addr);
        if !connected {
            thread::sleep(Duration::from_millis(5));
        }
    }

    assert!(connected, "pure-PQ handshake did not complete");
}

#[test]
fn handshake_completes_with_classical_suites() {
    let server = TestNode::start_with_suites(KemSuite::X25519, SigSuite::Ed25519);

    let client_identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let mut client = Node::from_socket(client_socket, client_identity).expect("client");

    client.set_suites(KemSuite::X25519, SigSuite::Ed25519);
    client
        .connect(server.addr, server.peer_static.clone())
        .expect("connect");

    let deadline = Instant::now() + TIMEOUT;
    let mut buf = [0u8; 65536];
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        if let Ok((n, from)) = client.socket_mut().recv_from(&mut buf) {
            let _ = client.handle_datagram(&buf[..n], from);
        }
        connected = client.is_connected(&server.addr);
        if !connected {
            thread::sleep(Duration::from_millis(5));
        }
    }

    assert!(connected, "classical handshake did not complete");
}

// ---------------------------------------------------------------------------
// Membership-gated handshakes
// ---------------------------------------------------------------------------

/// A controller that issues credentials, standing in for the control plane.
fn controller() -> ControllerIdentity {
    ControllerIdentity::new(Identity::generate().unwrap())
}

/// The membership a node presents for a network.
fn membership_for(
    controller: &ControllerIdentity,
    identity: &Identity,
    network_id: u64,
) -> Membership {
    let mut membership = Membership::new();
    membership.add(
        network_id,
        controller.issue(
            network_id,
            identity.address_for_network(network_id),
            &identity.public_key_bytes(),
            zt_crypto::time::now_unix(),
            3600,
            &[7u8; 16],
        ),
    );
    membership
}

/// The set of controllers a node trusts.
fn trust_for(controller: &ControllerIdentity) -> ControllerTrust {
    let mut trust = ControllerTrust::new();
    trust.add(TrustedController {
        public_key: controller.public_key(),
        controller_id: *controller.controller_id(),
    });
    trust
}

/// Drive a client handshake against a server and report whether it connected.
fn try_handshake(client: &mut Node, server: &TestNode) -> bool {
    client
        .connect(server.addr, server.peer_static.clone())
        .expect("connect");

    let deadline = Instant::now() + TIMEOUT;
    let mut buf = [0u8; 65536];
    while Instant::now() < deadline {
        if let Ok((n, from)) = client.socket_mut().recv_from(&mut buf) {
            let _ = client.handle_datagram(&buf[..n], from);
        }
        if client.is_connected(&server.addr) {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    false
}

#[test]
fn a_credentialed_node_joins_a_network_that_requires_membership() {
    let controller = controller();

    // The server requires membership and trusts the controller.
    let trust = trust_for(&controller);
    let server = TestNode::start_configured(
        KemSuite::X25519,
        SigSuite::Ed25519,
        move |node| {
            node.set_trust(trust);
            node.require_membership(true);
        },
    );

    // The client presents a credential from that controller.
    let client_identity = Identity::generate().unwrap();
    let client_static = StaticIdentity::new(client_identity.clone()).unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let mut client = Node::from_socket(client_socket, client_static).expect("client");
    client.set_suites(KemSuite::X25519, SigSuite::Ed25519);
    client.set_membership(membership_for(&controller, &client_identity, 42));

    assert!(
        try_handshake(&mut client, &server),
        "a node with valid credentials must be able to join"
    );
}

#[test]
fn an_uncredentialed_node_cannot_join_a_network_that_requires_membership() {
    let controller = controller();

    let trust = trust_for(&controller);
    let server = TestNode::start_configured(
        KemSuite::X25519,
        SigSuite::Ed25519,
        move |node| {
            node.set_trust(trust);
            node.require_membership(true);
        },
    );

    let client_identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let mut client = Node::from_socket(client_socket, client_identity).expect("client");
    client.set_suites(KemSuite::X25519, SigSuite::Ed25519);

    // The client presents nothing, so the handshake must not complete.
    assert!(
        !try_handshake(&mut client, &server),
        "a node without credentials must not be able to join"
    );
}

#[test]
fn a_node_with_a_foreign_credential_cannot_join() {
    let trusted = controller();
    let rogue = controller();

    let trust = trust_for(&trusted);
    let server = TestNode::start_configured(
        KemSuite::X25519,
        SigSuite::Ed25519,
        move |node| {
            node.set_trust(trust);
            node.require_membership(true);
        },
    );

    // The client presents a credential from a controller the server does not
    // trust.
    let client_identity = Identity::generate().unwrap();
    let client_static = StaticIdentity::new(client_identity.clone()).unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let mut client = Node::from_socket(client_socket, client_static).expect("client");
    client.set_suites(KemSuite::X25519, SigSuite::Ed25519);
    client.set_membership(membership_for(&rogue, &client_identity, 42));

    assert!(
        !try_handshake(&mut client, &server),
        "a credential from an untrusted controller must not be accepted"
    );
}

#[test]
fn a_node_replaying_another_nodes_credential_cannot_join() {
    let controller = controller();

    let trust = trust_for(&controller);
    let server = TestNode::start_configured(
        KemSuite::X25519,
        SigSuite::Ed25519,
        move |node| {
            node.set_trust(trust);
            node.require_membership(true);
        },
    );

    // The attacker presents a credential that was issued to someone else.
    let victim = Identity::generate().unwrap();
    let client_identity = Identity::generate().unwrap();
    let client_static = StaticIdentity::new(client_identity.clone()).unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let mut client = Node::from_socket(client_socket, client_static).expect("client");
    client.set_suites(KemSuite::X25519, SigSuite::Ed25519);
    client.set_membership(membership_for(&controller, &victim, 42));

    assert!(
        !try_handshake(&mut client, &server),
        "a replayed credential must not be accepted"
    );
}
