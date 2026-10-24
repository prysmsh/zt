//! A two-node ZT-next demo over real UDP sockets.
//!
//! This starts two nodes on the loopback interface, performs a
//! post-quantum hybrid handshake between them, and exchanges an encrypted
//! frame. It then prints a summary of what happened.
//!
//! ```text
//! cargo run -p zt-node --bin demo
//! ```
//!
//! The demo exercises:
//!
//! - A hybrid X25519 + ML-KEM-768 handshake with Ed25519 + ML-DSA-65
//!   authentication.
//! - An encrypted, replay-protected data path.
//! - A demonstration that a replayed datagram is rejected.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use zt_crypto::handshake_flow::{PeerStatic, StaticIdentity};
use zt_crypto::identity::Identity;
use zt_crypto::packet::{Packet, TYPE_FRAME};
use zt_node::Node;

fn main() {
    println!("=== ZT-next end-to-end demo ===\n");

    // --- set up two nodes ---
    let server_identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
    let client_identity = StaticIdentity::new(Identity::generate().unwrap()).unwrap();

    let server_socket = UdpSocket::bind("127.0.0.1:0").expect("bind server");
    server_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();

    let mut server = Node::from_socket(server_socket, server_identity).unwrap();
    let mut client = Node::from_socket(client_socket, client_identity).unwrap();

    println!("server listening on {server_addr}");
    println!("client bound to        {}", client.local_addr());
    println!(
        "suites: kem={:?} sig={:?}",
        client.offered_suites().0,
        client.offered_suites().1
    );
    println!();

    // --- the client knows the server's static key (in reality: from a
    // controller or a peer directory) ---
    let server_peer = PeerStatic {
        ed25519: server.identity_public_key(),
        ml_dsa: server.identity_pq_public_key(),
    };

    // --- 1. handshake ---
    let start = Instant::now();
    client.connect(server_addr, server_peer).expect("connect");

    let mut buf = [0u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut connected = false;

    while Instant::now() < deadline && !connected {
        // The server answers the client's initiation.
        if let Ok((n, from)) = server.socket_mut().recv_from(&mut buf) {
            let _ = server.handle_datagram(&buf[..n], from);
        }
        // The client processes the response.
        if let Ok((n, from)) = client.socket_mut().recv_from(&mut buf) {
            let _ = client.handle_datagram(&buf[..n], from);
        }
        connected = client.is_connected(&server_addr) && server.is_connected(&client.local_addr());
        if !connected {
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    let handshake_time = start.elapsed();
    if !connected {
        eprintln!("handshake FAILED");
        std::process::exit(1);
    }
    println!("handshake completed in {:?}", handshake_time);
    println!(
        "  client->server session established: {}",
        client.is_connected(&server_addr)
    );
    println!(
        "  server->client session established: {}",
        server.is_connected(&client.local_addr())
    );
    println!();

    // --- 2. exchange a frame ---
    let payload = b"Hello from the ZT-next mesh!".to_vec();
    client
        .send(server_addr, &Packet::new(TYPE_FRAME, payload.clone()))
        .expect("send");

    let mut received = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && received.is_empty() {
        if let Ok((n, from)) = server.socket_mut().recv_from(&mut buf) {
            received.extend(server.handle_datagram(&buf[..n], from).unwrap_or_default());
        }
    }

    if received.is_empty() {
        eprintln!("frame exchange FAILED");
        std::process::exit(1);
    }
    println!("frame received by server:");
    println!("  type    = 0x{:02x} (FRAME)", received[0].packet_type);
    println!(
        "  payload = {:?}",
        String::from_utf8_lossy(&received[0].payload)
    );
    println!();

    // --- 3. demonstrate replay rejection ---
    let replay_bytes = client
        .seal(server_addr, &Packet::new(TYPE_FRAME, b"replayed".to_vec()))
        .expect("seal");

    client.send_raw(&replay_bytes, server_addr).expect("send");
    let mut first = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && first.is_empty() {
        if let Ok((n, from)) = server.socket_mut().recv_from(&mut buf) {
            first.extend(server.handle_datagram(&buf[..n], from).unwrap_or_default());
        }
    }

    // Now replay the exact same datagram.
    client.send_raw(&replay_bytes, server_addr).expect("send");
    let mut second = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && second.is_empty() {
        if let Ok((n, from)) = server.socket_mut().recv_from(&mut buf) {
            second.extend(server.handle_datagram(&buf[..n], from).unwrap_or_default());
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    println!("replay protection:");
    println!("  original delivery accepted: {}", !first.is_empty());
    println!("  replayed delivery accepted:  {}", !second.is_empty());
    if first.is_empty() {
        println!("  (the original was still in flight; the check is inconclusive)");
    } else if second.is_empty() {
        println!("  => the replay was correctly REJECTED");
    } else {
        println!("  => WARNING: the replay was accepted (this is a bug)");
        std::process::exit(1);
    }
    println!();
    println!("=== demo complete ===");
}
