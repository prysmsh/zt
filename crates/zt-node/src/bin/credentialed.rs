//! A two-node ZT-next demo using real controller-issued credentials.
//!
//! Unlike `demo.rs`, which only exercises the protocol, this demo drives
//! the whole product path:
//!
//! 1. Enroll two nodes with a running controller.
//! 2. Load each node's credential and trust anchor from its state file.
//! 3. Start two real UDP nodes on the loopback interface.
//! 4. Connect them, so the handshake carries and verifies the credentials.
//! 5. Exchange an encrypted frame.
//!
//! The third node is an impostor: it presents a credential from a controller
//! the server does not trust, and is refused.
//!
//! ```text
//! cargo run -p zt-node --bin credentialed -- \
//!     --controller http://127.0.0.1:8080 --tenant agent-test --network <id>
//! ```

use std::net::UdpSocket;
use std::thread;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zt_crypto::credential::ControllerIdentity;
use zt_crypto::handshake_flow::{PeerStatic, StaticIdentity};
use zt_crypto::identity::Identity;
use zt_crypto::membership::{ControllerTrust, Membership, TrustedController};
use zt_crypto::packet::{Packet, TYPE_FRAME};
use zt_node::Node;

/// How long to wait for the handshake.
const TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    let mut controller_url = "http://127.0.0.1:8080".to_string();
    let mut tenant = String::new();
    let mut network_id = String::new();
    let mut directory = PathBuf::from("/tmp/zt-credentialed-demo");

    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{argument} needs a value"))?;
        match argument {
            "--controller" => controller_url = value.clone(),
            "--tenant" => tenant = value.clone(),
            "--network" => network_id = value.clone(),
            "--dir" => directory = PathBuf::from(value),
            other => return Err(format!("unknown option {other}").into()),
        }
        index += 2;
    }

    if tenant.is_empty() || network_id.is_empty() {
        println!("usage: credentialed --tenant <slug> --network <id> [--controller <url>] [--dir <path>]");
        return Ok(());
    }

    println!("=== ZT-next credentialed end-to-end demo ===\n");

    std::fs::create_dir_all(&directory)?;

    // --- enroll three nodes with the controller ---
    //
    // The first two are legitimate members of the network. The third is an
    // impostor that will present a credential from a controller the server
    // does not trust.
    // Node names must be unique within a network, so each run uses a
    // fresh suffix.
    let run = std::process::id();
    let mut members = Vec::new();
    for label in ["member-1", "member-2", "impostor"] {
        let name = format!("{label}-{run}");
        let state_path = directory.join(format!("{label}.json"));
        let _ = std::fs::remove_file(&state_path);

        let _details = enroll(
            &controller_url,
            &tenant,
            &network_id,
            &name,
            &state_path,
        )?;
        members.push((name.to_string(), state_path));
        println!("enrolled {name}");
    }
    println!();

    // --- load the credentials and trust anchors ---
    let server_state = load_state(&members[0].1)?;
    let client_state = load_state(&members[1].1)?;
    let impostor_state = load_state(&members[2].1)?;

    // --- the impostor swaps its genuine credential for a forged one ---
    //
    // The forged credential is signed by a controller the server does not
    // trust, but it is otherwise well formed and bound to the impostor's
    // own key. Only the trust anchor can tell it apart from a real one.
    let rogue = rogue_controller();
    let impostor_identity = impostor_state.identity();
    let forged = rogue.issue(
        11565521707275692465,
        impostor_identity.address_for_network(11565521707275692465),
        &impostor_identity.public_key_bytes(),
        zt_crypto::time::now_unix(),
        3600,
        &[7u8; 16],
    );
    let mut impostor_forged = impostor_state.clone();
    impostor_forged.credential = forged.serialize();
    impostor_forged.controller_key = rogue.public_key();
    println!(
        "impostor forged a credential from controller {}\n",
        hex::encode(rogue.public_key())
    );

    // --- start the server on its own thread ---
    //
    // The server has to answer the handshake while the client waits for the
    // response, so it runs on a separate thread with its own poll loop.
    let server_identity = StaticIdentity::new(server_state.identity()).unwrap();
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let server_controller_key = server_state.controller_public_key();
    let server_identity_for_peer = server_identity.clone_identity();
    let (frames_tx, frames_rx) = std::sync::mpsc::channel::<zt_crypto::packet::Packet>();
    let server_handle = thread::spawn(move || {
        let mut server = Node::from_socket(server_socket, server_identity).unwrap();
        server.set_trust(trust_for(server_controller_key));
        server.require_membership(true);

        let mut buffer = [0u8; 65536];
        loop {
            match server.socket_mut().recv_from(&mut buffer) {
                Ok((count, from)) => {
                    if let Ok(packets) = server.handle_datagram(&buffer[..count], from) {
                        for packet in packets {
                            let _ = frames_tx.send(packet);
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    });

    println!("server listening on {server_addr}");
    println!("server requires membership\n");

    // --- connect a legitimate member ---
    let client_identity = StaticIdentity::new(client_state.identity()).unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut client = Node::from_socket(client_socket, client_identity).unwrap();
    client.set_membership(membership_for(&client_state)?);

    let server_peer = PeerStatic {
        ed25519: server_identity_for_peer.public_key(),
        ml_dsa: server_identity_for_peer.pq_public_key(),
    };

    client.connect(server_addr, server_peer.clone()).unwrap();
    let connected = wait_for_handshake(&mut client, server_addr);
    println!("member-2 handshake: {}", if connected { "ACCEPTED" } else { "REFUSED" });
    if !connected {
        return Err("the legitimate member could not connect".into());
    }

    // --- exchange a frame ---
    let payload = b"hello from a credentialed node".to_vec();
    client
        .send(server_addr, &Packet::new(TYPE_FRAME, payload.clone()))
        .unwrap();

    let received = wait_for_frame(&frames_rx, &payload);
    println!("frame delivery: {}", if received { "OK" } else { "FAILED" });

    // --- the impostor ---
    let impostor_identity = StaticIdentity::new(impostor_forged.identity()).unwrap();
    let impostor_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    impostor_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut impostor = Node::from_socket(impostor_socket, impostor_identity).unwrap();
    impostor.set_membership(membership_for(&impostor_forged)?);

    impostor.connect(server_addr, server_peer).unwrap();
    let admitted = wait_for_handshake(&mut impostor, server_addr);
    println!(
        "impostor handshake:  {}",
        if admitted { "ACCEPTED (BUG)" } else { "REFUSED (correct)" }
    );

    println!();
    if received && !admitted {
        println!("PASS: credentials gate the network.");
        Ok(())
    } else {
        Err("FAIL: the credential check did not behave correctly".into())
    }
}

/// Enroll a node with the controller and return its state file path.
///
/// The enrollment is done with a direct HTTP call rather than by shelling
/// out to the agent, so the demo has no dependency on another crate's
/// binary. The request and response shapes match the agent's exactly.
fn enroll(
    controller_url: &str,
    tenant: &str,
    network_id: &str,
    name: &str,
    state_path: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    // Resolve the tenant slug to its identifier.
    let tenant_list = http_get(&format!("{controller_url}/api/v1/tenants"))?;
    let wanted = serde_json::json!(tenant);
    let tenant_id = tenant_list["items"]
        .as_array()
        .ok_or("tenants list is not an array")?
        .iter()
        .find(|candidate| candidate["slug"] == wanted)
        .and_then(|candidate| candidate["id"].as_str())
        .map(str::to_string)
        .ok_or("tenant not found")?;

    // The node generates its own identity and sends only the public half.
    let identity = Identity::generate()?;
    let public_key = hex::encode(identity.public_key_bytes());

    let response = http_post(
        &format!("{controller_url}/api/v1/t/{tenant_id}/nodes"),
        &serde_json::json!({
            "network_id": network_id,
            "name": name,
            "public_key": public_key,
            "tags": [],
        }),
    )?;

    let credential = response["credential"]
        .as_str()
        .ok_or("the controller did not return a credential")?;
    let credential_not_after = response["credential_not_after"].as_u64().unwrap_or(0);
    let node_id = response["node"]["id"].as_str().unwrap_or("");

    // The controller's public key is the trust anchor, pinned at enrollment.
    let controller_info = http_get(&format!("{controller_url}/api/v1/controller"))?;
    let controller_key = controller_info["public_key"].as_str().ok_or("no controller key")?;
    let controller_id = controller_info["id"].as_str().unwrap_or_default();

    let state = serde_json::json!({
        "identity_seed": hex::encode(identity.private_key_bytes()),
        "controller_key": controller_key,
        "controller_id": controller_id,
        "node_id": node_id,
        "network_id": network_id,
        "credential": credential,
        "credential_not_after": credential_not_after,
    });

    std::fs::write(state_path, serde_json::to_string_pretty(&state).unwrap())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(format!(
        "  node id: {node_id}\n  credential: {} bytes\n  expires: {}",
        credential.len() / 2,
        credential_not_after
    ))
}

/// Perform a blocking HTTP GET and parse the JSON response.
fn http_get(url: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    http_request("GET", url, None)
}

/// Perform a blocking HTTP POST and parse the JSON response.
fn http_post(
    url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    http_request("POST", url, Some(body.to_string()))
}

/// Send a single HTTP request over TCP and read the response.
fn http_request(
    method: &str,
    url: &str,
    body: Option<String>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let host_port = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    // The authority is everything up to the first slash. Splitting on the
    // last colon avoids mistaking the scheme's colon for the port.
    let authority = host_port.split('/').next().unwrap_or(host_port);
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.to_string()),
        None => (authority.to_string(), "80".to_string()),
    };
    let address = format!("{host}:{port}");
    let path = url
        .split_once(&authority)
        .map(|(_, rest)| {
            if rest.is_empty() {
                "/".to_string()
            } else {
                rest.to_string()
            }
        })
        .unwrap_or_else(|| "/".to_string())
        .to_string();

    let has_body = body.is_some();
    let payload = body.unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if has_body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    request.push_str("\r\n");
    request.push_str(&payload);

    let mut stream = TcpStream::connect(&address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = Vec::new();
    // The body length is used when available, because relying on the
    // connection close can surface a spurious timeout.
    let mut expected: Option<usize> = None;
    let mut header_end = 0usize;
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                response.extend_from_slice(&chunk[..count]);
                if header_end == 0 {
                    if let Some(index) = response
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                    {
                        header_end = index + 4;
                        let headers = String::from_utf8_lossy(&response[..header_end]);
                        expected = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.trim().eq_ignore_ascii_case("content-length") {
                                value.trim().parse().ok()
                            } else {
                                None
                            }
                        });
                        if let Some(length) = expected {
                            if response.len() >= header_end + length {
                                break;
                            }
                        }
                    }
                }
            }
            Err(error) => {
                if let (Some(length), true) = (expected, header_end > 0) {
                    if response.len() >= header_end + length {
                        break;
                    }
                }
                return Err(format!("could not read the response: {error}").into());
            }
        }
    }

    let text = String::from_utf8_lossy(&response);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or("malformed response")?;

    let parsed: serde_json::Value = serde_json::from_str(body)?;
    if let Some(error) = parsed.get("error").and_then(|value| value.as_str()) {
        return Err(error.to_string().into());
    }
    Ok(parsed)
}

/// The state a node stores on disk.
#[derive(Clone)]
struct LoadedState {
    identity_seed: [u8; 32],
    controller_key: [u8; 32],
    credential: Vec<u8>,
}

fn load_state(path: &std::path::Path) -> Result<LoadedState, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;

    let seed = hex::decode(value["identity_seed"].as_str().unwrap())?;
    let key = hex::decode(value["controller_key"].as_str().unwrap())?;
    let credential = hex::decode(value["credential"].as_str().unwrap())?;

    Ok(LoadedState {
        identity_seed: seed.try_into().unwrap(),
        controller_key: key.try_into().unwrap(),
        credential,
    })
}

impl LoadedState {
    fn identity(&self) -> Identity {
        Identity::from_bytes(&self.identity_seed)
    }

    fn controller_public_key(&self) -> [u8; 32] {
        self.controller_key
    }
}

/// The membership a node presents.
fn membership_for(state: &LoadedState) -> Result<Membership, Box<dyn std::error::Error>> {
    let credential = zt_crypto::credential::NodeCredential::deserialize(
        &state.credential,
        &state.controller_key,
    )?;
    let mut membership = Membership::new();
    membership.add(credential.network_id(), credential);
    Ok(membership)
}

/// The trust set a node uses.
fn trust_for(controller_key: [u8; 32]) -> ControllerTrust {
    let mut trust = ControllerTrust::new();
    trust.add(TrustedController {
        public_key: controller_key,
        controller_id: [0u8; 16],
    });
    trust
}

/// A controller the server does not trust.
fn rogue_controller() -> ControllerIdentity {
    ControllerIdentity::new(Identity::generate().unwrap())
}

/// Wait for the client to complete its handshake.
fn wait_for_handshake(client: &mut Node, peer: std::net::SocketAddr) -> bool {
    let deadline = Instant::now() + TIMEOUT;
    let mut buffer = [0u8; 65536];
    while Instant::now() < deadline {
        if let Ok((count, from)) = client.socket_mut().recv_from(&mut buffer) {
            let _ = client.handle_datagram(&buffer[..count], from);
        }
        if client.is_connected(&peer) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// Wait for a frame with the expected payload to arrive at the server.
fn wait_for_frame(
    frames: &std::sync::mpsc::Receiver<zt_crypto::packet::Packet>,
    expected: &[u8],
) -> bool {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        match frames.recv_timeout(Duration::from_millis(100)) {
            Ok(packet) => {
                if packet.packet_type == TYPE_FRAME && packet.payload == expected {
                    return true;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return false,
        }
    }
    false
}
