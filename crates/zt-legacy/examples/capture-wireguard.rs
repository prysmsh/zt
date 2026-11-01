//! Capture a WireGuard handshake from the kernel's implementation.
//!
//! The Linux kernel's WireGuard module is the reference implementation, and
//! the one a `tailscaled` peer speaks. This program drives a real handshake
//! against it and writes the bytes to a fixture file, so the committed test
//! can replay upstream's actual output without needing a kernel interface,
//! root, or any host state.
//!
//! # Running it
//!
//! ```text
//! cargo run -p zt-legacy --example capture-wireguard -- <output.json>
//! ```
//!
//! It needs the `wireguard` kernel module and the `wg` tool, and it creates
//! a temporary network interface. It is not part of the test suite for that
//! reason.

use std::io::Write;
use std::net::UdpSocket;
use std::process::Command;
use std::time::{Duration, Instant};

use zt_legacy::wireguard::{StaticKey, KEY_LEN};
use zt_legacy::wireguard_handshake::Responder;
use zt_legacy::wireguard_message::MessageInitiation;

/// The interface the kernel's WireGuard implementation listens on.
const INTERFACE: &str = "ztcap0";

/// Run a command, returning its output.
fn run(command: &mut Command) -> (bool, String) {
    match command.output() {
        Ok(output) => (
            output.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(error) => (false, error.to_string()),
    }
}

/// A random secret.
fn random_secret() -> [u8; KEY_LEN] {
    use rand::RngCore;
    let mut secret = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
}

/// Encode bytes as standard base64.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Bring up a kernel WireGuard interface with one peer.
fn set_up_interface(
    kernel_secret: &[u8; KEY_LEN],
    peer_public_key: &str,
    endpoint: &str,
) -> Option<u16> {
    let _ = Command::new("sudo")
        .args(["ip", "link", "del", INTERFACE])
        .status();

    let (created, output) =
        run(Command::new("sudo").args(["ip", "link", "add", INTERFACE, "type", "wireguard"]));
    if !created {
        eprintln!("could not create the interface: {output}");
        return None;
    }

    let _ = Command::new("sudo")
        .args(["ip", "address", "add", "10.98.0.1/24", "dev", INTERFACE])
        .status();
    let _ = Command::new("sudo")
        .args(["ip", "link", "set", INTERFACE, "up"])
        .status();

    // The interface's own key. `wg` reads it from a file, and the file has
    // to be under /etc/wireguard: the distribution's AppArmor profile for
    // `wg` grants no read access to anything else.
    let _ = Command::new("sudo")
        .args(["mkdir", "-p", "/etc/wireguard"])
        .status();

    let key_path = "/etc/wireguard/zt-capture-key";
    {
        use std::io::Write as _;
        let mut child = Command::new("sudo")
            .args(["tee", key_path])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn");
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(format!("{}\n", base64_encode(kernel_secret)).as_bytes());
        }
        let _ = child.wait();
    }
    let _ = Command::new("sudo")
        .args(["chmod", "600", key_path])
        .status();

    let (configured, output) = run(Command::new("sudo").args([
        "wg",
        "set",
        INTERFACE,
        "private-key",
        key_path,
        "listen-port",
        "0",
    ]));
    let _ = Command::new("sudo").args(["rm", "-f", key_path]).status();
    if !configured {
        eprintln!("could not set the interface key: {output}");
        return None;
    }

    let (peered, output) = run(Command::new("sudo").args([
        "wg",
        "set",
        INTERFACE,
        "peer",
        peer_public_key,
        "allowed-ips",
        "10.98.0.2/32",
        "endpoint",
        endpoint,
        "persistent-keepalive",
        "5",
    ]));
    if !peered {
        eprintln!("could not add the peer: {output}");
        return None;
    }

    let output = run(Command::new("sudo").args(["wg", "show", INTERFACE])).1;

    output
        .lines()
        .map(str::trim)
        .find_map(|line| {
            line.strip_prefix("listening port: ")
                .or_else(|| line.strip_prefix("listen port: "))
        })
        .and_then(|port| port.trim().parse::<u16>().ok())
}

fn tear_down() {
    let _ = Command::new("sudo")
        .args(["ip", "link", "del", INTERFACE])
        .status();
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: capture-wireguard <output.json>");
        std::process::exit(2);
    });

    if !run(Command::new("sudo").args(["modprobe", "wireguard"])).0 {
        eprintln!("the wireguard kernel module is not available");
        std::process::exit(1);
    }

    // The implementation's key pair. The ephemeral is chosen rather than
    // generated, so the captured handshake can be replayed exactly.
    let implementation_secret = random_secret();
    let implementation_ephemeral = random_secret();
    let implementation_public =
        base64_encode(&StaticKey::from_secret(implementation_secret).public_key_bytes());

    // The kernel's key pair.
    let kernel_secret = random_secret();

    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = socket.local_addr().expect("addr").port();

    let Some(listen_port) = set_up_interface(
        &kernel_secret,
        &implementation_public,
        &format!("127.0.0.1:{port}"),
    ) else {
        tear_down();
        eprintln!("could not set the interface up");
        std::process::exit(1);
    };

    let mut responder = Responder::begin_with_ephemeral(
        StaticKey::from_secret(implementation_secret),
        implementation_ephemeral,
        None,
    )
    .expect("begin");
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(20);

    let mut initiation_bytes: Option<Vec<u8>> = None;
    let mut response_bytes: Option<Vec<u8>> = None;

    while Instant::now() < deadline && response_bytes.is_none() {
        let (count, peer) = match socket.recv_from(&mut buffer) {
            Ok(result) => result,
            Err(_) => continue,
        };

        if count != zt_legacy::wireguard_message::INITIATION_SIZE {
            continue;
        }

        let Ok(initiation) = MessageInitiation::parse(&buffer[..count]) else {
            continue;
        };

        if responder.consume_initiation(&initiation).is_err() {
            eprintln!("the kernel's initiation did not authenticate");
            break;
        }

        let Ok(response) = responder.create_response() else {
            break;
        };

        initiation_bytes = Some(buffer[..count].to_vec());
        let serialized = response.serialize();
        let _ = socket.send_to(&serialized, peer);
        response_bytes = Some(serialized.to_vec());
    }

    tear_down();

    let (Some(initiation), Some(response)) = (initiation_bytes, response_bytes) else {
        eprintln!("the kernel did not complete the handshake");
        std::process::exit(1);
    };

    // The kernel accepts the response when it starts sending transport
    // data, which it does as soon as it has a session.
    let mut accepted = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    while Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((count, _)) if count > 16 => {
                accepted = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }

    if !accepted {
        eprintln!("the kernel did not accept the response");
        std::process::exit(1);
    }

    // The kernel's static public key, so the test can check the tag.
    let kernel_public = base64_encode(&StaticKey::from_secret(kernel_secret).public_key_bytes());

    let fixture = serde_json::json!({
        "description": "A handshake initiation captured from the Linux kernel's \
                        WireGuard implementation, and the response it accepted.",
        "kernel_public_key": kernel_public,
        "kernel_listen_port": listen_port,
        "implementation_static_secret": hex::encode(implementation_secret),
        "implementation_ephemeral_secret": hex::encode(implementation_ephemeral),
        "implementation_index": responder.local_index(),
        "implementation_public_key": implementation_public,
        "initiation": hex::encode(&initiation),
        "accepted_response": hex::encode(&response),
    });

    let mut file = std::fs::File::create(&path).expect("create the fixture");
    file.write_all(
        serde_json::to_string_pretty(&fixture)
            .expect("serialise")
            .as_bytes(),
    )
    .expect("write");
    file.write_all(b"\n").expect("write");

    println!("captured the handshake into {path}");
}
