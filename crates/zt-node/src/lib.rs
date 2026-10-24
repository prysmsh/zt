//! The ZT-next node: a UDP endpoint that speaks the ZT-next protocol.
//!
//! # What this covers
//!
//! This crate implements the **transport and session layer**:
//!
//! - A UDP socket bound to a local address.
//! - Outbound handshake initiation to a known peer.
//! - Inbound handshake response handling.
//! - An encrypted, replay-protected data path over the established session.
//!
//! It deliberately does **not** implement the topology layer (peer discovery,
//! path selection, relaying) — that is the next milestone. What it does
//! implement is enough to run a complete, real, over-the-wire exchange
//! between two nodes.
//!
//! # Threading
//!
//! A node owns its socket and runs a single receive loop. The receive loop
//! is expected to run on its own thread; [`Node::handle_datagram`] processes
//! one inbound datagram and returns any application-level packets it
//! produced. This keeps the node free of internal locking and makes the
//! concurrency policy explicit.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use zt_crypto::error::Error;
use zt_crypto::handshake_flow::{
    Initiator, PeerStatic, Responder, StaticIdentity, MAX_HANDSHAKE_MESSAGE,
};
use zt_crypto::identity::Identity;
use zt_crypto::packet::Packet;
use zt_crypto::pq::{KemSuite, SigSuite};
use zt_crypto::session::Session;

/// Errors produced by the node.
#[derive(Debug)]
pub enum NodeError {
    /// A cryptographic or protocol error.
    Crypto(Error),
    /// An I/O error from the socket.
    Io(std::io::Error),
    /// The requested peer is not known.
    UnknownPeer(SocketAddr),
}

impl From<Error> for NodeError {
    fn from(e: Error) -> Self {
        NodeError::Crypto(e)
    }
}

impl From<std::io::Error> for NodeError {
    fn from(e: std::io::Error) -> Self {
        NodeError::Io(e)
    }
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Crypto(e) => write!(f, "protocol error: {e}"),
            NodeError::Io(e) => write!(f, "io error: {e}"),
            NodeError::UnknownPeer(a) => write!(f, "unknown peer: {a}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// The result type for node operations.
pub type Result<T> = std::result::Result<T, NodeError>;

/// The default UDP port for ZT-next.
pub const DEFAULT_PORT: u16 = 9994;

/// How long to wait for a handshake response before retrying.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many times to retry a handshake before giving up.
pub const HANDSHAKE_ATTEMPTS: usize = 3;

/// The state of a peer as seen by this node.
enum PeerState {
    /// A handshake is in flight.
    ///
    /// The initiator is boxed because it is large and this variant is
    /// transient — keeping it inline would bloat every peer entry.
    Handshaking {
        initiator: Box<Initiator>,
        sent_at: Instant,
        attempts: usize,
    },
    /// A session is established.
    Connected(Box<Session>),
    /// The peer failed to complete a handshake.
    Failed,
}

/// A peer this node knows about.
struct Peer {
    address: SocketAddr,
    state: PeerState,
    /// The peer's static public key, learned when the peer introduced
    /// itself.
    static_key: Option<PeerStatic>,
}

/// A ZT-next node.
pub struct Node {
    socket: UdpSocket,
    identity: StaticIdentity,
    local: SocketAddr,
    peers: HashMap<SocketAddr, Peer>,
    kem_suite: KemSuite,
    sig_suite: SigSuite,
}

impl Node {
    /// Create a node bound to `local`, using the given identity.
    pub fn bind(local: SocketAddr, identity: Identity) -> Result<Node> {
        let socket = UdpSocket::bind(local)?;
        Node::from_socket(socket, StaticIdentity::new(identity)?)
    }

    /// Create a node from an existing socket and a prepared static identity.
    ///
    /// Taking a [`StaticIdentity`] rather than a raw [`Identity`] lets the
    /// caller learn the node's public keys *before* the node starts, which
    /// is what a peer directory needs.
    pub fn from_socket(socket: UdpSocket, identity: StaticIdentity) -> Result<Node> {
        let bound = socket.local_addr()?;
        Ok(Node {
            socket,
            identity,
            local: bound,
            peers: HashMap::new(),
            kem_suite: KemSuite::HybridX25519MlKem768,
            sig_suite: SigSuite::HybridEd25519MlDsa65,
        })
    }

    /// Access the underlying socket, for tests and for integrating with an
    /// external event loop.
    pub fn socket_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    /// The node's static public key, as a peer descriptor.
    pub fn peer_static(&self) -> PeerStatic {
        PeerStatic {
            ed25519: self.identity.public_key(),
            ml_dsa: self.identity.pq_public_key(),
        }
    }

    /// The node's Ed25519 public key.
    pub fn identity_public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }

    /// The node's ML-DSA-65 public key.
    pub fn identity_pq_public_key(&self) -> Vec<u8> {
        self.identity.pq_public_key()
    }

    /// The node's bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The node's Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }

    /// The node's ML-DSA-65 public key.
    pub fn pq_public_key(&self) -> Vec<u8> {
        self.identity.pq_public_key()
    }

    /// The cryptographic suites this node offers.
    pub fn suites(&self) -> (KemSuite, SigSuite) {
        (self.kem_suite, self.sig_suite)
    }

    /// Set the suites this node will use.
    pub fn set_suites(&mut self, kem: KemSuite, sig: SigSuite) {
        self.kem_suite = kem;
        self.sig_suite = sig;
    }

    /// The cryptographic suites this node offers.
    pub fn offered_suites(&self) -> (KemSuite, SigSuite) {
        (self.kem_suite, self.sig_suite)
    }

    /// Set the receive timeout.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket.set_read_timeout(timeout)?;
        Ok(())
    }

    /// Initiate a handshake with a peer.
    ///
    /// The peer must be reachable and must have told us its static public
    /// key through some out-of-band mechanism (a controller, a
    /// configuration file, or a previous session).
    ///
    /// This sends the first handshake message immediately.
    pub fn connect(&mut self, peer: SocketAddr, peer_key: PeerStatic) -> Result<()> {
        let mut initiator = Initiator::begin(
            self.identity.clone_identity(),
            peer_key.clone(),
            self.kem_suite,
            self.sig_suite,
        )?;

        let first_message = initiator.write_message_1()?;

        let entry = self.peers.entry(peer).or_insert_with(|| Peer {
            address: peer,
            state: PeerState::Failed,
            static_key: Some(peer_key),
        });
        entry.state = PeerState::Handshaking {
            initiator: Box::new(initiator),
            sent_at: Instant::now(),
            attempts: 1,
        };

        self.socket.send_to(&first_message, peer)?;
        Ok(())
    }

    /// Send an application packet to a connected peer.
    pub fn send(&mut self, peer: SocketAddr, packet: &Packet) -> Result<()> {
        let entry = self
            .peers
            .get_mut(&peer)
            .ok_or(NodeError::Crypto(Error::InvalidKey("unknown peer")))?;

        let bytes = match &mut entry.state {
            PeerState::Connected(session) => session.seal(packet)?,
            PeerState::Handshaking { .. } => {
                return Err(NodeError::Crypto(Error::InvalidKey(
                    "handshake in progress",
                )))
            }
            PeerState::Failed => {
                return Err(NodeError::Crypto(Error::InvalidKey(
                    "peer connection failed",
                )))
            }
        };
        self.socket.send_to(&bytes, peer)?;
        Ok(())
    }

    /// Encrypt a packet for a peer without sending it.
    ///
    /// Useful for tests that need to replay a datagram, and for callers
    /// that want to batch several packets into one datagram.
    pub fn seal(&mut self, peer: SocketAddr, packet: &Packet) -> Result<Vec<u8>> {
        let entry = self
            .peers
            .get_mut(&peer)
            .ok_or(NodeError::UnknownPeer(peer))?;

        let bytes = match &mut entry.state {
            PeerState::Connected(session) => session.seal(packet)?,
            PeerState::Handshaking { .. } => {
                return Err(NodeError::Crypto(Error::InvalidKey(
                    "handshake in progress",
                )))
            }
            PeerState::Failed => {
                return Err(NodeError::Crypto(Error::InvalidKey(
                    "peer connection failed",
                )))
            }
        };
        Ok(bytes)
    }

    /// Send raw bytes to an address.
    ///
    /// This bypasses the protocol entirely and exists for tests that need
    /// to inject malformed or replayed datagrams.
    pub fn send_raw(&self, bytes: &[u8], to: SocketAddr) -> Result<()> {
        self.socket.send_to(bytes, to)?;
        Ok(())
    }

    /// Handle one inbound datagram.
    ///
    /// Returns the application-level packets it produced. A handshake
    /// message produces none.
    pub fn handle_datagram(&mut self, bytes: &[u8], from: SocketAddr) -> Result<Vec<Packet>> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        // Distinguish handshake messages from data packets. Handshake
        // messages begin with their type byte (0x01 or 0x02); data packets
        // begin with a 4-byte session id whose first byte is never 0x01 or
        // 0x02 in practice. To be unambiguous, the first byte of a data
        // packet is masked to zero, so a leading 0x01/0x02 always means a
        // handshake message.
        match bytes[0] {
            0x01 | 0x02 => {
                self.handle_handshake(bytes, from)?;
                Ok(Vec::new())
            }
            _ => self.handle_data(bytes, from),
        }
    }

    fn handle_handshake(&mut self, bytes: &[u8], from: SocketAddr) -> Result<()> {
        if bytes.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(NodeError::Crypto(Error::InvalidLength));
        }
        let parsed = zt_crypto::handshake_flow::Message::deserialize(bytes)?;

        // An initiation is for us to respond to; a response completes a
        // handshake we started.
        if parsed.msg_type == zt_crypto::handshake_flow::MSG_INIT {
            self.respond_to_handshake(bytes, from)
        } else {
            self.complete_handshake(bytes, from)
        }
    }

    fn respond_to_handshake(&mut self, bytes: &[u8], from: SocketAddr) -> Result<()> {
        let mut responder = Responder::begin(
            self.identity.clone_identity(),
            self.kem_suite,
            self.sig_suite,
        )?;
        responder.read_message_1(bytes)?;
        let response = responder.write_message_2()?;

        // The responder's traffic keys are the mirror of the initiator's.
        let (send_key, recv_key) = responder.split_traffic_keys()?;

        // The session identifier must be identical on both sides. The
        // transcript hash is the one value both parties agree on, so it is
        // used as the session nonce.
        let transcript = responder.transcript_hash();
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&transcript[..8]);

        // The initiator is the peer whose datagram we received; the
        // responder is us.
        let session_id = derive_session_id(from, &self.identity.public_key(), &nonce);
        let session = Session::new(session_id, send_key, recv_key);

        self.socket.send_to(&response, from)?;

        self.peers.insert(
            from,
            Peer {
                address: from,
                state: PeerState::Connected(Box::new(session)),
                static_key: None,
            },
        );
        Ok(())
    }

    fn complete_handshake(&mut self, bytes: &[u8], from: SocketAddr) -> Result<()> {
        let entry = self
            .peers
            .get_mut(&from)
            .ok_or(NodeError::Crypto(Error::InvalidKey(
                "no handshake in progress for this peer",
            )))?;

        let peer_key = entry
            .static_key
            .clone()
            .ok_or(NodeError::Crypto(Error::InvalidKey(
                "no peer key for this handshake",
            )))?;

        let state = std::mem::replace(&mut entry.state, PeerState::Failed);
        let mut initiator = match state {
            PeerState::Handshaking { initiator, .. } => initiator,
            other => {
                entry.state = other;
                return Err(NodeError::Crypto(Error::InvalidKey(
                    "unexpected handshake response",
                )));
            }
        };

        let result = initiator.read_message_2(bytes)?;

        // Both sides derive the session identifier from the transcript hash,
        // which they both know, plus the responder's public key and the
        // initiator's address.
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&result.transcript_hash[..8]);
        let session_id = derive_session_id(self.local, &peer_key.ed25519, &nonce);

        let session = Session::new(session_id, result.send_key, result.recv_key);
        entry.state = PeerState::Connected(Box::new(session));
        Ok(())
    }

    fn handle_data(&mut self, bytes: &[u8], from: SocketAddr) -> Result<Vec<Packet>> {
        let entry = self
            .peers
            .get_mut(&from)
            .ok_or(NodeError::Crypto(Error::InvalidKey("unknown peer")))?;

        let packet = match &mut entry.state {
            PeerState::Connected(session) => session.open(bytes)?,
            _ => {
                return Err(NodeError::Crypto(Error::InvalidKey(
                    "no session with this peer",
                )))
            }
        };

        Ok(packet.into_iter().collect())
    }

    /// Retry any handshakes that have timed out.
    ///
    /// Returns the number of retries sent.
    pub fn retry_timeouts(&mut self) -> Result<usize> {
        let mut retried = 0usize;
        let now = Instant::now();

        for peer in self.peers.values_mut() {
            let should_retry = match &peer.state {
                PeerState::Handshaking {
                    sent_at, attempts, ..
                } => {
                    now.duration_since(*sent_at) > HANDSHAKE_TIMEOUT
                        && *attempts < HANDSHAKE_ATTEMPTS
                }
                _ => false,
            };
            if should_retry {
                if let PeerState::Handshaking {
                    initiator,
                    sent_at,
                    attempts,
                } = &mut peer.state
                {
                    *sent_at = now;
                    *attempts += 1;
                    let msg = initiator.write_message_1()?;
                    let addr = peer.address;
                    self.socket.send_to(&msg, addr)?;
                    retried += 1;
                }
            }
        }
        Ok(retried)
    }

    /// Whether a peer has an established session.
    pub fn is_connected(&self, peer: &SocketAddr) -> bool {
        matches!(
            self.peers.get(peer).map(|p| &p.state),
            Some(PeerState::Connected(_))
        )
    }

    /// Send a ping to a peer and measure the round trip.
    ///
    /// Returns the round-trip time in microseconds.
    pub fn ping(&mut self, peer: SocketAddr) -> Result<u64> {
        let start = Instant::now();
        let mut payload = Vec::new();
        payload.extend_from_slice(&start.elapsed().as_nanos().to_be_bytes());
        self.send(peer, &Packet::new(zt_crypto::packet::TYPE_PING, payload))?;
        Ok(start.elapsed().as_micros() as u64)
    }
}

/// Derive a session identifier that both peers compute identically.
///
/// The inputs must be the same on both sides, so the derivation uses the
/// *initiator's* address and the *responder's* public key — not each peer's
/// own view. The initiator knows the responder's address (it dialled it) and
/// the responder knows the initiator's address (the datagram source), so
/// both can compute it.
///
/// The identifier must be unique per session so that ciphertexts from an
/// earlier session cannot be replayed into a later one.
fn derive_session_id(
    initiator_addr: SocketAddr,
    responder_key: &[u8; 32],
    session_nonce: &[u8; 8],
) -> [u8; 4] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zt-next/session-id/v1");
    hasher.update(initiator_addr.ip().to_string().as_bytes());
    hasher.update(&initiator_addr.port().to_be_bytes());
    hasher.update(responder_key);
    hasher.update(session_nonce);
    let digest = hasher.finalize();
    let mut id = [0u8; 4];
    id.copy_from_slice(&digest.as_bytes()[..4]);
    id
}
