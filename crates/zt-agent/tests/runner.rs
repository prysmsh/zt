//! The agent's data plane, driven against a real controller.
//!
//! The controller runs on a loopback port and the agent talks to it over
//! HTTP, because that is the agent's whole job. The network interface is
//! a queue rather than a kernel device, so the test needs no privileges.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use zt_agent::{Agent, AgentConfig, Runner, RunnerConfig};
use zt_controller::{Controller, IdentityStore, SqliteStore};
use zt_tun::PacketDevice;

/// The network the two nodes share.
const NETWORK: &str = "10.77.0.0/24";

/// A controller running on a loopback port for the duration of a test.
struct TestController {
    address: SocketAddr,
    /// The controller, so the test can seed through the service layer.
    controller: Controller,
    _data_dir: tempfile::TempDir,
}

impl TestController {
    async fn start() -> TestController {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let identity_path = data_dir.path().join("controller.key");
        let database_path = data_dir.path().join("controller.db");

        let identity = IdentityStore::new(&identity_path)
            .load_or_create()
            .expect("identity");
        let store = Arc::new(SqliteStore::open(&database_path).expect("store"));
        let controller = Controller::with_store(identity, store).expect("controller");

        // The controller requires authentication, because the node's own
        // credential is what identifies it. The verifier points nowhere,
        // so no provider token is accepted.
        let state = zt_controller::AuthState {
            verifier: std::sync::Arc::new(zt_controller::Verifier::new(
                zt_controller::AuthConfig::new(
                    "https://issuer.invalid",
                    "https://audience.invalid",
                    "https://issuer.invalid/jwks",
                ),
            )),
            controller: controller.clone(),
            tenant_scope: "zt:tenant".to_string(),
            operator_scope: "zt:operator".to_string(),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");

        let served = controller.clone();
        tokio::spawn(async move {
            let app = zt_controller::router_with_auth(served, state);
            let _ = axum::serve(listener, app).await;
        });

        for _ in 0..100 {
            match tokio::net::TcpStream::connect(address).await {
                Ok(stream) => {
                    drop(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }

        TestController {
            address,
            controller,
            _data_dir: data_dir,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}

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

/// Create a tenant and a network, returning the tenant and network ids.
///
/// The tenant and the network are created through the service layer. The
/// controller requires an operator token for those, and the test has none:
/// what it is testing is the node's own path, which uses the node's
/// credential.
async fn seed(controller: &TestController) -> (String, String) {
    let tenant = controller
        .controller
        .create_tenant(
            "Runner Test".into(),
            "runner-test".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("create tenant");

    let network = controller
        .controller
        .create_network(
            &tenant.id,
            "Runner Net".into(),
            String::new(),
            NETWORK.into(),
            None,
            &zt_controller::Actor::system(),
        )
        .await
        .expect("create network");

    (tenant.id, network.id)
}

/// An agent that has enrolled, with its state on disk.
struct EnrolledAgent {
    agent: Agent,
    _dir: tempfile::TempDir,
}

async fn enroll(
    controller: &TestController,
    tenant_id: &str,
    network_id: &str,
    name: &str,
) -> EnrolledAgent {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path: PathBuf = dir.path().join("node.json");

    let config = AgentConfig {
        controller_url: controller.url(),
        // The tenant is named by its identifier. A slug would have to be
        // resolved, and resolving one lists the tenants, which is the
        // operator's path and not the node's.
        tenant: tenant_id.to_string(),
        network_id: network_id.to_string(),
        state_path,
        ..Default::default()
    };

    let mut agent = Agent::open(config).expect("open");

    // The operator enrols the node from the console and hands over the
    // credential. The enrolment goes through the service layer, because
    // the operator's own token is not what this test is about.
    let ed25519: [u8; 32] = hex::decode(agent.state().public_key_hex().expect("key"))
        .expect("hex")
        .try_into()
        .expect("32 bytes");

    let ml_dsa = agent.state().pq_key_pair().expect("key pair").public_key();

    let (_, credential) = controller
        .controller
        .enroll_node(
            tenant_id,
            network_id,
            name.to_string(),
            zt_controller::model::NodeKeys { ed25519, ml_dsa },
            Vec::new(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("enrol");

    agent
        .adopt(&hex::encode(credential.serialize()))
        .expect("adopt");

    EnrolledAgent { agent, _dir: dir }
}

/// A runner over a queue device, with the queue's handles.
fn runner(agent: &Agent, queue: Queue) -> Runner {
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("address");

    Runner::new(
        Box::new(QueueDevice { queue, mtu: 1400 }),
        agent.client().clone(),
        agent.state().static_identity().expect("identity"),
        agent.membership().expect("membership"),
        agent.trust().expect("trust"),
        agent.state().pq_public_key_hex().expect("post-quantum key"),
        RunnerConfig {
            listen,
            ..Default::default()
        },
    )
    .expect("runner")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_runner_learns_its_own_address_and_its_peers() {
    let controller = TestController::start().await;
    let (tenant_id, network_id) = seed(&controller).await;

    let first = enroll(&controller, &tenant_id, &network_id, "web-01").await;
    let second = enroll(&controller, &tenant_id, &network_id, "web-02").await;

    // The second node reports where it can be reached, so the first node
    // has something to route to.
    let second_client = second.agent.client().clone();
    second_client
        .report_presence(
            "127.0.0.1:9995",
            &second.agent.state().pq_public_key_hex().unwrap(),
        )
        .expect("report");

    let queue = Queue::default();
    let mut runner = runner(&first.agent, queue);

    runner.refresh_topology().expect("topology");

    let address: Ipv4Addr = runner
        .plane()
        .routes()
        .address_of("127.0.0.1:9995".parse().expect("address"))
        .expect("the peer should be routed");

    // The node's own address is in the network's range, and the peer has
    // the next one.
    assert_eq!(address, Ipv4Addr::new(10, 77, 0, 2));
    assert_eq!(runner.plane().routes().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_packet_crosses_the_overlay_between_two_runners() {
    let controller = TestController::start().await;
    let (tenant_id, network_id) = seed(&controller).await;

    let first = enroll(&controller, &tenant_id, &network_id, "web-01").await;
    let second = enroll(&controller, &tenant_id, &network_id, "web-02").await;

    // The two runners listen on loopback ports of their own.
    let first_queue = Queue::default();
    let first_runner = runner(&first.agent, first_queue.clone());

    let second_queue = Queue::default();
    let mut second_runner = runner(&second.agent, second_queue.clone());

    // Each node reports where its peers reach it.
    first_runner
        .report_presence(&first.agent.state().pq_public_key_hex().unwrap())
        .expect("report");
    second_runner
        .report_presence(&second.agent.state().pq_public_key_hex().unwrap())
        .expect("report");

    // Both learn the topology.
    let mut first_runner = first_runner;
    first_runner.refresh_topology().expect("topology");
    second_runner.refresh_topology().expect("topology");

    // The first node knows where the second one is.
    let second_endpoint = second_runner.local_addr();
    let second_address = first_runner
        .plane()
        .routes()
        .address_of(second_endpoint)
        .expect("the second node should be routed");

    // The handshake is completed by the first node reaching out.
    first_runner.connect_peers().expect("connect");

    // The session has to be up before a packet is worth sending: a packet
    // that arrives before the handshake is finished is dropped.
    for _ in 0..100 {
        first_runner.poll().expect("poll");
        second_runner.poll().expect("poll");

        if first_runner.is_connected(second_endpoint) {
            break;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        first_runner.is_connected(second_endpoint),
        "the handshake did not complete"
    );

    // A packet for the second node is read from the first node's device.
    let payload = b"across the overlay";
    first_queue.outbound.lock().unwrap().push(ipv4(
        Ipv4Addr::new(10, 77, 0, 1),
        second_address,
        payload,
    ));

    // The first node sends it, and the second one writes it to its device.
    for _ in 0..100 {
        first_runner.poll().expect("poll");
        second_runner.poll().expect("poll");

        if !second_queue.written.lock().unwrap().is_empty() {
            break;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let written = second_queue.written.lock().unwrap().clone();
    assert_eq!(
        written.len(),
        1,
        "the second node's device was not written to"
    );
    assert_eq!(
        written[0],
        ipv4(Ipv4Addr::new(10, 77, 0, 1), second_address, payload),
        "the packet arrived altered"
    );
}
