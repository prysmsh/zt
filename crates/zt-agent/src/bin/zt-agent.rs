//! The `zt-agent` command line interface.
//!
//! The agent is the node's control-plane client. It enrolls with a
//! controller, keeps the credential fresh, and reports the node's status.
//!
//! ```text
//! zt-agent enroll --controller http://127.0.0.1:8080 --tenant acme \
//!     --network <network-id> --name web-01
//! zt-agent renew
//! zt-agent status
//! zt-agent identity
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use zt_agent::{Agent, AgentConfig, AgentError, ControllerClient, Result};

const USAGE: &str = "\
zt-agent — ZT-next node agent

USAGE:
    zt-agent <COMMAND> [OPTIONS]

COMMANDS:
    enroll     Enroll this node with a controller and store its credential
    adopt      Store a credential an operator issued for this node
    renew      Renew the credential if it is due for renewal
    status     Show the node's enrollment and credential status
    identity   Print the node's public key and address
    checkin    Tell the controller the node is here, and fetch the topology
    run        Carry traffic: open the interface and forward packets

OPTIONS:
    --controller <URL>    Controller base URL (default: http://127.0.0.1:8080)
    --tenant <SLUG>       Tenant the node belongs to (required for enroll)
    --network <ID>        Network to join (required for enroll)
    --name <NAME>         Human-readable node name (required for enroll)
    --tags <A,B>          Comma-separated tags
    --credential <HEX>    The credential an operator issued (for adopt)
    --state <PATH>        Path to the node state file (default: zt-node.json)
    --interface <NAME>    Interface to open for the data plane (default: zt0)
    --listen <ADDR:PORT>  Address the node listens on (default: 0.0.0.0:9994)
    --relay               Forward packets between the others (no interface)
    --interval <SECONDS>  Repeat the check-in every so many seconds
    --force               Renew even when the credential is not yet due
    -h, --help            Print this help

The controller's public key is fetched on first run and pinned in the state
file. The state file holds private key material and is written with
owner-only permissions.
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    match run(&arguments) {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
            ExitCode::SUCCESS
        }
        Err(AgentError::Usage(message)) => {
            eprintln!("error: {message}\n");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// A parsed command line.
struct Options {
    command: String,
    controller: String,
    tenant: String,
    network: String,
    name: String,
    tags: Vec<String>,
    credential: Option<String>,
    state: PathBuf,
    force: bool,
    interface: String,
    listen: String,
    interval: Option<u64>,
    relay: bool,
}

/// Parse the command line.
fn parse(arguments: &[String]) -> Result<Options> {
    let mut options = Options {
        command: String::new(),
        controller: "http://127.0.0.1:8080".to_string(),
        tenant: String::new(),
        network: String::new(),
        name: String::new(),
        tags: Vec::new(),
        credential: None,
        state: PathBuf::from("zt-node.json"),
        force: false,
        interface: "zt0".to_string(),
        listen: "0.0.0.0:9994".to_string(),
        interval: None,
        relay: false,
    };

    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        match argument {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--force" => options.force = true,
            "--relay" => options.relay = true,
            "--controller" | "--tenant" | "--network" | "--name" | "--tags" | "--state"
            | "--credential" | "--interface" | "--listen" | "--interval" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| AgentError::Usage(format!("{argument} needs a value")))?;
                match argument {
                    "--controller" => options.controller = value.clone(),
                    "--tenant" => options.tenant = value.clone(),
                    "--network" => options.network = value.clone(),
                    "--name" => options.name = value.clone(),
                    "--tags" => {
                        options.tags = value
                            .split(',')
                            .map(|tag| tag.trim().to_string())
                            .filter(|tag| !tag.is_empty())
                            .collect()
                    }
                    "--state" => options.state = PathBuf::from(value),
                    "--credential" => options.credential = Some(value.clone()),
                    "--interface" => options.interface = value.clone(),
                    "--listen" => options.listen = value.clone(),
                    "--interval" => {
                        options.interval = Some(value.parse().map_err(|_| {
                            AgentError::Usage(format!("'{value}' is not a number of seconds"))
                        })?)
                    }
                    _ => unreachable!(),
                }
            }
            other if other.starts_with('-') => {
                return Err(AgentError::Usage(format!("unknown option {other}")));
            }
            other => {
                if options.command.is_empty() {
                    options.command = other.to_string();
                } else {
                    return Err(AgentError::Usage(format!("unexpected argument {other}")));
                }
            }
        }
        index += 1;
    }

    if options.command.is_empty() {
        return Err(AgentError::Usage("a command is required".into()));
    }

    Ok(options)
}

/// Run the requested command.
fn run(arguments: &[String]) -> Result<String> {
    let options = parse(arguments)?;

    let config = AgentConfig {
        controller_url: options.controller.clone(),
        tenant: options.tenant.clone(),
        network_id: options.network.clone(),
        state_path: options.state.clone(),
        ..Default::default()
    };

    match options.command.as_str() {
        "enroll" => enroll(options, config),
        "join" => join(options, config),
        "adopt" => adopt(options, config),
        "renew" => renew(options, config),
        "status" => status(options, config),
        "identity" => identity(options, config),
        "checkin" => checkin(options, config),
        "run" => run_data_plane(options, config),
        other => Err(AgentError::Usage(format!("unknown command {other}"))),
    }
}

/// Enroll the node and store its credential.
fn enroll(options: Options, config: AgentConfig) -> Result<String> {
    if options.tenant.is_empty() {
        return Err(AgentError::Usage("--tenant is required to enroll".into()));
    }
    if options.network.is_empty() {
        return Err(AgentError::Usage("--network is required to enroll".into()));
    }
    if options.name.is_empty() {
        return Err(AgentError::Usage("--name is required to enroll".into()));
    }

    let mut agent = Agent::open(config)?;
    let response = agent.enroll(&options.name, &options.tags)?;

    Ok(format!(
        "Enrolled {} in network {}\n  node id:   {}\n  address:   {}\n  expires:   {}\n  state:     {}",
        response.node.name,
        response.node.network_id,
        response.node.id,
        response.node.address,
        timestamp(response.credential_not_after),
        options.state.display(),
    ))
}

/// Ask to join a network and wait for the operator to approve it.
///
/// This is the flow that needs nothing from the operator up front: the
/// host asks to join, the operator clicks Approve in the console, and the
/// host picks up its credential on its next poll.
fn join(options: Options, config: AgentConfig) -> Result<String> {
    if options.tenant.is_empty() {
        return Err(AgentError::Usage("--tenant is required to join".into()));
    }
    if options.network.is_empty() {
        return Err(AgentError::Usage("--network is required to join".into()));
    }
    if options.name.is_empty() {
        return Err(AgentError::Usage("--name is required to join".into()));
    }

    // The join endpoint takes the slug, so the agent skips the
    // operator-scoped tenant resolution entirely.
    let mut config = config;
    config.tenant = String::new();

    let mut agent = Agent::open(config)?;

    eprintln!(
        "Asked to join {} — waiting for the operator to approve it in the console...",
        options.tenant
    );

    // Five minutes is enough time to open the console and click. The node
    // stays pending afterwards, so nothing is lost by timing out.
    let node = agent.join(
        &options.tenant,
        &options.name,
        std::time::Duration::from_secs(300),
    )?;

    Ok(format!(
        "Joined {} in network {}\n  node id:   {}\n  address:   {}\n  state:     {}",
        node.name,
        node.network_id,
        node.id,
        node.address,
        options.state.display(),
    ))
}

/// Adopt a credential an operator issued for this node.
///
/// The controller authenticates a node with the credential it issued it, so
/// a node that was enrolled by an operator adopts that credential. The node
/// then asks the controller who it is, which is how it learns its own
/// identifier.
fn adopt(options: Options, config: AgentConfig) -> Result<String> {
    let Some(credential) = options.credential else {
        return Err(AgentError::Usage(
            "--credential is required to adopt a credential".into(),
        ));
    };

    let mut agent = Agent::open(config)?;
    let node = agent.adopt(&credential)?;

    Ok(format!(
        "Adopted the credential for {}\n  node id:   {}\n  network:   {}\n  address:   {}\n  expires:   {}\n  state:     {}",
        node.name,
        node.id,
        node.network_id,
        node.address,
        timestamp(node.credential_not_after),
        options.state.display(),
    ))
}

/// Renew the credential if it is due.
fn renew(options: Options, config: AgentConfig) -> Result<String> {
    let mut agent = Agent::open(config)?;
    let now = now_unix();

    if options.force {
        // A forced renewal re-enrolls the credential for the same node.
        let node_id = agent.state().node_id.clone();
        if node_id.is_empty() {
            return Err(AgentError::NotEnrolled);
        }
        let response = agent.client().renew_credential(&node_id)?;
        agent.state_mut().set_credential(
            &response.node.id,
            &response.node.network_id,
            &response.credential,
            response.credential_not_after,
        );
        agent.save()?;
        return Ok(format!(
            "Renewed credential for {}\n  expires: {}",
            response.node.name,
            timestamp(response.credential_not_after)
        ));
    }

    match agent.renew_if_due(now)? {
        Some(response) => Ok(format!(
            "Renewed credential for {}\n  expires: {}",
            response.node.name,
            timestamp(response.credential_not_after)
        )),
        None => {
            let state = agent.state();
            Ok(format!(
                "Credential is still valid.\n  expires: {}\n  remaining: {}",
                timestamp(state.credential_not_after),
                humanize_duration(state.credential_ttl(now))
            ))
        }
    }
}

/// Show the node's status.
fn status(options: Options, config: AgentConfig) -> Result<String> {
    let agent = Agent::open(config)?;
    let state = agent.state();
    let now = now_unix();

    if state.node_id.is_empty() {
        return Ok(format!(
            "Not enrolled.\n  identity: {}\n  state:    {}",
            state.public_key_hex().unwrap_or_default(),
            options.state.display()
        ));
    }

    let mut lines = vec![
        format!("Node {}", state.node_id),
        format!("  network:   {}", state.network_id),
        format!(
            "  identity:  {}",
            state.public_key_hex().unwrap_or_default()
        ),
        format!("  expires:   {}", timestamp(state.credential_not_after)),
        format!(
            "  remaining: {}",
            humanize_duration(state.credential_ttl(now))
        ),
    ];

    if state.credential_expired(now) {
        lines.push("  status:    EXPIRED — run `zt-agent renew`".to_string());
    } else if agent.needs_renewal(now) {
        lines.push("  status:    renewal due".to_string());
    } else {
        lines.push("  status:    healthy".to_string());
    }

    Ok(lines.join("\n"))
}

/// Print the node's identity.
fn identity(options: Options, config: AgentConfig) -> Result<String> {
    let agent = Agent::open(config)?;
    let state = agent.state();
    let public_key = state.public_key_hex()?;

    Ok(format!(
        "public key: {public_key}\nstate:      {}",
        options.state.display()
    ))
}

/// Tell the controller the node is here.
///
/// A node that runs the control plane but not the data plane still has to
/// tell the controller it is alive: the console shows a node as online
/// while it keeps hearing from it, and a node that goes quiet is shown as
/// offline.
///
/// The node reports the endpoint its peers would reach it at, and asks
/// for the topology. With `--interval` it keeps doing so, which is what a
/// node that only carries the control plane runs.
fn checkin(options: Options, config: AgentConfig) -> Result<String> {
    let agent = Agent::open(config)?;

    let listen: std::net::SocketAddr = options
        .listen
        .parse()
        .map_err(|_| AgentError::Usage(format!("'{}' is not an address", options.listen)))?;

    // The endpoint is the address the node listens on. A node that only
    // runs the control plane may not listen at all, in which case the
    // address it would be reached at is still worth reporting.
    let socket = std::net::UdpSocket::bind(listen)
        .map_err(|error| AgentError::Io(format!("cannot listen: {error}")))?;
    let endpoint = socket
        .local_addr()
        .map_err(|error| AgentError::Io(error.to_string()))?;

    let pq_public_key = agent.state().pq_public_key_hex()?;
    let client = agent.client().clone();

    let report = |client: &ControllerClient| -> Result<usize> {
        client.report_presence(
            &endpoint.to_string(),
            &pq_public_key,
            &zt_agent::NodeUsage::default(),
        )?;
        Ok(0)
    };

    match options.interval {
        Some(seconds) => loop {
            report(&client)?;

            let topology = client.topology()?;
            println!(
                "checked in as {} in {} ({} peers)",
                topology.address,
                topology.cidr,
                topology.peers.len()
            );

            std::thread::sleep(Duration::from_secs(seconds.max(1)));
        },
        None => {
            report(&client)?;

            let topology = client.topology()?;
            Ok(format!(
                "Checked in as {} in {}\n  peers:   {}\n  state:   {}",
                topology.address,
                topology.cidr,
                topology.peers.len(),
                options.state.display(),
            ))
        }
    }
}

/// Carry traffic.
///
/// The node opens the virtual interface, tells the controller how its peers
/// reach it, asks for the topology, and forwards packets between the
/// interface and the peers until it is stopped.
fn run_data_plane(options: Options, config: AgentConfig) -> Result<String> {
    let agent = Agent::open(config)?;

    let listen: std::net::SocketAddr = options
        .listen
        .parse()
        .map_err(|_| AgentError::Usage(format!("'{}' is not an address", options.listen)))?;

    // The interface is opened by the operating system: the node needs the
    // privilege to create it, and the agent asks for none. A relay has no
    // interface at all, so it runs without one.
    let device: Box<dyn zt_tun::PacketDevice> = if options.relay {
        Box::new(zt_tun::NullDevice)
    } else {
        Box::new(
            zt_tun::TunDevice::open(&options.interface, 1400).map_err(|error| {
                AgentError::Io(format!("cannot open the interface: {error}"))
            })?,
        )
    };

    let runner_config = zt_agent::RunnerConfig {
        interface: options.interface.clone(),
        mtu: 1400,
        listen,
        relay: options.relay,
        ..Default::default()
    };

    let mut runner = zt_agent::Runner::new(
        Box::new(device),
        agent.client().clone(),
        agent.state().static_identity()?,
        agent.membership()?,
        agent.trust()?,
        agent.state().pq_public_key_hex()?,
        runner_config,
    )?;

    // The controller needs to know where the peers can reach this node,
    // and which post-quantum key they check its signature with. The runner
    // reports it on every refresh, so the node stays online.
    runner.report_presence(&agent.state().pq_public_key_hex()?)?;

    runner.run()?;

    Ok(String::new())
}

/// The current Unix time in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Render a Unix timestamp as a readable date.
///
/// The system clock's timezone is used, because this is operator-facing
/// output rather than a protocol value.
fn timestamp(unix_seconds: u64) -> String {
    let seconds = unix_seconds as i64;
    let days = seconds / 86_400;
    let time_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

/// Convert days since the Unix epoch into a civil date.
///
/// This is Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Render a duration in seconds as a short human-readable string.
fn humanize_duration(seconds: u64) -> String {
    if seconds == 0 {
        return "expired".to_string();
    }
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3600;
    let minutes = (seconds % 3600) / 60;

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}
