//! Kernel WireGuard link for tesserax, brought up with `ip` and `wg`.
//!
//! The link itself is a kernel WireGuard interface. This crate plans and
//! applies that bring-up. It does not speak a userspace UDP stack, does not
//! terminate TLS, and does not spawn QEMU. A [`Neighbor::Qemu`] entry only
//! checks that an existing tap name is a legal interface name and that the
//! guest tunnel address is already a host route on a peer.
//!
//! [`validate`] does not read the private key file. [`plan`] does not run
//! anything. [`apply`] runs the plan through a [`Runner`]. On Linux,
//! [`CommandRunner`] uses [`std::process::Command`] and passes `wg` only the
//! key path. Elsewhere, [`apply_system`] returns [`Error::Unsupported`].
//!
//! # Example
//!
//! ```
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//! use std::path::PathBuf;
//! use tesserax_wireguard::{AllowedIp, LinkConfig, Neighbor, Peer, plan, validate};
//!
//! let endpoint: SocketAddr = "192.0.2.10:51820".parse().unwrap();
//! let config = LinkConfig {
//!     interface_name: "wg-tess".to_string(),
//!     private_key_path: PathBuf::from("/run/wg.key"),
//!     listen_port: 51820,
//!     local_tunnel: IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1)),
//!     peers: vec![Peer {
//!         public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
//!         endpoint,
//!         allowed_ips: vec![AllowedIp::host(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)))],
//!         persistent_keepalive_secs: 25,
//!     }],
//!     neighbors: vec![Neighbor::Endpoint(endpoint)],
//! };
//! validate(&config).unwrap();
//! let commands = plan(&config);
//! assert!(commands.iter().all(|command| command.program != "qemu"));
//! assert_eq!(commands[0].program, "ip");
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

/// One CIDR in a peer's `allowed-ips` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedIp {
    /// Network address of the prefix.
    pub address: IpAddr,
    /// Prefix length: `0..=32` for IPv4, `0..=128` for IPv6.
    pub prefix_len: u8,
}

impl AllowedIp {
    /// A host route: `/32` for IPv4, `/128` for IPv6.
    pub fn host(address: IpAddr) -> Self {
        let prefix_len = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self {
            address,
            prefix_len,
        }
    }

    /// Parse `addr/prefix`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        text.parse()
    }

    /// Whether this prefix is a single host (`/32` or `/128`).
    pub fn is_host(&self) -> bool {
        match self.address {
            IpAddr::V4(_) => self.prefix_len == 32,
            IpAddr::V6(_) => self.prefix_len == 128,
        }
    }

    /// `address/prefix` as `wg` and `ip` print it.
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.address, self.prefix_len)
    }

    fn prefix_legal(&self) -> bool {
        match self.address {
            IpAddr::V4(_) => self.prefix_len <= 32,
            IpAddr::V6(_) => self.prefix_len <= 128,
        }
    }
}

impl FromStr for AllowedIp {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = text
            .split_once('/')
            .ok_or(Error::Invalid(Invalid::AllowedIpParse))?;
        if addr.is_empty() || prefix.is_empty() {
            return Err(Error::Invalid(Invalid::AllowedIpParse));
        }
        let address: IpAddr = addr
            .parse()
            .map_err(|_| Error::Invalid(Invalid::AllowedIpParse))?;
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|_| Error::Invalid(Invalid::AllowedIpParse))?;
        let allowed = Self {
            address,
            prefix_len,
        };
        if !allowed.prefix_legal() {
            return Err(Error::Invalid(Invalid::Prefix));
        }
        Ok(allowed)
    }
}

/// One kernel WireGuard peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Peer public key, as `wg` expects it (standard base64).
    pub public_key: String,
    /// Public UDP endpoint of the peer. Not a tunnel address.
    pub endpoint: SocketAddr,
    /// Traffic selectors for this peer.
    pub allowed_ips: Vec<AllowedIp>,
    /// Persistent keepalive in seconds. Must be greater than zero.
    pub persistent_keepalive_secs: u16,
}

/// What sits beside the tunnel.
///
/// Neither variant starts a virtual machine or opens a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Neighbor {
    /// The peer's public endpoint. The plan does not emit a command for it;
    /// the endpoint is already taken from [`Peer::endpoint`].
    Endpoint(SocketAddr),
    /// An adjacent QEMU guest that is already attached to `tap`.
    ///
    /// `guest_tunnel` is that guest's address inside the tunnel and must be
    /// one of a peer's allowed IPs as a host route. Bring-up only checks that
    /// `tap` is a legal interface name (`ip link show`). This crate does not
    /// spawn QEMU, build a QEMU command line, or open the tap.
    Qemu {
        /// Existing tap interface the guest is attached to.
        tap: String,
        /// Guest address inside the tunnel.
        guest_tunnel: IpAddr,
    },
}

/// Everything required to bring a kernel WireGuard interface up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfig {
    /// Interface name, 1..=16 bytes of ASCII alphanumeric, `_`, or `-`.
    pub interface_name: String,
    /// Path `wg` will read. [`validate`] does not open it.
    pub private_key_path: PathBuf,
    /// UDP listen port. `0` leaves the port unset in the kernel's usual way
    /// and is still passed through to `wg`.
    pub listen_port: u16,
    /// Host address placed on the interface (`/32` or `/128`).
    pub local_tunnel: IpAddr,
    /// At least one peer. More than one is allowed.
    pub peers: Vec<Peer>,
    /// Optional beside-the-tunnel notes. Empty is valid.
    pub neighbors: Vec<Neighbor>,
}

/// One process invocation in a bring-up plan. Never executed by [`plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// Executable name (`ip` or `wg`). Not a shell line.
    pub program: String,
    /// Arguments, each already a single argv element.
    pub args: Vec<String>,
}

impl Command {
    fn new(program: &str, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: program.to_string(),
            args: args.into_iter().collect(),
        }
    }
}

/// Why [`validate`] rejected a config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Interface name is empty, longer than 16 bytes, or not ASCII `[A-Za-z0-9_-]`.
    InterfaceName,
    /// Private key path is empty. The file is not read.
    EmptyKeyPath,
    /// `local_tunnel` is `0.0.0.0` or `::`.
    UnspecifiedLocal,
    /// `peers` is empty.
    NoPeers,
    /// A peer public key is empty.
    EmptyPublicKey,
    /// A peer endpoint address is unspecified.
    UnspecifiedEndpoint,
    /// A peer endpoint port is `0`.
    ZeroEndpointPort,
    /// `persistent_keepalive_secs` is `0`.
    ZeroKeepalive,
    /// A peer has no allowed IPs.
    EmptyAllowedIps,
    /// An allowed-IP prefix is illegal for its address family.
    Prefix,
    /// A host-route tunnel address is a different family from `local_tunnel`.
    Family,
    /// A QEMU tap name is not a legal interface name.
    TapName,
    /// A QEMU `guest_tunnel` is not a host route (`/32` or `/128`) of a peer.
    GuestTunnel,
    /// `addr/prefix` text could not be parsed.
    AllowedIpParse,
}

impl Invalid {
    fn as_str(self) -> &'static str {
        match self {
            Invalid::InterfaceName => {
                "interface name must be 1..=16 bytes of ASCII alphanumeric, '_' or '-'"
            }
            Invalid::EmptyKeyPath => "private key path is empty",
            Invalid::UnspecifiedLocal => "local tunnel address is unspecified",
            Invalid::NoPeers => "at least one peer is required",
            Invalid::EmptyPublicKey => "peer public key is empty",
            Invalid::UnspecifiedEndpoint => "peer endpoint address is unspecified",
            Invalid::ZeroEndpointPort => "peer endpoint port must not be 0",
            Invalid::ZeroKeepalive => "persistent keepalive must be greater than 0",
            Invalid::EmptyAllowedIps => "peer allowed IPs must not be empty",
            Invalid::Prefix => "allowed IP prefix is not legal for its address family",
            Invalid::Family => "tunnel host address family does not match the local tunnel address",
            Invalid::TapName => "tap name must be a valid interface name",
            Invalid::GuestTunnel => "guest tunnel address is not a host route of a peer",
            Invalid::AllowedIpParse => "allowed IP must be addr/prefix",
        }
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bring-up failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The config is not usable. No command was run.
    Invalid(Invalid),
    /// `ip link add` failed. No userspace WireGuard device is substituted.
    InterfaceCreate {
        /// Interface that was not created.
        interface: String,
        /// Runner detail. Does not include key material.
        detail: String,
    },
    /// A later planned command failed. If the interface had been created,
    /// `ip link del` was attempted and this is still the original failure.
    Command {
        /// Program that failed (`ip` or `wg`).
        program: String,
        /// Runner detail. Does not include key material.
        detail: String,
    },
    /// [`apply_system`] on a non-Linux target.
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(kind) => f.write_str(kind.as_str()),
            Error::InterfaceCreate { interface, detail } => {
                write!(f, "creating interface {interface} failed: {detail}")
            }
            Error::Command { program, detail } => write!(f, "{program} failed: {detail}"),
            Error::Unsupported => f.write_str(
                "kernel WireGuard via ip and wg is unsupported on this operating system",
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Failure reported by a [`Runner`].
///
/// Details must not contain private key bytes. A key path is the only key
/// material that may appear, and only because `wg` was given that path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunError {
    detail: String,
}

impl RunError {
    /// A failure whose `detail` is already safe to surface.
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// Runner message without the planned argv.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for RunError {}

/// Executes one planned command.
pub trait Runner {
    /// Run `command`. Do not log arguments that carry key material.
    fn run(&mut self, command: &Command) -> Result<(), RunError>;
}

/// Check `config` without reading the private key file and without running
/// anything.
pub fn validate(config: &LinkConfig) -> Result<(), Error> {
    if !valid_ifname(&config.interface_name) {
        return Err(Error::Invalid(Invalid::InterfaceName));
    }
    if config.private_key_path.as_os_str().is_empty() {
        return Err(Error::Invalid(Invalid::EmptyKeyPath));
    }
    if config.local_tunnel.is_unspecified() {
        return Err(Error::Invalid(Invalid::UnspecifiedLocal));
    }
    if config.peers.is_empty() {
        return Err(Error::Invalid(Invalid::NoPeers));
    }
    for peer in &config.peers {
        validate_peer(config.local_tunnel, peer)?;
    }
    for neighbor in &config.neighbors {
        if let Neighbor::Qemu { tap, guest_tunnel } = neighbor {
            if !valid_ifname(tap) {
                return Err(Error::Invalid(Invalid::TapName));
            }
            if !host_route_of_some_peer(&config.peers, *guest_tunnel) {
                return Err(Error::Invalid(Invalid::GuestTunnel));
            }
        }
    }
    Ok(())
}

fn validate_peer(local: IpAddr, peer: &Peer) -> Result<(), Error> {
    if peer.public_key.is_empty() {
        return Err(Error::Invalid(Invalid::EmptyPublicKey));
    }
    if peer.endpoint.ip().is_unspecified() {
        return Err(Error::Invalid(Invalid::UnspecifiedEndpoint));
    }
    if peer.endpoint.port() == 0 {
        return Err(Error::Invalid(Invalid::ZeroEndpointPort));
    }
    if peer.persistent_keepalive_secs == 0 {
        return Err(Error::Invalid(Invalid::ZeroKeepalive));
    }
    if peer.allowed_ips.is_empty() {
        return Err(Error::Invalid(Invalid::EmptyAllowedIps));
    }
    for allowed in &peer.allowed_ips {
        if !allowed.prefix_legal() {
            return Err(Error::Invalid(Invalid::Prefix));
        }
        if allowed.is_host() && !same_family(local, allowed.address) {
            return Err(Error::Invalid(Invalid::Family));
        }
    }
    Ok(())
}

fn valid_ifname(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=16).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn host_route_of_some_peer(peers: &[Peer], guest: IpAddr) -> bool {
    peers.iter().any(|peer| {
        peer.allowed_ips
            .iter()
            .any(|allowed| allowed.is_host() && allowed.prefix_legal() && allowed.address == guest)
    })
}

/// Exact command sequence for `config`.
///
/// Does not validate and does not execute. Call [`validate`] first.
/// [`Neighbor::Qemu`] contributes `ip link show <tap>` after the interface
/// is up and before host routes. No program in the plan is QEMU.
pub fn plan(config: &LinkConfig) -> Vec<Command> {
    let name = &config.interface_name;
    let mut commands = Vec::new();
    commands.push(Command::new(
        "ip",
        ["link", "add", "dev", name, "type", "wireguard"].map(str::to_string),
    ));

    let key_path = config.private_key_path.display().to_string();
    let listen = config.listen_port.to_string();
    for peer in &config.peers {
        let cidrs = peer
            .allowed_ips
            .iter()
            .map(AllowedIp::cidr)
            .collect::<Vec<_>>()
            .join(",");
        commands.push(Command::new(
            "wg",
            [
                "set".to_string(),
                name.clone(),
                "listen-port".to_string(),
                listen.clone(),
                "private-key".to_string(),
                key_path.clone(),
                "peer".to_string(),
                peer.public_key.clone(),
                "endpoint".to_string(),
                peer.endpoint.to_string(),
                "allowed-ips".to_string(),
                cidrs,
                "persistent-keepalive".to_string(),
                peer.persistent_keepalive_secs.to_string(),
            ],
        ));
    }

    let prefix = match config.local_tunnel {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    commands.push(Command::new(
        "ip",
        [
            "addr".to_string(),
            "replace".to_string(),
            format!("{}/{}", config.local_tunnel, prefix),
            "dev".to_string(),
            name.clone(),
        ],
    ));
    commands.push(Command::new(
        "ip",
        ["link", "set", "up", "dev", name].map(str::to_string),
    ));

    for neighbor in &config.neighbors {
        if let Neighbor::Qemu { tap, .. } = neighbor {
            commands.push(Command::new(
                "ip",
                ["link", "show", tap.as_str()].map(str::to_string),
            ));
        }
    }

    for peer in &config.peers {
        for allowed in &peer.allowed_ips {
            if allowed.is_host() {
                commands.push(Command::new(
                    "ip",
                    [
                        "route".to_string(),
                        "replace".to_string(),
                        allowed.cidr(),
                        "dev".to_string(),
                        name.clone(),
                    ],
                ));
            }
        }
    }
    commands
}

fn is_interface_add(command: &Command) -> bool {
    command.program == "ip"
        && command.args.len() >= 6
        && command.args[0] == "link"
        && command.args[1] == "add"
        && command.args[2] == "dev"
        && command.args[4] == "type"
        && command.args[5] == "wireguard"
}

/// Validate `config` and run [`plan`] through `runner`.
///
/// On the first failing command, if `ip link add` had succeeded, `runner` is
/// asked to run `ip link del dev <name>` and the original error is returned.
/// A failure of `ip link add` is [`Error::InterfaceCreate`]; nothing else is
/// tried in its place.
pub fn apply(config: &LinkConfig, runner: &mut dyn Runner) -> Result<(), Error> {
    validate(config)?;
    let commands = plan(config);
    let mut created = false;
    for command in &commands {
        if let Err(err) = runner.run(command) {
            if created {
                let cleanup = Command::new(
                    "ip",
                    ["link", "del", "dev", config.interface_name.as_str()].map(str::to_string),
                );
                let _ = runner.run(&cleanup);
            }
            if is_interface_add(command) {
                return Err(Error::InterfaceCreate {
                    interface: config.interface_name.clone(),
                    detail: err.detail,
                });
            }
            return Err(Error::Command {
                program: command.program.clone(),
                detail: err.detail,
            });
        }
        if is_interface_add(command) {
            created = true;
        }
    }
    Ok(())
}

/// Linux runner. Spawns [`std::process::Command`] and never opens the private
/// key file. `wg` receives only the path.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct CommandRunner;

#[cfg(target_os = "linux")]
impl Runner for CommandRunner {
    fn run(&mut self, command: &Command) -> Result<(), RunError> {
        let output = std::process::Command::new(&command.program)
            .args(&command.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|err| RunError::new(format!("failed to spawn {}: {err}", command.program)))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        let detail = if stderr.is_empty() {
            output.status.to_string()
        } else {
            let mut text = stderr.to_string();
            if text.len() > 500 {
                text.truncate(500);
            }
            format!("{}: {text}", output.status)
        };
        Err(RunError::new(detail))
    }
}

/// Apply `config` with the kernel tools on Linux.
///
/// On any other operating system this returns [`Error::Unsupported`] and does
/// not spawn a process.
pub fn apply_system(config: &LinkConfig) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        apply(config, &mut CommandRunner)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const PUBLIC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn addr4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn peer(endpoint: &str, allowed: Vec<AllowedIp>, keepalive: u16) -> Peer {
        Peer {
            public_key: PUBLIC.to_string(),
            endpoint: endpoint.parse().unwrap(),
            allowed_ips: allowed,
            persistent_keepalive_secs: keepalive,
        }
    }

    fn two_peer_config() -> LinkConfig {
        LinkConfig {
            interface_name: "wg-tess".to_string(),
            private_key_path: PathBuf::from("/run/wg.key"),
            listen_port: 51820,
            local_tunnel: addr4([10, 7, 0, 1]),
            peers: vec![
                peer(
                    "192.0.2.10:51820",
                    vec![
                        AllowedIp::host(addr4([10, 7, 0, 2])),
                        AllowedIp::parse("10.7.0.0/24").unwrap(),
                    ],
                    25,
                ),
                peer(
                    "192.0.2.11:51820",
                    vec![AllowedIp::host(addr4([10, 7, 0, 3]))],
                    15,
                ),
            ],
            neighbors: vec![
                Neighbor::Endpoint("192.0.2.10:51820".parse().unwrap()),
                Neighbor::Qemu {
                    tap: "tap0".to_string(),
                    guest_tunnel: addr4([10, 7, 0, 2]),
                },
            ],
        }
    }

    #[test]
    fn public_key_dummy_is_32_zero_bytes() {
        assert_eq!(PUBLIC.len(), 44);
        assert!(PUBLIC.ends_with('='));
        assert_eq!(PUBLIC.chars().filter(|c| *c == 'A').count(), 43);
    }

    #[test]
    fn validate_accepts_two_peers_and_qemu_host_route() {
        let config = two_peer_config();
        validate(&config).unwrap();
        assert_eq!(config.peers.len(), 2);
        assert_ne!(config.listen_port, 0);
    }

    #[test]
    fn validate_accepts_listen_port_zero_and_subnet_only() {
        let mut config = two_peer_config();
        config.listen_port = 0;
        config.neighbors.clear();
        config.peers.truncate(1);
        config.peers[0].allowed_ips = vec![AllowedIp::parse("10.7.0.0/24").unwrap()];
        validate(&config).unwrap();
        let commands = plan(&config);
        assert!(
            commands
                .iter()
                .all(|command| command.args.first().map(String::as_str) != Some("route"))
        );
    }

    #[test]
    fn validate_rejects_bad_inputs() {
        let mut config = two_peer_config();
        config.interface_name = "bad iface".to_string();
        assert_eq!(
            validate(&config),
            Err(Error::Invalid(Invalid::InterfaceName))
        );

        config = two_peer_config();
        config.interface_name = "a".repeat(17);
        assert_eq!(
            validate(&config),
            Err(Error::Invalid(Invalid::InterfaceName))
        );
        config.interface_name = "a".repeat(16);
        validate(&config).unwrap();

        config = two_peer_config();
        config.private_key_path = PathBuf::new();
        assert_eq!(
            validate(&config),
            Err(Error::Invalid(Invalid::EmptyKeyPath))
        );

        config = two_peer_config();
        config.peers[0].endpoint = "0.0.0.0:51820".parse().unwrap();
        assert_eq!(
            validate(&config),
            Err(Error::Invalid(Invalid::UnspecifiedEndpoint))
        );

        config = two_peer_config();
        config.peers[0].persistent_keepalive_secs = 0;
        assert_eq!(
            validate(&config),
            Err(Error::Invalid(Invalid::ZeroKeepalive))
        );

        config = two_peer_config();
        config.peers[0].allowed_ips.clear();
        assert_eq!(
            validate(&config),
            Err(Error::Invalid(Invalid::EmptyAllowedIps))
        );

        config = two_peer_config();
        config.neighbors = vec![Neighbor::Qemu {
            tap: "tap0".to_string(),
            guest_tunnel: addr4([10, 9, 0, 9]),
        }];
        assert_eq!(validate(&config), Err(Error::Invalid(Invalid::GuestTunnel)));

        config = two_peer_config();
        config.local_tunnel = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(validate(&config), Err(Error::Invalid(Invalid::Family)));

        config = two_peer_config();
        config.local_tunnel = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            validate(&config),
            Err(Error::Invalid(Invalid::UnspecifiedLocal))
        );

        assert_eq!(
            AllowedIp::parse("10.7.0.1/33"),
            Err(Error::Invalid(Invalid::Prefix))
        );
        assert_eq!(AllowedIp::host(addr4([10, 7, 0, 2])).cidr(), "10.7.0.2/32");
    }

    #[test]
    fn plan_matches_argv_and_names_no_qemu() {
        let config = two_peer_config();
        let commands = plan(&config);
        let expected = vec![
            cmd("ip", ["link", "add", "dev", "wg-tess", "type", "wireguard"]),
            cmd(
                "wg",
                [
                    "set",
                    "wg-tess",
                    "listen-port",
                    "51820",
                    "private-key",
                    "/run/wg.key",
                    "peer",
                    PUBLIC,
                    "endpoint",
                    "192.0.2.10:51820",
                    "allowed-ips",
                    "10.7.0.2/32,10.7.0.0/24",
                    "persistent-keepalive",
                    "25",
                ],
            ),
            cmd(
                "wg",
                [
                    "set",
                    "wg-tess",
                    "listen-port",
                    "51820",
                    "private-key",
                    "/run/wg.key",
                    "peer",
                    PUBLIC,
                    "endpoint",
                    "192.0.2.11:51820",
                    "allowed-ips",
                    "10.7.0.3/32",
                    "persistent-keepalive",
                    "15",
                ],
            ),
            cmd("ip", ["addr", "replace", "10.7.0.1/32", "dev", "wg-tess"]),
            cmd("ip", ["link", "set", "up", "dev", "wg-tess"]),
            cmd("ip", ["link", "show", "tap0"]),
            cmd("ip", ["route", "replace", "10.7.0.2/32", "dev", "wg-tess"]),
            cmd("ip", ["route", "replace", "10.7.0.3/32", "dev", "wg-tess"]),
        ];
        assert_eq!(commands, expected);
        assert!(commands.iter().all(|command| command.program != "qemu"));
        assert!(commands.iter().all(|command| {
            command
                .args
                .iter()
                .all(|arg| arg != "qemu" && !arg.ends_with("/qemu"))
        }));
    }

    #[test]
    fn plan_uses_host_prefix_128_for_ipv6() {
        let config = LinkConfig {
            interface_name: "wg-v6".to_string(),
            private_key_path: PathBuf::from("/run/wg.key"),
            listen_port: 51820,
            local_tunnel: "fd00::1".parse().unwrap(),
            peers: vec![peer(
                "[fd00::10]:51820",
                vec![AllowedIp::parse("fd00::2/128").unwrap()],
                25,
            )],
            neighbors: vec![],
        };
        validate(&config).unwrap();
        let commands = plan(&config);
        let addr = commands
            .iter()
            .find(|command| command.args.first().map(String::as_str) == Some("addr"))
            .unwrap();
        let route = commands
            .iter()
            .find(|command| command.args.first().map(String::as_str) == Some("route"))
            .unwrap();
        assert_eq!(addr.args[2], "fd00::1/128");
        assert_eq!(route.args[2], "fd00::2/128");
    }

    #[derive(Default)]
    struct Fake {
        fail_route: bool,
        calls: Vec<Command>,
    }

    impl Runner for Fake {
        fn run(&mut self, command: &Command) -> Result<(), RunError> {
            self.calls.push(command.clone());
            if self.fail_route && command.args.first().map(String::as_str) == Some("route") {
                return Err(RunError::new("boom"));
            }
            Ok(())
        }
    }

    #[test]
    fn apply_records_plan_and_deletes_iface_after_later_failure() {
        let config = two_peer_config();
        let mut ok = Fake::default();
        apply(&config, &mut ok).unwrap();
        assert_eq!(ok.calls, plan(&config));
        assert!(
            ok.calls
                .iter()
                .all(|command| command.args.get(1).map(String::as_str) != Some("del"))
        );

        let mut failing = Fake {
            fail_route: true,
            calls: Vec::new(),
        };
        let err = apply(&config, &mut failing).unwrap_err();
        match &err {
            Error::Command { program, detail } => {
                assert_eq!(program, "ip");
                assert_eq!(detail, "boom");
            }
            other => panic!("unexpected {other:?}"),
        }
        let last = failing.calls.last().unwrap();
        assert_eq!(last, &cmd("ip", ["link", "del", "dev", "wg-tess"]));
        assert!(!err.to_string().contains(PUBLIC));
        assert!(!err.to_string().contains("cleanup"));
    }

    struct FailEverything {
        calls: Vec<Command>,
    }

    impl Runner for FailEverything {
        fn run(&mut self, command: &Command) -> Result<(), RunError> {
            self.calls.push(command.clone());
            let detail = if command.args.get(1).map(String::as_str) == Some("del") {
                "cleanup-failed"
            } else if self.calls.len() == 1 {
                "add-failed"
            } else {
                "later-failed"
            };
            Err(RunError::new(detail))
        }
    }

    #[test]
    fn apply_interface_create_does_not_substitute_or_delete() {
        let config = two_peer_config();
        let mut runner = FailEverything { calls: Vec::new() };
        let err = apply(&config, &mut runner).unwrap_err();
        assert_eq!(
            err,
            Error::InterfaceCreate {
                interface: "wg-tess".to_string(),
                detail: "add-failed".to_string(),
            }
        );
        assert_eq!(runner.calls.len(), 1);
        assert!(is_interface_add(&runner.calls[0]));
        assert!(
            runner
                .calls
                .iter()
                .all(|command| command.program != "wireguard-go")
        );
    }

    struct FailSecond {
        calls: Vec<Command>,
    }

    impl Runner for FailSecond {
        fn run(&mut self, command: &Command) -> Result<(), RunError> {
            self.calls.push(command.clone());
            if self.calls.len() == 1 {
                return Ok(());
            }
            if command.args.get(1).map(String::as_str) == Some("del") {
                return Err(RunError::new("cleanup-failed"));
            }
            Err(RunError::new("later-failed"))
        }
    }

    #[test]
    fn apply_returns_original_error_when_cleanup_fails() {
        let config = two_peer_config();
        let mut runner = FailSecond { calls: Vec::new() };
        let err = apply(&config, &mut runner).unwrap_err();
        assert_eq!(
            err,
            Error::Command {
                program: "wg".to_string(),
                detail: "later-failed".to_string(),
            }
        );
        assert_eq!(
            runner.calls.last().unwrap(),
            &cmd("ip", ["link", "del", "dev", "wg-tess"])
        );
        assert!(!err.to_string().contains("cleanup-failed"));
        assert!(!err.to_string().contains(PUBLIC));
        assert!(!err.to_string().contains("/run/wg.key"));
    }

    fn cmd(program: &str, args: impl IntoIterator<Item = &'static str>) -> Command {
        Command::new(program, args.into_iter().map(str::to_string))
    }
}
