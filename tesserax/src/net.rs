//! CIDR blocks and trusted-proxy client address resolution.
//!
//! Pure address arithmetic over `core::net`; no socket is opened here.

use std::net::IpAddr;
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::error::CidrError;

/// One IPv4 or IPv6 CIDR block. The network part is stored masked.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Cidr {
    /// IPv4 block.
    V4 {
        /// Network address, host bits zero.
        network: u32,
        /// Prefix length, `0..=32`.
        prefix_len: u8,
    },
    /// IPv6 block.
    V6 {
        /// Network address, host bits zero.
        network: u128,
        /// Prefix length, `0..=128`.
        prefix_len: u8,
    },
}

impl Cidr {
    /// Parses `"10.0.0.0/8"`, `"fe80::/10"`, or a bare address (a `/32` or
    /// `/128` host block).
    pub fn parse(s: &str) -> Result<Self, CidrError> {
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let ip: IpAddr = addr_part
            .parse()
            .map_err(|_| CidrError::BadAddress(addr_part.to_owned()))?;
        let max = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = match prefix_part {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| CidrError::BadPrefix(p.to_owned()))?,
            None => max,
        };
        if prefix_len > max {
            return Err(CidrError::PrefixTooLong { prefix_len, max });
        }
        Ok(match ip {
            IpAddr::V4(v4) => Cidr::V4 {
                network: mask_v4(u32::from_be_bytes(v4.octets()), prefix_len),
                prefix_len,
            },
            IpAddr::V6(v6) => Cidr::V6 {
                network: mask_v6(u128::from_be_bytes(v6.octets()), prefix_len),
                prefix_len,
            },
        })
    }

    /// True iff `ip` is inside the block. IPv4 blocks never match IPv6
    /// addresses and vice versa (IPv4-mapped IPv6 is not unwrapped; normalise
    /// first if needed).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (
                Cidr::V4 {
                    network,
                    prefix_len,
                },
                IpAddr::V4(v4),
            ) => mask_v4(u32::from_be_bytes(v4.octets()), prefix_len) == network,
            (
                Cidr::V6 {
                    network,
                    prefix_len,
                },
                IpAddr::V6(v6),
            ) => mask_v6(u128::from_be_bytes(v6.octets()), prefix_len) == network,
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = CidrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cidr::parse(s)
    }
}

fn mask_v4(raw: u32, prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        p if p >= 32 => raw,
        p => raw & (u32::MAX << (32 - p)),
    }
}

fn mask_v6(raw: u128, prefix_len: u8) -> u128 {
    match prefix_len {
        0 => 0,
        p if p >= 128 => raw,
        p => raw & (u128::MAX << (128 - p)),
    }
}

/// An ordered list of CIDR blocks; [`matches`](Self::matches) is a linear scan.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct CidrList(Vec<Cidr>);

impl CidrList {
    /// Empty list (matches nothing).
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a block.
    pub fn push(&mut self, cidr: Cidr) {
        self.0.push(cidr);
    }

    /// Parses a comma- or whitespace-separated list; fails on the first bad
    /// entry.
    pub fn parse(s: &str) -> Result<Self, CidrError> {
        s.split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(Cidr::parse)
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// Loopback plus private ranges: `127.0.0.0/8`, `10.0.0.0/8`,
    /// `172.16.0.0/12`, `192.168.0.0/16`, `::1/128`, `fc00::/7`. A common
    /// trusted-proxy list for a reverse proxy on the same host or LAN.
    pub fn private_networks() -> Self {
        Self(vec![
            Cidr::V4 {
                network: 0x7F00_0000,
                prefix_len: 8,
            },
            Cidr::V4 {
                network: 0x0A00_0000,
                prefix_len: 8,
            },
            Cidr::V4 {
                network: 0xAC10_0000,
                prefix_len: 12,
            },
            Cidr::V4 {
                network: 0xC0A8_0000,
                prefix_len: 16,
            },
            Cidr::V6 {
                network: 1,
                prefix_len: 128,
            },
            Cidr::V6 {
                network: 0xFC00_u128 << 112,
                prefix_len: 7,
            },
        ])
    }

    /// True iff any block contains `ip`.
    pub fn matches(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }

    /// Number of blocks.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True iff the list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The blocks in order.
    pub fn iter(&self) -> impl Iterator<Item = &Cidr> + '_ {
        self.0.iter()
    }
}

impl From<Vec<Cidr>> for CidrList {
    fn from(v: Vec<Cidr>) -> Self {
        Self(v)
    }
}

impl FromIterator<Cidr> for CidrList {
    fn from_iter<I: IntoIterator<Item = Cidr>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// The caller's address, honouring forwarding headers only from a trusted
/// proxy.
///
/// `peer` is the transport-level source address. `forwarded_for` and
/// `real_ip` are the raw values of the `X-Forwarded-For` and `X-Real-IP`
/// headers, if present. When `peer` is not in `trusted`, both headers are
/// caller-controlled and ignored. Otherwise `X-Forwarded-For` is walked from
/// the right (the hop nearest to us) and the first address not in `trusted`
/// is the client; if every hop is trusted the leftmost is used; then
/// `X-Real-IP`; then `peer`.
pub fn honest_client_ip(
    peer: IpAddr,
    trusted: &CidrList,
    forwarded_for: Option<&str>,
    real_ip: Option<&str>,
) -> IpAddr {
    if !trusted.matches(peer) {
        return peer;
    }
    if let Some(xff) = forwarded_for {
        let hops: Vec<&str> = xff
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();
        for hop in hops.iter().rev() {
            if let Ok(ip) = hop.parse::<IpAddr>()
                && !trusted.matches(ip)
            {
                return ip;
            }
        }
        if let Some(Ok(ip)) = hops.first().map(|h| h.parse::<IpAddr>()) {
            return ip;
        }
    }
    if let Some(Ok(ip)) = real_ip.map(|v| v.trim().parse::<IpAddr>()) {
        return ip;
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_v4_matches() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(!c.contains(ip("192.0.2.1")));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains(ip("203.0.113.255"))
        );
        let host = Cidr::parse("127.0.0.1").unwrap();
        assert!(host.contains(ip("127.0.0.1")));
        assert!(!host.contains(ip("127.0.0.2")));
    }

    #[test]
    fn cidr_v6_matches_and_families_do_not_cross() {
        let c = Cidr::parse("fc00::/7").unwrap();
        assert!(c.contains(ip("fd12:3456::abcd")));
        assert!(!c.contains(ip("fe80::1")));
        assert!(!Cidr::parse("127.0.0.0/8").unwrap().contains(ip("::1")));
        assert!(!Cidr::parse("::/0").unwrap().contains(ip("127.0.0.1")));
    }

    #[test]
    fn cidr_rejects_bad_input() {
        assert_eq!(
            Cidr::parse("10.0.0.0/33"),
            Err(CidrError::PrefixTooLong {
                prefix_len: 33,
                max: 32
            })
        );
        assert!(matches!(
            Cidr::parse("::/129"),
            Err(CidrError::PrefixTooLong { .. })
        ));
        assert!(matches!(
            Cidr::parse("nope/8"),
            Err(CidrError::BadAddress(_))
        ));
        assert!(matches!(
            Cidr::parse("10.0.0.0/x"),
            Err(CidrError::BadPrefix(_))
        ));
    }

    #[test]
    fn private_networks_equals_parsed_list() {
        let parsed = CidrList::parse(
            "127.0.0.0/8 10.0.0.0/8, 172.16.0.0/12 192.168.0.0/16 ::1/128 fc00::/7",
        )
        .unwrap();
        assert_eq!(CidrList::private_networks(), parsed);
        let l = CidrList::private_networks();
        assert!(l.matches(ip("172.16.0.1")));
        assert!(!l.matches(ip("192.0.2.8")));
        assert!(!l.matches(ip("2001:db8::1")));
    }

    #[test]
    fn untrusted_peer_ignores_headers() {
        let got = honest_client_ip(
            ip("192.0.2.9"),
            &CidrList::new(),
            Some("192.0.2.4"),
            Some("198.51.100.8"),
        );
        assert_eq!(got, ip("192.0.2.9"));
    }

    #[test]
    fn trusted_peer_walks_forwarded_for_from_the_right() {
        let t = CidrList::private_networks();
        let peer = ip("127.0.0.1");
        assert_eq!(
            honest_client_ip(peer, &t, Some("192.0.2.8, 10.0.0.1"), None),
            ip("192.0.2.8")
        );
        assert_eq!(
            honest_client_ip(peer, &t, Some("10.0.0.5, 10.0.0.1"), None),
            ip("10.0.0.5")
        );
        assert_eq!(
            honest_client_ip(peer, &t, None, Some(" 198.51.100.4 ")),
            ip("198.51.100.4")
        );
        assert_eq!(honest_client_ip(peer, &t, Some("not-an-ip,  "), None), peer);
    }
}
