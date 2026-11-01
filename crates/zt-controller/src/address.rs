//! The IPv4 ranges a network is given, and the addresses inside them.
//!
//! A network carries a range, and every node in it has one address in that
//! range. The data plane routes on those addresses, so the controller has
//! to hand them out and to keep them unique.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::error::ControllerError;

/// An IPv4 range, as a network and a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Range {
    /// The first address of the range.
    pub network: u32,
    /// How many leading bits of an address are fixed.
    pub prefix: u8,
    /// The last address of the range.
    pub broadcast: u32,
}

impl Ipv4Range {
    /// Parse a range in the `10.88.0.0/24` form.
    pub fn parse(cidr: &str) -> Result<Self, ControllerError> {
        let (address, prefix) = cidr.split_once('/').ok_or_else(|| {
            ControllerError::InvalidRequest(format!(
                "'{cidr}' is not a range: it has no prefix length"
            ))
        })?;

        let address: Ipv4Addr = address.parse().map_err(|_| {
            ControllerError::InvalidRequest(format!("'{address}' is not an IPv4 address"))
        })?;

        let prefix: u8 = prefix.parse().map_err(|_| {
            ControllerError::InvalidRequest(format!("'{prefix}' is not a prefix length"))
        })?;

        if prefix > 32 {
            return Err(ControllerError::InvalidRequest(format!(
                "the prefix length {prefix} is not between 0 and 32"
            )));
        }

        let bits = u32::from(address);
        let keep = u32::MAX << (32 - u32::from(prefix));
        let network = bits & keep;
        let broadcast = network | !keep;

        Ok(Self {
            network,
            prefix,
            broadcast,
        })
    }

    /// Whether an address falls in the range.
    pub fn contains(&self, address: u32) -> bool {
        address >= self.network && address <= self.broadcast
    }

    /// The addresses in the range that a node may take.
    ///
    /// The network address and the broadcast address are not available: the
    /// first identifies the network and the last is the broadcast, and
    /// neither can belong to a node.
    pub fn hosts(&self) -> impl Iterator<Item = u32> + '_ {
        let first = if self.prefix >= 31 {
            // A range of two or fewer addresses has no host addresses.
            self.broadcast + 1
        } else {
            self.network + 1
        };

        let last = if self.prefix >= 31 {
            self.broadcast
        } else {
            self.broadcast - 1
        };

        // The range is inclusive. The closure takes the bound by value so
        // the iterator does not borrow the local.
        (first..=last).filter(move |address| *address <= last)
    }

    /// Render an address back as text.
    pub fn format(address: u32) -> String {
        Ipv4Addr::from(address).to_string()
    }
}

/// The lowest address in the range that is not taken.
///
/// Returns `None` when the range has no room left, which is a full
/// network rather than an error the caller can fix.
pub fn assign_address(range: &Ipv4Range, used: &HashSet<u32>) -> Option<String> {
    range
        .hosts()
        .find(|address| !used.contains(address))
        .map(Ipv4Range::format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_is_parsed() {
        let range = Ipv4Range::parse("10.88.0.7/24").expect("range");
        assert_eq!(range.network, u32::from(Ipv4Addr::new(10, 88, 0, 0)));
        assert_eq!(range.prefix, 24);
        assert_eq!(range.broadcast, u32::from(Ipv4Addr::new(10, 88, 0, 255)));
    }

    #[test]
    fn a_malformed_range_is_refused() {
        assert!(Ipv4Range::parse("10.88.0.0").is_err());
        assert!(Ipv4Range::parse("10.88.0.0/33").is_err());
        assert!(Ipv4Range::parse("nonsense/24").is_err());
    }

    #[test]
    fn the_host_addresses_exclude_the_network_and_the_broadcast() {
        let range = Ipv4Range::parse("10.88.0.0/24").expect("range");
        let hosts: Vec<u32> = range.hosts().collect();

        assert_eq!(hosts.first(), Some(&u32::from(Ipv4Addr::new(10, 88, 0, 1))));
        assert_eq!(
            hosts.last(),
            Some(&u32::from(Ipv4Addr::new(10, 88, 0, 254)))
        );
        assert_eq!(hosts.len(), 254);
    }

    #[test]
    fn a_tiny_range_has_no_host_addresses() {
        let range = Ipv4Range::parse("10.88.0.0/31").expect("range");
        assert_eq!(range.hosts().count(), 0);
    }

    #[test]
    fn the_lowest_free_address_is_taken() {
        let range = Ipv4Range::parse("10.88.0.0/24").expect("range");

        let used: HashSet<u32> = [Ipv4Addr::new(10, 88, 0, 1), Ipv4Addr::new(10, 88, 0, 2)]
            .into_iter()
            .map(u32::from)
            .collect();

        assert_eq!(assign_address(&range, &used), Some("10.88.0.3".to_string()));
    }

    #[test]
    fn a_full_range_has_nothing_left() {
        let range = Ipv4Range::parse("10.88.0.0/30").expect("range");
        let used: HashSet<u32> = range.hosts().collect();
        assert_eq!(assign_address(&range, &used), None);
    }
}
