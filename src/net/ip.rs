use std::net::Ipv4Addr;

use pnet::datalink::{self};
use pnet::ipnetwork;

pub fn parse_interface(s: &str) -> Result<datalink::NetworkInterface, String> {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == s)
        .ok_or_else(|| format!("network interface not found: {s}"))
}

pub fn find_ipv4(interface: &datalink::NetworkInterface) -> Option<Ipv4Addr> {
    interface.ips.iter().find_map(|ip| match ip {
        ipnetwork::IpNetwork::V4(ipv4) => Some(ipv4.ip()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
    use std::net::Ipv6Addr;

    fn make_interface(name: &str, ips: Vec<IpNetwork>) -> datalink::NetworkInterface {
        datalink::NetworkInterface {
            name: name.to_string(),
            description: String::new(),
            index: 1,
            mac: None,
            ips,
            flags: 0,
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> IpNetwork {
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(a, b, c, d), prefix).unwrap())
    }

    fn v6(addr: Ipv6Addr, prefix: u8) -> IpNetwork {
        IpNetwork::V6(Ipv6Network::new(addr, prefix).unwrap())
    }

    #[test]
    fn find_ipv4_returns_none_when_no_ips() {
        let iface = make_interface("eth0", vec![]);
        assert_eq!(find_ipv4(&iface), None);
    }

    #[test]
    fn find_ipv4_returns_none_when_only_ipv6() {
        let iface = make_interface("eth0", vec![v6(Ipv6Addr::LOCALHOST, 128)]);
        assert_eq!(find_ipv4(&iface), None);
    }

    #[test]
    fn find_ipv4_returns_single_ipv4() {
        let iface = make_interface("eth0", vec![v4(192, 168, 1, 10, 24)]);
        assert_eq!(find_ipv4(&iface), Some(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn find_ipv4_skips_ipv6_and_finds_ipv4() {
        let iface = make_interface(
            "eth0",
            vec![v6(Ipv6Addr::LOCALHOST, 128), v4(10, 0, 0, 5, 8)],
        );
        assert_eq!(find_ipv4(&iface), Some(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn find_ipv4_returns_first_when_multiple_ipv4() {
        let iface = make_interface(
            "eth0",
            vec![
                v4(10, 0, 0, 1, 8),
                v4(172, 16, 0, 1, 12),
                v4(192, 168, 0, 1, 24),
            ],
        );
        assert_eq!(find_ipv4(&iface), Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn find_ipv4_returns_address_not_network() {
        let iface = make_interface("eth0", vec![v4(192, 168, 1, 77, 24)]);
        assert_eq!(find_ipv4(&iface), Some(Ipv4Addr::new(192, 168, 1, 77)));
    }

    #[test]
    fn parse_interface_errors_for_unknown_name() {
        let name = "definitely-not-a-real-interface-xyz";
        let err = parse_interface(name).unwrap_err();
        assert_eq!(err, format!("network interface not found: {name}"));
    }

    #[test]
    fn parse_interface_errors_for_empty_name() {
        let err = parse_interface("").unwrap_err();
        assert!(err.starts_with("network interface not found"));
    }

    #[test]
    fn parse_interface_finds_existing_interface() {
        let Some(existing) = datalink::interfaces().into_iter().next() else {
            eprintln!("no network interfaces on this host; skipping");
            return;
        };
        let found = parse_interface(&existing.name).expect("interface should be found");
        assert_eq!(found.name, existing.name);
        assert_eq!(found.index, existing.index);
    }

    #[test]
    fn parse_interface_is_case_sensitive() {
        let Some(existing) = datalink::interfaces()
            .into_iter()
            .find(|i| i.name.chars().any(|c| c.is_ascii_lowercase()))
        else {
            return;
        };
        let swapped = existing.name.to_ascii_uppercase();
        if datalink::interfaces().iter().all(|i| i.name != swapped) {
            assert!(parse_interface(&swapped).is_err());
        }
    }
}
