use crate::config::Config;
use log::{debug, warn};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

pub struct AccessControl {
    allow_rules: Vec<IpRule>,
    deny_rules: Vec<IpRule>,
}

#[derive(Debug, Clone)]
enum IpRule {
    Single(IpAddr),
    Network { network: IpAddr, prefix: u8 },
    All,
}

impl AccessControl {
    pub fn new(config: &Config) -> Self {
        let mut allow_rules = Vec::new();
        let mut deny_rules = Vec::new();

        // Parse allow rules
        for rule in &config.allow {
            if let Ok(ip_rule) = parse_ip_rule(rule) {
                allow_rules.push(ip_rule);
            } else {
                warn!("Invalid allow rule: {}", rule);
            }
        }

        // Parse deny rules
        for rule in &config.deny {
            if let Ok(ip_rule) = parse_ip_rule(rule) {
                deny_rules.push(ip_rule);
            } else {
                warn!("Invalid deny rule: {}", rule);
            }
        }

        // If no allow rules are specified, allow all by default
        if allow_rules.is_empty() && deny_rules.is_empty() {
            allow_rules.push(IpRule::All);
        }

        Self {
            allow_rules,
            deny_rules,
        }
    }

    pub fn is_allowed(&self, addr: &SocketAddr) -> bool {
        let ip = addr.ip();

        // First check deny rules - if any deny rule matches, deny access
        for rule in &self.deny_rules {
            if self.matches_rule(rule, &ip) {
                debug!("IP {} denied by rule: {:?}", ip, rule);
                return false;
            }
        }

        // Then check allow rules - if any allow rule matches, allow access
        for rule in &self.allow_rules {
            if self.matches_rule(rule, &ip) {
                debug!("IP {} allowed by rule: {:?}", ip, rule);
                return true;
            }
        }

        // If no allow rules match, deny by default
        debug!("IP {} denied (no matching allow rule)", ip);
        false
    }

    fn matches_rule(&self, rule: &IpRule, ip: &IpAddr) -> bool {
        match rule {
            IpRule::All => true,
            IpRule::Single(rule_ip) => ip == rule_ip,
            IpRule::Network { network, prefix } => self.ip_in_network(ip, network, *prefix),
        }
    }

    fn ip_in_network(&self, ip: &IpAddr, network: &IpAddr, prefix: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_bits = u32::from(*ip);
                let net_bits = u32::from(*net);
                let mask = if prefix == 0 {
                    0
                } else {
                    !((1u32 << (32 - prefix)) - 1)
                };
                (ip_bits & mask) == (net_bits & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let ip_bits = u128::from(*ip);
                let net_bits = u128::from(*net);
                let mask = if prefix == 0 {
                    0
                } else {
                    !((1u128 << (128 - prefix)) - 1)
                };
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }
}

fn parse_ip_rule(rule: &str) -> Result<IpRule, String> {
    let rule = rule.trim();

    // Check for "all" or "*"
    if rule == "all" || rule == "*" {
        return Ok(IpRule::All);
    }

    // Check for CIDR notation
    if let Some(slash_pos) = rule.find('/') {
        let network_str = &rule[..slash_pos];
        let prefix_str = &rule[slash_pos + 1..];

        let network =
            IpAddr::from_str(network_str).map_err(|e| format!("Invalid network address: {}", e))?;

        let prefix = prefix_str
            .parse::<u8>()
            .map_err(|e| format!("Invalid prefix length: {}", e))?;

        // Validate prefix length
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix > max_prefix {
            return Err(format!("Prefix length {} too large for IP version", prefix));
        }

        return Ok(IpRule::Network { network, prefix });
    }

    // Try to parse as single IP address
    match IpAddr::from_str(rule) {
        Ok(ip) => Ok(IpRule::Single(ip)),
        Err(e) => Err(format!("Invalid IP address: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_ip_rule() {
        assert!(matches!(parse_ip_rule("all"), Ok(IpRule::All)));
        assert!(matches!(parse_ip_rule("*"), Ok(IpRule::All)));

        assert!(matches!(
            parse_ip_rule("192.168.1.1"),
            Ok(IpRule::Single(IpAddr::V4(_)))
        ));

        assert!(matches!(
            parse_ip_rule("192.168.1.0/24"),
            Ok(IpRule::Network { .. })
        ));
    }

    #[test]
    fn test_ip_in_network() {
        let acl = AccessControl {
            allow_rules: vec![],
            deny_rules: vec![],
        };

        let network = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 100));

        assert!(acl.ip_in_network(&ip1, &network, 24));
        assert!(!acl.ip_in_network(&ip2, &network, 24));
    }

    #[test]
    fn test_access_control() {
        let mut config = Config::default();
        config.allow = vec!["192.168.1.0/24".to_string()];
        config.deny = vec!["192.168.1.100".to_string()];

        let acl = AccessControl::new(&config);

        let allowed_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 12345);
        let denied_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let blocked_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345);

        assert!(acl.is_allowed(&allowed_addr));
        assert!(!acl.is_allowed(&denied_addr)); // Explicitly denied
        assert!(!acl.is_allowed(&blocked_addr)); // Not in allow list
    }
}
