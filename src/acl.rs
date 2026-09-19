use crate::config::Config;
use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use std::net::IpAddr;

pub struct AccessControl {
    rules: Vec<(bool, Option<IpNet>)>,
}

impl AccessControl {
    pub fn new(config: &Config) -> Result<Self> {
        let mut rules = Vec::with_capacity(config.acl_rules.len());
        for (allow, text) in &config.acl_rules {
            let network = match text.as_str() {
                "all" | "*" => None,
                _ => {
                    if let Ok(ip) = text.parse::<IpAddr>() {
                        Some(IpNet::from(canonical_ip(ip)))
                    } else {
                        let network = text.parse::<IpNet>().context("Invalid ACL IP/CIDR rule")?;
                        if let IpNet::V6(net) = network {
                            if net.addr().to_ipv4_mapped().is_some() {
                                bail!("Use an IPv4 CIDR for IPv4-mapped IPv6 ACL rules");
                            }
                        }
                        Some(network)
                    }
                }
            };
            rules.push((*allow, network));
        }
        Ok(Self { rules })
    }

    /// First matching rule wins. Once rules exist, unmatched clients are denied.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        self.rules
            .iter()
            .find(|(_, network)| network.is_none_or(|network| network.contains(&ip)))
            .map(|(allow, _)| *allow)
            .unwrap_or(self.rules.is_empty())
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        other => other,
    }
}
