use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // Basic server configuration
    pub port: u16,
    pub bind_address: IpAddr,
    pub listen_addresses: Vec<IpAddr>,
    pub bind_same: bool,

    // Process configuration
    pub user: Option<String>,
    pub group: Option<String>,
    pub daemon: bool,
    pub pidfile: Option<String>,

    // Connection configuration
    pub timeout: u64,
    pub max_clients: usize,
    pub max_requests_per_child: usize,
    pub max_spare_servers: usize,
    pub min_spare_servers: usize,
    pub start_servers: usize,

    // Logging configuration
    pub logfile: Option<String>,
    pub syslog: bool,
    pub log_level: String,
    pub debug: bool,

    // Access control
    pub allow: Vec<String>,
    pub deny: Vec<String>,

    // Authentication
    pub basic_auth: Option<BasicAuthConfig>,

    // Proxy configuration
    pub upstream: Vec<UpstreamConfig>,
    pub reverse_proxy: Vec<ReverseProxyConfig>,
    pub transparent_proxy: bool,

    // Filtering
    pub filter_file: Option<String>,
    pub filter_urls: bool,
    pub filter_extended: bool,
    pub filter_casesensitive: bool,

    // Headers
    pub anonymous: Vec<String>,
    pub via_proxy_name: Option<String>,
    pub x_tinyproxy: bool,
    pub add_headers: HashMap<String, String>,

    // SSL/TLS
    pub connect_ports: Vec<u16>,
    pub disable_via_header: bool,

    // Statistics
    pub stat_host: Option<String>,
    pub stat_file: Option<String>,

    // Error pages
    pub error_files: HashMap<u16, String>,
    pub default_error_file: Option<String>,

    // Performance
    pub buffer_size: usize,
    pub connection_pool_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password: String,
    pub realm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub upstream_type: String, // "http" or "socks5"
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub domain: Option<String>, // For domain-specific upstream
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseProxyConfig {
    pub path: String,
    pub url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8888,
            bind_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            listen_addresses: vec![],
            bind_same: false,

            user: Some("nobody".to_string()),
            group: Some("nobody".to_string()),
            daemon: false,
            pidfile: Some("/var/run/tinyproxy.pid".to_string()),

            timeout: 600,
            max_clients: 100,
            max_requests_per_child: 0, // 0 means unlimited
            max_spare_servers: 20,
            min_spare_servers: 5,
            start_servers: 10,

            logfile: Some("/var/log/tinyproxy.log".to_string()),
            syslog: false,
            log_level: "Info".to_string(),
            debug: false,

            allow: vec![],
            deny: vec![],

            basic_auth: None,

            upstream: vec![],
            reverse_proxy: vec![],
            transparent_proxy: false,

            filter_file: None,
            filter_urls: false,
            filter_extended: false,
            filter_casesensitive: false,

            anonymous: vec![],
            via_proxy_name: Some("tinyproxy".to_string()),
            x_tinyproxy: false,
            add_headers: HashMap::new(),

            connect_ports: vec![443, 563],
            disable_via_header: false,

            stat_host: None,
            stat_file: None,

            error_files: HashMap::new(),
            default_error_file: None,

            buffer_size: 8192,
            connection_pool_size: 100,
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        Self::parse_config(&content)
    }

    fn parse_config(content: &str) -> Result<Self> {
        let mut config = Self::default();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
            if parts.len() != 2 {
                continue;
            }

            let key = parts[0].to_lowercase();
            let value = parts[1].trim();

            match key.as_str() {
                "port" => {
                    config.port = value
                        .parse()
                        .with_context(|| format!("Invalid port value: {}", value))?;
                }
                "bind" => {
                    config.bind_address = value
                        .parse()
                        .with_context(|| format!("Invalid bind address: {}", value))?;
                }
                "listen" => {
                    let addr: IpAddr = value
                        .parse()
                        .with_context(|| format!("Invalid listen address: {}", value))?;
                    config.listen_addresses.push(addr);
                }
                "bindsame" => {
                    config.bind_same = parse_bool(value)?;
                }
                "user" => {
                    config.user = Some(value.to_string());
                }
                "group" => {
                    config.group = Some(value.to_string());
                }
                "pidfile" => {
                    config.pidfile = Some(value.to_string());
                }
                "timeout" => {
                    config.timeout = value
                        .parse()
                        .with_context(|| format!("Invalid timeout value: {}", value))?;
                }
                "maxclients" => {
                    config.max_clients = value
                        .parse()
                        .with_context(|| format!("Invalid max clients value: {}", value))?;
                }
                "maxrequestsperchild" => {
                    config.max_requests_per_child = value.parse().with_context(|| {
                        format!("Invalid max requests per child value: {}", value)
                    })?;
                }
                "logfile" => {
                    config.logfile = Some(value.to_string());
                }
                "syslog" => {
                    config.syslog = parse_bool(value)?;
                }
                "loglevel" => {
                    config.log_level = value.to_string();
                }
                "allow" => {
                    config.allow.push(value.to_string());
                }
                "deny" => {
                    config.deny.push(value.to_string());
                }
                "basicauth" => {
                    let parts: Vec<&str> = value.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        config.basic_auth = Some(BasicAuthConfig {
                            username: parts[0].to_string(),
                            password: parts[1].to_string(),
                            realm: "Tinyproxy".to_string(),
                        });
                    }
                }
                "upstream" => {
                    // Parse upstream configuration
                    // Format: upstream type:host:port [username:password] [domain]
                    if let Ok(upstream) = parse_upstream(value) {
                        config.upstream.push(upstream);
                    }
                }
                "reverseonly" => {
                    config.transparent_proxy = parse_bool(value)?;
                }
                "filter" => {
                    config.filter_file = Some(value.to_string());
                }
                "filterurls" => {
                    config.filter_urls = parse_bool(value)?;
                }
                "filterextended" => {
                    config.filter_extended = parse_bool(value)?;
                }
                "filtercasesensitive" => {
                    config.filter_casesensitive = parse_bool(value)?;
                }
                "anonymous" => {
                    config.anonymous.push(value.to_string());
                }
                "viaproxyname" => {
                    config.via_proxy_name = Some(value.to_string());
                }
                "xtinyproxy" => {
                    config.x_tinyproxy = parse_bool(value)?;
                }
                "connectport" => {
                    let port: u16 = value
                        .parse()
                        .with_context(|| format!("Invalid connect port value: {}", value))?;
                    config.connect_ports.push(port);
                }
                "disableviaheader" => {
                    config.disable_via_header = parse_bool(value)?;
                }
                "stathost" => {
                    config.stat_host = Some(value.to_string());
                }
                "statfile" => {
                    config.stat_file = Some(value.to_string());
                }
                "errorfile" => {
                    // Parse error file configuration
                    // Format: errorfile code file
                    let parts: Vec<&str> = value.splitn(2, char::is_whitespace).collect();
                    if parts.len() == 2 {
                        if let Ok(code) = parts[0].parse::<u16>() {
                            config.error_files.insert(code, parts[1].to_string());
                        }
                    }
                }
                "defaulterrorfile" => {
                    config.default_error_file = Some(value.to_string());
                }
                _ => {
                    // Unknown configuration option, log warning
                    log::warn!("Unknown configuration option: {}", key);
                }
            }
        }

        Ok(config)
    }

    pub fn get_listen_addresses(&self) -> Vec<SocketAddr> {
        if self.listen_addresses.is_empty() {
            vec![SocketAddr::new(self.bind_address, self.port)]
        } else {
            self.listen_addresses
                .iter()
                .map(|addr| SocketAddr::new(*addr, self.port))
                .collect()
        }
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.to_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Ok(true),
        "no" | "false" | "off" | "0" => Ok(false),
        _ => Err(anyhow::anyhow!("Invalid boolean value: {}", value)),
    }
}

fn parse_upstream(value: &str) -> Result<UpstreamConfig> {
    // Simple upstream parsing - can be extended for more complex formats
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() >= 3 {
        Ok(UpstreamConfig {
            upstream_type: parts[0].to_string(),
            host: parts[1].to_string(),
            port: parts[2].parse()?,
            username: None,
            password: None,
            domain: None,
        })
    } else {
        Err(anyhow::anyhow!("Invalid upstream format: {}", value))
    }
}
