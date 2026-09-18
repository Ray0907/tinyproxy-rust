use anyhow::{bail, ensure, Context, Result};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

#[derive(Clone)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password: String,
}

// Deliberately do not derive Debug: configuration contains credentials.
#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub listen_addresses: Vec<IpAddr>,
    pub bind_address: Option<IpAddr>,
    pub timeout: u64,
    pub header_timeout: u64,
    pub connect_timeout: u64,
    pub shutdown_timeout: u64,
    pub max_clients: usize,
    pub log_level: String,
    pub acl_rules: Vec<(bool, String)>,
    pub basic_auth: Vec<BasicAuthConfig>,
    pub filter_file: Option<String>,
    pub filter_urls: bool,
    pub filter_extended: bool,
    pub filter_casesensitive: bool,
    pub filter_default_deny: bool,
    pub connect_ports: Vec<u16>,
    pub disable_via_header: bool,
    pub via_proxy_name: String,
    pub stat_host: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8888,
            listen_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            bind_address: None,
            timeout: 600,
            header_timeout: 30,
            connect_timeout: 30,
            shutdown_timeout: 5,
            max_clients: 100,
            log_level: "Info".into(),
            acl_rules: Vec::new(),
            basic_auth: Vec::new(),
            filter_file: None,
            filter_urls: false,
            filter_extended: false,
            filter_casesensitive: false,
            filter_default_deny: false,
            connect_ports: vec![443, 563],
            disable_via_header: false,
            via_proxy_name: "tinyproxy-rust".into(),
            stat_host: None,
        }
    }
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .with_context(|| format!("Cannot read configuration: {}", path.display()))?;
        let mut config = Self::parse(&text)?;
        // Resolve relative filter paths against the configuration, not the cwd.
        if let Some(file) = &config.filter_file {
            if Path::new(file).is_relative() {
                config.filter_file = Some(
                    path.parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(file)
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        Ok(config)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut config = Self::default();
        let mut saw_listen = false;
        let mut saw_connect_port = false;
        for (index, line) in text.lines().enumerate() {
            let parse_line = || -> Result<Vec<String>> { tokenize(line) };
            let args = parse_line().with_context(|| format!("Line {}", index + 1))?;
            if args.is_empty() {
                continue;
            }
            let apply = |config: &mut Self,
                         saw_listen: &mut bool,
                         saw_connect_port: &mut bool|
             -> Result<()> {
                ensure!(
                    args[0].bytes().all(|c| c.is_ascii_alphabetic()),
                    "Invalid directive; use Tinyproxy key/value syntax, not TOML"
                );
                let key = args[0].to_ascii_lowercase();
                if key == "basicauth" {
                    let (username, password) = match args.as_slice() {
                        [_, user, pass] => (user.clone(), pass.clone()),
                        [_, legacy] => legacy
                            .split_once(':')
                            .map(|(user, pass)| (user.to_owned(), pass.to_owned()))
                            .context("BasicAuth requires a username and password")?,
                        _ => bail!("BasicAuth requires a username and password"),
                    };
                    ensure!(
                        !username.is_empty() && !password.is_empty() && !username.contains(':'),
                        "Invalid BasicAuth credentials"
                    );
                    ensure!(
                        !config
                            .basic_auth
                            .iter()
                            .any(|auth| auth.username == username),
                        "Duplicate BasicAuth username"
                    );
                    config
                        .basic_auth
                        .push(BasicAuthConfig { username, password });
                    return Ok(());
                }
                ensure!(args.len() == 2, "{} requires one value", args[0]);
                let value = &args[1];
                match key.as_str() {
                    "port" => config.port = value.parse().context("Invalid Port")?,
                    "listen" => {
                        let address = value.parse().context("Invalid Listen address")?;
                        if !*saw_listen {
                            config.listen_addresses.clear();
                            *saw_listen = true;
                        }
                        config.listen_addresses.push(address);
                    }
                    "bind" => {
                        config.bind_address = Some(value.parse().context("Invalid Bind address")?);
                    }
                    "timeout" => config.timeout = value.parse().context("Invalid Timeout")?,
                    "headertimeout" => {
                        config.header_timeout = value.parse().context("Invalid HeaderTimeout")?;
                    }
                    "connecttimeout" => {
                        config.connect_timeout = value.parse().context("Invalid ConnectTimeout")?;
                    }
                    "shutdowntimeout" => {
                        config.shutdown_timeout =
                            value.parse().context("Invalid ShutdownTimeout")?;
                    }
                    "maxclients" => {
                        config.max_clients = value.parse().context("Invalid MaxClients")?;
                    }
                    "loglevel" => config.log_level = value.clone(),
                    "allow" | "deny" => {
                        config.acl_rules.push((key == "allow", value.clone()));
                    }
                    "filter" => config.filter_file = Some(value.clone()),
                    "filterurls" => config.filter_urls = parse_bool(value)?,
                    "filterextended" => config.filter_extended = parse_bool(value)?,
                    "filtercasesensitive" => config.filter_casesensitive = parse_bool(value)?,
                    "filterdefaultdeny" => config.filter_default_deny = parse_bool(value)?,
                    "connectport" => {
                        let port = value.parse().context("Invalid ConnectPort")?;
                        if !*saw_connect_port {
                            config.connect_ports.clear();
                            *saw_connect_port = true;
                        }
                        config.connect_ports.push(port);
                    }
                    "disableviaheader" => config.disable_via_header = parse_bool(value)?,
                    "viaproxyname" => config.via_proxy_name = value.clone(),
                    "stathost" => config.stat_host = Some(value.to_ascii_lowercase()),
                    _ => bail!(
                        "Unsupported directive: {} (see README compatibility table)",
                        args[0]
                    ),
                }
                Ok(())
            };
            apply(&mut config, &mut saw_listen, &mut saw_connect_port)
                .with_context(|| format!("Line {}", index + 1))?;
        }
        if config.connect_ports.contains(&0) {
            ensure!(
                config.connect_ports.len() == 1,
                "ConnectPort 0 cannot be combined with other ports"
            );
            config.connect_ports.clear();
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.listen_addresses.is_empty(),
            "At least one Listen address is required"
        );
        ensure!(
            self.max_clients > 0 && self.max_clients <= 1_000_000,
            "MaxClients must be in 1..=1000000"
        );
        ensure!(
            [
                self.timeout,
                self.header_timeout,
                self.connect_timeout,
                self.shutdown_timeout
            ]
            .iter()
            .all(|seconds| (1..=86400).contains(seconds)),
            "Timeouts must be in 1..=86400 seconds"
        );
        ensure!(
            self.listen_addresses.iter().all(IpAddr::is_loopback)
                || !self.acl_rules.is_empty()
                || !self.basic_auth.is_empty(),
            "Non-loopback Listen requires explicit Allow/Deny rules or BasicAuth"
        );
        ensure!(
            !self.via_proxy_name.is_empty()
                && self
                    .via_proxy_name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
            "ViaProxyName must contain only letters, digits, dots, underscores or hyphens"
        );
        self.log_level
            .parse::<log::LevelFilter>()
            .context("Invalid LogLevel")?;
        ensure!(
            !self.filter_default_deny || self.filter_file.is_some(),
            "FilterDefaultDeny requires Filter"
        );
        ensure!(
            !self.connect_ports.contains(&0),
            "Use an empty port list to disable CONNECT in the library API"
        );
        Ok(())
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Ok(true),
        "no" | "false" | "off" | "0" => Ok(false),
        _ => bail!("Invalid boolean value"),
    }
}

fn tokenize(line: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut active = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(delimiter) = quote {
            if c == delimiter {
                quote = None;
            } else if c == '\\'
                && chars
                    .peek()
                    .is_some_and(|next| *next == delimiter || *next == '\\')
            {
                word.push(chars.next().expect("peeked character"));
            } else {
                word.push(c);
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
            active = true;
        } else if c == '#' && !active {
            break;
        } else if c.is_whitespace() {
            if active {
                words.push(std::mem::take(&mut word));
                active = false;
            }
        } else {
            word.push(c);
            active = true;
        }
    }
    ensure!(quote.is_none(), "Unterminated quoted value");
    if active {
        words.push(word);
    }
    Ok(words)
}
