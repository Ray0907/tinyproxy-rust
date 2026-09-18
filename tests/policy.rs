use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;
use tinyproxy_rust::{acl::AccessControl, config::Config, filter::Filter, runtime::Runtime};

#[test]
fn missing_config_is_an_error() {
    let directory = tempfile::tempdir().unwrap();
    assert!(Config::from_file(directory.path().join("missing.conf")).is_err());
}

#[test]
fn loopback_is_the_default_and_public_listening_must_be_explicit() {
    let config = Config::parse("").unwrap();
    assert_eq!(
        config.listen_addresses,
        vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(Config::parse("Listen 0.0.0.0").is_err());
    assert!(Config::parse("Listen 0.0.0.0\nAllow 192.168.0.0/16").is_ok());
    assert!(Config::parse("Listen 0.0.0.0\nBasicAuth user password").is_ok());
}

#[test]
fn basic_auth_supports_original_quoted_and_legacy_syntax() {
    let config = Config::parse(
        "BasicAuth alice secret\nBasicAuth \"bob\" \"a b:c#d\" # comment\nBasicAuth charlie:other",
    )
    .unwrap();
    assert_eq!(config.basic_auth.len(), 3);
    assert_eq!(config.basic_auth[1].password, "a b:c#d");
}

#[test]
fn malformed_auth_never_disables_authentication_silently() {
    for text in [
        "BasicAuth user",
        "BasicAuth user \"\"",
        "BasicAuth \"\" pass",
        "BasicAuth user pass\nBasicAuth user other",
    ] {
        assert!(Config::parse(text).is_err(), "accepted invalid BasicAuth");
    }
}

#[test]
fn error_messages_include_line_numbers_but_not_credentials() {
    let error = Config::parse("# comment\nBasicAuth user TOP_SECRET extra")
        .err()
        .unwrap();
    let message = format!("{error:#}");
    assert!(message.contains("Line 2"));
    assert!(!message.contains("TOP_SECRET"));
    let error = Config::parse("BasicAuth=TOP_SECRET").err().unwrap();
    assert!(!format!("{error:#}").contains("TOP_SECRET"));
}

#[test]
fn unsupported_and_malformed_directives_are_rejected() {
    for text in [
        "Upstream http://proxy:8080",
        "User nobody",
        "Group nobody",
        "Anonymous Cookie",
        "FilterURLs maybe",
        "MaxClients 0",
        "Timeout 0",
        "Unknown value",
        "Port = 8888",
    ] {
        assert!(Config::parse(text).is_err(), "accepted {text}");
    }
}

#[test]
fn connect_port_replaces_defaults_and_zero_disables_connect() {
    assert_eq!(
        Config::parse("ConnectPort 8443").unwrap().connect_ports,
        vec![8443]
    );
    assert!(Config::parse("ConnectPort 0")
        .unwrap()
        .connect_ports
        .is_empty());
    assert!(Config::parse("ConnectPort 0\nConnectPort 443").is_err());
}

#[test]
fn bind_does_not_change_listening_address() {
    let config = Config::parse("Bind 192.0.2.10").unwrap();
    assert_eq!(config.bind_address, Some("192.0.2.10".parse().unwrap()));
    assert!(config.listen_addresses[0].is_loopback());
}

#[test]
fn acl_preserves_order_and_handles_ipv4_mapped_clients() {
    let config = Config::parse("Allow 127.0.0.0/8\nDeny all").unwrap();
    let acl = AccessControl::new(&config).unwrap();
    assert!(acl.is_allowed("127.0.0.1".parse().unwrap()));
    assert!(acl.is_allowed("::ffff:127.0.0.1".parse().unwrap()));
    assert!(!acl.is_allowed("192.0.2.1".parse().unwrap()));
    let config = Config::parse("Deny all\nAllow 127.0.0.0/8").unwrap();
    assert!(!AccessControl::new(&config)
        .unwrap()
        .is_allowed("127.0.0.1".parse().unwrap()));
}

#[test]
fn invalid_acl_and_missing_filter_fail_at_startup() {
    let config = Config::parse("Allow not-an-ip").unwrap();
    assert!(Runtime::new(config).is_err());
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        filter_file: Some(directory.path().join("absent").to_string_lossy().into()),
        ..Config::default()
    };
    assert!(Runtime::new(config).is_err());
}

#[test]
fn domain_filtering_is_enabled_when_filter_urls_is_no() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, ".example.com").unwrap();
    let config = Config {
        filter_file: Some(file.path().to_string_lossy().into()),
        ..Config::default()
    };
    let filter = Filter::new(&config).unwrap();
    assert!(!filter.is_allowed("example.com", "/", false));
    assert!(!filter.is_allowed("sub.example.com.", "/", false));
    assert!(!filter.is_allowed("example.com", "example.com:443", true));
    assert!(filter.is_allowed("notexample.com", "/", false));
    assert!(filter.is_allowed("example.com.evil.test", "/", false));
}

#[test]
fn invalid_regex_is_not_downgraded_to_a_literal() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "[").unwrap();
    let config = Config {
        filter_file: Some(file.path().to_string_lossy().into()),
        filter_extended: true,
        ..Config::default()
    };
    assert!(Filter::new(&config).is_err());
}

#[test]
fn case_insensitive_regex_preserves_escape_semantics() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, r"^ads\D+\.test$").unwrap();
    let config = Config {
        filter_file: Some(file.path().to_string_lossy().into()),
        filter_extended: true,
        ..Config::default()
    };
    let filter = Filter::new(&config).unwrap();
    assert!(!filter.is_allowed("ADSxyz.test", "/", false));
    assert!(filter.is_allowed("ads123.test", "/", false));
}

#[test]
fn whitelist_filter_denies_unmatched_destinations() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "allowed.test").unwrap();
    let config = Config {
        filter_file: Some(file.path().to_string_lossy().into()),
        filter_default_deny: true,
        ..Config::default()
    };
    let filter = Filter::new(&config).unwrap();
    assert!(filter.is_allowed("allowed.test", "/", false));
    assert!(!filter.is_allowed("other.test", "/", false));
}

#[test]
fn relative_filter_path_is_relative_to_the_config() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("domains"), "blocked.test\n").unwrap();
    std::fs::write(directory.path().join("proxy.conf"), "Filter domains\n").unwrap();
    let config = Config::from_file(directory.path().join("proxy.conf")).unwrap();
    assert!(Runtime::new(config).is_ok());
}

#[test]
fn check_and_debug_work_without_double_logger_initialization() {
    let file = NamedTempFile::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tinyproxy-rust"))
        .args(["--check", "--debug", "-c"])
        .arg(file.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(env!("CARGO_BIN_EXE_tinyproxy-rust"))
        .arg("--version")
        .output()
        .unwrap()
        .status
        .success());
}
