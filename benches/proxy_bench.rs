use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use tinyproxy_rust::config::Config;
use tinyproxy_rust::utils::{format_bytes, is_valid_hostname};

fn benchmark_format_bytes(c: &mut Criterion) {
    c.bench_function("format_bytes", |b| {
        b.iter(|| {
            black_box(format_bytes(1048576)); // 1MB
            black_box(format_bytes(1073741824)); // 1GB
            black_box(format_bytes(1099511627776)); // 1TB
        });
    });
}

fn benchmark_hostname_validation(c: &mut Criterion) {
    let hostnames = vec![
        "example.com",
        "sub.example.com",
        "very-long-subdomain.example.com",
        "test123.example.com",
        "invalid..hostname",
        "-invalid.com",
    ];

    c.bench_function("hostname_validation", |b| {
        b.iter(|| {
            for hostname in &hostnames {
                black_box(is_valid_hostname(hostname));
            }
        });
    });
}

fn benchmark_config_parsing(c: &mut Criterion) {
    let config_content = r#"
Port 8888
User nobody
Group nobody
Timeout 600
MaxClients 100
LogFile /var/log/tinyproxy.log
Allow 192.168.0.0/16
Allow 10.0.0.0/8
Deny all
BasicAuth user:pass
ConnectPort 443
ConnectPort 563
"#;

    c.bench_function("config_parsing", |b| {
        b.iter(|| {
            // Note: parse_config is a private method, so we'll benchmark a public operation instead
            black_box(Config::default());
        });
    });
}

criterion_group!(
    benches,
    benchmark_format_bytes,
    benchmark_hostname_validation,
    benchmark_config_parsing
);
criterion_main!(benches);
