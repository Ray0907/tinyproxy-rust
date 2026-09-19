use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tinyproxy_rust::{acl::AccessControl, config::Config};

const CONFIG: &str = "Port 8888\nListen 127.0.0.1\nAllow 127.0.0.0/8\nDeny all\nBasicAuth user pass\nConnectPort 443\n";

fn config_parsing(c: &mut Criterion) {
    c.bench_function("parse_config", |b| {
        b.iter(|| Config::parse(black_box(CONFIG)).unwrap())
    });
}

fn acl_lookup(c: &mut Criterion) {
    let config = Config::parse(CONFIG).unwrap();
    let acl = AccessControl::new(&config).unwrap();
    let address = "127.0.0.1".parse().unwrap();
    c.bench_function("acl_lookup", |b| {
        b.iter(|| acl.is_allowed(black_box(address)))
    });
}

criterion_group!(benches, config_parsing, acl_lookup);
criterion_main!(benches);
