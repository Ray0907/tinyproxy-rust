use crate::config::Config;
use anyhow::{ensure, Context, Result};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::{rustls, TlsAcceptor};

/// Load once, before binding. TLS protects the proxy hop; origin TLS is never
/// intercepted. No client CA, certificate bypass, or TLS early data is enabled.
pub fn acceptor(config: &Config) -> Result<Option<TlsAcceptor>> {
    let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) else {
        return Ok(None);
    };
    let mut cert_reader = BufReader::new(File::open(cert).context("Cannot read TLSCert")?);
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("Invalid TLSCert PEM")?;
    ensure!(!certificates.is_empty(), "TLSCert contains no certificates");
    let mut key_reader = BufReader::new(File::open(key).context("Cannot read TLSKey")?);
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .context("Invalid TLSKey PEM")?
        .context("TLSKey contains no private key")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("TLS certificate/key validation failed")?;
    server.alpn_protocols = if config.http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    server.max_early_data_size = 0;
    Ok(Some(TlsAcceptor::from(Arc::new(server))))
}
