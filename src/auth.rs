use crate::config::Config;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hyper::header::{HeaderMap, PROXY_AUTHORIZATION};

pub struct Authenticator {
    credentials: Vec<Vec<u8>>,
}

impl Authenticator {
    pub fn new(config: &Config) -> Self {
        Self {
            credentials: config
                .basic_auth
                .iter()
                .map(|auth| format!("{}:{}", auth.username, auth.password).into_bytes())
                .collect(),
        }
    }

    pub fn authenticate(&self, headers: &HeaderMap) -> bool {
        if self.credentials.is_empty() {
            return true;
        }
        let mut values = headers.get_all(PROXY_AUTHORIZATION).iter();
        let Some(header) = values.next().and_then(|value| value.to_str().ok()) else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let mut parts = header.split_whitespace();
        let (Some(scheme), Some(encoded), None) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(decoded) = STANDARD.decode(encoded) else {
            return false;
        };
        // Credentials are never logged or forwarded. This is not a claim of
        // constant-time authentication; rate limiting is a separate follow-up.
        self.credentials.iter().any(|expected| *expected == decoded)
    }
}
