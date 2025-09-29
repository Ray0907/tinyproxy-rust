use crate::config::{BasicAuthConfig, Config};
use crate::error::{ProxyError, ProxyResult};
use crate::utils::HttpRequest;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::debug;

pub struct Authenticator {
    auth_config: Option<BasicAuthConfig>,
}

impl Authenticator {
    pub fn new(config: &Config) -> Self {
        Self {
            auth_config: config.basic_auth.clone(),
        }
    }

    pub fn authenticate(&self, request: &HttpRequest) -> ProxyResult<bool> {
        // If no authentication is configured, allow all requests
        let auth_config = match &self.auth_config {
            Some(config) => config,
            None => return Ok(true),
        };

        // Check for Proxy-Authorization header
        let auth_header = match request.headers.get("proxy-authorization") {
            Some(header) => header,
            None => {
                debug!("No Proxy-Authorization header found");
                return Ok(false);
            }
        };

        // Parse Basic authentication
        if !auth_header.starts_with("Basic ") {
            debug!("Non-Basic authentication scheme: {}", auth_header);
            return Err(ProxyError::AuthenticationFailed);
        }

        let encoded_credentials = &auth_header[6..]; // Skip "Basic "
        let decoded_credentials = STANDARD.decode(encoded_credentials).map_err(|e| {
            debug!("Failed to decode base64 credentials: {}", e);
            ProxyError::AuthenticationFailed
        })?;

        let credentials_str = String::from_utf8(decoded_credentials).map_err(|e| {
            debug!("Invalid UTF-8 in credentials: {}", e);
            ProxyError::AuthenticationFailed
        })?;

        let parts: Vec<&str> = credentials_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            debug!("Invalid credentials format");
            return Err(ProxyError::AuthenticationFailed);
        }

        let username = parts[0];
        let password = parts[1];

        // Verify credentials
        if username == auth_config.username && password == auth_config.password {
            debug!("Authentication successful for user: {}", username);
            Ok(true)
        } else {
            debug!("Authentication failed for user: {}", username);
            Ok(false)
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.auth_config.is_some()
    }

    pub fn get_realm(&self) -> String {
        self.auth_config
            .as_ref()
            .map(|config| config.realm.clone())
            .unwrap_or_else(|| "Tinyproxy".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_request_with_auth(auth_header: Option<&str>) -> HttpRequest {
        let mut headers = HashMap::new();
        if let Some(header) = auth_header {
            headers.insert("proxy-authorization".to_string(), header.to_string());
        }

        HttpRequest {
            method: "GET".to_string(),
            uri: "http://example.com".to_string(),
            version: "1.1".to_string(),
            headers,
        }
    }

    #[test]
    fn test_no_auth_configured() {
        let config = Config::default();
        let auth = Authenticator::new(&config);
        let request = create_test_request_with_auth(None);

        assert!(auth.authenticate(&request).unwrap());
        assert!(!auth.is_enabled());
    }

    #[test]
    fn test_missing_auth_header() {
        let mut config = Config::default();
        config.basic_auth = Some(BasicAuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
            realm: "Test".to_string(),
        });

        let auth = Authenticator::new(&config);
        let request = create_test_request_with_auth(None);

        assert!(!auth.authenticate(&request).unwrap());
        assert!(auth.is_enabled());
    }

    #[test]
    fn test_valid_auth() {
        let mut config = Config::default();
        config.basic_auth = Some(BasicAuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
            realm: "Test".to_string(),
        });

        let auth = Authenticator::new(&config);

        // Create valid Basic auth header (user:pass in base64)
        let credentials = STANDARD.encode("user:pass");
        let auth_header = format!("Basic {}", credentials);
        let request = create_test_request_with_auth(Some(&auth_header));

        assert!(auth.authenticate(&request).unwrap());
    }

    #[test]
    fn test_invalid_auth() {
        let mut config = Config::default();
        config.basic_auth = Some(BasicAuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
            realm: "Test".to_string(),
        });

        let auth = Authenticator::new(&config);

        // Create invalid Basic auth header
        let credentials = STANDARD.encode("wrong:credentials");
        let auth_header = format!("Basic {}", credentials);
        let request = create_test_request_with_auth(Some(&auth_header));

        assert!(!auth.authenticate(&request).unwrap());
    }

    #[test]
    fn test_malformed_auth_header() {
        let mut config = Config::default();
        config.basic_auth = Some(BasicAuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
            realm: "Test".to_string(),
        });

        let auth = Authenticator::new(&config);
        let request = create_test_request_with_auth(Some("Bearer token123"));

        assert!(auth.authenticate(&request).is_err());
    }
}
