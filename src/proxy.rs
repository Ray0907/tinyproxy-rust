use crate::config::Config;
use crate::error::ProxyResult;

pub struct ProxyLogic {
    config: std::sync::Arc<Config>,
}

impl ProxyLogic {
    pub fn new(config: std::sync::Arc<Config>) -> Self {
        Self { config }
    }

    pub async fn handle_http_proxy(
        &self,
        _method: &str,
        _uri: &str,
        _headers: &std::collections::HashMap<String, String>,
    ) -> ProxyResult<()> {
        // Basic HTTP proxy logic - this is a placeholder for now
        // In a full implementation, this would handle:
        // - URL rewriting
        // - Header manipulation
        // - Connection pooling
        // - SSL/TLS termination
        // - Reverse proxy rules
        // - Upstream selection

        Ok(())
    }

    pub fn should_use_upstream(&self, host: &str) -> Option<&crate::config::UpstreamConfig> {
        // Check if we should use an upstream proxy for this host
        for upstream in &self.config.upstream {
            if let Some(domain) = &upstream.domain {
                if host.ends_with(domain) {
                    return Some(upstream);
                }
            }
        }

        // If no specific upstream is configured, use the first one if available
        self.config.upstream.first()
    }

    pub fn get_reverse_proxy_target(&self, path: &str) -> Option<&str> {
        // Check reverse proxy rules
        for rule in &self.config.reverse_proxy {
            if path.starts_with(&rule.path) {
                return Some(&rule.url);
            }
        }
        None
    }

    pub fn process_headers(
        &self,
        headers: &mut std::collections::HashMap<String, String>,
        client_ip: &std::net::IpAddr,
    ) {
        // Remove anonymous headers
        for header in &self.config.anonymous {
            headers.remove(&header.to_lowercase());
        }

        // Add Via header if not disabled
        if !self.config.disable_via_header {
            let via_value = if let Some(proxy_name) = &self.config.via_proxy_name {
                format!("1.1 {}", proxy_name)
            } else {
                "1.1 tinyproxy-rust".to_string()
            };
            headers.insert("via".to_string(), via_value);
        }

        // Add X-Tinyproxy header if enabled
        if self.config.x_tinyproxy {
            headers.insert("x-tinyproxy".to_string(), client_ip.to_string());
        }

        // Add custom headers
        for (name, value) in &self.config.add_headers {
            headers.insert(name.to_lowercase(), value.clone());
        }
    }
}
