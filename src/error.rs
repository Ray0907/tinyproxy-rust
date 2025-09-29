use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Invalid HTTP request: {0}")]
    InvalidRequest(String),

    #[error("Invalid HTTP response: {0}")]
    InvalidResponse(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Upstream error: {0}")]
    Upstream(String),

    #[error("Filter blocked request: {0}")]
    FilterBlocked(String),

    #[error("TLS error: {0}")]
    Tls(#[from] native_tls::Error),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ProxyError {
    pub fn http_status_code(&self) -> u16 {
        match self {
            ProxyError::AuthenticationFailed => 407, // Proxy Authentication Required
            ProxyError::AccessDenied(_) => 403,      // Forbidden
            ProxyError::InvalidRequest(_) => 400,    // Bad Request
            ProxyError::Timeout => 408,              // Request Timeout
            ProxyError::FilterBlocked(_) => 403,     // Forbidden
            ProxyError::DnsResolution(_) => 502,     // Bad Gateway
            ProxyError::Upstream(_) => 502,          // Bad Gateway
            ProxyError::ResourceExhausted(_) => 503, // Service Unavailable
            _ => 500,                                // Internal Server Error
        }
    }

    pub fn error_message(&self) -> String {
        match self {
            ProxyError::AuthenticationFailed => "Proxy authentication required".to_string(),
            ProxyError::AccessDenied(msg) => {
                format!("Access denied: {}", msg)
            }
            ProxyError::InvalidRequest(msg) => {
                format!("Bad request: {}", msg)
            }
            ProxyError::Timeout => "Request timeout".to_string(),
            ProxyError::FilterBlocked(msg) => {
                format!("Request blocked by filter: {}", msg)
            }
            ProxyError::DnsResolution(msg) => {
                format!("DNS resolution failed: {}", msg)
            }
            ProxyError::Upstream(msg) => {
                format!("Upstream server error: {}", msg)
            }
            ProxyError::ResourceExhausted(msg) => {
                format!("Service temporarily unavailable: {}", msg)
            }
            _ => "Internal server error".to_string(),
        }
    }
}

pub type ProxyResult<T> = Result<T, ProxyError>;
